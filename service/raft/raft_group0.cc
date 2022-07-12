/*
 * Copyright (C) 2021-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "service/raft/raft_group0.hh"
#include "service/raft/raft_rpc.hh"
#include "service/raft/raft_sys_table_storage.hh"
#include "service/raft/group0_state_machine.hh"

#include "message/messaging_service.hh"
#include "cql3/query_processor.hh"
#include "cql3/untyped_result_set.hh"
#include "service/storage_proxy.hh"
#include "direct_failure_detector/failure_detector.hh"
#include "gms/gossiper.hh"
#include "db/system_keyspace.hh"

#include <seastar/core/smp.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/util/log.hh>
#include <seastar/util/defer.hh>
#include <seastar/rpc/rpc_types.hh>

#include "idl/group0.dist.hh"

namespace service {

raft_group0::raft_group0(seastar::abort_source& abort_source,
        raft_group_registry& raft_gr,
        netw::messaging_service& ms,
        gms::gossiper& gs,
        cql3::query_processor& qp,
        service::migration_manager& mm,
        raft_group0_client& client)
    : _abort_source(abort_source), _raft_gr(raft_gr), _ms(ms), _gossiper(gs), _qp(qp), _mm(mm), _client(client)
{
    init_rpc_verbs();
}

void raft_group0::init_rpc_verbs() {
    ser::group0_rpc_verbs::register_group0_peer_exchange(&_ms, [this] (const rpc::client_info&, rpc::opt_time_point, discovery::peer_list peers) {
        return peer_exchange(std::move(peers));
    });

    ser::group0_rpc_verbs::register_group0_modify_config(&_ms, [this] (const rpc::client_info&, rpc::opt_time_point,
            raft::group_id gid, std::vector<raft::config_member> add, std::vector<raft::server_id> del) {
        return _raft_gr.get_server(gid).modify_config(std::move(add), std::move(del));
    });
}

future<> raft_group0::uninit_rpc_verbs() {
    return when_all_succeed(
        ser::group0_rpc_verbs::unregister_group0_peer_exchange(&_ms),
        ser::group0_rpc_verbs::unregister_group0_modify_config(&_ms)
    ).discard_result();
}

future<raft::server_address> raft_group0::load_my_addr() {
    assert(this_shard_id() == 0);

    auto id = raft::server_id{co_await db::system_keyspace::get_raft_server_id()};
    if (!id) {
        on_internal_error(rslog, "raft_group0::load_my_addr(): server ID for group 0 missing");
    }

    co_return raft::server_address{id, inet_addr_to_raft_addr(_gossiper.get_broadcast_address())};
}

seastar::future<raft::server_address> raft_group0::load_or_create_my_addr() {
    assert(this_shard_id() == 0);
    auto id = raft::server_id{co_await db::system_keyspace::get_raft_server_id()};
    if (id == raft::server_id{}) {
        id = raft::server_id::create_random_id();
        co_await db::system_keyspace::set_raft_server_id(id.id);
    }
    co_return raft::server_address{id, inet_addr_to_raft_addr(_gossiper.get_broadcast_address())};
}

raft_server_for_group raft_group0::create_server_for_group0(raft::group_id gid, raft::server_address my_addr) {
    _raft_gr.address_map().set(my_addr);
    auto state_machine = std::make_unique<group0_state_machine>(_client, _mm, _qp.proxy());
    auto rpc = std::make_unique<raft_rpc>(*state_machine, _ms, _raft_gr.address_map(), gid, my_addr.id,
            [this] (gms::inet_address addr, raft::server_id raft_id, bool added) {
                // FIXME: we should eventually switch to UUID-based (not IP-based) node identification/communication scheme.
                // See #6403.
                auto fd_id = _gossiper.get_direct_fd_pinger().allocate_id(addr);
                if (added) {
                    rslog.info("Added {} (address: {}) to group 0 RPC map", raft_id, addr);
                    _raft_gr.direct_fd().add_endpoint(fd_id);
                } else {
                    rslog.info("Removed {} (address: {}) from group 0 RPC map", raft_id, addr);
                    _raft_gr.direct_fd().remove_endpoint(fd_id);
                }
            });
    // Keep a reference to a specific RPC class.
    auto& rpc_ref = *rpc;
    auto storage = std::make_unique<raft_sys_table_storage>(_qp, gid, my_addr.id);
    auto& persistence_ref = *storage;
    auto server = raft::create_server(my_addr.id, std::move(rpc), std::move(state_machine),
            std::move(storage), _raft_gr.failure_detector(), raft::server::configuration());

    // initialize the corresponding timer to tick the raft server instance
    auto ticker = std::make_unique<raft_ticker_type>([srv = server.get()] { srv->tick(); });

    return raft_server_for_group{
        .gid = std::move(gid),
        .server = std::move(server),
        .ticker = std::move(ticker),
        .rpc = rpc_ref,
        .persistence = persistence_ref,
    };
}

future<group0_info>
raft_group0::discover_group0(raft::server_address my_addr) {
    std::vector<raft::server_address> seeds;
    seeds.reserve(_gossiper.get_seeds().size());
    for (auto& seed : _gossiper.get_seeds()) {
        seeds.emplace_back(raft::server_id{}, inet_addr_to_raft_addr(seed));
    }

    auto& p_discovery = _group0.emplace<persistent_discovery>(co_await persistent_discovery::make(my_addr, std::move(seeds), _qp));
    co_return co_await futurize_invoke([this, &p_discovery, my_addr = std::move(my_addr)] () mutable {
        return p_discovery.run(_ms, _shutdown_gate.hold(), _abort_source, std::move(my_addr));
    }).finally(std::bind_front([] (raft_group0& self, persistent_discovery& p_discovery) -> future<> {
        co_await p_discovery.stop();
        self._group0 = std::monostate{};
    }, std::ref(*this), std::ref(p_discovery)));
}

future<group0_info> persistent_discovery::run(
        netw::messaging_service& ms,
        gate::holder pause_shutdown,
        abort_source& as,
        raft::server_address my_addr) {
    struct tracker {
        bool is_set = false;
        promise<std::optional<group0_info>> g0_info;

        void set_value(std::optional<group0_info> opt_g0_info) {
            if (!is_set) {
                is_set = true;
                g0_info.set_value(std::move(opt_g0_info));
            }
        }
        void set_exception() {
            if (!is_set) {
                is_set = true;
                g0_info.set_exception(std::current_exception());
            }
        }
    };

    // Send peer information to all known peers. If replies
    // discover new peers, send peer information to them as well.
    // As soon as we get a Raft Group 0 member information from
    // any peer, return it. If there is no Group 0, collect
    // replies from all peers, then, if this server has the smallest
    // id, make a new Group 0 with this server as the only member.
    // Otherwise sleep and keep pinging peers till some other node
    // creates a group and shares its group 0 id and peer address
    // with us.
    while (true) {
        auto output = co_await tick();

        if (std::holds_alternative<discovery::i_am_leader>(output)) {
            co_return group0_info{
                // Time-based ordering for groups identifiers may be
                // useful to provide linearisability between group
                // operations. Currently it's unused.
                .group0_id = raft::group_id{utils::UUID_gen::get_time_UUID()},
                .addr = my_addr
            };
        }

        if (std::holds_alternative<discovery::pause>(output)) {
            rslog.trace("server {} pausing discovery...", my_addr.id);
            co_await seastar::sleep_abortable(std::chrono::milliseconds{1000}, as);
            continue;
        }

        auto tracker = make_lw_shared<struct tracker>();
        (void)[] (persistent_discovery& self, netw::messaging_service& ms, gate::holder pause_shutdown,
                  discovery::request_list request_list, lw_shared_ptr<struct tracker> tracker) -> future<> {
            auto timeout = db::timeout_clock::now() + std::chrono::milliseconds{1000};
            co_await parallel_for_each(request_list, [&] (std::pair<raft::server_address, discovery::peer_list>& req) -> future<> {
                netw::msg_addr peer(raft_addr_to_inet_addr(req.first));
                rslog.trace("sending discovery message to {}", peer);
                try {
                    auto reply = co_await ser::group0_rpc_verbs::send_group0_peer_exchange(&ms, peer, timeout, std::move(req.second));

                    if (tracker->is_set) {
                        // Another peer was used to discover group 0 before us.
                        co_return;
                    }

                    if (auto peer_list = std::get_if<discovery::peer_list>(&reply.info)) {
                        // `tracker->is_set` is false so `run_discovery` hasn't exited yet, still safe to access `self`.
                        self.response(req.first, std::move(*peer_list));
                    } else if (auto g0_info = std::get_if<group0_info>(&reply.info)) {
                        tracker->set_value(std::move(*g0_info));
                    }
                } catch (std::exception& e) {
                    if (dynamic_cast<std::runtime_error*>(&e)) {
                        rslog.trace("failed to send message: {}", e);
                    } else {
                        tracker->set_exception();
                    }
                }
            });

            // In case we haven't discovered group 0 yet - need to run another iteration.
            tracker->set_value(std::nullopt);
        }(std::ref(*this), ms, pause_shutdown, std::move(std::get<discovery::request_list>(output)), tracker);

        if (auto g0_info = co_await tracker->g0_info.get_future()) {
            co_return *g0_info;
        }
    }
}

future<> raft_group0::abort() {
    co_await uninit_rpc_verbs();
    co_await _shutdown_gate.close();
}

future<> raft_group0::start_server_for_group0(raft::group_id group0_id) {
    assert(group0_id != raft::group_id{});

    auto my_addr = co_await load_my_addr();

    rslog.info("Server {} is starting group 0 with id {}", my_addr.id, group0_id);
    co_await _raft_gr.start_server_for_group(create_server_for_group0(group0_id, my_addr));
    _group0.emplace<raft::group_id>(group0_id);
}

future<> raft_group0::join_group0() {
    assert(this_shard_id() == 0);
    assert(!joined_group0());

    auto group0_id = raft::group_id{co_await db::system_keyspace::get_raft_group0_id()};
    if (group0_id) {
        // Group 0 ID present means we've already joined group 0 before.
        co_return co_await start_server_for_group0(group0_id);
    }

    raft::server* server = nullptr;
    auto my_addr = co_await load_or_create_my_addr();
    rslog.trace("{} found no local group 0. Discovering...", my_addr.id);
    while (true) {
        auto g0_info = co_await discover_group0(my_addr);
        rslog.trace("server {} found group 0 with id {}, leader {}", my_addr.id,
            g0_info.group0_id, g0_info.addr.id);
        if (server && group0_id != g0_info.group0_id) {
            // Subsequent discovery returned a different group 0 id?!
            throw std::runtime_error(format("Can't add server to two clusters ({} and {}). Please check your seeds don't overlap",
                group0_id, g0_info.group0_id));
        }
        group0_id = g0_info.group0_id;
        if (server == nullptr) {
            // This is the first time the discovery is run.
            raft::configuration initial_configuration;
            if (g0_info.addr.id == my_addr.id) {
                // We should start a new group with this node as voter.
                rslog.trace("server {} creating configuration as voter", my_addr.id);
                initial_configuration.current.emplace(my_addr, true);
            }
            auto grp = create_server_for_group0(group0_id, my_addr);
            server = grp.server.get();
            co_await grp.persistence.bootstrap(std::move(initial_configuration));
            co_await _raft_gr.start_server_for_group(std::move(grp));
        }
        if (server->get_configuration().contains(my_addr.id)) {
            // True if we started a new group or completed a configuration change
            // initiated earlier.
            rslog.trace("server {} already in group as {}", my_addr.id,
                    server->get_configuration().can_vote(my_addr.id)? "voter" : "non-voter");
            break;
        }
        auto pause_shutdown = _shutdown_gate.hold();
        auto timeout = db::timeout_clock::now() + std::chrono::milliseconds{1000};
        netw::msg_addr peer(raft_addr_to_inet_addr(g0_info.addr));
        try {
            // TODO: aborts?
            co_await ser::group0_rpc_verbs::send_group0_modify_config(&_ms, peer, timeout, group0_id, {{my_addr, false}}, {});
            break;
        } catch (std::runtime_error& e) {
            // Retry
            rslog.error("failed to modify config at peer {}: {}", g0_info.addr.id, e);
        }
        // Try again after a pause
        co_await seastar::sleep_abortable(std::chrono::milliseconds{1000}, _abort_source);
    }
    co_await db::system_keyspace::set_raft_group0_id(group0_id.id);
    // Allow peer_exchange() RPC to access group 0 only after group0_id is persisted.

    _group0 = group0_id;
    rslog.info("{} joined group 0 with id {}", my_addr.id, group0_id);
}

future<> raft_group0::setup_group0(db::system_keyspace& sys_ks) {
    assert(this_shard_id() == 0);

    if (!_raft_gr.is_enabled()) {
        rslog.info("raft_group0::setup_group0(): local RAFT feature disabled, skipping group 0 setup.");
        // Note: if the local feature was enabled by every node earlier, that would enable the cluster
        // SUPPORTS_RAFT feature, and the node should then refuse to start during feature check
        // (because if the local feature is disabled, then the cluster feature - enabled in the cluster - is 'unknown' to us).
        co_return;
    }

    if (sys_ks.bootstrap_complete()) {
        auto group0_id = raft::group_id{co_await db::system_keyspace::get_raft_group0_id()};
        if (group0_id) {
            // Group 0 ID is present => we've already joined group 0 earlier.
            rslog.info("raft_group0::setup_group0(): group 0 ID present. Starting existing Raft server.");
            co_await start_server_for_group0(group0_id);
        } else {
            // Scylla has bootstrapped earlier but group 0 ID not present. This means we're upgrading.
            // TODO: Prepare for upgrade.
        }

        co_return;
    }

    rslog.info("raft_group0::setup_group0(): joining group 0...");
    co_await join_group0();
    rslog.info("raft_group0::setup_group0(): successfully joined group 0.");
}

future<> raft_group0::become_voter() {
    if (!_raft_gr.is_enabled() || !joined_group0()) {
        co_return;
    }

    auto my_addr = co_await load_my_addr();
    assert(std::holds_alternative<raft::group_id>(_group0));
    auto& gid = std::get<raft::group_id>(_group0);
    if (!_raft_gr.get_server(gid).get_configuration().can_vote(my_addr.id)) {
        auto pause_shutdown = _shutdown_gate.hold();
        co_return co_await _raft_gr.group0().modify_config({{my_addr, true}}, {}, &_abort_source);
    }
}

future<> raft_group0::leave_group0() {
    assert(this_shard_id() == 0);

    if (!_raft_gr.is_enabled()) {
        rslog.info("leave_group0: local RAFT feature disabled, skipping.");
        co_return;
    }

    if (!joined_group0()) {
        // TODO: unimplemented upgrade case.
        co_return;
    }

    auto my_id = raft::server_id{co_await db::system_keyspace::get_raft_server_id()};
    if (!my_id) {
        on_internal_error(rslog,
            "leave_group0: we're fully upgraded to use Raft and group 0 ID is present but Raft server ID is not."
            " Please report a bug.");
    }

    // Note: if this gets stuck due to a failure, the DB admin can abort.
    // FIXME: this gets stuck without failures if we're the leader (#10833)
    co_return co_await _raft_gr.group0().modify_config({}, {my_id}, &_abort_source);
}

future<> raft_group0::remove_from_group0(gms::inet_address node) {
    if (!_raft_gr.is_enabled()) {
        co_return;
    }
    assert(this_shard_id() == 0);
    auto my_id = raft::server_id{co_await db::system_keyspace::get_raft_server_id()};
    if (my_id == raft::server_id{}) {
        throw std::runtime_error("Can't invoke removenode on a node which is not part of the cluster");
    }
    auto opt_id = _raft_gr.address_map().find_replace_id(node, my_id);
    if (!opt_id) {
        // The node being removed is not part of the
        // configuration.
        co_return;
    }
    auto remove_addr = *opt_id;

    auto pause_shutdown = _shutdown_gate.hold();
    if (std::holds_alternative<raft::group_id>(_group0)) {
        co_return co_await _raft_gr.group0().modify_config({}, {remove_addr}, &_abort_source);
    }
    auto g0_info = co_await discover_group0(my_id, raft::server_info{} /* XXX: apparently passing empty info works */);
    if (g0_info.addr.id == my_id) {
        co_return;
    }
    netw::msg_addr peer(raft_addr_to_inet_addr(g0_info.addr));
    // During removenode, the client itself will retry or abort
    // the operation if necessary, it's move important it's not
    // "flaky" on slow network or CPU.
    auto timeout = db::timeout_clock::now() + std::chrono::minutes{20};
    // TODO: aborts?
    co_return co_await ser::group0_rpc_verbs::send_group0_modify_config(&_ms, peer, timeout, g0_info.group0_id, {}, {remove_addr});
}

bool raft_group0::joined_group0() const {
    return std::holds_alternative<raft::group_id>(_group0);
}

future<group0_peer_exchange> raft_group0::peer_exchange(discovery::peer_list peers) {
    return std::visit([this, peers = std::move(peers)] (auto&& d) mutable -> future<group0_peer_exchange> {
        using T = std::decay_t<decltype(d)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            // Discovery not started or we're persisting the
            // leader information locally.
            co_return group0_peer_exchange{std::monostate{}};
        } else if constexpr (std::is_same_v<T, persistent_discovery>) {
            // Use discovery to produce a response
            if (auto response = co_await d.request(std::move(peers))) {
                co_return group0_peer_exchange{std::move(*response)};
            }
            // We just became a leader.
            // Eventually we'll answer with group0_info.
            co_return group0_peer_exchange{std::monostate{}};
        } else if constexpr (std::is_same_v<T, raft::group_id>) {
            // Even if in follower state, return own address: the
            // incoming RPC will then be bounced to the leader.
            co_return group0_peer_exchange{group0_info{
                .group0_id = std::get<raft::group_id>(_group0),
                .addr = _raft_gr.address_map().get_server_address(_raft_gr.group0().id())
            }};
        }
    }, _group0);
}

static constexpr auto DISCOVERY_KEY = "peers";

static mutation make_discovery_mutation(discovery::peer_set peers) {
    auto s = db::system_keyspace::discovery();
    auto ts = api::new_timestamp();
    auto raft_id_cdef = s->get_column_definition("raft_id");
    assert(raft_id_cdef);

    mutation m(s, partition_key::from_singular(*s, DISCOVERY_KEY));
    for (auto& p: peers) {
        auto& row = m.partition().clustered_row(*s, clustering_key::from_singular(*s, data_value(p.info)));
        row.apply(row_marker(ts));
        row.cells().apply(*raft_id_cdef, atomic_cell::make_live(*raft_id_cdef->type, ts, raft_id_cdef->type->decompose(p.id.id)));
    }

    return m;
}

static future<> store_discovered_peers(cql3::query_processor& qp, discovery::peer_set peers) {
    return qp.proxy().mutate_locally({make_discovery_mutation(std::move(peers))}, tracing::trace_state_ptr{});
}

static future<discovery::peer_set> load_discovered_peers(cql3::query_processor& qp) {
    static const auto load_cql = format(
            "SELECT server_info, raft_id FROM system.{} WHERE key = '{}'",
            db::system_keyspace::DISCOVERY, DISCOVERY_KEY);
    auto rs = co_await qp.execute_internal(load_cql, cql3::query_processor::cache_internal::yes);
    assert(rs);

    discovery::peer_set peers;
    for (auto& r: *rs) {
        peers.emplace(
            raft::server_id{r.get_as<utils::UUID>("raft_id")},
            r.get_as<bytes>("server_info")
        );
    }

    co_return peers;
}

future<persistent_discovery> persistent_discovery::make(raft::server_address self, peer_list seeds, cql3::query_processor& qp) {
    auto peers = co_await load_discovered_peers(qp);
    // If a peer is present both on disk and in provided list of `seeds`,
    // we take the information from disk (which may already contain the Raft ID of this peer).
    std::move(seeds.begin(), seeds.end(), std::inserter(peers, peers.end()));
    co_return persistent_discovery{std::move(self), {peers.begin(), peers.end()}, qp};
}

future<std::optional<discovery::peer_list>> persistent_discovery::request(peer_list peers) {
    for (auto& p: peers) {
        rslog.debug("discovery: request peer: id={}, info={}", p.id, p.info);
    }

    if (_gate.is_closed()) {
        // We stopped discovery, about to destroy it.
        co_return std::nullopt;
    }
    auto holder = _gate.hold();

    auto response = _discovery.request(peers);
    co_await store_discovered_peers(_qp, _discovery.peers());

    co_return response;
}

void persistent_discovery::response(raft::server_address from, const peer_list& peers) {
    // The peers discovered here will be persisted on the next `request` or `tick`.
    for (auto& p: peers) {
        rslog.debug("discovery: response peer: id={}, info={}", p.id, p.info);
    }
    _discovery.response(std::move(from), peers);
}

future<discovery::tick_output> persistent_discovery::tick() {
    // No need to enter `_gate`, since `stop` must be called after all calls to `tick` (and before the object is destroyed).

    auto result = _discovery.tick();
    co_await store_discovered_peers(_qp, _discovery.peers());

    co_return result;
}

future<> persistent_discovery::stop() {
    return _gate.close();
}

persistent_discovery::persistent_discovery(raft::server_address self, const peer_list& seeds, cql3::query_processor& qp)
    : _discovery{std::move(self), seeds}
    , _qp{qp}
{
    for (auto& addr: seeds) {
        rslog.debug("discovery: seed peer: id={}, info={}", addr.id, addr.info);
    }
}

} // end of namespace service

