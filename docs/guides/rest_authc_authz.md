# rest_authc_authz

## Description

The rest authenticator relies on an external rest endpoint to validate user credentials and retrieves user groups.

It will:

- check in the system_auth.roles table if the role exists. If the role exists check password with the stored hashed one
- If the role doesn't exists, it calls an external rest endpoint (https only)
- If creds are fine it stores the user/hashed password in the system_auth.roles table and returns the authenticated object user

The rest role manager only query for member roles so the default authorizer can assign permission to the uer role depending to it's member roles.
Difference with the standard role manager:

- do not manage creation, update and deletion of roles. This is performed by rest_authentication from ldap informations
- do not managed nested roles. Only takes in account roles in the member_of field of a user while the standard create a specific role for any roles in member_fo field and provide nested capability

## Rest Endpoint definition

Endpoint: GET /api/v1/user/groups, Protected with Basic Auth

Response:
 - 200 if ok with body:
`{
  "groups": [ "group1", "group2" ]
}`
- 404 if user not found
- 401 if auth failed

## Internal DB

It relies on:

- system_auth.roles DB to store the role and the list of member_of roles: [text (role_name), boolean (can_login), boolean (is_superuser), set<text> (member_of),text (salted_hash)]
- system_auth.roles_validation: role name are inserted in it with a TTL. When the role is not available in that table the rest_authenticator re check the user from the external endpoint [text (role_name)]
- system_auth.permissions to store permissions set for each roles: [text (role_name), text (resource), set<text> (permissions)]

## Test

Building Scylla with the frozen toolchain `dbuild` is as easy as:

```bash
$ git submodule update --init --force --recursive
$ ./tools/toolchain/dbuild ./configure.py
$ ./tools/toolchain/dbuild ninja build/release/scylla
```

Run scylla with RestAuthenticator

```bash
$ ./tools/toolchain/dbuild ./build/release/scylla --workdir tmp --smp 2 --developer-mode 1 \
--logger-log-level rest_authenticator=debug \
--authenticator com.criteo.scylladb.auth.RestAuthenticator \
--rest-authenticator-endpoint-host localhost \
--rest-authenticator-endpoint-port 8000 \
--rest-authenticator-endpoint-cafile-path ./tools/rest_authenticator_server/ssl/ca.crt \
--rest-authenticator-endpoint-ttl 30 \
--role-manager com.criteo.scylladb.auth.RestManager --authorizer CassandraAuthorizer
```

Run FastAPI rest server

```bash
$ ./tools/rest_authenticator_server/rest_server.sh
```

Run Test client

```bash
$ ./tools/rest_authenticator_server/scylla_client.sh
```

