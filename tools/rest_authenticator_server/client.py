#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Criteo
#

#
# This file is part of Scylla.
#
# Scylla is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Scylla is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scylla.  If not, see <http://www.gnu.org/licenses/>.
#

from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider


def contact_scylla(username='scylla_user', password='not_cassandra'):
    print(f'Run with user {username}')
    auth_provider = PlainTextAuthProvider(username=username, password=password)
    cluster = Cluster(auth_provider=auth_provider, protocol_version=2)
    session = cluster.connect()
    try:
        print('roles')
        rows = session.execute('SELECT * FROM system_auth.roles')
        for user_row in rows:
            print(user_row)

        print('role_members')
        rows = session.execute('SELECT * FROM system_auth.roles_valid')
        for user_row in rows:
            print(user_row)

        if username == 'cassandra':
            print('permissions')
            session.execute('GRANT ALL PERMISSIONS ON system_auth.roles TO group1')
            session.execute('GRANT ALL PERMISSIONS ON system_auth.roles_valid TO group1')

        # print('Delete scylla role')
        # session.execute("DELETE FROM system_auth.roles where role='scylla_user'")
        # session.execute("DELETE FROM system_auth.roles_valid where role='scylla_user'")

        # print('role_permissions')
        # rows = session.execut
        # e('SELECT * FROM system_auth.role_permissions')
        # for user_row in rows:
        #    print(user_row)

        # print(session.execute('LIST ALL PERMISSIONS OF scylla_user;'))
        # rows = session.execute('LIST ROLES OF scylla_user;')
        # for user_row in rows:
        #    print(user_row)
    finally:
        session.shutdown()


if __name__ == '__main__':
    contact_scylla(username='cassandra', password='cassandra')
    contact_scylla()
    contact_scylla(username='scylla_user2', password='not_cassandra')
