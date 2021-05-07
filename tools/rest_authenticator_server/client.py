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

if __name__ == '__main__':
    auth_provider = PlainTextAuthProvider(username='scylla_user', password='not_cassandra')
    cluster = Cluster(auth_provider=auth_provider, protocol_version=2)
    session = cluster.connect()

    session.execute("DELETE FROM system_auth.roles where role='scylla_user'")

    rows = session.execute('SELECT * FROM system_auth.roles')
    for user_row in rows:
        print(user_row)
