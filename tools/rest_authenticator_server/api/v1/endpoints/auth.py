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

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from schema.auth import ResponseAuth

router = APIRouter()

security = HTTPBasic()


@router.post('/user/groups', response_model=ResponseAuth)
async def get_user_groups(credentials: HTTPBasicCredentials = Depends(security)) -> ResponseAuth:
    print(f'Call for user {credentials.username}')
    if credentials.username == 'scylla_user':
        if credentials.password == 'not_cassandra':
            return ResponseAuth(groups=['group1', 'group2'])
        else:
            raise HTTPException(status_code=401, detail=f'Bad password for {credentials.username} user')
    else:
        raise HTTPException(status_code=404, detail=f'User {credentials.username} not found')
