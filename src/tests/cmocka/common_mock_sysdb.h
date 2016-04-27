/*
    Copyright (C) 2016 Red Hat

    SSSD tests: Mocked a sysdb connection

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __COMMON_MOCK_SYSDB_H_
#define __COMMON_MOCK_SYSDB_H_

#include "tests/cmocka/common_mock.h"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};


#define setup_sysdb_tests(name, provider, _ctx) \
    _setup_sysdb_tests((name), (provider), false, (_ctx))

#define setup_sysdb_enum_tests(name, provider, _ctx) \
    _setup_sysdb_tests((name), (provider), true, (_ctx))

#endif /* __COMMON_MOCK_SYSDB_H_ */
