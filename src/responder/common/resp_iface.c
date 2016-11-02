/*
    Copyright (C) 2016 Red Hat

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

#include "sbus/sssd_dbus.h"
#include "responder/common/resp_iface.h"
#include "responder/common/responder.h"

struct iface_responder_backend iface_responder_backend = {
    { &iface_responder_backend_meta, 0 },
    .DomainValid = sss_resp_domain_valid,
    .DomainInvalid = sss_resp_domain_invalid,
    .ResetNegcacheUsers = sss_resp_reset_ncache_users,
    .ResetNegcacheGroups = sss_resp_reset_ncache_groups,
};

static struct sbus_iface_map iface_map[] = {
    { RESP_IFACE_PATH, &iface_responder_backend.vtable },
    { NULL, NULL }
};

struct sbus_iface_map *resp_get_sbus_interface()
{
    return iface_map;
}
