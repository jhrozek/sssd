/*
    SSSD

    openshift_opts.h - OpenShift provider options

    Copyright (C) 2019 Red Hat

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

#ifndef LDAP_OPTS_H_
#define LDAP_OPTS_H_

#include "src/providers/data_provider.h"

extern struct dp_option id_opts[];
extern struct dp_option auth_opts[];
extern struct dp_option access_opts[];

enum ocp_id_opt {
    OCP_ADDTL_GROUP = 0,

    OCP_OPTS_ID /* opts counter */
};


enum ocp_auth_opt {
    API_SERVER_URL = 0,

    OCP_OPTS_AUTH /* opts counter */
};

enum ocp_access_opt {
    OCP_ACCT_ACL_LIST = 0,

    OCP_OPTS_ACCESS /* opts counter */
};

#endif /* LDAP_OPTS_H_ */
