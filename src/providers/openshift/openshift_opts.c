/*
    SSSD

    openshift_opts.c - OpenShift provider options

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

#include "src/providers/data_provider.h"

struct dp_option auth_opts[] = {
    { "ocp_api_server_url", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    DP_OPTION_TERMINATOR
};
