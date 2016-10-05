/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef _NSS_PRIVATE_H_
#define _NSS_PRIVATE_H_

struct nss_cmd_ctx;

typedef errno_t
(*nss_protocol_fill_packet_fn)(struct nss_ctx *nss_ctx,
                               struct nss_cmd_ctx *cmd_ctx,
                               struct sss_packet *packet,
                               struct cache_req_result *result);

struct nss_enum_index {
    unsigned int domain;
    unsigned int result;
};

struct nss_enum_ctx {
    struct cache_req_result **result;
    bool in_progress;
};

struct nss_state_ctx {
    struct nss_enum_index pwent;
    struct nss_enum_index grent;
};

struct nss_cmd_ctx {
    enum cache_req_type type;
    struct cli_ctx *cli_ctx;
    struct nss_ctx *nss_ctx;
    nss_protocol_fill_packet_fn fill_fn;

    /* For initgroups- */
    const char *rawname;
    const char *normalized_name;

    /* For enumeration. */
    struct nss_enum_ctx *enum_ctx;
    struct nss_enum_index *enum_index;
    uint32_t enum_limit;
};

struct nss_ctx {
    struct resp_ctx *rctx;
    struct sss_idmap_ctx *idmap_ctx;
    struct sss_names_ctx *global_names;

    /* Options. */
    int cache_refresh_percent;
    int enum_cache_timeout;
    bool filter_users_in_groups;
    char *pwfield;
    char *override_homedir;
    char *fallback_homedir;
    char *homedir_substr;
    char **allowed_shells;
    char *override_shell;
    char **vetoed_shells;
    char **etc_shells;
    char *shell_fallback;
    char *default_shell;
    const char **extra_attributes;

    /* Enumeration. */
    struct nss_enum_ctx pwent;
    struct nss_enum_ctx grent;

    /* Memory cache. */
    struct sss_mc_ctx *pwd_mc_ctx;
    struct sss_mc_ctx *grp_mc_ctx;
    struct sss_mc_ctx *initgr_mc_ctx;
};

#endif /* _NSS_PRIVATE_H_ */
