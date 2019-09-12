/*
    SSSD

    openshift_private.h - A private header used by the provider only

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

#ifndef __OPENSHIFT_PRIVATE_H_
#define __OPENSHIFT_PRIVATE_H_

#include "config.h"

#include <talloc.h>
#include <tevent.h>
#include <errno.h>

#include "providers/data_provider/dp.h"

struct openshift_init_ctx {
    struct openshift_id_ctx  *id_ctx;
    struct openshift_auth_ctx *auth_ctx;
};

struct openshift_id_ctx {
    struct      be_ctx *be;
    struct      sss_domain_info *domain;
    size_t      user_quota;
    unsigned    remove_user_timeout;
};

struct openshift_auth_ctx {
    struct be_ctx *be;
    struct tcurl_ctx *tc_ctx;

    struct dp_option *auth_opts;
};

/* openshift_id.c */
struct tevent_req *
openshift_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct openshift_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params);
errno_t openshift_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                            struct tevent_req *req,
                                            struct dp_reply_std *data);

/* openshift_auth.c */
struct ocp_user_info {
    const char *name;
    const char **groups;
    size_t ngroups;
};

struct tevent_req *
openshift_auth_handler_send(TALLOC_CTX *mem_ctx,
                            struct openshift_auth_ctx *auth_ctx,
                            struct pam_data *pd,
                            struct dp_req_params *params);

errno_t openshift_auth_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct pam_data **_data);

/* openshift_auth_tokenreview.c */
struct tevent_req *
token_review_auth_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct tcurl_ctx *tc_ctx,
                       const char *api_server_url,
                       struct sss_auth_token *token);

errno_t
token_review_auth_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ocp_user_info **_user_info);

#endif
