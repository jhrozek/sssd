/*
    SSSD

    openshift_init.c - Initialization of the openshift provider

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

#include "providers/data_provider/dp.h"
#include "providers/openshift/openshift_private.h"
#include "providers/openshift/openshift_opts.h"
#include "util/util.h"
#include "util/tev_curl.h"

int sssm_openshift_init(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct data_provider *provider,
                        const char *module_name,
                        void **_module_data)
{
    errno_t ret;
    struct openshift_init_ctx *init_ctx;

    init_ctx = talloc_zero(mem_ctx, struct openshift_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    init_ctx->id_ctx = talloc_zero(mem_ctx, struct openshift_id_ctx);
    if (init_ctx->id_ctx == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    init_ctx->id_ctx->be = be_ctx;
    init_ctx->id_ctx->domain = be_ctx->domain;
    init_ctx->id_ctx->remove_user_timeout = 10;  /* FIXME: make customizable */
    init_ctx->id_ctx->user_quota = 10;           /* FIXME: make customizable */
    init_ctx->id_ctx->domain->id_min = 10000;    /* FIXME: make customizable */
    init_ctx->id_ctx->domain->id_max = 20000;    /* FIXME: make customizable */

    init_ctx->auth_ctx = talloc_zero(mem_ctx, struct openshift_auth_ctx);
    if (init_ctx->auth_ctx == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    init_ctx->auth_ctx->be = be_ctx;

    ret = dp_get_options(init_ctx->auth_ctx,
                         be_ctx->cdb,
                         be_ctx->conf_path,
                         auth_opts,
                         OCP_OPTS_AUTH,
                         &init_ctx->auth_ctx->auth_opts);
    if (ret != EOK) {
        goto fail;
    }

    init_ctx->auth_ctx->tc_ctx = tcurl_init(init_ctx->auth_ctx,
                                            init_ctx->auth_ctx->be->ev);
    if (init_ctx->auth_ctx->tc_ctx == NULL) {
        goto fail;
    }

    *_module_data = init_ctx;
    return EOK;

fail:
    talloc_free(init_ctx);
    return ret;
}

int sssm_openshift_id_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct openshift_init_ctx *init_ctx;
    struct openshift_id_ctx *id_ctx;

    init_ctx = talloc_get_type(module_data, struct openshift_init_ctx);
    if (init_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Did not receive openshift_init_ctx\n");
        return EINVAL;
    }
    id_ctx = init_ctx->id_ctx;

    /* User/Group/... resolution request handlers
     */
    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  openshift_account_info_handler_send,
                  openshift_account_info_handler_recv,
                  id_ctx, struct openshift_id_ctx,
                  struct dp_id_data, struct dp_reply_std);

    /* Get-account-domain is normally only useable in AD environments
     * with Global Catalog, so let's just set the default noop
     * handlers
     */
    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send,
                  default_account_domain_recv,
                  NULL, void,
                  struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

int sssm_openshift_auth_init(TALLOC_CTX *mem_ctx,
                             struct be_ctx *be_ctx,
                             void *module_data,
                             struct dp_method *dp_methods)
{
    struct openshift_init_ctx *init_ctx;
    struct openshift_auth_ctx *auth_ctx;

    init_ctx = talloc_get_type(module_data, struct openshift_init_ctx);
    if (init_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Did not receive openshift_init_ctx\n");
        return EINVAL;
    }
    auth_ctx = init_ctx->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  openshift_auth_handler_send,
                  openshift_auth_handler_recv,
                  auth_ctx, struct openshift_auth_ctx,
                  struct pam_data, struct pam_data *);

    return EOK;
}
