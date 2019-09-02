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
#include "util/util.h"

int sssm_openshift_init(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct data_provider *provider,
                        const char *module_name,
                        void **_module_data)
{
    struct openshift_id_ctx *ctx;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct openshift_id_ctx);
    if (ctx == NULL) {
        return ENOMEM;
    }

    ctx->be = be_ctx;
    ctx->domain = be_ctx->domain;

    *_module_data = ctx;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sssm_openshift_id_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct openshift_id_ctx *ctx;

    ctx = talloc_get_type(module_data, struct openshift_id_ctx);
    if (ctx == NULL) {
        return EINVAL;
    }

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  openshift_account_info_handler_send,
                  openshift_account_info_handler_recv,
                  ctx, struct openshift_id_ctx,
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
    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  openshift_auth_handler_send,
                  openshift_auth_handler_recv, NULL, void,
                  struct pam_data, struct pam_data *);

    return EOK;
}
