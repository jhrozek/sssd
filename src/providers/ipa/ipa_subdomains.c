/*
    SSSD

    IPA Subdomains Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include <ctype.h>

#define SUBDOMAINS_FILTER "objectclass=ipaNTTrustedDomain"
#define MASTER_DOMAIN_FILTER "objectclass=ipaNTDomainAttrs"
#define RANGE_FILTER "objectclass=ipaIDRange"

#define IPA_CN "cn"
#define IPA_FLATNAME "ipaNTFlatName"
#define IPA_SID "ipaNTSecurityIdentifier"
#define IPA_TRUSTED_DOMAIN_SID "ipaNTTrustedDomainSID"

#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"
#define OBJECTCLASS "objectClass"

/* do not refresh more often than every 5 seconds for now */
#define IPA_SUBDOMAIN_REFRESH_LIMIT 5

/* refresh automatically every 4 hours */
#define IPA_SUBDOMAIN_REFRESH_PERIOD (3600 * 4)
#define IPA_SUBDOMAIN_DISABLED_PERIOD 3600

/* the directory domain - realm mappings are written to */
#define IPA_SUBDOMAIN_MAPPING_DIR PUBCONF_PATH"/krb5.include.d"

enum ipa_subdomains_req_type {
    IPA_SUBDOMAINS_MASTER,
    IPA_SUBDOMAINS_SLAVE,
    IPA_SUBDOMAINS_RANGES,

    IPA_SUBDOMAINS_MAX /* Counter */
};

struct ipa_subdomains_req_params {
    const char *filter;
    tevent_req_fn cb;
    const char *attrs[8];
};

struct ipa_subdomains_ctx {
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_search_base **search_bases;
    struct sdap_search_base **master_search_bases;
    struct sdap_search_base **ranges_search_bases;

    time_t last_refreshed;
    struct tevent_timer *timer_event;
    bool configured_explicit;
    time_t disabled_until;
};

struct be_ctx *ipa_get_subdomains_be_ctx(struct be_ctx *be_ctx)
{
    struct ipa_subdomains_ctx *subdom_ctx;

    subdom_ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                                 struct ipa_subdomains_ctx);
    if (subdom_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, ("Subdomains are not configured.\n"));
        return NULL;
    }

    return subdom_ctx->be_ctx;
}

const char *get_flat_name_from_subdomain_name(struct be_ctx *be_ctx,
                                              const char *name)
{
    struct ipa_subdomains_ctx *ctx;
    struct sss_domain_info *dom;

    ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                          struct ipa_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, ("Subdomains are not configured.\n"));
        return NULL;
    }

    dom = find_subdomain_by_name(ctx->be_ctx->domain, name, true);
    if (dom) {
        return dom->flat_name;
    }

    return NULL;
}

static errno_t ipa_ranges_parse_results(TALLOC_CTX *mem_ctx,
                                        size_t count,
                                        struct sysdb_attrs **reply,
                                        struct range_info ***_range_list)
{
    struct range_info **range_list = NULL;
    const char *value;
    size_t c;
    int ret;

    range_list = talloc_array(mem_ctx, struct range_info *, count + 1);
    if (range_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_array failed.\n"));
        return ENOMEM;
    }

    for (c = 0; c < count; c++) {
        range_list[c] = talloc_zero(range_list, struct range_info);
        if (range_list[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }
        range_list[c]->name = talloc_strdup(range_list[c], value);
        if (range_list[c]->name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[c], IPA_TRUSTED_DOMAIN_SID, &value);
        if (ret == EOK) {
            range_list[c]->trusted_dom_sid = talloc_strdup(range_list[c],
                                                           value);
            if (range_list[c]->trusted_dom_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_ID,
                                       &range_list[c]->base_id);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_ID_RANGE_SIZE,
                                       &range_list[c]->id_range_size);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_BASE_RID,
                                       &range_list[c]->base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(reply[c], IPA_SECONDARY_BASE_RID,
                                       &range_list[c]->secondary_base_rid);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
            goto done;
        }
    }
    range_list[c] = NULL;

    *_range_list = range_list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(range_list);
    }

    return ret;
}

static errno_t ipa_subdom_store(struct sss_domain_info *domain,
                                struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char *name;
    char *realm;
    const char *flat;
    const char *id;
    int ret;

    tmp_ctx = talloc_new(domain);

    ret = sysdb_attrs_get_string(attrs, IPA_CN, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
        goto done;
    }

    realm = get_uppercase_realm(tmp_ctx, name);
    if (!realm) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_FLATNAME, &flat);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
        goto done;
    }

    ret = sysdb_attrs_get_string(attrs, IPA_TRUSTED_DOMAIN_SID, &id);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
        goto done;
    }

    ret = sysdb_subdomain_store(domain->sysdb, name, realm, flat, id);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_subdomain_store failed.\n"));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_subdomains_write_mappings(struct sss_domain_info *domain)
{
    struct sss_domain_info *dom;
    errno_t ret;
    errno_t err;
    TALLOC_CTX *tmp_ctx;
    const char *mapping_file;
    char *sanitized_domain;
    char *tmp_file = NULL;
    int fd = -1;
    mode_t old_mode;
    FILE *fstream = NULL;
    int i;

    if (domain == NULL || domain->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("No domain name provided\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    sanitized_domain = talloc_strdup(tmp_ctx, domain->name);
    if (sanitized_domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        return ENOMEM;
    }

    /* only alpha-numeric chars, dashes and underscores are allowed in
     * krb5 include directory */
    for (i = 0; sanitized_domain[i] != '\0'; i++) {
        if (!isalnum(sanitized_domain[i])
                && sanitized_domain[i] != '-' && sanitized_domain[i] != '_') {
            sanitized_domain[i] = '_';
        }
    }

    mapping_file = talloc_asprintf(tmp_ctx, "%s/domain_realm_%s",
                                   IPA_SUBDOMAIN_MAPPING_DIR, sanitized_domain);
    if (!mapping_file) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_FUNC_DATA, ("Mapping file for domain [%s] is [%s]\n",
                             domain->name, mapping_file));

    tmp_file = talloc_asprintf(tmp_ctx, "%sXXXXXX", mapping_file);
    if (tmp_file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    old_mode = umask(077);
    fd = mkstemp(tmp_file);
    umask(old_mode);
    if (fd < 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("creating the temp file [%s] for domain-realm "
                                  "mappings failed.", tmp_file));
        ret = EIO;
        talloc_zfree(tmp_ctx);
        goto done;
    }

    fstream = fdopen(fd, "a");
    if (!fstream) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, ("fdopen failed [%d]: %s\n",
                                  ret, strerror(ret)));
        ret = close(fd);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                ("fclose failed [%d][%s].\n", ret, strerror(ret)));
            /* Nothing to do here, just report the failure */
        }
        ret = EIO;
        goto done;
    }

    ret = fprintf(fstream, "[domain_realm]\n");
    if (ret < 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("fprintf failed\n"));
        ret = EIO;
        goto done;
    }

    for (dom = get_next_domain(domain, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {
        ret = fprintf(fstream, ".%s = %s\n%s = %s\n",
                               dom->name, dom->realm, dom->name, dom->realm);
        if (ret < 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("fprintf failed\n"));
            goto done;
        }
    }

    ret = fclose(fstream);
    fstream = NULL;
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("fclose failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    ret = rename(tmp_file, mapping_file);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("rename failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    talloc_zfree(tmp_file);

    ret = chmod(mapping_file, 0644);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("fchmod failed [%d][%s].\n", ret, strerror(ret)));
        goto done;
    }

    ret = EOK;
done:
    if (fstream) {
        err = fclose(fstream);
        if (err != 0) {
            err = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                ("fclose failed [%d][%s].\n", err, strerror(err)));
            /* Nothing to do here, just report the failure */
        }
    }

    if (tmp_file) {
        err = unlink(tmp_file);
        if (err < 0) {
            err = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not remove file [%s]: [%d]: %s",
                   tmp_file, err, strerror(err)));
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t ipa_subdomains_refresh(struct ipa_subdomains_ctx *ctx,
                                      int count, struct sysdb_attrs **reply,
                                      bool *changes)
{
    struct sss_domain_info *domain, *dom;
    bool handled[count];
    const char *value;
    int c, h;
    int ret;

    domain = ctx->be_ctx->domain;
    memset(handled, 0, sizeof(bool) * count);
    h = 0;

    /* check existing subdomains */
    for (dom = get_next_domain(domain, true);
         dom && IS_SUBDOMAIN(dom); /* if we get back to a parent, stop */
         dom = get_next_domain(dom, false)) {
        for (c = 0; c < count; c++) {
            if (handled[c]) {
                continue;
            }
            ret = sysdb_attrs_get_string(reply[c], IPA_CN, &value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_string failed.\n"));
                goto done;
            }
            if (strcmp(value, dom->name) == 0) {
                break;
            }
        }

        if (c >= count) {
            /* ok this subdomain does not exist anymore, let's clean up */
            dom->disabled = true;
            ret = sysdb_subdomain_delete(dom->sysdb, dom->name);
            if (ret != EOK) {
                goto done;
            }
        } else {
            /* ok let's try to update it */
            ret = ipa_subdom_store(domain, reply[c]);
            if (ret) {
                /* Nothing we can do about the errorr. Let's at least try
                 * to reuse the existing domain
                 */
                DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to parse subdom data, "
                      "will try to use cached subdomain\n"));
            }
            handled[c] = true;
            h++;
        }
    }

    if (count == h) {
        /* all domains were already accounted for and have been updated */
        ret = EOK;
        goto done;
    }

    /* if we get here it means we have changes to the subdomains list */
    *changes = true;

    for (c = 0; c < count; c++) {
        if (handled[c]) {
            continue;
        }
        /* Nothing we can do about the errorr. Let's at least try
         * to reuse the existing domain.
         */
        ret = ipa_subdom_store(domain, reply[c]);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to parse subdom data, "
                  "will try to use cached subdomain\n"));
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        ctx->last_refreshed = 0;
    } else {
        ctx->last_refreshed = time(NULL);
    }

    return ret;
}

struct ipa_subdomains_req_ctx {
    struct be_req *be_req;
    struct ipa_subdomains_ctx *sd_ctx;
    struct sdap_id_op *sdap_op;

    char *current_filter;

    struct sdap_search_base **search_bases;
    int search_base_iter;

    size_t reply_count;
    struct sysdb_attrs **reply;
};

static void ipa_subdomains_get_conn_done(struct tevent_req *req);
static errno_t
ipa_subdomains_handler_get(struct ipa_subdomains_req_ctx *ctx,
                           enum ipa_subdomains_req_type type);
static void ipa_subdomains_handler_done(struct tevent_req *req);
static void ipa_subdomains_handler_master_done(struct tevent_req *req);
static void ipa_subdomains_handler_ranges_done(struct tevent_req *req);

static struct ipa_subdomains_req_params subdomain_requests[] = {
    { MASTER_DOMAIN_FILTER,
      ipa_subdomains_handler_master_done,
      { IPA_CN, IPA_FLATNAME, IPA_SID, NULL }
    },
    { SUBDOMAINS_FILTER,
      ipa_subdomains_handler_done,
      { IPA_CN, IPA_FLATNAME, IPA_TRUSTED_DOMAIN_SID, NULL }
    },
    { RANGE_FILTER,
      ipa_subdomains_handler_ranges_done,
      { OBJECTCLASS, IPA_CN,
        IPA_BASE_ID, IPA_BASE_RID, IPA_SECONDARY_BASE_RID,
        IPA_ID_RANGE_SIZE, IPA_TRUSTED_DOMAIN_SID, NULL
      }
    }
};

static void ipa_subdomains_retrieve(struct ipa_subdomains_ctx *ctx, struct be_req *be_req)
{
    struct ipa_subdomains_req_ctx *req_ctx = NULL;
    struct tevent_req *req;
    int dp_error = DP_ERR_FATAL;
    int ret;

    req_ctx = talloc(be_req, struct ipa_subdomains_req_ctx);
    if (req_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    req_ctx->be_req = be_req;
    req_ctx->sd_ctx = ctx;
    req_ctx->search_base_iter = 0;
    req_ctx->search_bases = ctx->search_bases;
    req_ctx->current_filter = NULL;
    req_ctx->reply_count = 0;
    req_ctx->reply = NULL;

    req_ctx->sdap_op = sdap_id_op_create(req_ctx,
                                         ctx->sdap_id_ctx->conn_cache);
    if (req_ctx->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    req = sdap_id_op_connect_send(req_ctx->sdap_op, req_ctx, &ret);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret)));
        goto done;
    }

    tevent_req_set_callback(req, ipa_subdomains_get_conn_done, req_ctx);

    return;

done:
    talloc_free(req_ctx);
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_get_conn_done(struct tevent_req *req)
{
    int ret;
    int dp_error = DP_ERR_FATAL;
    struct ipa_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);

    ret = sdap_id_op_connect_recv(req, &dp_error);
    talloc_zfree(req);
    if (ret) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("No IPA server is available, cannot get the "
                   "subdomain list while offline\n"));

/* FIXME: return saved results ?? */
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret)));
        }

        goto fail;
    }

    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_SLAVE);
    if (ret != EOK && ret != EAGAIN) {
        goto fail;
    }

    return;

fail:
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static errno_t
ipa_subdomains_handler_get(struct ipa_subdomains_req_ctx *ctx,
                           enum ipa_subdomains_req_type type)
{
    struct tevent_req *req;
    struct sdap_search_base *base;
    struct ipa_subdomains_req_params *params;

    if (type >= IPA_SUBDOMAINS_MAX) {
        return EINVAL;
    }

    params = &subdomain_requests[type];

    base = ctx->search_bases[ctx->search_base_iter];
    if (base == NULL) {
        return EOK;
    }

    talloc_free(ctx->current_filter);
    ctx->current_filter = sdap_get_id_specific_filter(ctx, params->filter,
                                                            base->filter);
    if (ctx->current_filter == NULL) {
        return ENOMEM;
    }

    req = sdap_get_generic_send(ctx, ctx->sd_ctx->be_ctx->ev,
                        ctx->sd_ctx->sdap_id_ctx->opts,
                        sdap_id_op_handle(ctx->sdap_op),
                        base->basedn, base->scope,
                        ctx->current_filter, params->attrs, NULL, 0,
                        dp_opt_get_int(ctx->sd_ctx->sdap_id_ctx->opts->basic,
                                       SDAP_SEARCH_TIMEOUT), false);

    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(req, params->cb, ctx);

    return EAGAIN;
}

static void ipa_subdomains_handler_done(struct tevent_req *req)
{
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;
    struct sss_domain_info *domain;
    bool refresh_has_changes = false;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);
    domain = ctx->sd_ctx->be_ctx->domain;

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count) {
        ctx->reply = talloc_realloc(ctx, ctx->reply, struct sysdb_attrs *,
                                    ctx->reply_count + reply_count);
        if (ctx->reply == NULL) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(ctx->reply+ctx->reply_count, reply,
               reply_count * sizeof(struct sysdb_attrs *));
        ctx->reply_count += reply_count;
    }

    ctx->search_base_iter++;
    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_SLAVE);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    ret = ipa_subdomains_refresh(ctx->sd_ctx, ctx->reply_count, ctx->reply,
                                 &refresh_has_changes);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to refresh subdomains.\n"));
        goto done;
    }

    if (refresh_has_changes) {
        ret = sysdb_update_subdomains(domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("sysdb_update_subdomains failed.\n"));
            goto done;
        }

        ret = ipa_subdomains_write_mappings(domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("ipa_subdomains_write_mappings failed.\n"));
        }
    }


    ctx->search_base_iter = 0;
    ctx->search_bases = ctx->sd_ctx->ranges_search_bases;
    ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_RANGES);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_OP_FAILURE, ("No search base for ranges available.\n"));
    ret = EINVAL;

done:
    be_req_terminate(ctx->be_req, DP_ERR_FATAL, ret, NULL);
}


static void ipa_subdomains_handler_ranges_done(struct tevent_req *req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;
    struct range_info **range_list = NULL;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);
    domain = ctx->sd_ctx->be_ctx->domain;
    sysdb = domain->sysdb;

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    ret = ipa_ranges_parse_results(ctx, reply_count, reply, &range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("ipa_ranges_parse_results request failed.\n"));
        goto done;
    }

    ret = sysdb_update_ranges(sysdb, range_list);
    talloc_free(range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_update_ranges failed.\n"));
        goto done;
    }


    ret = sysdb_master_domain_update(domain);
    if (ret != EOK) {
        goto done;
    }

    if (domain->flat_name == NULL ||
        domain->domain_id == NULL ||
        domain->realm == NULL) {

        ctx->search_base_iter = 0;
        ctx->search_bases = ctx->sd_ctx->master_search_bases;
        ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_MASTER);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }
    } else {
        ret = EOK;
    }

done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdomains_handler_master_done(struct tevent_req *req)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    size_t reply_count;
    struct sysdb_attrs **reply = NULL;
    struct ipa_subdomains_req_ctx *ctx;

    ctx = tevent_req_callback_data(req, struct ipa_subdomains_req_ctx);

    ret = sdap_get_generic_recv(req, ctx, &reply_count, &reply);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send request failed.\n"));
        goto done;
    }

    if (reply_count) {
        const char *flat = NULL;
        const char *id = NULL;

        ret = sysdb_attrs_get_string(reply[0], IPA_FLATNAME, &flat);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_attrs_get_string(reply[0], IPA_SID, &id);
        if (ret != EOK) {
            goto done;
        }

        ret = sysdb_master_domain_add_info(ctx->sd_ctx->be_ctx->domain,
                                           NULL, flat, id);
    } else {
        ctx->search_base_iter++;
        ret = ipa_subdomains_handler_get(ctx, IPA_SUBDOMAINS_MASTER);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            goto done;
        }

        /* Right now we know there has been an error
         * and we don't have the master domain record
         */
        DEBUG(SSSDBG_CRIT_FAILURE, ("Master domain record not found!\n"));

        if (!ctx->sd_ctx->configured_explicit) {
            ctx->sd_ctx->disabled_until = time(NULL) +
                                          IPA_SUBDOMAIN_DISABLED_PERIOD;
        }

        ret = EIO;
    }

done:
    if (ret == EOK) {
        dp_error = DP_ERR_OK;
    }
    be_req_terminate(ctx->be_req, dp_error, ret, NULL);
}

static void ipa_subdom_online_cb(void *pvt);

static void ipa_subdom_timer_refresh(struct tevent_context *ev,
                                     struct tevent_timer *te,
                                     struct timeval current_time,
                                     void *pvt)
{
    ipa_subdom_online_cb(pvt);
}

static void ipa_subdom_be_req_callback(struct be_req *be_req,
                                       int dp_err, int dp_ret,
                                       const char *errstr)
{
    talloc_free(be_req);
}

static void ipa_subdom_online_cb(void *pvt)
{
    struct ipa_subdomains_ctx *ctx;
    struct be_req *be_req;
    struct timeval tv;

    ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad private pointer\n"));
        return;
    }

    ctx->disabled_until = 0;

    be_req = be_req_create(ctx, NULL, ctx->be_ctx,
                           ipa_subdom_be_req_callback, NULL);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("be_req_create() failed.\n"));
        return;
    }

    ipa_subdomains_retrieve(ctx, be_req);

    tv = tevent_timeval_current_ofs(IPA_SUBDOMAIN_REFRESH_PERIOD, 0);
    ctx->timer_event = tevent_add_timer(ctx->be_ctx->ev, ctx, tv,
                                        ipa_subdom_timer_refresh, ctx);
    if (!ctx->timer_event) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom timer event\n"));
    }
}

static void ipa_subdom_offline_cb(void *pvt)
{
    struct ipa_subdomains_ctx *ctx;

    ctx = talloc_get_type(pvt, struct ipa_subdomains_ctx);

    if (ctx) {
        talloc_zfree(ctx->timer_event);
    }
}

static errno_t get_config_status(struct be_ctx *be_ctx,
                                 bool *configured_explicit)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    char *tmp_str;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_DOMAIN_SUBDOMAINS_PROVIDER, NULL,
                            &tmp_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("confdb_get_string failed.\n"));
        goto done;
    }

    if (tmp_str == NULL) {
        *configured_explicit = false;
    } else {
        *configured_explicit = true;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("IPA subdomain provider is configured %s.\n",
                             *configured_explicit ? "explicit" : "implicit"));

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

void ipa_subdomains_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ipa_subdomains_ctx *ctx;
    time_t now;

    ctx = talloc_get_type(be_ctx->bet_info[BET_SUBDOMAINS].pvt_bet_data,
                          struct ipa_subdomains_ctx);
    if (!ctx) {
        be_req_terminate(be_req, DP_ERR_FATAL, EINVAL, NULL);
        return;
    }

    now = time(NULL);

    if (ctx->disabled_until > now) {
        DEBUG(SSSDBG_TRACE_ALL, ("Subdomain provider disabled.\n"));
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    if (ctx->last_refreshed > now - IPA_SUBDOMAIN_REFRESH_LIMIT) {
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    ipa_subdomains_retrieve(ctx, be_req);
}

struct bet_ops ipa_subdomains_ops = {
    .handler = ipa_subdomains_handler,
    .finalize = NULL
};

int ipa_subdom_init(struct be_ctx *be_ctx,
                    struct ipa_id_ctx *id_ctx,
                    struct bet_ops **ops,
                    void **pvt_data)
{
    struct ipa_subdomains_ctx *ctx;
    int ret;
    bool configured_explicit = false;

    ret = get_config_status(be_ctx, &configured_explicit);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_config_status failed.\n"));
        return ret;
    }

    ctx = talloc_zero(id_ctx, struct ipa_subdomains_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ctx->be_ctx = be_ctx;
    ctx->sdap_id_ctx = id_ctx->sdap_id_ctx;
    ctx->search_bases = id_ctx->ipa_options->subdomains_search_bases;
    ctx->master_search_bases = id_ctx->ipa_options->master_domain_search_bases;
    ctx->ranges_search_bases = id_ctx->ipa_options->ranges_search_bases;
    ctx->configured_explicit = configured_explicit;
    ctx->disabled_until = 0;
    *ops = &ipa_subdomains_ops;
    *pvt_data = ctx;

    ret = be_add_online_cb(ctx, be_ctx, ipa_subdom_online_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom online callback"));
    }

    ret = be_add_offline_cb(ctx, be_ctx, ipa_subdom_offline_cb, ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to add subdom offline callback"));
    }

    return EOK;
}
