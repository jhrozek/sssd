/*
    SSSD

    Kerberos 5 Backend Module -- Renew a TGT automatically

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2010 Red Hat

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
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"

#define INITIAL_TGT_TABLE_SIZE 10

struct renew_tgt_ctx {
    hash_table_t *tgt_table;
    struct be_ctx *be_ctx;
    struct tevent_context *ev;
    struct krb5_ctx *krb5_ctx;
    time_t timer_interval;
    struct tevent_timer *te;
    bool added_to_online_callbacks;
};

struct renew_data {
    const char *ccfile;
    time_t start_time;
    time_t lifetime;
    time_t start_renew_at;
    struct pam_data *pd;
};

struct auth_data {
    struct be_ctx *be_ctx;
    struct krb5_ctx *krb5_ctx;
    struct pam_data *pd;
    struct renew_data *renew_data;
    hash_table_t *table;
    hash_key_t key;
};


static void renew_tgt_done(struct tevent_req *req);
static void renew_tgt(struct tevent_context *ev, struct tevent_timer *te,
                      struct timeval current_time, void *private_data)
{
    struct auth_data *auth_data = talloc_get_type(private_data,
                                                  struct auth_data);
    struct tevent_req *req;

    req = krb5_auth_send(auth_data, ev, auth_data->be_ctx, auth_data->pd,
                         auth_data->krb5_ctx);
    if (req == NULL) {
        DEBUG(1, ("krb5_auth_send failed.\n"));
/* Give back the pam data to the renewal item to be able to retry at the next
 * time the renewals re run. */
        auth_data->renew_data->pd = talloc_steal(auth_data->renew_data,
                                                 auth_data->pd);
        talloc_free(auth_data);
        return;
    }

    tevent_req_set_callback(req, renew_tgt_done, auth_data);
}

static void renew_tgt_done(struct tevent_req *req)
{
    struct auth_data *auth_data = tevent_req_callback_data(req,
                                                           struct auth_data);
    int ret;
    int pam_status = PAM_SYSTEM_ERR;
    int dp_err;
    hash_value_t value;

    ret = krb5_auth_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    if (ret) {
        DEBUG(1, ("krb5_auth request failed.\n"));
        if (auth_data->renew_data != NULL) {
            DEBUG(5, ("Giving back pam data.\n"));
            auth_data->renew_data->pd = talloc_steal(auth_data->renew_data,
                                                     auth_data->pd);
        }
    } else {
        switch (pam_status) {
            case PAM_SUCCESS:
                DEBUG(4, ("Successfully renewed TGT for user [%s].\n",
                          auth_data->pd->user));
/* In general a successful renewal will update the renewal item and free the
 * old data. But if the TGT has reached the end of his renewable lifetime it
 * will not be put into the list of renewable tickets again. In this case the
 * renewal item is not updated and the value from the hash and the one we have
 * stored are the same. Since the TGT cannot be renewed anymore we want to
 * remove it from the list of renewable tickets. */
                ret = hash_lookup(auth_data->table, &auth_data->key, &value);
                if (ret == HASH_SUCCESS) {
                    if (value.type == HASH_VALUE_PTR &&
                        auth_data->renew_data == talloc_get_type(value.ptr,
                                                           struct renew_data)) {
                        DEBUG(5, ("New TGT was not added for renewal, "
                                  "removing list entry for user [%s].\n",
                                  auth_data->pd->user));
                        ret = hash_delete(auth_data->table, &auth_data->key);
                        if (ret != HASH_SUCCESS) {
                            DEBUG(1, ("hash_delete failed.\n"));
                        }
                    }
                }
                break;
            case PAM_AUTHINFO_UNAVAIL:
            case PAM_AUTHTOK_LOCK_BUSY:
                DEBUG(4, ("Cannot renewed TGT for user [%s] while offline, "
                          "will retry later.\n",
                          auth_data->pd->user));
                if (auth_data->renew_data != NULL) {
                    DEBUG(5, ("Giving back pam data.\n"));
                    auth_data->renew_data->pd = talloc_steal(auth_data->renew_data,
                                                             auth_data->pd);
                }
                break;
            default:
                DEBUG(1, ("Failed to renew TGT for user [%s].\n",
                          auth_data->pd->user));
                ret = hash_delete(auth_data->table, &auth_data->key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(1, ("hash_delete failed.\n"));
                }
        }
    }

    talloc_zfree(auth_data);
}

static errno_t renew_all_tgts(struct renew_tgt_ctx *renew_tgt_ctx)
{
    int ret;
    hash_entry_t *entries;
    unsigned long count;
    size_t c;
    time_t now;
    struct auth_data *auth_data;
    struct renew_data *renew_data;
    struct tevent_timer *te;

    ret = hash_entries(renew_tgt_ctx->tgt_table, &count, &entries);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_entries failed.\n"));
        return ENOMEM;
    }

    now = time(NULL);

    for (c = 0; c < count; c++) {
        renew_data = talloc_get_type(entries[c].value.ptr, struct renew_data);
        DEBUG(9, ("Checking [%s] for renewal at [%.24s].\n", renew_data->ccfile,
                  ctime(&renew_data->start_renew_at)));
        /* If renew_data->pd == NULL a renewal request for this data is
         * currently running so we skip it. */
        if (renew_data->start_renew_at < now && renew_data->pd != NULL) {
            auth_data = talloc_zero(renew_tgt_ctx, struct auth_data);
            if (auth_data == NULL) {
                DEBUG(1, ("talloc_zero failed.\n"));
            } else {
/* We need to steal the pam_data here, because a successful renewal of the
 * ticket might add a new renewal item to the list with the same key (upn).
 * This would delete renew_data and all its children. But we cannot be sure
 * that adding the new renewal item is the last operation of the renewal
 * process with access the pam_data. To be on the safe side we steal the
 * pam_data and make it a child of auth_data which is only freed after the
 * renewal process is finished. In the case of an error during renewal we
 * might want to steal the pam_data back to renew_data before freeing
 * auth_data to allow a new renewal attempt. */
                auth_data->pd = talloc_move(auth_data, &renew_data->pd);
                auth_data->krb5_ctx = renew_tgt_ctx->krb5_ctx;
                auth_data->be_ctx = renew_tgt_ctx->be_ctx;
                auth_data->table = renew_tgt_ctx->tgt_table;
                auth_data->renew_data = renew_data;
                auth_data->key.type = entries[c].key.type;
                auth_data->key.str = talloc_strdup(auth_data,
                                                   entries[c].key.str);
                if (auth_data->key.str == NULL) {
                    DEBUG(1, ("talloc_strdup failed.\n"));
                    te = NULL;
                } else {
                    te = tevent_add_timer(renew_tgt_ctx->ev,
                                          auth_data, tevent_timeval_current(),
                                          renew_tgt, auth_data);
                    if (te == NULL) {
                        DEBUG(1, ("tevent_add_timer failed.\n"));
                    }
                }
            }

            if (auth_data == NULL || te == NULL) {
                DEBUG(1, ("Failed to renew TGT in [%s].\n", renew_data->ccfile));
                ret = hash_delete(renew_tgt_ctx->tgt_table, &entries[c].key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(1, ("hash_delete failed.\n"));
                }
            }
        }
    }

    talloc_free(entries);

    return EOK;
}

static void renew_handler(struct renew_tgt_ctx *renew_tgt_ctx);

static void renew_tgt_online_callback(void *private_data)
{
    struct renew_tgt_ctx *renew_tgt_ctx = talloc_get_type(private_data,
                                                          struct renew_tgt_ctx);

    renew_tgt_ctx->added_to_online_callbacks = false;
    renew_handler(renew_tgt_ctx);
}

static void renew_tgt_timer_handler(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval current_time, void *data)
{
    struct renew_tgt_ctx *renew_tgt_ctx = talloc_get_type(data,
                                                          struct renew_tgt_ctx);

    renew_handler(renew_tgt_ctx);
}

static void renew_handler(struct renew_tgt_ctx *renew_tgt_ctx)
{
    struct timeval next;
    int ret;

    if (be_is_offline(renew_tgt_ctx->be_ctx)) {
        if (renew_tgt_ctx->added_to_online_callbacks) {
            DEBUG(3, ("Renewal task was already added to online callbacks.\n"));
            return;
        }
        DEBUG(7, ("Offline, adding renewal task to online callbacks.\n"));
        ret = be_add_online_cb(renew_tgt_ctx->krb5_ctx, renew_tgt_ctx->be_ctx,
                               renew_tgt_online_callback, renew_tgt_ctx, NULL);
        if (ret == EOK) {
            renew_tgt_ctx->added_to_online_callbacks = true;
            return;
        }

        DEBUG(1, ("Failed to add the renewal task to online callbacks, "
                  "continue normal operation.\n"));
    } else {
        ret = renew_all_tgts(renew_tgt_ctx);
        if (ret != EOK) {
            DEBUG(1, ("renew_all_tgts failed. "
                      "Disabling automatic TGT renewal\n"));
            sss_log(SSS_LOG_ERR, "Disabling automatic TGT renewal.");
            talloc_zfree(renew_tgt_ctx);
            return;
        }
    }

    DEBUG(7, ("Adding new renew timer.\n"));

    next = tevent_timeval_current_ofs(renew_tgt_ctx->timer_interval,
                                      0);
    renew_tgt_ctx->te = tevent_add_timer(renew_tgt_ctx->ev, renew_tgt_ctx,
                                         next, renew_tgt_timer_handler,
                                         renew_tgt_ctx);
    if (renew_tgt_ctx->te == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        sss_log(SSS_LOG_ERR, "Disabling automatic TGT renewal.");
        talloc_zfree(renew_tgt_ctx);
    }

    return;
}

static void renew_del_cb(hash_entry_t *entry, hash_destroy_enum type, void *pvt)
{
    struct renew_data *renew_data;

    if (entry->value.type == HASH_VALUE_PTR) {
        renew_data = talloc_get_type(entry->value.ptr, struct renew_data);
        talloc_zfree(renew_data);
        return;
    }

    DEBUG(1, ("Unexpected value type [%d].\n", entry->value.type));
}

static errno_t check_ccache_file(struct renew_tgt_ctx *renew_tgt_ctx,
                                 const char *ccache_file, const char *upn,
                                 const char *user_name)
{
    int ret;
    struct stat stat_buf;
    struct tgt_times tgtt;
    struct pam_data pd;
    time_t now;
    const char *filename;

    if (ccache_file == NULL || upn == NULL || user_name == NULL) {
        DEBUG(6, ("Missing one of the needed attributes: [%s][%s][%s].\n",
                  ccache_file == NULL ? "cache file missing" : ccache_file,
                  upn == NULL ? "principal missing" : upn,
                  user_name == NULL ? "user name missing" : user_name));
        return EINVAL;
    }

    if (strncmp(ccache_file, "FILE:", 5) == 0) {
        filename = ccache_file + 5;
    } else {
        filename = ccache_file;
    }

    ret = stat(filename, &stat_buf);
    if (ret != EOK) {
        if (ret == ENOENT) {
            return EOK;
        }
        return ret;
    }

    DEBUG(9, ("Found ccache file [%s].\n", ccache_file));

    memset(&tgtt, 0, sizeof(tgtt));
    ret = get_ccache_file_data(ccache_file, upn, &tgtt);
    if (ret != EOK) {
        DEBUG(1, ("get_ccache_file_data failed.\n"));
        return ret;
    }

    memset(&pd, 0, sizeof(pd));
    pd.cmd = SSS_CMD_RENEW;
    pd.user = discard_const_p(char, user_name);
    now = time(NULL);
    if (tgtt.renew_till > tgtt.endtime && tgtt.renew_till > now &&
        tgtt.endtime > now) {
        DEBUG(7, ("Adding [%s] for automatic renewal.\n", ccache_file));
        ret = add_tgt_to_renew_table(renew_tgt_ctx->krb5_ctx, ccache_file,
                                     &tgtt, &pd, upn);
        if (ret != EOK) {
            DEBUG(1, ("add_tgt_to_renew_table failed, "
                      "automatic renewal not possible.\n"));
        }
    } else {
        DEBUG(9, ("TGT in [%s] for [%s] is too old.\n", ccache_file, upn));
    }

    return EOK;
}

static errno_t check_ccache_files(struct renew_tgt_ctx *renew_tgt_ctx)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    const char *ccache_filter = "("SYSDB_CCACHE_FILE"=*)";
    const char *ccache_attrs[] = { SYSDB_CCACHE_FILE, SYSDB_UPN, SYSDB_NAME,
                                   NULL };
    size_t msgs_count = 0;
    struct ldb_message **msgs = NULL;
    size_t c;
    const char *ccache_file;
    const char *upn;
    const char *user_name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(1, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = sysdb_search_users(tmp_ctx, renew_tgt_ctx->be_ctx->sysdb,
                             renew_tgt_ctx->be_ctx->domain, ccache_filter,
                             ccache_attrs, &msgs_count, &msgs);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_search_users failed.\n"));
        goto done;
    }

    if (msgs_count == 0) {
        DEBUG(9, ("No entries with ccache file found in cache.\n"));
        ret = EOK;
        goto done;
    }
    DEBUG(9, ("Found [%d] entries with ccache file in cache.\n", msgs_count));

    for (c = 0; c < msgs_count; c++) {
        user_name = ldb_msg_find_attr_as_string(msgs[c], SYSDB_NAME, NULL);
        if (user_name == NULL) {
            DEBUG(1, ("No user name found, this is a severe error, "
                      "but we ignore it here.\n"));
            continue;
        }

        upn = ldb_msg_find_attr_as_string(msgs[c], SYSDB_UPN, NULL);
        if (upn == NULL) {
            ret = krb5_get_simple_upn(tmp_ctx, renew_tgt_ctx->krb5_ctx,
                                      user_name, &upn);
            if (ret != EOK) {
                DEBUG(1, ("krb5_get_simple_upn failed.\n"));
                continue;
            }
            DEBUG(9, ("No upn stored in cache, using [%s].\n", upn));
        }

        ccache_file = ldb_msg_find_attr_as_string(msgs[c], SYSDB_CCACHE_FILE,
                                                  NULL);

        ret = check_ccache_file(renew_tgt_ctx, ccache_file, upn, user_name);
        if (ret != EOK) {
            DEBUG(5, ("Failed to check ccache file [%s].\n", ccache_file));
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t init_renew_tgt(struct krb5_ctx *krb5_ctx, struct be_ctx *be_ctx,
                       struct tevent_context *ev, time_t renew_intv)
{
    int ret;
    struct timeval next;

    krb5_ctx->renew_tgt_ctx = talloc_zero(krb5_ctx, struct renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ret = sss_hash_create_ex(krb5_ctx->renew_tgt_ctx, INITIAL_TGT_TABLE_SIZE,
                             &krb5_ctx->renew_tgt_ctx->tgt_table, 0, 0, 0, 0,
                             renew_del_cb, NULL);
    if (ret != EOK) {
        DEBUG(1, ("sss_hash_create failed.\n"));
        goto fail;
    }

    krb5_ctx->renew_tgt_ctx->be_ctx = be_ctx;
    krb5_ctx->renew_tgt_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->renew_tgt_ctx->ev = ev;
    krb5_ctx->renew_tgt_ctx->timer_interval = renew_intv;
    krb5_ctx->renew_tgt_ctx->added_to_online_callbacks = false;

    ret = check_ccache_files(krb5_ctx->renew_tgt_ctx);
    if (ret != EOK) {
        DEBUG(1, ("Failed to read ccache files, continuing ...\n"));
    }

    next = tevent_timeval_current_ofs(krb5_ctx->renew_tgt_ctx->timer_interval,
                                      0);
    krb5_ctx->renew_tgt_ctx->te = tevent_add_timer(ev, krb5_ctx->renew_tgt_ctx,
                                                   next, renew_tgt_timer_handler,
                                                   krb5_ctx->renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx->te == NULL) {
        DEBUG(1, ("tevent_add_timer failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    return EOK;

fail:
    talloc_zfree(krb5_ctx->renew_tgt_ctx);
    return ret;
}

errno_t add_tgt_to_renew_table(struct krb5_ctx *krb5_ctx, const char *ccfile,
                               struct tgt_times *tgtt, struct pam_data *pd,
                               const char *upn)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct renew_data *renew_data = NULL;

    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(7 ,("Renew context not initialized, "
                  "automatic renewal not available.\n"));
        return EOK;
    }

    if (pd->cmd != SSS_PAM_AUTHENTICATE && pd->cmd != SSS_CMD_RENEW &&
        pd->cmd != SSS_PAM_CHAUTHTOK) {
        DEBUG(1, ("Unexpected pam task [%d].\n", pd->cmd));
        return EINVAL;
    }

    if (upn == NULL) {
        DEBUG(1, ("Missing user principal name.\n"));
        return EINVAL;
    }

    /* hash_enter copies the content of the hash string, so it is safe to use
     * discard_const_p here. */
    key.type = HASH_KEY_STRING;
    key.str = discard_const_p(char, upn);

    renew_data = talloc_zero(krb5_ctx->renew_tgt_ctx, struct renew_data);
    if (renew_data == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    if (ccfile[0] == '/') {
        renew_data->ccfile = talloc_asprintf(renew_data, "FILE:%s", ccfile);
        if (renew_data->ccfile == NULL) {
            DEBUG(1, ("talloc_asprintf failed.\n"));
            ret = ENOMEM;
            goto done;
        }
    } else {
        renew_data->ccfile = talloc_strdup(renew_data, ccfile);
    }

    renew_data->start_time = tgtt->starttime;
    renew_data->lifetime = tgtt->endtime;
    renew_data->start_renew_at = (time_t) (tgtt->starttime +
                                        0.5 *(tgtt->endtime - tgtt->starttime));

    ret = copy_pam_data(renew_data, pd, &renew_data->pd);
    if (ret != EOK) {
        DEBUG(1, ("copy_pam_data failed.\n"));
        goto done;
    }

    if (renew_data->pd->newauthtok_type != SSS_AUTHTOK_TYPE_EMPTY) {
        talloc_zfree(renew_data->pd->newauthtok);
        renew_data->pd->newauthtok_size = 0;
        renew_data->pd->newauthtok_type = SSS_AUTHTOK_TYPE_EMPTY;
    }

    talloc_zfree(renew_data->pd->authtok);
    renew_data->pd->authtok = (uint8_t *) talloc_strdup(renew_data->pd,
                                                        renew_data->ccfile);
    if (renew_data->pd->authtok == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }
    renew_data->pd->authtok_size = strlen((char *) renew_data->pd->authtok) + 1;
    renew_data->pd->authtok_type = SSS_AUTHTOK_TYPE_CCFILE;

    renew_data->pd->cmd = SSS_CMD_RENEW;

    value.type = HASH_VALUE_PTR;
    value.ptr = renew_data;

    ret = hash_enter(krb5_ctx->renew_tgt_ctx->tgt_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_enter failed.\n"));
        ret = EFAULT;
        goto done;
    }

    DEBUG(7, ("Added [%s] for renewal at [%.24s].\n", renew_data->ccfile,
                                           ctime(&renew_data->start_renew_at)));

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(renew_data);
    }
    return ret;
}
