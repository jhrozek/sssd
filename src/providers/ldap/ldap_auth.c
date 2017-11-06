/*
    SSSD

    LDAP Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2008 Red Hat
    Copyright (C) 2010, rhafer@suse.de, Novell Inc.

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

#ifdef WITH_MOZLDAP
#define LDAP_OPT_SUCCESS LDAP_SUCCESS
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID  ((ber_tag_t) 0x80U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_OLD ((ber_tag_t) 0x81U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ((ber_tag_t) 0x82U)
#endif

#define _XOPEN_SOURCE 500 /* for strptime() */
#include <time.h>
#undef _XOPEN_SOURCE
#include <errno.h>
#include <sys/time.h>
#include <strings.h>

#include <shadow.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/user_info_msg.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"

/* MIT Kerberos has the same hardcoded warning interval of 7 days. Due to the
 * fact that using the expiration time of a Kerberos password with LDAP
 * authentication is presumably a rare case a separate config option is not
 * necessary. */
#define KERBEROS_PWEXPIRE_WARNING_TIME (7 * 24 * 60 * 60)

enum pwexpire {
    PWEXPIRE_NONE = 0,
    PWEXPIRE_LDAP_PASSWORD_POLICY,
    PWEXPIRE_KERBEROS,
    PWEXPIRE_SHADOW
};

static errno_t add_expired_warning(struct pam_data *pd, long exp_time)
{
    int ret;
    uint32_t *data;

    if (exp_time < 0 || exp_time > UINT32_MAX) {
        DEBUG(1, ("Time to expire out of range.\n"));
        return EINVAL;
    }

    data = talloc_array(pd, uint32_t, 2);
    if (data == NULL) {
        DEBUG(1, ("talloc_size failed.\n"));
        return ENOMEM;
    }

    data[0] = SSS_PAM_USER_INFO_EXPIRE_WARN;
    data[1] = (uint32_t) exp_time;

    ret = pam_add_response(pd, SSS_PAM_USER_INFO, 2 * sizeof(uint32_t),
                           (uint8_t *) data);
    if (ret != EOK) {
        DEBUG(1, ("pam_add_response failed.\n"));
    }

    return EOK;
}

static errno_t check_pwexpire_kerberos(const char *expire_date, time_t now,
                                       struct pam_data *pd,
                                       enum sdap_result *result)
{
    char *end;
    struct tm tm;
    time_t expire_time;
    int ret;

    memset(&tm, 0, sizeof(tm));

    *result = SDAP_AUTH_FAILED;

    end = strptime(expire_date, "%Y%m%d%H%M%SZ", &tm);
    if (end == NULL) {
        DEBUG(1, ("Kerberos expire date [%s] invalid.\n", expire_date));
        return EINVAL;
    }
    if (*end != '\0') {
        DEBUG(1, ("Kerberos expire date [%s] contains extra characters.\n",
                  expire_date));
        return EINVAL;
    }

    expire_time = mktime(&tm);
    if (expire_time == -1) {
        DEBUG(1, ("mktime failed to convert [%s].\n", expire_date));
        return EINVAL;
    }

    tzset();
    expire_time -= timezone;
    DEBUG(9, ("Time info: tzname[0] [%s] tzname[1] [%s] timezone [%d] "
              "daylight [%d] now [%d] expire_time [%d].\n", tzname[0],
              tzname[1], timezone, daylight, now, expire_time));

    if (difftime(now, expire_time) > 0.0) {
        DEBUG(4, ("Kerberos password expired.\n"));
        *result = SDAP_AUTH_PW_EXPIRED;
    } else {
        *result = SDAP_AUTH_SUCCESS;

        if (pd != NULL &&
            difftime(now + KERBEROS_PWEXPIRE_WARNING_TIME, expire_time) > 0.0) {
            ret = add_expired_warning(pd, (long) difftime(expire_time, now));
            if (ret != EOK) {
                DEBUG(1, ("add_expired_warning failed.\n"));
            }
        }
    }

    return EOK;
}

static errno_t check_pwexpire_shadow(struct spwd *spwd, time_t now,
                                     struct pam_data *pd,
                                     enum sdap_result *result)
{
    long today;
    long password_age;
    long exp;
    int ret;

    if (spwd->sp_lstchg <= 0) {
        DEBUG(4, ("Last change day is not set, new password needed.\n"));
        *result = SDAP_AUTH_PW_EXPIRED;
        return EOK;
    }

    today = (long) (now / (60 * 60 *24));
    password_age = today - spwd->sp_lstchg;
    if (password_age < 0) {
        DEBUG(2, ("The last password change time is in the future!.\n"));
        *result = SDAP_AUTH_SUCCESS;
        return EOK;
    }

    if ((spwd->sp_expire != -1 && today > spwd->sp_expire) ||
        (spwd->sp_max != -1 && spwd->sp_inact != -1 &&
         password_age > spwd->sp_max + spwd->sp_inact))
    {
        DEBUG(4, ("Account expired.\n"));
        *result = SDAP_ACCT_EXPIRED;
        return EOK;
    }

    if (spwd->sp_max != -1 && password_age > spwd->sp_max) {
        DEBUG(4, ("Password expired.\n"));
        *result = SDAP_AUTH_PW_EXPIRED;
        return EOK;
    }

    if (pd != NULL && spwd->sp_max != -1 && spwd->sp_warn != -1 &&
        password_age > spwd->sp_max - spwd->sp_warn ) {

        /* add_expired_warning() expects time in seconds */
        exp = (spwd->sp_max - password_age) * (60 * 60 * 24);
        if (exp == 0) {
            /* Seconds until next midnight */
            exp = ((today + 1) * (60 * 60 * 24)) - now;
        }

        ret = add_expired_warning(pd, exp);
        if (ret != EOK) {
            DEBUG(1, ("add_expired_warning failed.\n"));
        }
    }

    *result = SDAP_AUTH_SUCCESS;
    return EOK;
}

static errno_t check_pwexpire_ldap(struct pam_data *pd,
                                   struct sdap_ppolicy_data *ppolicy,
                                   enum sdap_result *result)
{
    if (ppolicy->grace > 0 || ppolicy->expire > 0) {
        uint32_t *data;
        uint32_t *ptr;

        data = talloc_size(pd, 2* sizeof(uint32_t));
        if (data == NULL) {
            DEBUG(1, ("talloc_size failed.\n"));
            return ENOMEM;
        }

        ptr = data;
        if (ppolicy->grace > 0) {
            *ptr = SSS_PAM_USER_INFO_GRACE_LOGIN;
            ptr++;
            *ptr = ppolicy->grace;
        } else if (ppolicy->expire > 0) {
            *ptr = SSS_PAM_USER_INFO_EXPIRE_WARN;
            ptr++;
            *ptr = ppolicy->expire;
        }

        pam_add_response(pd, SSS_PAM_USER_INFO, 2* sizeof(uint32_t),
                         (uint8_t*)data);
    }

    *result = SDAP_AUTH_SUCCESS;
    return EOK;
}

static errno_t string_to_shadowpw_days(const char *s, long *d)
{
    long l;
    char *endptr;

    if (s == NULL || *s == '\0') {
        *d = -1;
        return EOK;
    }

    errno = 0;
    l = strtol(s, &endptr, 10);
    if (errno != 0) {
        DEBUG(1, ("strtol failed [%d][%s].\n", errno, strerror(errno)));
        return errno;
    }

    if (*endptr != '\0') {
        DEBUG(1, ("Input string [%s] is invalid.\n", s));
        return EINVAL;
    }

    if (*d < -1) {
        DEBUG(1, ("Input string contains not allowed negative value [%d].\n",
                  *d));
        return EINVAL;
    }

    *d = l;

    return EOK;
}

static errno_t find_password_expiration_attributes(TALLOC_CTX *mem_ctx,
                                               const struct ldb_message *msg,
                                               struct dp_option *opts,
                                               enum pwexpire *type, void **data)
{
    const char *mark;
    const char *val;
    struct spwd *spwd;
    const char *pwd_policy;
    int ret;

    *type = PWEXPIRE_NONE;
    *data = NULL;

    pwd_policy = dp_opt_get_string(opts, SDAP_PWD_POLICY);
    if (pwd_policy == NULL) {
        DEBUG(1, ("Missing password policy.\n"));
        return EINVAL;
    }

    mark = ldb_msg_find_attr_as_string(msg, SYSDB_PWD_ATTRIBUTE, NULL);
    if (mark != NULL) {
        DEBUG(9, ("Found pwdAttribute, "
                  "assuming LDAP password policies are active.\n"));

        *type = PWEXPIRE_LDAP_PASSWORD_POLICY;
        return EOK;
    }

    if (strcasecmp(pwd_policy, PWD_POL_OPT_NONE) == 0) {
        DEBUG(9, ("No password policy requested.\n"));
        return EOK;
    } else if (strcasecmp(pwd_policy, PWD_POL_OPT_MIT) == 0) {
        mark = ldb_msg_find_attr_as_string(msg, SYSDB_KRBPW_LASTCHANGE, NULL);
        if (mark != NULL) {
            DEBUG(9, ("Found Kerberos password expiration attributes.\n"))
            val = ldb_msg_find_attr_as_string(msg, SYSDB_KRBPW_EXPIRATION,
                                              NULL);
            if (val != NULL) {
                *data = talloc_strdup(mem_ctx, val);
                if (*data == NULL) {
                    DEBUG(1, ("talloc_strdup failed.\n"));
                    return ENOMEM;
                }
                *type = PWEXPIRE_KERBEROS;

                return EOK;
            }
        } else {
            DEBUG(1, ("No Kerberos password expiration attributes found, "
                      "but MIT Kerberos password policy was requested.\n"));
            return EINVAL;
        }
    } else if (strcasecmp(pwd_policy, PWD_POL_OPT_SHADOW) == 0) {
        mark = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_LASTCHANGE, NULL);
        if (mark != NULL) {
            DEBUG(9, ("Found shadow password expiration attributes.\n"))
            spwd = talloc_zero(mem_ctx, struct spwd);
            if (spwd == NULL) {
                DEBUG(1, ("talloc failed.\n"));
                return ENOMEM;
            }

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_LASTCHANGE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_lstchg);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_MIN, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_min);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_MAX, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_max);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_WARNING, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_warn);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_INACTIVE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_inact);
            if (ret != EOK) goto shadow_fail;

            val = ldb_msg_find_attr_as_string(msg, SYSDB_SHADOWPW_EXPIRE, NULL);
            ret = string_to_shadowpw_days(val, &spwd->sp_expire);
            if (ret != EOK) goto shadow_fail;

            *data = spwd;
            *type = PWEXPIRE_SHADOW;

            return EOK;
        } else {
            DEBUG(1, ("No shadow password attributes found, "
                      "but shadow password policy was requested.\n"));
            return EINVAL;
        }
    }

    DEBUG(9, ("No password expiration attributes found.\n"));
    return EOK;

shadow_fail:
        talloc_free(spwd);
        return ret;
}

/* ==Get-User-DN========================================================== */

struct get_user_dn_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *ctx;
    struct sdap_handle *sh;

    const char **attrs;
    const char *name;

    char *dn;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
};

static void get_user_dn_done(void *pvt, int err, struct ldb_result *res);

struct tevent_req *get_user_dn_send(TALLOC_CTX *memctx,
                                    struct tevent_context *ev,
                                    struct sdap_auth_ctx *ctx,
                                    struct sdap_handle *sh,
                                    const char *username)
{
    struct tevent_req *req;
    struct get_user_dn_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct get_user_dn_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->sh = sh;
    state->name = username;

    state->attrs = talloc_array(state, const char *, 11);
    if (!state->attrs) {
        talloc_zfree(req);
        return NULL;
    }
    state->attrs[0] = SYSDB_ORIG_DN;
    state->attrs[1] = SYSDB_SHADOWPW_LASTCHANGE;
    state->attrs[2] = SYSDB_SHADOWPW_MIN;
    state->attrs[3] = SYSDB_SHADOWPW_MAX;
    state->attrs[4] = SYSDB_SHADOWPW_WARNING;
    state->attrs[5] = SYSDB_SHADOWPW_INACTIVE;
    state->attrs[6] = SYSDB_SHADOWPW_EXPIRE;
    state->attrs[7] = SYSDB_KRBPW_LASTCHANGE;
    state->attrs[8] = SYSDB_KRBPW_EXPIRATION;
    state->attrs[9] = SYSDB_PWD_ATTRIBUTE;
    state->attrs[10] = NULL;

    /* this sysdb call uses a sysdn operation, which means it will be
     * schedule only after we return, no timer hack needed */
    ret = sysdb_get_user_attr(state, state->ctx->be->sysdb,
                              state->ctx->be->domain, state->name,
                              state->attrs, get_user_dn_done, req);
    if (ret) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void get_user_dn_done(void *pvt, int err, struct ldb_result *res)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct get_user_dn_state *state = tevent_req_data(req,
                                           struct get_user_dn_state);
    const char *dn;
    int ret;

    if (err != LDB_SUCCESS) {
        tevent_req_error(req, EIO);
        return;
    }

    switch (res->count) {
    case 0:
        /* FIXME: not in cache, needs a true search */
        tevent_req_error(req, ENOENT);
        break;

    case 1:
        dn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_ORIG_DN, NULL);
        if (!dn) {
            /* TODO: try to search ldap server ? */

            /* FIXME: remove once we store originalDN on every call
             * NOTE: this is wrong, works only with some DITs */
            dn = talloc_asprintf(state, "%s=%s,%s",
                        state->ctx->opts->user_map[SDAP_AT_USER_NAME].name,
                        state->name,
                        dp_opt_get_string(state->ctx->opts->basic,
                                          SDAP_USER_SEARCH_BASE));
            if (!dn) {
                tevent_req_error(req, ENOMEM);
                break;
            }
        }

        state->dn = talloc_strdup(state, dn);
        if (!state->dn) {
            tevent_req_error(req, ENOMEM);
            break;
        }

        ret = find_password_expiration_attributes(state, res->msgs[0],
                                                  state->ctx->opts->basic,
                                                  &state->pw_expire_type,
                                                  &state->pw_expire_data);
        if (ret != EOK) {
            DEBUG(1, ("find_password_expiration_attributes failed.\n"));
            tevent_req_error(req, ENOMEM);
            break;
        }

        tevent_req_done(req);
        break;

    default:
        DEBUG(1, ("A user search by name (%s) returned > 1 results!\n",
                  state->name));
        tevent_req_error(req, EFAULT);
        break;
    }
}

static int get_user_dn_recv(struct tevent_req *req,
                            TALLOC_CTX *memctx, char **dn,
                            enum pwexpire *pw_expire_type,
                            void **pw_expire_data)
{
    struct get_user_dn_state *state = tevent_req_data(req,
                                           struct get_user_dn_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dn = talloc_steal(memctx, state->dn);
    if (!*dn) return ENOMEM;

    /* state->pw_expire_data may be NULL */
    *pw_expire_data = talloc_steal(memctx, state->pw_expire_data);

    *pw_expire_type = state->pw_expire_type;

    return EOK;
}

/* ==Authenticate-User==================================================== */

struct auth_state {
    struct tevent_context *ev;
    struct sdap_auth_ctx *ctx;
    const char *username;
    struct dp_opt_blob password;

    struct sdap_handle *sh;

    enum sdap_result result;
    char *dn;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;

    struct fo_server *srv;
};

static struct tevent_req *auth_get_server(struct tevent_req *req);
static void auth_resolve_done(struct tevent_req *subreq);
static void auth_connect_done(struct tevent_req *subreq);
static void auth_get_user_dn_done(struct tevent_req *subreq);
static void auth_bind_user_done(struct tevent_req *subreq);

static struct tevent_req *auth_send(TALLOC_CTX *memctx,
                                    struct tevent_context *ev,
                                    struct sdap_auth_ctx *ctx,
                                    const char *username,
                                    struct dp_opt_blob password)
{
    struct tevent_req *req;
    struct auth_state *state;

    req = tevent_req_create(memctx, &state, struct auth_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->username = username;
    state->password = password;
    state->srv = NULL;

    if (!auth_get_server(req)) goto fail;

    return req;

fail:
    talloc_zfree(req);
    return NULL;
}

static struct tevent_req *auth_get_server(struct tevent_req *req)
{
    struct tevent_req *next_req;
    struct auth_state *state = tevent_req_data(req,
                                               struct auth_state);

     /* NOTE: this call may cause service->uri to be refreshed
      * with a new valid server. Do not use service->uri before */
    next_req = be_resolve_server_send(state,
                                      state->ev,
                                      state->ctx->be,
                                      state->ctx->service->name);
    if (!next_req) {
        DEBUG(1, ("be_resolve_server_send failed.\n"));
        return NULL;
    }

    tevent_req_set_callback(next_req, auth_resolve_done, req);
    return next_req;
}

static void auth_resolve_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = be_resolve_server_recv(subreq, &state->srv);
    talloc_zfree(subreq);
    if (ret) {
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;
    }

    subreq = sdap_connect_send(state, state->ev, state->ctx->opts,
                               state->ctx->service->uri, true);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_connect_done, req);
}

static void auth_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = sdap_connect_recv(subreq, state, &state->sh);
    talloc_zfree(subreq);
    if (ret) {
        if (state->srv) {
            /* mark this server as bad if connection failed */
            fo_set_port_status(state->srv, PORT_NOT_WORKING);
        }
        if (ret == ETIMEDOUT) {
            if (auth_get_server(req) == NULL) {
                tevent_req_error(req, ENOMEM);
            }
            return;
        }

        tevent_req_error(req, ret);
        return;
    } else if (state->srv) {
        fo_set_port_status(state->srv, PORT_WORKING);
    }

    subreq = get_user_dn_send(state, state->ev,
                              state->ctx, state->sh,
                              state->username);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_get_user_dn_done, req);
}

static void auth_get_user_dn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;

    ret = get_user_dn_recv(subreq, state, &state->dn, &state->pw_expire_type,
                           &state->pw_expire_data);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_auth_send(state, state->ev, state->sh,
                            NULL, NULL, state->dn,
                            "password", state->password);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, auth_bind_user_done, req);
}

static void auth_bind_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct auth_state *state = tevent_req_data(req,
                                                    struct auth_state);
    int ret;
    struct sdap_ppolicy_data *ppolicy;

    ret = sdap_auth_recv(subreq, state, &state->result, &ppolicy);
    if (ppolicy != NULL) {
        DEBUG(9,("Found ppolicy data, "
                 "assuming LDAP password policies are active.\n"));
        state->pw_expire_type = PWEXPIRE_LDAP_PASSWORD_POLICY;
        state->pw_expire_data = ppolicy;
    }
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int auth_recv(struct tevent_req *req,
              TALLOC_CTX *memctx,
              struct sdap_handle **sh,
              enum sdap_result *result, char **dn,
              enum pwexpire *pw_expire_type, void **pw_expire_data)
{
    struct auth_state *state = tevent_req_data(req, struct auth_state);
    enum tevent_req_state tstate;
    uint64_t err;

    if (tevent_req_is_error(req, &tstate, &err)) {
        switch (tstate) {
        case TEVENT_REQ_USER_ERROR:
            if (err == ETIMEDOUT) *result = SDAP_UNAVAIL;
            else *result = SDAP_ERROR;
            return err;
        default:
            *result = SDAP_ERROR;
            return EIO;
        }
    }

    if (sh != NULL) {
        *sh = talloc_steal(memctx, state->sh);
        if (*sh == NULL) return ENOMEM;
    }

    if (dn != NULL) {
        *dn = talloc_steal(memctx, state->dn);
        if (*dn == NULL) return ENOMEM;
    }

    if (pw_expire_data != NULL) {
        *pw_expire_data = talloc_steal(memctx, state->pw_expire_data);
    }

    *pw_expire_type = state->pw_expire_type;

    *result = state->result;
    return EOK;
}

/* ==Perform-Password-Change===================== */

struct sdap_pam_chpass_state {
    struct be_req *breq;
    struct pam_data *pd;
    const char *username;
    char *dn;
    char *password;
    char *new_password;
    struct sdap_handle *sh;
};

static void sdap_auth4chpass_done(struct tevent_req *req);
static void sdap_pam_chpass_done(struct tevent_req *req);
static void sdap_pam_auth_reply(struct be_req *breq, int dp_err, int result);

void sdap_pam_chpass_handler(struct be_req *breq)
{
    struct sdap_pam_chpass_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;
    struct dp_opt_blob authtok;
    int dp_err = DP_ERR_FATAL;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                          struct sdap_auth_ctx);
    pd = talloc_get_type(breq->req_data, struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if (pd->priv == 1 && pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM &&
        pd->authtok_size == 0) {
        DEBUG(4, ("Password reset by root is not supported.\n"));
        pd->pam_status = PAM_PERM_DENIED;
        dp_err = DP_ERR_OK;
        goto done;
    }

    DEBUG(2, ("starting password change request for user [%s].\n", pd->user));

    pd->pam_status = PAM_SYSTEM_ERR;

    if (pd->cmd != SSS_PAM_CHAUTHTOK && pd->cmd != SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(2, ("chpass target was called by wrong pam command.\n"));
        goto done;
    }

    state = talloc_zero(breq, struct sdap_pam_chpass_state);
    if (!state) goto done;

    state->breq = breq;
    state->pd = pd;
    state->username = pd->user;
    state->password = talloc_strndup(state,
                                     (char *)pd->authtok, pd->authtok_size);
    if (!state->password) goto done;
    talloc_set_destructor((TALLOC_CTX *)state->password,
                          password_destructor);

    if (pd->cmd == SSS_PAM_CHAUTHTOK) {
        state->new_password = talloc_strndup(state,
                                             (char *)pd->newauthtok,
                                             pd->newauthtok_size);
        if (!state->new_password) goto done;
        talloc_set_destructor((TALLOC_CTX *)state->new_password,
                              password_destructor);
    }

    authtok.data = (uint8_t *)state->password;
    authtok.length = strlen(state->password);
    subreq = auth_send(breq, breq->be_ctx->ev,
                       ctx, state->username, authtok);
    if (!subreq) goto done;

    tevent_req_set_callback(subreq, sdap_auth4chpass_done, state);
    return;

done:
    sdap_pam_auth_reply(breq, dp_err, pd->pam_status);
}

static void sdap_auth4chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    struct tevent_req *subreq;
    enum sdap_result result;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    int dp_err = DP_ERR_FATAL;
    int ret;

    ret = auth_recv(req, state, &state->sh,
                    &result, &state->dn,
                    &pw_expire_type, &pw_expire_data);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    if ( (result == SDAP_AUTH_SUCCESS || result == SDAP_AUTH_PW_EXPIRED ) &&
        state->pd->cmd == SSS_PAM_CHAUTHTOK_PRELIM) {
        DEBUG(9, ("Initial authentication for change password operation "
                  "successful.\n"));
        state->pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        goto done;
    }

    if (result == SDAP_AUTH_SUCCESS) {
        switch (pw_expire_type) {
            case PWEXPIRE_SHADOW:
                ret = check_pwexpire_shadow(pw_expire_data, time(NULL), NULL,
                                            &result);
                if (ret != EOK) {
                    DEBUG(1, ("check_pwexpire_shadow failed.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                break;
            case PWEXPIRE_KERBEROS:
                ret = check_pwexpire_kerberos(pw_expire_data, time(NULL), NULL,
                                              &result);
                if (ret != EOK) {
                    DEBUG(1, ("check_pwexpire_kerberos failed.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }

                if (result == SDAP_AUTH_PW_EXPIRED) {
                    DEBUG(1, ("LDAP provider cannot change kerberos "
                              "passwords.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                break;
            case PWEXPIRE_LDAP_PASSWORD_POLICY:
            case PWEXPIRE_NONE:
                break;
            default:
                DEBUG(1, ("Unknow pasword expiration type.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
        }
    }

    switch (result) {
    case SDAP_AUTH_SUCCESS:
    case SDAP_AUTH_PW_EXPIRED:
        DEBUG(7, ("user [%s] successfully authenticated.\n", state->dn));
        if (pw_expire_type == PWEXPIRE_SHADOW) {
/* TODO: implement async ldap modify request */
            DEBUG(1, ("Changing shadow password attributes not implemented.\n"));
            state->pd->pam_status = PAM_MODULE_UNKNOWN;
            goto done;
        } else {
            subreq = sdap_exop_modify_passwd_send(state,
                                                  state->breq->be_ctx->ev,
                                                  state->sh,
                                                  state->dn,
                                                  state->password,
                                                  state->new_password);

            if (!subreq) {
                DEBUG(2, ("Failed to change password for %s\n", state->username));
                goto done;
            }

            tevent_req_set_callback(subreq, sdap_pam_chpass_done, state);
            return;
        }
        break;
    case SDAP_AUTH_FAILED:
        state->pd->pam_status = PAM_AUTH_ERR;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
    }

done:
    sdap_pam_auth_reply(state->breq, dp_err, state->pd->pam_status);
}

static void sdap_pam_chpass_done(struct tevent_req *req)
{
    struct sdap_pam_chpass_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_chpass_state);
    enum sdap_result result;
    int dp_err = DP_ERR_FATAL;
    int ret;
    char *user_error_message = NULL;
    size_t msg_len;
    uint8_t *msg;

    ret = sdap_exop_modify_passwd_recv(req, state, &result, &user_error_message);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    switch (result) {
    case SDAP_SUCCESS:
        state->pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        break;
    default:
        state->pd->pam_status = PAM_AUTHTOK_ERR;
        if (user_error_message != NULL) {
            ret = pack_user_info_chpass_error(state->pd, user_error_message,
                                              &msg_len, &msg);
            if (ret != EOK) {
                DEBUG(1, ("pack_user_info_chpass_error failed.\n"));
            } else {
                ret = pam_add_response(state->pd, SSS_PAM_USER_INFO, msg_len,
                                       msg);
                if (ret != EOK) {
                    DEBUG(1, ("pam_add_response failed.\n"));
                }
            }
        }
    }

done:
    sdap_pam_auth_reply(state->breq, dp_err, state->pd->pam_status);
}
/* ==Perform-User-Authentication-and-Password-Caching===================== */

struct sdap_pam_auth_state {
    struct be_req *breq;
    struct pam_data *pd;
    const char *username;
    struct dp_opt_blob password;
};

static void sdap_pam_auth_done(struct tevent_req *req);
static void sdap_password_cache_done(struct tevent_req *req);

void sdap_pam_auth_handler(struct be_req *breq)
{
    struct sdap_pam_auth_state *state;
    struct sdap_auth_ctx *ctx;
    struct tevent_req *subreq;
    struct pam_data *pd;
    int dp_err = DP_ERR_FATAL;

    ctx = talloc_get_type(breq->be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                          struct sdap_auth_ctx);
    pd = talloc_get_type(breq->req_data, struct pam_data);

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
    case SSS_PAM_CHAUTHTOK_PRELIM:

        state = talloc_zero(breq, struct sdap_pam_auth_state);
        if (!state) goto done;

        state->breq = breq;
        state->pd = pd;
        state->username = pd->user;
        state->password.data = pd->authtok;
        state->password.length = pd->authtok_size;

        subreq = auth_send(breq, breq->be_ctx->ev, ctx,
                           state->username, state->password);
        if (!subreq) goto done;

        tevent_req_set_callback(subreq, sdap_pam_auth_done, state);
        return;

    case SSS_PAM_CHAUTHTOK:
        break;

    case SSS_PAM_ACCT_MGMT:
    case SSS_PAM_SETCRED:
    case SSS_PAM_OPEN_SESSION:
    case SSS_PAM_CLOSE_SESSION:
        pd->pam_status = PAM_SUCCESS;
        dp_err = DP_ERR_OK;
        break;
    default:
        pd->pam_status = PAM_MODULE_UNKNOWN;
        dp_err = DP_ERR_OK;
    }

done:
    sdap_pam_auth_reply(breq, dp_err, pd->pam_status);
}

static void sdap_pam_auth_done(struct tevent_req *req)
{
    struct sdap_pam_auth_state *state =
                    tevent_req_callback_data(req, struct sdap_pam_auth_state);
    struct tevent_req *subreq;
    enum sdap_result result;
    enum pwexpire pw_expire_type;
    void *pw_expire_data;
    int dp_err = DP_ERR_OK;
    int ret;

    ret = auth_recv(req, state, NULL,
                    &result, NULL,
                    &pw_expire_type, &pw_expire_data);
    talloc_zfree(req);
    if (ret) {
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_FATAL;
        goto done;
    }

    if (result == SDAP_AUTH_SUCCESS) {
        switch (pw_expire_type) {
            case PWEXPIRE_SHADOW:
                ret = check_pwexpire_shadow(pw_expire_data, time(NULL),
                                            state->pd, &result);
                if (ret != EOK) {
                    DEBUG(1, ("check_pwexpire_shadow failed.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                break;
            case PWEXPIRE_KERBEROS:
                ret = check_pwexpire_kerberos(pw_expire_data, time(NULL),
                                              state->pd, &result);
                if (ret != EOK) {
                    DEBUG(1, ("check_pwexpire_kerberos failed.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                break;
            case PWEXPIRE_LDAP_PASSWORD_POLICY:
                ret = check_pwexpire_ldap(state->pd, pw_expire_data, &result);
                if (ret != EOK) {
                    DEBUG(1, ("check_pwexpire_ldap failed.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
                }
                break;
            case PWEXPIRE_NONE:
                break;
            default:
                DEBUG(1, ("Unknow pasword expiration type.\n"));
                    state->pd->pam_status = PAM_SYSTEM_ERR;
                    goto done;
        }
    }

    switch (result) {
    case SDAP_AUTH_SUCCESS:
        state->pd->pam_status = PAM_SUCCESS;
        break;
    case SDAP_AUTH_FAILED:
        state->pd->pam_status = PAM_PERM_DENIED;
        break;
    case SDAP_UNAVAIL:
        state->pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        break;
    case SDAP_ACCT_EXPIRED:
        state->pd->pam_status = PAM_ACCT_EXPIRED;
        break;
    case SDAP_AUTH_PW_EXPIRED:
        state->pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        break;
    default:
        state->pd->pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_FATAL;
    }

    if (result == SDAP_UNAVAIL) {
        be_mark_offline(state->breq->be_ctx);
        dp_err = DP_ERR_OFFLINE;
        goto done;
    }

    if (result == SDAP_AUTH_SUCCESS &&
        state->breq->be_ctx->domain->cache_credentials) {

        char *password = talloc_strndup(state, (char *)
                                        state->password.data,
                                        state->password.length);
        /* password caching failures are not fatal errors */
        if (!password) {
            DEBUG(2, ("Failed to cache password for %s\n", state->username));
            goto done;
        }
        talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

        subreq = sysdb_cache_password_send(state,
                                           state->breq->be_ctx->ev,
                                           state->breq->be_ctx->sysdb,
                                           NULL,
                                           state->breq->be_ctx->domain,
                                           state->username, password);

        /* password caching failures are not fatal errors */
        if (!subreq) {
            DEBUG(2, ("Failed to cache password for %s\n", state->username));
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_password_cache_done, state);
        return;
    }

done:
    sdap_pam_auth_reply(state->breq, dp_err, state->pd->pam_status);
}

static void sdap_password_cache_done(struct tevent_req *subreq)
{
    struct sdap_pam_auth_state *state = tevent_req_callback_data(subreq,
                                                struct sdap_pam_auth_state);
    int ret;

    ret = sysdb_cache_password_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        /* password caching failures are not fatal errors */
        DEBUG(2, ("Failed to cache password for %s\n", state->username));
    } else {
        DEBUG(4, ("Password successfully cached for %s\n", state->username));
    }

    sdap_pam_auth_reply(state->breq, DP_ERR_OK, state->pd->pam_status);
}

static void sdap_pam_auth_reply(struct be_req *req, int dp_err, int result)
{
    req->fn(req, dp_err, result, NULL);
}

