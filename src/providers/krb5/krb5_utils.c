/*
    SSSD

    Kerberos 5 Backend Module -- Utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <string.h>
#include <stdlib.h>
#include <libgen.h>

#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_auth.h"
#include "src/util/find_uid.h"
#include "util/util.h"

errno_t find_or_guess_upn(TALLOC_CTX *mem_ctx, struct ldb_message *msg,
                          struct krb5_ctx *krb5_ctx,
                          struct sss_domain_info *dom, const char *user,
                          const char *user_dom, char **_upn)
{
    const char *upn;
    int ret;

    upn = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    if (upn == NULL) {
        ret = krb5_get_simple_upn(mem_ctx, krb5_ctx, dom, user,
                                  user_dom, _upn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("krb5_get_simple_upn failed.\n"));
            return ret;
        }
    } else {
        *_upn = talloc_strdup(mem_ctx, upn);
        if (*_upn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            return ENOMEM;
        }
    }

    return EOK;
}

errno_t check_if_cached_upn_needs_update(struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         const char *user,
                                         const char *upn)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret;
    const char *attrs[] = {SYSDB_UPN, NULL};
    struct sysdb_attrs *new_attrs;
    struct ldb_result *res;
    bool in_transaction = false;
    const char *cached_upn;

    if (sysdb == NULL || user == NULL || upn == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = sysdb_get_user_attr(tmp_ctx, sysdb, domain, user, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_get_user_attr failed.\n"));
        goto done;
    }

    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("[%d] user objects for name [%s] found, " \
                                  "expected 1.\n", res->count, user));
        ret = EINVAL;
        goto done;
    }

    cached_upn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_UPN, NULL);

    if (cached_upn != NULL && strcmp(cached_upn, upn) == 0) {
        DEBUG(SSSDBG_TRACE_ALL, ("Cached UPN and new one match, "
                                 "nothing to do.\n"));
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, ("Replacing UPN [%s] with [%s] for user [%s].\n",
                              cached_upn, upn, user));

    new_attrs = sysdb_new_attrs(tmp_ctx);
    if (new_attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_new_attrs failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(new_attrs, SYSDB_UPN, upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Error %d starting transaction (%s)\n", ret, strerror(ret)));
        goto done;
    }
    in_transaction = true;

    ret = sysdb_set_entry_attr(sysdb, res->msgs[0]->dn, new_attrs,
                               SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_set_entry_attr failed [%d][%s].\n",
                                  ret, strerror(ret)));
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

#define S_EXP_UID "{uid}"
#define L_EXP_UID (sizeof(S_EXP_UID) - 1)
#define S_EXP_USERID "{USERID}"
#define L_EXP_USERID (sizeof(S_EXP_USERID) - 1)
#define S_EXP_EUID "{euid}"
#define L_EXP_EUID (sizeof(S_EXP_EUID) - 1)
#define S_EXP_USERNAME "{username}"
#define L_EXP_USERNAME (sizeof(S_EXP_USERNAME) - 1)

char *expand_ccname_template(TALLOC_CTX *mem_ctx, struct krb5child_req *kr,
                             const char *template, bool file_mode,
                             bool case_sensitive, bool *private_path)
{
    char *copy;
    char *p;
    char *n;
    char *result = NULL;
    char *dummy;
    char *name;
    char *res = NULL;
    const char *cache_dir_tmpl;
    TALLOC_CTX *tmp_ctx = NULL;
    char action;
    bool rerun;

    *private_path = false;

    if (template == NULL) {
        DEBUG(1, ("Missing template.\n"));
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    copy = talloc_strdup(tmp_ctx, template);
    if (copy == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        goto done;
    }

    result = talloc_strdup(tmp_ctx, "");
    if (result == NULL) {
        DEBUG(1, ("talloc_strdup failed.\n"));
        goto done;
    }

    p = copy;
    while ( (n = strchr(p, '%')) != NULL) {
        *n = '\0';
        n++;
        if ( *n == '\0' ) {
            DEBUG(1, ("format error, single %% at the end of the template.\n"));
            goto done;
        }

        rerun = true;
        action = *n;
        while (rerun) {
            rerun = false;
            switch (action) {
            case 'u':
                if (kr->pd->user == NULL) {
                    DEBUG(1, ("Cannot expand user name template "
                              "because user name is empty.\n"));
                    goto done;
                }
                name = sss_get_cased_name(tmp_ctx, kr->pd->user,
                                          case_sensitive);
                if (!name) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          ("sss_get_cased_name failed\n"));
                    goto done;
                }

                result = talloc_asprintf_append(result, "%s%s", p,
                                                name);
                if (!file_mode) *private_path = true;
                break;
            case 'U':
                if (kr->uid <= 0) {
                    DEBUG(1, ("Cannot expand uid template "
                              "because uid is invalid.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->uid);
                if (!file_mode) *private_path = true;
                break;
            case 'p':
                if (kr->upn == NULL) {
                    DEBUG(1, ("Cannot expand user principal name template "
                              "because upn is empty.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->upn);
                if (!file_mode) *private_path = true;
                break;
            case '%':
                result = talloc_asprintf_append(result, "%s%%", p);
                break;
            case 'r':
                dummy = dp_opt_get_string(kr->krb5_ctx->opts, KRB5_REALM);
                if (dummy == NULL) {
                    DEBUG(1, ("Missing kerberos realm.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, dummy);
                break;
            case 'h':
                if (kr->homedir == NULL) {
                    DEBUG(1, ("Cannot expand home directory template "
                              "because the path is not available.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%s", p, kr->homedir);
                if (!file_mode) *private_path = true;
                break;
            case 'd':
                if (file_mode) {
                    cache_dir_tmpl = dp_opt_get_string(kr->krb5_ctx->opts,
                                                       KRB5_CCACHEDIR);
                    if (cache_dir_tmpl == NULL) {
                        DEBUG(1, ("Missing credential cache directory.\n"));
                        goto done;
                    }

                    dummy = expand_ccname_template(tmp_ctx, kr, cache_dir_tmpl,
                                                   false, case_sensitive,
                                                   private_path);
                    if (dummy == NULL) {
                        DEBUG(1, ("Expanding credential cache directory "
                                  "template failed.\n"));
                        goto done;
                    }
                    result = talloc_asprintf_append(result, "%s%s", p, dummy);
                    talloc_zfree(dummy);
                } else {
                    DEBUG(1, ("'%%d' is not allowed in this template.\n"));
                    goto done;
                }
                break;
            case 'P':
                if (!file_mode) {
                    DEBUG(1, ("'%%P' is not allowed in this template.\n"));
                    goto done;
                }
                if (kr->pd->cli_pid == 0) {
                    DEBUG(1, ("Cannot expand PID template "
                              "because PID is not available.\n"));
                    goto done;
                }
                result = talloc_asprintf_append(result, "%s%d", p,
                                                kr->pd->cli_pid);
                break;

            /* Additional syntax from krb5.conf default_ccache_name */
            case '{':
                if (strncmp(n , S_EXP_UID, L_EXP_UID) == 0) {
                    action = 'U';
                    n += L_EXP_UID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_USERID, L_EXP_USERID) == 0) {
                    action = 'U';
                    n += L_EXP_USERID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_EUID, L_EXP_EUID) == 0) {
                    /* SSSD does not distinguish betwen uid and euid,
                     * so we treat both the same way */
                    action = 'U';
                    n += L_EXP_EUID - 1;
                    rerun = true;
                    continue;
                } else if (strncmp(n , S_EXP_USERNAME, L_EXP_USERNAME) == 0) {
                    action = 'u';
                    n += L_EXP_USERNAME - 1;
                    rerun = true;
                    continue;
                } else {
                    /* ignore any expansion variable we do not understand and
                     * let libkrb5 hndle it or fail */
                    name = n;
                    n = strchr(name, '}');
                    if (!n) {
                        DEBUG(SSSDBG_CRIT_FAILURE, (
                              "Invalid substitution sequence in cache "
                              "template. Missing closing '}' in [%s].\n",
                              template));
                        goto done;
                    }
                    result = talloc_asprintf_append(result, "%s%%%.*s", p,
                                                    (int)(n - name + 1), name);
                }
                break;
            default:
                DEBUG(1, ("format error, unknown template [%%%c].\n", *n));
                goto done;
            }
        }

        if (result == NULL) {
            DEBUG(1, ("talloc_asprintf_append failed.\n"));
            goto done;
        }

        p = n + 1;
    }

    result = talloc_asprintf_append(result, "%s", p);
    if (result == NULL) {
        DEBUG(1, ("talloc_asprintf_append failed.\n"));
        goto done;
    }

    res = talloc_move(mem_ctx, &result);
done:
    talloc_zfree(tmp_ctx);
    return res;
}

static errno_t check_parent_stat(bool private_path, struct stat *parent_stat,
                                 uid_t uid, gid_t gid)
{
    if (private_path) {
        if (!((parent_stat->st_uid == 0 && parent_stat->st_gid == 0) ||
               parent_stat->st_uid == uid)) {
            DEBUG(1, ("Private directory can only be created below a "
                      "directory belonging to root or to [%d][%d].\n",
                      uid, gid));
            return EINVAL;
        }

        if (parent_stat->st_uid == uid) {
            if (!(parent_stat->st_mode & S_IXUSR)) {
                DEBUG(1, ("Parent directory does have the search bit set for "
                          "the owner.\n"));
                return EINVAL;
            }
        } else {
            if (!(parent_stat->st_mode & S_IXOTH)) {
                DEBUG(1, ("Parent directory does have the search bit set for "
                        "others.\n"));
                return EINVAL;
            }
        }
    } else {
        if (parent_stat->st_uid != 0 || parent_stat->st_gid != 0) {
            DEBUG(1, ("Public directory cannot be created below a user "
                      "directory.\n"));
            return EINVAL;
        }

        if (!(parent_stat->st_mode & S_IXOTH)) {
            DEBUG(1, ("Parent directory does have the search bit set for "
                      "others.\n"));
            return EINVAL;
        }
    }

    return EOK;
}

struct string_list {
    struct string_list *next;
    struct string_list *prev;
    char *s;
};

static errno_t find_ccdir_parent_data(TALLOC_CTX *mem_ctx,
                                      const char *ccdirname,
                                      struct stat *parent_stat,
                                      struct string_list **missing_parents)
{
    int ret = EFAULT;
    char *parent = NULL;
    char *end;
    struct string_list *li;

    ret = stat(ccdirname, parent_stat);
    if (ret == EOK) {
        if ( !S_ISDIR(parent_stat->st_mode) ) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("[%s] is not a directory.\n", ccdirname));
            return EINVAL;
        }
        return EOK;
    } else {
        if (errno != ENOENT) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("stat for [%s] failed: [%d][%s].\n", ccdirname, ret,
                   strerror(ret)));
            return ret;
        }
    }

    li = talloc_zero(mem_ctx, struct string_list);
    if (li == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    li->s = talloc_strdup(li, ccdirname);
    if (li->s == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("talloc_strdup failed.\n"));
        return ENOMEM;
    }

    DLIST_ADD(*missing_parents, li);

    parent = talloc_strdup(mem_ctx, ccdirname);
    if (parent == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("talloc_strdup failed.\n"));
        return ENOMEM;
    }

    /* We'll remove all trailing slashes from the back so that
     * we only pass /some/path to find_ccdir_parent_data, not
     * /some/path */
    do {
        end = strrchr(parent, '/');
        if (end == NULL || end == parent) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Cannot find parent directory of [%s], / is not allowed.\n",
                   ccdirname));
            ret = EINVAL;
            goto done;
        }
        *end = '\0';
    } while (*(end+1) == '\0');

    ret = find_ccdir_parent_data(mem_ctx, parent, parent_stat, missing_parents);

done:
    talloc_free(parent);
    return ret;
}

static errno_t
check_ccache_re(const char *filename, pcre *illegal_re)
{
    errno_t ret;

    ret = pcre_exec(illegal_re, NULL, filename, strlen(filename),
                    0, 0, NULL, 0);
    if (ret == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Illegal pattern in ccache directory name [%s].\n", filename));
        return EINVAL;
    } else if (ret == PCRE_ERROR_NOMATCH) {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("Ccache directory name [%s] does not contain "
               "illegal patterns.\n", filename));
        return EOK;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, ("pcre_exec failed [%d].\n", ret));
    return EFAULT;
}

errno_t
create_ccache_dir(const char *ccdirname, pcre *illegal_re,
                  uid_t uid, gid_t gid, bool private_path)
{
    int ret = EFAULT;
    struct stat parent_stat;
    struct string_list *missing_parents = NULL;
    struct string_list *li = NULL;
    mode_t old_umask;
    mode_t new_dir_mode;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("talloc_new failed.\n"));
        return ENOMEM;
    }

    if (*ccdirname != '/') {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Only absolute paths are allowed, not [%s] .\n", ccdirname));
        ret = EINVAL;
        goto done;
    }

    if (illegal_re != NULL) {
        ret = check_ccache_re(ccdirname, illegal_re);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = find_ccdir_parent_data(tmp_ctx, ccdirname, &parent_stat,
                                 &missing_parents);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("find_ccdir_parent_data failed.\n"));
        goto done;
    }

    ret = check_parent_stat(private_path, &parent_stat, uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("check_parent_stat failed for %s directory [%s].\n",
               private_path ? "private" : "public", ccdirname));
        goto done;
    }

    DLIST_FOR_EACH(li, missing_parents) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Creating directory [%s].\n", li->s));
        if (li->next == NULL) {
            new_dir_mode = private_path ? 0700 : 01777;
        } else {
            if (private_path &&
                parent_stat.st_uid == uid && parent_stat.st_gid == gid) {
                new_dir_mode = 0700;
            } else {
                new_dir_mode = 0755;
            }
        }

        old_umask = umask(0000);
        ret = mkdir(li->s, new_dir_mode);
        umask(old_umask);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("mkdir [%s] failed: [%d][%s].\n", li->s, ret,
                   strerror(ret)));
            goto done;
        }
        if (private_path &&
            ((parent_stat.st_uid == uid && parent_stat.st_gid == gid) ||
             li->next == NULL)) {
            ret = chown(li->s, uid, gid);
            if (ret != EOK) {
                ret = errno;
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("chown failed [%d][%s].\n", ret, strerror(ret)));
                goto done;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t get_ccache_file_data(const char *ccache_file, const char *client_name,
                             struct tgt_times *tgtt)
{
    krb5_error_code kerr;
    krb5_context ctx = NULL;
    krb5_ccache cc = NULL;
    krb5_principal client_princ = NULL;
    krb5_principal server_princ = NULL;
    char *server_name;
    krb5_creds mcred;
    krb5_creds cred;
    const char *realm_name;
    int realm_length;

    kerr = krb5_init_context(&ctx);
    if (kerr != 0) {
        DEBUG(1, ("krb5_init_context failed.\n"));
        goto done;
    }

    kerr = krb5_parse_name(ctx, client_name, &client_princ);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_parse_name failed.\n"));
        goto done;
    }

    sss_krb5_princ_realm(ctx, client_princ, &realm_name, &realm_length);

    server_name = talloc_asprintf(NULL, "krbtgt/%.*s@%.*s",
                                  realm_length, realm_name,
                                  realm_length, realm_name);
    if (server_name == NULL) {
        kerr = KRB5_CC_NOMEM;
        DEBUG(1, ("talloc_asprintf failed.\n"));
        goto done;
    }

    kerr = krb5_parse_name(ctx, server_name, &server_princ);
    talloc_free(server_name);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_parse_name failed.\n"));
        goto done;
    }

    kerr = krb5_cc_resolve(ctx, ccache_file, &cc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_resolve failed.\n"));
        goto done;
    }

    memset(&mcred, 0, sizeof(mcred));
    memset(&cred, 0, sizeof(mcred));

    mcred.server = server_princ;
    mcred.client = client_princ;

    kerr = krb5_cc_retrieve_cred(ctx, cc, 0, &mcred, &cred);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_retrieve_cred failed.\n"));
        goto done;
    }

    tgtt->authtime = cred.times.authtime;
    tgtt->starttime = cred.times.starttime;
    tgtt->endtime = cred.times.endtime;
    tgtt->renew_till = cred.times.renew_till;

    krb5_free_cred_contents(ctx, &cred);

    kerr = krb5_cc_close(ctx, cc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, ctx, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_close failed.\n"));
        goto done;
    }
    cc = NULL;

    kerr = 0;

done:
    if (cc != NULL) {
        krb5_cc_close(ctx, cc);
    }

    if (client_princ != NULL) {
        krb5_free_principal(ctx, client_princ);
    }

    if (server_princ != NULL) {
        krb5_free_principal(ctx, server_princ);
    }

    if (ctx != NULL) {
        krb5_free_context(ctx);
    }

    if (kerr != 0) {
        return EIO;
    }

    return EOK;
}

static errno_t
create_ccache_dir_head(const char *parent, pcre *illegal_re,
                       uid_t uid, gid_t gid, bool private_path)
{
    char *ccdirname;
    TALLOC_CTX *tmp_ctx = NULL;
    char *end;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ccdirname = talloc_strdup(tmp_ctx, parent);
    if (ccdirname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    /* We'll remove all trailing slashes from the back so that
     * we only pass /some/path to find_ccdir_parent_data, not
     * /some/path/ */
    do {
        end = strrchr(ccdirname, '/');
        if (end == NULL || end == ccdirname) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot find parent directory of [%s], "
                  "/ is not allowed.\n", ccdirname));
            ret = EINVAL;
            goto done;
        }
        *end = '\0';
    } while (*(end+1) == '\0');

    ret = create_ccache_dir(ccdirname, illegal_re, uid, gid, private_path);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
check_cc_validity(const char *location,
                  const char *realm,
                  const char *princ,
                  bool *_valid)
{
    errno_t ret;
    bool valid = false;
    krb5_ccache ccache = NULL;
    krb5_context context = NULL;
    krb5_error_code krberr;

    krberr = krb5_init_context(&context);
    if (krberr) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to init kerberos context\n"));
        return EIO;
    }

    krberr = krb5_cc_resolve(context, location, &ccache);
    if (krberr == KRB5_FCC_NOFILE || ccache == NULL) {
        /* KRB5_FCC_NOFILE would be returned if the directory components
         * of the DIR cache do not exist, which is the case in /run
         * after a reboot
         */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("ccache %s is missing or empty\n", location));
        valid = false;
        ret = EOK;
        goto done;
    } else if (krberr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, context, krberr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_resolve failed.\n"));
        ret = EIO;
        goto done;
    }

    krberr = check_for_valid_tgt(context, ccache, realm, princ, &valid);
    if (krberr != EOK) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, context, krberr);
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not check if ccache contains a valid principal\n"));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_valid = valid;
    }
    if (ccache) krb5_cc_close(context, ccache);
    krb5_free_context(context);
    return ret;
}


struct sss_krb5_ccache {
    struct sss_creds *creds;
    krb5_context context;
    krb5_ccache ccache;
};

static int sss_free_krb5_ccache(void *mem)
{
    struct sss_krb5_ccache *cc = talloc_get_type(mem, struct sss_krb5_ccache);

    if (cc->ccache) {
        krb5_cc_close(cc->context, cc->ccache);
    }
    krb5_free_context(cc->context);
    restore_creds(cc->creds);
    return 0;
}

static errno_t sss_open_ccache_as_user(TALLOC_CTX *mem_ctx,
                                       const char *ccname,
                                       uid_t uid, gid_t gid,
                                       struct sss_krb5_ccache **ccache)
{
    struct sss_krb5_ccache *cc;
    krb5_error_code kerr;
    errno_t ret;

    cc = talloc_zero(mem_ctx, struct sss_krb5_ccache);
    if (!cc) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)cc, sss_free_krb5_ccache);

    ret = switch_creds(cc, uid, gid, 0, NULL, &cc->creds);
    if (ret) {
        goto done;
    }

    kerr = krb5_init_context(&cc->context);
    if (kerr) {
        ret = EIO;
        goto done;
    }

    kerr = krb5_cc_resolve(cc->context, ccname, &cc->ccache);
    if (kerr == KRB5_FCC_NOFILE || cc->ccache == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, ("ccache %s is missing or empty\n", ccname));
        ret = ERR_NOT_FOUND;
        goto done;
    } else if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_resolve failed.\n"));
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret) {
        talloc_free(cc);
    } else {
        *ccache = cc;
    }
    return ret;
}

static errno_t sss_destroy_ccache(struct sss_krb5_ccache *cc)
{
    krb5_error_code kerr;
    errno_t ret;

    kerr = krb5_cc_destroy(cc->context, cc->ccache);
    if (kerr) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_destroy failed.\n"));
        ret = EIO;
    }

    /* krb5_cc_destroy frees cc->ccache in all events */
    cc->ccache = NULL;

    return ret;
}

errno_t sss_krb5_cc_destroy(const char *ccname, uid_t uid, gid_t gid)
{
    struct sss_krb5_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = sss_open_ccache_as_user(tmp_ctx, ccname, uid, gid, &cc);
    if (ret) {
        goto done;
    }

    ret = sss_destroy_ccache(cc);

done:
    talloc_free(tmp_ctx);
    return ret;
}


/* This function is called only as a way to validate that we have the
 * right cache */
errno_t sss_krb5_check_ccache_princ(uid_t uid, gid_t gid,
                                    const char *ccname, const char *principal)
{
    struct sss_krb5_ccache *cc = NULL;
    krb5_principal ccprinc = NULL;
    krb5_principal kprinc = NULL;
    krb5_error_code kerr;
    const char *cc_type;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = sss_open_ccache_as_user(tmp_ctx, ccname, uid, gid, &cc);
    if (ret) {
        goto done;
    }

    cc_type = krb5_cc_get_type(cc->context, cc->ccache);

    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("Searching for [%s] in cache of type [%s]\n", principal, cc_type));

    kerr = krb5_parse_name(cc->context, principal, &kprinc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_parse_name failed.\n"));
        ret = ERR_INTERNAL;
        goto done;
    }

    kerr = krb5_cc_get_principal(cc->context, cc->ccache, &ccprinc);
    if (kerr != 0) {
        KRB5_DEBUG(SSSDBG_OP_FAILURE, cc->context, kerr);
        DEBUG(SSSDBG_CRIT_FAILURE, ("krb5_cc_get_principal failed.\n"));
    }

    if (ccprinc) {
        if (krb5_principal_compare(cc->context, kprinc, ccprinc) == TRUE) {
            /* found in the primary ccache */
            ret = EOK;
            goto done;
        }
    }

#ifdef HAVE_KRB5_CC_COLLECTION

    if (krb5_cc_support_switch(cc->context, cc_type)) {

        krb5_cc_close(cc->context, cc->ccache);
        cc->ccache = NULL;

        kerr = krb5_cc_set_default_name(cc->context, ccname);
        if (kerr != 0) {
            KRB5_DEBUG(SSSDBG_MINOR_FAILURE, cc->context, kerr);
            /* try to continue despite failure */
        }

        kerr = krb5_cc_cache_match(cc->context, kprinc, &cc->ccache);
        if (kerr == 0) {
            ret = EOK;
            goto done;
        }
        KRB5_DEBUG(SSSDBG_TRACE_INTERNAL, cc->context, kerr);
    }

#endif /* HAVE_KRB5_CC_COLLECTION */

    ret = ERR_NOT_FOUND;

done:
    krb5_free_principal(cc->context, ccprinc);
    krb5_free_principal(cc->context, kprinc);
    talloc_free(tmp_ctx);
    return ret;
}

/*======== ccache back end utilities ========*/
struct sss_krb5_cc_be *
get_cc_be_ops(enum sss_krb5_cc_type type)
{
    struct sss_krb5_cc_be *be = NULL;

    switch (type) {
        case SSS_KRB5_TYPE_FILE:
            be = &file_cc;
            break;

#ifdef HAVE_KRB5_CC_COLLECTION
        case SSS_KRB5_TYPE_DIR:
            be = &dir_cc;
            break;

        case SSS_KRB5_TYPE_KEYRING:
            be = &keyring_cc;
            break;
#endif /* HAVE_KRB5_CC_COLLECTION */

        case SSS_KRB5_TYPE_UNKNOWN:
            be = NULL;
            break;
    }

    return be;
}

struct sss_krb5_cc_be *
get_cc_be_ops_ccache(const char *ccache)
{
    enum sss_krb5_cc_type type;

    type = sss_krb5_get_type(ccache);
    return get_cc_be_ops(type);
}

/*======== Operations on the FILE: back end ========*/
errno_t
cc_file_create(const char *location, pcre *illegal_re,
               uid_t uid, gid_t gid, bool private_path)
{
    const char *filename;

    filename = sss_krb5_residual_check_type(location, SSS_KRB5_TYPE_FILE);
    if (filename == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Bad ccache type %s\n", location));
        return EINVAL;
    }

    return create_ccache_dir_head(filename, illegal_re, uid, gid, private_path);
}

static errno_t
cc_residual_is_used(uid_t uid, const char *ccname,
                    enum sss_krb5_cc_type type, bool *result)
{
    int ret;
    struct stat stat_buf;
    bool active;

    *result = false;

    if (ccname == NULL || *ccname == '\0') {
        return EINVAL;
    }

    ret = lstat(ccname, &stat_buf);

    if (ret == -1) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_FUNC_DATA, ("Cache file [%s] does not exist, "
                                     "it will be recreated\n", ccname));
            *result = false;
            return ENOENT;
        }

        DEBUG(SSSDBG_OP_FAILURE,
              ("stat failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    if (stat_buf.st_uid != uid) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cache file [%s] exists, but is owned by [%d] instead of "
               "[%d].\n", ccname, stat_buf.st_uid, uid));
        return EINVAL;
    }

    switch (type) {
#ifdef HAVE_KRB5_CC_COLLECTION
        case SSS_KRB5_TYPE_DIR:
            ret = S_ISDIR(stat_buf.st_mode);
            break;
#endif /* HAVE_KRB5_CC_COLLECTION */
        case SSS_KRB5_TYPE_FILE:
            ret = S_ISREG(stat_buf.st_mode);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unsupported ccache type\n"));
            return EINVAL;
    }

    if (ret == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cache file [%s] exists, but is not the expected type\n",
              ccname));
        return EINVAL;
    }

    ret = check_if_uid_is_active(uid, &active);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("check_if_uid_is_active failed.\n"));
        return ret;
    }

    if (!active) {
        DEBUG(SSSDBG_TRACE_FUNC, ("User [%d] is not active\n", uid));
    } else {
        DEBUG(SSSDBG_TRACE_LIBS,
              ("User [%d] is still active, reusing ccache [%s].\n",
              uid, ccname));
        *result = true;
    }
    return EOK;
}

static void
cc_check_template(const char *cc_template)
{
    size_t template_len;

    template_len = strlen(cc_template);
    if (template_len >= 6 &&
        strcmp(cc_template + (template_len - 6), "XXXXXX") != 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, ("ccache file name template [%s] doesn't "
                   "contain randomizing characters (XXXXXX), file might not "
                   "be rewritable\n", cc_template));
    }
}

errno_t
cc_file_check_existing(const char *location, uid_t uid,
                       const char *realm, const char *princ,
                       const char *cc_template, bool *_active, bool *_valid)
{
    errno_t ret;
    bool active;
    bool valid;
    const char *filename;

    filename = sss_krb5_residual_check_type(location, SSS_KRB5_TYPE_FILE);
    if (!filename) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("%s is not of type FILE:\n", location));
        return EINVAL;
    }

    if (filename[0] != '/') {
        DEBUG(SSSDBG_OP_FAILURE, ("Only absolute path names are allowed.\n"));
        return EINVAL;
    }

    ret = cc_residual_is_used(uid, filename, SSS_KRB5_TYPE_FILE, &active);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Could not check if ccache is active.\n"));
        }
        cc_check_template(cc_template);
        active = false;
        return ret;
    }

    ret = check_cc_validity(location, realm, princ, &valid);
    if (ret != EOK) {
        return ret;
    }

    *_active = active;
    *_valid = valid;
    return EOK;
}

struct sss_krb5_cc_be file_cc = {
    .type               = SSS_KRB5_TYPE_FILE,
    .create             = cc_file_create,
    .check_existing     = cc_file_check_existing,
};

#ifdef HAVE_KRB5_CC_COLLECTION
/*======== Operations on the DIR: back end ========*/
errno_t
cc_dir_create(const char *location, pcre *illegal_re,
              uid_t uid, gid_t gid, bool private_path)
{
    const char *dir_name;

    dir_name = sss_krb5_residual_check_type(location, SSS_KRB5_TYPE_DIR);
    if (dir_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad residual type\n"));
        return EINVAL;
    }

    return create_ccache_dir_head(dir_name, illegal_re, uid, gid, private_path);
}

errno_t
cc_dir_check_existing(const char *location, uid_t uid,
                      const char *realm, const char *princ,
                      const char *cc_template, bool *_active, bool *_valid)
{
    bool active;
    bool active_primary = false;
    bool valid;
    enum sss_krb5_cc_type type;
    const char *filename;
    const char *dir;
    char *tmp;
    char *primary_file;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;

    type = sss_krb5_get_type(location);
    if (type != SSS_KRB5_TYPE_DIR) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("%s is not of type DIR:\n", location));
        return EINVAL;
    }

    filename = sss_krb5_cc_file_path(location);
    if (!filename) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Existing ccname does not contain path into the collection"));
        return EINVAL;
    }

    if (filename[0] != '/') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Only absolute path names are allowed.\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    tmp = talloc_strdup(tmp_ctx, filename);
    if (!tmp) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    if (0 == strncmp(location, "DIR::", 5)) {
        dir = dirname(tmp);
        if (!dir) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Cannot get base directory of %s.\n", tmp));
            ret = EINVAL;
            goto done;
        }
    } else {
        dir = tmp;
    }

    ret = cc_residual_is_used(uid, dir, SSS_KRB5_TYPE_DIR, &active);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Could not check if ccache is active.\n"));
        }
        cc_check_template(cc_template);
        goto done;
    }

    /* If primary file isn't in ccache dir, we will ignore it.
     * But if primary file has wrong permissions, we will fail.
     */
    primary_file = talloc_asprintf(tmp_ctx, "%s/primary", dir);
    if (!primary_file) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf failed.\n"));
        ret = ENOMEM;
        goto done;
    }
    ret = cc_residual_is_used(uid, primary_file, SSS_KRB5_TYPE_FILE,
                              &active_primary);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not check if file 'primary' [%s] in dir ccache"
               " is active.\n", primary_file));
        goto done;
    }

    ret = check_cc_validity(location, realm, princ, &valid);
    if (ret != EOK) {
        goto done;
    }

    *_active = active;
    *_valid = valid;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sss_krb5_cc_be dir_cc = {
    .type               = SSS_KRB5_TYPE_DIR,
    .create             = cc_dir_create,
    .check_existing     = cc_dir_check_existing,
};


/*======== Operations on the KEYRING: back end ========*/

errno_t
cc_keyring_create(const char *location, pcre *illegal_re,
                  uid_t uid, gid_t gid, bool private_path)
{
    const char *residual;

    residual = sss_krb5_residual_check_type(location, SSS_KRB5_TYPE_KEYRING);
    if (residual == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Bad ccache type %s\n", location));
        return EINVAL;
    }

    /* No special steps are needed to create a kernel keyring.
     * Everything is handled in libkrb5.
     */
    return EOK;
}

errno_t
cc_keyring_check_existing(const char *location, uid_t uid,
                          const char *realm, const char *princ,
                          const char *cc_template, bool *_active,
                          bool *_valid)
{
    errno_t ret;
    bool active;
    bool valid;
    const char *residual;

    residual = sss_krb5_residual_check_type(location, SSS_KRB5_TYPE_KEYRING);
    if (!residual) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("%s is not of type KEYRING:\n", location));
        return EINVAL;
    }

    /* The keyring cache is always active */
    active = true;

    /* Check if any user is actively using this cache */
    ret = check_cc_validity(location, realm, princ, &valid);
    if (ret != EOK) {
        return ret;
    }

    *_active = active;
    *_valid = valid;
    return EOK;
}

struct sss_krb5_cc_be keyring_cc = {
    .type               = SSS_KRB5_TYPE_KEYRING,
    .create             = cc_keyring_create,
    .check_existing     = cc_keyring_check_existing,
};

#endif /* HAVE_KRB5_CC_COLLECTION */

errno_t get_domain_or_subdomain(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                                char *domain_name,
                                struct sss_domain_info **dom)
{

    if (domain_name != NULL &&
        strcasecmp(domain_name, be_ctx->domain->name) != 0) {
        *dom = find_subdomain_by_name(be_ctx->domain, domain_name, true);
        if (*dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("find_subdomain_by_name failed.\n"));
            return ENOMEM;
        }
    } else {
        *dom = be_ctx->domain;
    }

    return EOK;
}
