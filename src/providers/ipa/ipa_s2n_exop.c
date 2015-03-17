/*
    SSSD

    IPA Helper routines - external users and groups with s2n plugin

    Copyright (C) Sumit Bose <sbose@redhat.com> - 2011

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

#include "util/util.h"
#include "util/sss_nss.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_subdomains.h"

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL,
    REQ_FULL_WITH_MEMBERS
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP,
    RESP_USER_GROUPLIST,
    RESP_GROUP_MEMBERS
};

/* ==Sid2Name Extended Operation============================================= */
#define EXOP_SID2NAME_OID "2.16.840.1.113730.3.8.10.4"
#define EXOP_SID2NAME_V1_OID "2.16.840.1.113730.3.8.10.4.1"

struct ipa_s2n_exop_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    char *retoid;
    struct berval *retdata;
};

static void ipa_s2n_exop_done(struct sdap_op *op,
                           struct sdap_msg *reply,
                           int error, void *pvt);

static struct tevent_req *ipa_s2n_exop_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_handle *sh,
                                            bool is_v1,
                                            int timeout,
                                            struct berval *bv)
{
    struct tevent_req *req = NULL;
    struct ipa_s2n_exop_state *state;
    int ret;
    int msgid;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_exop_state);
    if (!req) return NULL;

    state->sh = sh;
    state->retoid = NULL;
    state->retdata = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Executing extended operation\n");

    ret = ldap_extended_operation(state->sh->ldap,
                               is_v1 ? EXOP_SID2NAME_V1_OID : EXOP_SID2NAME_OID,
                               bv, NULL, NULL, &msgid);
    if (ret == -1 || msgid == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_extended_operation failed\n");
        ret = ERR_NETWORK_IO;
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "ldap_extended_operation sent, msgid = %d\n",
                                  msgid);

    ret = sdap_op_add(state, ev, state->sh, msgid, ipa_s2n_exop_done, req,
                      timeout, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        ret = ERR_INTERNAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_s2n_exop_done(struct sdap_op *op,
                               struct sdap_msg *reply,
                               int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);
    int ret;
    char *errmsg = NULL;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    int result;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &result, NULL, &errmsg, NULL,
                            NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_result failed (%d)\n",
                                 state->op->msgid);
        ret = ERR_NETWORK_IO;
        goto done;
    }

    DEBUG(result == LDAP_SUCCESS ? SSSDBG_TRACE_FUNC : SSSDBG_OP_FAILURE,
          "ldap_extended_operation result: %s(%d), %s.\n",
          sss_ldap_err2string(result), result, errmsg);

    if (result != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_extended_operation failed, " \
                                 "server logs might contain more details.\n");
        ret = ERR_NETWORK_IO;
        goto done;
    }

    ret = ldap_parse_extended_result(state->sh->ldap, reply->msg,
                                      &retoid, &retdata, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_extendend_result failed (%d)\n",
                                 ret);
        ret = ERR_NETWORK_IO;
        goto done;
    }

    state->retoid = talloc_strdup(state, retoid);
    if (state->retoid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    state->retdata = talloc(state, struct berval);
    if (state->retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->retdata->bv_len = retdata->bv_len;
    state->retdata->bv_val = talloc_memdup(state->retdata, retdata->bv_val,
                                           retdata->bv_len);
    if (state->retdata->bv_val == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_memdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ldap_memfree(errmsg);
    ldap_memfree(retoid);
    ber_bvfree(retdata);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int ipa_s2n_exop_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             char **retoid, struct berval **retdata)
{
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *retoid = talloc_steal(mem_ctx, state->retoid);
    *retdata = talloc_steal(mem_ctx, state->retdata);

    return EOK;
}

static errno_t talloc_ber_flatten(TALLOC_CTX *mem_ctx, BerElement *ber,
                                  struct berval **_bv)
{
    int ret;
    struct berval *bv = NULL;
    struct berval *tbv = NULL;

    ret = ber_flatten(ber, &bv);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    tbv = talloc_zero(mem_ctx, struct berval);
    if (tbv == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tbv->bv_len = bv->bv_len;
    tbv->bv_val = talloc_memdup(tbv, bv->bv_val, bv->bv_len);
    if (tbv->bv_val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ber_bvfree(bv);
    if (ret == EOK) {
        *_bv = tbv;
    } else  {
        talloc_free(tbv);
    }

    return ret;
}

/* The extended operation expect the following ASN.1 encoded request data:
 *
 * ExtdomRequestValue ::= SEQUENCE {
 *    inputType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix uid (3),
 *        posix gid (3)
 *    },
 *    requestType ENUMERATED {
 *        simple (1),
 *        full (2)
 *        full_with_members (3)
 *    },
 *    data InputData
 * }
 *
 * InputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData
 *    uid PosixUid,
 *    gid PosixGid
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    uid INTEGER
 * }
 *
 * PosixGid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 */

static errno_t s2n_encode_request(TALLOC_CTX *mem_ctx,
                                  const char *domain_name,
                                  int entry_type,
                                  enum request_types request_type,
                                  struct req_input *req_input,
                                  struct berval **_bv)
{
    BerElement *ber = NULL;
    int ret;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        return ENOMEM;
    }

    switch (entry_type) {
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:  /* the extdom exop does not care if the
                                        ID belongs to a user or a group */
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, request_type,
                                                  domain_name,
                                                  req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_UID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID);
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_GROUP:
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, request_type,
                                                  domain_name,
                                                  req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_GID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID);
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_BY_SECID:
            if (req_input->type == REQ_INP_SECID) {
            ret = ber_printf(ber, "{ees}", INP_SID, request_type,
                                           req_input->inp.secid);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type == REQ_INP_ID);
                ret = EINVAL;
                goto done;
            }
            break;
        default:
            ret = EINVAL;
            goto done;
    }
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = talloc_ber_flatten(mem_ctx, ber, _bv);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    ber_free(ber, 1);

    return ret;
}

/* If the extendend operation is successful it returns the following ASN.1
 * encoded response:
 *
 * ExtdomResponseValue ::= SEQUENCE {
 *    responseType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix_user (3),
 *        posix_group (4),
 *        posix_user_grouplist (5),
 *        posix_group_members (6)
 *    },
 *    data OutputData
 * }
 *
 * OutputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData,
 *    user PosixUser,
 *    group PosixGroup,
 *    usergrouplist PosixUserGrouplist,
 *    groupmembers PosixGroupMembers
 *
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUser ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER
 *    gid INTEGER
 * }
 *
 * PosixGroup ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 * PosixUserGrouplist ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER,
 *    gid INTEGER,
 *    gecos OCTET STRING,
 *    home_directory OCTET STRING,
 *    shell OCTET STRING,
 *    grouplist GroupNameList
 * }
 *
 * GroupNameList ::= SEQUENCE OF OCTET STRING
 *
 * PosixGroupMembers ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER,
 *    members GroupMemberList
 * }
 *
 * GroupMemberList ::= SEQUENCE OF OCTET STRING
 */

struct resp_attrs {
    enum response_types response_type;
    char *domain_name;
    union {
        struct passwd user;
        struct group group;
        char *sid_str;
        char *name;
    } a;
    size_t ngroups;
    char **groups;
    struct sysdb_attrs *sysdb_attrs;
};

static errno_t get_extra_attrs(BerElement *ber, struct resp_attrs *resp_attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    char *ber_cookie;
    char *name;
    struct berval **values;
    struct ldb_val v;
    int ret;
    size_t c;

    if (resp_attrs->sysdb_attrs == NULL) {
        resp_attrs->sysdb_attrs = sysdb_new_attrs(resp_attrs);
        if (resp_attrs->sysdb_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            return ENOMEM;
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found new sequence.\n");
    for (tag = ber_first_element(ber, &ber_len, &ber_cookie);
         tag != LBER_DEFAULT;
         tag = ber_next_element(ber, &ber_len, ber_cookie)) {

        tag = ber_scanf(ber, "{a{V}}", &name, &values);
        if (tag == LBER_ERROR) {
            DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
            return EINVAL;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Extra attribute [%s].\n", name);

        for (c = 0; values[c] != NULL; c++) {

            v.data = (uint8_t *) values[c]->bv_val;
            v.length = values[c]->bv_len;

            ret = sysdb_attrs_add_val(resp_attrs->sysdb_attrs, name, &v);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_val failed.\n");
                ldap_memfree(name);
                ber_bvecfree(values);
                return ret;
            }
        }

        ldap_memfree(name);
        ber_bvecfree(values);
    }

    return EOK;
}

static errno_t add_v1_user_data(BerElement *ber, struct resp_attrs *attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    int ret;
    char *gecos = NULL;
    char *homedir = NULL;
    char *shell = NULL;
    char **list = NULL;
    size_t c;

    tag = ber_scanf(ber, "aaa", &gecos, &homedir, &shell);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (gecos == NULL || *gecos == '\0') {
        attrs->a.user.pw_gecos = NULL;
    } else {
        attrs->a.user.pw_gecos = talloc_strdup(attrs, gecos);
        if (attrs->a.user.pw_gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (homedir == NULL || *homedir == '\0') {
        attrs->a.user.pw_dir = NULL;
    } else {
        attrs->a.user.pw_dir = talloc_strdup(attrs, homedir);
        if (attrs->a.user.pw_dir == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (shell == NULL || *shell == '\0') {
        attrs->a.user.pw_shell = NULL;
    } else {
        attrs->a.user.pw_shell = talloc_strdup(attrs, shell);
        if (attrs->a.user.pw_shell == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tag = ber_scanf(ber, "{v}", &list);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    for (attrs->ngroups = 0; list[attrs->ngroups] != NULL;
         attrs->ngroups++);

    if (attrs->ngroups > 0) {
        attrs->groups = talloc_zero_array(attrs, char *, attrs->ngroups + 1);
        if (attrs->groups == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }

        for (c = 0; c < attrs->ngroups; c++) {
            attrs->groups[c] = talloc_strdup(attrs->groups,
                                             list[c]);
            if (attrs->groups[c] == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }
    }

    tag = ber_peek_tag(ber, &ber_len);
    DEBUG(SSSDBG_TRACE_ALL, "BER tag is [%d]\n", (int) tag);
    if (tag == LBER_SEQUENCE) {
        ret = get_extra_attrs(ber, attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_extra_attrs failed.\n");
            goto done;
        }
    }


    ret = EOK;

done:
    ber_memfree(gecos);
    ber_memfree(homedir);
    ber_memfree(shell);
    ber_memvfree((void **) list);

    return ret;
}

static errno_t add_v1_group_data(BerElement *ber, struct resp_attrs *attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    int ret;
    char **list = NULL;
    size_t c;

    tag = ber_scanf(ber, "{v}", &list);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (list != NULL) {
        for (attrs->ngroups = 0; list[attrs->ngroups] != NULL;
             attrs->ngroups++);

        if (attrs->ngroups > 0) {
            attrs->a.group.gr_mem = talloc_zero_array(attrs, char *,
                                                    attrs->ngroups + 1);
            if (attrs->a.group.gr_mem == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                ret = ENOMEM;
                goto done;
            }

            for (c = 0; c < attrs->ngroups; c++) {
                attrs->a.group.gr_mem[c] =
                                    talloc_strdup(attrs->a.group.gr_mem,
                                                  list[c]);
                if (attrs->a.group.gr_mem[c] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
            }
        }
    } else {
        attrs->a.group.gr_mem = talloc_zero_array(attrs, char *, 1);
        if (attrs->a.group.gr_mem == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tag = ber_peek_tag(ber, &ber_len);
    DEBUG(SSSDBG_TRACE_ALL, "BER tag is [%d]\n", (int) tag);
    if (tag == LBER_SEQUENCE) {
        ret = get_extra_attrs(ber, attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_extra_attrs failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    ber_memvfree((void **) list);

    return ret;
}

static errno_t ipa_s2n_save_objects(struct sss_domain_info *dom,
                                    struct req_input *req_input,
                                    struct resp_attrs *attrs,
                                    struct resp_attrs *simple_attrs,
                                    const char *view_name,
                                    struct sysdb_attrs *override_attrs);

static errno_t s2n_response_to_attrs(TALLOC_CTX *mem_ctx,
                                     char *retoid,
                                     struct berval *retdata,
                                     struct resp_attrs **resp_attrs)
{
    BerElement *ber = NULL;
    ber_tag_t tag;
    int ret;
    enum response_types type;
    char *domain_name = NULL;
    char *name = NULL;
    uid_t uid;
    gid_t gid;
    struct resp_attrs *attrs = NULL;
    char *sid_str;
    bool is_v1 = false;

    if (retoid == NULL || retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing OID or data.\n");
        return EINVAL;
    }

    if (strcmp(retoid, EXOP_SID2NAME_V1_OID) == 0) {
        is_v1 = true;
    } else if (strcmp(retoid, EXOP_SID2NAME_OID) == 0) {
        is_v1 = false;
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result has wrong OID, expected [%s] or [%s], got [%s].\n",
              EXOP_SID2NAME_OID, EXOP_SID2NAME_V1_OID, retoid);
        return EINVAL;
    }

    ber = ber_init(retdata);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_init failed.\n");
        return EINVAL;
    }

    tag = ber_scanf(ber, "{e", &type);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    attrs = talloc_zero(mem_ctx, struct resp_attrs);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
        case RESP_USER:
        case RESP_USER_GROUPLIST:
            tag = ber_scanf(ber, "{aaii", &domain_name, &name, &uid, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            /* Winbind is not consistent with the case of the returned user
             * name. In general all names should be lower case but there are
             * bug in some version of winbind which might lead to upper case
             * letters in the name. To be on the safe side we explicitly
             * lowercase the name. */
            attrs->a.user.pw_name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.user.pw_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            attrs->a.user.pw_uid = uid;
            attrs->a.user.pw_gid = gid;

            if (is_v1 && type == RESP_USER_GROUPLIST) {
                ret = add_v1_user_data(ber, attrs);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_v1_user_data failed.\n");
                    goto done;
                }
            }

            tag = ber_scanf(ber, "}}");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            break;
        case RESP_GROUP:
        case RESP_GROUP_MEMBERS:
            tag = ber_scanf(ber, "{aai", &domain_name, &name, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            /* Winbind is not consistent with the case of the returned user
             * name. In general all names should be lower case but there are
             * bug in some version of winbind which might lead to upper case
             * letters in the name. To be on the safe side we explicitly
             * lowercase the name. */
            attrs->a.group.gr_name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.group.gr_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }

            attrs->a.group.gr_gid = gid;

            if (is_v1 && type == RESP_GROUP_MEMBERS) {
                ret = add_v1_group_data(ber, attrs);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_v1_group_data failed.\n");
                    goto done;
                }
            }

            tag = ber_scanf(ber, "}}");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            break;
        case RESP_SID:
            tag = ber_scanf(ber, "a}", &sid_str);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.sid_str = talloc_strdup(attrs, sid_str);
            if (attrs->a.sid_str == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            break;
        case RESP_NAME:
            tag = ber_scanf(ber, "{aa}", &domain_name, &name);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_tc_utf8_str_tolower failed.\n");
                ret = ENOMEM;
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected response type [%d].\n",
                                      type);
            ret = EINVAL;
            goto done;
    }

    attrs->response_type = type;
    if (type != RESP_SID) {
        attrs->domain_name = talloc_strdup(attrs, domain_name);
        if (attrs->domain_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    ber_memfree(domain_name);
    ber_memfree(name);
    ber_free(ber, 1);

    if (ret == EOK) {
        *resp_attrs = attrs;
    } else {
        talloc_free(attrs);
    }

    return ret;
}

struct ipa_s2n_get_fqlist_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct req_input req_input;
    char **fqname_list;
    size_t fqname_idx;
    int exop_timeout;
    int entry_type;
    enum request_types request_type;
    struct resp_attrs *attrs;
    struct sss_domain_info *obj_domain;
    struct sysdb_attrs *override_attrs;
};

static errno_t ipa_s2n_get_fqlist_step(struct tevent_req *req);
static void ipa_s2n_get_fqlist_get_override_done(struct tevent_req *subreq);
static void ipa_s2n_get_fqlist_next(struct tevent_req *subreq);
static errno_t ipa_s2n_get_fqlist_save_step(struct tevent_req *req);

static struct tevent_req *ipa_s2n_get_fqlist_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct ipa_id_ctx *ipa_ctx,
                                                struct sss_domain_info *dom,
                                                struct sdap_handle *sh,
                                                int exop_timeout,
                                                int entry_type,
                                                enum request_types request_type,
                                                char **fqname_list)
{
    int ret;
    struct ipa_s2n_get_fqlist_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_fqlist_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->dom = dom;
    state->sh = sh;
    state->fqname_list = fqname_list;
    state->fqname_idx = 0;
    state->req_input.type = REQ_INP_NAME;
    state->req_input.inp.name = NULL;
    state->exop_timeout = exop_timeout;
    state->entry_type = entry_type;
    state->request_type = request_type;
    state->attrs = NULL;
    state->override_attrs = NULL;

    ret = ipa_s2n_get_fqlist_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_fqlist_step failed.\n");
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t ipa_s2n_get_fqlist_step(struct tevent_req *req)
{
    int ret;
    struct ipa_s2n_get_fqlist_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_fqlist_state);
    struct berval *bv_req;
    struct tevent_req *subreq;
    struct sss_domain_info *parent_domain;
    char *short_name = NULL;
    char *domain_name = NULL;

    parent_domain = get_domains_head(state->dom);

    ret = sss_parse_name(state, parent_domain->names,
                         state->fqname_list[state->fqname_idx],
                         &domain_name, &short_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name '%s' [%d]: %s\n",
                                    state->fqname_list[state->fqname_idx],
                                    ret, sss_strerror(ret));
        return ret;
    }

    if (domain_name) {
        state->obj_domain = find_domain_by_name(parent_domain,
                                                domain_name, true);
        if (state->obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
            return ENOMEM;
        }
    } else {
        state->obj_domain = parent_domain;
    }

    state->req_input.inp.name = short_name;

    ret = s2n_encode_request(state, state->obj_domain->name, state->entry_type,
                             state->request_type,
                             &state->req_input, &bv_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n_encode_request failed.\n");
        return ret;
    }

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, true,
                               state->exop_timeout, bv_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_fqlist_next, req);

    return EOK;
}

static void ipa_s2n_get_fqlist_next(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_fqlist_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_fqlist_state);
    char *retoid = NULL;
    struct berval *retdata = NULL;
    const char *sid_str;
    struct be_acct_req *ar;

    ret = ipa_s2n_exop_recv(subreq, state, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n exop request failed.\n");
        goto fail;
    }

    talloc_zfree(state->attrs);
    ret = s2n_response_to_attrs(state, retoid, retdata, &state->attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
        goto fail;
    }

    if (state->ipa_ctx->view_name == NULL ||
            strcmp(state->ipa_ctx->view_name, SYSDB_DEFAULT_VIEW_NAME) == 0) {
        ret = ipa_s2n_get_fqlist_save_step(req);
        if (ret == EOK) {
            tevent_req_done(req);
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_fqlist_save_step failed.\n");
            goto fail;
        }

        return;
    }

    ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                 &sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto fail;
    }

    ret = get_be_acct_req_for_sid(state, sid_str, state->obj_domain->name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_be_acct_req_for_sid failed.\n");
        goto fail;
    }

    subreq = ipa_get_ad_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_fqlist_get_override_done, req);

    return;

fail:
    tevent_req_error(req,ret);
    return;
}

static void ipa_s2n_get_fqlist_get_override_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_fqlist_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_fqlist_state);

    ret = ipa_get_ad_override_recv(subreq, NULL, state, &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
    }

    ret = ipa_s2n_get_fqlist_save_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_fqlist_save_step failed.\n");
        goto fail;
    }

    return;

fail:
    tevent_req_error(req,ret);
    return;
}

static errno_t ipa_s2n_get_fqlist_save_step(struct tevent_req *req)
{
    int ret;
    struct ipa_s2n_get_fqlist_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_fqlist_state);

    ret = ipa_s2n_save_objects(state->dom, &state->req_input, state->attrs,
                               NULL, state->ipa_ctx->view_name,
                               state->override_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
        return ret;
    }

    state->fqname_idx++;
    if (state->fqname_list[state->fqname_idx] == NULL) {
        return EOK;
    }

    ret = ipa_s2n_get_fqlist_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_fqlist_step failed.\n");
        return ret;
    }

    return EAGAIN;
}

static int ipa_s2n_get_fqlist_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_s2n_get_user_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    struct req_input *req_input;
    int entry_type;
    enum request_types request_type;
    struct resp_attrs *attrs;
    struct resp_attrs *simple_attrs;
    struct sysdb_attrs *override_attrs;
    int exop_timeout;
};

static void ipa_s2n_get_user_done(struct tevent_req *subreq);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct ipa_id_ctx *ipa_ctx,
                                             struct sdap_options *opts,
                                             struct sss_domain_info *dom,
                                             struct sysdb_attrs *override_attrs,
                                             struct sdap_handle *sh,
                                             int entry_type,
                                             struct req_input *req_input)
{
    struct ipa_s2n_get_user_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct berval *bv_req = NULL;
    int ret = EFAULT;
    bool is_v1 = false;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_user_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->req_input = req_input;
    state->entry_type = entry_type;
    state->attrs = NULL;
    state->simple_attrs = NULL;
    state->exop_timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->override_attrs = override_attrs;

    if (sdap_is_extension_supported(sh, EXOP_SID2NAME_V1_OID)) {
        state->request_type = REQ_FULL_WITH_MEMBERS;
        is_v1 = true;
    } else if (sdap_is_extension_supported(sh, EXOP_SID2NAME_OID)) {
        state->request_type = REQ_FULL;
        is_v1 = false;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Extdom not supported on the server, "
                              "cannot resolve objects from trusted domains.\n");
        ret = EIO;
        goto fail;
    }

    ret = s2n_encode_request(state, dom->name, entry_type, state->request_type,
                             req_input, &bv_req);
    if (ret != EOK) {
        goto fail;
    }

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, is_v1,
                               state->exop_timeout, bv_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static errno_t process_members(struct sss_domain_info *domain,
                               struct sysdb_attrs *group_attrs,
                               char **members,
                               TALLOC_CTX *mem_ctx, char ***_missing_members)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    const char *dn_str;
    struct sss_domain_info *obj_domain;
    struct sss_domain_info *parent_domain;
    char **missing_members = NULL;
    size_t miss_count = 0;

    if (members == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No members\n");
        *_missing_members = NULL;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (_missing_members != NULL && mem_ctx != NULL) {
        /* count members */
        for (c = 0; members[c] != NULL; c++);
        missing_members = talloc_zero_array(tmp_ctx, char *, c + 1);
        if (missing_members == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    parent_domain = get_domains_head(domain);

    for (c = 0; members[c] != NULL; c++) {
        obj_domain = find_domain_by_object_name(parent_domain, members[c]);
        if (obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_object_name failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_user_by_name(tmp_ctx, obj_domain, members[c], NULL,
                                        &msg);
        if (ret == EOK) {
            if (group_attrs != NULL) {
                dn_str = ldb_dn_get_linearized(msg->dn);
                if (dn_str == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_get_linearized failed.\n");
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_ALL, "Adding member [%s][%s]\n",
                                        members[c], dn_str);

                ret = sysdb_attrs_add_string(group_attrs, SYSDB_MEMBER, dn_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }
        } else if (ret == ENOENT) {
            if (group_attrs != NULL) {
                DEBUG(SSSDBG_TRACE_ALL, "Adding ghost member [%s]\n",
                                        members[c]);

                /* There were cases where the server returned the same user
                 * multiple times */
                ret = sysdb_attrs_add_string_safe(group_attrs, SYSDB_GHOST,
                                                  members[c]);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (missing_members != NULL) {
                missing_members[miss_count] = talloc_strdup(missing_members,
                                                            members[c]);
                if (missing_members[miss_count] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                miss_count++;
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed.\n");
            goto done;
        }
    }

    if (_missing_members != NULL)  {
        if (miss_count == 0) {
            *_missing_members = NULL;
        } else {
            if (mem_ctx != NULL) {
                *_missing_members = talloc_steal(mem_ctx, missing_members);
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Missing memory context for missing members list.\n");
                ret = EINVAL;
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t get_group_dn_list(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom,
                                 size_t ngroups, char **groups,
                                 struct ldb_dn ***_dn_list,
                                 char ***_missing_groups)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn **dn_list = NULL;
    char **missing_groups = NULL;
    struct ldb_message *msg = NULL;
    size_t n_dns = 0;
    size_t n_missing = 0;
    struct sss_domain_info *obj_domain;
    struct sss_domain_info *parent_domain;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    dn_list = talloc_zero_array(tmp_ctx, struct ldb_dn *, ngroups + 1);
    missing_groups = talloc_zero_array(tmp_ctx, char *, ngroups + 1);
    if (dn_list == NULL || missing_groups == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    parent_domain = (dom->parent == NULL) ? dom : dom->parent;

    for (c = 0; c < ngroups; c++) {
        obj_domain = find_domain_by_object_name(parent_domain, groups[c]);
        if (obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_object_name failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_group_by_name(tmp_ctx, obj_domain, groups[c], NULL,
                                         &msg);
        if (ret == EOK) {
            dn_list[n_dns] = ldb_dn_copy(dn_list, msg->dn);
            if (dn_list[n_dns] == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_copy failed.\n");
                ret = ENOMEM;
                goto done;
            }
            n_dns++;
        } else if (ret == ENOENT) {
            missing_groups[n_missing] = talloc_strdup(missing_groups,
                                                      groups[c]);
            if (missing_groups[n_missing] == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            n_missing++;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_group_by_name failed.\n");
            goto done;
        }
    }

    if (n_missing != 0) {
        *_missing_groups = talloc_steal(mem_ctx, missing_groups);
    } else {
        *_missing_groups = NULL;
    }

    if (n_dns != 0) {
        *_dn_list = talloc_steal(mem_ctx, dn_list);
    } else {
        *dn_list = NULL;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static void ipa_s2n_get_fqlist_done(struct tevent_req  *subreq);
static void ipa_s2n_get_user_get_override_done(struct tevent_req *subreq);
static void ipa_s2n_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    int ret;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    struct resp_attrs *attrs = NULL;
    struct berval *bv_req = NULL;
    char **missing_list = NULL;
    struct ldb_dn **group_dn_list = NULL;
    const char *sid_str;
    struct be_acct_req *ar;

    ret = ipa_s2n_exop_recv(subreq, state, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n exop request failed.\n");
        goto done;
    }

    switch (state->request_type) {
    case REQ_FULL_WITH_MEMBERS:
    case REQ_FULL:
        ret = s2n_response_to_attrs(state, retoid, retdata, &attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
            goto done;
        }

        if (!(strcasecmp(state->dom->name, attrs->domain_name) == 0 ||
              (state->dom->flat_name != NULL &&
               strcasecmp(state->dom->flat_name, attrs->domain_name) == 0))) {
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected domain name returned, "
                                      "expected [%s] or [%s], got [%s].\n",
                         state->dom->name,
                         state->dom->flat_name == NULL ? "" :
                                                         state->dom->flat_name,
                         attrs->domain_name);
            ret = EINVAL;
            goto done;
        }

        state->attrs = attrs;

        if (attrs->response_type == RESP_USER_GROUPLIST) {
            ret = get_group_dn_list(state, state->dom,
                                    attrs->ngroups, attrs->groups,
                                    &group_dn_list, &missing_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_group_dn_list failed.\n");
                goto done;
            }

            if (missing_list != NULL) {
                subreq = ipa_s2n_get_fqlist_send(state, state->ev,
                                                 state->ipa_ctx, state->dom,
                                                 state->sh, state->exop_timeout,
                                                 BE_REQ_GROUP,
                                                 REQ_FULL_WITH_MEMBERS,
                                                 missing_list);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "ipa_s2n_get_fqlist_send failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                tevent_req_set_callback(subreq, ipa_s2n_get_fqlist_done,
                                        req);

                return;
            }
            break;
        } else if (attrs->response_type == RESP_GROUP_MEMBERS) {
            ret = process_members(state->dom, NULL, attrs->a.group.gr_mem,
                                  state, &missing_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "process_members failed.\n");
                goto done;
            }

            if (missing_list != NULL) {
                subreq = ipa_s2n_get_fqlist_send(state, state->ev,
                                                 state->ipa_ctx, state->dom,
                                                 state->sh, state->exop_timeout,
                                                 BE_REQ_USER,
                                                 REQ_FULL_WITH_MEMBERS,
                                                 missing_list);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "ipa_s2n_get_fqlist_send failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                tevent_req_set_callback(subreq, ipa_s2n_get_fqlist_done,
                                        req);

                return;
            }
            break;
        }

        if (state->req_input->type == REQ_INP_SECID) {
            /* We already know the SID, we do not have to read it. */
            break;
        }

        state->request_type = REQ_SIMPLE;

        ret = s2n_encode_request(state, state->dom->name, state->entry_type,
                                 state->request_type, state->req_input,
                                 &bv_req);
        if (ret != EOK) {
            goto done;
        }

        subreq = ipa_s2n_exop_send(state, state->ev, state->sh, false,
                                   state->exop_timeout, bv_req);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

        return;

    case REQ_SIMPLE:
        ret = s2n_response_to_attrs(state, retoid, retdata,
                                    &state->simple_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
            goto done;
        }

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected request type.\n");
        ret = EINVAL;
        goto done;
    }

    if (state->attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing data of full request.\n");
        ret = EINVAL;
        goto done;
    }

    if (state->simple_attrs != NULL
            && state->simple_attrs->response_type == RESP_SID) {
        sid_str = state->simple_attrs->a.sid_str;
        ret = EOK;
    } else if (state->attrs->sysdb_attrs != NULL) {
        ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                     &sid_str);
    } else if (state->req_input->type == REQ_INP_SECID) {
        sid_str = state->req_input->inp.secid;
        ret = EOK;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "No SID available.\n");
        ret = ENOENT;
    }

    if (ret == ENOENT
            || state->ipa_ctx->view_name == NULL
            || strcmp(state->ipa_ctx->view_name,
                      SYSDB_DEFAULT_VIEW_NAME) == 0) {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            goto done;
        }
    } else if (ret == EOK) {
        ret = get_be_acct_req_for_sid(state, sid_str, state->dom->name, &ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_be_acct_req_for_sid failed.\n");
            goto done;
        }

        subreq = ipa_get_ad_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_get_override_done,
                                req);

        return;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;
}

static errno_t get_groups_dns(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                              char **name_list, char ***_dn_list)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    int c;
    struct sss_domain_info *root_domain;
    char **dn_list;

    if (name_list == NULL) {
        *_dn_list = NULL;
        return EOK;
    }

    /* To handle cross-domain memberships we have to check the domain for
     * each group the member should be added or deleted. Since sub-domains
     * use fully-qualified names by default any short name can only belong
     * to the root/head domain. find_domain_by_object_name() will return
     * the domain given in the first argument if the second argument is a
     * a short name hence we always use root_domain as first argument. */
    root_domain = get_domains_head(dom);
    if (root_domain->fqnames) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Root domain uses fully-qualified names, " \
              "objects might not be correctly added to groups with " \
              "short names.\n");
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    for (c = 0; name_list[c] != NULL; c++);

    dn_list = talloc_zero_array(tmp_ctx, char *, c + 1);
    if (dn_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; name_list[c] != NULL; c++) {
        dom = find_domain_by_object_name(root_domain, name_list[c]);
        if (dom == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot find domain for [%s].\n", name_list[c]);
            ret = ENOENT;
            goto done;
        }

        /* This might fail if some unexpected cases are used. But current
         * sysdb code which handles group membership constructs DNs this way
         * as well, IPA names are lowercased and AD names by default will be
         * lowercased as well. If there are really use-cases which cause an
         * issue here, sysdb_group_strdn() has to be replaced by a proper
         * search. */
        dn_list[c] = sysdb_group_strdn(dn_list, dom->name, name_list[c]);
        if (dn_list[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_group_strdn failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    *_dn_list = talloc_steal(mem_ctx, dn_list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t ipa_s2n_save_objects(struct sss_domain_info *dom,
                                    struct req_input *req_input,
                                    struct resp_attrs *attrs,
                                    struct resp_attrs *simple_attrs,
                                    const char *view_name,
                                    struct sysdb_attrs *override_attrs)
{
    int ret;
    time_t now;
    uint64_t timeout = 10*60*60; /* FIXME: find a better timeout ! */
    struct sss_nss_homedir_ctx homedir_ctx;
    char *name = NULL;
    char *realm;
    char *upn = NULL;
    gid_t gid;
    gid_t orig_gid = 0;
    TALLOC_CTX *tmp_ctx;
    const char *sid_str;
    const char *tmp_str;
    struct ldb_result *res;
    enum sysdb_member_type type;
    char **sysdb_grouplist;
    char **add_groups;
    char **add_groups_dns;
    char **del_groups;
    char **del_groups_dns;
    bool in_transaction = false;
    int tret;
    struct sysdb_attrs *gid_override_attrs = NULL;
    char ** exop_grouplist;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    now = time(NULL);

    if (attrs->sysdb_attrs == NULL) {
        attrs->sysdb_attrs = sysdb_new_attrs(attrs);
        if (attrs->sysdb_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (attrs->sysdb_attrs != NULL) {
        ret = sysdb_attrs_get_string(attrs->sysdb_attrs,
                                     ORIGINALAD_PREFIX SYSDB_NAME, &tmp_str);
        if (ret == EOK) {
            name = talloc_strdup(tmp_ctx, tmp_str);
            if (name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL, "Found original AD name [%s].\n", name);
        } else if (ret == ENOENT) {
            name = NULL;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(attrs->sysdb_attrs,
                                     SYSDB_DEFAULT_OVERRIDE_NAME, &tmp_str);
        if (ret == EOK) {
            ret = sysdb_attrs_add_lc_name_alias(attrs->sysdb_attrs, tmp_str);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias failed.\n");
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(attrs->sysdb_attrs, SYSDB_UPN, &tmp_str);
        if (ret == EOK) {
            upn = talloc_strdup(tmp_ctx, tmp_str);
            if (upn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL, "Found original AD upn [%s].\n", upn);
        } else if (ret == ENOENT) {
            upn = NULL;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    }

    if (strcmp(dom->name, attrs->domain_name) != 0) {
        dom = find_domain_by_name(get_domains_head(dom),
                                  attrs->domain_name, true);
        if (dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "Cannot find domain: [%s]\n", attrs->domain_name);
            ret = EINVAL;
            goto done;
        }
    }

    switch (attrs->response_type) {
        case RESP_USER:
        case RESP_USER_GROUPLIST:
            type = SYSDB_MEMBER_USER;
            if (dom->subdomain_homedir
                    && attrs->a.user.pw_dir == NULL) {
                ZERO_STRUCT(homedir_ctx);
                homedir_ctx.username = attrs->a.user.pw_name;
                homedir_ctx.uid = attrs->a.user.pw_uid;
                homedir_ctx.domain = dom->name;
                homedir_ctx.flatname = dom->flat_name;
                homedir_ctx.config_homedir_substr = dom->homedir_substr;

                attrs->a.user.pw_dir = expand_homedir_template(attrs,
                                                  dom->subdomain_homedir,
                                                  &homedir_ctx);
                if (attrs->a.user.pw_dir == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            if (name == NULL) {
                /* we always use the fully qualified name for subdomain users */
                name = sss_tc_fqname(tmp_ctx, dom->names, dom,
                                     attrs->a.user.pw_name);
                if (!name) {
                    DEBUG(SSSDBG_OP_FAILURE, "failed to format user name.\n");
                    ret = ENOMEM;
                    goto done;
                }
            }

            ret = sysdb_attrs_add_lc_name_alias(attrs->sysdb_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias failed.\n");
                goto done;
            }

            if (upn == NULL) {
                /* We also have to store a fake UPN here, because otherwise the
                 * krb5 child later won't be able to properly construct one as
                 * the username is fully qualified but the child doesn't have
                 * access to the regex to deconstruct it */
                /* FIXME: The real UPN is available from the PAC, we should get
                 * it from there. */
                realm = get_uppercase_realm(tmp_ctx, dom->name);
                if (!realm) {
                    DEBUG(SSSDBG_OP_FAILURE, "failed to get realm.\n");
                    ret = ENOMEM;
                    goto done;
                }
                upn = talloc_asprintf(tmp_ctx, "%s@%s",
                                      attrs->a.user.pw_name, realm);
                if (!upn) {
                    DEBUG(SSSDBG_OP_FAILURE, "failed to format UPN.\n");
                    ret = ENOMEM;
                    goto done;
                }

                /* We might already have the SID or the UPN from other sources
                 * hence sysdb_attrs_add_string_safe is used to avoid double
                 * entries. */
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs, SYSDB_UPN,
                                                  upn);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (simple_attrs != NULL
                    && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (attrs->response_type == RESP_USER_GROUPLIST) {
                /* Since RESP_USER_GROUPLIST contains all group memberships it
                 * is effectively an initgroups request hence
                 * SYSDB_INITGR_EXPIRE will be set.*/
                ret = sysdb_attrs_add_time_t(attrs->sysdb_attrs,
                                             SYSDB_INITGR_EXPIRE,
                                             time(NULL) + timeout);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_time_t failed.\n");
                    goto done;
                }
            }

            gid = 0;
            if (dom->mpg == false) {
                gid = attrs->a.user.pw_gid;
            } else {
                /* The extdom plugin always returns the objects with the
                 * default view applied. Since the GID is handled specially
                 * for MPG domains we have add any overridden GID separately.
                 */
                ret = sysdb_attrs_get_uint32_t(attrs->sysdb_attrs,
                                               ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                               &orig_gid);
                if (ret == EOK || ret == ENOENT) {
                    if ((orig_gid != 0 && orig_gid != attrs->a.user.pw_gid)
                            || attrs->a.user.pw_uid != attrs->a.user.pw_gid) {

                        gid_override_attrs = sysdb_new_attrs(tmp_ctx);
                        if (gid_override_attrs == NULL) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_new_attrs failed.\n");
                            ret = ENOMEM;
                            goto done;
                        }

                        ret = sysdb_attrs_add_uint32(gid_override_attrs,
                                                     SYSDB_GIDNUM,
                                                     attrs->a.user.pw_gid);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_attrs_add_uint32 failed.\n");
                            goto done;
                        }
                    }
                } else {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_get_uint32_t failed.\n");
                    goto done;
                }
            }

            ret = sysdb_transaction_start(dom->sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
                goto done;
            }
            in_transaction = true;

            ret = sysdb_store_user(dom, name, NULL,
                                   attrs->a.user.pw_uid,
                                   gid, attrs->a.user.pw_gecos,
                                   attrs->a.user.pw_dir, attrs->a.user.pw_shell,
                                   NULL, attrs->sysdb_attrs, NULL,
                                   timeout, now);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_user failed.\n");
                goto done;
            }

            if (gid_override_attrs != NULL) {
                ret = sysdb_set_user_attr(dom, name, gid_override_attrs,
                                          SYSDB_MOD_REP);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_user_attr failed.\n");
                    goto done;
                }
            }

            if (attrs->response_type == RESP_USER_GROUPLIST) {
                ret = get_sysdb_grouplist(tmp_ctx, dom->sysdb, dom, name,
                                          &sysdb_grouplist);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "get_sysdb_grouplist failed.\n");
                    goto done;
                }

                /* names returned by extdom exop will be all lower case, since
                 * we handle domain names case sensitve in the cache we have
                 * to make sure we use the right case. */
                ret = fix_domain_in_name_list(tmp_ctx, dom, attrs->groups,
                                              &exop_grouplist);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "fix_domain_name failed.\n");
                    goto done;
                }

                ret = diff_string_lists(tmp_ctx, exop_grouplist,
                                        sysdb_grouplist, &add_groups,
                                        &del_groups, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "diff_string_lists failed.\n");
                    goto done;
                }

                ret = get_groups_dns(tmp_ctx, dom, add_groups, &add_groups_dns);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "get_groups_dns failed.\n");
                    goto done;
                }

                ret = get_groups_dns(tmp_ctx, dom, del_groups, &del_groups_dns);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "get_groups_dns failed.\n");
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_INTERNAL, "Updating memberships for %s\n",
                                             name);
                ret = sysdb_update_members_dn(dom, name, SYSDB_MEMBER_USER,
                                          (const char *const *) add_groups_dns,
                                          (const char *const *) del_groups_dns);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Membership update failed [%d]: %s\n",
                                               ret, sss_strerror(ret));
                    goto done;
                }
            }

            ret = sysdb_transaction_commit(dom->sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
                goto done;
            }
            in_transaction = false;

            break;
        case RESP_GROUP:
        case RESP_GROUP_MEMBERS:
            type = SYSDB_MEMBER_GROUP;

            if (name == NULL) {
                name = attrs->a.group.gr_name;
            }

            if (IS_SUBDOMAIN(dom)) {
                /* we always use the fully qualified name for subdomain users */
                name = sss_get_domain_name(tmp_ctx, name, dom);
                if (!name) {
                    DEBUG(SSSDBG_OP_FAILURE, "failed to format user name,\n");
                    ret = ENOMEM;
                    goto done;
                }
            }
            DEBUG(SSSDBG_TRACE_FUNC, "Processing group %s\n", name);

            ret = sysdb_attrs_add_lc_name_alias(attrs->sysdb_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias failed.\n");
                goto done;
            }

            /* We might already have the SID from other sources hence
             * sysdb_attrs_add_string_safe is used to avoid double entries. */
            if (req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (simple_attrs != NULL
                && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            ret = process_members(dom, attrs->sysdb_attrs,
                                  attrs->a.group.gr_mem, NULL, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "process_members failed.\n");
                goto done;
            }

            ret = sysdb_store_group(dom, name, attrs->a.group.gr_gid,
                                    attrs->sysdb_attrs, timeout, now);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_group failed.\n");
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected response type [%d].\n",
                                      attrs->response_type);
            ret = EINVAL;
            goto done;
    }

    ret = sysdb_attrs_get_string(attrs->sysdb_attrs, SYSDB_SID_STR, &sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot find SID of object with override.\n");
        goto done;
    }

    ret = sysdb_search_object_by_sid(tmp_ctx, dom, sid_str, NULL, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot find object with override with SID [%s].\n", sid_str);
        goto done;
    }

    ret = sysdb_store_override(dom, view_name, type, override_attrs,
                               res->msgs[0]->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_override failed.\n");
        goto done;
    }

done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static void ipa_s2n_get_fqlist_done(struct tevent_req  *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    const char *sid_str;
    struct be_acct_req *ar;

    ret = ipa_s2n_get_fqlist_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n get_fqlist request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                 &sid_str);
    if (ret == ENOENT) {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            goto fail;
        }
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto fail;
    }

    ret = get_be_acct_req_for_sid(state, sid_str, state->dom->name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_be_acct_req_for_sid failed.\n");
        goto fail;
    }

    if (state->override_attrs == NULL
            && state->ipa_ctx->view_name != NULL
            && strcmp(state->ipa_ctx->view_name,
                      SYSDB_DEFAULT_VIEW_NAME) != 0) {
        subreq = ipa_get_ad_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override_send failed.\n");
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_get_override_done,
                                req);
    } else {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs,
                                   state->ipa_ctx->view_name,
                                   state->override_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            tevent_req_error(req, ret);
            return;
        }

        tevent_req_done(req);
    }

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void ipa_s2n_get_user_get_override_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    struct sysdb_attrs *override_attrs = NULL;

    ret = ipa_get_ad_override_recv(subreq, NULL, state, &override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                               state->simple_attrs, state->ipa_ctx->view_name,
                               override_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int ipa_s2n_get_acct_info_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
