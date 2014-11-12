/*
   SSSD

   System Database - View and Override related calls

   Copyright (C) 2014 Sumit Bose <sbose@redhat.com>

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
#include "db/sysdb_private.h"

/* In general is should not be possible that there is a view container without
 * a view name set. But to be on the safe side we return both information
 * separately. */
static errno_t sysdb_get_view_name_ex(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      char **_view_name,
                                      bool *view_container_exists)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *tmp_str;
    struct ldb_dn *view_base_dn;
    struct ldb_result *res;
    const char *attrs[] = {SYSDB_VIEW_NAME,
                           NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    view_base_dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_BASE);
    if (view_base_dn == NULL) {
        ret = EIO;
        goto done;
    }
    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, view_base_dn, LDB_SCOPE_BASE,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Base search returned [%d] results, "
                                 "expected 1.\n", res->count);
        ret = EINVAL;
        goto done;
    }

    if (res->count == 0) {
        *view_container_exists = false;
        ret = ENOENT;
        goto done;
    } else {
        *view_container_exists = true;
        tmp_str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_VIEW_NAME,
                                              NULL);
        if (tmp_str == NULL) {
            ret = ENOENT;
            goto done;
        }
    }

    *_view_name = talloc_steal(mem_ctx, discard_const(tmp_str));
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_get_view_name(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                            char **view_name)
{
    bool view_container_exists;

    return sysdb_get_view_name_ex(mem_ctx, sysdb, view_name,
                                  &view_container_exists);
}

errno_t sysdb_update_view_name(struct sysdb_ctx *sysdb,
                               const char *view_name)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *tmp_str;
    bool view_container_exists = false;
    bool add_view_name = false;
    struct ldb_message *msg;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_view_name_ex(tmp_ctx, sysdb, &tmp_str,
                                 &view_container_exists);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_view_name_ex failed.\n");
        goto done;
    }

    if (ret == EOK) {
        if (strcmp(tmp_str, view_name) == 0) {
            /* view name already known, nothing to do */
            DEBUG(SSSDBG_TRACE_ALL, "View name already in place.\n");
            ret = EOK;
            goto done;
        } else {
            /* view name changed */
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "View name changed from [%s] to [%s].\n", tmp_str, view_name);
        }
    } else {
        add_view_name = true;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    msg->dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_BASE);
    if (msg->dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = EIO;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_VIEW_NAME,
                            add_view_name ? LDB_FLAG_MOD_ADD
                                          : LDB_FLAG_MOD_REPLACE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_string(msg, SYSDB_VIEW_NAME, view_name);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (view_container_exists) {
        ret = ldb_modify(sysdb->ldb, msg);
    } else {
        ret = ldb_add(sysdb->ldb, msg);
    }
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to %s view container",
                                    view_container_exists ? "modify" : "add");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_delete_view_tree(struct sysdb_ctx *sysdb, const char *view_name)
{
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, SYSDB_TMPL_VIEW_SEARCH_BASE,
                        view_name);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = EIO;
        goto done;
    }

    ret = sysdb_delete_recursive(sysdb, dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_recursive failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_invalidate_overrides(struct sysdb_ctx *sysdb)
{
    int ret;
    int sret;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    struct ldb_result *res;
    size_t c;
    struct ldb_message *msg;
    struct ldb_dn *base_dn;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    base_dn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_CACHE_EXPIRE, LDB_FLAG_MOD_REPLACE,
                            NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }
    ret = ldb_msg_add_string(msg, SYSDB_CACHE_EXPIRE, "1");
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start failed.\n");
        goto done;
    }
    in_transaction = true;

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
                     NULL, "%s", SYSDB_UC);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        msg->dn = res->msgs[c]->dn;

        ret = ldb_modify(sysdb->ldb, msg);
        if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_modify failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    talloc_free(res);

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res, base_dn, LDB_SCOPE_SUBTREE,
                     NULL, "%s", SYSDB_GC);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    for (c = 0; c < res->count; c++) {
        msg->dn = res->msgs[c]->dn;

        ret = ldb_modify(sysdb->ldb, msg);
        if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_modify failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = EOK;

done:
    if (in_transaction) {
        if (ret == EOK) {
            sret = sysdb_transaction_commit(sysdb);
            if (sret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_commit failed, " \
                                         "nothing we can do about.\n");
                ret = sret;
            }
        } else {
            sret = sysdb_transaction_cancel(sysdb);
            if (sret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_cancel failed, " \
                                         "nothing we can do about.\n");
            }
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
add_name_and_aliases_for_name_override(struct sss_domain_info *domain,
                                       struct sysdb_attrs *attrs,
                                       bool add_name,
                                       const char *name_override)
{
    char *fq_name = NULL;
    int ret;

    if (strchr(name_override, '@') == NULL) {
        fq_name = sss_tc_fqname(attrs, domain->names, domain, name_override);
        if (fq_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_tc_fqname failed.\n");
            return ENOMEM;
        }

        if (!domain->case_sensitive) {
            ret = sysdb_attrs_add_lc_name_alias(attrs, fq_name);
        } else {
            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS,
                                         fq_name);
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_add_lc_name_alias failed.\n");
            goto done;
        }
    }

    if (add_name) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_DEFAULT_OVERRIDE_NAME,
                                     fq_name == NULL ? name_override : fq_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_lc_name_alias failed.\n");
            goto done;
        }
    }

    if (!domain->case_sensitive) {
        ret = sysdb_attrs_add_lc_name_alias(attrs, name_override);
    } else {
        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME_ALIAS, name_override);
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_lc_name_alias failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(fq_name);
    return ret;
}

errno_t sysdb_store_override(struct sss_domain_info *domain,
                             const char *view_name,
                             enum sysdb_member_type type,
                             struct sysdb_attrs *attrs, struct ldb_dn *obj_dn)
{
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    int ret;
    struct ldb_dn *override_dn;
    const char *override_dn_str;
    const char *obj_dn_str;
    const char *obj_attrs[] = { SYSDB_OBJECTCLASS,
                                SYSDB_OVERRIDE_DN,
                                NULL};
    size_t count = 0;
    struct ldb_message **msgs;
    struct ldb_message *msg = NULL;
    const char *obj_override_dn;
    bool add_ref = true;
    size_t c;
    bool in_transaction = false;
    bool has_override = true;
    const char *name_override;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (attrs != NULL) {
        has_override = true;
        ret = sysdb_attrs_get_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                     &anchor);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing anchor in override attributes.\n");
            ret = EINVAL;
            goto done;
        }

        override_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                                     SYSDB_TMPL_OVERRIDE, anchor, view_name);
        if (override_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        /* if there is no override for the given object, just store the DN of
         * the object iself in the SYSDB_OVERRIDE_DN attribute to indicate
         * that it was checked if an override exists and none was found. */
        has_override = false;
        override_dn = obj_dn;
    }

    override_dn_str = ldb_dn_get_linearized(override_dn);
    obj_dn_str = ldb_dn_get_linearized(obj_dn);
    if (override_dn_str == NULL || obj_dn_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_get_linearized failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, obj_dn, LDB_SCOPE_BASE,
                             NULL, obj_attrs, &count, &msgs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Object to override does not exists.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
        }
        goto done;
    }
    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Base searched returned more than one object.\n");
        ret = EINVAL;
        goto done;
    }

    obj_override_dn = ldb_msg_find_attr_as_string(msgs[0], SYSDB_OVERRIDE_DN,
                                                  NULL);
    if (obj_override_dn != NULL) {
        if (strcmp(obj_override_dn, override_dn_str) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Existing [%s] and new [%s] override DN do not match.\n",
                   obj_override_dn, override_dn_str);
            ret = EINVAL;
            goto done;
        }

        add_ref = false;
    }

    ret = ldb_transaction_start(domain->sysdb->ldb);
    if (ret != EOK) {
        return sysdb_error_to_errno(ret);
    }
    in_transaction = true;

    if (has_override) {
        ret = ldb_delete(domain->sysdb->ldb, override_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "ldb_delete failed, maybe object did not exist. Ignoring.\n");
        }

        ret = sysdb_attrs_get_string(attrs, SYSDB_NAME, &name_override);
        if (ret == EOK) {
            ret = add_name_and_aliases_for_name_override(domain, attrs, false,
                                                         name_override);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "add_name_and_aliases_for_name_override failed.\n");
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        msg = ldb_msg_new(tmp_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = override_dn;

        msg->elements = talloc_array(msg, struct ldb_message_element,
                                     attrs->num);
        if (msg->elements == NULL) {
            ret = ENOMEM;
            goto done;
        }

        /* TODO: add nameAlias for case-insentitive searches */
        for (c = 0; c < attrs->num; c++) {
            msg->elements[c] = attrs->a[c];
            msg->elements[c].flags = LDB_FLAG_MOD_ADD;
        }
        msg->num_elements = attrs->num;

        ret = ldb_msg_add_empty(msg, SYSDB_OBJECTCLASS, LDB_FLAG_MOD_ADD, NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        switch(type) {
        case SYSDB_MEMBER_USER:
            ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                                     SYSDB_OVERRIDE_USER_CLASS);
            break;
        case SYSDB_MEMBER_GROUP:
            ret = ldb_msg_add_string(msg, SYSDB_OBJECTCLASS,
                                     SYSDB_OVERRIDE_GROUP_CLASS);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected object type.\n");
            ret = EINVAL;
            goto done;
        }
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_OBJECT_DN, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_OBJECT_DN, obj_dn_str);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_add(domain->sysdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store override entry: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    if (add_ref) {
        talloc_free(msg);
        msg = ldb_msg_new(tmp_ctx);
        if (msg == NULL) {
            ret = ENOMEM;
            goto done;
        }

        msg->dn = obj_dn;

        ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_ADD,
                                NULL);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_msg_add_string(msg, SYSDB_OVERRIDE_DN, override_dn_str);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        ret = ldb_modify(domain->sysdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to store override DN: %s(%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(domain->sysdb->ldb));
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

    ret = EOK;

done:
    if (in_transaction) {
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "Error: %d (%s)\n", ret, strerror(ret));
            ldb_transaction_cancel(domain->sysdb->ldb);
        } else {
            ret = ldb_transaction_commit(domain->sysdb->ldb);
            ret = sysdb_error_to_errno(ret);
        }
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

static errno_t safe_original_attributes(struct sss_domain_info *domain,
                                        struct sysdb_attrs *attrs,
                                        struct ldb_dn *obj_dn,
                                        const char **allowed_attrs)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *orig_obj;
    char *orig_attr_name;
    struct ldb_message_element *el = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_obj, obj_dn,
                     LDB_SCOPE_BASE, NULL, NULL);
    if (ret != EOK || orig_obj->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Original object not found.\n");
        goto done;
    }

    /* Safe orginal values in attributes prefixed by OriginalAD. */
    for (c = 0; allowed_attrs[c] != NULL; c++) {
        el = ldb_msg_find_element(orig_obj->msgs[0], allowed_attrs[c]);
        if (el != NULL) {
            orig_attr_name = talloc_asprintf(tmp_ctx, "%s%s",
                                             ORIGINALAD_PREFIX,
                                             allowed_attrs[c]);
            if (orig_attr_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_val(attrs, orig_attr_name,
                                      &el->values[0]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_val failed.\n");
                goto done;
            }
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Original object does not have [%s] set.\n",
                  allowed_attrs[c]);
        }
    }

    /* Add existing aliases to new ones */
    el = ldb_msg_find_element(orig_obj->msgs[0], SYSDB_NAME_ALIAS);
    if (el != NULL) {
        for (c = 0; c < el->num_values; c++) {
            /* To avoid issue with ldb_modify if e.g. the orginal and the
             * override name are the same, we use the *_safe version here. */
            ret = sysdb_attrs_add_val_safe(attrs, SYSDB_NAME_ALIAS,
                                           &el->values[c]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_val failed.\n");
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_apply_default_override(struct sss_domain_info *domain,
                                     struct sysdb_attrs *override_attrs,
                                     struct ldb_dn *obj_dn)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *attrs;
    size_t c;
    size_t d;
    size_t num_values;
    struct ldb_message_element *el = NULL;
    const char *allowed_attrs[] = { SYSDB_UIDNUM,
                                    SYSDB_GIDNUM,
                                    SYSDB_GECOS,
                                    SYSDB_HOMEDIR,
                                    SYSDB_SHELL,
                                    SYSDB_NAME,
                                    SYSDB_SSH_PUBKEY,
                                    NULL };
    bool override_attrs_found = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; allowed_attrs[c] != NULL; c++) {
        ret = sysdb_attrs_get_el_ext(override_attrs, allowed_attrs[c], false,
                                     &el);
        if (ret == EOK) {
            override_attrs_found = true;

            if (strcmp(allowed_attrs[c], SYSDB_NAME) == 0) {
                if (el->values[0].data[el->values[0].length] != '\0') {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "String attribute does not end with \\0.\n");
                    ret = EINVAL;
                    goto done;
                }

                ret = add_name_and_aliases_for_name_override(domain, attrs,
                                                   true,
                                                   (char *) el->values[0].data);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "add_name_and_aliases_for_name_override failed.\n");
                    goto done;
                }
            } else {
                num_values = el->num_values;
                /* Only SYSDB_SSH_PUBKEY is allowed to have multiple values. */
                if (strcmp(allowed_attrs[c], SYSDB_SSH_PUBKEY) != 0
                        && num_values != 1) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "Override attribute for [%s] has more [%zd] " \
                          "than one value, using only the first.\n",
                          allowed_attrs[c], num_values);
                    num_values = 1;
                }

                for (d = 0; d < num_values; d++) {
                    ret = sysdb_attrs_add_val(attrs,  allowed_attrs[c],
                                              &el->values[d]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_attrs_add_val failed.\n");
                        goto done;
                    }
                    DEBUG(SSSDBG_TRACE_ALL,
                          "Override [%s] with [%.*s] for [%s].\n",
                          allowed_attrs[c], (int) el->values[d].length,
                          el->values[d].data, ldb_dn_get_linearized(obj_dn));
                }
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el_ext failed.\n");
            goto done;
        }
    }

    if (override_attrs_found) {
        ret = safe_original_attributes(domain, attrs, obj_dn, allowed_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "safe_original_attributes failed.\n");
            goto done;
        }

        ret = sysdb_set_entry_attr(domain->sysdb, obj_dn, attrs, SYSDB_MOD_REP);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}


#define SYSDB_USER_NAME_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_USER_CLASS")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_USER_UID_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_USER_CLASS")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_GROUP_NAME_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_GROUP_CLASS")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GROUP_GID_OVERRIDE_FILTER "(&(objectClass="SYSDB_OVERRIDE_GROUP_CLASS")("SYSDB_GIDNUM"=%lu))"

enum override_object_type {
    OO_TYPE_UNDEF = 0,
    OO_TYPE_USER,
    OO_TYPE_GROUP
};

static errno_t sysdb_search_override_by_name(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             const char *filter,
                                             const char **attrs,
                                             struct ldb_result **override_obj,
                                             struct ldb_result **orig_obj)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *base_dn;
    struct ldb_result *override_res;
    struct ldb_result *orig_res;
    char *sanitized_name;
    char *lc_sanitized_name;
    const char *src_name;
    int ret;
    const char *orig_obj_dn;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_VIEW_SEARCH_BASE, domain->view_name);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* If this is a subdomain we need to use fully qualified names for the
     * search as well by default */
    src_name = sss_get_domain_name(tmp_ctx, name, domain);
    if (src_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_get_domain_name failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, src_name, domain,
                                      &sanitized_name, &lc_sanitized_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_filter_sanitize_for_dom failed.\n");
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &override_res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, filter,
                     lc_sanitized_name,
                     sanitized_name, sanitized_name);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (override_res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No user override found for name [%s].\n",
                                 name);
        ret = ENOENT;
        goto done;
    } else if (override_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one override for name [%s].\n", name);
        ret = EINVAL;
        goto done;
    }

    if (orig_obj != NULL) {
        orig_obj_dn = ldb_msg_find_attr_as_string(override_res->msgs[0],
                                                  SYSDB_OVERRIDE_OBJECT_DN,
                                                  NULL);
        if (orig_obj_dn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing link to original object in override [%s].\n",
                  ldb_dn_get_linearized(override_res->msgs[0]->dn));
            ret = EINVAL;
            goto done;
        }

        base_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, orig_obj_dn);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_res, base_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        *orig_obj = talloc_steal(mem_ctx, orig_res);
    }


    *override_obj = talloc_steal(mem_ctx, override_res);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_search_user_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                             struct sss_domain_info *domain,
                                             const char *name,
                                             const char **attrs,
                                             struct ldb_result **override_obj,
                                             struct ldb_result **orig_obj)
{

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_USER_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_group_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            const char **attrs,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_GROUP_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_user_override_by_name(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain,
                                           const char *name,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    const char *attrs[] = SYSDB_PW_ATTRS;

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_USER_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

errno_t sysdb_search_group_override_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    const char *attrs[] = SYSDB_GRSRC_ATTRS;

    return sysdb_search_override_by_name(mem_ctx, domain, name,
                                         SYSDB_GROUP_NAME_OVERRIDE_FILTER,
                                         attrs, override_obj, orig_obj);
}

static errno_t sysdb_search_override_by_id(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain,
                                           unsigned long int id,
                                           enum override_object_type type,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    TALLOC_CTX *tmp_ctx;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    static const char *group_attrs[] = SYSDB_GRSRC_ATTRS;
    const char **attrs;
    struct ldb_dn *base_dn;
    struct ldb_result *override_res;
    struct ldb_result *orig_res;
    int ret;
    const char *orig_obj_dn;
    const char *filter;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    base_dn = ldb_dn_new_fmt(tmp_ctx, domain->sysdb->ldb,
                             SYSDB_TMPL_VIEW_SEARCH_BASE, domain->view_name);
    if (base_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt failed.\n");
        ret = ENOMEM;
        goto done;
    }

    switch(type) {
    case OO_TYPE_USER:
        filter = SYSDB_USER_UID_OVERRIDE_FILTER;
        attrs = user_attrs;
        break;
    case OO_TYPE_GROUP:
        filter = SYSDB_GROUP_GID_OVERRIDE_FILTER;
        attrs = group_attrs;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected override object type [%d].\n",
                                   type);
        ret = EINVAL;
        goto done;
    }

    ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &override_res, base_dn,
                     LDB_SCOPE_SUBTREE, attrs, filter, id);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (override_res->count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No user override found for %s with id [%lu].\n",
              (type == OO_TYPE_USER ? "user" : "group"), id);
        ret = ENOENT;
        goto done;
    } else if (override_res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one override for id [%lu].\n", id);
        ret = EINVAL;
        goto done;
    }

    if (orig_obj != NULL) {
        orig_obj_dn = ldb_msg_find_attr_as_string(override_res->msgs[0],
                                                  SYSDB_OVERRIDE_OBJECT_DN,
                                                  NULL);
        if (orig_obj_dn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing link to original object in override [%s].\n",
                  ldb_dn_get_linearized(override_res->msgs[0]->dn));
            ret = EINVAL;
            goto done;
        }

        base_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, orig_obj_dn);
        if (base_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &orig_res, base_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        *orig_obj = talloc_steal(mem_ctx, orig_res);
    }


    *override_obj = talloc_steal(mem_ctx, override_res);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_search_user_override_by_uid(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          uid_t uid,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_id(mem_ctx, domain, uid, OO_TYPE_USER,
                                       override_obj, orig_obj);
}

errno_t sysdb_search_group_override_by_gid(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            gid_t gid,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj)
{
    return sysdb_search_override_by_id(mem_ctx, domain, gid, OO_TYPE_GROUP,
                                       override_obj, orig_obj);
}

/**
 * @brief Add override data to the original object
 *
 * @param[in] domain Domain struct, needed to access the cache
 * @oaram[in] obj The original object
 * @param[in] override_obj The object with the override data, may be NULL
 * @param[in] req_attrs List of attributes to be requested, if not set a
 *                      default list dependig on the object type will be used
 *
 * @return EOK - Override data was added successfully
 * @return ENOMEM - There was insufficient memory to complete the operation
 * @return ENOENT - The original object did not have the SYSDB_OVERRIDE_DN
 *                  attribute or the value of the attribute points an object
 *                  which does not exists. Both conditions indicate that the
 *                  cache must be refreshed.
 */
errno_t sysdb_add_overrides_to_object(struct sss_domain_info *domain,
                                      struct ldb_message *obj,
                                      struct ldb_message *override_obj,
                                      const char **req_attrs)
{
    int ret;
    const char *override_dn_str;
    struct ldb_dn *override_dn;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_message *override;
    uint64_t uid;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    static const char *group_attrs[] = SYSDB_GRSRC_ATTRS;
    const char **attrs;
    struct attr_map {
        const char *attr;
        const char *new_attr;
    } attr_map[] = {
        {SYSDB_UIDNUM, OVERRIDE_PREFIX SYSDB_UIDNUM},
        {SYSDB_GIDNUM, OVERRIDE_PREFIX SYSDB_GIDNUM},
        {SYSDB_GECOS, OVERRIDE_PREFIX SYSDB_GECOS},
        {SYSDB_HOMEDIR, OVERRIDE_PREFIX SYSDB_HOMEDIR},
        {SYSDB_SHELL, OVERRIDE_PREFIX SYSDB_SHELL},
        {SYSDB_NAME, OVERRIDE_PREFIX SYSDB_NAME},
        {SYSDB_SSH_PUBKEY, OVERRIDE_PREFIX SYSDB_SSH_PUBKEY},
        {NULL, NULL}
    };
    size_t c;
    size_t d;
    struct ldb_message_element *tmp_el;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (override_obj == NULL) {
        override_dn_str = ldb_msg_find_attr_as_string(obj,
                                                      SYSDB_OVERRIDE_DN, NULL);
        if (override_dn_str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing override DN for objext [%s].\n",
                  ldb_dn_get_linearized(obj->dn));
            ret = ENOENT;
            goto done;
        }

        override_dn = ldb_dn_new(tmp_ctx, domain->sysdb->ldb, override_dn_str);
        if (override_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        if (ldb_dn_compare(obj->dn, override_dn) == 0) {
            DEBUG(SSSDBG_TRACE_ALL, "Object [%s] has no overrides.\n",
                                    ldb_dn_get_linearized(obj->dn));
            ret = EOK;
            goto done;
        }

        attrs = req_attrs;
        if (attrs == NULL) {
            uid = ldb_msg_find_attr_as_uint64(obj, SYSDB_UIDNUM, 0);
            if (uid == 0) {
                /* No UID hence group object */
                attrs = group_attrs;
            } else {
                attrs = user_attrs;
            }
        }

        ret = ldb_search(domain->sysdb->ldb, tmp_ctx, &res, override_dn,
                         LDB_SCOPE_BASE, attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        if (res->count == 1) {
            override = res->msgs[0];
        } else if (res->count == 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "Override object [%s] does not exists.\n",
                                     override_dn_str);
            ret = ENOENT;
            goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Base search for override object returned [%d] results.\n",
                  res->count);
            ret = EINVAL;
            goto done;
        }
    } else {
        override = override_obj;
    }

    for (c = 0; attr_map[c].attr != NULL; c++) {
        tmp_el = ldb_msg_find_element(override, attr_map[c].attr);
        if (tmp_el != NULL) {
            for (d = 0; d < tmp_el->num_values; d++) {
                ret = ldb_msg_add_steal_value(obj, attr_map[c].new_attr,
                                              &tmp_el->values[d]);
                if (ret != LDB_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_value failed.\n");
                    ret = sysdb_error_to_errno(ret);
                    goto done;
                }
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sysdb_add_group_member_overrides(struct sss_domain_info *domain,
                                         struct ldb_message *obj)
{
    int ret;
    size_t c;
    struct ldb_message_element *members;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *member_dn;
    struct ldb_result *member_obj;
    struct ldb_result *override_obj;
    static const char *member_attrs[] = SYSDB_PW_ATTRS;
    const char *override_dn_str;
    struct ldb_dn *override_dn;
    const char *memberuid;

    members = ldb_msg_find_element(obj, SYSDB_MEMBER);
    if (members == NULL || members->num_values == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Group has no members.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < members->num_values; c++) {
        member_dn = ldb_dn_from_ldb_val(tmp_ctx, domain->sysdb->ldb,
                                        &members->values[c]);
        if (member_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_from_ldb_val failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = ldb_search(domain->sysdb->ldb, member_dn, &member_obj, member_dn,
                         LDB_SCOPE_BASE, member_attrs, NULL);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        if (member_obj->count != 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Base search for member object returned [%d] results.\n",
                  member_obj->count);
            ret = EINVAL;
            goto done;
        }

        override_dn_str = ldb_msg_find_attr_as_string(member_obj->msgs[0],
                                                      SYSDB_OVERRIDE_DN, NULL);
        if (override_dn_str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Missing override DN for objext [%s].\n",
                  ldb_dn_get_linearized(member_obj->msgs[0]->dn));
            ret = ENOENT;
            goto done;
        }

        override_dn = ldb_dn_new(member_obj, domain->sysdb->ldb,
                                 override_dn_str);
        if (override_dn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        memberuid = NULL;
        if (ldb_dn_compare(member_obj->msgs[0]->dn, override_dn) != 0) {
            DEBUG(SSSDBG_TRACE_ALL, "Checking override for object [%s].\n",
                  ldb_dn_get_linearized(member_obj->msgs[0]->dn));

            ret = ldb_search(domain->sysdb->ldb, member_obj, &override_obj,
                             override_dn, LDB_SCOPE_BASE, member_attrs, NULL);
            if (ret != LDB_SUCCESS) {
                ret = sysdb_error_to_errno(ret);
                goto done;
            }

            if (override_obj->count != 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                     "Base search for override object returned [%d] results.\n",
                     member_obj->count);
                ret = EINVAL;
                goto done;
            }

            memberuid = ldb_msg_find_attr_as_string(override_obj->msgs[0],
                                                    SYSDB_NAME,
                                                    NULL);
        }

        if (memberuid == NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "No override name available.\n");

            memberuid = ldb_msg_find_attr_as_string(member_obj->msgs[0],
                                                    SYSDB_NAME,
                                                    NULL);
            if (memberuid == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Object [%s] has no name.\n",
                      ldb_dn_get_linearized(member_obj->msgs[0]->dn));
                ret = EINVAL;
                goto done;
            }
        }

        ret = ldb_msg_add_string(obj, OVERRIDE_PREFIX SYSDB_MEMBERUID,
                                 memberuid);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_string failed.\n");
            ret = sysdb_error_to_errno(ret);
            goto done;
        }

        /* Free all temporary data of the current member to avoid memory usage
         * spikes. All temporary data should be allocated below member_dn. */
        talloc_free(member_dn);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

struct ldb_message_element *
sss_view_ldb_msg_find_element(struct sss_domain_info *dom,
                                              const struct ldb_message *msg,
                                              const char *attr_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *val;
    char *override_attr_name;

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = NULL;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = NULL;
            goto done;
        }

        val = ldb_msg_find_element(msg, override_attr_name);
        if (val != NULL) {
            goto done;
        }
    }

    val = ldb_msg_find_element(msg, attr_name);

done:
    talloc_free(tmp_ctx);
    return val;
}

uint64_t sss_view_ldb_msg_find_attr_as_uint64(struct sss_domain_info *dom,
                                              const struct ldb_message *msg,
                                              const char *attr_name,
                                              uint64_t default_value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    uint64_t val;
    char *override_attr_name;

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = default_value;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = default_value;
            goto done;
        }

        if (ldb_msg_find_element(msg, override_attr_name) != NULL) {
            val = ldb_msg_find_attr_as_uint64(msg, override_attr_name,
                                              default_value);
            goto done;
        }
    }

    val = ldb_msg_find_attr_as_uint64(msg, attr_name, default_value);

done:
    talloc_free(tmp_ctx);
    return val;
}

const char *sss_view_ldb_msg_find_attr_as_string(struct sss_domain_info *dom,
                                                 const struct ldb_message *msg,
                                                 const char *attr_name,
                                                 const char * default_value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *val;
    char *override_attr_name;

    if (DOM_HAS_VIEWS(dom)) {
        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
            val = default_value;
            goto done;
        }

        override_attr_name = talloc_asprintf(tmp_ctx, "%s%s", OVERRIDE_PREFIX,
                                                              attr_name);
        if (override_attr_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            val = default_value;
            goto done;
        }

        if (ldb_msg_find_element(msg, override_attr_name) != NULL) {
            val = ldb_msg_find_attr_as_string(msg, override_attr_name,
                                              default_value);
            goto done;
        }
    }

    val = ldb_msg_find_attr_as_string(msg, attr_name, default_value);

done:
    talloc_free(tmp_ctx);
    return val;
}
