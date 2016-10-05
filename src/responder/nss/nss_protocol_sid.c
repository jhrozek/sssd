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

#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"

static errno_t fill_sid(struct sss_packet *packet,
                        enum sss_id_type id_type,
                        struct ldb_message *msg)
{
    int ret;
    const char *sid_str;
    struct sized_string sid;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;

    sid_str = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, NULL);
    if (sid_str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing SID.\n");
        return EINVAL;
    }

    to_sized_string(&sid, sid_str);

    ret = sss_packet_grow(packet, sid.len +  3* sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    memcpy(&body[pctr], sid.str, sid.len);

    return EOK;
}

static errno_t fill_orig(struct sss_packet *packet,
                         struct resp_ctx *rctx,
                         enum sss_id_type id_type,
                         struct ldb_message *msg)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;
    size_t c;
    size_t sum;
    size_t found;
    size_t array_size;
    size_t extra_attrs_count = 0;
    const char **extra_attrs_list = NULL;
    const char *orig_attr_list[] = {SYSDB_SID_STR,
                                    ORIGINALAD_PREFIX SYSDB_NAME,
                                    ORIGINALAD_PREFIX SYSDB_UIDNUM,
                                    ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                    ORIGINALAD_PREFIX SYSDB_HOMEDIR,
                                    ORIGINALAD_PREFIX SYSDB_GECOS,
                                    ORIGINALAD_PREFIX SYSDB_SHELL,
                                    SYSDB_UPN,
                                    SYSDB_DEFAULT_OVERRIDE_NAME,
                                    SYSDB_AD_ACCOUNT_EXPIRES,
                                    SYSDB_AD_USER_ACCOUNT_CONTROL,
                                    SYSDB_SSH_PUBKEY,
                                    SYSDB_USER_CERT,
                                    SYSDB_USER_EMAIL,
                                    SYSDB_ORIG_DN,
                                    SYSDB_ORIG_MEMBEROF,
                                    NULL};
    struct sized_string *keys;
    struct sized_string *vals;
    struct nss_ctx *nctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    nctx = talloc_get_type(rctx->pvt_ctx, struct nss_ctx);
    if (nctx->extra_attributes != NULL) {
        extra_attrs_list = nctx->extra_attributes;
            for(extra_attrs_count = 0;
                extra_attrs_list[extra_attrs_count] != NULL;
                extra_attrs_count++);
    }

    array_size = sizeof(orig_attr_list) + extra_attrs_count;
    keys = talloc_array(tmp_ctx, struct sized_string, array_size);
    vals = talloc_array(tmp_ctx, struct sized_string, array_size);
    if (keys == NULL || vals == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    sum = 0;
    found = 0;

    ret = process_attr_list(tmp_ctx, msg, orig_attr_list, &keys, &vals,
                            &array_size, &sum, &found);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
        goto done;
    }

    if (extra_attrs_count != 0) {
        ret = process_attr_list(tmp_ctx, msg, extra_attrs_list, &keys, &vals,
                                &array_size, &sum, &found);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "process_attr_list failed.\n");
            goto done;
        }
    }

    ret = sss_packet_grow(packet, sum +  3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        goto done;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    for (c = 0; c < found; c++) {
        memcpy(&body[pctr], keys[c].str, keys[c].len);
        pctr+= keys[c].len;
        memcpy(&body[pctr], vals[c].str, vals[c].len);
        pctr+= vals[c].len;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t fill_name(struct sss_packet *packet,
                         struct resp_ctx *rctx,
                         struct sss_domain_info *dom,
                         enum sss_id_type id_type,
                         bool apply_no_view,
                         struct ldb_message *msg)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *orig_name = NULL;
    struct sized_string *name;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;

    if (apply_no_view) {
        orig_name = ldb_msg_find_attr_as_string(msg,
                                                ORIGINALAD_PREFIX SYSDB_NAME,
                                                NULL);
    } else {
        if (DOM_HAS_VIEWS(dom)) {
            orig_name = ldb_msg_find_attr_as_string(msg,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL);
        }
    }

    if (orig_name == NULL) {
        orig_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    }
    if (orig_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing name.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sized_output_name(tmp_ctx, rctx, orig_name, dom, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
             "sized_output_name failed for %s: (%d): %s\n",
             orig_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_packet_grow(packet, name->len + 3 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        goto done;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    memcpy(&body[pctr], name->str, name->len);


    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t fill_id(struct sss_packet *packet,
                       enum sss_id_type id_type,
                       struct ldb_message *msg)
{
    int ret;
    uint8_t *body;
    size_t blen;
    size_t pctr = 0;
    uint64_t tmp_id;
    uint32_t id;

    if (id_type == SSS_ID_TYPE_GID) {
        tmp_id = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
    } else {
        tmp_id = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    }

    if (tmp_id == 0 || tmp_id >= UINT32_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid POSIX ID.\n");
        return EINVAL;
    }
    id = (uint32_t) tmp_id;

    ret = sss_packet_grow(packet, 4 * sizeof(uint32_t));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &blen);
    SAFEALIGN_SETMEM_UINT32(body, 1, &pctr); /* Num results */
    SAFEALIGN_SETMEM_UINT32(body + pctr, 0, &pctr); /* reserved */
    SAFEALIGN_COPY_UINT32(body + pctr, &id_type, &pctr);
    SAFEALIGN_COPY_UINT32(body + pctr, &id, &pctr);

    return EOK;
}
