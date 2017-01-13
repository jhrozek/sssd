/*
   SSSD

   KCM Server - ccache storage in sssd-secrets

   Copyright (C) Red Hat, 2016

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

#include "config.h"

#include <stdio.h>
#include <talloc.h>
#include <jansson.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/tev_curl.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

/* The base for storing secrets is:
 *  http://localhost/kcm/persistent/$uid
 *
 * Under $base, there are two containers:
 *  /ccache     - stores the ccaches
 *  /ntlm       - stores NTLM creds [Not implement yet]
 *
 * There is also a special entry that contains the UUID of the default
 * cache for this UID:
 *  /default    - stores the UUID of the default ccache for this UID
 *
 * Each ccache has a name and an UUID. On the secrets level, the 'secret'
 * is a concatenation of the stringified UUID and the name separated
 * by a plus-sign.
 */

#define KCM_SEC_URL        "http://localhost/kcm/persistent"
#define KCM_SEC_BASE_FMT    KCM_SEC_URL"/%"SPRIuid"/"
#define KCM_SEC_CCACHE_FMT  KCM_SEC_BASE_FMT"ccache/"
#define KCM_SEC_DFL_FMT     KCM_SEC_BASE_FMT"default"

#define KS_JSON_VERSION     1

#ifndef SSSD_SECRETS_SOCKET
#define SSSD_SECRETS_SOCKET VARDIR"/run/secrets.socket"
#endif  /* SSSD_SECRETS_SOCKET */

#ifndef SEC_TIMEOUT
#define SEC_TIMEOUT         5
#endif /* SEC_TIMEOUT */

#define SEC_KEY_SEPARATOR   '-'

/* Just to keep the name of the ccache readable */
#define MAX_CC_NUM          99999

static const char *container_url_create(TALLOC_CTX *mem_ctx,
                                        struct cli_creds *client)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SEC_CCACHE_FMT,
                           cli_creds_get_uid(client));
}

static const char *cc_url_create(TALLOC_CTX *mem_ctx,
                                 struct cli_creds *client,
                                 const char *sec_key)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SEC_CCACHE_FMT"%s",
                           cli_creds_get_uid(client),
                           sec_key);
}

static const char *dfl_url_create(TALLOC_CTX *mem_ctx,
                                  struct cli_creds *client)
{
    return talloc_asprintf(mem_ctx,
                           KCM_SEC_DFL_FMT,
                           cli_creds_get_uid(client));
}

static const char *sec_key_create(TALLOC_CTX *mem_ctx,
                                  const char *name,
                                  uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    uuid_unparse(uuid, uuid_str);
    return talloc_asprintf(mem_ctx,
                           "%s%c%s", uuid_str, SEC_KEY_SEPARATOR, name);
}

static errno_t sec_key_get_uuid(const char *sec_key,
                                uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    if (strlen(sec_key) < UUID_STR_SIZE + 2) {
        /* One char for separator and at least one for the name */
        DEBUG(SSSDBG_CRIT_FAILURE, "Key %s is too short\n", sec_key);
        return EINVAL;
    }

    if (sec_key[UUID_STR_SIZE-1] != SEC_KEY_SEPARATOR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Key doesn't contain the separator\n");
        return EINVAL;
    }

    strncpy(uuid_str, sec_key, UUID_STR_SIZE-1);
    uuid_str[UUID_STR_SIZE-1] = '\0';
    uuid_parse(uuid_str, uuid);
    return EOK;
}

static const char *sec_key_get_name(const char *sec_key)
{
    if (strlen(sec_key) < UUID_STR_SIZE + 2) {
        /* One char for separator and at least one for the name */
        DEBUG(SSSDBG_CRIT_FAILURE, "Key %s is too short\n", sec_key);
        return NULL;
    }

    return sec_key + UUID_STR_SIZE;
}

static errno_t sec_key_parse(TALLOC_CTX *mem_ctx,
                             const char *sec_key,
                             const char **_name,
                             uuid_t uuid)
{
    char uuid_str[UUID_STR_SIZE];

    if (strlen(sec_key) < UUID_STR_SIZE + 2) {
        /* One char for separator and at least one for the name */
        DEBUG(SSSDBG_CRIT_FAILURE, "Key %s is too short\n", sec_key);
        return EINVAL;
    }

    strncpy(uuid_str, sec_key, sizeof(uuid_str));
    if (sec_key[UUID_STR_SIZE - 1] != SEC_KEY_SEPARATOR) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Key doesn't contain the separator\n");
        return EINVAL;
    }
    uuid_str[UUID_STR_SIZE-1] = '\0';

    *_name = talloc_strdup(mem_ctx, sec_key + UUID_STR_SIZE);
    if (*_name == NULL) {
        return ENOMEM;
    }
    uuid_parse(uuid_str, uuid);

    return EOK;
}

static bool sec_key_match_name(const char *sec_key,
                               const char *name)
{
    if (strlen(sec_key) < UUID_STR_SIZE + 2) {
        /* One char for separator and at least one for the name */
        DEBUG(SSSDBG_MINOR_FAILURE, "Key %s is too short\n", sec_key);
        return false;
    }

    return strcmp(sec_key + UUID_STR_SIZE, name) == 0;
}

static const char *find_by_name(const char **sec_key_list,
                                const char *name)
{
    const char *sec_name = NULL;

    if (sec_key_list == NULL) {
        return NULL;
    }

    for (int i = 0; sec_key_list[i]; i++) {
        if (sec_key_match_name(sec_key_list[i], name)) {
            sec_name = sec_key_list[i];
            break;
        }
    }

    return sec_name;
}

static bool sec_key_match_uuid(const char *sec_key,
                               uuid_t uuid)
{
    errno_t ret;
    uuid_t key_uuid;

    ret = sec_key_get_uuid(sec_key, key_uuid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot convert key to UUID\n");
        return false;
    }

    return uuid_compare(key_uuid, uuid) == 0;
}

static const char *find_by_uuid(const char **sec_key_list,
                                uuid_t uuid)
{
    const char *sec_name = NULL;

    if (sec_key_list == NULL) {
        return NULL;
    }

    for (int i = 0; sec_key_list[i]; i++) {
        if (sec_key_match_uuid(sec_key_list[i], uuid)) {
            sec_name = sec_key_list[i];
            break;
        }
    }

    return sec_name;
}

/*
 * ccache marshalling to JSON
 */

/*
 * Creates an array of principal elements that will be used later
 * in the form of:
 *          "componenets": [ "elem1", "elem2", ...]
 */
static json_t *princ_data_to_json(krb5_principal princ)
{
    json_t *jdata = NULL;
    json_t *data_array = NULL;
    int ret;

    data_array = json_array();
    if (data_array == NULL) {
        return NULL;
    }

    for (ssize_t i = 0; i < princ->length; i++) {
        jdata = json_stringn(princ->data[i].data, princ->data[i].length);
        if (jdata == NULL) {
            json_decref(data_array);
            return NULL;
        }

        ret = json_array_append_new(data_array, jdata);
        if (ret != 0) {
            json_decref(jdata);
            json_decref(data_array);
            return NULL;
        }
        /* data_array now owns the reference to jdata */
    }

    return data_array;
}

/* Creates:
 *      {
 *          "type": "number",
 *          "realm": "string",
 *          "componenents": [ "elem1", "elem2", ...]
 *      }
 */
static json_t *princ_to_json(krb5_principal princ)
{
    json_t *jprinc = NULL;
    json_t *components = NULL;
    json_error_t error;

    components = princ_data_to_json(princ);
    if (components == NULL) {
        return NULL;
    }

    jprinc = json_pack_ex(&error,
                          JSON_STRICT,
                          "{s:i, s:s%, s:o}",
                          "type", princ->type,
                          "realm", princ->realm.data, princ->realm.length,
                          "components", components);
    if (jprinc == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        json_decref(components);
        return NULL;
    }

    return jprinc;
}

/* Creates:
 *          {
 *              "uuid": <data>,
 *              "payload": <data>,
 *          },
 */
static json_t *cred_to_json(struct kcm_cred *crd)
{
    char uuid_str[UUID_STR_SIZE];
    uint8_t *cred_blob_data;
    size_t cred_blob_size;
    json_t *jcred;
    json_error_t error;
    char *base64_cred_blob;

    uuid_unparse(crd->uuid, uuid_str);
    cred_blob_data = sss_iobuf_get_data(crd->cred_blob);
    cred_blob_size = sss_iobuf_get_size(crd->cred_blob);

    base64_cred_blob = sss_base64_encode(crd, cred_blob_data, cred_blob_size);
    if (base64_cred_blob == NULL) {
        return NULL;
    }

    jcred = json_pack_ex(&error,
                         JSON_STRICT,
                         "{s:s, s:s}",
                         "uuid", uuid_str,
                         "payload", base64_cred_blob);
    talloc_free(base64_cred_blob);
    if (jcred == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON cred structure on line %d: %s\n",
              error.line, error.text);
        return NULL;
    }
    return jcred;
}

/*
 * Creates:
 *      [
 *          {
 *              "uuid": <data>,
 *              "payload": <data>,
 *          },
 *          ...
 *      ]
 */
static json_t *creds_to_json_array(struct kcm_cred *creds)
{
    struct kcm_cred *crd;
    json_t *array;
    json_t *jcred;

    array = json_array();
    if (array == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(crd, creds) {
        jcred = cred_to_json(crd);
        if (jcred == NULL) {
            json_decref(array);
            return NULL;
        }

        json_array_append_new(array, jcred);
        /* array now owns jcred */
        jcred = NULL;
    }

    return array;
}

/*
 * The ccache is formatted in JSON as:
 * {
 *      version: number
 *      kdc_offset: number
 *      principal : {
 *          "type": "number",
 *          "realm": "string",
 *          "componenents": [ "elem1", "elem2", ...]
 *      }
 *      creds : [
 *                  {
 *                      "uuid": <data>,
 *                      "payload": <data>,
 *                  },
 *                  {
 *                      ...
 *                  }
 *             ]
 *      }
 * }
 */
static json_t *ccache_to_json(struct kcm_ccache *cc)
{
    json_t *princ = NULL;
    json_t *creds = NULL;
    json_t *jcc = NULL;

    princ = princ_to_json(cc->client);
    if (princ == NULL) {
        return NULL;
    }

    creds = creds_to_json_array(cc->creds);
    if (creds == NULL) {
        json_decref(princ);
        return NULL;
    }

    jcc = json_pack("{s:i, s:i, s:o, s:o}",
                    "version", KS_JSON_VERSION,
                    "kdc_offset", cc->kdc_offset,
                    "principal", princ,
                    "creds", creds);
    if (jcc == NULL) {
        json_decref(creds);
        json_decref(princ);
        return NULL;
    }

    return jcc;
}

static errno_t ccache_to_sec_kv(TALLOC_CTX *mem_ctx,
                                struct kcm_ccache *cc,
                                const char **_sec_key,
                                const char **_sec_value)
{
    json_t *jcc = NULL;
    char *jdump;

    jcc = ccache_to_json(cc);
    if (jcc == NULL) {
        return ENOMEM;
    }

    /* it would be more efficient to learn the size with json_dumpb and
     * a NULL buffer, but that's only available since 2.10
     */
    jdump = json_dumps(jcc, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    if (jdump == NULL) {
        return ERR_JSON_ENCODING;
    }

    *_sec_key = sec_key_create(mem_ctx, cc->name, cc->uuid);
    *_sec_value = talloc_strdup(mem_ctx, jdump);
    free(jdump);
    json_decref(jcc);
    if (*_sec_key == NULL || *_sec_value == NULL) {
        return ENOMEM;
    }

    return EOK;
}

/*
 * ccache unmarshalling from JSON
 */
static errno_t json_element_to_krb5_data(TALLOC_CTX *mem_ctx,
                                         json_t *element,
                                         krb5_data *data)
{
    const char *str_value;
    size_t str_len;

    str_value = json_string_value(element);
    str_len = json_string_length(element);
    if (str_value == NULL || str_len == 0) {
        return EINVAL;
    }

    data->data = talloc_strndup(mem_ctx, str_value, str_len);
    if (data->data == NULL) {
        return ENOMEM;
    }
    data->length = str_len;

    return EOK;
}

static errno_t json_array_to_krb5_data(TALLOC_CTX *mem_ctx,
                                       json_t *array,
                                       krb5_data **_data,
                                       size_t *_len)
{
    errno_t ret;
    int ok;
    size_t len;
    size_t idx;
    json_t *element;
    krb5_data *data;

    ok = json_is_array(array);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json object is not an array.\n");
        return ERR_JSON_DECODING;
    }

    len = json_array_size(array);
    if (len == 0) {
        *_data = NULL;
        *_len = 0;
        return EOK;
    }

    data = talloc_zero_array(mem_ctx, krb5_data, len);
    if (data == NULL) {
        return ENOMEM;
    }

    json_array_foreach(array, idx, element) {
        ret = json_element_to_krb5_data(data, element, &data[idx]);
        if (ret != EOK) {
            talloc_free(data);
            return ret;
        }
    }

    *_data = data;
    *_len = len;
    return EOK;
}

static errno_t json_to_princ(TALLOC_CTX *mem_ctx,
                             json_t *js_princ,
                             krb5_principal *_princ)
{
    errno_t ret;
    json_t *components = NULL;
    int ok;
    krb5_principal princ = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char *realm_str;
    size_t realm_size;
    json_error_t error;

    ok = json_is_object(js_princ);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json principal is not an object.\n");
        ret = ERR_JSON_DECODING;
        goto done;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    princ = talloc_zero(tmp_ctx, struct krb5_principal_data);
    if (princ == NULL) {
        return ENOMEM;
    }
    princ->magic = KV5M_PRINCIPAL;

    ret = json_unpack_ex(js_princ,
                         &error,
                         JSON_STRICT,
                         "{s:i, s:s%, s:o}",
                         "type", &princ->type,
                         "realm", &realm_str, &realm_size,
                         "components", &components);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        ret = EINVAL;
        goto done;
    }

    princ->realm.data = talloc_strndup(mem_ctx, realm_str, realm_size);
    if (princ->realm.data == NULL) {
        return ENOMEM;
    }
    princ->realm.length = realm_size;
    /* FIXME - realm magic */

    /* FIXME - overflow */
    ret = json_array_to_krb5_data(princ, components,
                                  &princ->data,
                                  (size_t *) &princ->length);
    if (ret != EOK) {
        ret = EINVAL;
        goto done;
    }

    *_princ = talloc_steal(mem_ctx, princ);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t json_elem_to_cred(TALLOC_CTX *mem_ctx,
                                 json_t *element,
                                 struct kcm_cred **_crd)
{
    errno_t ret;
    char *uuid_str;
    json_error_t error;
    uuid_t uuid;
    struct sss_iobuf *cred_blob;
    const char *base64_cred_blob;
    struct kcm_cred *crd;
    uint8_t *outbuf;
    size_t outbuf_size;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = json_unpack_ex(element,
                         &error,
                         JSON_STRICT,
                         "{s:s, s:s}",
                         "uuid", &uuid_str,
                         "payload", &base64_cred_blob);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON cred structure on line %d: %s\n",
              error.line, error.text);
        return EINVAL;
    }

    uuid_parse(uuid_str, uuid);

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    outbuf = sss_base64_decode(tmp_ctx, base64_cred_blob, &outbuf_size);
    if (outbuf == NULL) {
        ret = EIO;
        goto done;
    }

    cred_blob = sss_iobuf_init_readonly(tmp_ctx, outbuf, outbuf_size);
    if (cred_blob == NULL) {
        ret = ENOMEM;
        goto done;
    }

    crd = kcm_cred_new(tmp_ctx, uuid, cred_blob);
    if (crd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *_crd = talloc_steal(mem_ctx, crd);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t json_to_creds(struct kcm_ccache *cc,
                             json_t *jcreds)
{
    errno_t ret;
    int ok;
    size_t idx;
    json_t *value;
    struct kcm_cred *crd;

    ok = json_is_array(jcreds);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json creds object is not an array.\n");
        return ERR_JSON_DECODING;
    }

    json_array_foreach(jcreds, idx, value) {
        ret = json_elem_to_cred(cc, value, &crd);
        if (ret != EOK) {
            return ret;
        }

        ret = kcm_cc_store_creds(cc, crd);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static errno_t sec_json_value_to_ccache(struct kcm_ccache *cc,
                                        json_t *root)
{
    errno_t ret;
    json_t *princ = NULL;
    json_t *creds = NULL;
    json_error_t error;
    int version;

    ret = json_unpack_ex(root,
                         &error,
                         JSON_STRICT,
                         "{s:i, s:i, s:o, s:o}",
                         "version", &version,
                         "kdc_offset", &cc->kdc_offset,
                         "principal", &princ,
                         "creds", &creds);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON creds structure on line %d: %s\n",
              error.line, error.text);
        return EINVAL;
    }

    if (version != KS_JSON_VERSION) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Expected version %d, received version %d\n",
              KS_JSON_VERSION, version);
        return EINVAL;
    }

    ret = json_to_princ(cc, princ, &cc->client);
    if (ret != EOK) {
        return ret;
    }

    ret = json_to_creds(cc, creds);
    if (ret != EOK) {
        return EOK;
    }

    return EOK;
}

static errno_t sec_value_to_json(const char *input,
                                 json_t **_root)
{
    json_t *root = NULL;
    json_error_t error;
    int ok;

    root = json_loads(input, 0, &error);
    if (root == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse JSON payload on line %d: %s\n",
              error.line, error.text);
        return ERR_JSON_DECODING;
    }

    ok = json_is_object(root);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Json data is not an object.\n");
        json_decref(root);
        return ERR_JSON_DECODING;
    }

    *_root = root;
    return EOK;
}

/*
 * sec_key is a concatenation of the ccache's UUID and name
 * sec_value is the JSON dump of the ccache contents
 */
static errno_t sec_kv_to_ccache(TALLOC_CTX *mem_ctx,
                                const char *sec_key,
                                const char *sec_value,
                                struct cli_creds *client,
                                struct kcm_ccache **_cc)
{
    errno_t ret;
    json_t *root = NULL;
    struct kcm_ccache *cc = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    ret = sec_value_to_json(sec_value, &root);
    if (ret != EOK) {
        goto done;
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cc = talloc_zero(tmp_ctx, struct kcm_ccache);
    if (cc == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* We rely on sssd-secrets only searching the user's subtree so we
     * set the ownership to the client
     */
    cc->owner.uid = cli_creds_get_uid(client);
    cc->owner.gid = cli_creds_get_gid(client);

    ret = sec_key_parse(cc, sec_key, &cc->name, cc->uuid);
    if (ret != EOK) {
        goto done;
    }

    ret = sec_json_value_to_ccache(cc, root);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
    *_cc = talloc_steal(mem_ctx, cc);
done:
    talloc_free(tmp_ctx);
    json_decref(root);
    return ret;
}

static errno_t ccache_to_sec_input(TALLOC_CTX *mem_ctx,
                                   struct kcm_ccache *cc,
                                   struct cli_creds *client,
                                   const char **_url,
                                   struct sss_iobuf **_payload)
{
    errno_t ret;
    const char *key;
    const char *value;
    const char *url;
    struct sss_iobuf *payload;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ccache_to_sec_kv(mem_ctx, cc, &key, &value);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert cache %s to JSON [%d]: %s\n",
              cc->name, ret, sss_strerror(ret));
        goto done;
    }

    url = cc_url_create(tmp_ctx, client, key);
    if (url == NULL) {
        ret = ENOMEM;
        goto done;
    }

    payload = sss_iobuf_init_readonly(tmp_ctx,
                                      (const uint8_t *) value,
                                      strlen(value)+1);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create payload buffer\n");
        goto done;
    }

    ret = EOK;
    *_url = talloc_steal(mem_ctx, url);
    *_payload = talloc_steal(mem_ctx, payload);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *sec_headers[] = {
    "Content-type: application/octet-stream",
    NULL,
};

struct ccdb_sec {
    struct tcurl_ctx *tctx;
};

static errno_t http2errno(int http_code)
{
    if (http_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "HTTP request returned %d\n", http_code);
    }

    switch (http_code) {
    case 200:
        return EOK;
    case 404:
        return ERR_NO_CREDS;
    case 400:
        return ERR_INPUT_PARSE;
    case 403:
        return EACCES;
    case 409:
        return EEXIST;
    case 413:
        return E2BIG;
    case 507:
        return ENOSPC;
    }

    return EIO;
}

/*
 * Helper request to list all UUID+name pairs
 */
struct sec_list_state {
    const char **sec_key_list;
    size_t sec_key_list_len;
};

static void sec_list_done(struct tevent_req *subreq);
static errno_t sec_list_parse(struct sss_iobuf *outbuf,
                              TALLOC_CTX *mem_ctx,
                              const char ***_list,
                              size_t *_list_len);

static struct tevent_req *sec_list_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct ccdb_sec *secdb,
                                        struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_list_state *state = NULL;
    errno_t ret;
    const char *container_url;

    req = tevent_req_create(mem_ctx, &state, struct sec_list_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Listing all ccaches in the secrets store\n");
    container_url = container_url_create(state, client);
    if (container_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_list_state *state = tevent_req_data(req,
                                                struct sec_list_state);
    struct sss_iobuf *outbuf;
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (http_code == 404) {
        /* If no ccaches are found, return an empty list */
        state->sec_key_list = talloc_zero_array(state, const char *, 1);
        if (state->sec_key_list == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    } else if (http_code == 200) {
        ret = sec_list_parse(outbuf, state,
                             &state->sec_key_list,
                             &state->sec_key_list_len);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    } else {
        tevent_req_error(req, http2errno(http_code));
        return;
    }

    tevent_req_done(req);
}

static errno_t sec_list_parse(struct sss_iobuf *outbuf,
                              TALLOC_CTX *mem_ctx,
                              const char ***_list,
                              size_t *_list_len)
{
    json_t *root;
    uint8_t *sec_http_list;
    json_error_t error;
    json_t *element;
    errno_t ret;
    int ok;
    size_t idx;
    const char **list;
    size_t list_len;

    sec_http_list = sss_iobuf_get_data(outbuf);
    if (sec_http_list == NULL) {
        return EINVAL;
    }

    root = json_loads((const char *) sec_http_list, 0, &error);
    if (root == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "Failed to parse JSON payload on line %d: %s\n",
                error.line, error.text);
        return ERR_JSON_DECODING;
    }

    ok = json_is_array(root);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "list reply is not an object.\n");
        ret = ERR_JSON_DECODING;
        goto done;
    }

    list_len = json_array_size(root);
    list = talloc_zero_array(mem_ctx, const char *, list_len + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(root, idx, element) {
        list[idx] = talloc_strdup(list, json_string_value(element));
        if (list[idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
    *_list = list;
    *_list_len = list_len;
done:
    if (ret != EOK) {
        talloc_free(list);
    }
    json_decref(root);
    return ret;
}

static errno_t sec_list_recv(struct tevent_req *req,
                             TALLOC_CTX *mem_ctx,
                             const char ***_sec_key_list,
                             size_t *_sec_key_list_len)

{
    struct sec_list_state *state = tevent_req_data(req,
                                                struct sec_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_sec_key_list != NULL) {
        *_sec_key_list = talloc_steal(mem_ctx, state->sec_key_list);
    }
    if (_sec_key_list_len) {
        *_sec_key_list_len = state->sec_key_list_len;
    }
    return EOK;
}

/*
 * Helper request to get a ccache by key
 */
struct sec_get_state {
    const char *sec_key;
    struct cli_creds *client;

    struct kcm_ccache *cc;
};

static void sec_get_done(struct tevent_req *subreq);

static struct tevent_req *sec_get_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct ccdb_sec *secdb,
                                       struct cli_creds *client,
                                       const char *sec_key)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_get_state *state = NULL;
    errno_t ret;
    const char *cc_url;

    req = tevent_req_create(mem_ctx, &state, struct sec_get_state);
    if (req == NULL) {
        return NULL;
    }
    state->sec_key = sec_key;
    state->client = client;

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving ccache %s\n", sec_key);

    cc_url = cc_url_create(state, state->client, state->sec_key);
    if (cc_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state,
                             ev,
                             secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             cc_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_get_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_get_state *state = tevent_req_data(req,
                                                struct sec_get_state);
    struct sss_iobuf *outbuf;
    const char *sec_value;
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    sec_value = (const char *) sss_iobuf_get_data(outbuf);
    if (sec_value == NULL) {
        tevent_req_error(req, EINVAL);
        return;
    }

    ret = sec_kv_to_ccache(state,
                           state->sec_key,
                           sec_value,
                           state->client,
                           &state->cc);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot convert JSON keyval to ccache blob [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sec_get_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct kcm_ccache **_cc)
{
    struct sec_get_state *state = tevent_req_data(req, struct sec_get_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/*
 * Helper request to get a ccache name or ID
 */
struct sec_get_ccache_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;
    const char *name;
    uuid_t uuid;

    const char *sec_key;

    struct kcm_ccache *cc;
};

static void sec_get_ccache_list_done(struct tevent_req *subreq);
static void sec_get_ccache_done(struct tevent_req *subreq);

static struct tevent_req *sec_get_ccache_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct ccdb_sec *secdb,
                                              struct cli_creds *client,
                                              const char *name,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sec_get_ccache_state *state = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sec_get_ccache_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    state->name = name;
    uuid_copy(state->uuid, uuid);

    if ((name == NULL && uuid_is_null(uuid))
            || (name != NULL && !uuid_is_null(uuid))) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected one of name, uuid to be set\n");
        ret = EINVAL;
        goto immediate;
    }

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, sec_get_ccache_list_done, req);
    return req;


immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void sec_get_ccache_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);
    const char **sec_key_list;

    ret = sec_list_recv(subreq, state, &sec_key_list, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot list keys [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->name != NULL) {
        state->sec_key = find_by_name(sec_key_list, state->name);
    } else {
        state->sec_key = find_by_uuid(sec_key_list, state->uuid);
    }

    if (state->sec_key == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot find %s in the ccache list\n", state->name);
        /* Don't error out, just return an empty list */
        tevent_req_done(req);
        return;
    }

    subreq = sec_get_send(state,
                          state->ev,
                          state->secdb,
                          state->client,
                          state->sec_key);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, sec_get_ccache_done, req);
}

static void sec_get_ccache_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);

    ret = sec_get_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot resolve key to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sec_get_ccache_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   struct kcm_ccache **_cc)
{
    struct sec_get_ccache_state *state = tevent_req_data(req,
                                                struct sec_get_ccache_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/*
 * The actual sssd-secrets back end
 */
static errno_t ccdb_sec_init(struct kcm_ccdb *db)
{
    struct ccdb_sec *secdb = NULL;

    secdb = talloc_zero(db, struct ccdb_sec);
    if (secdb == NULL) {
        return ENOMEM;
    }

    secdb->tctx = tcurl_init(secdb, db->ev);
    if (secdb->tctx == NULL) {
        talloc_zfree(secdb);
        return ENOMEM;
   }

    /* We just need the random numbers to generate pseudo-random ccache names
     * and avoid conflicts */
    srand(time(NULL));

    db->db_handle = secdb;
    return EOK;
}

struct ccdb_sec_dummy_state {
};

struct ccdb_sec_nextid_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    unsigned int nextid;
    char *nextid_name;

    int maxtries;
    int numtry;
};

static errno_t ccdb_sec_nextid_generate(struct tevent_req *req);
static void ccdb_sec_nextid_list_done(struct tevent_req *subreq);

/* Generate a unique ID */
/* GET the name from secrets, if doesn't exist, OK, if exists, try again */
static struct tevent_req *ccdb_sec_nextid_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_sec_nextid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_nextid_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;

    state->maxtries = 3;
    state->numtry = 0;

    ret = ccdb_sec_nextid_generate(req);
    if (ret != EOK) {
        goto immediate;
    }

    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_sec_nextid_generate(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);

    if (state->numtry >= state->maxtries) {
        return EBUSY;
    }

    state->nextid = rand() % MAX_CC_NUM;
    state->nextid_name = talloc_asprintf(state, "%"SPRIuid":%u",
                                         cli_creds_get_uid(state->client),
                                         state->nextid);
    if (state->nextid_name == NULL) {
        return ENOMEM;
    }

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ccdb_sec_nextid_list_done, req);

    state->numtry++;
    return EOK;
}

static void ccdb_sec_nextid_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);
    const char **sec_key_list;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_name(sec_key_list[i], state->nextid_name) == true) {
            break;
        }
    }

    if (i < sec_key_list_len) {
        /* Try again */
        ret = ccdb_sec_nextid_generate(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_nextid_recv(struct tevent_req *req,
                                    unsigned int *_nextid)
{
    struct ccdb_sec_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_nextid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_nextid = state->nextid;
    return EOK;
}

/* IN:  HTTP PUT $base/default -d 'uuid' */
/* We chose only UUID here to avoid issues later with renaming */
static void ccdb_sec_set_default_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_set_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_dummy_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    struct sss_iobuf *uuid_iobuf;
    errno_t ret;
    const char *url;
    char uuid_str[UUID_STR_SIZE];

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    url = dfl_url_create(state, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    uuid_unparse(uuid, uuid_str);
    uuid_iobuf = sss_iobuf_init_readonly(state,
                                         (uint8_t *) uuid_str,
                                         UUID_STR_SIZE);
    if (uuid_iobuf == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_PATCH,
                             SSSD_SECRETS_SOCKET,
                             url,
                             sec_headers,
                             uuid_iobuf,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_set_default_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_set_default_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_dummy_state *state = tevent_req_data(req,
                                                struct ccdb_sec_dummy_state);

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* IN:  HTTP GET $base/default  */
/* OUT: uuid */
struct ccdb_sec_get_default_state {
    uuid_t uuid;
};

static void ccdb_sec_get_default_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_get_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_get_default_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    const char *url;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_get_default_state);
    if (req == NULL) {
        return NULL;
    }

    url = dfl_url_create(state, client);
    if (url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_GET,
                             SSSD_SECRETS_SOCKET,
                             url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_get_default_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_get_default_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_sec_get_default_state);
    struct sss_iobuf *outbuf;
    size_t uuid_size;

    ret = tcurl_http_recv(state, subreq, &http_code, &outbuf);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code == 404) {
        /* Return a NULL uuid */
        uuid_clear(state->uuid);
        tevent_req_done(req);
        return;
    } else if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    uuid_size = sss_iobuf_get_len(outbuf);
    if (uuid_size != UUID_STR_SIZE) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected UUID size %zu\n", uuid_size);
        tevent_req_error(req, EIO);
        return;
    }

    uuid_parse((const char *) sss_iobuf_get_data(outbuf), state->uuid);
    tevent_req_done(req);
}

static errno_t ccdb_sec_get_default_recv(struct tevent_req *req,
                                         uuid_t uuid)
{
    struct ccdb_sec_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_sec_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    uuid_copy(uuid, state->uuid);
    return EOK;
}

/* trailing slash for list */
/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
struct ccdb_sec_list_state {
    uuid_t *uuid_list;
};

static void ccdb_sec_list_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_list_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_list_state);
    if (req == NULL) {
        return NULL;
    }

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_list_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_list_state *state = tevent_req_data(req,
                                                struct ccdb_sec_list_state);
    const char **sec_key_list;
    size_t sec_key_list_len;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->uuid_list = talloc_array(state, uuid_t, sec_key_list_len + 1);
    if (state->uuid_list == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (size_t i = 0; i < sec_key_list_len; i++) {
        ret = sec_key_get_uuid(sec_key_list[i],
                               state->uuid_list[i]);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
    }
    /* Sentinel */
    uuid_clear(state->uuid_list[sec_key_list_len]);

    tevent_req_done(req);
}

static errno_t ccdb_sec_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  uuid_t **_uuid_list)
{
    struct ccdb_sec_list_state *state = tevent_req_data(req,
                                                struct ccdb_sec_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

struct ccdb_sec_getbyuuid_state {
    struct kcm_ccache *cc;
};


/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
/* for each item in list, compare with the uuid: portion */
/* HTTP GET $base/ccache/uuid:name  */
/* return result */
static void ccdb_sec_getbyuuid_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  uuid_t uuid)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_getbyuuid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_getbyuuid_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_getbyuuid_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_getbyuuid_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyuuid_state);

    ret = sec_get_ccache_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_getbyuuid_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_sec_getbyuuid_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

/* HTTP GET $base/ccache/  */
/* OUT: a list of <uuid:name, uuid:name> */
/* for each item in list, compare with the :name portion */
/* HTTP GET $base/ccache/uuid:name  */
/* return result */
struct ccdb_sec_getbyname_state {
    struct kcm_ccache *cc;
};

static void ccdb_sec_getbyname_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_getbyname_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  const char *name)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_getbyname_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    uuid_t null_uuid;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_getbyname_state);
    if (req == NULL) {
        return NULL;
    }
    uuid_clear(null_uuid);

    subreq = sec_get_ccache_send(state, ev, secdb, client, name, null_uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_getbyname_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_getbyname_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_getbyname_state *state = tevent_req_data(req,
                                            struct ccdb_sec_getbyname_state);

    ret = sec_get_ccache_recv(subreq, state, &state->cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_getbyname_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_sec_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_sec_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_sec_name_by_uuid_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    uuid_t uuid;

    const char *name;
};

static void ccdb_sec_name_by_uuid_done(struct tevent_req *subreq);

struct tevent_req *ccdb_sec_name_by_uuid_send(TALLOC_CTX *sec_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_name_by_uuid_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(sec_ctx, &state, struct ccdb_sec_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_name_by_uuid_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_name_by_uuid_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_name_by_uuid_state);
    const char **sec_key_list;
    const char *name;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_uuid(sec_key_list[i], state->uuid) == true) {
            /* Match, copy name */
            name = sec_key_get_name(sec_key_list[i]);
            if (name == NULL) {
                tevent_req_error(req, EINVAL);
                return;
            }

            state->name = talloc_strdup(state, name);
            if (state->name == NULL) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            tevent_req_done(req);
            return;
        }
    }

    tevent_req_error(req, ERR_KCM_CC_END);
    return;
}

errno_t ccdb_sec_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *sec_ctx,
                                   const char **_name)
{
    struct ccdb_sec_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_sec_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(sec_ctx, state->name);
    return EOK;
}

struct ccdb_sec_uuid_by_name_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;

    const char *name;

    uuid_t uuid;
};

static void ccdb_sec_uuid_by_name_done(struct tevent_req *subreq);

struct tevent_req *ccdb_sec_uuid_by_name_send(TALLOC_CTX *sec_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_uuid_by_name_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;

    req = tevent_req_create(sec_ctx, &state, struct ccdb_sec_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    state->name = name;

    subreq = sec_list_send(state, state->ev, state->secdb, state->client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_uuid_by_name_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_uuid_by_name_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_sec_uuid_by_name_state);
    const char **sec_key_list;
    size_t sec_key_list_len;
    size_t i;

    ret = sec_list_recv(subreq, state, &sec_key_list, &sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    for (i = 0; i < sec_key_list_len; i++) {
        if (sec_key_match_name(sec_key_list[i], state->name) == true) {
            /* Match, copy UUID */
            ret = sec_key_get_uuid(sec_key_list[i], state->uuid);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            tevent_req_done(req);
            return;
        }
    }

    tevent_req_error(req, ERR_KCM_CC_END);
    return;
}

errno_t ccdb_sec_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *sec_ctx,
                                   uuid_t _uuid)
{
    struct ccdb_sec_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_sec_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}

/* HTTP POST $base to create the container */
/* HTTP PUT $base to create the container. Since PUT errors out on duplicates, at least
 * we fail consistently here and don't overwrite the ccache on concurrent requests
 */
struct ccdb_sec_create_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;

    const char *key_url;
    struct sss_iobuf *ccache_payload;
};

static void ccdb_sec_container_done(struct tevent_req *subreq);
static void ccdb_sec_ccache_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_create_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               struct kcm_ccache *cc)
{
    struct tevent_req *subreq = NULL;
    struct tevent_req *req = NULL;
    struct ccdb_sec_create_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);
    errno_t ret;
    const char *container_url;
    const char *key;
    const char *value;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_create_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;

    DEBUG(SSSDBG_TRACE_FUNC, "Creating ccache storage for %s\n", cc->name);

    /* Do the encoding asap so that if we fail, we don't even attempt any
     * writes */
    ret = ccache_to_sec_kv(state, cc, &key, &value);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert cache %s to JSON [%d]: %s\n",
              cc->name, ret, sss_strerror(ret));
        goto immediate;
    }

    state->ccache_payload = sss_iobuf_init_readonly(state,
                                                    (const uint8_t *) value,
                                                    strlen(value)+1);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create payload buffer\n");
        goto immediate;
    }

    container_url = container_url_create(state, client);
    if (container_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    state->key_url = cc_url_create(state, client, key);
    if (state->key_url == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Creating the ccache container\n");
    subreq = tcurl_http_send(state, ev, secdb->tctx,
                             TCURL_HTTP_POST,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_container_done, req);
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_container_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_create_state *state = tevent_req_data(req,
                                                struct ccdb_sec_create_state);

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* Conflict is not an error as multiple ccaches are under the same
     * container */
    if (http_code != 200 && http_code != 409) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create the ccache container\n");
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "ccache container created\n");
    DEBUG(SSSDBG_TRACE_FUNC, "creating empty ccache payload\n");

    subreq = tcurl_http_send(state,
                             state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_PUT,
                             SSSD_SECRETS_SOCKET,
                             state->key_url,
                             sec_headers,
                             state->ccache_payload,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_ccache_done, req);
}

static void ccdb_sec_ccache_done(struct tevent_req *subreq)
{
    errno_t ret;
    int http_code;
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ccdb_sec_create_state *state = tevent_req_data(req,
                                                struct ccdb_sec_create_state);

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Communication with the secrets responder failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_create_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_sec_mod_cred_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    struct kcm_mod_ctx *mod_cc;

    struct ccdb_sec *secdb;
};

static void ccdb_sec_mod_cred_get_done(struct tevent_req *subreq);
static void ccdb_sec_mod_cred_patch_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_mod_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct kcm_ccdb *db,
                                            struct cli_creds *client,
                                            uuid_t uuid,
                                            struct kcm_mod_ctx *mod_cc)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_mod_cred_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_mod_cred_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->db =db;
    state->client = client;
    state->secdb = secdb;
    state->mod_cc = mod_cc;

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, *ccdb_sec_mod_cred_get_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_mod_cred_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_mod_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_mod_cred_state);
    struct kcm_ccache *cc;
    const char *url;
    struct sss_iobuf *payload;

    ret = sec_get_ccache_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (cc == NULL) {
        tevent_req_error(req, ERR_KCM_CC_END);
        return;
    }

    kcm_mod_cc(cc, state->mod_cc);

    ret = ccache_to_sec_input(state, cc, state->client, &url, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to marshall modified ccache to payload [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_PATCH,
                             SSSD_SECRETS_SOCKET,
                             url,
                             sec_headers,
                             payload,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_mod_cred_patch_done, req);
}

static void ccdb_sec_mod_cred_patch_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_mod_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_mod_cred_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "HTTP PATCH request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        tevent_req_error(req, http2errno(http_code));
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_mod_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_sec_store_cred_state {
    struct tevent_context *ev;
    struct kcm_ccdb *db;
    struct cli_creds *client;
    struct sss_iobuf *cred_blob;

    struct ccdb_sec *secdb;
};

static void ccdb_sec_store_cred_get_done(struct tevent_req *subreq);
static void ccdb_sec_store_cred_patch_done(struct tevent_req *subreq);

/* HTTP PATCH $base/ccache/uuid:name */
static struct tevent_req *ccdb_sec_store_cred_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct kcm_ccdb *db,
                                                   struct cli_creds *client,
                                                   uuid_t uuid,
                                                   struct sss_iobuf *cred_blob)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_store_cred_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_store_cred_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->db =db;
    state->client = client;
    state->cred_blob = cred_blob;
    state->secdb = secdb;

    subreq = sec_get_ccache_send(state, ev, secdb, client, NULL, uuid);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, *ccdb_sec_store_cred_get_done, req);
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_store_cred_get_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_store_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_store_cred_state);
    struct kcm_ccache *cc;
    const char *url;
    struct sss_iobuf *payload;

    ret = sec_get_ccache_recv(subreq, state, &cc);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = kcm_cc_store_cred_blob(cc, state->cred_blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = ccache_to_sec_input(state, cc, state->client, &url, &payload);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to marshall modified ccache to payload [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_PATCH,
                             SSSD_SECRETS_SOCKET,
                             url,
                             sec_headers,
                             payload,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_store_cred_patch_done, req);
}

static void ccdb_sec_store_cred_patch_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_store_cred_state *state = tevent_req_data(req,
                                            struct ccdb_sec_store_cred_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "HTTP PATCH request failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        tevent_req_error(req, http2errno(http_code));
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_store_cred_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* HTTP DELETE $base/ccache/uuid:name */
struct ccdb_sec_delete_state {
    struct tevent_context *ev;
    struct ccdb_sec *secdb;
    struct cli_creds *client;
    uuid_t uuid;

    size_t sec_key_list_len;
};

static void ccdb_sec_delete_list_done(struct tevent_req *subreq);
static void ccdb_sec_delete_cc_done(struct tevent_req *subreq);
static void ccdb_sec_delete_container_done(struct tevent_req *subreq);

static struct tevent_req *ccdb_sec_delete_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               uuid_t uuid)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ccdb_sec_delete_state *state = NULL;
    struct ccdb_sec *secdb = talloc_get_type(db->db_handle, struct ccdb_sec);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_sec_delete_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->secdb = secdb;
    state->client = client;
    uuid_copy(state->uuid, uuid);

    subreq = sec_list_send(state, ev, secdb, client);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_list_done, req);
    return req;


immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ccdb_sec_delete_list_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    const char **sec_key_list;
    const char *sec_key;
    const char *cc_url;

    ret = sec_list_recv(subreq,
                        state,
                        &sec_key_list,
                        &state->sec_key_list_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (sec_key_list == 0) {
        tevent_req_done(req);
        return;
    }

    sec_key = find_by_uuid(sec_key_list, state->uuid);
    if (sec_key == NULL) {
        tevent_req_done(req);
        return;
    }

    cc_url = cc_url_create(state, state->client, sec_key);
    if (cc_url == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_DELETE,
                             SSSD_SECRETS_SOCKET,
                             cc_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_cc_done, req);
}

static void ccdb_sec_delete_cc_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    int http_code;
    const char *container_url;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    if (state->sec_key_list_len != 1) {
        DEBUG(SSSDBG_TRACE_FUNC, "There are other ccaches, done\n");
        tevent_req_done(req);
        return;
    }

    /* FIXME - make a function */
    container_url = container_url_create(state, state->client);
    if (container_url == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = tcurl_http_send(state, state->ev,
                             state->secdb->tctx,
                             TCURL_HTTP_DELETE,
                             SSSD_SECRETS_SOCKET,
                             container_url,
                             sec_headers,
                             NULL,
                             SEC_TIMEOUT);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ccdb_sec_delete_container_done, req);
}

static void ccdb_sec_delete_container_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ccdb_sec_delete_state *state = tevent_req_data(req,
                                                struct ccdb_sec_delete_state);
    int http_code;

    ret = tcurl_http_recv(state, subreq, &http_code, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (http_code != 200) {
        ret = http2errno(http_code);
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ccdb_sec_delete_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

const struct kcm_ccdb_ops ccdb_sec_ops = {
    .init = ccdb_sec_init,

    .nextid_send = ccdb_sec_nextid_send,
    .nextid_recv = ccdb_sec_nextid_recv,

    .set_default_send = ccdb_sec_set_default_send,
    .set_default_recv = ccdb_sec_set_default_recv,

    .get_default_send = ccdb_sec_get_default_send,
    .get_default_recv = ccdb_sec_get_default_recv,

    .list_send = ccdb_sec_list_send,
    .list_recv = ccdb_sec_list_recv,

    .getbyname_send = ccdb_sec_getbyname_send,
    .getbyname_recv = ccdb_sec_getbyname_recv,

    .getbyuuid_send = ccdb_sec_getbyuuid_send,
    .getbyuuid_recv = ccdb_sec_getbyuuid_recv,

    .name_by_uuid_send = ccdb_sec_name_by_uuid_send,
    .name_by_uuid_recv = ccdb_sec_name_by_uuid_recv,

    .uuid_by_name_send = ccdb_sec_uuid_by_name_send,
    .uuid_by_name_recv = ccdb_sec_uuid_by_name_recv,

    .create_send = ccdb_sec_create_send,
    .create_recv = ccdb_sec_create_recv,

    .mod_send = ccdb_sec_mod_send,
    .mod_recv = ccdb_sec_mod_recv,

    .store_cred_send = ccdb_sec_store_cred_send,
    .store_cred_recv = ccdb_sec_store_cred_recv,

    .delete_send = ccdb_sec_delete_send,
    .delete_recv = ccdb_sec_delete_recv,
};
