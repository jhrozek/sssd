/*
   SSSD

   Secrets Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#include "responder/secrets/secsrv_private.h"
#include "util/crypto/sss_crypto.h"
#include <ldb.h>

#define MKEY_SIZE (256 / 8)

struct local_context {
    struct ldb_context *ldb;
    struct sec_data master_key;
};

int local_decrypt(struct local_context *lctx, TALLOC_CTX *mem_ctx,
                  const char *secret, const char *enctype,
                  char **plain_secret)
{
    char *output;

    if (enctype && strcmp(enctype, "masterkey") == 0) {
        struct sec_data _secret;
        size_t outlen;
        int ret;

        _secret.data = (char *)sss_base64_decode(mem_ctx, secret,
                                                 &_secret.length);
        if (!_secret.data) return EINVAL;

        ret = sss_decrypt(mem_ctx, AES256_HMAC_SHA256,
                          (uint8_t *)lctx->master_key.data,
                          lctx->master_key.length,
                          (uint8_t *)_secret.data, _secret.length,
                          (uint8_t **)&output, &outlen);
        if (ret) return ret;

        if (((strnlen(output, outlen) + 1) != outlen) ||
            output[outlen - 1] != '\0') {
            return EIO;
        }
    } else {
        output = talloc_strdup(mem_ctx, secret);
        if (!output) return ENOMEM;
    }

    *plain_secret = output;
    return EOK;
}

int local_encrypt(struct local_context *lctx, TALLOC_CTX *mem_ctx,
                  const char *secret, const char *enctype,
                  char **ciphertext)
{
    struct sec_data _secret;
    char *output;
    int ret;

    if (!enctype || strcmp(enctype, "masterkey") != 0) return EINVAL;

    ret = sss_encrypt(mem_ctx, AES256_HMAC_SHA256,
                      (uint8_t *)lctx->master_key.data,
                      lctx->master_key.length,
                      (const uint8_t *)secret, strlen(secret) + 1,
                      (uint8_t **)&_secret.data, &_secret.length);
    if (ret) return ret;

    output = sss_base64_encode(mem_ctx,
                               (uint8_t *)_secret.data, _secret.length);
    if (!output) return ENOMEM;

    *ciphertext = output;
    return EOK;
}

int local_db_dn(TALLOC_CTX *mem_ctx,
                struct ldb_context *ldb,
                const char *req_path,
                struct ldb_dn **req_dn)
{
    struct ldb_dn *dn;
    const char *s, *e;
    int ret;

    dn = ldb_dn_new(mem_ctx, ldb, "cn=secrets");
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    s = req_path;

    while (s && *s) {
        e = strchr(s, '/');
        if (e) {
            if (e == s) {
                s++;
                continue;
            }
            if (!ldb_dn_add_child_fmt(dn, "cn=%.*s", (int)(e - s), s)) {
                ret = ENOMEM;
                goto done;
            }
            s = e + 1;
        } else {
            if (!ldb_dn_add_child_fmt(dn, "cn=%s", s)) {
                ret = ENOMEM;
                goto done;
            }
            s = NULL;
        }
    }

    *req_dn = dn;
    ret = EOK;

done:
    return ret;
}

char *local_dn_to_path(TALLOC_CTX *mem_ctx,
                       struct ldb_dn *basedn,
                       struct ldb_dn *dn)
{
    int basecomps;
    int dncomps;
    char *path = NULL;

    basecomps = ldb_dn_get_comp_num(basedn);
    dncomps = ldb_dn_get_comp_num(dn);

    for (int i = dncomps - basecomps; i > 0; i--) {
        const struct ldb_val *val;

        val = ldb_dn_get_component_val(dn, i - 1);
        if (!val) return NULL;

        if (path) {
            path = talloc_strdup_append_buffer(path, "/");
            if (!path) return NULL;
            path = talloc_strndup_append_buffer(path, (char *)val->data,
                                                val->length);
        } else {
            path = talloc_strndup(mem_ctx, (char *)val->data, val->length);
        }
        if (!path) return NULL;
    }

    return path;
}

int local_db_get_simple(TALLOC_CTX *mem_ctx,
                        struct local_context *lctx,
                        const char *req_path,
                        char **secret)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", "enctype", NULL };
    const char *filter = "(type=simple)";
    struct ldb_result *res;
    struct ldb_dn *dn;
    const char *attr_secret;
    const char *attr_enctype;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = local_db_dn(tmp_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                     attrs, filter);
    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    switch (res->count) {
    case 0:
        ret = ENOENT;
        goto done;
    case 1:
        break;
    default:
        ret = E2BIG;
        goto done;
    }

    attr_secret = ldb_msg_find_attr_as_string(res->msgs[0], "secret", NULL);
    if (!attr_secret) {
        ret = ENOENT;
        goto done;
    }

    attr_enctype = ldb_msg_find_attr_as_string(res->msgs[0], "enctype", NULL);

    if (attr_enctype) {
        ret = local_decrypt(lctx, mem_ctx, attr_secret, attr_enctype, secret);
        if (ret) goto done;
    } else {
        *secret = talloc_strdup(mem_ctx, attr_secret);
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int local_db_list_keys(TALLOC_CTX *mem_ctx,
                       struct local_context *lctx,
                       const char *req_path,
                       char ***_keys,
                       int *num_keys)
{
    TALLOC_CTX *tmp_ctx;
    static const char *attrs[] = { "secret", NULL };
    const char *filter = "(type=simple)";
    struct ldb_result *res;
    struct ldb_dn *dn;
    char **keys;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = local_db_dn(tmp_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_search(lctx->ldb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
                     attrs, filter);
    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    }

    keys = talloc_array(mem_ctx, char *, res->count);
    if (!keys) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < res->count; i++) {
        keys[i] = local_dn_to_path(keys, dn, res->msgs[i]->dn);
        if (!keys[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_keys = keys;
    *num_keys = res->count;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int local_db_put_simple(TALLOC_CTX *mem_ctx,
                        struct local_context *lctx,
                        const char *req_path,
                        const char *secret)
{
    struct ldb_message *msg;
    const char *enctype = "masterkey";
    char *enc_secret;
    int ret;

    msg = ldb_msg_new(mem_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    ret = local_encrypt(lctx, msg, secret, enctype, &enc_secret);
    if (ret != EOK) goto done;

    ret = local_db_dn(msg, lctx->ldb, req_path, &msg->dn);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "type", "simple");
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "enctype", enctype);
    if (ret != EOK) goto done;

    ret = ldb_msg_add_string(msg, "secret", enc_secret);
    if (ret != EOK) goto done;

    ret = ldb_add(lctx->ldb, msg);
    if (ret != EOK) {
        if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) ret = EEXIST;
        else ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(msg);
    return ret;
}

int local_db_delete(TALLOC_CTX *mem_ctx,
                    struct local_context *lctx,
                    const char *req_path)
{
    struct ldb_dn *dn;
    int ret;

    ret = local_db_dn(mem_ctx, lctx->ldb, req_path, &dn);
    if (ret != EOK) goto done;

    ret = ldb_delete(lctx->ldb, dn);
    if (ret != EOK) {
        ret = EIO;
    }

done:
    return ret;
}

int local_secrets_map_path(TALLOC_CTX *mem_ctx,
                           struct sec_req_ctx *secreq,
                           char **local_db_path)
{
    int ret;

    /* be strict for now */
    if (secreq->parsed_url.fragment != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI fragments: [%s]\n",
              secreq->parsed_url.fragment);
        return EINVAL;
    }

    if (secreq->parsed_url.userinfo != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unrecognized URI userinfo: [%s]\n",
              secreq->parsed_url.userinfo);
        return EINVAL;
    }

    /* only type simple for now */
    if (secreq->parsed_url.query != NULL) {
        ret = strcmp(secreq->parsed_url.query, "type=simple");
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Invalid URI query: [%s]\n",
                  secreq->parsed_url.query);
            return EINVAL;
        }
    }

    /* drop SEC_BASEPATH prefix */
    *local_db_path =
        talloc_strdup(mem_ctx, &secreq->mapped_path[sizeof(SEC_BASEPATH) - 1]);
    if (!*local_db_path) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to map request to local db path\n");
        return ENOMEM;
    }

    return EOK;
}


struct local_secret_state {
    struct tevent_context *ev;
    struct sec_req_ctx *secreq;
};

struct tevent_req *local_secret_req(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    void *provider_ctx,
                                    struct sec_req_ctx *secreq)
{
    struct tevent_req *req;
    struct local_secret_state *state;
    struct local_context *lctx;
    struct sec_data body = { 0 };
    char *req_path;
    char *secret;
    char **keys;
    int nkeys;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct local_secret_state);
    if (!req) return NULL;

    state->ev = ev;
    state->secreq = secreq;

    lctx = talloc_get_type(provider_ctx, struct local_context);
    if (!lctx) {
        ret = EIO;
        goto done;
    }

    ret = local_secrets_map_path(state, secreq, &req_path);
    if (ret) goto done;

    switch (secreq->method) {
    case HTTP_GET:
        if (req_path[strlen(req_path) - 1] == '/') {
            ret = local_db_list_keys(state, lctx, req_path, &keys, &nkeys);
            if (ret) goto done;

            ret = sec_array_to_json(state, keys, nkeys, &body.data);
            if (ret) goto done;
        } else {
            ret = local_db_get_simple(state, lctx, req_path, &secret);
            if (ret) goto done;

            ret = sec_simple_secret_to_json(state, secret, &body.data);
            if (ret) goto done;
        }

        body.length = strlen(body.data);
        break;

    case HTTP_PUT:
        ret = sec_json_to_simple_secret(state, secreq->body.data, &secret);
        if (ret) goto done;

        ret = local_db_put_simple(state, lctx, req_path, secret);
        if (ret) goto done;
        break;

    case HTTP_DELETE:
        ret = local_db_delete(state, lctx, req_path);
        if (ret) goto done;
        break;

    default:
        ret = EINVAL;
        goto done;
    }

    if (body.data) {
        ret = sec_http_reply_with_body(secreq, &secreq->reply, STATUS_200,
                                       "application/json", &body);
    } else {
        ret = sec_http_status_reply(secreq, &secreq->reply, STATUS_200);
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        /* shortcircuit the request here as all called functions are
         * synchronous and final and no further subrequests are made */
        tevent_req_done(req);
    }
    return tevent_req_post(req, state->ev);
}

int generate_master_key(const char *filename, size_t size)
{
    char buf[size];
    struct sec_data data = { buf, size };
    ssize_t rsize;
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return errno;

    rsize = sss_atomic_io_s(fd, data.data, data.length, true);
    close(fd);
    if (rsize != size) return EFAULT;

    fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, 0600);
    if (fd == -1) return errno;

    rsize = sss_atomic_io_s(fd, data.data, data.length, false);
    close(fd);
    if (rsize != size) {
        unlink(filename);
        return EFAULT;
    }

    return EOK;
}

/* FIXME: allocate on the responder context */
static struct provider_handle local_secrets_handle = {
    .fn = local_secret_req,
    .context = NULL,
};

int local_secrets_provider_handle(TALLOC_CTX *mem_ctx,
                                  struct provider_handle **handle)
{
    struct local_context *lctx;
    int ret;

    if (local_secrets_handle.context == NULL) {
        const char *mkey = SECRETS_DB_PATH"/.secrets.mkey";
        ssize_t size;
        int mfd;

        lctx = talloc_zero(NULL, struct local_context);
        if (!lctx) return ENOMEM;

        lctx->ldb = ldb_init(lctx, NULL);
        if (!lctx->ldb) return ENOMEM;

        ret = ldb_connect(lctx->ldb, SECRETS_DB_PATH"/secrets.ldb", 0, NULL);
        if (ret != LDB_SUCCESS) {
            talloc_free(lctx->ldb);
            return EIO;
        }

        lctx->master_key.data = talloc_size(lctx, MKEY_SIZE);
        if (!lctx->master_key.data) return ENOMEM;
        lctx->master_key.length = MKEY_SIZE;

        ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                      S_IFREG|S_IRUSR|S_IWUSR, 0);
        if (ret == ENOENT) {
            ret = generate_master_key(mkey, MKEY_SIZE);
            if (ret) return EFAULT;
            ret = check_and_open_readonly(mkey, &mfd, 0, 0,
                                          S_IFREG|S_IRUSR|S_IWUSR, 0);
        }
        if (ret) return EFAULT;

        size = sss_atomic_io_s(mfd, lctx->master_key.data,
                               lctx->master_key.length, true);
        close(mfd);
        if (size < 0 || size != lctx->master_key.length) return EIO;

        local_secrets_handle.context = lctx;
    }

    *handle = &local_secrets_handle;
    return EOK;
}
