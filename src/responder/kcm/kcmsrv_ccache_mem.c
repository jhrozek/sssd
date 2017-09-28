/*
   SSSD

   KCM Server - ccache in-memory storage

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

#include <talloc.h>
#include <stdio.h>

#include "util/util.h"
#include "responder/kcm/kcmsrv_ccache_be.h"

struct ccdb_mem;

/*
 * The KCM memory database is just a double-linked list of kcm_ccache structures
 */
struct ccache_mem_wrap {
    struct kcm_ccache *cc;
    bool is_default;

    struct ccache_mem_wrap *next;
    struct ccache_mem_wrap *prev;

    struct ccdb_mem *mem_be;
};

struct ccdb_mem {
    /* Both ccaches and the next-id are kept in memory */
    struct ccache_mem_wrap *head;
    unsigned int nextid;
};

static struct ccache_mem_wrap *memdb_get_by_uuid(struct ccdb_mem *memdb,
                                                 struct cli_creds *client,
                                                 uuid_t uuid)
{
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccache_mem_wrap *out = NULL;
    errno_t ret;

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        uuid_t cc_uuid;

        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (kcm_cc_access(ccwrap->cc, client)) {
            ret = kcm_cc_get_uuid(ccwrap->cc, cc_uuid);
            if (ret != EOK) {
                continue;
            }

            if (uuid_compare(uuid, cc_uuid) == 0) {
                out = ccwrap;
                break;
            }
        }
    }

    return out;
}

static struct ccache_mem_wrap *memdb_get_by_name(struct ccdb_mem *memdb,
                                                 struct cli_creds *client,
                                                 const char *name)
{
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccache_mem_wrap *out = NULL;

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        const char *ccname;

        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        ccname = kcm_cc_get_name(ccwrap->cc);
        if (ccname == NULL) {
            continue;
        }

        if (kcm_cc_access(ccwrap->cc, client)) {
            if (strcmp(ccname, name) == 0) {
                out = ccwrap;
                break;
            }
        }
    }

    return out;
}

/* Since with the in-memory database, the database operations are just
 * fake-async wrappers around otherwise sync operations, we don't often
 * need any state, so we use this empty structure instead
 */
struct ccdb_mem_dummy_state {
};

static int ccwrap_destructor(void *ptr)
{
    struct ccache_mem_wrap *ccwrap = talloc_get_type(ptr, struct ccache_mem_wrap);
    struct kcm_cred *crd;
    struct sss_iobuf *crd_blob;

    if (ccwrap == NULL) {
        return 0;
    }

    if (ccwrap->cc != NULL) {
        crd = kcm_cc_get_cred(ccwrap->cc);
        if (crd != NULL) {
            crd_blob = kcm_cred_get_creds(crd);
            if (crd_blob != NULL) {
                safezero(sss_iobuf_get_data(crd_blob),
                         sss_iobuf_get_size(crd_blob));
            }
        }
    }


    DLIST_REMOVE(ccwrap->mem_be->head, ccwrap);

    return 0;
}

static errno_t ccdb_mem_init(struct kcm_ccdb *db,
                             struct tevent_context *ev)
{
    struct ccdb_mem *memdb = NULL;

    memdb = talloc_zero(db, struct ccdb_mem);
    if (memdb == NULL) {
        return ENOMEM;
    }

    kcm_ccdb_set_handle(db, memdb);
    return EOK;
}

struct ccdb_mem_nextid_state {
    unsigned int nextid;
};

static struct tevent_req *ccdb_mem_nextid_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_nextid_state *state = NULL;
    struct ccdb_mem *memdb = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_nextid_state);
    if (req == NULL) {
        return NULL;
    }

    memdb = kcm_ccdb_get_handle(db);
    if (memdb == NULL) {
        ret = EIO;
        goto immediate;
    }

    state->nextid = memdb->nextid++;

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_nextid_recv(struct tevent_req *req,
                                    unsigned int *_nextid)
{
    struct ccdb_mem_nextid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_nextid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_nextid = state->nextid;
    return EOK;
}

struct ccdb_mem_list_state {
    uuid_t *uuid_list;
};

static struct tevent_req *ccdb_mem_list_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct kcm_ccdb *db,
                                             struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem_list_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    size_t num_ccaches = 0;
    size_t cc_index = 0;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_list_state);
    if (req == NULL) {
        return NULL;
    }

    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (kcm_cc_access(ccwrap->cc, client)) {
            num_ccaches++;
        }
    }

    state->uuid_list = talloc_zero_array(state, uuid_t, num_ccaches+1);
    if (state->uuid_list == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    cc_index = 0;
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (kcm_cc_access(ccwrap->cc, client)) {
            ret = kcm_cc_get_uuid(ccwrap->cc, state->uuid_list[cc_index]);
            if (ret != EOK) {
                continue;
            }
            cc_index++;
        }
    }
    uuid_clear(state->uuid_list[num_ccaches]);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_list_recv(struct tevent_req *req,
                                  TALLOC_CTX *mem_ctx,
                                  uuid_t **_uuid_list)
{
    struct ccdb_mem_list_state *state = tevent_req_data(req,
                                                struct ccdb_mem_list_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_uuid_list = talloc_steal(mem_ctx, state->uuid_list);
    return EOK;
}

static struct tevent_req *ccdb_mem_set_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client,
                                                    uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    struct ccache_mem_wrap *ccwrap = NULL;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    /* Reset all ccache defaults first */
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (kcm_cc_access(ccwrap->cc, client)) {
            ccwrap->is_default = false;
        }
    }

    /* Then set the default for the right ccache. This also allows to
     * pass a null uuid to just reset the old ccache (for example after
     * deleting the default
     */
    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap != NULL) {
        ccwrap->is_default = true;
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_set_default_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ccdb_mem_get_default_state {
    uuid_t dfl_uuid;
};

static struct tevent_req *ccdb_mem_get_default_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct kcm_ccdb *db,
                                                    struct cli_creds *client)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_get_default_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_get_default_state);
    if (req == NULL) {
        return NULL;
    }


    /* Reset all ccache defaults first */
    DLIST_FOR_EACH(ccwrap, memdb->head) {
        if (ccwrap->cc == NULL) {
            /* since KCM stores ccaches, better not crash.. */
            DEBUG(SSSDBG_CRIT_FAILURE, "BUG: ccwrap contains NULL cc\n");
            continue;
        }

        if (kcm_cc_access(ccwrap->cc, client) && ccwrap->is_default == true) {
            break;
        }
    }

    if (ccwrap == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
               "No ccache marked as default, returning null ccache\n");
        uuid_clear(state->dfl_uuid);
    } else {
        ret = kcm_cc_get_uuid(ccwrap->cc, state->dfl_uuid);
        if (ret != EOK) {
            goto fail;
        }
    }

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_get_default_recv(struct tevent_req *req,
                                         uuid_t dfl)
{
    struct ccdb_mem_get_default_state *state = tevent_req_data(req,
                                                struct ccdb_mem_get_default_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    uuid_copy(dfl, state->dfl_uuid);
    return EOK;
}

struct ccdb_mem_getbyuuid_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_mem_getbyuuid_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_getbyuuid_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyuuid_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap != NULL) {
        state->cc = kcm_ccache_shallow_dup(state, ccwrap->cc);
        if (state->cc == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyuuid_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyuuid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyuuid_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_mem_getbyname_state {
    struct kcm_ccache *cc;
};

static struct tevent_req *ccdb_mem_getbyname_send(TALLOC_CTX *mem_ctx,
                                                  struct tevent_context *ev,
                                                  struct kcm_ccdb *db,
                                                  struct cli_creds *client,
                                                  const char *name)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_getbyname_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_getbyname_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_name(memdb, client, name);
    if (ccwrap != NULL) {
        state->cc = kcm_ccache_shallow_dup(state, ccwrap->cc);
        if (state->cc == NULL) {
            ret = ENOMEM;
            goto immediate;
        }
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_getbyname_recv(struct tevent_req *req,
                                       TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache **_cc)
{
    struct ccdb_mem_getbyname_state *state = tevent_req_data(req,
                                                struct ccdb_mem_getbyname_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_cc = talloc_steal(mem_ctx, state->cc);
    return EOK;
}

struct ccdb_mem_name_by_uuid_state {
    const char *name;
};

struct tevent_req *ccdb_mem_name_by_uuid_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_name_by_uuid_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_name_by_uuid_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    state->name = talloc_strdup(state,
                                kcm_cc_get_name(ccwrap->cc));
    if (state->name == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t ccdb_mem_name_by_uuid_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   const char **_name)
{
    struct ccdb_mem_name_by_uuid_state *state = tevent_req_data(req,
                                                struct ccdb_mem_name_by_uuid_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_name = talloc_steal(mem_ctx, state->name);
    return EOK;
}

struct ccdb_mem_uuid_by_name_state {
    uuid_t uuid;
};

struct tevent_req *ccdb_mem_uuid_by_name_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct kcm_ccdb *db,
                                              struct cli_creds *client,
                                              const char *name)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_uuid_by_name_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_uuid_by_name_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_name(memdb, client, name);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = kcm_cc_get_uuid(ccwrap->cc, state->uuid);
    if (ret != EOK) {
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t ccdb_mem_uuid_by_name_recv(struct tevent_req *req,
                                   TALLOC_CTX *mem_ctx,
                                   uuid_t _uuid)
{
    struct ccdb_mem_uuid_by_name_state *state = tevent_req_data(req,
                                                struct ccdb_mem_uuid_by_name_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);
    uuid_copy(_uuid, state->uuid);
    return EOK;
}

static struct tevent_req *ccdb_mem_create_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               struct kcm_ccache *cc)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = talloc_zero(memdb, struct ccache_mem_wrap);
    if (ccwrap == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    ccwrap->cc = cc;
    ccwrap->mem_be = memdb;
    talloc_steal(ccwrap, cc);

    DLIST_ADD(memdb->head, ccwrap);
    talloc_set_destructor((TALLOC_CTX *) ccwrap, ccwrap_destructor);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_create_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_mod_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct kcm_ccdb *db,
                                            struct cli_creds *client,
                                            uuid_t uuid,
                                            struct kcm_mod_ctx *mod_cc)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    /* UUID is immutable, so search by that */
    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    kcm_mod_cc(ccwrap->cc, mod_cc);

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_mod_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_store_cred_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct kcm_ccdb *db,
                                                   struct cli_creds *client,
                                                   uuid_t uuid,
                                                   struct sss_iobuf *cred_blob)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    struct ccache_mem_wrap *ccwrap = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = kcm_cc_store_cred_blob(ccwrap->cc, cred_blob);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot store credentials to ccache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto immediate;
    }

    ret = EOK;
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_store_cred_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static struct tevent_req *ccdb_mem_delete_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct kcm_ccdb *db,
                                               struct cli_creds *client,
                                               uuid_t uuid)
{
    struct tevent_req *req = NULL;
    struct ccdb_mem_dummy_state *state = NULL;
    struct ccache_mem_wrap *ccwrap;
    struct ccdb_mem *memdb = kcm_ccdb_get_handle(db);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ccdb_mem_dummy_state);
    if (req == NULL) {
        return NULL;
    }

    ccwrap = memdb_get_by_uuid(memdb, client, uuid);
    if (ccwrap == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BUG: Attempting to free unknown ccache\n");
        ret = ERR_KCM_CC_END;
        goto immediate;
    }

    ret = EOK;
    /* Destructor takes care of everything */
    talloc_free(ccwrap);
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ccdb_mem_delete_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

const struct kcm_ccdb_ops ccdb_mem_ops = {
    .init = ccdb_mem_init,

    .nextid_send = ccdb_mem_nextid_send,
    .nextid_recv = ccdb_mem_nextid_recv,

    .set_default_send = ccdb_mem_set_default_send,
    .set_default_recv = ccdb_mem_set_default_recv,

    .get_default_send = ccdb_mem_get_default_send,
    .get_default_recv = ccdb_mem_get_default_recv,

    .list_send = ccdb_mem_list_send,
    .list_recv = ccdb_mem_list_recv,

    .getbyname_send = ccdb_mem_getbyname_send,
    .getbyname_recv = ccdb_mem_getbyname_recv,

    .getbyuuid_send = ccdb_mem_getbyuuid_send,
    .getbyuuid_recv = ccdb_mem_getbyuuid_recv,

    .name_by_uuid_send = ccdb_mem_name_by_uuid_send,
    .name_by_uuid_recv = ccdb_mem_name_by_uuid_recv,

    .uuid_by_name_send = ccdb_mem_uuid_by_name_send,
    .uuid_by_name_recv = ccdb_mem_uuid_by_name_recv,

    .create_send = ccdb_mem_create_send,
    .create_recv = ccdb_mem_create_recv,

    .mod_send = ccdb_mem_mod_send,
    .mod_recv = ccdb_mem_mod_recv,

    .store_cred_send = ccdb_mem_store_cred_send,
    .store_cred_recv = ccdb_mem_store_cred_recv,

    .delete_send = ccdb_mem_delete_send,
    .delete_recv = ccdb_mem_delete_recv,
};
