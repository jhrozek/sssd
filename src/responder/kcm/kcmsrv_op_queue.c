/*
   SSSD

   KCM Server - the KCM operations wait queue

   Copyright (C) Red Hat, 2017

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
#include "util/util_creds.h"
#include "responder/kcm/kcmsrv_pvt.h"

#define QUEUE_HASH_SIZE      32

struct kcm_ops_queue_entry {
    struct tevent_queue_entry *qentry;
};

struct kcm_ops_queue {
    uid_t uid;
    struct kcm_ops_queue_ctx *qctx;
    struct tevent_context *ev;

    struct tevent_queue *tq;
};

struct kcm_ops_queue_ctx {
    /* UID:kcm_ops_queue */
    hash_table_t *wait_queue_hash;
};

/*
 * Per-UID wait queue
 *
 * They key in the hash table is the UID of the peer. The value of each
 * hash table entry is a tevent_queue structure
 */
struct kcm_ops_queue_ctx *kcm_ops_queue_create(TALLOC_CTX *mem_ctx)
{
    errno_t ret;
    struct kcm_ops_queue_ctx *queue_ctx;

    queue_ctx = talloc_zero(mem_ctx, struct kcm_ops_queue_ctx);
    if (queue_ctx == NULL) {
        return NULL;
    }

    ret = sss_hash_create_ex(mem_ctx, QUEUE_HASH_SIZE,
                             &queue_ctx->wait_queue_hash, 0, 0, 0, 0,
                             NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_hash_create failed [%d]: %s\n", ret, sss_strerror(ret));
        talloc_free(queue_ctx);
        return NULL;
    }

    return queue_ctx;
}

static void remove_queue(struct tevent_context *ctx,
                         struct tevent_immediate *im,
                         void *private_data)
{
    struct kcm_ops_queue *kcm_q;
    size_t qlen;
    int ret;
    hash_key_t key;

    kcm_q = talloc_get_type(private_data, struct kcm_ops_queue);
    if (kcm_q == NULL) {
        return;
    }

    qlen = tevent_queue_length(kcm_q->tq);
    if (qlen > 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Some requests are in the queue\n");
        return;
    }

    key.type = HASH_KEY_ULONG;
    key.ul = kcm_q->uid;

    /* If this was the last entry, remove the key (the UID) from the
     * hash table to signal the queue is empty
     */
    DEBUG(SSSDBG_TRACE_ALL, "Removing an empty queue\n");
    ret = hash_delete(kcm_q->qctx->wait_queue_hash, &key);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to remove wait queue for user %"SPRIuid"\n",
              kcm_q->uid);
        return;
    }

    talloc_free(kcm_q);
}

static void kcm_op_queue_trigger(struct tevent_req *req, void *private_data)
{
    struct tevent_immediate *imm;
    struct kcm_ops_queue *kcm_q;
    size_t qlen;

    if (private_data == NULL) {
        return;
    }

    kcm_q = talloc_get_type(private_data, struct kcm_ops_queue);
    if (kcm_q == NULL) {
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Marking %p as done\n", req);
    tevent_req_done(req);

    qlen = tevent_queue_length(kcm_q->tq);
    if (qlen > 0) {
        DEBUG(SSSDBG_TRACE_ALL, "More request to be enqueued, waiting..\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Scheduling the removal of an empty queue\n");
    imm = tevent_create_immediate(kcm_q->qctx);
    if (imm == NULL) {
        return;
    }
    tevent_schedule_immediate(imm, kcm_q->ev, remove_queue, kcm_q);
}

static struct kcm_ops_queue *kcm_op_queue_add(struct kcm_ops_queue_ctx *qctx,
                                              uid_t uid,
                                              struct tevent_context *ev,
                                              struct tevent_req *req)
{
    errno_t ret;
    hash_key_t key;
    hash_value_t value;
    struct kcm_ops_queue *per_uid_queue = NULL;;
    char *qname;

    key.type = HASH_KEY_ULONG;
    key.ul = uid;

    ret = hash_lookup(qctx->wait_queue_hash, &key, &value);
    switch (ret) {
    case HASH_ERROR_KEY_NOT_FOUND:
        /* No request for this UID yet. Create a new queue and then
         * add this request to the new queue
         */
        per_uid_queue = talloc_zero(qctx, struct kcm_ops_queue);
        if (per_uid_queue == NULL) {
            return NULL;
        }
        per_uid_queue->uid = uid;
        per_uid_queue->ev = ev;
        per_uid_queue->qctx = qctx;

        qname = talloc_asprintf(per_uid_queue, "%"SPRIuid, uid);
        if (qname == NULL) {
            return NULL;
        }

        per_uid_queue->tq = tevent_queue_create(qctx->wait_queue_hash, qname);
        if (per_uid_queue == NULL) {
            talloc_free(qname);
            return NULL;
        }

        value.type = HASH_VALUE_PTR;
        value.ptr = per_uid_queue;

        ret = hash_enter(qctx->wait_queue_hash, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "hash_enter failed.\n");
            return NULL;
        }

        DEBUG(SSSDBG_TRACE_LIBS,
              "Added a first request to the queue, running immediately\n");
        break;

    case HASH_SUCCESS:
        /* The key with this UID already exists. Its value is request queue
         * for the UID, so let's just add the current request to the end
         * of the queue and wait for the previous requests to finish
         */
        if (value.type != HASH_VALUE_PTR) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected hash value type.\n");
            return NULL;
        }

        per_uid_queue = talloc_get_type(value.ptr, struct kcm_ops_queue);
        if (per_uid_queue == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid queue pointer\n");
            return NULL;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Waiting in queue\n");
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_lookup failed.\n");
        return NULL;
    }

    if (per_uid_queue == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No queue to add to\n");
        return NULL;
    }

    return per_uid_queue;
}

struct kcm_op_queue_state {
    struct kcm_ops_queue_entry *entry;
};

/*
 * Enqueue a request.
 *
 * If the request queue /for the given ID/ is empty, that is, if this
 * request is the first one in the queue, run the request immediatelly.
 *
 * Otherwise just add it to the queue and wait until the previous request
 * finishes and only at that point mark the current request as done, which
 * will trigger calling the recv function and allow the request to continue.
 */
struct tevent_req *kcm_op_queue_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct kcm_ops_queue_ctx *qctx,
                                     struct cli_creds *client)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct kcm_op_queue_state *state;
    struct kcm_ops_queue *per_uid_queue = NULL;;
    uid_t uid;

    uid = cli_creds_get_uid(client);

    req = tevent_req_create(mem_ctx, &state, struct kcm_op_queue_state);
    if (req == NULL) {
        return NULL;
    }

    state->entry = talloc_zero(state, struct kcm_ops_queue_entry);
    if (state->entry == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "Adding request by %"SPRIuid" to the wait queue\n", uid);

    per_uid_queue = kcm_op_queue_add(qctx, uid, ev, req);
    if (per_uid_queue == NULL) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot enqueue request [%d]: %s\n", ret, sss_strerror(ret));
        goto immediate;
    }

    subreq = tevent_queue_wait_send(state, ev, per_uid_queue->tq);
    tevent_req_set_callback(subreq, kcm_op_queue_done, req);
    DEBUG(SSSDBG_TRACE_LIBS, "Waiting our turn in the queue\n");
    return req;

immediate:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void kcm_op_queue_done(struct tevent_req
/*
 * The queue recv function is called when this request is 'activated'. The queue
 * entry should be allocated on the same memory context as the enqueued request
 * to trigger freeing the kcm_ops_queue_entry structure destructor when the
 * parent request is done and its tevent_req freed. This would in turn unblock
 * the next request in the queue
 */
errno_t kcm_op_queue_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          struct kcm_ops_queue_entry **_entry)
{
    struct kcm_op_queue_state *state = tevent_req_data(req,
                                                struct kcm_op_queue_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *_entry = talloc_steal(mem_ctx, state->entry);
    return EOK;
}
