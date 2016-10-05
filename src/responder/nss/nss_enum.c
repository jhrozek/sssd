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

#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/nss/nss_private.h"

struct nss_setent_state {
    struct nss_ctx *nss_ctx;
    struct nss_enum_ctx *enum_ctx;
};

static void nss_setent_done(struct tevent_req *subreq);

struct tevent_req *
nss_setent_send(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct cli_ctx *cli_ctx,
                enum cache_req_type type,
                struct nss_enum_ctx *enum_ctx)
{
    struct nss_setent_state *state;
    struct cache_req_data *data;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct nss_setent_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state->enum_ctx = enum_ctx;

    /* Object is already being constructed. Register ourselves for
     * notification when its finished. */
    if (enum_ctx->in_progress) {
        /* TODO */
    }

    /* Object is already created and not expired, just return here. */
    if (state->enum_ctx->result != NULL) {
        ret = EOK;
        goto done;
    }

    /* Create new object. */

    data = cache_req_data_enum(req, type);
    if (data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set cache request data!\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = cache_req_send(req, ev, cli_ctx->rctx, cli_ctx->rctx->ncache,
                            0, NULL, data);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send cache request!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, nss_setent_done, req);

    ret = EAGAIN;

done:
    switch (ret) {
    case EAGAIN:
        enum_ctx->in_progress = true;
        break;
    case EOK:
        tevent_req_done(req);
        tevent_req_post(req, ev);
        enum_ctx->in_progress = false;
        break;
    default:
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
        enum_ctx->in_progress = false;
        break;
    }

    return req;
}

static void nss_setent_done(struct tevent_req *subreq)
{
    struct cache_req_result **result;
    struct nss_setent_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct nss_setent_state);
    state->enum_ctx->in_progress = false;

    ret = cache_req_recv(state, subreq, &result);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    talloc_zfree(state->enum_ctx->result);
    state->enum_ctx->result = talloc_steal(state->nss_ctx, result);

    tevent_req_done(req);
    return;
}

errno_t
nss_setent_recv(struct tevent_req *req)
{
    struct nss_setent_state *state;
    state = tevent_req_data(req, struct nss_setent_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
