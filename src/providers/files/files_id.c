/*
    SSSD

    files_id.c - Identity operaions on the files provider

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

#include "providers/data_provider/dp.h"
#include "providers/files/files_private.h"

static struct dp_reply_std
files_account_info_handler(struct dp_id_data *data,
                           struct sss_domain_info *domain)
{
    struct dp_reply_std reply;

    /* For now we support only core attrs. */
    if (data->attr_type != BE_ATTR_CORE) {
        dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL, "Invalid attr type");
        return reply;
    }

    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
        switch (data->filter_type) {
        case BE_FILTER_ENUM:
        case BE_FILTER_NAME:
        case BE_FILTER_IDNUM:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown user request filter %d\n", data->filter_type);
            goto fail;
        }
        break;
    case BE_REQ_GROUP:
        switch (data->filter_type) {
        case BE_FILTER_ENUM:
        case BE_FILTER_NAME:
        case BE_FILTER_IDNUM:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown group request filter %d\n", data->filter_type);
            goto fail;
        }
        break;
    case BE_REQ_INITGROUPS:
        switch (data->filter_type) {
        case BE_FILTER_NAME:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown initgroups request filter %d\n", data->filter_type);
            goto fail;
        }
        break;
    }

    /* All data is in fact returned from responder cache for now,
     * we completely rely on the inotify-induced enumeration
     */
    dp_reply_std_set(&reply, DP_ERR_OK, EOK, NULL);
    return reply;

fail:
    dp_reply_std_set(&reply, DP_ERR_FATAL, EINVAL, "Invalid request type");
    return reply;
}

struct files_account_info_handler_state {
    struct dp_reply_std reply;
};

struct tevent_req *
files_account_info_handler_send(TALLOC_CTX *mem_ctx,
                               struct files_id_ctx *id_ctx,
                               struct dp_id_data *data,
                               struct dp_req_params *params)
{
    struct files_account_info_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct files_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->reply = files_account_info_handler(data, id_ctx->domain);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

errno_t files_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        struct dp_reply_std *data)
{
    struct files_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct files_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
