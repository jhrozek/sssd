/*
    SSSD

    openshift_id.c - Identity lookups for the openshift provider

    Copyright (C) 2019 Red Hat

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
#include "providers/openshift/openshift_private.h"

struct openshift_account_info_handler_state {
    struct dp_reply_std reply;

    struct openshift_id_ctx *id_ctx;
};

struct tevent_req *
openshift_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct openshift_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params)
{
    errno_t ret;
    struct openshift_account_info_handler_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct openshift_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->id_ctx = id_ctx;

    switch (data->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
    case BE_REQ_GROUP:
    case BE_REQ_INITGROUPS:
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected entry type: %d\n", data->entry_type & BE_REQ_TYPE_MASK);
        ret = EINVAL;
        goto immediate;
    }

    /* FIXME: the id handler will first just create any users you ask for. Later,
     * we'll try to use the client certificate that kubectl uses to actually
     * query for users.
     */
    ret = EOK;
immediate:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, params->ev);
    return req;
}

errno_t openshift_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                            struct tevent_req *req,
                                            struct dp_reply_std *data)
{
    struct openshift_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct openshift_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;
    return EOK;
}
