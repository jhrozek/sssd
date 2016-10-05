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

static void
nss_protocol_done(struct cli_ctx *cli_ctx, errno_t error)
{
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    switch (error) {
    case EOK:
        /* Create empty packet if none was provided. */
        if (pctx->creq->out == NULL) {
            ret = sss_packet_new(pctx->creq, 0,
                                 sss_packet_get_cmd(pctx->creq->in),
                                 &pctx->creq->out);
            if (ret != EOK) {
                goto done;
            }

            sss_packet_set_error(pctx->creq->out, EOK);
        }

        ret = EOK;
        goto done;
    case ENOENT:
        ret = sss_cmd_send_empty(cli_ctx);
        goto done;
    default:
        ret = sss_cmd_send_error(cli_ctx, error);
        goto done;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send reply [%d]: %s!\n",
              ret, sss_strerror(ret));
        return;
    }

    sss_cmd_done(cli_ctx, NULL);
    return;
}

void nss_protocol_reply(struct cli_ctx *cli_ctx,
                        struct nss_ctx *nss_ctx,
                        struct cache_req_result *result,
                        nss_protocol_fill_packet_fn fill_fn)
{
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0, sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        goto done;

    }

    ret = fill_fn(nss_ctx, pctx->creq->out, result);
    if (ret != EOK) {
        goto done;
    }

    sss_packet_set_error(pctx->creq->out, EOK);

done:
    nss_protocol_done(cli_ctx, ret);
}

const char *
nss_protocol_parse_name(struct cli_ctx *cli_ctx)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    /* get user name to query */
    sss_packet_get_body(pctx->creq->in, &body, &blen);

    /* if not terminated fail */
    if (body[blen -1] != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not null terminated\n");
        return NULL;
    }

    /* If the body isn't valid UTF-8, fail */
    if (!sss_utf8_check(body, blen -1)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Body is not UTF-8 string\n");
        return NULL;
    }

    return (const char *)body;
}

uint32_t
nss_protocol_parse_id(struct cli_ctx *cli_ctx)
{
    struct cli_protocol *pctx;
    uint8_t *body;
    size_t blen;
    uint32_t id;

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &blen);

    if (blen != sizeof(uint32_t)) {
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32(&id, body, NULL);

    return id;
}
