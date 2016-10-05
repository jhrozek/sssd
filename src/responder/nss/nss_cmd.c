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
#include "responder/nss/nsssrv_mmap_cache.h"

static struct nss_cmd_ctx *
nss_cmd_ctx_create(TALLOC_CTX *mem_ctx,
                   struct cli_ctx *cli_ctx,
                   enum cache_req_type type,
                   nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;

    cmd_ctx = talloc_zero(cli_ctx, struct nss_cmd_ctx);
    if (cmd_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    cmd_ctx->cli_ctx = cli_ctx;
    cmd_ctx->nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    cmd_ctx->type = type;
    cmd_ctx->fill_fn = fill_fn;

    return cmd_ctx;
}

static void nss_get_by_name_done(struct tevent_req *subreq);

static errno_t nss_get_by_name(struct cli_ctx *cli_ctx,
                               enum cache_req_type type,
                               enum sss_mc_type memcache,
                               nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        return ENOMEM;
    }

    subreq = nss_get_by_name_send(cmd_ctx, cli_ctx->ev,
                                  cli_ctx, type, memcache);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create get by name request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_get_by_name_done, cmd_ctx);
    return EOK;
}

static void nss_get_by_name_done(struct tevent_req *subreq)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct cache_req_result *result;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_get_by_name_recv(cmd_ctx, subreq, &result, &cmd_ctx->rawname);
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx,
                       result, cmd_ctx->fill_fn);

done:
    talloc_free(cmd_ctx);
}

static void nss_get_by_id_done(struct tevent_req *subreq);

static errno_t nss_get_by_id(struct cli_ctx *cli_ctx,
                             enum cache_req_type type,
                             enum sss_mc_type memcache,
                             nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        return ENOMEM;
    }

    subreq = nss_get_by_id_send(cmd_ctx, cli_ctx->ev, cli_ctx, type, memcache);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create get by id request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_get_by_id_done, cmd_ctx);
    return EOK;
}

static void nss_get_by_id_done(struct tevent_req *subreq)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct cache_req_result *result;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_get_by_id_recv(cmd_ctx, subreq, &result);
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
        goto done;
    }

    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx,
                       result, cmd_ctx->fill_fn);

done:
    talloc_free(cmd_ctx);
}

static void nss_setent_done(struct tevent_req *subreq);

static errno_t nss_setent(struct cli_ctx *cli_ctx,
                          enum cache_req_type type,
                          struct nss_enum_ctx *enum_ctx)
{
    struct tevent_req *subreq;

    subreq = nss_setent_send(cli_ctx, cli_ctx->ev, cli_ctx, type, enum_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create setent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_setent_done, cli_ctx);
    return EOK;
}

static void nss_setent_done(struct tevent_req *subreq)
{
    struct cli_ctx *cli_ctx;
    errno_t ret;

    cli_ctx = tevent_req_callback_data(subreq, struct cli_ctx);

    ret = nss_setent_recv(subreq);
    if (ret != EOK && ret != ENOENT) {
        nss_protocol_done(cli_ctx, ret);
        return;
    }

    /* Both EOK and ENOENT means that setent was successful. */
    nss_protocol_done(cli_ctx, EOK);
}

static void nss_getent_done(struct tevent_req *subreq);

static errno_t nss_getent(struct cli_ctx *cli_ctx,
                          enum cache_req_type type,
                          struct nss_enum_ctx *enum_ctx,
                          struct nss_enum_index *index,
                          nss_protocol_fill_packet_fn fill_fn)
{
    struct nss_cmd_ctx *cmd_ctx;
    struct tevent_req *subreq;
    struct cli_protocol *pctx;
    size_t body_len;
    uint8_t *body;

    cmd_ctx = nss_cmd_ctx_create(cli_ctx, cli_ctx, type, fill_fn);
    if (cmd_ctx == NULL) {
        return ENOMEM;
    }

    pctx = talloc_get_type(cli_ctx->protocol_ctx, struct cli_protocol);

    /* Get maximum number of entries to return in one call. */
    sss_packet_get_body(pctx->creq->in, &body, &body_len);
    if (body_len != sizeof(uint32_t)) {
        return EINVAL;
    }
    SAFEALIGN_COPY_UINT32(&cmd_ctx->enum_limit, body, NULL);

    cmd_ctx->enum_ctx = enum_ctx;
    cmd_ctx->enum_index = index;

    subreq = nss_setent_send(cli_ctx, cli_ctx->ev, cli_ctx, type, enum_ctx);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create setent request!\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, nss_getent_done, cmd_ctx);
    return EOK;
}

static void nss_getent_done(struct tevent_req *subreq)
{
    struct cache_req_result *result;
    struct cache_req_result *limited;
    struct nss_cmd_ctx *cmd_ctx;
    struct nss_enum_ctx *enum_ctx;
    struct nss_enum_index *index;
    errno_t ret;

    cmd_ctx = tevent_req_callback_data(subreq, struct nss_cmd_ctx);

    ret = nss_setent_recv(subreq);
    if (ret != EOK && ret != ENOENT) {
        goto done;
    }

    enum_ctx = cmd_ctx->enum_ctx;
    index = cmd_ctx->enum_index;
    result = enum_ctx->result[index->domain];

    if (result != NULL && index->result >= result->count) {
        /* Switch to next domain. */
        index->result = 0;
        index->domain++;

        result = enum_ctx->result[index->domain];
    }

    if (result == NULL) {
        /* No more domains to try. */
        ret = ENOENT;
        goto done;
    }

    /* Create copy of the result with limited number of records. */
    limited = cache_req_copy_limited_result(cmd_ctx, result, index->result,
                                            cmd_ctx->enum_limit);
    if (limited == NULL) {
        ret = ERR_INTERNAL;
        goto done;
    }

    index->result += result->count;

    /* Reply with limited result. */
    nss_protocol_reply(cmd_ctx->cli_ctx, cmd_ctx->nss_ctx,
                       result, cmd_ctx->fill_fn);

    ret = EOK;

done:
    if (ret != EOK) {
        nss_protocol_done(cmd_ctx->cli_ctx, ret);
    }

    return;
}

static errno_t nss_endent(struct cli_ctx *cli_ctx,
                          struct nss_enum_index *index)
{
    DEBUG(SSSDBG_CONF_SETTINGS, "Resetting enumeration state\n");

    index->domain = 0;
    index->result = 0;

    nss_protocol_done(cli_ctx, EOK);

    return EOK;
}

static errno_t nss_cmd_getpwnam(struct cli_ctx *cli_ctx)
{
    return nss_get_by_name(cli_ctx, CACHE_REQ_USER_BY_NAME, SSS_MC_PASSWD,
                           nss_protocol_fill_pwent);
}

static errno_t nss_cmd_getpwuid(struct cli_ctx *cli_ctx)
{
    return nss_get_by_name(cli_ctx, CACHE_REQ_USER_BY_ID, SSS_MC_PASSWD,
                           nss_protocol_fill_pwent);
}

static errno_t nss_cmd_setpwent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_USERS, &nss_ctx->pwent);
}

static errno_t nss_cmd_getpwent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_USERS,
                      &nss_ctx->pwent, &state_ctx->pwent,
                      nss_protocol_fill_pwent);
}

static errno_t nss_cmd_endpwent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_endent(cli_ctx, &state_ctx->pwent);
}

static errno_t nss_cmd_getgrnam(struct cli_ctx *cli_ctx)
{
    return nss_get_by_name(cli_ctx, CACHE_REQ_GROUP_BY_NAME, SSS_MC_GROUP,
                           nss_protocol_fill_grent);
}

static errno_t nss_cmd_getgrgid(struct cli_ctx *cli_ctx)
{
    return nss_get_by_name(cli_ctx, CACHE_REQ_GROUP_BY_ID, SSS_MC_GROUP,
                           nss_protocol_fill_grent);
}

static errno_t nss_cmd_setgrent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_GROUPS, &nss_ctx->grent);
}

static errno_t nss_cmd_getgrent(struct cli_ctx *cli_ctx)
{
    struct nss_ctx *nss_ctx;
    struct nss_state_ctx *state_ctx;

    nss_ctx = talloc_get_type(cli_ctx->rctx->pvt_ctx, struct nss_ctx);
    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_setent(cli_ctx, CACHE_REQ_ENUM_GROUPS,
                      &nss_ctx->grent, &state_ctx->grent,
                      nss_protocol_fill_grent);
}

static errno_t nss_cmd_endgrent(struct cli_ctx *cli_ctx)
{
    struct nss_state_ctx *state_ctx;

    state_ctx = talloc_get_type(cli_ctx->state_ctx, struct nss_state_ctx);

    return nss_endent(cli_ctx, &state_ctx->grent);
}

static errno_t nss_cmd_initgroups(struct cli_ctx *cli_ctx)
{
    return nss_get_by_name(cli_ctx, CACHE_REQ_INITGROUPS, SSS_MC_INITGROUPS,
                           nss_protocol_fill_initgr);
}

static struct sss_cmd_table nss_cmds[] = {
    {SSS_GET_VERSION, sss_cmd_get_version},
    {SSS_NSS_GETPWNAM, nss_cmd_getpwnam},
    {SSS_NSS_GETPWUID, nss_cmd_getpwuid},
    {SSS_NSS_SETPWENT, nss_cmd_setpwent},
    {SSS_NSS_GETPWENT, nss_cmd_getpwent},
    {SSS_NSS_ENDPWENT, nss_cmd_endpwent},
    {SSS_NSS_GETGRNAM, nss_cmd_getgrnam},
    {SSS_NSS_GETGRGID, nss_cmd_getgrgid},
    {SSS_NSS_SETGRENT, nss_cmd_setgrent},
    {SSS_NSS_GETGRENT, nss_cmd_getgrent},
    {SSS_NSS_ENDGRENT, nss_cmd_endgrent},
    {SSS_NSS_INITGR, nss_cmd_initgroups},
    {SSS_NSS_SETNETGRENT, nss_cmd_setnetgrent},
    {SSS_NSS_GETNETGRENT, nss_cmd_getnetgrent},
    {SSS_NSS_ENDNETGRENT, nss_cmd_endnetgrent},
    {SSS_NSS_GETSERVBYNAME, nss_cmd_getservbyname},
    {SSS_NSS_GETSERVBYPORT, nss_cmd_getservbyport},
    {SSS_NSS_SETSERVENT, nss_cmd_setservent},
    {SSS_NSS_GETSERVENT, nss_cmd_getservent},
    {SSS_NSS_ENDSERVENT, nss_cmd_endservent},
    {SSS_NSS_GETSIDBYNAME, NULL},
    {SSS_NSS_GETSIDBYID, NULL},
    {SSS_NSS_GETNAMEBYSID, NULL},
    {SSS_NSS_GETIDBYSID, NULL},
    {SSS_NSS_GETORIGBYNAME, NULL},
    {SSS_NSS_GETNAMEBYCERT, NULL},
    {SSS_CLI_NULL, NULL}
};

struct sss_cmd_table *get_nss_cmds(void) {
    return nss_cmds;
}

int nss_connection_setup(struct cli_ctx *cli_ctx)
{
    int ret;

    ret = sss_connection_setup(cli_ctx);
    if (ret != EOK) return ret;

    cli_ctx->state_ctx = talloc_zero(cli_ctx, struct nss_state_ctx);
    if (cli_ctx->state_ctx == NULL) {
        return ENOMEM;
    }

    return EOK;
}
