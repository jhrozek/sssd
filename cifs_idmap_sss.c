/*
    Authors:
        Benjamin Franzke <benjaminfranzke@googlemail.com>

    Copyright (C) 2013 Benjamin Franzke

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

/* TODO: Support well known SIDs as in samba's
 *        - librpc/idl/security.idl or
 *        - source4/rpc_server/lsa/lsa_lookup.c?
 */

/* TODO: Support of [all] samba's Unix SIDs:
 *         Users:  S-1-22-1-%UID
 *         Groups: S-1-22-2-%GID
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>

#include <sss_idmap.h>
#include <sss_nss_idmap.h>
#include <cifsidmap.h>

#define WORLD_SID "S-1-1-0"

#ifdef DEBUG
#include <syslog.h>
#define debug(str, ...) \
    syslog(0, "%s: " str "\n", \
           __FUNCTION__, ##__VA_ARGS__)
#else
#define debug(...) do { } while(0)
#endif

struct sssd_ctx {
    struct sss_idmap_ctx *idmap;
    const char **errmsg;
};

#define ctx_set_error(ctx, error) \
    do { \
        *ctx->errmsg = error; \
        debug("%s", error ? error : ""); \
    } while (0);

int
cifs_idmap_init_plugin(void **handle, const char **errmsg)
{
    struct sssd_ctx *ctx;
    enum idmap_error_code err;

    ctx = malloc(sizeof *ctx);
    if (!ctx) {
        *errmsg = "Failed to allocate context";
        return -1;
    }
    ctx->errmsg = errmsg;
    ctx_set_error(ctx, NULL);

    err = sss_idmap_init(NULL, NULL, NULL, &ctx->idmap);
    if (err != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(err));
        return -1;
    }

    *handle = ctx;
    return 0;
}

void
cifs_idmap_exit_plugin(void *handle)
{
    struct sssd_ctx *ctx = handle;

    debug("exit");

    sss_idmap_free(ctx->idmap);

    free(ctx);
}

/* Test with `getcifsacl file` on client. */
int cifs_idmap_sid_to_str(void *handle, const struct cifs_sid *sid,
                          char **name)
{
    struct sssd_ctx *ctx = handle;
    enum idmap_error_code idmap_err;
    char *str_sid;
    enum sss_id_type id_type;
    int err;

    idmap_err = sss_idmap_bin_sid_to_sid(ctx->idmap,
                                         (uint8_t *) sid, sizeof(*sid),
                                         &str_sid);
    if (idmap_err != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(idmap_err));
        *name = NULL;
        return -1;
    }

    debug("sid: %s", str_sid);

    if (strcmp(str_sid, WORLD_SID) == 0) {
        *name = strdup("\\Everyone");
        if (!*name) {
            ctx_set_error(ctx, strerror(ENOMEM));
            return -ENOMEM;
        }
        return 0;
    }

    err = sss_nss_getnamebysid(str_sid, name, &id_type);
    if (err != 0)  {
        ctx_set_error(ctx, strerror(err));
        *name = NULL;
        return -err;
    }

    /* FIXME: Map Samba Unix SIDs? (sid->id and use getpwuid)? */

    debug("name: %s", *name);

    return 0;
}

static int
sid_to_cifs_sid(struct sssd_ctx *ctx, const char *sid, struct cifs_sid *csid)
{
    uint8_t *bin_sid = NULL;
    enum idmap_error_code idmap_err;
    size_t length;

    idmap_err = sss_idmap_sid_to_bin_sid(ctx->idmap,
                                         sid, &bin_sid, &length);
    if (idmap_err != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(idmap_err));
        return -1;
    }
    if (length > sizeof(struct cifs_sid)) {
        debug("length: %zd", length);
        ctx_set_error(ctx, "incompatible internal sid length");
        free(bin_sid);
        return -1;
    }

    memcpy(csid, bin_sid, length);
    free(bin_sid);

    return 0;
}

/* Test with setcifsacl -a */
int cifs_idmap_str_to_sid(void *handle, const char *name,
                          struct cifs_sid *csid)
{
    struct sssd_ctx *ctx = handle;
    int err;
    enum sss_id_type id_type;
    const char *str_sid;
    char *sss_sid = NULL;
    int success = 0;

    debug("%s", name);

    if (strncmp("S-", name, 2) == 0) {
        debug("%s: name is sid string representation", __FUNCTION__);
        str_sid = name;
        if (!str_sid) {
        }
    } else {
        err = sss_nss_getsidbyname(name, &sss_sid, &id_type);
        if (err != 0)  {
            ctx_set_error(ctx, strerror(err));
            /* TODO: Map name==Everyone to WOLD_SID? */
            return -err;
        }
        str_sid = sss_sid;
    }

    if (sid_to_cifs_sid(ctx, str_sid, csid) != 0)
        success = -1;

    if (sss_sid) 
        free(sss_sid);

    return success;
}

static int
samba_unix_sid_to_id(const char *sid, struct cifs_uxid *cuxid)
{
    id_t id;
    uint8_t type;

    debug("scanf: %d", sscanf(sid, "S-1-22-%hhu-%u", &type, &id));
    if (sscanf(sid, "S-1-22-%hhu-%u", &type, &id) != 2)
        return -1;

    switch (type) {
    case 1:
        cuxid->type = CIFS_UXID_TYPE_UID;
        cuxid->id.uid = id;
        break;
    case 2:
        cuxid->type = CIFS_UXID_TYPE_GID;
        cuxid->id.gid = id;
    default:
        cuxid->type = CIFS_UXID_TYPE_UNKNOWN;
        return -1;
    }

    return 0;
}

static int
sss_sid_to_id(struct sssd_ctx *ctx, const char *sid, struct cifs_uxid *cuxid)
{
    int err;
    enum sss_id_type id_type;

    err = sss_nss_getidbysid(sid, (uint32_t *)&cuxid->id.uid, &id_type);
    if (err != 0)  {
        ctx_set_error(ctx, strerror(err));
        return -1;
    }

    switch (id_type) {
    case SSS_ID_TYPE_UID:
        cuxid->type = CIFS_UXID_TYPE_UID;
        break;
    case SSS_ID_TYPE_GID:
        cuxid->type = CIFS_UXID_TYPE_GID;
        break;
    case SSS_ID_TYPE_BOTH:
        cuxid->type = CIFS_UXID_TYPE_BOTH;
        break;
    case SSS_ID_TYPE_NOT_SPECIFIED:
        return -1;
    }

    return 0;
}

/**
 * cifs_idmap_sids_to_ids - convert struct cifs_sids to struct cifs_uxids
 * usecase: mount.cifs -o sec=krb5,multiuser,cifsacl,nounix 
 * test: ls -n on mounted share
 */
int cifs_idmap_sids_to_ids(void *handle, const struct cifs_sid *sid,
                           const size_t num, struct cifs_uxid *cuxid)
{
    struct sssd_ctx *ctx = handle;
    enum idmap_error_code idmap_err;
    int success = -1;
    size_t i;
    char *str_sid;

    debug("num: %zd", num);

    if (num > UINT_MAX) {
        ctx_set_error(ctx, "num is too large.");
        return -EINVAL;
    }

    for (i = 0; i < num; ++i) {

        idmap_err = sss_idmap_bin_sid_to_sid(ctx->idmap, (uint8_t *) &sid[i],
                                             sizeof(sid[i]), &str_sid);
        if (idmap_err != IDMAP_SUCCESS) {
            ctx_set_error(ctx, idmap_error_string(idmap_err));
            continue;
        }

        cuxid[i].type = CIFS_UXID_TYPE_UNKNOWN;

        if (sss_sid_to_id(ctx, str_sid, &cuxid[i]) == 0 || 
            samba_unix_sid_to_id(str_sid, &cuxid[i]) == 0) {

            debug("setting uid of %s to %d", str_sid, cuxid[i].id.uid);
            success = 0;
        }

        free(str_sid);
    }

    return success;
}


int cifs_idmap_ids_to_sids(void *handle, const struct cifs_uxid *cuxid,
                           const size_t num, struct cifs_sid *sid)
{
    struct sssd_ctx *ctx = handle;
    int err, success = -1;
    char *str_sid;
    enum sss_id_type id_type;
    size_t i;

    debug("num ids: %zd", num);

    if (num > UINT_MAX) {
        ctx_set_error(ctx, "num is too large.");
        return -EINVAL;
    }

    for (i = 0; i < num; ++i) {

        err = sss_nss_getsidbyid((uint32_t)cuxid[i].id.uid, &str_sid, &id_type);
        if (err != 0)  {
            ctx_set_error(ctx, strerror(err));
            sid[i].revision = 0;
            /* FIXME: would it be safe to map *any* uid/gids unknown by sssd to
               SAMBA's UNIX SIDs? */
            continue;
        }

        if (sid_to_cifs_sid(ctx, str_sid, sid) == 0)
            success = 0;
        else
            sid[i].revision = 0;
        free(str_sid);
    }

    return success;
}
