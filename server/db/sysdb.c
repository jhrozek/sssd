/*
   SSSD

   System Database

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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
#include "db/sysdb_private.h"
#include "confdb/confdb.h"
#include <time.h>

/************************************************
 * Initialiazation stuff
 */

static int sysdb_read_var(TALLOC_CTX *mem_ctx,
                          struct confdb_ctx *cdb,
                          const char *name,
                          const char *def_value,
                          char **target)
{
    int ret;
    char **values;

    ret = confdb_get_param(cdb, mem_ctx,
                           SYSDB_CONF_SECTION,
                           name, &values);
    if (ret != EOK)
        return ret;

    if (values[0])
        *target = values[0];
    else
        *target = talloc_strdup(mem_ctx, def_value);

    return EOK;
}

static int sysdb_get_db_path(TALLOC_CTX *mem_ctx,
                             struct confdb_ctx *cdb,
                             char **db_path)
{
    TALLOC_CTX *tmp_ctx;
    char *default_ldb_path;
    char *path;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx)
        return ENOMEM;

    default_ldb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, SYSDB_FILE);
    if (default_ldb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sysdb_read_var(tmp_ctx, cdb, "ldbFile",
                     default_ldb_path, &path);

    *db_path = talloc_steal(mem_ctx, path);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sysdb_check_init(struct sysdb_ctx *ctx)
{
    TALLOC_CTX *tmp_ctx;
    const char *base_ldif;
	struct ldb_ldif *ldif;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    char *version = NULL;
    int ret;

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx)
        return ENOMEM;

    verdn = ldb_dn_new(tmp_ctx, ctx->ldb, "cn=sysdb");
    if (!verdn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ctx->ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count > 1) {
        ret = EIO;
        goto done;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (el) {
            if (el->num_values != 1) {
                ret = EINVAL;
                goto done;
            }
            version = talloc_strndup(tmp_ctx,
                                     (char *)(el->values[0].data),
                                     el->values[0].length);
            if (!version) {
                ret = ENOMEM;
                goto done;
            }

            if (strcmp(version, SYSDB_VERSION) == 0) {
                /* all fine, return */
                ret = EOK;
                goto done;
            }
        }

        DEBUG(0,("Unknown DB version [%s], expected [%s], aborting!\n",
                 version?version:"not found", SYSDB_VERSION));
        ret = EINVAL;
        goto done;
    }

    /* cn=sysdb does not exists, means db is empty, populate */
    base_ldif = SYSDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(ctx->ldb, &base_ldif))) {
        ret = ldb_add(ctx->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to inizialiaze DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(ctx->ldb)));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(ctx->ldb, ldif);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct tevent_context *ev,
               struct confdb_ctx *cdb,
               const char *alt_db_path,
               struct sysdb_ctx **_ctx)
{
    struct sysdb_ctx *ctx;
    int ret;

    if (!ev) return EINVAL;

    ctx = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!ctx) {
        return ENOMEM;
    }
    ctx->ev = ev;

    if (!alt_db_path) {
        ret = sysdb_get_db_path(ctx, cdb, &ctx->ldb_file);
        if (ret != EOK) {
            return ret;
        }
    } else {
        ctx->ldb_file = talloc_strdup(ctx, alt_db_path);
    }
    if (ctx->ldb_file == NULL) {
        return ENOMEM;
    }

    DEBUG(3, ("DB Path is: %s\n", ctx->ldb_file));

    ctx->ldb = ldb_init(ctx, ev);
    if (!ctx->ldb) {
        talloc_free(ctx);
        return EIO;
    }

    ret = ldb_connect(ctx->ldb, ctx->ldb_file, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(ctx);
        return EIO;
    }

    ret = sysdb_check_init(ctx);
    if (ret != EOK) {
        talloc_free(ctx);
        return ret;
    }

    *_ctx = ctx;

    return EOK;
}
