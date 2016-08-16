/*
    SSSD

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

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

typedef int errno_t;

#include "config.h"

#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <ldb.h>
#include "util/debug.h"

struct sss_ldif_vprint_ctx {
    char *ldif;
};

#define SSS_DEBUG_LEVEL SSSDBG_TRACE_ALL

static int ldif_vprintf_fn(void *private_data, const char *fmt, ...)
{
    struct sss_ldif_vprint_ctx *print_ctx;
    va_list ap;
    int lenght = 0;

    /* Note that the function should return the number of
     * bytes written, or a negative error code.
     */

    print_ctx = talloc_get_type(private_data, struct sss_ldif_vprint_ctx);

    if (print_ctx == NULL) {
        return - ENOMEM;
    }

    if (fmt != NULL) {
        va_start(ap, fmt);

        if (print_ctx->ldif != NULL) {
            lenght = strlen(print_ctx->ldif);
        }

        print_ctx->ldif = talloc_vasprintf_append_buffer(print_ctx->ldif,
                                                         fmt, ap);
        va_end(ap);

        if (print_ctx->ldif == NULL) {
            return - ENOENT;
        }

        lenght = strlen(print_ctx->ldif) - lenght;
    }

    return lenght;
}

static void sss_ldb_ldif2log(enum ldb_changetype changetype,
                             struct ldb_context *ldb,
                             const struct ldb_message *message)
{
    int ret;
    struct ldb_ldif ldif;
    struct sss_ldif_vprint_ctx *ldb_print_ctx;
    const char *function;

    switch (changetype) {
    case LDB_CHANGETYPE_ADD:
        function = "ldb_add";
        break;
    case LDB_CHANGETYPE_MODIFY:
        function = "ldb_modify";
        break;
    default:
        function = __FUNCTION__;
        break;
    }

    ldb_print_ctx = talloc_zero(ldb, struct sss_ldif_vprint_ctx);
    if (ldb_print_ctx == NULL) {
        return;
    }
    ldb_print_ctx->ldif = NULL;

    ldif.changetype = changetype;
    ldif.msg = (void *)(intptr_t)message;

    ret = ldb_ldif_write(ldb, ldif_vprintf_fn, ldb_print_ctx, &ldif);
    if (ret < 0) {
        ret = - ret;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_ldif_write() failed with [%d][%s].\n",
              ret, strerror(ret));
        goto done;
    }

    if (DEBUG_IS_SET(SSS_DEBUG_LEVEL)) {
        sss_debug_fn(__FILE__, __LINE__, function,
                     SSS_DEBUG_LEVEL,
                     "ldif\n[\n%s]\n", ldb_print_ctx->ldif);
    }

done:
    talloc_free(ldb_print_ctx->ldif);
    talloc_free(ldb_print_ctx);

    return;
}

typedef typeof(ldb_add) ldb_add_fn;
static ldb_add_fn *orig_ldb_add = NULL;

int ldb_add(struct ldb_context *ldb, const struct ldb_message *message)
{
    if (orig_ldb_add == NULL) {
        orig_ldb_add = dlsym(RTLD_NEXT, "ldb_add");
    }

    sss_ldb_ldif2log(LDB_CHANGETYPE_ADD, ldb, message);

    return orig_ldb_add(ldb, message);
}

typedef typeof(ldb_delete) ldb_delete_fn;
static ldb_delete_fn *orig_ldb_delete = NULL;

int ldb_delete(struct ldb_context *ldb, struct ldb_dn *dn)
{
    if (orig_ldb_delete == NULL) {
        orig_ldb_delete = dlsym(RTLD_NEXT, "ldb_delete");
    }

    DEBUG(SSS_DEBUG_LEVEL, "Deleting [%s]\n", ldb_dn_get_linearized(dn));

    return orig_ldb_delete(ldb, dn);
}

typedef typeof(ldb_modify) ldb_modify_fn;
static ldb_modify_fn *orig_ldb_modify = NULL;

int ldb_modify(struct ldb_context *ldb, const struct ldb_message *message)
{
    if (orig_ldb_modify == NULL) {
        orig_ldb_modify = dlsym(RTLD_NEXT, "ldb_modify");
    }

    sss_ldb_ldif2log(LDB_CHANGETYPE_MODIFY, ldb, message);

    return orig_ldb_modify(ldb, message);
}

typedef typeof(ldb_rename) ldb_rename_fn;
static ldb_rename_fn *orig_ldb_rename = NULL;

int ldb_rename(struct ldb_context *ldb,
               struct ldb_dn *olddn,
               struct ldb_dn *newdn)
{
    if (orig_ldb_rename == NULL) {
        orig_ldb_rename = dlsym(RTLD_NEXT, "ldb_rename");
    }

    DEBUG(SSS_DEBUG_LEVEL,
          "Renaming [%s] to [%s]\n",
          ldb_dn_get_linearized(olddn), ldb_dn_get_linearized(newdn));

    return orig_ldb_rename(ldb, olddn, newdn);
}
