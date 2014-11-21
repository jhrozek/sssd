/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) Simo Sorce 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* NSS interfaces to mmap cache */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include "nss_mc.h"
#include "sss_cli.h"
#include "util/io.h"

/* FIXME: hook up to library destructor to avoid leaks */
/* FIXME: temporarily open passwd file on our own, later we will probably
 * use socket passing from the main process */
/* FIXME: handle name upper/lower casing ? Maybe a flag passed down by
 * sssd or a flag in sss_mc_header ? per domain ? */

#define MEMCPY_WITH_BARRIERS(res, dest, src, len) \
do { \
    uint32_t _b1; \
    res = false; \
    _b1 = (src)->b1; \
    if (MC_VALID_BARRIER(_b1)) { \
        __sync_synchronize(); \
        memcpy(dest, src, len); \
        __sync_synchronize(); \
        if ((src)->b2 == _b1) { \
            res = true; \
        } \
    } \
} while(0)

errno_t sss_nss_check_header(struct sss_cli_mc_ctx *ctx)
{
    struct sss_mc_header h;
    bool copy_ok;
    int count;

    /* retry barrier protected reading max 5 times then give up */
    for (count = 5; count > 0; count--) {
        MEMCPY_WITH_BARRIERS(copy_ok, &h,
                             (struct sss_mc_header *)ctx->mmap_base,
                             sizeof(struct sss_mc_header));
        if (copy_ok) {
            /* record is consistent so we can proceed */
            break;
        }
    }
    if (count == 0) {
        /* couldn't successfully read header we have to give up */
        return EIO;
    }

    if (h.major_vno != SSS_MC_MAJOR_VNO ||
        h.minor_vno != SSS_MC_MINOR_VNO ||
        h.status == SSS_MC_HEADER_RECYCLED) {
        return EINVAL;
    }

    /* first time we check the header, let's fill our own struct */
    if (ctx->data_table == NULL) {
        ctx->seed = h.seed;
        ctx->data_table = MC_PTR_ADD(ctx->mmap_base, h.data_table);
        ctx->hash_table = MC_PTR_ADD(ctx->mmap_base, h.hash_table);
        ctx->dt_size = h.dt_size;
        ctx->ht_size = h.ht_size;
    } else {
        if (ctx->seed != h.seed ||
            ctx->data_table != MC_PTR_ADD(ctx->mmap_base, h.data_table) ||
            ctx->hash_table != MC_PTR_ADD(ctx->mmap_base, h.hash_table) ||
            ctx->dt_size != h.dt_size ||
            ctx->ht_size != h.ht_size) {
            return EINVAL;
        }
    }

    return 0;
}

static void sss_nss_mc_destroy_ctx(struct sss_cli_mc_ctx *ctx)
{
    if ((ctx->mmap_base != NULL) && (ctx->mmap_size != 0)) {
        munmap(ctx->mmap_base, ctx->mmap_size);
    }
    if (ctx->fd != -1) {
        close(ctx->fd);
    }
    memset(ctx, 0, sizeof(struct sss_cli_mc_ctx));
    ctx->fd = -1;
}

static errno_t sss_nss_mc_init_ctx(const char *name,
                                   struct sss_cli_mc_ctx *ctx)
{
    struct stat fdstat;
    char *file = NULL;
    int ret;

    sss_nss_lock();
    /* check if ctx is initialised by previous thread. */
    if (ctx->initialized) {
        ret = sss_nss_check_header(ctx);
        goto done;
    }

    ret = asprintf(&file, "%s/%s", SSS_NSS_MCACHE_DIR, name);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    ctx->fd = sss_open_cloexec(file, O_RDONLY, &ret);
    if (ctx->fd == -1) {
        goto done;
    }

    ret = fstat(ctx->fd, &fdstat);
    if (ret == -1) {
        ret = EIO;
        goto done;
    }

    if (fdstat.st_size < MC_HEADER_SIZE) {
        ret = ENOMEM;
        goto done;
    }
    ctx->mmap_size = fdstat.st_size;

    ctx->mmap_base = mmap(NULL, ctx->mmap_size,
                          PROT_READ, MAP_SHARED, ctx->fd, 0);
    if (ctx->mmap_base == MAP_FAILED) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_nss_check_header(ctx);
    if (ret != 0) {
        goto done;
    }

    ctx->initialized = true;

    ret = 0;

done:
    if (ret) {
        sss_nss_mc_destroy_ctx(ctx);
    }
    free(file);
    sss_nss_unlock();

    return ret;
}

errno_t sss_nss_mc_get_ctx(const char *name, struct sss_cli_mc_ctx *ctx)
{
    char *envval;
    int ret;

    envval = getenv("SSS_NSS_USE_MEMCACHE");
    if (envval && strcasecmp(envval, "NO") == 0) {
        return EPERM;
    }

    if (ctx->initialized) {
        ret = sss_nss_check_header(ctx);
        goto done;
    }

    ret = sss_nss_mc_init_ctx(name, ctx);

done:
    if (ret) {
        sss_nss_mc_destroy_ctx(ctx);
    }
    return ret;
}

uint32_t sss_nss_mc_hash(struct sss_cli_mc_ctx *ctx,
                         const char *key, size_t len)
{
    return murmurhash3(key, len, ctx->seed) % MC_HT_ELEMS(ctx->ht_size);
}

errno_t sss_nss_mc_get_record(struct sss_cli_mc_ctx *ctx,
                              uint32_t slot, struct sss_mc_rec **_rec)
{
    struct sss_mc_rec *rec;
    struct sss_mc_rec *copy_rec = NULL;
    size_t buf_size = 0;
    size_t rec_len;
    uint32_t b1;
    uint32_t b2;
    bool copy_ok;
    int count;
    int ret;

    if (!MC_SLOT_WITHIN_BOUNDS(slot, ctx->dt_size)) {
        return EINVAL;
    }

    /* try max 5 times */
    for (count = 5; count > 0; count--) {
        rec = MC_SLOT_TO_PTR(ctx->data_table, slot, struct sss_mc_rec);

        /* fetch record length */
        b1 = rec->b1;
        __sync_synchronize();
        rec_len = rec->len;
        __sync_synchronize();
        b2 = rec->b2;
        if (!MC_VALID_BARRIER(b1) || b1 != b2) {
            /* record is inconsistent, retry */
            continue;
        }

        if (!MC_CHECK_RECORD_LENGTH(ctx, rec)) {
            /* record has invalid length */
            free(copy_rec);
            return EINVAL;
        }

        if (rec_len > buf_size) {
            free(copy_rec);
            copy_rec = malloc(rec_len);
            if (!copy_rec) {
                ret = ENOMEM;
                goto done;
            }
            buf_size = rec_len;
        }
        /* we cannot access data directly, we must copy data and then
         * access the copy */
        MEMCPY_WITH_BARRIERS(copy_ok, copy_rec, rec, rec_len);

        /* we must check data is consistent again after the copy */
        if (copy_ok && b1 == copy_rec->b2) {
            /* record is consistent, use it */
            break;
        }
    }
    if (count == 0) {
        /* couldn't successfully read header we have to give up */
        ret = EIO;
        goto done;
    }

    *_rec = copy_rec;
    ret = 0;

done:
    if (ret) {
        free(copy_rec);
        *_rec = NULL;
    }
    return ret;
}

/*
 * returns strings froma a buffer.
 *
 * Call first time with *cookie set to null, then call again
 * with the returned cookie.
 * On the last string the cookie will be reset to null and
 * all strings will have been returned.
 * In case the last string is not zero terminated EINVAL is returned.
 */
errno_t sss_nss_str_ptr_from_buffer(char **str, void **cookie,
                                    char *buf, size_t len)
{
    char *max = buf + len;
    char *ret;
    char *p;

    if (*cookie == NULL) {
        p = buf;
    } else {
        p = *((char **)cookie);
    }

    ret = p;

    while (p < max) {
        if (*p == '\0') {
            break;
        }
        p++;
    }
    if (p >= max) {
        return EINVAL;
    }
    p++;
    if (p == max) {
        *cookie = NULL;
    } else {
        *cookie = p;
    }

    *str = ret;
    return 0;
}

