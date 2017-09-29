/*
    SSSD

    Extended NSS Responder Interface

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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
#include <stdlib.h>
#include <errno.h>

#include <sys/param.h> /* for MIN() */

#include "sss_client/sss_cli.h"
#include "sss_client/nss_mc.h"
#include "sss_client/nss_common.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "sss_client/idmap/sss_nss_idmap_private.h"

struct sss_nss_initgr_rep {
    gid_t *groups;
    long int *ngroups;
    long int *start;
};

struct nss_input {
    union {
        const char *name;
        uid_t uid;
        gid_t gid;
    } input;
    struct sss_cli_req_data rd;
    enum sss_cli_command cmd;
    union {
        struct sss_nss_pw_rep pwrep;
        struct sss_nss_gr_rep grrep;
        struct sss_nss_initgr_rep initgrrep;
    } result;
};

errno_t sss_nss_mc_get(struct nss_input *inp)
{
    switch(inp->cmd) {
    case SSS_NSS_GETPWNAM:
        return sss_nss_mc_getpwnam(inp->input.name, (inp->rd.len - 1),
                                   inp->result.pwrep.result,
                                   inp->result.pwrep.buffer,
                                   inp->result.pwrep.buflen);
        break;
    case SSS_NSS_GETPWUID:
        return sss_nss_mc_getpwuid(inp->input.uid,
                                   inp->result.pwrep.result,
                                   inp->result.pwrep.buffer,
                                   inp->result.pwrep.buflen);
        break;
    case SSS_NSS_GETGRNAM:
        return sss_nss_mc_getgrnam(inp->input.name, (inp->rd.len - 1),
                                   inp->result.grrep.result,
                                   inp->result.grrep.buffer,
                                   inp->result.grrep.buflen);
        break;
    case SSS_NSS_GETGRGID:
        return sss_nss_mc_getgrgid(inp->input.gid,
                                   inp->result.grrep.result,
                                   inp->result.grrep.buffer,
                                   inp->result.grrep.buflen);
        break;
    case SSS_NSS_INITGR:
        return sss_nss_mc_initgroups_dyn(inp->input.name, (inp->rd.len - 1),
                                         -1 /* currently ignored */,
                                         inp->result.initgrrep.start,
                                         inp->result.initgrrep.ngroups,
                                         &(inp->result.initgrrep.groups),
                                         *(inp->result.initgrrep.ngroups));
        break;
    default:
        return EINVAL;
    }
}

int sss_get_ex(struct nss_input *inp, uint32_t flags, unsigned int timeout)
{
    uint8_t *repbuf = NULL;
    size_t replen;
    size_t len;
    uint32_t num_results;
    int ret;
    int time_left;
    int errnop;
    size_t c;
    gid_t *new_groups;
    size_t idx;

    ret = sss_nss_mc_get(inp);
    switch (ret) {
    case 0:
        return 0;
    case ERANGE:
        return ERANGE;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmaped cache failed,
         * fall back to socket based comms */
        break;
    }

    sss_nss_timedlock(timeout, &time_left);

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_get(inp);
    switch (ret) {
    case 0:
        ret = 0;
        goto out;
    case ERANGE:
        ret = ERANGE;
        goto out;
    case ENOENT:
        /* fall through, we need to actively ask the parent
         * if no entry is found */
        break;
    default:
        /* if using the mmaped cache failed,
         * fall back to socket based comms */
        break;
    }

    ret = sss_nss_make_request_timeout(inp->cmd, &inp->rd, time_left,
                                       &repbuf, &replen, &errnop);
    if (ret != NSS_STATUS_SUCCESS) {
        ret = errnop != 0 ? errnop : EIO;
        goto out;
    }

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if (num_results == 0) {
        ret = ENOENT;
        goto out;
    }

    if (inp->cmd == SSS_NSS_INITGR) {
        if ((*(inp->result.initgrrep.ngroups) - *(inp->result.initgrrep.start))
                    < num_results) {
            new_groups = realloc(inp->result.initgrrep.groups,
                                 (num_results + *(inp->result.initgrrep.start))
                                    * sizeof(gid_t));
            if (new_groups == NULL) {
                ret = ENOMEM;
                goto out;
            }

            inp->result.initgrrep.groups = new_groups;
        }
        *(inp->result.initgrrep.ngroups) = num_results
                                            + *(inp->result.initgrrep.start);

        idx = 2 * sizeof(uint32_t);
        for (c = 0; c < num_results; c++) {
            SAFEALIGN_COPY_UINT32(
                &(inp->result.initgrrep.groups[*(inp->result.initgrrep.start)]),
                repbuf + idx, &idx);
            *(inp->result.initgrrep.start) += 1;
        }

        ret = 0;
        goto out;
    }

    /* only 1 result is accepted for this function */
    if (num_results != 1) {
        ret = EBADMSG;
        goto out;
    }

    len = replen - 8;
    if (inp->cmd == SSS_NSS_GETPWNAM || inp->cmd == SSS_NSS_GETPWUID) {
        ret = sss_nss_getpw_readrep(&(inp->result.pwrep), repbuf+8, &len);
    } else if (inp->cmd == SSS_NSS_GETGRNAM || inp->cmd == SSS_NSS_GETGRGID) {
        ret = sss_nss_getgr_readrep(&(inp->result.grrep), repbuf+8, &len);
    } else {
        ret = EINVAL;
        goto out;
    }
    if (ret) {
        goto out;
    }

    if (len == 0) {
        /* no extra data */
        ret = 0;
        goto out;
    }

out:
    free(repbuf);

    sss_nss_unlock();
    return ret;
}

int sss_nss_getpwnam_timeout(const char *name, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_GETPWNAM,
        .rd.data = name,
        .result.pwrep.result = pwd,
        .result.pwrep.buffer = buffer,
        .result.pwrep.buflen = buflen};

    if (buffer == NULL || buflen == 0) {
        return ERANGE;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &inp.rd.len);
    if (ret != 0) {
        return EINVAL;
    }
    inp.rd.len++;

    *result = NULL;

    ret = sss_get_ex(&inp, flags, timeout);
    if (ret == 0) {
        *result = inp.result.pwrep.result;
    }
    return ret;
}

int sss_nss_getpwuid_timeout(uid_t uid, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    uint32_t user_uid = uid;
    struct nss_input inp = {
        .input.uid = uid,
        .cmd = SSS_NSS_GETPWUID,
        .rd.len = sizeof(uint32_t),
        .rd.data = &user_uid,
        .result.pwrep.result = pwd,
        .result.pwrep.buffer = buffer,
        .result.pwrep.buflen = buflen};

    if (buffer == NULL || buflen == 0) {
        return ERANGE;
    }

    *result = NULL;

    ret = sss_get_ex(&inp, flags, timeout);
    if (ret == 0) {
        *result = inp.result.pwrep.result;
    }
    return ret;
}

int sss_nss_getgrnam_timeout(const char *name, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_GETGRNAM,
        .rd.data = name,
        .result.grrep.result = grp,
        .result.grrep.buffer = buffer,
        .result.grrep.buflen = buflen};

    if (buffer == NULL || buflen == 0) {
        return ERANGE;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &inp.rd.len);
    if (ret != 0) {
        return EINVAL;
    }
    inp.rd.len++;

    *result = NULL;

    ret = sss_get_ex(&inp, flags, timeout);
    if (ret == 0) {
        *result = inp.result.grrep.result;
    }
    return ret;
}

int sss_nss_getgrgid_timeout(gid_t gid, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    uint32_t group_gid = gid;
    struct nss_input inp = {
        .input.gid = gid,
        .cmd = SSS_NSS_GETGRGID,
        .rd.len = sizeof(uint32_t),
        .rd.data = &group_gid,
        .result.grrep.result = grp,
        .result.grrep.buffer = buffer,
        .result.grrep.buflen = buflen};

    if (buffer == NULL || buflen == 0) {
        return ERANGE;
    }

    *result = NULL;

    ret = sss_get_ex(&inp, flags, timeout);
    if (ret == 0) {
        *result = inp.result.grrep.result;
    }
    return ret;
}

int sss_nss_getgrouplist_timeout(const char *name, gid_t group,
                                 gid_t *groups, int *ngroups,
                                 uint32_t flags, unsigned int timeout)
{
    int ret;
    gid_t *new_groups;
    long int new_ngroups;
    long int start = 1;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_INITGR,
        .rd.data = name};

    if (groups == NULL || ngroups == NULL || *ngroups == 0) {
        return EINVAL;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &inp.rd.len);
    if (ret != 0) {
        return ret;
    }
    inp.rd.len++;

    new_ngroups = MAX(1, *ngroups);
    new_groups = malloc(new_ngroups * sizeof(gid_t));
    if (new_groups == NULL) {
        free(discard_const(inp.rd.data));
        return ENOMEM;
    }
    new_groups[0] = group;

    inp.result.initgrrep.groups = new_groups,
    inp.result.initgrrep.ngroups = &new_ngroups;
    inp.result.initgrrep.start = &start;


    ret = sss_get_ex(&inp, flags, timeout);
    free(discard_const(inp.rd.data));
    if (ret != 0) {
        free(new_groups);
        return ret;
    }

    memcpy(groups, new_groups, MIN(*ngroups, start) * sizeof(gid_t));
    free(new_groups);

    if (start > *ngroups) {
        ret = ERANGE;
    } else {
        ret = 0;
    }
    *ngroups = start;

    return ret;
}
