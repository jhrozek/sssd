/*
    Authors:
        Petr Čech <pcech@redhat.com>

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

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/negcache.h"


static const int get_pw_bufsize(void)
{
    int bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }
    return bufsize;
}

static const int get_nc_timeout(struct sss_nc_ctx *ncache, bool is_locals)
{
    const int timeout = sss_ncache_get_timeout(ncache);
    const int locals_timeout = sss_ncache_get_locals_timeout(ncache);

    return is_locals ? locals_timeout : timeout;
}

int sss_ncache_init_from_confdb(TALLOC_CTX *mem_ctx,
                                struct confdb_ctx *cdb,
                                const char *section,
                                struct sss_nc_ctx **_ncache)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_nc_ctx *ncache;
    int timeout;
    int locals_timeout;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sss_ncache_init(tmp_ctx, &ncache);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing negative cache\n");
        goto done;
    }

    ret = confdb_get_int(cdb, section,
                         CONFDB_NSS_ENTRY_NEG_TIMEOUT, 15,
                         &timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, section,
                         CONFDB_RESPONDER_NEG_CACHE_LOCAL_TIMEOUT,
                         0, &locals_timeout);
    if (ret != EOK) goto done;

    sss_ncache_set_timeout(ncache, timeout);
    sss_ncache_set_locals_timeout(ncache, locals_timeout);

    *_ncache = talloc_steal(mem_ctx, ncache);
    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

int sss_ncache_check_user_with_locals(struct sss_nc_ctx *ncache,
                                      struct sss_domain_info *dom,
                                      const char *name)
{
    struct passwd pwd = {0};
    struct passwd *pwd_result;
    char *buffer;
    const int bufsize = get_pw_bufsize();
    bool is_locals = false;
    int ret;

    buffer = talloc_array(NULL, char, bufsize);
    if (buffer == NULL) {
        return ENOMEM;
    }

    ret = getpwnam_r(name, &pwd, buffer, bufsize, &pwd_result);
    if (ret == EOK && pwd_result != NULL) {
        is_locals = sss_ncache_get_locals_timeout(ncache) == 0 ? false : true;
    }
    talloc_zfree(buffer);

    ret = sss_ncache_check_user(ncache, get_nc_timeout(ncache, is_locals),
                                dom, name);
    if (ret != EEXIST && is_locals) {

        ret = sss_ncache_set_user(ncache, false, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s@%s\n",
                  name, dom->name);
        }

        ret = EEXIST;
    }

    return ret;
}

int sss_ncache_check_uid_with_locals(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *dom, uid_t uid)
{
    struct passwd pwd = {0};
    struct passwd *pwd_result;
    char *buffer;
    const int bufsize = get_pw_bufsize();
    bool is_locals = false;
    int ret;

    buffer = talloc_array(NULL, char, bufsize);
    if (buffer == NULL) {
        return ENOMEM;
    }

    ret = getpwuid_r(uid, &pwd, buffer, bufsize, &pwd_result);
    if (ret == EOK && pwd_result != NULL) {
        is_locals = sss_ncache_get_locals_timeout(ncache) == 0 ? false : true;
    }
    talloc_zfree(buffer);

    ret = sss_ncache_check_uid(ncache, get_nc_timeout(ncache, is_locals),
                               dom, uid);
    if (ret != EEXIST && is_locals) {

        ret = sss_ncache_set_uid(ncache, false, dom, uid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot set negative cache for UID %"PRIu32"\n",
                  uid);
        }

        ret = EEXIST;
    }

    return ret;
}

int sss_ncache_check_group_with_locals(struct sss_nc_ctx *ncache,
                                       struct sss_domain_info *dom,
                                       const char *name)
{
    struct group grp = {0};
    struct group *grp_result;
    char *buffer;
    const int bufsize = get_pw_bufsize();
    bool is_locals = false;
    int ret;

    buffer = talloc_array(NULL, char, bufsize);
    if (buffer == NULL) {
        return ENOMEM;
    }

    ret = getgrnam_r(name, &grp, buffer, bufsize, &grp_result);
    if (ret == EOK && grp_result != NULL) {
        is_locals = sss_ncache_get_locals_timeout(ncache) == 0 ? false : true;
    }
    talloc_zfree(buffer);

    ret = sss_ncache_check_group(ncache, get_nc_timeout(ncache, is_locals),
                                 dom, name);
    if (ret != EEXIST && is_locals) {

        ret = sss_ncache_set_group(ncache, false, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot set negcache for %s@%s\n",
                  name, dom->name);
        }

        ret = EEXIST;
    }

    return ret;
}

int sss_ncache_check_gid_with_locals(struct sss_nc_ctx *ncache,
                                     struct sss_domain_info *dom, uid_t gid)
{
    struct group grp = {0};
    struct group *grp_result;
    char *buffer;
    const int bufsize = get_pw_bufsize();
    bool is_locals = false;
    int ret;

    buffer = talloc_array(NULL, char, bufsize);
    if (buffer == NULL) {
        return ENOMEM;
    }

    ret = getgrgid_r(gid, &grp, buffer, bufsize, &grp_result);
    if (ret == EOK && grp_result != NULL) {
        is_locals = sss_ncache_get_locals_timeout(ncache) == 0 ? false : true;
    }
    talloc_zfree(buffer);

    ret = sss_ncache_check_gid(ncache, get_nc_timeout(ncache, is_locals),
                               dom, gid);
    if (ret != EEXIST && is_locals) {

        ret = sss_ncache_set_gid(ncache, false, dom, gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot set negative cache for GID %"PRIu32"\n",
                  gid);
        }

        ret = EEXIST;
    }

    return ret;
}

// sss_ncache_check_sid