/*
    SSSD

    Session recording utilities

    Authors:
        Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>

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

#include "util/session_recording.h"
#include "util/debug.h"
#include <string.h>
#include <errno.h>

errno_t session_recording_conf_load(TALLOC_CTX *mem_ctx,
                                    struct confdb_ctx *cdb,
                                    struct session_recording_conf *pconf)
{
    int ret;
    char *str;

    if (cdb == NULL || pconf == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* Read session_recording/scope option */
    ret = confdb_get_string(cdb, mem_ctx, CONFDB_SESSION_RECORDING_CONF_ENTRY,
                            CONFDB_SESSION_RECORDING_SCOPE, "none", &str);
    if (ret != EOK) goto done;
    if (strcasecmp(str, "none") == 0) {
        pconf->scope = SESSION_RECORDING_SCOPE_NONE;
    } else if (strcasecmp(str, "some") == 0) {
        pconf->scope = SESSION_RECORDING_SCOPE_SOME;
    } else if (strcasecmp(str, "all") == 0) {
        pconf->scope = SESSION_RECORDING_SCOPE_ALL;
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unknown value for session recording scope: %s\n",
              str);
        ret = EINVAL;
        goto done;
    }

    /* Read session_recording/users option */
    ret = confdb_get_string_as_list(cdb, mem_ctx,
                                    CONFDB_SESSION_RECORDING_CONF_ENTRY,
                                    CONFDB_SESSION_RECORDING_USERS,
                                    &pconf->users);
    if (ret != EOK && ret != ENOENT) goto done;

    /* Read session_recording/groups option */
    ret = confdb_get_string_as_list(cdb, mem_ctx,
                                    CONFDB_SESSION_RECORDING_CONF_ENTRY,
                                    CONFDB_SESSION_RECORDING_GROUPS,
                                    &pconf->groups);
    if (ret != EOK && ret != ENOENT) goto done;

    ret = EOK;
done:
    return ret;
}
