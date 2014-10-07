/*
   SSSD

   Data Provider Helpers

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <talloc.h>

#include "util/util.h"
#include "sbus_client.h"

int sbus_client_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     const char *server_address,
                     struct sbus_connection **_conn)
{
    struct sbus_connection *conn = NULL;
    int ret;
    char *filename;

    /* Validate input */
    if (server_address == NULL) {
        return EINVAL;
    }

    filename = strchr(server_address, '/');
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected dbus address [%s].\n", server_address);
        return EIO;
    }

    ret = check_file(filename, geteuid(), getegid(),
                     S_IFSOCK|S_IRUSR|S_IWUSR, 0, NULL, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_file failed for [%s].\n", filename);
        return EIO;
    }

    ret = sbus_new_connection(mem_ctx, ev, server_address, &conn);
    if (ret != EOK) {
        goto fail;
    }

    *_conn = conn;
    return EOK;

fail:
    talloc_free(conn);
    return ret;
}
