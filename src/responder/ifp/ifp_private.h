/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    Autofs responder: the responder server

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

#ifndef _SSHSRV_PRIVATE_H_
#define _SSHSRV_PRIVATE_H_

#include "responder/common/responder.h"
#include "providers/data_provider.h"

#define INFP_INTROSPECT_XML "infopipe/org.freedesktop.sssd.infopipe.Introspect.xml"

#define INFOPIPE_DBUS_NAME "org.freedesktop.sssd.infopipe"
#define INFOPIPE_INTERFACE "org.freedesktop.sssd.infopipe"
#define INFOPIPE_PATH "/org/freedesktop/sssd/infopipe"

struct sysbus_ctx {
    struct sbus_connection *conn;
    char *introspect_xml;
};

struct ifp_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;
    struct sss_nc_ctx *ncache;

    struct sysbus_ctx *sysbus;
};

/* == Utility functions == */
errno_t sysbus_get_caller(struct sbus_connection *conn,
                          DBusMessage *message,
                          uid_t *_uid);

struct infp_req {
    struct ifp_ctx *ifp_ctx;
    struct sysbus_ctx *system_bus;

    struct sbus_connection *conn;
    DBusMessage *message;
    DBusMessage *reply;
    uid_t caller;
};

struct infp_req *infp_req_create(TALLOC_CTX *mem_ctx,
                                 DBusMessage *message,
                                 struct sbus_connection *conn);

errno_t infp_enomem(struct infp_req *ireq);

errno_t infp_invalid_args(struct infp_req *ireq,
                          DBusError *error);

void infp_return_failure(struct infp_req *ireq, const char *err_msg);

errno_t infp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                                struct ldb_message_element *el);

/* == Public InfoPipe Methods ==
 *
 * NOTE: Any changes to the method names and arguments for these calls
 * must also be updated in the org.freedesktop.sssd.infopipe.Introspect.xml
 * or clients may not behave properly.
 */

/* Introspection */
int infp_introspect(DBusMessage *message, struct sbus_connection *conn);

#endif /* _SSHSRV_PRIVATE_H_ */
