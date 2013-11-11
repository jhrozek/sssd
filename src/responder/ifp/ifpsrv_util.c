/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: Utility functions

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

#include "db/sysdb.h"
#include "responder/ifp/ifp_private.h"

errno_t
sysbus_get_caller(struct sbus_connection *conn,
                  DBusMessage *message,
                  uid_t *_uid)
{
    const char *conn_name;
    DBusError error;
    unsigned long uid;

    /* Get the connection UID */
    conn_name = dbus_message_get_sender(message);
    if (conn_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Critical error: D-BUS client has no unique name\n"));
        return EFAULT;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sender name is %s\n", conn_name));

    dbus_error_init(&error);
    uid = dbus_bus_get_unix_user(sbus_get_connection(conn), conn_name, &error);
    if (uid == (unsigned long) -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not identify unix user. Error message was '%s:%s'\n",
               error.name, error.message));
        dbus_error_free(&error);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("sender ID is %lu\n", uid));
    *_uid = uid;
    return EOK;
}

static int infp_req_destructor(void *ptr)
{
    struct infp_req *ifp_req = talloc_get_type(ptr, struct infp_req);

    if (ifp_req == NULL || ifp_req->reply == NULL) {
        return 0;
    }

    dbus_message_unref(ifp_req->reply);
    return 0;
}

struct infp_req *infp_req_create(TALLOC_CTX *mem_ctx,
                                 DBusMessage *message,
                                 struct sbus_connection *conn)
{
    struct infp_req *req;
    struct ifp_ctx *ifp_ctx = NULL;
    DBusMessage *reply;
    errno_t ret;

    ifp_ctx = talloc_get_type(sbus_conn_get_private_data(conn),
                              struct ifp_ctx);
    if (ifp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad private pointer\n"));
        return NULL;
    }

    if (ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Responder not connected to sysbus!\n"));
        return NULL;
    }

    req = talloc_zero(mem_ctx, struct infp_req);
    if (req == NULL) {
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX *) req, infp_req_destructor);

    reply = dbus_message_new_method_return(message);
    if (reply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot construct reply\n"));
        goto fail;
    }

    req->ifp_ctx = ifp_ctx;
    req->system_bus = ifp_ctx->sysbus;
    req->conn = conn;
    req->message = message;
    req->reply = reply;

    ret = sysbus_get_caller(conn, message, &req->caller);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not identify caller, access denied\n"));
        goto fail;
    }

    return req;

fail:
    talloc_free(req);
    return NULL;
}

errno_t infp_enomem(struct infp_req *ireq)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(ireq->reply,
                                   DBUS_ERROR_NO_MEMORY,
                                   "Out of memory!\n");
    if (reply == NULL) {
        return ENOMEM;
    }

    sbus_conn_send_reply(ireq->conn, reply);
    return EOK;
}

errno_t infp_invalid_args(struct infp_req *ireq,
                          DBusError *error)
{
    DBusMessage *reply;
    const char *err_msg;

    err_msg = talloc_strdup(ireq, error->message);
    dbus_error_free(error);

    reply = dbus_message_new_error(ireq->reply,
                                   DBUS_ERROR_INVALID_ARGS,
                                   err_msg);
    if (reply == NULL) {
        return ENOMEM;
    }

    sbus_conn_send_reply(ireq->conn, reply);
    return EOK;
}

/* Helper function to return an immediate error message in the event
 * of internal error in the InfoPipe to avoid forcing the clients to
 * time out waiting for a reply.
 * This function will make a best effort to send a reply, but if it
 * fails, clients will simply have to handle the timeout.
 */
void infp_return_failure(struct infp_req *ireq, const char *err_msg)
{
    DBusMessage *reply;

    if (ireq == NULL) return;

    reply = dbus_message_new_error(ireq->reply,
                                   DBUS_ERROR_FAILED,
                                   err_msg);
    /* If the reply was NULL, we ran out of memory, so we won't
     * bother trying to queue the message to send. In this case,
     * our safest move is to allow the client to time out waiting
     * for a reply.
     */
    if (reply) {
        sbus_conn_send_reply(ireq->conn, reply);
    }
}
