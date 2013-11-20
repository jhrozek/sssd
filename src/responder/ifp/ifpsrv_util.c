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

#define IFP_DEFAULT_ATTRS {SYSDB_NAME, SYSDB_UIDNUM,   \
                           SYSDB_GIDNUM, SYSDB_GECOS,  \
                           SYSDB_HOMEDIR, SYSDB_SHELL, \
                           NULL}

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

    ret = check_allowed_uids(req->caller, ifp_ctx->rctx->allowed_uids_count,
                             ifp_ctx->rctx->allowed_uids);
    if (ret == EACCES) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("User %"SPRIuid" not in ACL\n", req->caller));
        goto fail;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
               ("Cannot check if user %"SPRIuid" is present in ACL\n",
               req->caller));
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

errno_t infp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                                struct ldb_message_element *el)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;
    unsigned int i;

    if (el == NULL) {
        return EINVAL;
    }

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &(el->name));
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             DBUS_TYPE_ARRAY_AS_STRING
                                             DBUS_TYPE_STRING_AS_STRING,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&iter_dict_val,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                 &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add all the values */
    for (i = 0; i < el->num_values; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, ("element [%s] has value [%s]\n",
              el->name, (const char *) el->values[i].data));

        dbret = dbus_message_iter_append_basic(&iter_array,
                                               DBUS_TYPE_STRING,
                                               &(el->values[i].data));
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(&iter_dict_val,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static inline bool
attr_in_list(const char **list, size_t nlist, const char *str)
{
    size_t i;

    for (i = 0; i < nlist; i++) {
        if (strcasecmp(list[i], str) == 0) {
            break;
        }
    }

    return (i < nlist) ? true : false;
}

const char **
ifp_parse_attr_list(TALLOC_CTX *mem_ctx, const char *conf_str)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char **list = NULL;
    const char **res = NULL;
    int list_size;
    char **conf_list = NULL;
    int conf_list_size = 0;
    const char **allow = NULL;
    const char **deny = NULL;
    int ai = 0, di = 0, li = 0;
    int i;
    const char *defaults[] = IFP_DEFAULT_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    if (conf_str) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Cannot parse attribute ACL list  %s: %d\n",
                                    conf_str, ret));
            goto done;
        }

        allow = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        deny = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        if (allow == NULL || deny == NULL) {
            goto done;
        }
    }

    for (i = 0; i < conf_list_size; i++) {
        switch (conf_list[i][0]) {
            case '+':
                allow[ai] = conf_list[i] + 1;
                ai++;
                continue;
            case '-':
                deny[di] = conf_list[i] + 1;
                di++;
                continue;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, ("ACL values must start with "
                      "either '+' (allow) or '-' (deny), got '%s'\n",
                      conf_list[i]));
                goto done;
        }
    }

    /* Assume the output will have to hold defauls and all the configured,
     * values, resize later
     */
    list_size = 0;
    while (defaults[list_size]) {
        list_size++;
    }
    list_size += conf_list_size;

    list = talloc_zero_array(tmp_ctx, const char *, list_size + 1);
    if (list == NULL) {
        goto done;
    }

    /* Start by copying explicitly allowed attributes */
    for (i = 0; i < ai; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, allow[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, allow[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Added allowed attr %s to whitelist\n", allow[i]));
    }

    /* Add defaults */
    for (i = 0; defaults[i]; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, defaults[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, defaults[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("Added default attr %s to whitelist\n", defaults[i]));
    }

    res = talloc_steal(mem_ctx, list);
done:
    talloc_free(tmp_ctx);
    return res;
}

bool
ifp_attr_allowed(const char *whitelist[], const char *attr)
{
    size_t i;

    if (whitelist == NULL) {
        return false;
    }

    for (i = 0; whitelist[i]; i++) {
        if (strcasecmp(whitelist[i], attr) == 0) {
            break;
        }
    }

    return (whitelist[i]) ? true : false;
}
