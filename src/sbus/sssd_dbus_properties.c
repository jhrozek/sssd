/*
    Authors:
        Stef Walter <stefw@redhat.com>

    Copyright (C) 2014 Red Hat

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
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_private.h"

static int
dispatch_properties_set(struct sbus_connection *conn,
                        struct sbus_interface *intf,
                        DBusMessage *message)
{
    const char *signature;
    const struct sbus_interface_meta *meta;
    const struct sbus_property_meta *property;
    const char *interface_name;
    const char *property_name;
    const char *type;
    struct sbus_request *req;
    sbus_msg_handler_fn handler_fn;
    DBusMessageIter iter;
    DBusMessageIter variant;

    req = sbus_new_request(conn, intf, message);
    if (!req)
        return ENOMEM;

    meta = intf->vtable->meta;

    signature = dbus_message_get_signature(message);
    if (strcmp (signature, "ssv") != 0)
        return sbus_request_fail_and_finish(req, DBUS_ERROR_INVALID_ARGS,
                                            "Invalid argument types passed to Set method");

    dbus_message_iter_init (message, &iter);
    dbus_message_iter_get_basic (&iter, &interface_name);
    dbus_message_iter_next (&iter);
    dbus_message_iter_get_basic (&iter, &property_name);
    dbus_message_iter_next (&iter);

    if (strcmp (interface_name, meta->name) != 0)
        return sbus_request_fail_and_finish(req, DBUS_ERROR_UNKNOWN_INTERFACE, "No such interface");

    property = sbus_meta_find_property (intf->vtable->meta, property_name);
    if (property == NULL)
        return sbus_request_fail_and_finish(req, DBUS_ERROR_UNKNOWN_PROPERTY, "No such property");

    if (!(property->flags & SBUS_PROPERTY_WRITABLE))
        return sbus_request_fail_and_finish(req, DBUS_ERROR_PROPERTY_READ_ONLY, "Property is not writable");

    dbus_message_iter_recurse(&iter, &variant);
    type = dbus_message_iter_get_signature (&variant);
    if (strcmp (property->type, type) != 0)
        return sbus_request_fail_and_finish(req, DBUS_ERROR_INVALID_ARGS, "Invalid data type for property");

    handler_fn = VTABLE_FUNC(intf->vtable, property->vtable_offset_set);
    if (!handler_fn)
        return sbus_request_fail_and_finish(req, DBUS_ERROR_NOT_SUPPORTED, "Not implemented");

    return sbus_request_invoke_or_finish(req, handler_fn, property->invoker_set);
}

DBusHandlerResult
sbus_properties_dispatch(struct sbus_connection *conn,
                         struct sbus_interface *intf,
                         DBusMessage *message)
{
    const char *member;
    int ret;

    member = dbus_message_get_member(message);

    /* Set is handled a lot like a method invocation */
    if (strcmp (member, "Set") == 0) {
        ret = dispatch_properties_set(conn, intf, message);

    } else {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    /* Error has already been logged */
    if (ret == ENOMEM)
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    else if (ret == EOK)
        return DBUS_HANDLER_RESULT_HANDLED;
    else
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
