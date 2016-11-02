/* The following definitions are auto-generated from resp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "resp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.responder.Backend.DomainInvalid */
const struct sbus_arg_meta iface_responder_backend_DomainInvalid__in[] = {
    { "name", "s" },
    { NULL, }
};

int iface_responder_backend_DomainInvalid_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.responder.Backend.DomainValid */
const struct sbus_arg_meta iface_responder_backend_DomainValid__in[] = {
    { "name", "s" },
    { NULL, }
};

int iface_responder_backend_DomainValid_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_responder_backend_ResetNegcacheUsers_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_responder_backend_ResetNegcacheGroups_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.responder.Backend */
const struct sbus_method_meta iface_responder_backend__methods[] = {
    {
        "DomainInvalid", /* name */
        iface_responder_backend_DomainInvalid__in,
        NULL, /* no out_args */
        offsetof(struct iface_responder_backend, DomainInvalid),
        invoke_s_method,
    },
    {
        "DomainValid", /* name */
        iface_responder_backend_DomainValid__in,
        NULL, /* no out_args */
        offsetof(struct iface_responder_backend, DomainValid),
        invoke_s_method,
    },
    {
        "ResetNegcacheUsers", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_responder_backend, ResetNegcacheUsers),
        NULL, /* no invoker */
    },
    {
        "ResetNegcacheGroups", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_responder_backend, ResetNegcacheGroups),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.responder.Backend */
const struct sbus_interface_meta iface_responder_backend_meta = {
    "org.freedesktop.sssd.responder.Backend", /* name */
    iface_responder_backend__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    int (*handler)(struct sbus_request *, void *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}
