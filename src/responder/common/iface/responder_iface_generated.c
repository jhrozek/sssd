/* The following definitions are auto-generated from responder_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "responder_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.Responder.Domain.Enable */
const struct sbus_arg_meta iface_responder_domain_Enable__in[] = {
    { "name", "s" },
    { NULL, }
};

int iface_responder_domain_Enable_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* arguments for org.freedesktop.sssd.Responder.Domain.Disable */
const struct sbus_arg_meta iface_responder_domain_Disable__in[] = {
    { "name", "s" },
    { NULL, }
};

int iface_responder_domain_Disable_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.Responder.Domain */
const struct sbus_method_meta iface_responder_domain__methods[] = {
    {
        "Enable", /* name */
        iface_responder_domain_Enable__in,
        NULL, /* no out_args */
        offsetof(struct iface_responder_domain, Enable),
        invoke_s_method,
    },
    {
        "Disable", /* name */
        iface_responder_domain_Disable__in,
        NULL, /* no out_args */
        offsetof(struct iface_responder_domain, Disable),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.Responder.Domain */
const struct sbus_interface_meta iface_responder_domain_meta = {
    "org.freedesktop.sssd.Responder.Domain", /* name */
    iface_responder_domain__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

int iface_responder_ncache_ResetUsers_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

int iface_responder_ncache_ResetGroups_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.Responder.NegativeCache */
const struct sbus_method_meta iface_responder_ncache__methods[] = {
    {
        "ResetUsers", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_responder_ncache, ResetUsers),
        NULL, /* no invoker */
    },
    {
        "ResetGroups", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_responder_ncache, ResetGroups),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.Responder.NegativeCache */
const struct sbus_interface_meta iface_responder_ncache_meta = {
    "org.freedesktop.sssd.Responder.NegativeCache", /* name */
    iface_responder_ncache__methods,
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
