/* The following declarations are auto-generated from resp_iface.xml */

#ifndef __RESP_IFACE_XML__
#define __RESP_IFACE_XML__

#include "sbus/sssd_dbus.h"

/* ------------------------------------------------------------------------
 * DBus Constants
 *
 * Various constants of interface and method names mostly for use by clients
 */

/* constants for org.freedesktop.sssd.responder.Backend */
#define IFACE_RESPONDER_BACKEND "org.freedesktop.sssd.responder.Backend"
#define IFACE_RESPONDER_BACKEND_DOMAININVALID "DomainInvalid"
#define IFACE_RESPONDER_BACKEND_DOMAINVALID "DomainValid"
#define IFACE_RESPONDER_BACKEND_RESETNEGCACHEUSERS "ResetNegcacheUsers"
#define IFACE_RESPONDER_BACKEND_RESETNEGCACHEGROUPS "ResetNegcacheGroups"

/* ------------------------------------------------------------------------
 * DBus handlers
 *
 * These structures are filled in by implementors of the different
 * dbus interfaces to handle method calls.
 *
 * Handler functions of type sbus_msg_handler_fn accept raw messages,
 * other handlers are typed appropriately. If a handler that is
 * set to NULL is invoked it will result in a
 * org.freedesktop.DBus.Error.NotSupported error for the caller.
 *
 * Handlers have a matching xxx_finish() function (unless the method has
 * accepts raw messages). These finish functions the
 * sbus_request_return_and_finish() with the appropriate arguments to
 * construct a valid reply. Once a finish function has been called, the
 * @dbus_req it was called with is freed and no longer valid.
 */

/* vtable for org.freedesktop.sssd.responder.Backend */
struct iface_responder_backend {
    struct sbus_vtable vtable; /* derive from sbus_vtable */
    int (*DomainInvalid)(struct sbus_request *req, void *data, const char *arg_name);
    int (*DomainValid)(struct sbus_request *req, void *data, const char *arg_name);
    int (*ResetNegcacheUsers)(struct sbus_request *req, void *data);
    int (*ResetNegcacheGroups)(struct sbus_request *req, void *data);
};

/* finish function for DomainInvalid */
int iface_responder_backend_DomainInvalid_finish(struct sbus_request *req);

/* finish function for DomainValid */
int iface_responder_backend_DomainValid_finish(struct sbus_request *req);

/* finish function for ResetNegcacheUsers */
int iface_responder_backend_ResetNegcacheUsers_finish(struct sbus_request *req);

/* finish function for ResetNegcacheGroups */
int iface_responder_backend_ResetNegcacheGroups_finish(struct sbus_request *req);

/* ------------------------------------------------------------------------
 * DBus Interface Metadata
 *
 * These structure definitions are filled in with the information about
 * the interfaces, methods, properties and so on.
 *
 * The actual definitions are found in the accompanying C file next
 * to this header.
 */

/* interface info for org.freedesktop.sssd.responder.Backend */
extern const struct sbus_interface_meta iface_responder_backend_meta;

#endif /* __RESP_IFACE_XML__ */
