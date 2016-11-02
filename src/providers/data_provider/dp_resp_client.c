/*
   SSSD

   Data Provider Responder client - DP calls responder interface

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

#include "config.h"
#include <talloc.h>
#include <tevent.h>

#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/data_provider.h"
#include "providers/data_provider/dp_private.h"
#include "responder/common/resp_iface.h"

/* List of DP clients that deal with users or groups */
/* FIXME - it would be much cleaner to implement sbus signals
 * and let the responder subscribe to these messages rather than
 * keep a list here..
 *  https://fedorahosted.org/sssd/ticket/2233
 */
static enum dp_clients user_clients[] = {
    DPC_NSS,
    DPC_PAM,
    DPC_IFP,
    DPC_PAC,
    DPC_SUDO,

    DP_CLIENT_SENTINEL
};

static void dispatch_cli_msg(struct data_provider *provider,
                             struct DBusMessage *msg,
                             enum dp_clients *client_list)
{
    struct dp_client *dp_cli_list[DP_CLIENT_SENTINEL] = { NULL };

    if (client_list != NULL) {
        for (int i = 0; client_list[i] != DP_CLIENT_SENTINEL; i++) {
            dp_cli_list[i] = provider->clients[i];
        }
    } else {
        memcpy(dp_cli_list, provider->clients, sizeof(dp_cli_list));
    }

    for (int i = 0; i < DP_CLIENT_SENTINEL; i++) {
        struct dp_client *cli = dp_cli_list[i];

        if (cli == NULL) {
            continue;
        }

        sbus_conn_send_reply(dp_client_conn(cli), msg);
    }
}

static void dp_sbus_set_domain_status(struct data_provider *provider,
                                      struct sss_domain_info *dom)
{
    DBusMessage *msg;
    dbus_bool_t dbret;
    const char *meth;

    if (sss_domain_get_state(dom) == DOM_DISABLED) {
        meth = IFACE_RESPONDER_BACKEND_DOMAININVALID;
    } else {
        meth = IFACE_RESPONDER_BACKEND_DOMAINVALID;
    }

    msg = dbus_message_new_method_call(NULL,
                                       RESP_IFACE_PATH,
                                       IFACE_RESPONDER_BACKEND,
                                       meth);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        return;
    }

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &dom->name,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        dbus_message_unref(msg);
        return;
    }

    dispatch_cli_msg(provider, msg, NULL);
    dbus_message_unref(msg);
    return;
}

void dp_sbus_enable_domain(struct data_provider *provider,
                           struct sss_domain_info *dom)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to enable a domain\n");
    sss_domain_set_state(dom, DOM_ACTIVE);
    return dp_sbus_set_domain_status(provider, dom);
}

void dp_sbus_disable_domain(struct data_provider *provider,
                            struct sss_domain_info *dom)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering responders to disable a domain\n");
    sss_domain_set_state(dom, DOM_DISABLED);
    return dp_sbus_set_domain_status(provider, dom);
}
