/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: command handlers

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

#include "responder/ifp/ifp_private.h"

int infp_introspect(DBusMessage *message, struct sbus_connection *conn)
{
    DBusMessage *reply;
    FILE *xml_stream = NULL;
    struct ifp_ctx *ifp_ctx;
    struct sysbus_ctx *sysbus;
    long xml_size, read_size;
    int ret;
    dbus_bool_t dbret;

    ifp_ctx = talloc_get_type(sbus_conn_get_private_data(conn),
                              struct ifp_ctx);
    if (ifp_ctx == NULL || ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad private pointer\n"));
        return EFAULT;
    }
    sysbus = ifp_ctx->sysbus;

    if (sysbus->introspect_xml == NULL) {
        /* Read in the Introspection XML the first time */
        xml_stream = fopen(SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML, "r");
        if (xml_stream == NULL) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not open [%s] for reading. [%d:%s]\n",
                   SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML,
                   ret, strerror(ret)));
            return ret;
        }

        if (fseek(xml_stream, 0L, SEEK_END) != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not seek into [%s]. [%d:%s]\n",
                   SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML,
                  ret, strerror(ret)));
            goto done;
        }

        errno = 0;
        xml_size = ftell(xml_stream);
        if (xml_size <= 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not get [%s] length (or file is empty). [%d:%s]\n",
                   SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML,
                   ret, strerror(ret)));
            goto done;
        }

        if (fseek(xml_stream, 0L, SEEK_SET) != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not seek into [%s]. [%d:%s]\n",
                   SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML,
                   ret, strerror(ret)));
            goto done;
        }

        sysbus->introspect_xml = talloc_size(sysbus, xml_size+1);
        if (sysbus->introspect_xml == NULL) {
            ret = ENOMEM;
            goto done;
        }

        read_size = fread(sysbus->introspect_xml, 1, xml_size, xml_stream);
        if (read_size < xml_size) {
            if (!feof(xml_stream)) {
                ret = ferror(xml_stream);
                DEBUG(SSSDBG_CRIT_FAILURE,
                      ("Error occurred while reading [%s]. [%d:%s]\n",
                       SSSD_INTROSPECT_PATH"/"INFP_INTROSPECT_XML,
                       ret, strerror(ret)));

                talloc_free(sysbus->introspect_xml);
                sysbus->introspect_xml = NULL;
                goto done;
            }
        }

        /* Copy the introspection XML to the sysbus_ctx */
        sysbus->introspect_xml[xml_size+1] = '\0';
    }

    /* Return the Introspection XML */
    reply = dbus_message_new_method_return(message);
    if (reply == NULL) {
        ret = ENOMEM;
        goto done;
    }
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_STRING, &sysbus->introspect_xml,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    DEBUG(SSSDBG_TRACE_LIBS, ("%s\n", sysbus->introspect_xml));
    ret = EOK;

done:
    if (xml_stream) fclose(xml_stream);
    return ret;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

