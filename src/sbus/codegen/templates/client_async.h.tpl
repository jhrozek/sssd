<template name="file-header">
    /*
        Generated by sbus code generator

        Copyright (C) 2017 Red Hat

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

    #ifndef ${file-guard}
    #define ${file-guard}

    #include <errno.h>
    #include <talloc.h>
    #include <tevent.h>

    #include "${sbus-path}/sbus.h"
    #include "${header:client_properties}"
    <loop name="custom-type-header">
    #include "${custom-type-header}"
    </loop>

</template>

<template name="method-caller">
    struct tevent_req *
    sbus_call_${token}_send
        (TALLOC_CTX *mem_ctx,
         struct sbus_connection *conn,
         <toggle name="if-raw-input">
         DBusMessage *raw_message);
         <or>
         const char *busname,
         const char *object_path<loop name="in">,
         ${type} arg_${name}</loop>);
         </toggle>

    errno_t
    sbus_call_${token}_recv
        (<toggle name="if-use-talloc">TALLOC_CTX *mem_ctx,
         struct tevent_req *req<or>struct tevent_req *req</toggle><toggle name="if-raw-output">,
         DBusMessage **_reply);
         <or><loop name="out">,
         ${type} _${name}</loop>);
         </toggle>

</template>

<template name="signal-caller">
    void
    sbus_emit_${token}
        (struct sbus_connection *conn,
         <toggle name="if-raw-input">
         DBusMessage *raw_message);
         <or>
         const char *object_path<loop name="in">,
         ${type} arg_${name}</loop>);
         </toggle>

</template>

<template name="property-caller">
    <toggle name="get-static">
    struct tevent_req *
    sbus_get_${token}_send
        (TALLOC_CTX *mem_ctx,
         struct sbus_connection *conn,
         const char *busname,
         const char *object_path);

    errno_t
    sbus_get_${token}_recv
        (struct tevent_req *req,
         ${output-type} _value);

    </toggle>
    <toggle name="get-talloc">
    struct tevent_req *
    sbus_get_${token}_send
        (TALLOC_CTX *mem_ctx,
         struct sbus_connection *conn,
         const char *busname,
         const char *object_path);

    errno_t
    sbus_get_${token}_recv
        (TALLOC_CTX *mem_ctx,
         struct tevent_req *req,
         ${output-type} _value);

    </toggle>
    <toggle name="set">
    struct tevent_req *
    sbus_set_${token}_send
        (TALLOC_CTX *mem_ctx,
         struct sbus_connection *conn,
         const char *busname,
         const char *object_path,
         ${input-type} value);

    errno_t
    sbus_set_${token}_recv
        (struct tevent_req *req);

    </toggle>
</template>

<template name="getall-caller">
    struct tevent_req *
    sbus_getall_${token}_send
        (TALLOC_CTX *mem_ctx,
         struct sbus_connection *conn,
         const char *busname,
         const char *object_path);

    errno_t
    sbus_getall_${token}_recv
        (TALLOC_CTX *mem_ctx,
         struct tevent_req *req,
         struct sbus_all_${token} **_properties);

</template>

<template name="file-footer">
    #endif /* ${file-guard} */
</template>
