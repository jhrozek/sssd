/*
   SSSD

   libcurl tevent integration

   Copyright (C) Red Hat, 2016

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

#ifndef __TEV_CURL_H
#define __TEV_CURL_H

#include <talloc.h>
#include <tevent.h>

#include "util/sss_iobuf.h"

/* Supported HTTP requests */
enum tcurl_http_request {
    HTTP_GET,
    HTTP_PUT,
    HTTP_DELETE,
};

/*
 * Initialize the tcurl tevent wrapper. Headers are a NULL-terminated
 * array of strings such as:
 *   static const char *headers[] = {
 *       "Content-type: application/octet-stream",
 *       NULL,
 *   };
 */
struct tcurl_ctx *tcurl_init(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             const char *headers[]);

/*
 * Run a single request. Currently only UNIX sockets at socket_path are supported.
 * The timeout parameter defaults to 0 if not specified.
 *
 * If the request runs into completion, but reports a failure with HTTP return
 * code, the request will be marked as done. Only if the request cannot run at
 * all (if e.g. the socket is unreachable), the request will fail completely.
 */
struct tevent_req *tcurl_http_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct tcurl_ctx *tctx,
                                   enum tcurl_http_request req_type,
                                   const char *socket_path,
                                   const char *url,
                                   struct sss_iobuf *req_data,
                                   int timeout);

int tcurl_http_recv(TALLOC_CTX *mem_ctx,
                    struct tevent_req *req,
                    int *_http_code,
                    struct sss_iobuf **_outbuf);

#endif /* __TEV_CURL_H */
