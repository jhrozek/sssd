/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    Autofs responder: the responder server

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

#ifndef _SSHSRV_PRIVATE_H_
#define _SSHSRV_PRIVATE_H_

#include "responder/common/responder.h"
#include "providers/data_provider.h"

struct ifp_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;
};

#endif /* _SSHSRV_PRIVATE_H_ */
