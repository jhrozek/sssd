/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "config.h"

#include "util/sss_ldap.h"
#include "util/util.h"

const char* sss_ldap_err2string(int err)
{
    static const char *password_expired = "Password expired";

    switch (err) {
    case LDAP_X_SSSD_PASSWORD_EXPIRED:
        return password_expired;
    default:
        return ldap_err2string(err);
    }
}

int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp)
{
#ifdef HAVE_LDAP_CONTROL_CREATE
    return ldap_control_create(oid, iscritical, value, dupval, ctrlp);
#else
    LDAPControl *lc = NULL;

    if (oid == NULL || ctrlp == NULL) {
        return LDAP_PARAM_ERROR;
    }

    lc = calloc(sizeof(LDAPControl), 1);
    if (lc == NULL) {
        return LDAP_NO_MEMORY;
    }

    lc->ldctl_oid = strdup(oid);
    if (lc->ldctl_oid == NULL) {
        free(lc);
        return LDAP_NO_MEMORY;
    }

    if (value != NULL && value->bv_val != NULL) {
        if (dupval == 0) {
            lc->ldctl_value = *value;
        } else {
            ber_dupbv(&lc->ldctl_value, value);
            if (lc->ldctl_value.bv_val == NULL) {
                free(lc->ldctl_oid);
                free(lc);
                return LDAP_NO_MEMORY;
            }
        }
    }

    lc->ldctl_iscritical = iscritical;

    *ctrlp = lc;

    return LDAP_SUCCESS;
#endif
}

inline const char *
sss_ldap_escape_ip_address(TALLOC_CTX *mem_ctx, int family, const char *addr)
{
    return family == AF_INET6 ? talloc_asprintf(mem_ctx, "[%s]", addr) :
                                talloc_strdup(mem_ctx, addr);
}

#ifdef HAVE_LDAP_INIT_FD
struct sdap_async_sys_connect_state {
    long old_flags;
    struct tevent_fd *fde;
    int fd;
    socklen_t addr_len;
    struct sockaddr_storage addr;
};

static void sdap_async_sys_connect_done(struct tevent_context *ev,
                                        struct tevent_fd *fde, uint16_t flags,
                                        void *priv);

static struct tevent_req *sdap_async_sys_connect_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    int fd,
                                                    const struct sockaddr *addr,
                                                    socklen_t addr_len)
{
    struct tevent_req *req;
    struct sdap_async_sys_connect_state *state;
    long flags;
    int ret;
    int fret;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        DEBUG(1, ("fcntl F_GETFL failed.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_async_sys_connect_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->old_flags = flags;
    state->fd = fd;
    state->addr_len = addr_len;
    memcpy(&state->addr, addr, addr_len);

    ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (ret != EOK) {
        DEBUG(1, ("fcntl F_SETFL failed.\n"));
        goto done;
    }

    ret = connect(fd, addr, addr_len);
    if (ret == EOK) {
        goto done;
    }

    ret = errno;
    switch(ret) {
        case EINPROGRESS:
        case EINTR:
            state->fde = tevent_add_fd(ev, state, fd,
                                       TEVENT_FD_READ | TEVENT_FD_WRITE,
                                       sdap_async_sys_connect_done, req);
            if (state->fde == NULL) {
                DEBUG(1, ("tevent_add_fd failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            return req;

            break;
        default:
            DEBUG(1, ("connect failed [%d][%s].\n", ret, strerror(ret)));
    }

done:
    fret = fcntl(fd, F_SETFL, flags);
    if (fret != EOK) {
        DEBUG(1, ("fcntl F_SETFL failed.\n"));
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, ev);
    return req;
}

static void sdap_async_sys_connect_done(struct tevent_context *ev,
                                        struct tevent_fd *fde, uint16_t flags,
                                        void *priv)
{
    struct tevent_req *req = talloc_get_type(priv, struct tevent_req);
    struct sdap_async_sys_connect_state *state = tevent_req_data(req,
                                          struct sdap_async_sys_connect_state);
    int ret = EOK;
    int fret;

    /* I found the following comment in samba's lib/async_req/async_sock.c:
     * Stevens, Network Programming says that if there's a
     * successful connect, the socket is only writable. Upon an
     * error, it's both readable and writable.
     */
    if ((flags & (TEVENT_FD_READ|TEVENT_FD_WRITE)) ==
        (TEVENT_FD_READ|TEVENT_FD_WRITE)) {

        ret = connect(state->fd, (struct sockaddr *) &state->addr,
                      state->addr_len);
        if (ret == EOK) {
            goto done;
        }

        ret = errno;
        if (ret == EINPROGRESS || ret == EINTR) {
            return;
        }

        DEBUG(1, ("connect failed [%d][%s].\n", ret, strerror(ret)));
    }

done:
    talloc_zfree(fde);

    fret = fcntl(state->fd, F_SETFL, state->old_flags);
    if (fret != EOK) {
        DEBUG(1, ("fcntl F_SETFL failed.\n"));
    }

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

static int sdap_async_sys_connect_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t set_fd_flags_and_opts(int fd)
{
    int ret;
    long flags;
    int dummy = 1;

    flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) {
        ret = errno;
        DEBUG(1, ("fcntl F_GETFD failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    flags = fcntl(fd, F_SETFD, flags| FD_CLOEXEC);
    if (flags == -1) {
        ret = errno;
        DEBUG(1, ("fcntl F_SETFD failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        ret = errno;
        DEBUG(1, ("fcntl F_GETFL failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    flags = fcntl(fd, F_SETFL, flags| O_NONBLOCK);
    if (flags == -1) {
        ret = errno;
        DEBUG(1, ("fcntl F_SETFL failed [%d][%s].\n", ret, strerror(ret)));
        return ret;
    }

    /* SO_KEEPALIVE and TCP_NODELAY are set by OpenLDAP client libraries but
     * failures are ignored.*/
    ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &dummy, sizeof(dummy));
    if (ret != 0) {
        ret = errno;
        DEBUG(5, ("setsockopt SO_KEEPALIVE failed.[%d][%s].\n", ret,
                  strerror(ret)));
    }

    ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &dummy, sizeof(dummy));
    if (ret != 0) {
        ret = errno;
        DEBUG(5, ("setsockopt TCP_NODELAY failed.[%d][%s].\n", ret,
                  strerror(ret)));
    }

    return EOK;
}

#define LDAP_PROTO_TCP 1 /* ldap://  */
#define LDAP_PROTO_UDP 2 /* reserved */
#define LDAP_PROTO_IPC 3 /* ldapi:// */
#define LDAP_PROTO_EXT 4 /* user-defined socket/sockbuf */

extern int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld);

static void sss_ldap_init_sys_connect_done(struct tevent_req *subreq);
#endif

struct sss_ldap_init_state {
    LDAP *ldap;
    int sd;
    const char *uri;
};


struct tevent_req *sss_ldap_init_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      const char *uri,
                                      struct sockaddr_storage *addr,
                                      int addr_len)
{
    int ret = EOK;
    struct tevent_req *req;
    struct sss_ldap_init_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sss_ldap_init_state);
    if (req == NULL) {
        DEBUG(1, ("tevent_req_create failed.\n"));
        return NULL;
    }

    state->ldap = NULL;
    state->uri = uri;

#ifdef HAVE_LDAP_INIT_FD
    struct tevent_req *subreq;

    state->sd = socket(addr->ss_family, SOCK_STREAM, 0);
    if (state->sd == -1) {
        ret = errno;
        DEBUG(1, ("socket failed [%d][%s].\n", ret, strerror(ret)));
        goto fail;
    }

    ret = set_fd_flags_and_opts(state->sd);
    if (ret != EOK) {
        DEBUG(1, ("set_fd_flags_and_opts failed.\n"));
        goto fail;
    }

    DEBUG(9, ("Using file descriptor [%d] for LDAP connection.\n", state->sd));

    subreq = sdap_async_sys_connect_send(state, ev, state->sd,
                                         (struct sockaddr *) addr, addr_len);
    if (subreq == NULL) {
        ret = ENOMEM;
        DEBUG(1, ("sdap_async_sys_connect_send failed.\n"));
        goto fail;
    }

    tevent_req_set_callback(subreq, sss_ldap_init_sys_connect_done, req);
    return req;

fail:
    close(state->sd);
    tevent_req_error(req, ret);
#else
    DEBUG(3, ("ldap_init_fd not available, "
              "will use ldap_initialize with uri [%s].\n", uri));
    state->sd = -1;
    ret = ldap_initialize(&state->ldap, uri);
    if (ret == LDAP_SUCCESS) {
        tevent_req_done(req);
    } else {
        DEBUG(1, ("ldap_initialize failed [%s].\n", sss_ldap_err2string(ret)));
        if (ret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
    }
#endif

    tevent_req_post(req, ev);
    return req;
}

#ifdef HAVE_LDAP_INIT_FD
static void sss_ldap_init_sys_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sss_ldap_init_state *state = tevent_req_data(req,
                                                    struct sss_ldap_init_state);
    int ret;
    int lret;

    ret = sdap_async_sys_connect_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("sdap_async_sys_connect request failed.\n"));
        close(state->sd);
        tevent_req_error(req, ret);
        return;
    }
    /* Initialize LDAP handler */

    lret = ldap_init_fd(state->sd, LDAP_PROTO_TCP, state->uri, &state->ldap);
    if (lret != LDAP_SUCCESS) {
        DEBUG(1, ("ldap_init_fd failed: %s\n", sss_ldap_err2string(lret)));
        close(state->sd);
        if (lret == LDAP_SERVER_DOWN) {
            tevent_req_error(req, ETIMEDOUT);
        } else {
            tevent_req_error(req, EIO);
        }
        return;
    }

    if (ldap_is_ldaps_url(state->uri)) {
        lret = ldap_install_tls(state->ldap);
        if (lret != LDAP_SUCCESS) {
            if (lret == LDAP_LOCAL_ERROR) {
                DEBUG(5, ("TLS/SSL already in place.\n"));
            } else {
                DEBUG(1, ("ldap_install_tls failed: %s\n",
                          sss_ldap_err2string(lret)));

                tevent_req_error(req, EIO);
                return;
            }
        }
    }

    tevent_req_done(req);
    return;
}
#endif

int sss_ldap_init_recv(struct tevent_req *req, LDAP **ldap, int *sd)
{
    struct sss_ldap_init_state *state = tevent_req_data(req,
                                                    struct sss_ldap_init_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *ldap = state->ldap;
    *sd = state->sd;

    return EOK;
}
