/*
    SSSD

    ipa_dyndns.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <ctype.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/child_common.h"
#include "providers/data_provider.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "resolv/async_resolv.h"

#define IPA_DYNDNS_TIMEOUT 15

struct ipa_ipaddress {
    struct ipa_ipaddress *next;
    struct ipa_ipaddress *prev;

    struct sockaddr *addr;
    bool matched;
};

struct ipa_dyndns_ctx {
    struct ipa_options *ipa_ctx;
    struct sdap_id_op* sdap_op;
    char *hostname;
    struct ipa_ipaddress *addresses;
    bool use_server_with_nsupdate;
};


static struct tevent_req * ipa_dyndns_update_send(struct ipa_options *ctx);

static void ipa_dyndns_update_done(struct tevent_req *req);

void ipa_dyndns_update(void *pvt)
{
    struct ipa_options *ctx = talloc_get_type(pvt, struct ipa_options);
    struct tevent_req *req = ipa_dyndns_update_send(ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not update DNS\n"));
        return;
    }
    tevent_req_set_callback(req, ipa_dyndns_update_done, req);
}

static void ipa_dyndns_sdap_connect_done(struct tevent_req *subreq);
static int ipa_dyndns_add_ldap_iface(struct ipa_dyndns_ctx *state,
                                     struct sdap_handle *sh);
static int ipa_dyndns_gss_tsig_update_step(struct tevent_req *req);

static struct tevent_req *
ipa_dyndns_gss_tsig_update_send(struct ipa_dyndns_ctx *ctx);

static void ipa_dyndns_gss_tsig_update_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_update_send(struct ipa_options *ctx)
{
    int ret;
    char *iface;
    struct ipa_dyndns_ctx *state;
    struct ifaddrs *ifaces;
    struct ifaddrs *ifa;
    struct ipa_ipaddress *address;
    struct tevent_req *req, *subreq;

    DEBUG (9, ("Performing update\n"));

    req = tevent_req_create(ctx, &state, struct ipa_dyndns_ctx);
    if (req == NULL) {
        return NULL;
    }
    state->ipa_ctx = ctx;
    state->use_server_with_nsupdate = false;

    iface = dp_opt_get_string(ctx->basic, IPA_DYNDNS_IFACE);

    if (iface) {
        /* Get the IP addresses associated with the
         * specified interface
         */
        errno = 0;
        ret = getifaddrs(&ifaces);
        if (ret == -1) {
            ret = errno;
            DEBUG(0, ("Could not read interfaces [%d][%s]\n",
                      ret, strerror(ret)));
            goto failed;
        }

        for(ifa = ifaces; ifa != NULL; ifa=ifa->ifa_next) {
            /* Some interfaces don't have an ifa_addr */
            if (!ifa->ifa_addr) continue;

            /* Add IP addresses to the list */
            if((ifa->ifa_addr->sa_family == AF_INET ||
                ifa->ifa_addr->sa_family == AF_INET6) &&
               strcasecmp(ifa->ifa_name, iface) == 0) {
                /* Add this address to the IP address list */
                address = talloc_zero(state, struct ipa_ipaddress);
                if (!address) {
                    goto failed;
                }

                address->addr = talloc_memdup(address, ifa->ifa_addr,
                                              sizeof(struct sockaddr));
                if(address->addr == NULL) {
                    goto failed;
                }
                DLIST_ADD(state->addresses, address);
            }
        }

        freeifaddrs(ifaces);

        ret = ipa_dyndns_gss_tsig_update_step(req);
        if (ret != EOK) {
            goto failed;
        }
    }

    else {
        /* Detect DYNDNS interface from LDAP connection */
        state->sdap_op = sdap_id_op_create(state, state->ipa_ctx->id_ctx->conn_cache);
        if (!state->sdap_op) {
            DEBUG(1, ("sdap_id_op_create failed\n"));
            ret = ENOMEM;
            goto failed;
        }

        subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
        if (!subreq) {
            DEBUG(1, ("sdap_id_op_connect_send failed: [%d](%s)\n",
                ret, strerror(ret)));

            goto failed;
        }

        tevent_req_set_callback(subreq, ipa_dyndns_sdap_connect_done, req);
    }

    return req;

failed:
    talloc_free(req);
    return NULL;
}

static void ipa_dyndns_sdap_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(9,("No LDAP server is available, dynamic DNS update is skipped in OFFLINE mode.\n"));
        } else {
            DEBUG(9,("Failed to connect to LDAP server: [%d](%s)\n",
                ret, strerror(ret)));
        }

        goto failed;
    }

    ret = ipa_dyndns_add_ldap_iface(state, sdap_id_op_handle(state->sdap_op));
    talloc_zfree(state->sdap_op);
    if (ret != EOK) {
        goto failed;
    }

    ret = ipa_dyndns_gss_tsig_update_step(req);
    if (ret != EOK) {
        goto failed;
    }

    return;

failed:
    tevent_req_error(req, ret);
}

static int ipa_dyndns_add_ldap_iface(struct ipa_dyndns_ctx *state,
                                     struct sdap_handle *sh)
{
    int ret;
    int fd;
    struct ipa_ipaddress *address;
    struct sockaddr sa;
    socklen_t sa_len = sizeof(sa);

    if (!sh) {
        return EINVAL;
    }

    /* Get the file descriptor for the primary LDAP connection */
    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret != EOK) {
        return ret;
    }

    ret = getsockname(fd, &sa, &sa_len);
    if (ret == -1) {
        DEBUG(0,("Failed to get socket name\n"));
        return errno;
    }

    switch(sa.sa_family) {
    case AF_INET:
    case AF_INET6:
        address = talloc(state, struct ipa_ipaddress);
        if (!address) {
            return ENOMEM;
        }
        address->addr = talloc_memdup(address, &sa,
                                      sizeof(struct sockaddr));
        if(address->addr == NULL) {
            talloc_zfree(address);
            return ENOMEM;
        }
        DLIST_ADD(state->addresses, address);
        break;
    default:
        DEBUG(1, ("Connection to LDAP is neither IPv4 nor IPv6\n"));
        return EIO;
    }

    return EOK;
}

static int ipa_dyndns_gss_tsig_update_step(struct tevent_req *req)
{
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);
    char *ipa_hostname;
    struct tevent_req *subreq;

    /* Get the IPA hostname */
    ipa_hostname = dp_opt_get_string(state->ipa_ctx->basic,
                                     IPA_HOSTNAME);
    if (!ipa_hostname) {
        /* This should never happen, but we'll protect
         * against it anyway.
         */
        return EINVAL;
    }

    state->hostname = talloc_strdup(state, ipa_hostname);
    if(state->hostname == NULL) {
        return ENOMEM;
    }

    /* In the future, it might be best to check that an update
     * needs to be run before running it, but this is such a
     * rare event that it's probably fine to just run an update
     * every time we come online.
     */
    subreq = ipa_dyndns_gss_tsig_update_send(state);
    if(subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq,
                            ipa_dyndns_gss_tsig_update_done,
                            req);
    return EOK;
}

struct ipa_nsupdate_ctx {
    char *update_msg;
    struct ipa_dyndns_ctx *dyndns_ctx;
    int pipefd_to_child;
    struct tevent_timer *timeout_handler;
    int child_status;
};


static int create_nsupdate_message(struct ipa_nsupdate_ctx *ctx,
                                   bool use_server_with_nsupdate);

static struct tevent_req *
fork_nsupdate_send(struct ipa_nsupdate_ctx *ctx);

static void fork_nsupdate_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_gss_tsig_update_send(struct ipa_dyndns_ctx *ctx)
{
    int ret;
    struct ipa_nsupdate_ctx *state;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(ctx, &state, struct ipa_nsupdate_ctx);
    if(req == NULL) {
        return NULL;
    }
    state->dyndns_ctx = ctx;
    state->child_status = 0;

    /* Format the message to pass to the nsupdate command */
    ret = create_nsupdate_message(state, ctx->use_server_with_nsupdate);
    if (ret != EOK) {
        goto failed;
    }

    /* Fork a child process to perform the DNS update */
    subreq = fork_nsupdate_send(state);
    if(subreq == NULL) {
        goto failed;
    }
    tevent_req_set_callback(subreq, fork_nsupdate_done, req);

    return req;

failed:
    talloc_free(req);
    return NULL;
}

struct nsupdate_send_ctx {
    struct ipa_nsupdate_ctx *nsupdate_ctx;
    int child_status;
};

static int create_nsupdate_message(struct ipa_nsupdate_ctx *ctx,
                                   bool use_server_with_nsupdate)
{
    int ret, i;
    char *servername = NULL;
    char *realm;
    char *zone;
    char ip_addr[INET6_ADDRSTRLEN];
    const char *ip;
    struct ipa_ipaddress *new_record;

    realm = dp_opt_get_string(ctx->dyndns_ctx->ipa_ctx->basic, IPA_KRB5_REALM);
    if (!realm) {
        return EIO;
    }

    zone = dp_opt_get_string(ctx->dyndns_ctx->ipa_ctx->basic,
                             IPA_DOMAIN);
    if (!zone) {
        return EIO;
    }

    /* The DNS zone for IPA is the lower-case
     * version of hte IPA domain
     */
    for(i = 0; zone[i] != '\0'; i++) {
        zone[i] = tolower(zone[i]);
    }

    if (use_server_with_nsupdate) {
        if (strncmp(ctx->dyndns_ctx->ipa_ctx->service->sdap->uri,
                    "ldap://", 7) != 0) {
            DEBUG(1, ("Unexpected format of LDAP URI.\n"));
            return EIO;
        }
        servername = ctx->dyndns_ctx->ipa_ctx->service->sdap->uri + 7;
        if (!servername) {
            return EIO;
        }

        DEBUG(9, ("Creating update message for server [%s], realm [%s] "
                  "and zone [%s].\n", servername, realm, zone));

        /* Add the server, realm and zone headers */
        ctx->update_msg = talloc_asprintf(ctx, "server %s\nrealm %s\nzone %s.\n",
                                               servername, realm, zone);
    } else {
        DEBUG(9, ("Creating update message for realm [%s] and zone [%s].\n",
                  realm, zone));

        /* Add the realm and zone headers */
        ctx->update_msg = talloc_asprintf(ctx, "realm %s\nzone %s.\n",
                                               realm, zone);
    }
    if (ctx->update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Remove any existing entries */
    ctx->update_msg = talloc_asprintf_append(ctx->update_msg,
                                             "update delete %s. in A\nsend\n"
                                             "update delete %s. in AAAA\nsend\n",
                                             ctx->dyndns_ctx->hostname,
                                             ctx->dyndns_ctx->hostname);
    if (ctx->update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DLIST_FOR_EACH(new_record, ctx->dyndns_ctx->addresses) {
        switch(new_record->addr->sa_family) {
        case AF_INET:
            ip = inet_ntop(new_record->addr->sa_family,
                           &(((struct sockaddr_in *)new_record->addr)->sin_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = EIO;
                goto done;
            }
            break;

        case AF_INET6:
            ip = inet_ntop(new_record->addr->sa_family,
                           &(((struct sockaddr_in6 *)new_record->addr)->sin6_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = EIO;
                goto done;
            }
            break;

        default:
            DEBUG(0, ("Unknown address family\n"));
            ret = EIO;
            goto done;
        }

        /* Format the record update */
        ctx->update_msg = talloc_asprintf_append(
                ctx->update_msg,
                "update add %s. 86400 in %s %s\n",
                ctx->dyndns_ctx->hostname,
                new_record->addr->sa_family == AF_INET ? "A" : "AAAA",
                ip_addr);
        if (ctx->update_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ctx->update_msg = talloc_asprintf_append(ctx->update_msg, "send\n");
    if (ctx->update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

static void ipa_dyndns_stdin_done(struct tevent_req *subreq);

static void ipa_dyndns_child_handler(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt);

static void ipa_dyndns_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt);

static struct tevent_req *
fork_nsupdate_send(struct ipa_nsupdate_ctx *ctx)
{
    int pipefd_to_child[2];
    pid_t pid;
    int ret;
    errno_t err;
    struct timeval tv;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct nsupdate_send_ctx *state;
    char *args[3];

    req = tevent_req_create(ctx, &state, struct nsupdate_send_ctx);
    if (req == NULL) {
        return NULL;
    }
    state->nsupdate_ctx = ctx;
    state->child_status = 0;

    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", err, strerror(err)));
        return NULL;
    }

    pid = fork();

    if (pid == 0) { /* child */
        args[0] = talloc_strdup(ctx, NSUPDATE_PATH);
        args[1] = talloc_strdup(ctx, "-g");
        args[2] = NULL;
        if (args[0] == NULL || args[1] == NULL) {
            return NULL;
        }

        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
            return NULL;
        }

        errno = 0;
        ret = execv(NSUPDATE_PATH, args);
        if(ret == -1) {
            err = errno;
            DEBUG(1, ("execv failed [%d][%s].\n", err, strerror(err)));
        }
        return NULL;
    }

    else if (pid > 0) { /* parent */
        close(pipefd_to_child[0]);

        ctx->pipefd_to_child = pipefd_to_child[1];

        /* Write the update message to the nsupdate child */
        subreq = write_pipe_send(req,
                                 ctx->dyndns_ctx->ipa_ctx->id_ctx->be->ev,
                                 (uint8_t *)ctx->update_msg,
                                 strlen(ctx->update_msg)+1,
                                 ctx->pipefd_to_child);
        if (subreq == NULL) {
            return NULL;
        }
        tevent_req_set_callback(subreq, ipa_dyndns_stdin_done, req);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ctx->dyndns_ctx->ipa_ctx->id_ctx->be->ev,
                                  pid, ipa_dyndns_child_handler, req);
        if (ret != EOK) {
            return NULL;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(IPA_DYNDNS_TIMEOUT, 0);
        ctx->timeout_handler = tevent_add_timer(
                ctx->dyndns_ctx->ipa_ctx->id_ctx->be->ev,
                req, tv, ipa_dyndns_timeout, req);
        if(ctx->timeout_handler == NULL) {
            return NULL;
        }
    }

    else { /* error */
        err = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", err, strerror(err)));
        return NULL;
    }

    return req;
}

static void ipa_dyndns_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct tevent_req *req =
            talloc_get_type(pvt, struct tevent_req);

    DEBUG(1, ("Timeout reached for dynamic DNS update\n"));

    tevent_req_error(req, ETIMEDOUT);
}

static void ipa_dyndns_stdin_done(struct tevent_req *subreq)
{
    /* Verify that the buffer was sent, then return
     * and wait for the sigchld handler to finish.
     */
    DEBUG(9, ("Sending nsupdate data complete\n"));

    int ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Sending nsupdate data failed\n"));
        tevent_req_error(req, ret);
        return;
    }

    close(state->nsupdate_ctx->pipefd_to_child);
    state->nsupdate_ctx->pipefd_to_child = -1;
}

static void ipa_dyndns_child_handler(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    state->child_status = child_status;

    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        DEBUG(1, ("Dynamic DNS child failed with status [%d]\n",
                  child_status));
        tevent_req_error(req, EIO);
        return;
    }

    if WIFSIGNALED(child_status) {
        DEBUG(1, ("Dynamic DNS child was terminated by signal [%d]\n",
                  WTERMSIG(child_status)));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

static int ipa_dyndns_child_recv(struct tevent_req *req, int *child_status)
{
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static int ipa_dyndns_generic_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void fork_nsupdate_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_nsupdate_ctx *state = tevent_req_data(req,
                                                     struct ipa_nsupdate_ctx);

    ret = ipa_dyndns_child_recv(subreq, &state->child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int fork_nsupdate_recv(struct tevent_req *req, int *child_status)
{
    struct ipa_nsupdate_ctx *state =
            tevent_req_data(req, struct ipa_nsupdate_ctx);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void ipa_dyndns_gss_tsig_update_done(struct tevent_req *subreq)
{
    /* Check the return code from the sigchld handler
     * and return it to the parent request.
     */
    int ret;
    int child_status;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);

    ret = fork_nsupdate_recv(subreq, &child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (state->use_server_with_nsupdate == false &&
            WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
            DEBUG(9, ("nsupdate failed, retrying with server name.\n"));
            state->use_server_with_nsupdate = true;
            ret = ipa_dyndns_gss_tsig_update_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        } else {
            tevent_req_error(req, ret);
            return;
        }
    }

    tevent_req_done(req);
}

static void ipa_dyndns_update_done(struct tevent_req *req)
{
    int ret = ipa_dyndns_generic_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(1, ("Updating DNS entry failed\n"));
        return;
    }

    DEBUG(1,("Updated DNS entry\n"));
}
