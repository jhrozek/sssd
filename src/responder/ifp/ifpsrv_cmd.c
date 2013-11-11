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

#include "db/sysdb.h"

#include "responder/ifp/ifp_private.h"
#include "responder/common/responder_cache.h"

struct infp_attr_req {
    const char *user;
    const char **attrs;

    struct infp_req *ireq;
};

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       const char *inp, const char **attrs);
static errno_t ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct ldb_result **_res);

static void infp_user_get_attr_process(struct tevent_req *req);

static errno_t
infp_user_get_attr_reply(struct infp_req *ireq, const char *user,
                         const char **attrs, struct ldb_result *res);
static errno_t
infp_user_get_attr_unpack_msg(struct infp_attr_req *attr_req,
                              DBusMessage *message,
                              DBusError *error);

int infp_user_get_attr(DBusMessage *message, struct sbus_connection *conn)
{
    errno_t ret;
    DBusError error;
    struct infp_req *ireq;
    struct ifp_ctx *ifp_ctx;
    struct infp_attr_req *attr_req;
    struct tevent_req *req;

    ifp_ctx = talloc_get_type(sbus_conn_get_private_data(conn),
                              struct ifp_ctx);
    if (ifp_ctx == NULL || ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Bad private pointer\n"));
        return EFAULT;
    }

    ireq = infp_req_create(conn, message, conn);
    if (ireq == NULL) {
        return EIO;
    }

    attr_req = talloc_zero(ireq, struct infp_attr_req);
    if (attr_req == NULL) {
        infp_enomem(ireq);
        ret = ENOMEM;
        goto fail;
    }
    attr_req->ireq = ireq;

    dbus_error_init(&error);
    ret = infp_user_get_attr_unpack_msg(attr_req, message, &error);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Parsing arguments to %s failed: %s:%s\n",
              INFP_USER_GET_ATTR, error.name, error.message));
        ret = infp_invalid_args(ireq, &error);
        goto fail;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          ("Looking up attributes of user [%s] on behalf of %"SPRIuid"\n",
           attr_req->user, ireq->caller));


    req = ifp_user_get_attr_send(ireq, ifp_ctx->rctx,
                                 attr_req->user, attr_req->attrs);
    if (req == NULL) {
        infp_enomem(ireq);
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, infp_user_get_attr_process, attr_req);
    return EOK;

fail:
    talloc_free(ireq);
    return ret;
}

static errno_t
infp_user_get_attr_unpack_msg(struct infp_attr_req *attr_req,
                              DBusMessage *message,
                              DBusError *error)
{
    dbus_bool_t dbret;
    char **attrs;
    int nattrs;
    int i;
    errno_t ret;

    dbret = dbus_message_get_args(message, error,
                                  DBUS_TYPE_STRING, &attr_req->user,
                                  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                                  &attrs, &nattrs,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        return EIO;
    }

    /* Copy the attributes to maintain memory hierarchy with talloc */
    attr_req->attrs = talloc_zero_array(attr_req, const char *, nattrs + 1);
    if (attr_req->attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < nattrs; i++) {
        attr_req->attrs[i] = talloc_strdup(attr_req->attrs, attrs[i]);
        if (attr_req->attrs[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
done:
    dbus_free_string_array(attrs);
    return EOK;
}

static void infp_user_get_attr_process(struct tevent_req *req)
{
    struct infp_attr_req *attr_req;
    errno_t ret;
    struct ldb_result *res;

    attr_req = tevent_req_callback_data(req, struct infp_attr_req);

    ret = ifp_user_get_attr_recv(attr_req, req, &res);
    talloc_zfree(req);
    if (ret == ENOENT) {
        infp_return_failure(attr_req->ireq, "No such user\n");
        return;
    } else if (ret != EOK) {
        infp_return_failure(attr_req->ireq, "Failed to read user attribute\n");
        return;
    }

    ret = infp_user_get_attr_reply(attr_req->ireq, attr_req->user,
                                   attr_req->attrs, res);
    if (ret != EOK) {
        infp_return_failure(attr_req->ireq, "Failed to construct a reply\n");
        return;
    }
}

static errno_t
infp_user_get_attr_reply(struct infp_req *ireq, const char *user,
                         const char **attrs, struct ldb_result *res)
{
    errno_t ret;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;
    struct ldb_message_element *el;
    int ai;

    /* Construct a reply */
    dbus_message_iter_init_append(ireq->reply, &iter);

    dbret = dbus_message_iter_open_container(
                                      &iter, DBUS_TYPE_ARRAY,
                                      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                      DBUS_TYPE_STRING_AS_STRING
                                      DBUS_TYPE_VARIANT_AS_STRING
                                      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                      &iter_dict);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    for (ai = 0; attrs[ai]; ai++) {
        el = ldb_msg_find_element(res->msgs[0], attrs[ai]);
        if (el == NULL || el->num_values == 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Attribute %s not present or has no values\n", attrs[ai]));
            continue;
        }

        ret = infp_add_ldb_el_to_dict(&iter_dict, el);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Cannot add attribute %s to message\n", attrs[ai]));
            continue;
        }
    }

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    sbus_conn_send_reply(ireq->conn, ireq->reply);

done:
    talloc_free(ireq);
    return ret;
}

struct ifp_user_get_attr_state {
    const char *inp;
    const char **attrs;

    char *name;
    char *domname;
    struct cache_req *creq;

    struct resp_ctx *rctx;
};

static void ifp_user_get_attr_dom(struct tevent_req *subreq);
static errno_t
ifp_user_get_attr_search(struct cache_req *creq,
                         const char **attrs,
                         struct tevent_req *req);

static struct tevent_req *
ifp_user_get_attr_send(TALLOC_CTX *mem_ctx, struct resp_ctx *rctx,
                       const char *inp, const char **attrs)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ifp_user_get_attr_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ifp_user_get_attr_state);
    if (req == NULL) {
         return NULL;
    }
    state->inp = inp;
    state->attrs = attrs;
    state->rctx = rctx;

    subreq = sss_parse_inp_send(req, rctx, inp);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ifp_user_get_attr_dom, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
    return req;
}

static void
ifp_user_get_attr_dom(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);

    ret = sss_parse_inp_recv(subreq, state, &state->name, &state->domname);
    talloc_free(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->creq = cache_req_new(state, state->rctx, state->domname);
    if (state->creq == NULL) {
        /* FIXME - change to ERR_UKNOWN_DOMAIN */
        tevent_req_error(req, ENOMEM);
        return;
    }

    /* This is search specific and needs to be wrapped up */
    state->creq->inp.str = state->name;

    /* All set up, do the search! */
    ret = ifp_user_get_attr_search(state->creq, state->attrs, req);
    if (ret == EOK) {
        /* The data was cached. Just quit */
        tevent_req_done(req);
        return;
    }

    /* Execution will resume in ifp_dp_callback */
}

static void ifp_dp_callback(uint16_t err_maj, uint32_t err_min,
                            const char *err_msg, void *ptr);

static errno_t
ifp_user_get_attr_search(struct cache_req *creq,
                         const char **attrs,
                         struct tevent_req *req)
{
    struct sss_domain_info *dom = creq->domain;
    char *name = NULL;
    errno_t ret;

    while (dom) {
       /* if it is a domainless search, skip domains that require fully
        * qualified names instead */
        while (dom && creq->check_next && dom->fqnames) {
            dom = get_next_domain(dom, false);
        }

        if (!dom) break;

        if (dom != creq->domain) {
            /* make sure we reset the check_provider flag when we check
             * a new domain */
            creq->check_provider = NEED_CHECK_PROVIDER(dom->provider);
        }

        /* make sure to update the cache_req if we changed domain */
        creq->domain = dom;

        talloc_free(name);
        name = sss_get_cased_name(creq, creq->inp.str, dom->case_sensitive);
        if (!name) return ENOMEM;

        /* verify this user has not yet been negatively cached,
        * or has been permanently filtered */
        ret = sss_ncache_check_user(creq->nctx,
                                    1, /* FIXME */
                                    dom, name);
        /* if neg cached, return we didn't find it */
        if (ret == EEXIST) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  ("User [%s] does not exist in [%s]! (negative cache)\n",
                   name, dom->name));
            /* if a multidomain search, try with next */
            if (creq->check_next) {
                dom = get_next_domain(dom, false);
                continue;
            }

            /* There are no further domains or this was a
             * fully-qualified user request.
             */
            return ENOENT;
        }

        DEBUG(SSSDBG_FUNC_DATA,
              ("Requesting info for [%s@%s]\n", name, dom->name));

        ret = sysdb_get_user_attr(creq, dom, name, attrs, &creq->res);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                   ("Failed to make request to our cache!\n"));
            return EIO;
        }

        if (creq->res->count > 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("getpwnam call returned more than one result !?!\n"));
            return ENOENT;
        }

        if (creq->res->count == 0 && creq->check_provider == false) {
            /* set negative cache only if not result of cache check */
            ret = sss_ncache_set_user(creq->nctx, false, dom, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, ("Cannot set negcache for %s@%s\n",
                      name, dom->name));
                /* Not fatal */
            }

            /* if a multidomain search, try with next */
            if (creq->check_next) {
                dom = get_next_domain(dom, false);
                if (dom) continue;
            }

            DEBUG(SSSDBG_TRACE_FUNC, ("No results for getpwnam call\n"));
            return ENOENT;
        }

        /* if this is a caching provider (or if we haven't checked the cache
         * yet) then verify that the cache is uptodate */
        if (creq->check_provider) {
            ret = cache_req_check(creq, creq->res, SSS_DP_USER,
                                  ifp_dp_callback, 0, req);
            if (ret != EOK) {
                /* Anything but EOK means we should reenter the mainloop
                 * because we may be refreshing the cache
                 */
                return ret;
            }
        }

        /* One result found */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Returning info for user [%s@%s]\n", name, dom->name));
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE,
          ("No matching domain found for [%s], fail!\n", creq->inp.str));
    return ENOENT;
}

static void ifp_dp_callback(uint16_t err_maj, uint32_t err_min,
                            const char *err_msg, void *ptr)
{
    errno_t ret;
    struct tevent_req *req = talloc_get_type(ptr, struct tevent_req);
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);

    if (err_maj) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    /* Backend was updated successfully. Check again */
    ret = ifp_user_get_attr_search(state->creq, state->attrs, req);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
ifp_user_get_attr_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ldb_result **_res)
{
    struct ifp_user_get_attr_state *state = tevent_req_data(req,
                                            struct ifp_user_get_attr_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->creq == NULL) {
        /* Did the request end with success but with no data? */
        return ENOENT;
    }

    if (_res) {
        *_res = talloc_steal(mem_ctx, state->creq->res);
    }
    return EOK;
}

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

