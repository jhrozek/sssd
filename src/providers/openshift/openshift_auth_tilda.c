/*
    SSSD

    openshift_auth.c - OpenShift provider authentication using the tilda
                       API

    Copyright (C) 2019 Red Hat

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

#include <security/pam_modules.h>
#include <jansson.h>

#include "providers/data_provider/dp.h"
#include "providers/data_provider.h"
#include "util/tev_curl.h"
#include "providers/openshift/openshift_private.h"
#include "providers/openshift/openshift_opts.h"

#define TILDA_API_ENDPOINT  "/apis/user.openshift.io/v1/users/~"
#define TILDA_API_TIMEOUT   5 /* FIXME: Configurable? Is this a good default? */

static void ocp_user_debug(struct ocp_user_info *user)
{
    if (user == NULL) {
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA, "name: %s\n", user->name);
    for (size_t i = 0; i < user->ngroups - 1; i++) {
        DEBUG(SSSDBG_FUNC_DATA, "group: %s\n", user->groups[i]);
    }
}

/* OK, this is just temporary until jhrozek understands the tokenReview
 * and tilda output. Given a fullname as either bar or foo:bar, returns the part
 * after the colon or if the colon is absent, the full name
 */
static const char *parse_name(const char *fullname)
{
    const char *delim;
    delim = strchr(fullname, ':');

    return delim ? delim + 1 : fullname;
}

/*
 * The identities object looks like this:
 *
 *          ["my_htpasswd_provider:tuser"],
 *          "groups":["somegroup","system:authenticated","system:authenticated:oauth"]
 *
 * This function parses the object into a ocp_user_info structure.
 */
static errno_t parse_tilda_identities(TALLOC_CTX *mem_ctx,
                                      const char *username,
                                      json_t *jidentities,
                                      json_t *jgroups,
                                      struct ocp_user_info **_user_info)
{
    errno_t ret;
    const char *raw_name;
    struct ocp_user_info *user_info;
    size_t grp_index;
    size_t n_ids;
    json_t *grp;

    user_info = talloc_zero(mem_ctx, struct ocp_user_info);
    if (user_info == NULL) {
        return ENOMEM;
    }

    n_ids = json_array_size(jidentities);
    if (n_ids != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Expected one identity, got %zu\n", n_ids);
        ret = EINVAL;
        goto done;
    }

    raw_name = json_string_value(json_array_get(jidentities, 0));
    if (raw_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot parse name\n");
        ret = EINVAL;
        goto done;
    }

    user_info->name = talloc_strdup(user_info, parse_name(raw_name));
    if (user_info->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* FIXME: compare against the passed in username and fail earlier?
     *
     * The generic auth handler does it as well, so it's not a security
     * risk and we won't allow a user who does not match
     */

    user_info->groups = talloc_zero_array(user_info,
                                          const char *,
                                          json_array_size(jgroups) + 1);
    if (user_info->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(jgroups, grp_index, grp) {
        /* FIXME: skip system groups? */
        user_info->groups[grp_index] = talloc_strdup(user_info->groups,
                                                     parse_name(json_string_value(grp)));
        if (user_info->groups[grp_index] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    user_info->ngroups = json_array_size(jgroups);

    ret = EOK;
    *_user_info = user_info;
done:
    if (ret != EOK) {
        talloc_free(user_info);
    }
    return ret;
}
/*
 * Turns a raw sss_iobuf reply from the tilda API into an ocp_user_info
 * structure if possible or fail trying.
 *
 * API reference:
 * https://docs.okd.io/latest/rest_api/apis-user.openshift.io/v1.User.html
 *
 * Example tilda API reply:
 *  {"kind":"User",
 *   "apiVersion":"user.openshift.io/v1",
 *   "metadata":
 *          {"name":"tuser",
 *           "selfLink":"/apis/user.openshift.io/v1/users/tuser",
 *           "uid":"c8b1e002-d39d-11e9-b899-0a580a810025",
 *           "resourceVersion":"300112",
 *           "creationTimestamp":"2019-09-10T07:37:04Z"},
 *   "identities":
 *          ["my_htpasswd_provider:tuser"],
 *          "groups":["somegroup","system:authenticated","system:authenticated:oauth"]
 *  }
 *
 * This function parses the object into a ocp_user_info structure.
 */
static errno_t parse_tilda_reply(TALLOC_CTX *mem_ctx,
                                 const char *username,
                                 struct sss_iobuf *reply,
                                 struct ocp_user_info **_user_info)
{
    json_t *jreply = NULL;
    json_error_t error;
    int ok;
    errno_t ret;
    const char *kind = NULL;
    const char *api_version = NULL;
    json_t *metadata = NULL;
    json_t *identities = NULL;
    json_t *groups = NULL;

    /* Does reply contain valid JSON? */
    jreply = json_loadb((const char *) sss_iobuf_get_data(reply),
                        sss_iobuf_get_len(reply),
                        0,
                        &error);
    if (jreply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse JSON payload on line %d: %s\n",
              error.line, error.text);
        return ERR_JSON_DECODING;
    }

    /* Is the JSON a valid object? */
    ok = json_is_object(jreply);
    if (!ok) {
        DEBUG(SSSDBG_CRIT_FAILURE, "reply is not a json object\n");
        json_decref(jreply);
        return ERR_JSON_DECODING;
    }

    /* Does the object match the expected output? */
    ret = json_unpack_ex(jreply,
                         &error,
                         JSON_STRICT,
                         "{s:s, s:s, s:o, s:o, s:o}",
                         "kind", &kind,
                         "apiVersion", &api_version,
                         "metadata", &metadata,
                         "identities", &identities,
                         "groups", &groups);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        ret = ERR_JSON_DECODING;
        goto done;
    }

    if (kind == NULL
            || strcasecmp(kind, "User") != 0) {
        ret = ERR_JSON_DECODING;
        goto done;
    }

    if (api_version == NULL
            || strcasecmp(api_version, "user.openshift.io/v1") != 0) {
        ret = ERR_JSON_DECODING;
        goto done;
    }

    /* FIXME: Some sanity check? Username length check, group array size check etc? */
    /* FIXME: Use the authenticated flag? */

    /* OK, the entry parses, let's construct the user_info structure */
    ret = parse_tilda_identities(mem_ctx, username, identities, groups, _user_info);
done:
    if (jreply != NULL) {
        json_decref(jreply);
    }
    return ret;
}

/*
 *  The API description can be found at:
 *      https://docs.okd.io/latest/rest_api/apis-user.openshift.io/v1.User.html
 *
 *  The authentication itself works by sending a GET request for the
 *  "~" object at the /apis/user.openshift.io/v1/users/~ endpoint with the OAuth
 *  token that was passed as a password through the PAM stack.
 *
 *  The token is used in the Authorization header.
 */
static struct tcurl_request *
tilda_api_req_create(TALLOC_CTX *mem_ctx,
                     const char *api_server,
                     struct sss_auth_token *token)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct tcurl_request *tcurl_req;
    const char **headers;
    const char *raw_token;
    const char *url;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return NULL;
    }

    ret = sss_authtok_get_password(token, &raw_token, NULL);
    if (ret != EOK) {
        goto fail;
    }

    headers = talloc_zero_array(tmp_ctx, const char *, 3);
    if (headers == NULL) {
        goto fail;
    }
    headers[0] = talloc_asprintf(headers, "Authorization: Bearer %s", raw_token);
    headers[1] = talloc_strdup(headers, "Content-Type: application/json; charset=utf-8");
    if (headers[0] == NULL || headers[1] == NULL) {
        goto fail;
    }

    url = talloc_asprintf(tmp_ctx, "%s"TILDA_API_ENDPOINT, api_server);
    if (url == NULL) {
        goto fail;
    }

    tcurl_req = tcurl_http(tmp_ctx, TCURL_HTTP_GET, NULL, url, headers, NULL);
    if (tcurl_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create TCURL request!\n");
        goto fail;
    }

    tcurl_req = talloc_steal(mem_ctx, tcurl_req);
    talloc_free(tmp_ctx);
    return tcurl_req;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}

struct tilda_auth_state {
    const char *username;
    struct ocp_user_info *user_info;
};

static void tilda_auth_done(struct tevent_req *subreq);

/*
 * Validate the OAuth token passed as sss_auth_token against the
 * /apis/user.openshift.io/v1/users/~ API endpoint of
 * api_server_url
 *
 * If the endpoint replies with anything than HTTP 2xx, fail and return
 * a SSSD specific error code.
 *
 * Otherwise try to parse out the JSON object in the reply and construct
 * a user_info structure that can be returned to the caller in _recv.
 */
struct tevent_req *
tilda_auth_send(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct tcurl_ctx *tc_ctx,
                const char *username,
                const char *api_server_url,
                struct sss_auth_token *token)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct tilda_auth_state *state = NULL;
    struct tcurl_request *tilda_api_req;

    req = tevent_req_create(mem_ctx, &state, struct tilda_auth_state);
    if (req == NULL) {
        return NULL;
    }
    state->username = username;

    DEBUG(SSSDBG_FUNC_DATA, "Would try to contact %s\n", api_server_url);

    tilda_api_req = tilda_api_req_create(state, api_server_url, token);
    if (tilda_api_req == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /* FIXME: This just unconditionally turns off all TLS checks... */
    tcurl_req_verify_peer(tilda_api_req, NULL, NULL, false, false);

    subreq = tcurl_request_send(state, ev, tc_ctx,
                                tilda_api_req,
                                TILDA_API_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, tilda_auth_done, req);
    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static void tilda_auth_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tilda_auth_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sss_iobuf *response = NULL;
    int http_code;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct tilda_auth_state);

    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "tilda API call failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "tilda finished with http code %d\n", http_code);

    /* FIXME: We might opt to parse the reply in a nicer fashion later on ... */
    if (debug_level & SSSDBG_TRACE_ALL || http_code > 200) {
        const uint8_t *reply = sss_iobuf_get_data(response);
        DEBUG(http_code > 200 ? SSSDBG_TRACE_FUNC : SSSDBG_TRACE_ALL,
              "Reply: %s\n",
              (const char *) reply);
    }

    /* Map HTTP error codes to SSSD error codes */
    switch (http_code) {
    case 201:
    case 200:
        DEBUG(SSSDBG_FUNC_DATA, "Authenticated\n");
        break;
    case 401:
        ret = ERR_AUTH_DENIED;
        break;
    case 403:
        ret = ERR_ACCESS_DENIED;
        break;
    case 408:
        ret = ETIMEDOUT;
        break;
    default:
        ret = ERR_AUTH_FAILED;
        break;
    }

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    ret = parse_tilda_reply(state, state->username, response, &state->user_info);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    ocp_user_debug(state->user_info);

    tevent_req_done(req);
}

errno_t
tilda_auth_recv(TALLOC_CTX *mem_ctx,
                struct tevent_req *req,
                struct ocp_user_info **_user_info)
{
    struct tilda_auth_state *state;
    state = tevent_req_data(req, struct tilda_auth_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_user_info != NULL) {
        *_user_info = talloc_steal(mem_ctx, state->user_info);
    }

    return EOK;
}
