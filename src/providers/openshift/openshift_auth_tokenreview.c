/*
    SSSD

    openshift_auth_tokenreview.c - OpenShift provider authentication
                                   using the TokenReview Kubernetes API

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

#include <jansson.h>

#include "providers/data_provider/dp.h"
#include "providers/data_provider.h"
#include "util/tev_curl.h"
#include "providers/openshift/openshift_private.h"
#include "providers/openshift/openshift_opts.h"

#define TOKEN_REVIEW_ENDPOINT       "/apis/authentication.k8s.io/v1/tokenreviews"
#define TOKEN_REVIEW_CURL_TIMEOUT   5 /* FIXME: Configurable? Is this a good default? */

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
 * output. Given a fullname as either bar or foo:bar, returns the part
 * after the colon or if the colon is absent, the full name
 */
static const char *parse_name(const char *fullname)
{
    const char *delim;
    delim = strchr(fullname, ':');

    return delim ? delim + 1 : fullname;
}

/*
 * Creates:
 *  {
 *      "kind": "TokenReview",
 *      "apiVersion": "authentication.k8s.io/v1",
 *      "spec": {
 *          "token": $raw_token
 *  }
 *
 *  given $raw_token
 */
static json_t *
token_review_json_body(const char *raw_token)
{
    json_t *jbody = NULL;
    json_t *jtoken_spec = NULL;
    json_error_t error;

    jtoken_spec = json_pack_ex(&error,
                               JSON_STRICT,
                               "{s:s}",
                               "token", raw_token);
    if (jtoken_spec == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON token spec structure on line %d: %s\n",
              error.line, error.text);
        return NULL;
    }

    jbody = json_pack_ex(&error,
                         JSON_STRICT,
                         "{s:s, s:s, s:o}",
                         "kind", "TokenReview",
                         "apiVersion", "authentication.k8s.io/v1",
                         "spec", jtoken_spec);
    if (jbody == NULL) {
        json_decref(jtoken_spec);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to pack JSON token spec structure on line %d: %s\n",
              error.line, error.text);
        return NULL;
    }

    return jbody;
}

/*
 * Turn $raw_token into a JSON representation that can be used
 * as a POST body for the TokenReview request and return this
 * representation as sss_iobuf that can be then consumed by the
 * tevent curl wrapper
 */
static struct sss_iobuf *
token_review_body_as_iobuf(TALLOC_CTX *mem_ctx,
                           const char *raw_token)
{
    json_t *jbody = NULL;
    char *str_body;
    struct sss_iobuf *body;

    jbody = token_review_json_body(raw_token);
    if (jbody == NULL) {
        return NULL;
    }

    str_body = json_dumps(jbody, JSON_INDENT(4) | JSON_ENSURE_ASCII);
    if (str_body == NULL) {
        json_decref(jbody);
        return NULL;
    }

    body = sss_iobuf_init_readonly(mem_ctx,
                                   (const uint8_t *) str_body,
                                   strlen(str_body));
    json_decref(jbody);
    free(str_body);
    if (body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create payload buffer\n");
        return NULL;
    }

    return body;
}

/*
 * Read the reply of the TokenReview API endpoint as seen here:
 *  https://docs.okd.io/latest/rest_api/apis-authentication.k8s.io/v1.TokenReview.html
 * and either return an error, or, on success, fill the ocp_user_info
 * structure.
 *
 */
static errno_t parse_tokenreview_status(TALLOC_CTX *mem_ctx,
                                        json_t *tr_status,
                                        struct ocp_user_info **_user_info)
{
    json_t *juser = NULL;
    int authenticated;
    const char *username;
    json_t *groups = NULL;
    json_t *grp = NULL;
    json_t *extra = NULL;
    json_error_t error;
    errno_t ret;
    struct ocp_user_info *user_info;
    size_t grp_index;

    ret = json_unpack_ex(tr_status,
                         &error,
                         JSON_STRICT,
                         "{s:b, s:o }",
                         "authenticated", &authenticated,
                         "user", &juser);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        return ERR_JSON_DECODING;
    }

    ret = json_unpack_ex(juser,
                         &error,
                         JSON_STRICT,
                         "{s:s, s:o, s?:o }",
                         "username", &username,
                         "groups", &groups,
                         "extra", &extra);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        return ERR_JSON_DECODING;
    }

    /* FIXME: Some sanity check? Username length check, group array size check etc? */
    /* FIXME: What is the authenticated flag? */

    /* OK, the entry parses, let's construct the user_info structure */
    user_info = talloc_zero(mem_ctx, struct ocp_user_info);
    if (user_info == NULL) {
        return ENOMEM;
    }

    user_info->name = talloc_strdup(user_info,
                                    parse_name(username));
    if (user_info->name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    user_info->groups = talloc_zero_array(user_info,
                                          const char *,
                                          json_array_size(groups) + 1);
    if (user_info->groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    json_array_foreach(groups, grp_index, grp) {
        user_info->groups[grp_index] = talloc_strdup(user_info->groups,
                                                     parse_name(json_string_value(grp)));
        if (user_info->groups[grp_index] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    user_info->ngroups = json_array_size(groups);

    ret = EOK;
    *_user_info = user_info;
done:
    if (ret != EOK) {
        talloc_free(user_info);
    }
    return ret;
}

/*
 * For API specification see:
 *  https://docs.okd.io/latest/rest_api/apis-authentication.k8s.io/v1.TokenReview.html
 *
 *
 * Turns a raw sss_iobuf reply from the TokenReview API into an ocp_user_info
 * structure if possible or fail trying.
 *
 * Example reply:
 *
 * { "kind":"TokenReview",
 *   "apiVersion":"authentication.k8s.io/v1",
 *   "metadata": {
 *          "creationTimestamp": null
 *   },
 *   "spec": {
 *          "token":"Ml3qL0VaRZfEhVY-hxxgaiNe1O6NKxdTdKjKUOKgutI"
 *   },
 *   "status": {
 *          "authenticated":true,
 *          "user": {
 *              "username":"kube:admin",
 *              "groups":["system:cluster-admins","system:authenticated"],
 *              "extra":{"scopes.authorization.openshift.io":["user:full"]}
 *          }
 *   }
 *  }
 */
static errno_t parse_userinfo(TALLOC_CTX *mem_ctx,
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
    json_t *spec = NULL;
    json_t *status = NULL;

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
                         "spec", &spec,
                         "status", &status);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unpack JSON princ structure on line %d: %s\n",
              error.line, error.text);
        ret = ERR_JSON_DECODING;
        goto done;
    }

    if (kind == NULL
            || strcasecmp(kind, "tokenReview") != 0) {
        ret = ERR_JSON_DECODING;
        goto done;
    }

    if (api_version == NULL
            || strcasecmp(api_version, "authentication.k8s.io/v1") != 0) {
        ret = ERR_JSON_DECODING;
        goto done;
    }

    /* Try to parse out the user entry from the status nested object */
    ret = parse_tokenreview_status(mem_ctx, status, _user_info);
done:
    if (jreply != NULL) {
        json_decref(jreply);
    }
    return ret;
}

/*
 *  The API description can be found at:
 *        https://docs.okd.io/latest/rest_api/apis-authentication.k8s.io/v1.TokenReview.html
 *  The authentication itself works by sending a POST request to the
 *  TokenReview endpoint with the OAuth token that was passed as a password
 *  through the PAM stack. The token is used in both the POST body (it is
 *  the token we want reviewed) and in the Authorization header (we
 *  authenticate using that token). The latter is problematic, because not
 *  all users can request a review of a token, even their own. Therefore one
 *  of the later patches uses the tilda interface instead.
 */
static struct tcurl_request *
token_review_req_create(TALLOC_CTX *mem_ctx,
                        const char *api_server,
                        struct sss_auth_token *token)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct tcurl_request *tcurl_req;
    const char **headers;
    const char *raw_token;
    const char *url;
    struct sss_iobuf *json_req_body;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return NULL;
    }

    ret = sss_authtok_get_password(token, &raw_token, NULL);
    if (ret != EOK) {
        goto fail;
    }

    /* We set the authoriation header to auth with the token and set
     * the content type to json because that's what we POST
     */
    headers = talloc_zero_array(tmp_ctx, const char *, 3);
    if (headers == NULL) {
        goto fail;
    }
    headers[0] = talloc_asprintf(headers, "Authorization: Bearer %s", raw_token);
    headers[1] = talloc_strdup(headers, "Content-Type: application/json; charset=utf-8");
    if (headers[0] == NULL || headers[1] == NULL) {
        goto fail;
    }

    /* Create the POST body */
    json_req_body = token_review_body_as_iobuf(tmp_ctx, raw_token);
    if (json_req_body == NULL) {
        goto fail;
    }

    url = talloc_asprintf(tmp_ctx, "%s"TOKEN_REVIEW_ENDPOINT, api_server);
    if (url == NULL) {
        goto fail;
    }

    tcurl_req = tcurl_http(tmp_ctx, TCURL_HTTP_POST, NULL, url, headers, json_req_body);
    if (tcurl_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create TCURL request!\n");
        goto fail;
    }

    /*
     * Currently everything is owned by tmp_ctx. While tcurl_http strdups url,
     * it does not take ownership of json_req_body. Fixup the memory hierarchy
     * so that it looks like this:
     *      mem_ctx -> tcurl_req -> json_req_body
     */
    talloc_steal(tcurl_req, json_req_body);
    tcurl_req = talloc_steal(mem_ctx, tcurl_req);
    talloc_free(tmp_ctx);
    return tcurl_req;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}
struct token_review_state {
    struct ocp_user_info *user_info;
};

static void token_review_auth_done(struct tevent_req *subreq);

/*
 * Validate the OAuth token passed as sss_auth_token against TokenReview
 * API endpoint of api_server_url by crafting a special JSON object and
 * POST-ing it to the endpoint.
 *
 * If the endpoint replies with anything than HTTP 2xx, fail and return
 * a SSSD specific error code.
 *
 * Otherwise try to parse out the JSON object in the reply and construct
 * a user_info structure that can be returned to the caller in _recv.
 */
struct tevent_req *
token_review_auth_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct tcurl_ctx *tc_ctx,
                       const char *api_server_url,
                       struct sss_auth_token *token)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct token_review_state *state = NULL;
    struct tcurl_request *token_review_req;

    req = tevent_req_create(mem_ctx, &state, struct token_review_state);
    if (req == NULL) {
        return NULL;
    }

    DEBUG(SSSDBG_FUNC_DATA, "Would try to contact %s\n", api_server_url);

    token_review_req = token_review_req_create(state, api_server_url, token);
    if (token_review_req == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    /* FIXME: This just unconditionally turns off all TLS checks... */
    tcurl_req_verify_peer(token_review_req, NULL, NULL, false, false);

    subreq = tcurl_request_send(state, ev, tc_ctx,
                                token_review_req,
                                TOKEN_REVIEW_CURL_TIMEOUT);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, token_review_auth_done, req);
    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static void token_review_auth_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct token_review_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sss_iobuf *response = NULL;
    int http_code;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct token_review_state);

    ret = tcurl_request_recv(state, subreq, &response, &http_code);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "tokenReview API call failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,
          "tokenReview finished with http code %d\n", http_code);

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

    /* Now the return code is either 200 or 201. So we can parse out the
     * entry out of the reply
     */
    ret = parse_userinfo(state, response, &state->user_info);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    ocp_user_debug(state->user_info);

    /* If the parsing finished as well, let's finish the request */
    tevent_req_done(req);
}

errno_t
token_review_auth_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct ocp_user_info **_user_info)
{
    struct token_review_state *state;
    state = tevent_req_data(req, struct token_review_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_user_info != NULL) {
        *_user_info = talloc_steal(mem_ctx, state->user_info);
    }

    return EOK;
}
