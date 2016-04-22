/*
    Copyright (C) 2015 Red Hat

    SSSD tests: PAM tests

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

#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include "sss_cli.h"

#include "responder/pam/pamsrv.h"
#include "responder/common/responder_packet.h"
#include "responder/common/sss_packet.h"
#include "providers/data_provider.h"

/* Make linker happy */
int __wrap_sss_parse_name_for_domains(TALLOC_CTX *memctx,
                                      struct sss_domain_info *domains,
                                      const char *default_domain,
                                      const char *orig,
                                      char **domain, char **name)
{
    char *atsign;

    atsign = strrchr(orig, '@');
    if (atsign == NULL) {
        *domain = NULL;
        *name = talloc_strdup(memctx, orig);
        if (*name == NULL) {
            return ENOMEM;
        }
        return EOK;
    }

    *name = talloc_strndup(memctx, orig, atsign - orig);
    *domain = talloc_strdup(memctx, atsign+1);
    if (*name == NULL || *domain == NULL) {
        return ENOMEM;
    }

    return EOK;
}

void __wrap_sss_packet_get_body(struct sss_packet *packet, uint8_t **body, size_t *blen)
{
    *body = packet->buffer;
    *blen = packet->memsize;
}

static struct cli_ctx *
mock_pam_cctx(TALLOC_CTX *mem_ctx,
              enum sss_cli_command cmd,
              int cli_protocol_version,
              struct sss_cli_req_data *rd)
{
    struct cli_ctx *cctx = NULL;
    struct pam_ctx *pctx;
    struct cli_protocol *prctx;
    int ret;

    cctx = talloc_zero(mem_ctx, struct cli_ctx);
    if (!cctx) goto fail;

    cctx->rctx = talloc_zero(cctx, struct resp_ctx);
    if (cctx->rctx == NULL) goto fail;

    pctx = talloc_zero(cctx->rctx, struct pam_ctx);
    if (pctx == NULL) goto fail;
    pctx->rctx = cctx->rctx;

    prctx = talloc_zero(cctx, struct cli_protocol);
    if (prctx == NULL) goto fail;

    prctx->creq = talloc_zero(prctx, struct cli_request);
    if (prctx->creq == NULL) goto fail;

    prctx->cli_protocol_version = talloc_zero(prctx,
                                             struct cli_protocol_version);
    if (prctx->cli_protocol_version == NULL) goto fail;

    prctx->cli_protocol_version->version = cli_protocol_version;

    prctx->creq = talloc_zero(cctx, struct cli_request);
    if (prctx->creq == NULL) goto fail;

    ret = sss_packet_new(prctx->creq, 0, cmd, &prctx->creq->in);
    if (ret != EOK) goto fail;

    prctx->creq->in->buffer = discard_const(rd->data);
    prctx->creq->in->memsize = rd->len;

    cctx->protocol_ctx = prctx;
    return cctx;

fail:
    talloc_free(cctx);
    return NULL;
}

static struct pam_data *
mock_pam_data(TALLOC_CTX *mem_ctx, enum sss_cli_command cmd)
{
    struct pam_data *pd = NULL;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) goto fail;

    pd->cmd = cmd;
    pd->authtok = sss_authtok_new(pd);
    pd->newauthtok = sss_authtok_new(pd);
    if (pd->authtok == NULL || pd->newauthtok == NULL) goto fail;

    return pd;

fail:
    talloc_free(pd);
    return NULL;
}

static bool authtok_matches(struct sss_auth_token *authtok,
                            const char *exp_pass)
{
    int ret;
    const char *password;
    size_t pwlen;

    ret = sss_authtok_get_password(authtok, &password, &pwlen);
    if (ret != EOK) {
        return false;
    }

    if (strncmp(password, exp_pass, pwlen) == 0) {
        return true;
    }

    return false;
}

static int test_auth(struct pam_data *pd, const char *exp_pass)
{
    pd->pam_status = PAM_AUTH_ERR;

    if (authtok_matches(pd->authtok, exp_pass) == true) {
        pd->pam_status = PAM_SUCCESS;
    }

    return EOK;
}

static int test_2fa_auth(struct pam_data *pd,
                         const char *ltp, const char *otp)
{
    errno_t ret;
    const char *fa1;
    size_t fa1_len;
    const char *fa2;
    size_t fa2_len;

    pd->pam_status = PAM_AUTH_ERR;

    ret = sss_authtok_get_2fa(pd->authtok, &fa1, &fa1_len, &fa2, &fa2_len);
    if (ret != EOK) {
        return ret;
    }

    if (strncmp(ltp, fa1, fa1_len) == 0 && strncmp(otp, fa2, fa2_len) == 0) {
        pd->pam_status = PAM_SUCCESS;
    }

    return EOK;
}

static int test_sc_auth(struct pam_data *pd, const char *exp_pin)
{
    errno_t ret;
    const char *pin;
    size_t pin_len;

    pd->pam_status = PAM_AUTH_ERR;

    ret = sss_authtok_get_sc_pin(pd->authtok, &pin, &pin_len);
    if (ret != EOK) {
        return ret;
    }

    if (strncmp(pin, exp_pin, pin_len) == 0) {
        pd->pam_status = PAM_SUCCESS;
    }

    return EOK;
}

static int test_chauthtok(struct pam_data *pd,
                          const char *old_pass,
                          const char *new_pass)
{
    pd->pam_status = PAM_AUTH_ERR;

    if (authtok_matches(pd->authtok, old_pass) == true
            && authtok_matches(pd->newauthtok, new_pass) == true) {
        pd->pam_status = PAM_SUCCESS;
    }

    return EOK;
}

static int mock_pam_preauth(struct pam_data *pd)
{
    errno_t ret = PAM_SYSTEM_ERR;
    char *internal_name;

    if (strcmp(pd->user, "otpuser") == 0) {
        ret = pam_resp_otp_info(pd, "test_vendor",
                                "test_id", "enter PIN for test");
    } else if (strcmp(pd->user, "scuser") == 0) {
        internal_name = sss_create_internal_fqname(pd, pd->user, "testdomain");
        if (internal_name == NULL) {
            return ENOMEM;
        }

        ret = add_pam_cert_response(pd, internal_name, "sc_name");
        talloc_free(internal_name);
        pd->pam_status = PAM_SUCCESS;
    }

    return ret;
}

static void mock_pam_add_domain_name(struct pam_data *pd,
                                     const char *domname)
{
    errno_t ret;

    ret = pam_add_response(pd, SSS_PAM_DOMAIN_NAME, strlen(domname)+1,
                           (uint8_t *) discard_const(domname));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
    }
}

static int mock_pam_prelim(struct pam_data *pd)
{
    errno_t ret = PAM_SYSTEM_ERR;

    if (strcmp(pd->user, "testuser") == 0) {
        ret = test_auth(pd, "secret");
    } else if (strcmp(pd->user, "offlinechpass") == 0) {
        ret = test_auth(pd, "secret");
    } else if (strcmp(pd->user, "srvchpass") == 0) {
        ret = test_auth(pd, "secret");
    } else if (strcmp(pd->user, "otpuser") == 0) {
        ret = test_auth(pd, "secret");
    }

    return ret;
}

static int mock_pam_auth(struct pam_data *pd)
{
    errno_t ret = PAM_SYSTEM_ERR;

    if (strcmp(pd->user, "testuser") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == EOK) {
            const char *info_message = "This is a syslog message";
            ret = pam_add_response(pd, SSS_PAM_SYSTEM_INFO,
                                   strlen(info_message)+1,
                                   (const uint8_t *) info_message);
        }
    } else if (strcmp(pd->user, "offlinechpass") == 0) {
        ret = test_auth(pd, "secret");
    } else if (strcmp(pd->user, "textinfo") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == EOK) {
            const char *info_message = "This is a textinfo message";
            ret = pam_add_response(pd, SSS_PAM_TEXT_MSG,
                                   strlen(info_message)+1,
                                   (const uint8_t *) info_message);
        }
    } else if (strcmp(pd->user, "srvchpass") == 0) {
        ret = test_auth(pd, "secret");
    } else if (strcmp(pd->user, "otpuser") == 0) {
        ret = test_2fa_auth(pd, "secret", "1234");
    } else if (strcmp(pd->user, "otpsshuser") == 0) {
        ret = test_auth(pd, "secret1234");
        if (ret == EOK) {
            ret = pam_resp_otp_used(pd);
        }
    } else if (strcmp(pd->user, "otpsingle") == 0) {
        ret = test_2fa_auth(pd, "secret", "1234");
        if (ret == EOK) {
            ret = pam_resp_otp_used(pd);
        }
    } else if (strcmp(pd->user, "scuser") == 0) {
        ret = test_sc_auth(pd, "4321");
    } else if (strcmp(pd->user, "domtest") == 0) {
        pd->pam_status = PAM_AUTH_ERR;
        if (pd->requested_domains[0] != NULL
                && strcmp(pd->requested_domains[0], "mydomain") == 0
                && pd->requested_domains[1] == NULL) {
            pd->pam_status = PAM_SUCCESS;
        }

        ret = EOK;
    } else if (strcmp(pd->user, "retrytest") == 0) {
        ret = test_auth(pd, "retried_secret");
    } else if (strcmp(pd->user, "offlineuser") == 0) {
        ret = test_auth(pd, "secret");
        if (pd->pam_status == PAM_SUCCESS) {
            pamsrv_resp_offline_auth(pd, 123);
        } else if (pd->pam_status == PAM_AUTH_ERR) {
            pamsrv_resp_offline_delayed_auth(pd, 456);
        }
    } else if (strcmp(pd->user, "gracelogin") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pam_resp_grace_login(pd, 1);
        }
    } else if (strcmp(pd->user, "expirelogin_sec") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pam_resp_expired_login(pd, 1);
        }
    } else if (strcmp(pd->user, "expirelogin_min") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pam_resp_expired_login(pd, 61);
        }
    } else if (strcmp(pd->user, "expirelogin_hour") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pam_resp_expired_login(pd, 3601);
        }
    } else if (strcmp(pd->user, "expirelogin_day") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pam_resp_expired_login(pd, 24*3601);
        }
    } else if (strcmp(pd->user, "sshuser") == 0) {
        ret = test_auth(pd, "secret");
        if (ret == PAM_SUCCESS) {
            pd->pam_status = PAM_ACCT_EXPIRED;
            pamsrv_exp_warn(pd, PAM_VERBOSITY_INFO, "SSH user is expired");
        }
    } else if (strcmp(pd->user, "reqduser") == 0) {
        pd->pam_status = PAM_NEW_AUTHTOK_REQD;
        ret = PAM_SUCCESS;
    } else if (strcmp(pd->user, "root_chpass") == 0) {
        mock_pam_add_domain_name(pd, "chpass_domain");
        pd->pam_status = PAM_PERM_DENIED;
        ret = PAM_SUCCESS;
    } else if (strcmp(pd->user, "unknown_user") == 0) {
        pd->pam_status = PAM_USER_UNKNOWN;
        ret = PAM_SUCCESS;
    } else if (strcmp(pd->user, "unavail_user") == 0) {
        pd->pam_status = PAM_AUTHINFO_UNAVAIL;
        ret = PAM_SUCCESS;
    } else if (strcmp(pd->user, "emptypass") == 0) {
        if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_EMPTY) {
            pd->pam_status = PAM_SUCCESS;
            ret = PAM_SUCCESS;
        }
    }

    return ret;
}

static int mock_pam_chauthtok(struct pam_data *pd)
{
    errno_t ret = PAM_SYSTEM_ERR;

    if (strcmp(pd->user, "testuser") == 0) {
        ret = test_chauthtok(pd, "secret", "new_secret");
    } else if (strcmp(pd->user, "offlinechpass") == 0) {
        pamsrv_resp_offline_chpass(pd);
        pd->pam_status = PAM_AUTH_ERR;
        ret = EOK;
    } else if (strcmp(pd->user, "srvchpass") == 0) {
        pam_resp_srv_msg(pd, "Test server message");
        pd->pam_status = PAM_AUTH_ERR;
        ret = EOK;
    } else if (strcmp(pd->user, "otpuser") == 0) {
        pam_resp_otp_chpass(pd);
        pd->pam_status = PAM_SUCCESS;
        ret = EOK;
    }

    return ret;
}

static int mock_pam_acct(struct pam_data *pd)
{
    if (strcmp(pd->user, "allowed_user") == 0) {
        pd->pam_status = PAM_SUCCESS;
    } else if (strcmp(pd->user, "denied_user") == 0) {
        pd->pam_status = PAM_PERM_DENIED;
    } else if (strcmp(pd->user, "reqduser") == 0) {
        pd->pam_status = PAM_SUCCESS;
    }

    return EOK;
}

static int mock_pam_set_cred(struct pam_data *pd)
{
    const char *cred_msg = "CREDS=set";

    pd->pam_status = PAM_SUCCESS;
    return pam_add_response(pd, SSS_ALL_ENV_ITEM,
                            strlen(cred_msg)+1,
                            (const uint8_t *) cred_msg);
}

static int mock_pam_open_session(struct pam_data *pd)
{
    const char *session_msg = "SESSION=open";

    pd->pam_status = PAM_SUCCESS;
    return pam_add_response(pd, SSS_ALL_ENV_ITEM,
                            strlen(session_msg)+1,
                            (const uint8_t *) session_msg);
}

static int mock_pam_close_session(struct pam_data *pd)
{
    pd->pam_status = PAM_SUCCESS;
    return EOK;
}

/* Receives a packed response and returns a mock reply */
int __wrap_sss_pam_make_request(enum sss_cli_command cmd,
                                struct sss_cli_req_data *rd,
                                uint8_t **repbuf, size_t *replen,
                                int *errnop)
{
    errno_t ret;
    TALLOC_CTX *test_ctx;
    struct cli_ctx *cctx;
    struct pam_data *pd;
    struct cli_protocol *prctx;

    test_ctx = talloc_new(NULL);
    if (test_ctx == NULL) {
        return ENOMEM;
    }

    /* The PAM responder functions expect both cctx and pd to be talloc
     * contexts
     */
    cctx = mock_pam_cctx(test_ctx, cmd, 3, rd);
    pd = mock_pam_data(test_ctx, cmd);
    if (cctx == NULL || pd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    prctx = talloc_get_type(cctx->protocol_ctx, struct cli_protocol);

    ret = pam_forwarder_parse_data(cctx, pd);
    if (ret != EOK) {
        goto done;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    switch (cmd) {
    case SSS_PAM_PREAUTH:
        ret = mock_pam_preauth(pd);
        break;
    case SSS_PAM_CHAUTHTOK_PRELIM:
        ret = mock_pam_prelim(pd);
        break;
    case SSS_PAM_AUTHENTICATE:
        ret = mock_pam_auth(pd);
        break;
    case SSS_PAM_ACCT_MGMT:
        ret = mock_pam_acct(pd);
        break;
    case SSS_PAM_CHAUTHTOK:
        ret = mock_pam_chauthtok(pd);
        break;
    case SSS_PAM_SETCRED:
        ret = mock_pam_set_cred(pd);
        break;
    case SSS_PAM_OPEN_SESSION:
        ret = mock_pam_open_session(pd);
        break;
    case SSS_PAM_CLOSE_SESSION:
        ret = mock_pam_close_session(pd);
        break;
    default:
        break;
    }

    if (ret != EOK) {
        goto done;
    }

    ret = pamsrv_reply_packet(prctx->creq, pd, cmd, &prctx->creq->out);
    if (ret != EOK) {
        goto done;
    }

    *repbuf = malloc(prctx->creq->out->memsize);
    memcpy(*repbuf, prctx->creq->out->buffer, prctx->creq->out->memsize);
    *replen = prctx->creq->out->memsize;

    ret = EOK;
done:
    return ret;
}
