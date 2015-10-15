/*
   SSSD

   PAM Responder

   Copyright (C) Red Hat 2015

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

#include "util/util.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"
#include "responder/common/responder_packet.h"

static errno_t pack_user_info_msg(TALLOC_CTX *mem_ctx,
                                  const char *user_error_message,
                                  size_t *resp_len,
                                  uint8_t **_resp)
{
    uint32_t resp_type = SSS_PAM_USER_INFO_ACCOUNT_EXPIRED;
    size_t err_len;
    uint8_t *resp;
    size_t p;

    err_len = strlen(user_error_message);
    *resp_len = 2 * sizeof(uint32_t) + err_len;
    resp = talloc_size(mem_ctx, *resp_len);
    if (resp == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    p = 0;
    SAFEALIGN_SET_UINT32(&resp[p], resp_type, &p);
    SAFEALIGN_SET_UINT32(&resp[p], err_len, &p);
    safealign_memcpy(&resp[p], user_error_message, err_len, &p);
    if (p != *resp_len) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Size mismatch\n");
    }

    *_resp = resp;
    return EOK;
}

static void inform_user(struct pam_data* pd, const char *pam_message)
{
    size_t msg_len;
    uint8_t *msg;
    errno_t ret;

    ret = pack_user_info_msg(pd, pam_message, &msg_len, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pack_user_info_account_expired failed.\n");
    } else {
        ret = pam_add_response(pd, SSS_PAM_USER_INFO, msg_len, msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "pam_add_response failed.\n");
        }
    }
}

void pamsrv_exp_warn(struct pam_data *pd,
                     int pam_verbosity,
                     const char *pam_account_expired_message)
{
    if (pd->pam_status == PAM_ACCT_EXPIRED &&
            ((pd->service != NULL && strcasecmp(pd->service, "sshd") == 0) ||
             pam_verbosity >= PAM_VERBOSITY_INFO)) {
        inform_user(pd, pam_account_expired_message);
    }
}


void pamsrv_lock_warn(struct pam_data *pd,
                      const char *pam_account_locked_message)
{
    if (pd->account_locked) {
        inform_user(pd, pam_account_locked_message);
    }
}
