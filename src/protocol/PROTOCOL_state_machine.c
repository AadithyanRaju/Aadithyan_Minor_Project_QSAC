/**
 * @file PROTOCOL_state_machine.c
 * @brief Access Control State Machine implementation.
 */

#include "PROTOCOL_state_machine.h"
#include <string.h>

qsac_status_t qsac_sm_init(qsac_state_machine_t *sm)
{
    if (!sm) {
        return QSAC_ERR_INVALID_PARAM;
    }
    memset(sm, 0, sizeof(*sm));
    sm->state = QSAC_SM_STATE_IDLE;
    return QSAC_OK;
}

const char *qsac_sm_get_state_name(qsac_sm_state_t state)
{
    switch (state) {
        case QSAC_SM_STATE_IDLE:                return "IDLE";
        case QSAC_SM_STATE_HANDSHAKING:         return "HANDSHAKING";
        case QSAC_SM_STATE_SESSION_ESTABLISHED: return "SESSION_ESTABLISHED";
        case QSAC_SM_STATE_ACCESS_REQUESTED:    return "ACCESS_REQUESTED";
        case QSAC_SM_STATE_ACCESS_GRANTED:      return "ACCESS_GRANTED";
        case QSAC_SM_STATE_ACCESS_DENIED:       return "ACCESS_DENIED";
        case QSAC_SM_STATE_ERROR:               return "ERROR";
        default:                                return "UNKNOWN";
    }
}

qsac_sm_state_t qsac_sm_get_state(const qsac_state_machine_t *sm)
{
    if (!sm) {
        return QSAC_SM_STATE_ERROR;
    }
    return sm->state;
}

qsac_status_t qsac_sm_process_event(qsac_state_machine_t *sm,
                                    qsac_sm_event_t event,
                                    const void *event_data)
{
    if (!sm) {
        return QSAC_ERR_INVALID_PARAM;
    }

    switch (sm->state) {
        case QSAC_SM_STATE_IDLE:
            if (event == QSAC_EVT_CONNECT_TRIGGER) {
                sm->state = QSAC_SM_STATE_HANDSHAKING;
                return QSAC_OK;
            }
            break;

        case QSAC_SM_STATE_HANDSHAKING:
            if (event == QSAC_EVT_HANDSHAKE_OK) {
                if (event_data) {
                    memcpy(sm->session_key, event_data, QSAC_SESSION_KEY_SIZE);
                }
                sm->state = QSAC_SM_STATE_SESSION_ESTABLISHED;
                sm->msg_counter = 0;
                return QSAC_OK;
            } else if (event == QSAC_EVT_HANDSHAKE_FAIL) {
                sm->state = QSAC_SM_STATE_ERROR;
                return QSAC_ERR_VERIFY_FAIL;
            }
            break;

        case QSAC_SM_STATE_SESSION_ESTABLISHED:
            if (event == QSAC_EVT_ACCESS_REQUEST) {
                sm->state = QSAC_SM_STATE_ACCESS_REQUESTED;
                return QSAC_OK;
            } else if (event == QSAC_EVT_DISCONNECT || event == QSAC_EVT_TIMEOUT) {
                qsac_sm_terminate(sm);
                return QSAC_OK;
            }
            break;

        case QSAC_SM_STATE_ACCESS_REQUESTED:
            if (event == QSAC_EVT_TOKEN_VALID) {
                if (event_data) {
                    sm->granted_permissions = *(const uint32_t *)event_data;
                }
                sm->state = QSAC_SM_STATE_ACCESS_GRANTED;
                return QSAC_OK;
            } else if (event == QSAC_EVT_TOKEN_INVALID) {
                sm->state = QSAC_SM_STATE_ACCESS_DENIED;
                return QSAC_ERR_VERIFY_FAIL;
            } else if (event == QSAC_EVT_DISCONNECT || event == QSAC_EVT_TIMEOUT) {
                qsac_sm_terminate(sm);
                return QSAC_OK;
            }
            break;

        case QSAC_SM_STATE_ACCESS_GRANTED:
        case QSAC_SM_STATE_ACCESS_DENIED:
            if (event == QSAC_EVT_DISCONNECT || event == QSAC_EVT_TIMEOUT) {
                qsac_sm_terminate(sm);
                return QSAC_OK;
            } else if (event == QSAC_EVT_ACCESS_REQUEST) {
                sm->state = QSAC_SM_STATE_ACCESS_REQUESTED;
                return QSAC_OK;
            }
            break;

        case QSAC_SM_STATE_ERROR:
            if (event == QSAC_EVT_DISCONNECT || event == QSAC_EVT_CONNECT_TRIGGER) {
                qsac_sm_terminate(sm);
                return QSAC_OK;
            }
            break;

        default:
            sm->state = QSAC_SM_STATE_ERROR;
            return QSAC_ERR_INVALID_PARAM;
    }

    return QSAC_ERR_INVALID_PARAM;
}

qsac_status_t qsac_sm_encrypt_payload(qsac_state_machine_t *sm,
                                      const uint8_t *plaintext,
                                      size_t pt_len,
                                      uint8_t *iv,
                                      uint8_t *ciphertext,
                                      uint8_t *tag)
{
    qsac_status_t status;

    if (!sm || !plaintext || !iv || !ciphertext || !tag || sm->state < QSAC_SM_STATE_SESSION_ESTABLISHED) {
        return QSAC_ERR_INVALID_PARAM;
    }

    status = qsac_random_bytes(iv, QSAC_AES_IV_SIZE);
    if (status != QSAC_OK) {
        return status;
    }

    sm->msg_counter++;
    uint32_t aad = sm->msg_counter;

    return qsac_aes_gcm_encrypt(sm->session_key,
                                iv,
                                (const uint8_t *)&aad, sizeof(aad),
                                plaintext, pt_len,
                                ciphertext, tag);
}

qsac_status_t qsac_sm_decrypt_payload(qsac_state_machine_t *sm,
                                      const uint8_t *iv,
                                      const uint8_t *ciphertext,
                                      size_t ct_len,
                                      const uint8_t *tag,
                                      uint8_t *plaintext)
{
    if (!sm || !iv || !ciphertext || !tag || !plaintext || sm->state < QSAC_SM_STATE_SESSION_ESTABLISHED) {
        return QSAC_ERR_INVALID_PARAM;
    }

    uint32_t aad = sm->msg_counter;

    return qsac_aes_gcm_decrypt(sm->session_key,
                                iv,
                                (const uint8_t *)&aad, sizeof(aad),
                                ciphertext, ct_len,
                                tag, plaintext);
}

void qsac_sm_terminate(qsac_state_machine_t *sm)
{
    if (sm) {
        memset(sm->session_key, 0, sizeof(sm->session_key));
        sm->granted_permissions = 0;
        sm->msg_counter = 0;
        sm->state = QSAC_SM_STATE_IDLE;
    }
}
