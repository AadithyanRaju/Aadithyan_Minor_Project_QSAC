/**
 * @file PROTOCOL_state_machine.h
 * @brief Access Control State Machine declarations.
 */

#ifndef PROTOCOL_STATE_MACHINE_H
#define PROTOCOL_STATE_MACHINE_H

#include "../crypto/crypto_api.h"
#include "PROTOCOL_token_verify.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QSAC_SM_STATE_IDLE = 0,
    QSAC_SM_STATE_HANDSHAKING,
    QSAC_SM_STATE_SESSION_ESTABLISHED,
    QSAC_SM_STATE_ACCESS_REQUESTED,
    QSAC_SM_STATE_ACCESS_GRANTED,
    QSAC_SM_STATE_ACCESS_DENIED,
    QSAC_SM_STATE_ERROR
} qsac_sm_state_t;

typedef enum {
    QSAC_EVT_CONNECT_TRIGGER = 0,
    QSAC_EVT_HANDSHAKE_OK,
    QSAC_EVT_HANDSHAKE_FAIL,
    QSAC_EVT_ACCESS_REQUEST,
    QSAC_EVT_TOKEN_VALID,
    QSAC_EVT_TOKEN_INVALID,
    QSAC_EVT_DISCONNECT,
    QSAC_EVT_TIMEOUT
} qsac_sm_event_t;

typedef struct {
    qsac_sm_state_t state;
    uint8_t         session_key[QSAC_SESSION_KEY_SIZE];
    uint32_t        granted_permissions;
    uint32_t        session_id;
    uint32_t        msg_counter;
} qsac_state_machine_t;

qsac_status_t qsac_sm_init(qsac_state_machine_t *sm);

qsac_status_t qsac_sm_process_event(qsac_state_machine_t *sm,
                                    qsac_sm_event_t event,
                                    const void *event_data);

qsac_sm_state_t qsac_sm_get_state(const qsac_state_machine_t *sm);

const char *qsac_sm_get_state_name(qsac_sm_state_t state);

qsac_status_t qsac_sm_encrypt_payload(qsac_state_machine_t *sm,
                                      const uint8_t *plaintext,
                                      size_t pt_len,
                                      uint8_t *iv,
                                      uint8_t *ciphertext,
                                      uint8_t *tag);

qsac_status_t qsac_sm_decrypt_payload(qsac_state_machine_t *sm,
                                      const uint8_t *iv,
                                      const uint8_t *ciphertext,
                                      size_t ct_len,
                                      const uint8_t *tag,
                                      uint8_t *plaintext);

void qsac_sm_terminate(qsac_state_machine_t *sm);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_STATE_MACHINE_H */
