/**
 * @file PROTOCOL_handshake.h
 * @brief Hybrid quantum-classical session authentication handshake declarations.
 */

#ifndef PROTOCOL_HANDSHAKE_H
#define PROTOCOL_HANDSHAKE_H

#include "../crypto/crypto_api.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------
 * Handshake Message Structures
 * ---------------------------------------------- */

#define QSAC_NONCE_SIZE 32
#define QSAC_HANDSHAKE_CONFIRMATION_SIZE 32

typedef struct {
    uint8_t client_nonce[QSAC_NONCE_SIZE];
    uint8_t ecdh_pubkey[QSAC_ECC_PUBKEY_SIZE];
    uint8_t mlkem_pubkey[QSAC_MLKEM_PUBKEY_SIZE];
} __attribute__((packed)) qsac_client_hello_t;

typedef struct {
    uint8_t server_nonce[QSAC_NONCE_SIZE];
    uint8_t ecdh_pubkey[QSAC_ECC_PUBKEY_SIZE];
    uint8_t mlkem_ciphertext[QSAC_MLKEM_CIPHERTEXT_SIZE];
    uint8_t mldsa_signature[QSAC_MLDSA_SIG_SIZE];
} __attribute__((packed)) qsac_server_hello_t;

typedef struct {
    uint8_t iv[QSAC_AES_IV_SIZE];
    uint8_t tag[QSAC_AES_TAG_SIZE];
    uint8_t encrypted_confirmation[QSAC_HANDSHAKE_CONFIRMATION_SIZE];
} __attribute__((packed)) qsac_client_finished_t;

/* ----------------------------------------------
 * Handshake State Machine & Contexts
 * ---------------------------------------------- */

typedef enum {
    QSAC_HS_STATE_INIT = 0,
    QSAC_HS_STATE_HELLO_SENT,
    QSAC_HS_STATE_SERVER_RESPONDED,
    QSAC_HS_STATE_DERIVED,
    QSAC_HS_STATE_ESTABLISHED,
    QSAC_HS_STATE_FAILED
} qsac_handshake_state_t;

typedef struct {
    uint32_t ecdh_key_slot;
    uint8_t  ecdh_pubkey[QSAC_ECC_PUBKEY_SIZE];
    uint8_t  mlkem_pubkey[QSAC_MLKEM_PUBKEY_SIZE];
    uint8_t  client_nonce[QSAC_NONCE_SIZE];
    uint8_t  server_nonce[QSAC_NONCE_SIZE];
    uint8_t  mlkem_privkey[QSAC_MLKEM_PRIVKEY_SIZE];
    uint8_t  session_key[QSAC_SESSION_KEY_SIZE];
    uint8_t  transcript_hash[32];
    qsac_handshake_state_t state;
} qsac_handshake_client_ctx_t;

typedef struct {
    uint32_t ecdh_key_slot;
    uint8_t  client_nonce[QSAC_NONCE_SIZE];
    uint8_t  server_nonce[QSAC_NONCE_SIZE];
    uint8_t  session_key[QSAC_SESSION_KEY_SIZE];
    uint8_t  transcript_hash[32];
    qsac_handshake_state_t state;
} qsac_handshake_server_ctx_t;

/* ----------------------------------------------
 * Protocol Handshake Functions
 * ---------------------------------------------- */

qsac_status_t qsac_handshake_client_init(qsac_handshake_client_ctx_t *ctx, uint32_t ecdh_slot);

qsac_status_t qsac_handshake_client_create_hello(qsac_handshake_client_ctx_t *ctx,
                                                 qsac_client_hello_t *hello);

qsac_status_t qsac_handshake_server_process_hello_and_respond(
    qsac_handshake_server_ctx_t *server_ctx,
    uint32_t server_ecdh_slot,
    const uint8_t *server_mldsa_privkey,
    const qsac_client_hello_t *client_hello,
    qsac_server_hello_t *server_hello);

qsac_status_t qsac_handshake_client_process_server_hello(
    qsac_handshake_client_ctx_t *client_ctx,
    const uint8_t *server_mldsa_pubkey,
    const qsac_server_hello_t *server_hello,
    qsac_client_finished_t *client_finished);

qsac_status_t qsac_handshake_server_process_finished(
    qsac_handshake_server_ctx_t *server_ctx,
    const qsac_client_finished_t *client_finished);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_HANDSHAKE_H */
