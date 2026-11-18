/**
 * @file PROTOCOL_token_verify.h
 * @brief Access token definitions, generation, and verification declarations.
 */

#ifndef PROTOCOL_TOKEN_VERIFY_H
#define PROTOCOL_TOKEN_VERIFY_H

#include "../crypto/crypto_api.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------
 * Token Permission Bitmasks
 * ---------------------------------------------- */
#define QSAC_PERM_NONE           0x00000000
#define QSAC_PERM_ACCESS_DOOR    0x00000001
#define QSAC_PERM_READ_TELEMETRY 0x00000002
#define QSAC_PERM_WRITE_CONFIG   0x00000004
#define QSAC_PERM_ADMIN          0x80000000

#define QSAC_TOKEN_PAYLOAD_SIZE  28
#define QSAC_TOKEN_TOTAL_SIZE    (QSAC_TOKEN_PAYLOAD_SIZE + QSAC_MLDSA_SIG_SIZE)

typedef struct {
    uint8_t  device_id[16];
    uint32_t issued_at;
    uint32_t expires_at;
    uint32_t permissions;
} __attribute__((packed)) qsac_token_payload_t;

typedef struct {
    qsac_token_payload_t payload;
    uint8_t signature[QSAC_MLDSA_SIG_SIZE];
} __attribute__((packed)) qsac_access_token_t;

/* ----------------------------------------------
 * Token Verification API
 * ---------------------------------------------- */

qsac_status_t qsac_token_load_authority_key(const uint8_t *pubkey);

qsac_status_t qsac_token_issue(const uint8_t *authority_privkey,
                               const qsac_token_payload_t *payload,
                               qsac_access_token_t *out_token);

qsac_status_t qsac_token_verify(const qsac_access_token_t *token,
                                uint32_t current_time,
                                uint32_t *permissions);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_TOKEN_VERIFY_H */
