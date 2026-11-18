/**
 * @file PROTOCOL_enrollment.h
 * @brief Device enrollment protocol declarations.
 */

#ifndef PROTOCOL_ENROLLMENT_H
#define PROTOCOL_ENROLLMENT_H

#include "../crypto/crypto_api.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QSAC_KEY_SLOT_ECC_IDENTITY    0x01

qsac_status_t qsac_enrollment_execute(void);
int qsac_enrollment_is_complete(void);
const uint8_t *qsac_enrollment_get_ecc_pubkey(void);
const uint8_t *qsac_enrollment_get_mldsa_pubkey(void);
const uint8_t *qsac_enrollment_get_mldsa_privkey(void);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_ENROLLMENT_H */
