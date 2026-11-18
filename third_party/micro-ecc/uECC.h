/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _MICRO_ECC_H_
#define _MICRO_ECC_H_

#include <stdint.h>
#include <stdbool.h>

/* Target curve selection */
#ifndef uECC_SUPPORTS_secp256r1
#define uECC_SUPPORTS_secp256r1 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct uECC_Curve_t;
typedef const struct uECC_Curve_t * uECC_Curve;

/* Curve accessor */
uECC_Curve uECC_secp256r1(void);

/* Returns the size of a private key for the curve in bytes */
int uECC_curve_private_key_size(uECC_Curve curve);

/* Returns the size of a public key for the curve in bytes (uncompressed x || y) */
int uECC_curve_public_key_size(uECC_Curve curve);

/* Function pointer type for random number generation.
 * Should return 1 on success, 0 on failure.
 */
typedef int (*uECC_RNG_Function)(uint8_t *dest, unsigned size);

/* Set the RNG function to be used for key generation and ECDSA signing */
void uECC_set_rng(uECC_RNG_Function rng_function);

/* Get the current RNG function */
uECC_RNG_Function uECC_get_rng(void);

/* Generate a public/private key pair.
 * Outputs:
 *   public_key  - 64 bytes (32-byte x || 32-byte y)
 *   private_key - 32 bytes
 * Returns 1 on success, 0 on failure.
 */
int uECC_make_key(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve);

/* Compute ECDH shared secret.
 * Inputs:
 *   public_key  - 64 bytes peer public key (x || y)
 *   private_key - 32 bytes private key
 * Output:
 *   secret      - 32 bytes shared secret (x-coordinate)
 * Returns 1 on success, 0 on failure.
 */
int uECC_shared_secret(const uint8_t *public_key,
                       const uint8_t *private_key,
                       uint8_t *secret,
                       uECC_Curve curve);

/* Compute ECDSA signature.
 * Inputs:
 *   private_key  - 32 bytes private key
 *   message_hash - hash of message (e.g. 32 bytes SHA-256)
 *   hash_size    - size of message_hash in bytes
 * Output:
 *   signature    - 64 bytes signature (32-byte r || 32-byte s)
 * Returns 1 on success, 0 on failure.
 */
int uECC_sign(const uint8_t *private_key,
              const uint8_t *message_hash,
              unsigned hash_size,
              uint8_t *signature,
              uECC_Curve curve);

/* Verify ECDSA signature.
 * Inputs:
 *   public_key   - 64 bytes public key (x || y)
 *   message_hash - hash of message (e.g. 32 bytes SHA-256)
 *   hash_size    - size of message_hash in bytes
 *   signature    - 64 bytes signature (r || s)
 * Returns 1 if signature is valid, 0 if invalid.
 */
int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve);

#ifdef __cplusplus
}
#endif

#endif /* _MICRO_ECC_H_ */
