/**
 * @file atecc608b.h
 * @brief Microchip ATECC608B Cryptographic Co-Processor / HSM Driver.
 *
 * Implements hardware security module integration for QSAC:
 *   - Hardware True Random Number Generator (TRNG)
 *   - Hardware Key Isolation (Internal EEPROM slots)
 *   - Hardware ECC P-256 (ECDH, ECDSA Sign/Verify)
 *   - Hardware SHA-256 acceleration
 *   - Chip diagnostics: 9-byte Serial Number, Revision ID, Lock Status
 */

#ifndef QSAC_ATECC608B_H
#define QSAC_ATECC608B_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------
 * I2C & Device Parameters
 * ---------------------------------------------- */

#define ATECC_I2C_ADDR_DEFAULT      0x60    /* 7-bit default I2C address (0xC0 write) */

/* Packet Word Addresses */
#define ATECC_WORD_ADDR_RESET       0x00
#define ATECC_WORD_ADDR_SLEEP       0x01
#define ATECC_WORD_ADDR_IDLE        0x02
#define ATECC_WORD_ADDR_COMMAND     0x03

/* Command Opcodes */
#define ATECC_OP_READ               0x02
#define ATECC_OP_NONCE              0x16
#define ATECC_OP_RANDOM             0x1B
#define ATECC_OP_INFO               0x30
#define ATECC_OP_LOCK               0x17
#define ATECC_OP_GENKEY             0x40
#define ATECC_OP_SIGN               0x41
#define ATECC_OP_ECDH               0x43
#define ATECC_OP_VERIFY             0x45
#define ATECC_OP_SHA                0x47

/* Buffer & Key Sizes */
#define ATECC_SERIAL_NUM_SIZE       9       /* 9-byte unique hardware serial number */
#define ATECC_REV_NUM_SIZE          4       /* 4-byte revision number */
#define ATECC_RANDOM_SIZE           32      /* 32 bytes from HW TRNG */
#define ATECC_PUBKEY_SIZE           64      /* 64 bytes uncompressed (X || Y) */
#define ATECC_SIG_SIZE              64      /* 64 bytes ECDSA signature (R || S) */
#define ATECC_SHARED_SECRET_SIZE    32      /* 32 bytes ECDH pre-master secret */
#define ATECC_DIGEST_SIZE           32      /* 32 bytes SHA-256 */

/* Maximum packet size for send/receive */
#define ATECC_CMD_BUF_SIZE          160
#define ATECC_RSP_BUF_SIZE          160

/* ----------------------------------------------
 * Device Information Structure
 * ---------------------------------------------- */

typedef struct {
    bool     present;                           /* True if detected on I2C */
    uint8_t  serial_number[ATECC_SERIAL_NUM_SIZE]; /* 9-byte unique chip ID */
    uint32_t revision;                          /* 4-byte chip revision (e.g., 0x00006002) */
    bool     config_locked;                     /* True if Config Zone is locked */
    bool     data_locked;                       /* True if Data/OTP Zone is locked */
} atecc608b_info_t;

/* ----------------------------------------------
 * Driver API
 * ---------------------------------------------- */

/**
 * @brief Initialize the ATECC608B driver and probe the device.
 *        Reads serial number, revision, and lock status.
 * @param info  Output struct populated with chip info (optional, can be NULL).
 * @return 0 on success, negative error code if device not found.
 */
int atecc608b_init(atecc608b_info_t *info);

/**
 * @brief Check if ATECC608B hardware is detected and ready.
 */
bool atecc608b_is_present(void);

/**
 * @brief Get cached device info structure.
 */
const atecc608b_info_t *atecc608b_get_info(void);

/**
 * @brief Wake up the ATECC608B from sleep mode.
 * @return 0 on success, negative on error.
 */
int atecc608b_wakeup(void);

/**
 * @brief Put the ATECC608B into low-power sleep mode.
 */
void atecc608b_sleep(void);

/**
 * @brief Put the ATECC608B into idle mode.
 */
void atecc608b_idle(void);

/**
 * @brief Generate 32 cryptographically secure random bytes using the hardware TRNG.
 * @param rand_out  Output buffer (32 bytes).
 * @return 0 on success, negative on error.
 */
int atecc608b_random(uint8_t *rand_out);

/**
 * @brief Compute SHA-256 digest using the hardware SHA engine.
 * @param data      Input data.
 * @param len       Length of input data.
 * @param digest32  Output 32-byte digest buffer.
 * @return 0 on success, negative on error.
 */
int atecc608b_sha256(const uint8_t *data, size_t len, uint8_t *digest32);

/**
 * @brief Generate a NIST P-256 keypair in an ATECC608B slot.
 *        Private key is stored in slot EEPROM and never leaves the chip.
 * @param slot      Key slot index (0..15).
 * @param pubkey    Output 64-byte uncompressed public key (X || Y).
 * @return 0 on success, negative on error.
 */
int atecc608b_genkey(uint16_t slot, uint8_t *pubkey);

/**
 * @brief Perform ECDH key agreement using the private key in slot and peer public key.
 * @param slot            Slot index holding device private key.
 * @param peer_pubkey     Peer's 64-byte public key (X || Y).
 * @param shared_secret   Output 32-byte shared secret (X-coordinate).
 * @return 0 on success, negative on error.
 */
int atecc608b_ecdh(uint16_t slot, const uint8_t *peer_pubkey, uint8_t *shared_secret);

/**
 * @brief Sign a 32-byte message digest using the private key in slot.
 * @param slot      Slot index holding device signing key.
 * @param digest    32-byte SHA-256 digest.
 * @param sig       Output 64-byte ECDSA signature (R || S).
 * @return 0 on success, negative on error.
 */
int atecc608b_sign(uint16_t slot, const uint8_t *digest, uint8_t *sig);

/**
 * @brief Verify an ECDSA signature using the hardware verify engine.
 * @param pubkey    Signer's 64-byte public key (X || Y).
 * @param digest    32-byte message digest.
 * @param sig       64-byte signature (R || S).
 * @return 0 on success (valid signature), negative on error or verification failure.
 */
int atecc608b_verify(const uint8_t *pubkey, const uint8_t *digest, const uint8_t *sig);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_ATECC608B_H */
