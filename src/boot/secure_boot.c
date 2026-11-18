/**
 * @file secure_boot.c
 * @brief PQC-signed secure boot verification.
 *
 * Implements the secure boot flow described in Section IV-C:
 *   At power-on, the HSM (or boot ROM with HSM-verified trust anchor)
 *   verifies the first-stage bootloader signature using ML-DSA before
 *   releasing the main core from reset.
 *
 * SLH-DSA is supported as an alternative where signature size is less
 * constrained than verification time, since SLH-DSA verification is
 * comparatively cheap even though signing is expensive and signatures
 * are large. Signing happens once at build time off-device; only
 * verification runs on the constrained device.
 */

#include "../crypto/crypto_api.h"
#include <string.h>

/* ----------------------------------------------
 * Firmware image metadata
 * ---------------------------------------------- */

/**
 * Firmware image header (prepended to the binary by the build/signing tool):
 *
 *   [magic: 4 bytes, "QSAC"]
 *   [version: 4 bytes]
 *   [image_size: 4 bytes, excluding this header]
 *   [sig_algo: 1 byte, 0x01=ML-DSA, 0x02=SLH-DSA]
 *   [reserved: 3 bytes]
 *   [signature: variable length, depends on sig_algo]
 *   [image data follows]
 */

#define QSAC_FW_MAGIC          0x51534143  /* "QSAC" in little-endian */
#define QSAC_SIG_ALGO_MLDSA    0x01
#define QSAC_SIG_ALGO_SLHDSA   0x02

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t image_size;
    uint8_t  sig_algo;
    uint8_t  reserved[3];
} __attribute__((packed)) qsac_fw_header_t;

/* ----------------------------------------------
 * Manufacturer public key (trust anchor, in HSM)
 * ---------------------------------------------- */

static uint8_t g_manufacturer_pubkey[QSAC_MLDSA_PUBKEY_SIZE];
static uint8_t g_manufacturer_key_loaded = 0;

/**
 * @brief Load the manufacturer's signing public key from HSM.
 */
qsac_status_t qsac_secboot_load_manufacturer_key(const uint8_t *pubkey)
{
    if (!pubkey) {
        return QSAC_ERR_INVALID_PARAM;
    }
    memcpy(g_manufacturer_pubkey, pubkey, QSAC_MLDSA_PUBKEY_SIZE);
    g_manufacturer_key_loaded = 1;
    return QSAC_OK;
}

/* ----------------------------------------------
 * Secure boot verification
 * ---------------------------------------------- */

/**
 * @brief Verify a firmware image's PQC signature.
 *
 * Called by the bootloader before jumping to the application.
 * If verification fails, the device must NOT boot the image.
 *
 * @param fw_base   Pointer to the start of the firmware image (including header).
 * @param total_len Total length of the image in flash (header + signature + data).
 * @return QSAC_OK if the image is authentic, QSAC_ERR_VERIFY_FAIL otherwise.
 */
qsac_status_t qsac_secboot_verify(const uint8_t *fw_base, size_t total_len)
{
    const qsac_fw_header_t *hdr;
    const uint8_t *signature;
    const uint8_t *image_data;
    size_t sig_size;
    size_t expected_total;

    if (!fw_base || !g_manufacturer_key_loaded) {
        return QSAC_ERR_INVALID_PARAM;
    }

    hdr = (const qsac_fw_header_t *)fw_base;

    /* Validate magic */
    if (hdr->magic != QSAC_FW_MAGIC) {
        return QSAC_ERR_VERIFY_FAIL;
    }

    /* Determine signature size based on algorithm */
    switch (hdr->sig_algo) {
    case QSAC_SIG_ALGO_MLDSA:
        sig_size = QSAC_MLDSA_SIG_SIZE;
        break;
    case QSAC_SIG_ALGO_SLHDSA:
        sig_size = QSAC_SLHDSA_SIG_SIZE;
        break;
    default:
        return QSAC_ERR_INVALID_PARAM;
    }

    /* Validate total size consistency */
    expected_total = sizeof(qsac_fw_header_t) + sig_size + hdr->image_size;
    if (total_len < expected_total) {
        return QSAC_ERR_VERIFY_FAIL;
    }

    /* Locate signature and image data */
    signature  = fw_base + sizeof(qsac_fw_header_t);
    image_data = signature + sig_size;

    /* Verify the PQC signature over the image data.
     *
     * Note: We verify over the raw image bytes. The header fields
     * (version, size) should also be authenticated; a production
     * implementation would hash header + image together.
     *
     * TODO Phase 5: Include header in the signed payload. */

    if (hdr->sig_algo == QSAC_SIG_ALGO_MLDSA) {
        return qsac_mldsa_verify(g_manufacturer_pubkey,
                                  image_data, hdr->image_size,
                                  signature);
    }

    /* TODO Phase 5: Implement SLH-DSA verification path.
     * SLH-DSA verify is expected to be cheap; signing (which happens
     * off-device at build time) is the expensive part. */
    return QSAC_ERR_NOT_IMPLEMENTED;
}
