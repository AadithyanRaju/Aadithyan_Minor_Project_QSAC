/**
 * @file atecc608b.c
 * @brief Microchip ATECC608B Cryptographic Co-Processor / HSM Driver Implementation.
 */

#include "atecc608b.h"
#include "hal/hal.h"
#include <string.h>
#include <stdio.h>

/* ----------------------------------------------
 * Module State
 * ---------------------------------------------- */

static atecc608b_info_t g_atecc_info = {
    .present = false,
    .serial_number = {0},
    .revision = 0,
    .config_locked = false,
    .data_locked = false
};

/* ----------------------------------------------
 * CRC-16 Calculation (Microchip Polynomial 0x8005)
 * ---------------------------------------------- */

static void atecc_calc_crc(size_t len, const uint8_t *data, uint8_t *crc)
{
    uint16_t crc_reg = 0;
    for (size_t counter = 0; counter < len; counter++) {
        for (uint8_t shift = 0x01; shift > 0x00; shift <<= 1) {
            uint8_t data_bit = (data[counter] & shift) ? 1 : 0;
            uint8_t crc_bit = (crc_reg >> 15) & 1;
            crc_reg <<= 1;
            if (data_bit != crc_bit) {
                crc_reg ^= 0x8005;
            }
        }
    }
    crc[0] = (uint8_t)(crc_reg & 0xFF);
    crc[1] = (uint8_t)(crc_reg >> 8);
}

/* ----------------------------------------------
 * Power Management & Bus Control
 * ---------------------------------------------- */

int atecc608b_wakeup(void)
{
    hal_i2c_wake_pulse();
    hal_delay_us(1500); /* t_WHI = 1.5 ms typical */

    uint8_t rx[4] = {0};
    int ret = hal_i2c_read(ATECC_I2C_ADDR_DEFAULT, rx, sizeof(rx));
    if (ret < 0) {
        /* Retry wake once if bus was busy */
        hal_delay_ms(2);
        hal_i2c_wake_pulse();
        hal_delay_us(1500);
        ret = hal_i2c_read(ATECC_I2C_ADDR_DEFAULT, rx, sizeof(rx));
    }

    if (ret >= 0 && rx[0] == 0x04 && rx[1] == 0x11) {
        return 0; /* Successfully woke up with valid wake signature */
    }

    /* Even if wake signature read was missed due to clock stretching,
     * if the chip responds to subsequent command polling, wake succeeded. */
    return (ret >= 0) ? 0 : -1;
}

void atecc608b_sleep(void)
{
    uint8_t sleep_cmd = ATECC_WORD_ADDR_SLEEP;
    hal_i2c_write(ATECC_I2C_ADDR_DEFAULT, &sleep_cmd, 1);
    hal_delay_us(500);
}

void atecc608b_idle(void)
{
    uint8_t idle_cmd = ATECC_WORD_ADDR_IDLE;
    hal_i2c_write(ATECC_I2C_ADDR_DEFAULT, &idle_cmd, 1);
    hal_delay_us(500);
}

/* ----------------------------------------------
 * Low-Level Command Send & Response Receive
 * ---------------------------------------------- */

static int atecc_execute_command(uint8_t opcode, uint8_t param1, uint16_t param2,
                                 const uint8_t *data, size_t data_len,
                                 uint8_t *response, size_t max_rsp_len,
                                 uint32_t wait_ms, uint32_t timeout_ms)
{
    uint8_t tx_buf[ATECC_CMD_BUF_SIZE];
    uint8_t count = (uint8_t)(1 + 1 + 1 + 2 + data_len + 2);

    if ((size_t)(count + 1) > sizeof(tx_buf)) {
        return -1;
    }

    /* Packet framing: [Word Address (0x03)] [Count] [Opcode] [Param1] [Param2 LSB] [Param2 MSB] [Data...] [CRC16] */
    tx_buf[0] = ATECC_WORD_ADDR_COMMAND;
    tx_buf[1] = count;
    tx_buf[2] = opcode;
    tx_buf[3] = param1;
    tx_buf[4] = (uint8_t)(param2 & 0xFF);
    tx_buf[5] = (uint8_t)((param2 >> 8) & 0xFF);

    if (data && data_len > 0) {
        memcpy(&tx_buf[6], data, data_len);
    }

    /* Calculate CRC over tx_buf[1] .. tx_buf[5 + data_len] */
    atecc_calc_crc(count - 2, &tx_buf[1], &tx_buf[6 + data_len]);

    /* Ensure device is awake */
    atecc608b_wakeup();

    /* Send command */
    int w_ret = hal_i2c_write(ATECC_I2C_ADDR_DEFAULT, tx_buf, count + 1);
    if (w_ret < 0) {
        atecc608b_sleep();
        return -2;
    }

    /* Execution delay */
    if (wait_ms > 0) {
        hal_delay_ms(wait_ms);
    }

    /* Poll for response */
    uint32_t elapsed = wait_ms;
    uint8_t rx_buf[ATECC_RSP_BUF_SIZE] = {0};
    int r_ret = -1;

    while (elapsed < timeout_ms) {
        /* Read count byte first, or attempt small read */
        r_ret = hal_i2c_read(ATECC_I2C_ADDR_DEFAULT, rx_buf, sizeof(rx_buf));
        if (r_ret > 0 && rx_buf[0] >= 4) {
            break;
        }
        hal_delay_ms(2);
        elapsed += 2;
    }

    atecc608b_idle();

    if (r_ret <= 0 || rx_buf[0] < 4) {
        return -3; /* Timeout / no response */
    }

    uint8_t rsp_len = rx_buf[0];
    if (rsp_len > sizeof(rx_buf)) {
        return -4;
    }

    /* Verify CRC */
    uint8_t expected_crc[2];
    atecc_calc_crc(rsp_len - 2, rx_buf, expected_crc);
    if (rx_buf[rsp_len - 2] != expected_crc[0] || rx_buf[rsp_len - 1] != expected_crc[1]) {
        return -5; /* CRC mismatch */
    }

    /* Check for error code response: [0x04, error_code, CRC_L, CRC_H] */
    if (rsp_len == 4 && rx_buf[1] != 0x00) {
        return -(100 + rx_buf[1]); /* Returns negative device error */
    }

    size_t copy_len = rsp_len - 3; /* Exclude Count and 2-byte CRC */
    if (copy_len > max_rsp_len) {
        copy_len = max_rsp_len;
    }

    if (response && copy_len > 0) {
        memcpy(response, &rx_buf[1], copy_len);
    }

    return (int)copy_len;
}

/* ----------------------------------------------
 * Public Device Information Queries
 * ---------------------------------------------- */

bool atecc608b_is_present(void)
{
    return g_atecc_info.present;
}

const atecc608b_info_t *atecc608b_get_info(void)
{
    return &g_atecc_info;
}

int atecc608b_init(atecc608b_info_t *info)
{
    memset(&g_atecc_info, 0, sizeof(g_atecc_info));

    /* Attempt to wake the device */
    if (atecc608b_wakeup() < 0) {
        return -1;
    }

    /* Read Device Revision (Info command, mode 0x00) */
    uint8_t rev_buf[4] = {0};
    int ret = atecc_execute_command(ATECC_OP_INFO, 0x00, 0x0000, NULL, 0,
                                   rev_buf, sizeof(rev_buf), 1, 30);
    if (ret < 4) {
        atecc608b_sleep();
        return -2;
    }

    g_atecc_info.revision = ((uint32_t)rev_buf[0] << 24) |
                            ((uint32_t)rev_buf[1] << 16) |
                            ((uint32_t)rev_buf[2] << 8)  |
                            ((uint32_t)rev_buf[3]);

    /* Read Config Zone Block 0 (32 bytes) to obtain Serial Number bytes:
     * SN[0..3] = config[0..3], SN[4..8] = config[8..12] */
    uint8_t cfg_block0[32] = {0};
    ret = atecc_execute_command(ATECC_OP_READ, 0x80, 0x0000, NULL, 0,
                                cfg_block0, sizeof(cfg_block0), 1, 30);
    if (ret >= 32) {
        memcpy(&g_atecc_info.serial_number[0], &cfg_block0[0], 4);
        memcpy(&g_atecc_info.serial_number[4], &cfg_block0[8], 5);
    }

    /* Read Config Zone Block 2 (32 bytes, offset 64..95) to inspect Lock Bytes:
     * Byte 86 (index 22): LockConfig (0x55 = unlocked, 0x00 = locked)
     * Byte 87 (index 23): LockValue  (0x55 = unlocked, 0x00 = locked)
     * Block 2 address = (2 << 3) = 0x0010 */
    uint8_t cfg_block2[32] = {0};
    ret = atecc_execute_command(ATECC_OP_READ, 0x80, 0x0010, NULL, 0,
                                cfg_block2, sizeof(cfg_block2), 1, 30);
    if (ret >= 32) {
        g_atecc_info.config_locked = (cfg_block2[22] == 0x00);
        g_atecc_info.data_locked   = (cfg_block2[23] == 0x00);
    }

    g_atecc_info.present = true;

    if (info) {
        memcpy(info, &g_atecc_info, sizeof(atecc608b_info_t));
    }

    atecc608b_sleep();
    return 0;
}

/* ----------------------------------------------
 * Hardware TRNG
 * ---------------------------------------------- */

int atecc608b_random(uint8_t *rand_out)
{
    if (!rand_out) {
        return -1;
    }

    /* Opcode 0x1B, Param1 0x00 (update seed), Param2 0x0000. Wait ~23 ms. */
    int ret = atecc_execute_command(ATECC_OP_RANDOM, 0x00, 0x0000, NULL, 0,
                                    rand_out, ATECC_RANDOM_SIZE, 23, 60);
    atecc608b_sleep();
    return (ret == ATECC_RANDOM_SIZE) ? 0 : -2;
}

/* ----------------------------------------------
 * Hardware SHA-256
 * ---------------------------------------------- */

int atecc608b_sha256(const uint8_t *data, size_t len, uint8_t *digest32)
{
    if (!digest32 || (len > 0 && !data)) {
        return -1;
    }

    if (len <= 64) {
        /* Single-block SHA computation (Start + End) */
        /* Step 1: Start (mode 0x00) */
        int ret = atecc_execute_command(ATECC_OP_SHA, 0x00, 0x0000, NULL, 0,
                                        NULL, 0, 7, 30);
        if (ret < 0 && ret != 0) {
            atecc608b_sleep();
            return -2;
        }

        /* Step 2: End (mode 0x02), param2 = length */
        ret = atecc_execute_command(ATECC_OP_SHA, 0x02, (uint16_t)len, data, len,
                                    digest32, ATECC_DIGEST_SIZE, 9, 40);
        atecc608b_sleep();
        return (ret == ATECC_DIGEST_SIZE) ? 0 : -3;
    }

    /* For arbitrary long payloads, process in 64-byte chunks */
    int ret = atecc_execute_command(ATECC_OP_SHA, 0x00, 0x0000, NULL, 0, NULL, 0, 7, 30);
    if (ret < 0 && ret != 0) {
        atecc608b_sleep();
        return -2;
    }

    size_t offset = 0;
    while (offset + 64 <= len) {
        ret = atecc_execute_command(ATECC_OP_SHA, 0x01, 64, &data[offset], 64, NULL, 0, 7, 30);
        if (ret < 0 && ret != 0) {
            atecc608b_sleep();
            return -4;
        }
        offset += 64;
    }

    size_t rem = len - offset;
    ret = atecc_execute_command(ATECC_OP_SHA, 0x02, (uint16_t)rem,
                                (rem > 0) ? &data[offset] : NULL, rem,
                                digest32, ATECC_DIGEST_SIZE, 9, 40);
    atecc608b_sleep();
    return (ret == ATECC_DIGEST_SIZE) ? 0 : -5;
}

/* ----------------------------------------------
 * Hardware ECC P-256 Operations
 * ---------------------------------------------- */

int atecc608b_genkey(uint16_t slot, uint8_t *pubkey)
{
    if (!pubkey || slot > 15) {
        return -1;
    }

    /* GenKey mode 0x04: Generate private key in slot, return 64-byte public key. Wait ~60 ms. */
    int ret = atecc_execute_command(ATECC_OP_GENKEY, 0x04, slot, NULL, 0,
                                    pubkey, ATECC_PUBKEY_SIZE, 50, 150);
    atecc608b_sleep();
    return (ret == ATECC_PUBKEY_SIZE) ? 0 : -2;
}

int atecc608b_ecdh(uint16_t slot, const uint8_t *peer_pubkey, uint8_t *shared_secret)
{
    if (!peer_pubkey || !shared_secret || slot > 15) {
        return -1;
    }

    /* ECDH mode 0x00: Clear output, slot private key * peer_pubkey. Wait ~60 ms. */
    int ret = atecc_execute_command(ATECC_OP_ECDH, 0x00, slot, peer_pubkey, ATECC_PUBKEY_SIZE,
                                    shared_secret, ATECC_SHARED_SECRET_SIZE, 50, 150);
    atecc608b_sleep();
    return (ret == ATECC_SHARED_SECRET_SIZE) ? 0 : -2;
}

static int atecc_load_tempkey(const uint8_t *data32)
{
    /* Load 32-byte data into TempKey using Nonce pass-through (mode 0x03) */
    uint8_t zero_pad[64] = {0};
    memcpy(zero_pad, data32, 32);

    int ret = atecc_execute_command(ATECC_OP_NONCE, 0x03, 0x0000, zero_pad, 32,
                                    NULL, 0, 5, 30);
    return (ret == 0 || ret >= 0) ? 0 : -1;
}

int atecc608b_sign(uint16_t slot, const uint8_t *digest, uint8_t *sig)
{
    if (!digest || !sig || slot > 15) {
        return -1;
    }

    /* Step 1: Load 32-byte digest into TempKey */
    if (atecc_load_tempkey(digest) < 0) {
        atecc608b_sleep();
        return -2;
    }

    /* Step 2: Sign TempKey using private key in slot (mode 0x80 = external message). Wait ~60 ms. */
    int ret = atecc_execute_command(ATECC_OP_SIGN, 0x80, slot, NULL, 0,
                                    sig, ATECC_SIG_SIZE, 50, 150);
    atecc608b_sleep();
    return (ret == ATECC_SIG_SIZE) ? 0 : -3;
}

int atecc608b_verify(const uint8_t *pubkey, const uint8_t *digest, const uint8_t *sig)
{
    if (!pubkey || !digest || !sig) {
        return -1;
    }

    /* Step 1: Load 32-byte digest into TempKey */
    if (atecc_load_tempkey(digest) < 0) {
        atecc608b_sleep();
        return -2;
    }

    /* Step 2: Verify command (mode 0x02 = external verify).
     * Data buffer: 64 bytes signature (R || S) followed by 64 bytes public key (X || Y) */
    uint8_t verify_data[128];
    memcpy(&verify_data[0], sig, ATECC_SIG_SIZE);
    memcpy(&verify_data[64], pubkey, ATECC_PUBKEY_SIZE);

    /* Curve P-256 = Param2 0x0004. Wait ~60 ms. */
    uint8_t status_byte = 0xFF;
    int ret = atecc_execute_command(ATECC_OP_VERIFY, 0x02, 0x0004,
                                    verify_data, sizeof(verify_data),
                                    &status_byte, 1, 50, 150);
    atecc608b_sleep();

    /* A successful verify returns status byte 0x00 */
    return (ret >= 0 && status_byte == 0x00) ? 0 : -3;
}
