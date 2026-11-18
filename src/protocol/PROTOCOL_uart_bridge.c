/**
 * @file PROTOCOL_uart_bridge.c
 * @brief Live UART / USB-CDC binary framing bridge for host communication.
 */

#include "protocol/PROTOCOL_uart_bridge.h"
#include "protocol/PROTOCOL_handshake.h"
#include "protocol/PROTOCOL_state_machine.h"
#include "protocol/PROTOCOL_token_verify.h"
#include "benchmarks/BENCHMARKS_runner.h"
#include "hal/hal.h"
#if defined(QSAC_PLATFORM_PICO)
#include "pico/stdlib.h"
#include "hardware/timer.h"
#endif
#include <string.h>

#define SYNC_BYTE_0 0xAA
#define SYNC_BYTE_1 0x55

#define RX_BUFFER_SIZE 4096

typedef enum {
    RX_STATE_SYNC0 = 0,
    RX_STATE_SYNC1,
    RX_STATE_LEN_H,
    RX_STATE_LEN_L,
    RX_STATE_OPCODE,
    RX_STATE_SEQ,
    RX_STATE_PAYLOAD,
    RX_STATE_CRC_H,
    RX_STATE_CRC_L
} rx_state_t;

/* Static protocol buffers in BSS to prevent stack overflow */
static uint8_t rx_payload[RX_BUFFER_SIZE];
static uint16_t rx_expected_len;
static uint16_t rx_payload_index;
static uint8_t rx_opcode;
static uint8_t rx_seq;
static uint8_t rx_crc_h;
static rx_state_t rx_state = RX_STATE_SYNC0;

static qsac_handshake_client_ctx_t hs_client_ctx;
static qsac_client_hello_t hs_client_hello;
static qsac_server_hello_t hs_server_hello;
static qsac_client_finished_t hs_client_fin;
static qsac_state_machine_t access_sm;
static qsac_access_token_t incoming_token;

static uint8_t server_mldsa_pubkey[QSAC_MLDSA_PUBKEY_SIZE];
static uint8_t authority_mldsa_pubkey[QSAC_MLDSA_PUBKEY_SIZE];
static int authority_key_provisioned = 0;
static uint8_t g_active_session_key[QSAC_SESSION_KEY_SIZE];
static int g_session_established = 0;
static uint32_t g_last_rx_counter = 0;
static int g_counter_initialized = 0;

static void send_frame(uint8_t opcode, uint8_t seq, const uint8_t *payload, uint16_t len)
{
    uint8_t header[6];
    header[0] = SYNC_BYTE_0;
    header[1] = SYNC_BYTE_1;
    header[2] = (uint8_t)((len >> 8) & 0xFF);
    header[3] = (uint8_t)(len & 0xFF);
    header[4] = opcode;
    header[5] = seq;

    /* Compute CRC over header[2..5] and payload */
    uint16_t crc = 0xFFFF;
    for (int i = 2; i < 6; i++) {
        crc ^= ((uint16_t)header[i] << 8);
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }
    for (size_t i = 0; i < len; i++) {
        crc ^= ((uint16_t)payload[i] << 8);
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc = crc << 1;
            }
        }
    }

    uint8_t crc_bytes[2];
    crc_bytes[0] = (uint8_t)((crc >> 8) & 0xFF);
    crc_bytes[1] = (uint8_t)(crc & 0xFF);

    hal_uart_write(header, 6);
    if (len > 0 && payload != NULL) {
        hal_uart_write(payload, len);
    }
    hal_uart_write(crc_bytes, 2);
}

void qsac_uart_bridge_init(void)
{
    rx_state = RX_STATE_SYNC0;
    rx_payload_index = 0;
    qsac_sm_init(&access_sm);
}

static uint8_t g_bench_seq_counter = 0;
static void bench_cb(const qsac_benchmark_record_t *rec) {
    send_frame(OP_BENCHMARK_REPORT, g_bench_seq_counter++, (const uint8_t *)rec, sizeof(*rec));
}

static uint8_t g_tvla_seq_counter = 0;
static void tvla_cb(const qsac_tvla_sample_t *sample) {
    send_frame(OP_TVLA_SAMPLE, g_tvla_seq_counter++, (const uint8_t *)sample, sizeof(*sample));
}

static void handle_rx_frame(uint8_t opcode, uint8_t seq, const uint8_t *payload, uint16_t len)
{
    switch (opcode) {
        case OP_PING: {
            const char *pong_msg = "PICO-RP2040-QSAC-v0.1.0";
            send_frame(OP_PONG, seq, (const uint8_t *)pong_msg, (uint16_t)strlen(pong_msg));
            break;
        }

        case OP_HANDSHAKE_INIT: {
            /* Payload contains Server ML-DSA-44 Public Key (1312 bytes) */
            if (len >= QSAC_MLDSA_PUBKEY_SIZE) {
                memcpy(server_mldsa_pubkey, payload, QSAC_MLDSA_PUBKEY_SIZE);
                memcpy(authority_mldsa_pubkey, payload, QSAC_MLDSA_PUBKEY_SIZE);
                qsac_token_load_authority_key(authority_mldsa_pubkey);
                authority_key_provisioned = 1;
            }

            /* Initialize Handshake Client Context */
            qsac_handshake_client_init(&hs_client_ctx, 0x10);
            qsac_status_t st = qsac_handshake_client_create_hello(&hs_client_ctx, &hs_client_hello);
            if (st == QSAC_OK) {
                /* ClientHello payload: client_nonce (32B) + ecdh_pubkey (64B) + mlkem_pubkey (800B) = 896B */
                uint8_t hello_payload[sizeof(qsac_client_hello_t)];
                memcpy(hello_payload, hs_client_hello.client_nonce, QSAC_NONCE_SIZE);
                memcpy(hello_payload + QSAC_NONCE_SIZE, hs_client_hello.ecdh_pubkey, QSAC_ECC_PUBKEY_SIZE);
                memcpy(hello_payload + QSAC_NONCE_SIZE + QSAC_ECC_PUBKEY_SIZE,
                       hs_client_hello.mlkem_pubkey, QSAC_MLKEM_PUBKEY_SIZE);

                send_frame(OP_CLIENT_HELLO, seq, hello_payload, sizeof(hello_payload));
                qsac_sm_process_event(&access_sm, QSAC_EVT_CONNECT_TRIGGER, NULL);
            } else {
                int32_t err = st;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
            }
            break;
        }

        case OP_SERVER_HELLO: {
            /* Payload format: server_nonce (32B) + ecdh_pubkey (64B) + mlkem_ct (768B) + mldsa_sig (2420B) = 3284B */
            if (len < sizeof(qsac_server_hello_t)) {
                int32_t err = QSAC_ERR_INVALID_PARAM;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }

            memcpy(hs_server_hello.server_nonce, payload, QSAC_NONCE_SIZE);
            memcpy(hs_server_hello.ecdh_pubkey, payload + QSAC_NONCE_SIZE, QSAC_ECC_PUBKEY_SIZE);
            memcpy(hs_server_hello.mlkem_ciphertext,
                   payload + QSAC_NONCE_SIZE + QSAC_ECC_PUBKEY_SIZE,
                   QSAC_MLKEM_CIPHERTEXT_SIZE);
            memcpy(hs_server_hello.mldsa_signature,
                   payload + QSAC_NONCE_SIZE + QSAC_ECC_PUBKEY_SIZE + QSAC_MLKEM_CIPHERTEXT_SIZE,
                   QSAC_MLDSA_SIG_SIZE);

            qsac_status_t st = qsac_handshake_client_process_server_hello(
                &hs_client_ctx, server_mldsa_pubkey, &hs_server_hello, &hs_client_fin);

            if (st == QSAC_OK) {
                /* Save persistent session key and establish session */
                memcpy(g_active_session_key, hs_client_ctx.session_key, QSAC_SESSION_KEY_SIZE);
                g_session_established = 1;
                g_last_rx_counter = 0;
                g_counter_initialized = 0;

                /* Transition State Machine to SESSION_ESTABLISHED */
                qsac_sm_process_event(&access_sm, QSAC_EVT_HANDSHAKE_OK, hs_client_ctx.session_key);

                /* Send ClientFinished confirmation frame: IV (12B) + Tag (16B) + Encrypted Confirm (32B) + Diagnostic Prefixes (12B) */
                uint8_t fin_buf[sizeof(qsac_client_finished_t) + 12];
                memcpy(fin_buf, hs_client_fin.iv, QSAC_AES_IV_SIZE);
                memcpy(fin_buf + QSAC_AES_IV_SIZE, hs_client_fin.tag, QSAC_AES_TAG_SIZE);
                memcpy(fin_buf + QSAC_AES_IV_SIZE + QSAC_AES_TAG_SIZE,
                       hs_client_fin.encrypted_confirmation,
                       QSAC_HANDSHAKE_CONFIRMATION_SIZE);
                memcpy(fin_buf + 60, hs_client_ctx.session_key, 4);
                memcpy(fin_buf + 64, hs_client_ctx.ecdh_pubkey, 4);
                memcpy(fin_buf + 68, hs_client_ctx.transcript_hash, 4);

                send_frame(OP_CLIENT_FINISHED, seq, fin_buf, sizeof(fin_buf));
            } else {
                int32_t err = st;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
            }
            break;
        }

        case OP_SUBMIT_TOKEN: {
            /* Payload: optional current_time (4B) + token payload (32B) + ML-DSA signature (2420B) */
            uint32_t current_time;
            const uint8_t *token_bytes;

            if (len >= 4 + sizeof(qsac_access_token_t)) {
                memcpy(&current_time, payload, 4);
                token_bytes = payload + 4;
            } else if (len >= sizeof(qsac_access_token_t)) {
                token_bytes = payload;
                const qsac_access_token_t *t = (const qsac_access_token_t *)token_bytes;
                current_time = t->payload.issued_at + 5;
            } else {
                int32_t err = QSAC_ERR_INVALID_PARAM;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }

            memcpy(&incoming_token, token_bytes, sizeof(qsac_access_token_t));
            uint32_t granted_perms = 0;

            qsac_status_t st = qsac_token_verify(&incoming_token, current_time, &granted_perms);

            uint8_t result_buf[8];
            int32_t code = (st == QSAC_OK) ? 0 : (int32_t)st;
            memcpy(result_buf, &code, 4);
            memcpy(result_buf + 4, &granted_perms, 4);

            if (st == QSAC_OK) {
                qsac_sm_process_event(&access_sm, QSAC_EVT_TOKEN_VALID, &granted_perms);
                /* Physical Access Trigger: blink LED & pulse GP15 */
                hal_led_set(1);
                hal_status_pin_set(QSAC_STATUS_PIN_SESSION_OK, 1);
                hal_delay_ms(50);
                hal_led_set(0);
            } else {
                qsac_sm_process_event(&access_sm, QSAC_EVT_TOKEN_INVALID, NULL);
            }

            send_frame(OP_TOKEN_RESULT, seq, result_buf, sizeof(result_buf));
            break;
        }

        case OP_ENCRYPTED_MSG: {
            /* Payload: IV (12B) + AAD (4B) + Ciphertext + Tag (16B) */
            if (len < 12 + 4 + 16) {
                int32_t err = QSAC_ERR_INVALID_PARAM;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }

            if (!g_session_established) {
                int32_t err = QSAC_ERR_KEY_NOT_FOUND;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }

            const uint8_t *iv = payload;
            const uint8_t *aad = payload + 12;
            size_t ct_len = len - 12 - 4 - 16;
            const uint8_t *ct = payload + 12 + 4;
            const uint8_t *tag = ct + ct_len;

            uint32_t rx_counter = ((uint32_t)aad[0] << 24) |
                                  ((uint32_t)aad[1] << 16) |
                                  ((uint32_t)aad[2] << 8)  |
                                  ((uint32_t)aad[3]);

            if (g_counter_initialized && rx_counter <= g_last_rx_counter) {
                int32_t err = QSAC_ERR_REPLAY_DETECTED;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }

            static uint8_t decrypted_buf[256];
            if (ct_len >= sizeof(decrypted_buf)) {
                ct_len = sizeof(decrypted_buf) - 1;
            }

            qsac_status_t st = qsac_aes_gcm_decrypt(
                g_active_session_key,
                iv,
                aad, 4,
                ct, ct_len,
                tag,
                decrypted_buf);

            if (st == QSAC_OK) {
                g_last_rx_counter = rx_counter;
                g_counter_initialized = 1;

                decrypted_buf[ct_len] = '\0';
                /* Form encrypted response */
                const char *resp_text = "PICO: Secure Actuator Active | Door: OPEN | Health: NOMINAL";
                size_t resp_len = strlen(resp_text);

                static uint8_t resp_payload[300];
                static uint8_t resp_iv[12];
                static uint8_t resp_tag[16];
                qsac_random_bytes(resp_iv, sizeof(resp_iv));

                st = qsac_aes_gcm_encrypt(
                    g_active_session_key,
                    resp_iv,
                    aad, 4,
                    (const uint8_t *)resp_text, resp_len,
                    resp_payload + 16, /* ct location */
                    resp_tag);

                if (st == QSAC_OK) {
                    memcpy(resp_payload, resp_iv, 12);
                    memcpy(resp_payload + 12, aad, 4);
                    memcpy(resp_payload + 16 + resp_len, resp_tag, 16);
                    send_frame(OP_ENCRYPTED_RESP, seq, resp_payload, (uint16_t)(16 + resp_len + 16));
                }
            } else {
                int32_t err = st;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
            }
            break;
        }

        case OP_RUN_BENCHMARKS: {
            g_bench_seq_counter = seq;
            qsac_benchmarks_run_all(bench_cb);

            /* End marker record */
            qsac_benchmark_record_t end_rec;
            memset(&end_rec, 0, sizeof(end_rec));
            strncpy(end_rec.name, "BENCHMARKS_COMPLETE", sizeof(end_rec.name) - 1);
            send_frame(OP_BENCHMARK_REPORT, g_bench_seq_counter++, (const uint8_t *)&end_rec, sizeof(end_rec));
            break;
        }

        case OP_TVLA_REQUEST: {
            /* Payload: primitive_id (1B) + class_id (1B) + count (2B uint16_t LE) */
            if (len < 4) {
                int32_t err = QSAC_ERR_INVALID_PARAM;
                send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
                return;
            }
            uint8_t prim_id = payload[0];
            uint8_t class_id = payload[1];
            uint16_t count = (uint16_t)payload[2] | ((uint16_t)payload[3] << 8);

            g_tvla_seq_counter = seq;
            qsac_tvla_run(prim_id, class_id, count, tvla_cb);

            /* End marker sample: sample_index = 0xFFFF */
            qsac_tvla_sample_t end_sample;
            memset(&end_sample, 0, sizeof(end_sample));
            end_sample.sample_index = 0xFFFF;
            send_frame(OP_TVLA_SAMPLE, g_tvla_seq_counter++, (const uint8_t *)&end_sample, sizeof(end_sample));
            break;
        }

        default: {
            int32_t err = QSAC_ERR_NOT_IMPLEMENTED;
            send_frame(OP_ERROR, seq, (const uint8_t *)&err, sizeof(err));
            break;
        }
    }
}

void qsac_uart_bridge_poll(void)
{
#if defined(QSAC_PLATFORM_PICO)
    static uint64_t last_rx_us = 0;
    uint64_t now_us = time_us_64();
    if (rx_state != RX_STATE_SYNC0 && (now_us - last_rx_us > 50000)) { // 50ms inter-byte timeout
        rx_state = RX_STATE_SYNC0;
        rx_payload_index = 0;
    }
#endif

    while (1) {
        int c = hal_uart_getc_nonblocking();
        if (c < 0) {
            break;
        }
#if defined(QSAC_PLATFORM_PICO)
        last_rx_us = time_us_64();
#endif
        uint8_t byte = (uint8_t)c;

        switch (rx_state) {
            case RX_STATE_SYNC0:
                if (byte == SYNC_BYTE_0) {
                    rx_state = RX_STATE_SYNC1;
                }
                break;

            case RX_STATE_SYNC1:
                if (byte == SYNC_BYTE_1) {
                    rx_state = RX_STATE_LEN_H;
                } else if (byte != SYNC_BYTE_0) {
                    rx_state = RX_STATE_SYNC0;
                }
                break;

            case RX_STATE_LEN_H:
                rx_expected_len = ((uint16_t)byte) << 8;
                rx_state = RX_STATE_LEN_L;
                break;

            case RX_STATE_LEN_L:
                rx_expected_len |= (uint16_t)byte;
                if (rx_expected_len > RX_BUFFER_SIZE) {
                    rx_state = RX_STATE_SYNC0;
                } else {
                    rx_state = RX_STATE_OPCODE;
                }
                break;

            case RX_STATE_OPCODE:
                rx_opcode = byte;
                rx_state = RX_STATE_SEQ;
                break;

            case RX_STATE_SEQ:
                rx_seq = byte;
                rx_payload_index = 0;
                if (rx_expected_len == 0) {
                    rx_state = RX_STATE_CRC_H;
                } else {
                    rx_state = RX_STATE_PAYLOAD;
                }
                break;

            case RX_STATE_PAYLOAD:
                rx_payload[rx_payload_index++] = byte;
                if (rx_payload_index >= rx_expected_len) {
                    rx_state = RX_STATE_CRC_H;
                }
                break;

            case RX_STATE_CRC_H:
                rx_crc_h = byte;
                rx_state = RX_STATE_CRC_L;
                break;

            case RX_STATE_CRC_L: {
                uint16_t received_crc = (((uint16_t)rx_crc_h) << 8) | (uint16_t)byte;

                /* Compute CRC over header[2..5] and payload */
                uint8_t header_check[4];
                header_check[0] = (uint8_t)((rx_expected_len >> 8) & 0xFF);
                header_check[1] = (uint8_t)(rx_expected_len & 0xFF);
                header_check[2] = rx_opcode;
                header_check[3] = rx_seq;

                uint16_t computed_crc = 0xFFFF;
                for (int i = 0; i < 4; i++) {
                    computed_crc ^= ((uint16_t)header_check[i] << 8);
                    for (int j = 0; j < 8; j++) {
                        if (computed_crc & 0x8000) {
                            computed_crc = (computed_crc << 1) ^ 0x1021;
                        } else {
                            computed_crc = computed_crc << 1;
                        }
                    }
                }
                for (size_t i = 0; i < rx_expected_len; i++) {
                    computed_crc ^= ((uint16_t)rx_payload[i] << 8);
                    for (int j = 0; j < 8; j++) {
                        if (computed_crc & 0x8000) {
                            computed_crc = (computed_crc << 1) ^ 0x1021;
                        } else {
                            computed_crc = computed_crc << 1;
                        }
                    }
                }

                if (computed_crc == received_crc) {
                    handle_rx_frame(rx_opcode, rx_seq, rx_payload, rx_expected_len);
                }
                rx_state = RX_STATE_SYNC0;
                break;
            }

            default:
                rx_state = RX_STATE_SYNC0;
                break;
        }
    }
}
