/**
 * @file PROTOCOL_uart_bridge.h
 * @brief Live UART / USB-CDC binary framing bridge for host communication.
 */

#ifndef PROTOCOL_UART_BRIDGE_H
#define PROTOCOL_UART_BRIDGE_H

#include "crypto/crypto_api.h"
#include "protocol/PROTOCOL_handshake.h"
#include "protocol/PROTOCOL_state_machine.h"
#include "protocol/PROTOCOL_token_verify.h"
#include <stdint.h>
#include <stddef.h>

#define OP_PING              0x01
#define OP_PONG              0x81
#define OP_HANDSHAKE_INIT    0x02
#define OP_CLIENT_HELLO      0x82
#define OP_SERVER_HELLO      0x03
#define OP_CLIENT_FINISHED   0x83
#define OP_SUBMIT_TOKEN      0x04
#define OP_TOKEN_RESULT      0x84
#define OP_ENCRYPTED_MSG     0x05
#define OP_ENCRYPTED_RESP    0x85
#define OP_RUN_BENCHMARKS    0x09
#define OP_BENCHMARK_REPORT  0x89
#define OP_TVLA_REQUEST      0x0B
#define OP_TVLA_SAMPLE       0x8B
#define OP_ERROR             0xFF

/**
 * @brief Initialize UART protocol bridge and access control state machine.
 */
void qsac_uart_bridge_init(void);

/**
 * @brief Poll UART for incoming frames and process protocol events.
 */
void qsac_uart_bridge_poll(void);

#endif /* PROTOCOL_UART_BRIDGE_H */
