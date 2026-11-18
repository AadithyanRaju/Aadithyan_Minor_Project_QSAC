/**
 * @file qsac_features.h
 * @brief QSAC Firmware Feature Switches & Configuration Settings.
 *
 * Use this header file to easily enable or disable specific firmware features,
 * hardware peripherals, cryptographic coprocessors, and test routines.
 *
 * Set a switch to 1 to enable the feature, or 0 to disable it.
 */

#ifndef QSAC_FEATURES_H
#define QSAC_FEATURES_H

#include "qsac_feature_settings.h"
/* -----------------------------------------------------------------------------
 * FEATURE SWITCHES
 * ----------------------------------------------------------------------------- */

/**
 * @def QSAC_FEATURE_ATECC608B
 * @brief Feature 1: Microchip ATECC608B Hardware Security Module (HSM).
 *
 *  QSAC_FEATURE_ATECC608B_ENABLED = ENABLED:
 *      - Probes and communicates with ATECC608B over I2C0 (GP4 SDA / GP5 SCL).
 *      - Hardware True Random Number Generator (TRNG) active.
 *      - Hardware Key Isolation (keys stored in EEPROM slots 0-15).
 *      - Hardware ECC P-256 (ECDH, ECDSA Sign/Verify) acceleration.
 *      - Hardware SHA-256 engine active.
 *
 *  QSAC_FEATURE_ATECC608B_DISABLED = DISABLED:
 *      - Completely disables ATECC608B probing and I2C initialization.
 *      - Firmware runs in pure software mode (micro-ecc, RP2040 ROSC RNG).
 *      - GP4 (Pin 6) and GP5 (Pin 7) remain unconfigured/untouched.
 */
#ifndef QSAC_FEATURE_ATECC608B
#define QSAC_FEATURE_ATECC608B          QSAC_FEATURE_ATECC608B_ENABLED
#endif

/**
 * @def QSAC_FEATURE_STATUS_LEDS
 * @brief Feature 2: Hardware Status Indicator LEDs (GP6 - GP16).
 *
 *  1 = ENABLED:
 *      - GP6 through GP16 (Physical Pins 9 to 21) are asserted during self-tests.
 *
 *  0 = DISABLED:
 *      - Status pins remain untouched/quiet (useful for low power or test rigs).
 *
 *  NOTE: GP4 (Pin 6) and GP5 (Pin 7) are NEVER used for status LEDs.
 */
#ifndef QSAC_FEATURE_STATUS_LEDS
#define QSAC_FEATURE_STATUS_LEDS        QSAC_FEATURE_STATUS_LEDS_ENABLED
#endif

/**
 * @def QSAC_FEATURE_PQC_MLKEM
 * @brief Feature 3: Post-Quantum Cryptography — ML-KEM-512 (FIPS 203).
 *
 *  1 = ENABLED:
 *      - Software Kyber/ML-KEM-512 key encapsulation and decapsulation active.
 *
 *  0 = DISABLED:
 *      - ML-KEM algorithms and self-tests are skipped.
 */
#ifndef QSAC_FEATURE_PQC_MLKEM
#define QSAC_FEATURE_PQC_MLKEM          QSAC_FEATURE_PQC_MLKEM_ENABLED
#endif

/**
 * @def QSAC_FEATURE_PQC_MLDSA
 * @brief Feature 4: Post-Quantum Cryptography — ML-DSA-44 (FIPS 204).
 *
 *  1 = ENABLED:
 *      - Software Dilithium/ML-DSA-44 keygen, signing, and verification active.
 *
 *  0 = DISABLED:
 *      - ML-DSA algorithms and self-tests are skipped.
 */
#ifndef QSAC_FEATURE_PQC_MLDSA
#define QSAC_FEATURE_PQC_MLDSA          QSAC_FEATURE_PQC_MLDSA_ENABLED
#endif

/**
 * @def QSAC_FEATURE_HYBRID_HANDSHAKE
 * @brief Feature 5: Hybrid Handshake Protocol.
 *
 *  1 = ENABLED:
 *      - Runs the dual-key hybrid handshake (ECDH + ML-KEM + HKDF combiner).
 *
 *  0 = DISABLED:
 *      - Hybrid handshake self-test is skipped.
 */
#ifndef QSAC_FEATURE_HYBRID_HANDSHAKE
#define QSAC_FEATURE_HYBRID_HANDSHAKE     QSAC_FEATURE_HYBRID_HANDSHAKE_ENABLED
#endif

/**
 * @def QSAC_FEATURE_ACCESS_TOKENS
 * @brief Feature 6: Access Control State Machine & ML-DSA Capability Tokens.
 *
 *  1 = ENABLED:
 *      - Access token issuance, validity verification, and session state machine active.
 *
 *  0 = DISABLED:
 *      - Token tests and state machine tests are skipped.
 */
#ifndef QSAC_FEATURE_ACCESS_TOKENS
#define QSAC_FEATURE_ACCESS_TOKENS      QSAC_FEATURE_ACCESS_TOKENS_ENABLED
#endif

/**
 * @def QSAC_FEATURE_UART_GATEWAY
 * @brief Feature 7: Live Host PC UART Protocol Bridge.
 *
 *  1 = ENABLED:
 *      - After self-tests, starts listening on USB-UART for incoming PC server frames.
 *
 *  0 = DISABLED:
 *      - Firmware idles with onboard LED heartbeat without running UART bridge.
 */
#ifndef QSAC_FEATURE_UART_GATEWAY
#define QSAC_FEATURE_UART_GATEWAY       QSAC_FEATURE_UART_GATEWAY_ENABLED
#endif

#endif /* QSAC_FEATURES_H */
