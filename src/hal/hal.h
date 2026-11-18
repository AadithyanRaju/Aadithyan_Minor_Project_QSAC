/**
 * @file hal.h
 * @brief Hardware Abstraction Layer for QSAC.
 *
 * Provides a platform-independent interface for:
 *   - System initialization (clocks, peripherals)
 *   - UART output (logging / debug)
 *   - Cycle-count instrumentation (DWT on ARM, clock_gettime on host)
 *   - GPIO (LED for status indication)
 *
 * Implementations:
 *   - stm32h5_hal.c  — real hardware (STM32H5 Nucleo)
 *   - host_hal.c     — host simulation (Linux/macOS, for dev/test)
 */

#ifndef QSAC_HAL_H
#define QSAC_HAL_H

#include "qsac_features.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------
 * System
 * ---------------------------------------------- */

/**
 * @brief Initialize the platform: clocks, GPIO, UART, peripherals.
 */
void hal_system_init(void);

/**
 * @brief Get the system clock frequency in Hz.
 */
uint32_t hal_get_sysclk_hz(void);

/**
 * @brief Spin-delay for the specified number of milliseconds.
 */
void hal_delay_ms(uint32_t ms);

/**
 * @brief Spin-delay for the specified number of microseconds.
 */
void hal_delay_us(uint32_t us);

/* ----------------------------------------------
 * I2C Interface (for external Secure Elements / HSM)
 * ---------------------------------------------- */

#define QSAC_I2C_DEFAULT_BAUDRATE   100000  /* 100 kHz standard mode */
#define QSAC_I2C_FAST_BAUDRATE      400000  /* 400 kHz fast mode */

/**
 * @brief Initialize the hardware I2C peripheral for secure element communication.
 * @param baudrate  Baud rate in Hz (e.g. 100000 or 400000).
 * @return 0 on success, negative error code on failure.
 */
int hal_i2c_init(uint32_t baudrate);

/**
 * @brief Perform a wake pulse for ATECC608B (holds SDA low for >= 60 us).
 */
void hal_i2c_wake_pulse(void);

/**
 * @brief Write data over I2C to a slave address.
 * @param addr      7-bit slave address.
 * @param data      Pointer to data buffer.
 * @param len       Number of bytes to write.
 * @return Number of bytes written, or negative on error.
 */
int hal_i2c_write(uint8_t addr, const uint8_t *data, size_t len);

/**
 * @brief Read data over I2C from a slave address.
 * @param addr      7-bit slave address.
 * @param buf       Pointer to destination buffer.
 * @param len       Number of bytes to read.
 * @return Number of bytes read, or negative on error.
 */
int hal_i2c_read(uint8_t addr, uint8_t *buf, size_t len);

/* ----------------------------------------------
 * UART / Logging
 * ---------------------------------------------- */

/**
 * @brief Send a null-terminated string over UART (or stdout on host).
 */
void hal_uart_print(const char *msg);

/**
 * @brief Send a formatted string (printf-style) over UART.
 */
void hal_uart_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * @brief Print a buffer as hex bytes.
 */
void hal_print_hex(const uint8_t *data, size_t len);

/**
 * @brief Read a single character from UART/USB without blocking.
 * @return Character value (0-255) if available, or -1 if no data is available.
 */
int hal_uart_getc_nonblocking(void);

/**
 * @brief Write raw binary buffer to UART/USB.
 */
void hal_uart_write(const uint8_t *data, size_t len);

/* ----------------------------------------------
 * Cycle counter (benchmarking)
 * ---------------------------------------------- */

/**
 * @brief Enable the cycle counter (DWT->CYCCNT on ARM, no-op on host).
 */
void hal_cycle_counter_init(void);

/**
 * @brief Read the current cycle count.
 *
 * On ARM: reads DWT->CYCCNT.
 * On host: returns nanoseconds from clock_gettime, scaled to pseudo-cycles.
 */
uint32_t hal_cycle_count(void);

/* ----------------------------------------------
 * Status LED & GPIO Symbols (GP6 - GP16 on Pico)
 * ---------------------------------------------- */

#define QSAC_GPIO_STATUS_START_PIN  6
#define QSAC_GPIO_STATUS_END_PIN    16
#define QSAC_GPIO_STATUS_NUM_PINS   11

/**
 * EXCLUDED PINS (NEVER used for test/status indications):
 *   GP04 (Physical Pin 6) -> Dedicated to ATECC608B I2C0 SDA
 *   GP05 (Physical Pin 7) -> Dedicated to ATECC608B I2C0 SCL
 *
 * Status indicator pin mapping (Physical board pins in parentheses):
 *   GP6  (Physical Pin 9):   System Initialized / Power-On Ready
 *   GP7  (Physical Pin 10):  Hardware RNG Active & Valid
 *   GP8  (Physical Pin 11):  SHA-256 Hashing Active & Valid
 *   GP9  (Physical Pin 12):  SHA-3-256 Hashing Active & Valid
 *   GP10 (Physical Pin 14):  AES-256-GCM AEAD Active & Valid
 *   GP11 (Physical Pin 15):  ECC P-256 KeyGen Active & Valid
 *   GP12 (Physical Pin 16):  ECDH Key Agreement Active & Valid
 *   GP13 (Physical Pin 17):  ECDSA Signature Sign/Verify Active & Valid
 *   GP14 (Physical Pin 19):  HKDF Key Combiner Active & Valid
 *   GP15 (Physical Pin 20):  All Self-Tests Passed / Session Ready
 *   GP16 (Physical Pin 21):  System Fault / Error Condition
 */
typedef enum {
    QSAC_STATUS_PIN_SYS_READY  = 6,  /* Physical Pin 9  */
    QSAC_STATUS_PIN_RNG_OK     = 7,  /* Physical Pin 10 */
    QSAC_STATUS_PIN_SHA256_OK  = 8,  /* Physical Pin 11 */
    QSAC_STATUS_PIN_SHA3_OK    = 9,  /* Physical Pin 12 */
    QSAC_STATUS_PIN_AES_GCM_OK = 10, /* Physical Pin 14 */
    QSAC_STATUS_PIN_ECC_KEYGEN = 11, /* Physical Pin 15 */
    QSAC_STATUS_PIN_ECDH_OK    = 12, /* Physical Pin 16 */
    QSAC_STATUS_PIN_ECDSA_OK   = 13, /* Physical Pin 17 */
    QSAC_STATUS_PIN_HKDF_OK    = 14, /* Physical Pin 19 */
    QSAC_STATUS_PIN_SESSION_OK = 15, /* Physical Pin 20 */
    QSAC_STATUS_PIN_ERROR      = 16  /* Physical Pin 21 */
} qsac_status_pin_t;

/**
 * @brief Set the status LED state (1 = on, 0 = off).
 */
void hal_led_set(int state);

/**
 * @brief Toggle the status LED.
 */
void hal_led_toggle(void);

/**
 * @brief Initialize all status GPIO pins (GP6-GP16 as outputs, default LOW).
 */
void hal_status_pins_init(void);

/**
 * @brief Set a specific status pin (GP6 to GP16).
 * @param pin   Pin number (6..16 or qsac_status_pin_t).
 * @param state 1 = high/on, 0 = low/off.
 */
void hal_status_pin_set(uint8_t pin, int state);

/**
 * @brief Toggle a specific status pin (GP6 to GP16).
 * @param pin   Pin number (6..16).
 */
void hal_status_pin_toggle(uint8_t pin);

/**
 * @brief Set all status pins via an 11-bit mask (bit 0 = GP6 ... bit 10 = GP16).
 * @param mask  11-bit status mask.
 */
void hal_status_mask_set(uint16_t mask);

/**
 * @brief Clear all status pins (GP6-GP16 set to 0).
 */
void hal_status_pins_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* QSAC_HAL_H */
