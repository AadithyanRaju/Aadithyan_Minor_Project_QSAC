/**
 * @file pico_hal.c
 * @brief Raspberry Pi Pico (RP2040) HAL backend.
 *
 * Hardware implementation for the RP2040 (Cortex-M0+ @ 125 MHz).
 * Uses the official pico-sdk for UART, GPIO, and timer access.
 *
 * This file is compiled only when QSAC_PLATFORM_PICO is defined.
 */

#ifdef QSAC_PLATFORM_PICO

#include "hal.h"

#include "pico/stdlib.h"
#include "pico/time.h"
#include "hardware/gpio.h"
#include "hardware/timer.h"
#include "hardware/clocks.h"
#include "hardware/i2c.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* ----------------------------------------------
 * Pin assignments (Pico / Pico W)
 * ---------------------------------------------- */

#define QSAC_LED_PIN       PICO_DEFAULT_LED_PIN  /* GPIO 25 on Pico */
#define QSAC_UART_ID       uart0
#define QSAC_UART_TX_PIN   0
#define QSAC_UART_RX_PIN   1
#define QSAC_UART_BAUD     115200

#define QSAC_I2C_INST      i2c0
#define QSAC_I2C_SDA_PIN   4                     /* GP4 (Pin 6) */
#define QSAC_I2C_SCL_PIN   5                     /* GP5 (Pin 7) */

/* ----------------------------------------------
 * System
 * ---------------------------------------------- */

void hal_system_init(void)
{
    /* Initialize pico-sdk stdio (USB or UART based on cmake config) */
    stdio_init_all();

    /* Initialize UART for logging */
    uart_init(QSAC_UART_ID, QSAC_UART_BAUD);
    gpio_set_function(QSAC_UART_TX_PIN, GPIO_FUNC_UART);
    gpio_set_function(QSAC_UART_RX_PIN, GPIO_FUNC_UART);

    /* Initialize standard onboard LED */
    gpio_init(QSAC_LED_PIN);
    gpio_set_dir(QSAC_LED_PIN, GPIO_OUT);
    gpio_put(QSAC_LED_PIN, 0);

#if QSAC_FEATURE_STATUS_LEDS
    /* Initialize Status GPIO symbols GP6 through GP16 */
    hal_status_pins_init();
#endif

#if QSAC_FEATURE_ATECC608B
    /* Initialize I2C0 peripheral for ATECC608B */
    hal_i2c_init(QSAC_I2C_DEFAULT_BAUDRATE);
#endif

    /* Give USB time to enumerate (if using USB serial) */
    sleep_ms(2000);
}

uint32_t hal_get_sysclk_hz(void)
{
    return clock_get_hz(clk_sys);
}

void hal_delay_ms(uint32_t ms)
{
    sleep_ms(ms);
}

void hal_delay_us(uint32_t us)
{
    sleep_us(us);
}

/* ----------------------------------------------
 * I2C Interface (for ATECC608B)
 * ---------------------------------------------- */

int hal_i2c_init(uint32_t baudrate)
{
    i2c_init(QSAC_I2C_INST, baudrate);
    gpio_set_function(QSAC_I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(QSAC_I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(QSAC_I2C_SDA_PIN);
    gpio_pull_up(QSAC_I2C_SCL_PIN);
    return 0;
}

void hal_i2c_wake_pulse(void)
{
    /* ATECC608B wakeup pulse: drive SDA low for at least 60 us.
     * Configure SDA pin as GPIO output, drive low, then restore to I2C with pull-up. */
    gpio_set_function(QSAC_I2C_SDA_PIN, GPIO_FUNC_SIO);
    gpio_set_dir(QSAC_I2C_SDA_PIN, GPIO_OUT);
    gpio_put(QSAC_I2C_SDA_PIN, 0);
    sleep_us(120);
    gpio_put(QSAC_I2C_SDA_PIN, 1);
    gpio_set_dir(QSAC_I2C_SDA_PIN, GPIO_IN);
    gpio_set_function(QSAC_I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(QSAC_I2C_SDA_PIN);
}

int hal_i2c_write(uint8_t addr, const uint8_t *data, size_t len)
{
    int ret = i2c_write_timeout_us(QSAC_I2C_INST, addr, data, len, false, 50000);
    return ret;
}

int hal_i2c_read(uint8_t addr, uint8_t *buf, size_t len)
{
    int ret = i2c_read_timeout_us(QSAC_I2C_INST, addr, buf, len, false, 50000);
    return ret;
}

/* ----------------------------------------------
 * UART / Logging
 * ---------------------------------------------- */

void hal_uart_print(const char *msg)
{
    printf("%s", msg);
}

void hal_uart_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void hal_print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

int hal_uart_getc_nonblocking(void)
{
    int c = getchar_timeout_us(0);
    return (c == PICO_ERROR_TIMEOUT) ? -1 : c;
}

void hal_uart_write(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        putchar_raw(data[i]);
    }
}

/* ----------------------------------------------
 * Cycle counter
 * ---------------------------------------------- */

void hal_cycle_counter_init(void)
{
    /* The RP2040 timer is always running; nothing to init */
}

uint32_t hal_cycle_count(void)
{
    uint64_t us = time_us_64();
    uint32_t mhz = hal_get_sysclk_hz() / 1000000;
    return (uint32_t)(us * mhz);
}

/* ----------------------------------------------
 * Status LED & GPIO Symbols (GP6 - GP16)
 * ---------------------------------------------- */

static int led_state = 0;

void hal_led_set(int state)
{
    led_state = state;
    gpio_put(QSAC_LED_PIN, state ? 1 : 0);
}

void hal_led_toggle(void)
{
    hal_led_set(!led_state);
}

void hal_status_pins_init(void)
{
#if QSAC_FEATURE_STATUS_LEDS
    for (uint8_t pin = QSAC_GPIO_STATUS_START_PIN; pin <= QSAC_GPIO_STATUS_END_PIN; pin++) {
        /* Explicit safety guard: NEVER touch GP4 (Pin 6) or GP5 (Pin 7) dedicated to I2C */
        if (pin == QSAC_I2C_SDA_PIN || pin == QSAC_I2C_SCL_PIN) {
            continue;
        }
        gpio_init(pin);
        gpio_set_dir(pin, GPIO_OUT);
        gpio_put(pin, 0);
    }
#endif
}

void hal_status_pin_set(uint8_t pin, int state)
{
#if QSAC_FEATURE_STATUS_LEDS
    /* Explicit safety guard: NEVER touch GP4 (Pin 6) or GP5 (Pin 7) */
    if (pin == QSAC_I2C_SDA_PIN || pin == QSAC_I2C_SCL_PIN) {
        return;
    }
    if (pin >= QSAC_GPIO_STATUS_START_PIN && pin <= QSAC_GPIO_STATUS_END_PIN) {
        gpio_put(pin, state ? 1 : 0);
    }
#else
    (void)pin; (void)state;
#endif
}

void hal_status_pin_toggle(uint8_t pin)
{
#if QSAC_FEATURE_STATUS_LEDS
    /* Explicit safety guard: NEVER touch GP4 (Pin 6) or GP5 (Pin 7) */
    if (pin == QSAC_I2C_SDA_PIN || pin == QSAC_I2C_SCL_PIN) {
        return;
    }
    if (pin >= QSAC_GPIO_STATUS_START_PIN && pin <= QSAC_GPIO_STATUS_END_PIN) {
        gpio_xor_mask(1u << pin);
    }
#else
    (void)pin;
#endif
}

void hal_status_mask_set(uint16_t mask)
{
#if QSAC_FEATURE_STATUS_LEDS
    for (uint8_t i = 0; i < QSAC_GPIO_STATUS_NUM_PINS; i++) {
        uint8_t pin = QSAC_GPIO_STATUS_START_PIN + i;
        if (pin == QSAC_I2C_SDA_PIN || pin == QSAC_I2C_SCL_PIN) {
            continue;
        }
        gpio_put(pin, (mask & (1 << i)) ? 1 : 0);
    }
#else
    (void)mask;
#endif
}

void hal_status_pins_clear(void)
{
#if QSAC_FEATURE_STATUS_LEDS
    for (uint8_t pin = QSAC_GPIO_STATUS_START_PIN; pin <= QSAC_GPIO_STATUS_END_PIN; pin++) {
        if (pin == QSAC_I2C_SDA_PIN || pin == QSAC_I2C_SCL_PIN) {
            continue;
        }
        gpio_put(pin, 0);
    }
#endif
}

#endif /* QSAC_PLATFORM_PICO */
