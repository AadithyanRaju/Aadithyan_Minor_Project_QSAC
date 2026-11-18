/**
 * @file host_hal.c
 * @brief Host-simulation HAL backend.
 *
 * Allows the firmware to compile and run on a Linux/macOS development
 * machine for testing without physical hardware. UART output goes to
 * stdout, RNG uses /dev/urandom, cycle counts use clock_gettime.
 */

#ifdef QSAC_PLATFORM_HOST

#include "hal.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ----------------------------------------------
 * System
 * ---------------------------------------------- */

void hal_system_init(void)
{
    /* Nothing to initialize on host */
    printf("[HAL-HOST] System initialized (simulation mode)\n");
}

uint32_t hal_get_sysclk_hz(void)
{
    /* Simulate 80 MHz to match the paper's reference clock */
    return 80000000;
}

void hal_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

void hal_delay_us(uint32_t us)
{
    usleep(us);
}

int hal_i2c_init(uint32_t baudrate)
{
    (void)baudrate;
    return 0;
}

void hal_i2c_wake_pulse(void)
{
}

int hal_i2c_write(uint8_t addr, const uint8_t *data, size_t len)
{
    (void)addr;
    (void)data;
    (void)len;
    return -1;
}

int hal_i2c_read(uint8_t addr, uint8_t *buf, size_t len)
{
    (void)addr;
    (void)buf;
    (void)len;
    return -1;
}

/* ----------------------------------------------
 * UART / Logging
 * ---------------------------------------------- */

void hal_uart_print(const char *msg)
{
    fputs(msg, stdout);
    fflush(stdout);
}

void hal_uart_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

void hal_print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/* ----------------------------------------------
 * Cycle counter
 * ---------------------------------------------- */

static struct timespec ts_start;

void hal_cycle_counter_init(void)
{
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
}

uint32_t hal_cycle_count(void)
{
    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);

    /* Convert elapsed nanoseconds to pseudo-cycles at 80 MHz */
    uint64_t ns = (uint64_t)(ts_now.tv_sec - ts_start.tv_sec) * 1000000000ULL
                + (uint64_t)(ts_now.tv_nsec - ts_start.tv_nsec);
    /* 80 MHz = 80 cycles per microsecond = 0.08 cycles per nanosecond */
    return (uint32_t)((ns * 80) / 1000);
}

/* ----------------------------------------------
 * Status LED
 * ---------------------------------------------- */

static int led_state = 0;

void hal_led_set(int state)
{
    led_state = state;
    printf("[HAL-HOST] LED %s\n", state ? "ON" : "OFF");
}

void hal_led_toggle(void)
{
    hal_led_set(!led_state);
}

static uint16_t g_host_status_mask = 0;

void hal_status_pins_init(void)
{
    g_host_status_mask = 0;
}

void hal_status_pin_set(uint8_t pin, int state)
{
    if (pin >= QSAC_GPIO_STATUS_START_PIN && pin <= QSAC_GPIO_STATUS_END_PIN) {
        uint8_t idx = pin - QSAC_GPIO_STATUS_START_PIN;
        if (state) {
            g_host_status_mask |= (1 << idx);
        } else {
            g_host_status_mask &= ~(1 << idx);
        }
    }
}

void hal_status_pin_toggle(uint8_t pin)
{
    if (pin >= QSAC_GPIO_STATUS_START_PIN && pin <= QSAC_GPIO_STATUS_END_PIN) {
        uint8_t idx = pin - QSAC_GPIO_STATUS_START_PIN;
        g_host_status_mask ^= (1 << idx);
    }
}

void hal_status_mask_set(uint16_t mask)
{
    g_host_status_mask = mask & ((1 << QSAC_GPIO_STATUS_NUM_PINS) - 1);
}

void hal_status_pins_clear(void)
{
    g_host_status_mask = 0;
}

#endif /* QSAC_PLATFORM_HOST */
