/**
 * @file stm32h5_hal.c
 * @brief STM32H5 Nucleo HAL backend.
 *
 * Real hardware implementation for the STM32H5 series.
 * Requires STM32CubeH5 HAL library.
 *
 * This file is compiled only when QSAC_PLATFORM_STM32H5 is defined.
 */

#ifdef QSAC_PLATFORM_STM32H5

/* TODO Phase 1: Include actual STM32 HAL headers once the SDK is set up.
 * #include "stm32h5xx_hal.h"
 */

#include "hal.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* ----------------------------------------------
 * Peripheral handles (configured by STM32CubeMX)
 * ---------------------------------------------- */

/* TODO Phase 1: Declare these as extern from the CubeMX-generated code:
 *
 * extern UART_HandleTypeDef huart1;
 * extern RNG_HandleTypeDef  hrng;
 * extern PKA_HandleTypeDef  hpka;
 * extern CRYP_HandleTypeDef hcryp;
 * extern HASH_HandleTypeDef hhash;
 */

/* ----------------------------------------------
 * System
 * ---------------------------------------------- */

void hal_system_init(void)
{
    /* TODO Phase 1: Implement with STM32 HAL:
     *
     * HAL_Init();
     * SystemClock_Config();   // Configure to 250 MHz (H5 max) or 80 MHz for comparison
     * MX_GPIO_Init();
     * MX_USART1_UART_Init();  // 115200 baud
     * MX_RNG_Init();
     * MX_PKA_Init();
     * MX_CRYP_Init();
     * MX_HASH_Init();
     *
     * // Enable DWT cycle counter
     * hal_cycle_counter_init();
     */
}

uint32_t hal_get_sysclk_hz(void)
{
    /* TODO Phase 1: return SystemCoreClock; */
    return 80000000;  /* placeholder */
}

void hal_delay_ms(uint32_t ms)
{
    /* TODO Phase 1: HAL_Delay(ms); */
    (void)ms;
}

void hal_delay_us(uint32_t us)
{
    (void)us;
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
    /* TODO Phase 1:
     * HAL_UART_Transmit(&huart1, (uint8_t*)msg, strlen(msg), HAL_MAX_DELAY);
     */
    (void)msg;
}

void hal_uart_printf(const char *fmt, ...)
{
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    hal_uart_print(buf);
}

void hal_print_hex(const uint8_t *data, size_t len)
{
    char hex[3];
    for (size_t i = 0; i < len; i++) {
        snprintf(hex, sizeof(hex), "%02x", data[i]);
        hal_uart_print(hex);
    }
}

/* ----------------------------------------------
 * Cycle counter (DWT)
 * ---------------------------------------------- */

void hal_cycle_counter_init(void)
{
    /* TODO Phase 1: Enable DWT cycle counter on Cortex-M:
     *
     * CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
     * DWT->CYCCNT = 0;
     * DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
     */
}

uint32_t hal_cycle_count(void)
{
    /* TODO Phase 1: return DWT->CYCCNT; */
    return 0;
}

/* ----------------------------------------------
 * Status LED
 * ---------------------------------------------- */

void hal_led_set(int state)
{
    /* TODO Phase 1:
     * HAL_GPIO_WritePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin,
     *                   state ? GPIO_PIN_SET : GPIO_PIN_RESET);
     */
    (void)state;
}

void hal_led_toggle(void)
{
    /* TODO Phase 1:
     * HAL_GPIO_TogglePin(LED_GREEN_GPIO_Port, LED_GREEN_Pin);
     */
}

void hal_status_pins_init(void) {}
void hal_status_pin_set(uint8_t pin, int state) { (void)pin; (void)state; }
void hal_status_pin_toggle(uint8_t pin) { (void)pin; }
void hal_status_mask_set(uint16_t mask) { (void)mask; }
void hal_status_pins_clear(void) {}

#endif /* QSAC_PLATFORM_STM32H5 */
