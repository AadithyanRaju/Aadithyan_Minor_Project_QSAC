cmake_minimum_required(VERSION 3.20)

# ----------------------------------------------
# Build options
# ----------------------------------------------

option(QSAC_TARGET_HOST       "Build for host simulation (Linux/macOS)" OFF)
option(QSAC_TARGET_STM32H5    "Build for STM32H5 Nucleo"               OFF)
option(QSAC_TARGET_NXP_IMXRT  "Build for NXP i.MX RT"                 OFF)
option(QSAC_TARGET_PICO       "Build for Raspberry Pi Pico"             ON)
option(QSAC_ENABLE_PQC        "Enable PQC algorithms (Phase 3+)"       ON)
option(QSAC_ENABLE_HYBRID     "Enable hybrid handshake (Phase 4+)"     OFF)
option(QSAC_ENABLE_BENCHMARKS "Enable benchmark instrumentation"      OFF)

# The Pico SDK must choose the cross-compiler before project() enables C.
if(QSAC_TARGET_PICO)
    if(NOT DEFINED PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
        set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
    elseif(NOT DEFINED PICO_SDK_PATH)
        set(PICO_SDK_PATH "C:/Users/aadit/Documents/Codex/pico/pico-sdk")
    endif()
    if(NOT EXISTS "${PICO_SDK_PATH}/pico_sdk_init.cmake")
        message(FATAL_ERROR "Pico SDK not found at: ${PICO_SDK_PATH}")
    endif()
    include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
endif()

project(qsac_firmware
    VERSION 0.1.0
    DESCRIPTION "Quantum-Secure Access Control for Microcontroller-Based IoT"
    LANGUAGES C CXX ASM
)

# ----------------------------------------------
# Compiler settings
# ----------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2 -g -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-O0 -g3 -DDEBUG")

# Warnings
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
    -Wno-unused-parameter
    -fstack-usage
)

# ----------------------------------------------
# Common source files
# ----------------------------------------------

set(QSAC_SOURCES
    src/main.c
    src/protocol/PROTOCOL_enrollment.c
    src/protocol/PROTOCOL_handshake.c
    src/protocol/PROTOCOL_token_verify.c
    src/protocol/PROTOCOL_state_machine.c
    src/protocol/PROTOCOL_uart_bridge.c
    src/benchmarks/BENCHMARKS_runner.c
    src/boot/secure_boot.c
)

set(QSAC_INCLUDES
    src/
    src/benchmarks/
)

# ----------------------------------------------
# Platform-specific configuration
# ----------------------------------------------

if(QSAC_TARGET_HOST)
    message(STATUS "═══════════════════════════════════════════")
    message(STATUS "  Target: Host Simulation (Linux/macOS)")
    message(STATUS "  Crypto: OpenSSL")
    message(STATUS "═══════════════════════════════════════════")
    add_compile_definitions(QSAC_PLATFORM_HOST)

    # Use host crypto backend (OpenSSL) and host HAL
    list(APPEND QSAC_SOURCES
        src/crypto/host_crypto_backend.c
        src/hal/host_hal.c
    )

    # Find OpenSSL
    find_package(OpenSSL REQUIRED)
    if(OpenSSL_FOUND)
        message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
        message(STATUS "  OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    endif()

elseif(QSAC_TARGET_STM32H5)
    message(STATUS "═══════════════════════════════════════════")
    message(STATUS "  Target: STM32H5 Nucleo (Cortex-M4)")
    message(STATUS "═══════════════════════════════════════════")
    add_compile_definitions(QSAC_PLATFORM_STM32H5)

    # Use real HSM backend and STM32 HAL
    list(APPEND QSAC_SOURCES
        src/crypto/hsm_backend.c
        src/hal/stm32h5_hal.c
    )

    # Optimization: -Os for size on constrained targets
    set(CMAKE_C_FLAGS_RELEASE "-Os -g -DNDEBUG")

elseif(QSAC_TARGET_NXP_IMXRT)
    message(STATUS "Target: NXP i.MX RT (EdgeLock)")
    add_compile_definitions(QSAC_PLATFORM_NXP_IMXRT)
    list(APPEND QSAC_SOURCES
        src/crypto/hsm_backend.c
    )

elseif(QSAC_TARGET_PICO)
    message(STATUS "═══════════════════════════════════════════")
    message(STATUS "  Target: Raspberry Pi Pico (RP2040)")
    message(STATUS "  Core:   Cortex-M0+ @ 125 MHz")
    message(STATUS "  RAM:    264 KB SRAM")
    message(STATUS "  Flash:  2 MB")
    message(STATUS "  Crypto: Hybrid PQC + ATECC608B HSM")
    message(STATUS "═══════════════════════════════════════════")
    add_compile_definitions(QSAC_PLATFORM_PICO)

    # Use Pico-specific HAL, crypto backend, ATECC608B driver, and crypto libraries
    list(APPEND QSAC_SOURCES
        src/crypto/atecc608b.c
        src/crypto/pico_crypto_backend.c
        src/crypto/sha256.c
        src/crypto/sha3.c
        src/crypto/fips202.c
        src/crypto/aes_gcm.c
        src/crypto/tiny_aes.c
        src/crypto/pqc_backend.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_cbd.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_indcpa.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_kem.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_ntt.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_poly.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_polyvec.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_reduce.c
        src/crypto/pqc/mlkem512/CRYPTO_PQC_MLKEM512_verify.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_ntt.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_packing.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_poly.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_polyvec.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_reduce.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_rounding.c
        src/crypto/pqc/mldsa44/CRYPTO_PQC_MLDSA44_sign.c
        third_party/micro-ecc/uECC.c
        src/hal/pico_hal.c
    )

    list(APPEND QSAC_INCLUDES
        src/crypto
        src/crypto/pqc/mlkem512
        src/crypto/pqc/mldsa44
        src/protocol
        src/storage
        third_party/micro-ecc
    )

    # Optimize for performance on RP2040 (2MB flash available)
    set(CMAKE_C_FLAGS_RELEASE "-O3 -g -DNDEBUG")

    set(QSAC_PICO_SDK_AVAILABLE TRUE)
endif()

# ----------------------------------------------
# PQC library integration (Phase 3+)
# ----------------------------------------------

if(QSAC_ENABLE_PQC)
    message(STATUS "PQC enabled: ML-KEM-512 + ML-DSA-2")
    add_compile_definitions(QSAC_PQC_ENABLED)
endif()

# ----------------------------------------------
# Benchmark instrumentation (Phase 6)
# ----------------------------------------------

if(QSAC_ENABLE_BENCHMARKS)
    add_compile_definitions(QSAC_BENCHMARKS_ENABLED)
    message(STATUS "Benchmark instrumentation enabled")
endif()

# ----------------------------------------------
# Build the firmware
# ----------------------------------------------

# For Pico, pico_sdk_init() must be called before add_executable
if(QSAC_TARGET_PICO AND QSAC_PICO_SDK_AVAILABLE)
    pico_sdk_init()
endif()

add_executable(qsac_firmware ${QSAC_SOURCES})

target_include_directories(qsac_firmware PRIVATE ${QSAC_INCLUDES})

# Link libraries
if(QSAC_TARGET_HOST)
    target_link_libraries(qsac_firmware PRIVATE OpenSSL::SSL OpenSSL::Crypto)

elseif(QSAC_TARGET_PICO AND QSAC_PICO_SDK_AVAILABLE)
    target_link_libraries(qsac_firmware PRIVATE
        pico_stdlib
        hardware_timer
        hardware_gpio
        hardware_i2c
        hardware_spi
    )

    # Enable USB serial output (more convenient than UART for dev)
    pico_enable_stdio_usb(qsac_firmware 1)
    pico_enable_stdio_uart(qsac_firmware 1)

    # Generate .uf2 file for drag-and-drop flashing
    pico_add_extra_outputs(qsac_firmware)
endif()

# ----------------------------------------------
# Post-build
# ----------------------------------------------

if(QSAC_TARGET_PICO AND QSAC_PICO_SDK_AVAILABLE)
    # Pico: pico_add_extra_outputs already generates .uf2
    add_custom_command(TARGET qsac_firmware POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMAND ${CMAKE_COMMAND} -E echo "  Build complete."
        COMMAND ${CMAKE_COMMAND} -E echo "  Flash: hold BOOTSEL + plug USB, then copy qsac_firmware.uf2 to RPI-RP2"
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMENT "Pico build complete"
    )
elseif(NOT QSAC_TARGET_HOST)
    # Other ARM targets: generate .bin and .hex
    add_custom_command(TARGET qsac_firmware POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:qsac_firmware> qsac_firmware.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:qsac_firmware> qsac_firmware.hex
        COMMAND ${CMAKE_SIZE}    $<TARGET_FILE:qsac_firmware>
        COMMENT "Generating binary and hex images"
    )
else()
    # Host target: print a run message
    add_custom_command(TARGET qsac_firmware POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMAND ${CMAKE_COMMAND} -E echo "  Build complete: ./qsac_firmware"
        COMMAND ${CMAKE_COMMAND} -E echo ""
        COMMENT "Host build complete"
    )
endif()
