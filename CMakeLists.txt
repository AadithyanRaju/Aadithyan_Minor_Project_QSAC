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
        # Search common standard installation directories across platforms
        set(PICO_SDK_SEARCH_DIRS
            "$ENV{PICO_SDK_PATH}"
            "$ENV{USERPROFILE}/Documents/Codex/pico/pico-sdk"
            "$ENV{USERPROFILE}/.pico-sdk/sdk/2.1.1"
            "$ENV{USERPROFILE}/.pico-sdk/sdk/2.1.0"
            "$ENV{USERPROFILE}/.pico-sdk/sdk/2.0.0"
            "$ENV{USERPROFILE}/pico/pico-sdk"
            "$ENV{HOME}/.pico-sdk/sdk/2.1.1"
            "$ENV{HOME}/.pico-sdk/sdk/2.1.0"
            "$ENV{HOME}/.pico-sdk/sdk/2.0.0"
            "$ENV{HOME}/pico/pico-sdk"
            "C:/pico/pico-sdk"
            "/usr/share/pico-sdk"
            "/opt/pico-sdk"
        )
        foreach(_pico_cand IN LISTS PICO_SDK_SEARCH_DIRS)
            if(_pico_cand AND EXISTS "${_pico_cand}/pico_sdk_init.cmake")
                set(PICO_SDK_PATH "${_pico_cand}")
                break()
            endif()
        endforeach()
    endif()

    if(NOT DEFINED PICO_SDK_PATH OR NOT EXISTS "${PICO_SDK_PATH}/pico_sdk_init.cmake")
        message(FATAL_ERROR
            "Raspberry Pi Pico SDK not found!\n"
            "Please specify the SDK path using either:\n"
            "  1. -DPICO_SDK_PATH=<path_to_pico_sdk>\n"
            "  2. set PICO_SDK_PATH environment variable (e.g. export PICO_SDK_PATH=/path/to/pico-sdk)"
        )
    endif()

    # Auto-detect ARM toolchain path if not in system PATH
    if(NOT DEFINED PICO_TOOLCHAIN_PATH AND DEFINED ENV{PICO_TOOLCHAIN_PATH})
        set(PICO_TOOLCHAIN_PATH "$ENV{PICO_TOOLCHAIN_PATH}")
    elseif(NOT DEFINED PICO_TOOLCHAIN_PATH)
        find_program(_ARM_GCC_EXISTS arm-none-eabi-gcc)
        if(NOT _ARM_GCC_EXISTS)
            file(GLOB _XPACK_GCC "$ENV{APPDATA}/xPacks/@xpack-dev-tools/arm-none-eabi-gcc/*/.content/bin")
            file(GLOB _LOCAL_GCC "$ENV{LOCALAPPDATA}/pico-sdk/toolchain/*/*/bin")
            set(_TOOLCHAIN_CANDS
                ${_XPACK_GCC}
                ${_LOCAL_GCC}
                "$ENV{USERPROFILE}/.pico-sdk/toolchain/13_3_rel1/bin"
            )
            foreach(_cand IN LISTS _TOOLCHAIN_CANDS)
                if(_cand AND (EXISTS "${_cand}/arm-none-eabi-gcc.exe" OR EXISTS "${_cand}/arm-none-eabi-gcc"))
                    set(PICO_TOOLCHAIN_PATH "${_cand}")
                    set(ENV{PICO_TOOLCHAIN_PATH} "${_cand}")
                    break()
                endif()
            endforeach()
        endif()
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

# ----------------------------------------------
# Standalone PQC Test Target (Phase 3+)
# ----------------------------------------------
option(QSAC_BUILD_TESTS "Build PQC standalone unit test binary" ON)

if(QSAC_BUILD_TESTS)
    set(QSAC_TEST_SOURCES
        tests/test_pqc_standalone.c
        src/crypto/fips202.c
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
    )

    add_executable(test_pqc_standalone ${QSAC_TEST_SOURCES})

    target_include_directories(test_pqc_standalone PRIVATE
        src/
        src/crypto
        src/crypto/pqc/mlkem512
        src/crypto/pqc/mldsa44
        tests/
    )

    if(QSAC_TARGET_PICO AND QSAC_PICO_SDK_AVAILABLE)
        target_link_libraries(test_pqc_standalone PRIVATE pico_stdlib)
        pico_enable_stdio_usb(test_pqc_standalone 1)
        pico_enable_stdio_uart(test_pqc_standalone 1)
        pico_add_extra_outputs(test_pqc_standalone)
    endif()
endif()

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
