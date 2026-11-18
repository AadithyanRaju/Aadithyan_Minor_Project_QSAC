# QSAC - Microcontrollers
---

## Overview

### What the Project Does

**QSAC** is an end-to-end, zero-trust cryptographic firmware architecture and access control framework engineered specifically for resource-constrained microcontrollers. It provides post-quantum cryptographic resilience, authenticated key agreement, offline capability token verification, and session confidentiality on embedded platforms such as the **Raspberry Pi Pico (RP2040 ARM Cortex-M0+ @ 125 MHz, 264 KB SRAM)**.

Key features of the project include:
- **Hybrid Post-Quantum Key Agreement**: Merges classical Elliptic Curve Diffie-Hellman (**ECDH NIST P-256**) with lattice-based Post-Quantum Cryptography (**NIST FIPS 203 ML-KEM-512**) using an **HKDF-SHA-256** key combiner. This defense-in-depth design guarantees confidentiality even if either the classical or post-quantum primitive is broken.
- **Offline Post-Quantum Capability Tokens**: Issues and verifies access control tokens authenticated via **NIST FIPS 204 ML-DSA-44** digital signatures. Edge nodes verify role-based access permissions, validity timestamps, and device identity locally in ~55 ms without requiring real-time cloud connectivity.
- **Authenticated Session Confidentiality**: Protects all post-handshake communication with **AES-256-GCM** (NIST SP 800-38D), featuring GHASH message authentication and monotonic anti-replay counter protection.
- **Hardware Security Module (HSM) Co-Processing**: Integrates directly with the **Microchip ATECC608B** secure element over I2C0 for True Random Number Generation (TRNG), hardware key isolation, and ECDH/ECDSA acceleration, while providing seamless software fallback (RP2040 ROSC TRNG and `micro-ecc`).
- **Live Bidirectional UART Gateway**: Implements a robust binary framed transport layer (`0xAA 0x55` sync, sequence numbering, opcode dispatch, and CRC-16-CCITT integrity verification) connecting microcontrollers to host PC servers and IoT access gateways.
- **Hardware-Level Diagnostics**: Exposes a real-time status matrix across GPIO pins (GP6 to GP16) that reflects individual cryptographic self-tests (RNG, SHA-256, SHA-3, AES-GCM, ECC, ECDH, ECDSA, HKDF, ML-KEM, ML-DSA, and Session Valid) for hardware validation via LEDs or logic analyzers.

---

### Why the Project is Useful: Research and Product Dev

#### 1. Research Perspective
- **Empirical Post-Quantum Silicon Benchmarking**: Demonstrates the real-world practicality, latency, cycle costs, and memory footprints of NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) running on an ultra-constrained Cortex-M0+ microcontroller with only 264 KB SRAM.
- **Side-Channel & Leakage Assessment**: Provides a testbed with built-in instrumentation for **TVLA (Test Vector Leakage Assessment)** timing side-channel analysis and cycle-accurate performance logging.
- **Stack & Memory Envelope Profiling**: Includes automated callgraph stack analyzers and stack canary tools to track maximum stack watermarks, proving lattice cryptography fits safely within tight SRAM budgets (under 3 KB peak stack).
- **Adversarial & Negative Testing**: Ships with an automated 10-scenario adversarial suite validating resilience against Man-in-the-Middle (MitM) transcript tampering, expired token replay attacks, forged authority keys, bit-flipped ciphertexts, and parser overflow attacks.
- **CNSA 2.0 & Post-Quantum Migration**: Serves as a transparent reference implementation for researchers studying hybrid transition architectures aligned with BSI, ANSSI, and NSA CNSA 2.0 recommendations.

#### 2. Product Development Perspective
- **Future-Proofing Long-Life Field Devices**: Embedded IoT hardware (smart door locks, industrial PLCs, smart meters, automotive ECUs) often stays deployed in the field for 10 to 20+ years. QSAC defeats **Harvest Now, Decrypt Later (HNDL)** attacks by preventing adversaries from recording traffic today to decrypt with future quantum computers.
- **Decentralized Offline Access Authorization**: Devices do not need persistent network access to authorize doors, gates, or operational commands. High-privilege tokens signed by a central authority can be delivered via NFC, Bluetooth, or QR code and verified offline by the MCU in milliseconds.
- **Modular Hardware Root-of-Trust Agility**: Cryptographic backends are decoupled through an abstract Hardware Abstraction Layer (HAL). Teams can toggle between Microchip ATECC608B HSM, NXP EdgeLock, STM32H5 hardware crypto, or pure software implementations via compile-time feature switches.
- **Production-Ready Multi-Platform Architecture**: Offers built-in support for Raspberry Pi Pico (RP2040), STM32H5 Nucleo, and host workstation simulation (Linux/macOS), enabling seamless integration into automated CI/CD unit testing and firmware deployment pipelines.

---

## File Structure and Description

```
Project_Amrita/
├── CMakeLists.txt                # Root CMake build configuration (RP2040, STM32H5, Host targets)
├── CMakePresets.json             # CMake build presets for Raspberry Pi Pico and Ninja
├── build.ps1                     # Windows PowerShell one-step build script for RP2040 (build-pico)
├── build.bat                     # Windows batch wrapper for build.ps1 (Command Prompt / double-click)
├── README.md                     # Project documentation
│
├── src/                          # Firmware source code
│   ├── main.c                    # Firmware entry point: boot self-tests & live UART gateway loop
│   ├── qsac_features.h           # Feature toggles (ATECC608B, PQC, LEDs, Tokens, Gateway)
│   ├── qsac_feature_settings.h   # Default enable/disable definitions for feature flags
│   │
│   ├── benchmarks/               # In-firmware benchmark instrumentation
│   │   ├── BENCHMARKS_runner.c   # Cycle-counting and stack canary execution harness
│   │   └── BENCHMARKS_runner.h   # Benchmark interface definitions
│   │
│   ├── boot/                     # Secure boot implementation
│   │   └── secure_boot.c         # Image verification and bootloader integrity hooks
│   │
│   ├── crypto/                   # Cryptographic engine implementations
│   │   ├── crypto_api.h          # Unified cryptographic abstraction API
│   │   ├── aes_gcm.c / .h        # AES-256-GCM AEAD encryption, decryption, and GHASH
│   │   ├── atecc608b.c / .h      # Microchip ATECC608B I2C hardware security module driver
│   │   ├── fips202.c / .h        # Keccak-f[1600] permutation, SHA3-256, and SHAKE-128/256
│   │   ├── sha256.c / .h         # Software SHA-256 implementation
│   │   ├── sha3.c / .h           # SHA-3 wrapper interfaces
│   │   ├── tiny_aes.c / .h       # Lightweight AES block cipher core
│   │   ├── host_crypto_backend.c # OpenSSL-backed crypto backend for host simulation
│   │   ├── hsm_backend.c         # Hardware security module backend dispatcher
│   │   ├── pico_crypto_backend.c # RP2040 crypto backend (ATECC608B + ROSC TRNG + software)
│   │   ├── pqc_backend.c         # Unified wrapper dispatching ML-KEM and ML-DSA calls
│   │   │
│   │   └── pqc/                  # Standalone C Post-Quantum Cryptography implementations
│   │       ├── mlkem512/         # NIST FIPS 203 ML-KEM-512 (Kyber)
│   │       │   ├── CRYPTO_PQC_MLKEM512_cbd.c     # Centered binomial distribution sampling
│   │       │   ├── CRYPTO_PQC_MLKEM512_indcpa.c  # Ind-CPA encryption & decryption
│   │       │   ├── CRYPTO_PQC_MLKEM512_kem.c     # CCA-secure KEM (KeyGen, Encaps, Decaps)
│   │       │   ├── CRYPTO_PQC_MLKEM512_ntt.c     # Number Theoretic Transform (NTT) operations
│   │       │   ├── CRYPTO_PQC_MLKEM512_poly.c    # Polynomial arithmetic
│   │       │   ├── CRYPTO_PQC_MLKEM512_polyvec.c # Polynomial vector operations
│   │       │   ├── CRYPTO_PQC_MLKEM512_reduce.c  # Montgomery and Barrett modular reductions
│   │       │   └── CRYPTO_PQC_MLKEM512_verify.c  # Constant-time comparison & conditional move
│   │       │
│   │       └── mldsa44/          # NIST FIPS 204 ML-DSA-44 (Dilithium)
│   │           ├── CRYPTO_PQC_MLDSA44_ntt.c      # NTT forward and inverse transforms
│   │           ├── CRYPTO_PQC_MLDSA44_packing.c  # Public/secret key and signature byte packing
│   │           ├── CRYPTO_PQC_MLDSA44_poly.c     # Polynomial vector calculations
│   │           ├── CRYPTO_PQC_MLDSA44_polyvec.c  # High-order polynomial vectors
│   │           ├── CRYPTO_PQC_MLDSA44_reduce.c   # Modular arithmetic reductions
│   │           ├── CRYPTO_PQC_MLDSA44_rounding.c # Signature decomposition and hints
│   │           └── CRYPTO_PQC_MLDSA44_sign.c     # KeyGen, Sign, and Verify routines
│   │
│   ├── hal/                      # Hardware Abstraction Layer (HAL)
│   │   ├── hal.h                 # Unified GPIO, UART, Timer, Cycle Counter, and I2C HAL API
│   │   ├── host_hal.c            # POSIX / PC emulation HAL
│   │   ├── pico_hal.c            # Raspberry Pi Pico (RP2040) HAL implementation
│   │   └── stm32h5_hal.c         # STM32H5 Nucleo HAL implementation
│   │
│   └── protocol/                 # State machine and communication protocol
│       ├── PROTOCOL_enrollment.c / .h   # Device provisioning and identity registration
│       ├── PROTOCOL_handshake.c / .h    # Dual-key hybrid handshake (ECDH + ML-KEM + HKDF)
│       ├── PROTOCOL_state_machine.c / .h# Zero-trust session state machine
│       ├── PROTOCOL_token_verify.c / .h # ML-DSA-44 capability token verification engine
│       └── PROTOCOL_uart_bridge.c / .h  # Live UART framed packet receiver & dispatcher
│
├── tests/                        # Unit and integration test suites
│   └── test_pqc_standalone.c     # Standalone C test binary for ML-KEM-512 and ML-DSA-44
│
├── third_party/                  # External dependencies
│   └── micro-ecc/                # Compact C implementation of ECDH & ECDSA for secp256r1
│       ├── uECC.c
│       └── uECC.h
│
└── tools/                        # Host tooling, gateway server, and validation suites
    ├── flash.sh                  # Shell script for flashing Pico (BOOTSEL, picotool, OpenOCD)
    ├── physical_check.py         # End-to-end physical hardware validation and pin check
    ├── benchmarks.py             # UART speed, KAT, and cycle count collector
    │
    ├── benchmarks/               # Historical benchmark results and analysis scripts
    │   ├── benchmark_results_rp2040.json  # Silicon benchmark data (cycles, latency, stack)
    │   └── callgraph_stack_analysis.py    # Static callgraph and stack usage parser
    │
    ├── gateway/                  # Host Gateway and Access Control Authority Server
    │   ├── qsac_server.py        # Interactive PC gateway server & authority
    │   ├── qsac_frame.py         # Binary framing codec, CRC-16, and opcode definitions
    │   └── pqc/                  # Python reference implementations of ML-KEM & ML-DSA
    │       ├── mlkem512.py
    │       └── mldsa44.py
    │
    └── security/                 # Security assessment and adversarial test suites
        ├── qsac_security_suite.py        # 10-phase automated adversarial penetration suite
        ├── fuzzer.py                     # Serial packet fuzzer (boundary, mutation, noise)
        ├── dos_burst_suite.py            # High-throughput DoS and frame burst stress tester
        ├── rbac_test_suite.py            # Fine-grained permission verification tests
        ├── tvla_timing_evaluator.py      # Test Vector Leakage Assessment timing evaluator
        └── security_assessment_report.md # Formal security assessment and compliance report
```

---

## Requirements

### Hardware Requirements
- **Microcontroller**: Raspberry Pi Pico (RP2040 dual-core ARM Cortex-M0+ @ 125 MHz, 264 KB SRAM, 2 MB Flash) or STM32H5 Nucleo.
- **Connection**: Standard Micro-USB to USB-A/C cable (data and power).
- **Optional HSM**: Microchip ATECC608B CryptoAuthentication module (wired to I2C0: `GP4` SDA / Pin 6, `GP5` SCL / Pin 7, 3.3V, GND).
- **Optional Status Monitoring**: LEDs or a logic analyzer connected to GPIO status pins `GP6` through `GP16` (Physical Pins 9 through 21).

### Software & Toolchain Requirements
- **Cross-Compiler**: ARM GNU Toolchain (`arm-none-eabi-gcc`, `arm-none-eabi-g++`, `arm-none-eabi-objcopy`) version 10.3+ or 12/13.
- **Build Generator**: [CMake](https://cmake.org/download/) (v3.20 or newer) and [Ninja](https://ninja-build.org/) (or Make).
- **SDK**: [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk) (v1.5.1+ or v2.0+).
- **Host Runtime**: Python 3.9+ with `pip`.
- **Python Libraries**:
  - `pyserial`: Serial communication with the microcontroller.
  - `cryptography` (>= 41.0.0): Classical crypto and HKDF primitives.
  - `numpy`, `scipy`: Statistical evaluations for TVLA side-channel analysis.
- **Optional Host Simulation**: GCC or Clang with OpenSSL development headers (`libssl-dev` on Debian/Ubuntu, `openssl@3` on macOS).

---

## Setup (include clone)

### 1. Clone the Repository
Clone the repository and initialize submodules:

```bash
git clone --recurse-submodules https://github.com/your-username/QSAC-Microcontrollers.git
cd QSAC-Microcontrollers
```

*(If you have already cloned without submodules, run `git submodule update --init --recursive`)*.

### 2. Configure Environment Variables
Ensure the Raspberry Pi Pico SDK and ARM toolchain are reachable *(Note: If you use `build.ps1` or `build.bat` on Windows, these are auto-detected from standard locations such as Codex, .pico-sdk, and xPacks)*:

#### On Linux / macOS (Bash / Zsh):
```bash
export PICO_SDK_PATH=/path/to/pico-sdk
export PICO_TOOLCHAIN_PATH=/path/to/arm-gnu-toolchain/bin   # (optional if in PATH)
```

#### On Windows (PowerShell):
```powershell
$env:PICO_SDK_PATH = "C:\Users\<user>\.pico-sdk\sdk\2.1.1"
$env:PICO_TOOLCHAIN_PATH = "C:\Users\<user>\.pico-sdk\toolchain\13_3_rel1\bin"
```

### 3. Install Python Dependencies
Install all required Python packages for the host gateway, benchmark harness, and adversarial security suites:

```bash
pip install pyserial cryptography numpy scipy
```

### 4. Build the Firmware

#### Option A: One-Step Build Script on Windows (Recommended)
The included `build.ps1` script (with `build.bat` wrapper) automatically discovers your Pico SDK, ARM toolchain (`arm-none-eabi-gcc`), Ninja, and picotool, configures CMake, and compiles all targets into `build-pico/`:

```powershell
# In PowerShell:
powershell -ExecutionPolicy Bypass -File .\build.ps1
# (or .\build.ps1 if your execution policy allows)
```

```cmd
# In Command Prompt (CMD) or by double-clicking:
build.bat
```

#### Option B: Using CMake Presets
```bash
# Configure using the RP2040 Pico preset
cmake --preset pico

# Build the firmware and test targets
cmake --build --preset pico
```

#### Option C: Standard CMake Command
```bash
mkdir build-pico && cd build-pico
cmake -G Ninja -DQSAC_TARGET_PICO=ON -DCMAKE_BUILD_TYPE=Release ..
ninja
```

The build produces the following artifacts in the `build-pico/` folder:
- `qsac_firmware.uf2` : Drag-and-drop firmware binary for RP2040.
- `qsac_firmware.elf` : ELF executable with debug symbols.
- `qsac_firmware.bin` / `qsac_firmware.hex` : Raw binary and Intel HEX formats.
- `test_pqc_standalone.uf2` : Standalone PQC unit test binary.

#### Option D: Building for Host Simulation (Linux / macOS)
To test and debug protocol logic on your PC without hardware:
```bash
mkdir build-host && cd build-host
cmake -G "Unix Makefiles" -DQSAC_TARGET_HOST=ON -DCMAKE_BUILD_TYPE=Debug ..
make
./qsac_firmware
```

---

## Run

### Step 1: Flash Firmware to the Microcontroller

#### Method 1: BOOTSEL Drag-and-Drop (Easiest)
1. Hold down the **BOOTSEL** button on your Raspberry Pi Pico.
2. Plug the USB cable into your computer while holding the button.
3. Release the button; a mass storage volume named `RPI-RP2` will appear.
4. Drag and drop `build-pico/qsac_firmware.uf2` onto the `RPI-RP2` drive.
5. The Pico automatically reboots and executes the firmware.

#### Method 2: Automated Script
On Linux or macOS:
```bash
./tools/flash.sh build-pico/qsac_firmware.uf2 pico
```

#### Method 3: Using `picotool`
```bash
picotool load build-pico/qsac_firmware.uf2 -f
picotool reboot
```

---

### Step 2: Observe Boot Self-Tests & Pin Status

Connect a serial monitor (e.g., PuTTY, minicom, or VS Code Serial Monitor) to the Pico's COM/TTY port at **115200 baud, 8-N-1**.

Upon boot, the device executes a 12-stage self-test and asserts corresponding status GPIO pins:

```text
╔══════════════════════════════════════════╗
║  QSAC — Quantum-Secure Access Control   ║
║  Firmware v0.1.0                         ║
║  Clock: 125 MHz                          ║
╚══════════════════════════════════════════╝

[INIT] Initializing crypto subsystem...
[INIT] Crypto subsystem ready.

-- Cryptographic Subsystem Self-Tests --

[TEST 1/12]  Hardware RNG (ATECC608B TRNG / ROSC)    [PASS] (5,487,285 cycles)
[TEST 2/12]  SHA-256 (NIST Vector)                   [PASS] (133,631 cycles)
[TEST 3/12]  SHA-3-256 (FIPS 202)                    [PASS] (285,568 cycles)
[TEST 4/12]  AES-256-GCM (Authenticated Roundtrip)  [PASS] (3,817,331 cycles)
[TEST 5/12]  ECC P-256 KeyGen                        [PASS] (64,419,025 cycles)
[TEST 6/12]  ECDH P-256 Key Agreement               [PASS] (50,140,675 cycles)
[TEST 7/12]  ECDSA P-256 Sign & Verify               [PASS] (56,241,675 cycles)
[TEST 8/12]  HKDF-SHA-256 Combiner                   [PASS] (77,320 cycles)
[TEST 9/12]  ML-KEM-512 (FIPS 203 Encaps/Decaps)     [PASS] (9,572,987 cycles)
[TEST 10/12] ML-DSA-44 (FIPS 204 Sign/Verify)        [PASS] (54,908,500 cycles)
[TEST 11/12] Hybrid Handshake Roundtrip              [PASS] (124,132,682 cycles)
[TEST 12/12] Access Control & Token Verification     [PASS] (6,889,375 cycles)
------------------------------------------
[RESULT] 12/12 tests passed ✓
------------------------------------------
[DONE] Hybrid Handshake & Access Control State Machine nominal.
[GATEWAY] Initializing Live Host UART Protocol Bridge...
[GATEWAY] Listening for Host PC / Gateway commands over USB-UART...
```

#### Hardware Pinout Status Matrix
| Pin | GPIO | Status Signal Name | Output | Verified Functionality |
| :---: | :---: | :--- | :---: | :--- |
| **Pin 6** | `GP4` | `I2C0_SDA` | I2C Data | ATECC608B HSM Data Line |
| **Pin 7** | `GP5` | `I2C0_SCL` | I2C Clock | ATECC608B HSM Clock Line |
| **Pin 9** | `GP6` | `QSAC_STATUS_PIN_SYS_READY` | 3.3V HIGH | System initialized & crypto engine ready |
| **Pin 10** | `GP7` | `QSAC_STATUS_PIN_RNG_OK` | 3.3V HIGH | TRNG / ROSC entropy operational |
| **Pin 11** | `GP8` | `QSAC_STATUS_PIN_SHA256_OK` | 3.3V HIGH | SHA-256 NIST vector validated |
| **Pin 12** | `GP9` | `QSAC_STATUS_PIN_SHA3_OK` | 3.3V HIGH | SHA-3-256 FIPS 202 validated |
| **Pin 14** | `GP10` | `QSAC_STATUS_PIN_AES_GCM_OK`| 3.3V HIGH | AES-256-GCM AEAD authenticated roundtrip OK |
| **Pin 15** | `GP11` | `QSAC_STATUS_PIN_ECC_KEYGEN`| 3.3V HIGH | Classical ECC P-256 keygen passed |
| **Pin 16** | `GP12` | `QSAC_STATUS_PIN_ECDH_OK` | 3.3V HIGH | ECDH shared secret agreement verified |
| **Pin 17** | `GP13` | `QSAC_STATUS_PIN_ECDSA_OK` | 3.3V HIGH | ECDSA sign and verify verified |
| **Pin 19** | `GP14` | `QSAC_STATUS_PIN_HKDF_OK` | 3.3V HIGH | HKDF-SHA-256 dual-key combiner OK |
| **Pin 20** | `GP15` | `QSAC_STATUS_PIN_SESSION_OK`| 3.3V HIGH | All self-tests passed & session nominal |
| **Pin 21** | `GP16` | `QSAC_STATUS_PIN_ERROR` | 0V LOW | Global error line (pulled HIGH on fault) |

---

### Step 3: Run the Host Gateway & Access Control Authority Server

Launch the host authority server to interactively perform hybrid handshakes, issue post-quantum capability tokens, and send encrypted commands:

```bash
python tools/gateway/qsac_server.py
```

The server automatically identifies available COM/TTY ports and presents an interactive CLI:
1. **Option [1] Perform Post-Quantum Hybrid Handshake**: Exchanges public keys, derives shared secret, and establishes an AES-256-GCM session.
2. **Option [2] Issue & Submit ML-DSA-44 Token**: Generates an authority-signed capability token for door access and sends it to the device for on-chip verification.
3. **Option [3] Send Encrypted Command**: Transmits authenticated telemetry requests or configuration commands.
4. **Option [4] Run Silicon Benchmarks**: Requests the device to report cycle counts and stack usage for all cryptographic primitives.

---

### Step 4: Run Physical Diagnostic Verification

Run the automated diagnostic suite to verify UF2 flashing, USB enumeration, and live protocol roundtrips:

```bash
python tools/physical_check.py
```

---

### Step 5: Run the Adversarial Security Assessment Suite

Execute the comprehensive 10-phase adversarial test suite to test defenses against packet tampering, replay, and forgery:

```bash
python tools/security/qsac_security_suite.py
```

#### Test Results Summary
| Test ID | Adversarial Scenario | Expected Defense | Result |
| :--- | :--- | :--- | :---: |
| **SEC-01** | CRC-16 Checksum Corruption | Corrupted frame discarded silently; link stable | **✓ PASS** |
| **SEC-02** | Malformed Framing Length | Parser recovers safely from truncated buffer | **✓ PASS** |
| **SEC-03** | Unknown Opcode Injection | Unknown opcodes rejected with `OP_ERROR` | **✓ PASS** |
| **SEC-04** | Handshake MitM Transcript Tampering | Ciphertext modification detected; handshake aborted | **✓ PASS** |
| **SEC-05** | Forged Authority Key Token | Untrusted authority ML-DSA-44 signature rejected | **✓ PASS** |
| **SEC-06** | Privilege Escalation Tamper Check | Modified permission bitmask detected by signature | **✓ PASS** |
| **SEC-07** | Expired Token Replay Attack | Stale timestamp rejected by monotonic clock check | **✓ PASS** |
| **SEC-08** | Out-of-Order State Injection | Unauthenticated commands blocked by state machine | **✓ PASS** |
| **SEC-09** | AES-256-GCM Ciphertext Bit-Flip | GHASH tag failure drops tampered payload | **✓ PASS** |
| **SEC-10** | AEAD Anti-Replay Counter Rollback | Decreased counter detected and rejected | **✓ PASS** |

---

### Step 6: Benchmark Performance Analysis

Run the benchmarking harness over UART to evaluate execution speed across iterations:

```bash
python tools/benchmarks.py --port COM3 --test speed --algo all --iterations 100
```

#### Empirical Benchmark Summary (RP2040 @ 125 MHz)
| Algorithm | Operation | Average Cycles | Latency (@ 125 MHz) | Peak Stack Usage |
| :--- | :--- | :---: | :---: | :---: |
| **ML-KEM-512** | KeyGen | 12,621,037 | 100.97 ms | 1,520 bytes |
| **ML-KEM-512** | Encapsulation | 7,386,287 | 59.09 ms | 1,568 bytes |
| **ML-KEM-512** | Decapsulation | 2,186,700 | **17.49 ms** | 2,528 bytes |
| **ML-DSA-44** | KeyGen | 11,847,625 | 94.78 ms | 1,136 bytes |
| **ML-DSA-44** | Sign | 48,019,125 | 384.15 ms | 1,440 bytes |
| **ML-DSA-44** | Verify | 6,889,375 | **55.12 ms** | 1,288 bytes |
| **ECDH P-256** | KeyGen | 64,419,025 | 515.35 ms | 992 bytes |
| **ECDH P-256** | Shared Secret | 50,140,675 | 401.12 ms | 1,136 bytes |
| **AES-256-GCM** | Encrypt (1 KB) | 3,817,331 | 30.54 ms | 800 bytes |
| **AES-256-GCM** | Decrypt (1 KB) | 3,816,962 | 30.54 ms | 788 bytes |
| **SHA-256** | 1 KB Hash | 133,631 | 1.07 ms | 692 bytes |
| **SHA-3-256** | 1 KB Hash | 285,568 | 2.28 ms | 940 bytes |
| **HKDF-SHA-256**| Key Derivation | 77,320 | 0.62 ms | 1,244 bytes |

---

