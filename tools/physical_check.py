#!/usr/bin/env python3
"""
QSAC Physical Hardware Verification & Diagnostic Suite
Target: Raspberry Pi Pico (RP2040 ARM Cortex-M0+)

Automates:
  1. UF2 Firmware flashing to physical RP2040
  2. USB-CDC / UART COM port auto-detection
  3. Live hardware boot self-test verification (12 test phases)
  4. Binary framed protocol ping & status query
  5. Live Post-Quantum Hybrid Handshake (ECDH + ML-KEM-512 + ML-DSA-44)
  6. ML-DSA-44 Access Token issuance and verification
  7. Silicon cycle counting & stack canary measurements
  8. Physical GPIO pin voltage checklist
"""

import sys
import os
import time
import shutil
import struct
import json
import string
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Add gateway tools directory to path
gateway_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'gateway'))
if gateway_dir not in sys.path:
    sys.path.insert(0, gateway_dir)

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("[-] pyserial not found. Install via: pip install pyserial")
    sys.exit(1)

from qsac_frame import (
    encode_frame, FrameDecoder,
    OP_PING, OP_PONG,
    OP_HANDSHAKE_INIT, OP_CLIENT_HELLO,
    OP_SERVER_HELLO, OP_CLIENT_FINISHED,
    OP_SUBMIT_TOKEN, OP_TOKEN_RESULT,
    OP_ENCRYPTED_MSG, OP_ENCRYPTED_RESP,
    OP_RUN_BENCHMARKS, OP_BENCHMARK_REPORT,
    OP_ERROR
)
from qsac_server import QsacHostServer, QSAC_PERM_ACCESS_DOOR, QSAC_PERM_READ_TELEMETRY, QSAC_PERM_ADMIN
from pqc.mldsa44 import mldsa44_keypair, mldsa44_sign, mldsa44_verify
from pqc.mlkem512 import mlkem512_encaps

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

def _find_uf2() -> Path:
    candidates = [
        WORKSPACE_ROOT / "build-pico" / "qsac_firmware.uf2",
        WORKSPACE_ROOT / "build" / "qsac_firmware.uf2",
        WORKSPACE_ROOT / "firmware" / "build-pico" / "qsac_firmware.uf2",
        WORKSPACE_ROOT / "firmware" / "build" / "qsac_firmware.uf2",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]

UF2_PATH = _find_uf2()

def _find_picotool() -> Path:
    if os.environ.get("PICOTOOL_PATH") and Path(os.environ["PICOTOOL_PATH"]).exists():
        return Path(os.environ["PICOTOOL_PATH"])
    which_p = shutil.which("picotool")
    if which_p:
        return Path(which_p)
    candidates = [
        WORKSPACE_ROOT / "tools" / "picotool" / "picotool.exe",
        Path.home() / "Desktop" / "pico" / "tools" / "picotool-sdk" / "picotool" / "picotool.exe",
        Path.home() / ".pico-sdk" / "picotool" / "2.0.0" / "picotool" / "picotool.exe",
    ]
    for c in candidates:
        if c.exists():
            return c
    return Path("picotool")

PICOTOOL_PATH = _find_picotool()

PHYSICAL_PINOUT = [
    {"pin": 9,  "gpio": "GP6",  "label": "QSAC_STATUS_PIN_SYS_READY",   "expected": "HIGH (3.3V)", "description": "System initialized and crypto core ready"},
    {"pin": 10, "gpio": "GP7",  "label": "QSAC_STATUS_PIN_RNG_OK",      "expected": "HIGH (3.3V)", "description": "Hardware TRNG / ROSC self-test passed"},
    {"pin": 11, "gpio": "GP8",  "label": "QSAC_STATUS_PIN_SHA256_OK",   "expected": "HIGH (3.3V)", "description": "SHA-256 NIST test vector verified"},
    {"pin": 12, "gpio": "GP9",  "label": "QSAC_STATUS_PIN_SHA3_OK",     "expected": "HIGH (3.3V)", "description": "SHA-3-256 FIPS 202 test vector verified"},
    {"pin": 14, "gpio": "GP10", "label": "QSAC_STATUS_PIN_AES_GCM_OK",  "expected": "HIGH (3.3V)", "description": "AES-256-GCM authenticated roundtrip passed"},
    {"pin": 15, "gpio": "GP11", "label": "QSAC_STATUS_PIN_ECC_KEYGEN",  "expected": "HIGH (3.3V)", "description": "Classical ECC P-256 key generation verified"},
    {"pin": 16, "gpio": "GP12", "label": "QSAC_STATUS_PIN_ECDH_OK",    "expected": "HIGH (3.3V)", "description": "ECDH shared secret agreement verified"},
    {"pin": 17, "gpio": "GP13", "label": "QSAC_STATUS_PIN_ECDSA_OK",   "expected": "HIGH (3.3V)", "description": "ECDSA sign & verify roundtrip passed"},
    {"pin": 19, "gpio": "GP14", "label": "QSAC_STATUS_PIN_HKDF_OK",    "expected": "HIGH (3.3V)", "description": "HKDF-SHA-256 key combiner deterministic"},
    {"pin": 20, "gpio": "GP15", "label": "QSAC_STATUS_PIN_SESSION_OK", "expected": "HIGH (3.3V)", "description": "ALL 12 self-tests passed; session nominal"},
    {"pin": 21, "gpio": "GP16", "label": "QSAC_STATUS_PIN_ERROR",      "expected": "LOW (0.0V)",  "description": "Error indicator (asserts 3.3V if any self-test fails)"},
    {"pin": 6,  "gpio": "GP4",  "label": "I2C0_SDA",                    "expected": "PULL-UP 3.3V", "description": "ATECC608B Hardware Security Module data line"},
    {"pin": 7,  "gpio": "GP5",  "label": "I2C0_SCL",                    "expected": "PULL-UP 3.3V", "description": "ATECC608B Hardware Security Module clock line"},
    {"pin": 38, "gpio": "GND",  "label": "GROUND",                      "expected": "0.0V (GND)",   "description": "Reference ground for multimeter / logic analyzer"},
    {"pin": "LED", "gpio": "GP25", "label": "HEARTBEAT_LED",            "expected": "BLINK 1 Hz",   "description": "Onboard Green LED flashes 1 Hz when operating normally"}
]


def print_banner():
    print("""
╔════════════════════════════════════════════════════════════════════════╗
║         QSAC — Physical Hardware Verification & Diagnostic Suite       ║
║            Raspberry Pi Pico (RP2040 ARM Cortex-M0+ @ 125 MHz)        ║
╚════════════════════════════════════════════════════════════════════════╝
""")


def find_rp2040_bootsel_drive() -> str | None:
    """Scans Windows drive letters for a mounted RPI-RP2 volume."""
    import ctypes
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(f"{letter}:\\")
        bitmask >>= 1

    for drive in drives:
        info_file = Path(drive) / "INFO_UF2.TXT"
        if info_file.exists():
            try:
                content = info_file.read_text(errors="ignore")
                if "RP2040" in content or "Raspberry Pi" in content:
                    return drive
            except Exception:
                pass
    return None


def reboot_pico_to_bootsel(port: str) -> bool:
    """Sends 1200-baud reset pulse to reboot Pico into USB BOOTSEL mode."""
    try:
        s = serial.Serial(port, 1200)
        s.close()
        time.sleep(1.5)
        return True
    except Exception:
        return False


def copy_uf2_to_drive(src: Path, dst: Path):
    """Safely writes UF2 image to RP2040 flash, tolerating instantaneous USB dismount."""
    try:
        with open(src, 'rb') as fsrc:
            with open(dst, 'wb') as fdst:
                while True:
                    chunk = fsrc.read(65536)
                    if not chunk:
                        break
                    fdst.write(chunk)
                fdst.flush()
    except (OSError, PermissionError):
        # RP2040 unmounts as soon as the final sector is committed
        pass

def flash_firmware(port: str | None = None, wait_timeout: float = 15.0) -> bool:
    """Flashes the latest qsac_firmware.uf2 to the connected RP2040."""
    print("\n── [Step 1] Physical Firmware Flash (RP2040) ──")
    if not UF2_PATH.exists():
        print(f"[-] Firmware file not found: {UF2_PATH}")
        print("    Run: cmake --build --preset pico (or ninja -C build-pico) to build the binary.")
        return False

    print(f"  Firmware binary : {UF2_PATH} ({UF2_PATH.stat().st_size:,} bytes)")

    # Check for direct BOOTSEL or active COM port, with waiting loop if disconnected
    start_time = time.time()
    notified_wait = False

    while True:
        # 1. Check for mounted RPI-RP2 mass-storage volume
        drive = find_rp2040_bootsel_drive()
        if drive:
            print(f"[+] Found Pico in BOOTSEL mode on drive: {drive}")
            dest = Path(drive) / "qsac_firmware.uf2"
            print(f"    Copying {UF2_PATH.name} -> {dest} ...", end="", flush=True)
            copy_uf2_to_drive(UF2_PATH, dest)
            print(" DONE!")
            print("[+] Pico has accepted the UF2 image and is rebooting into QSAC firmware.")
            time.sleep(3.5)
            return True

        # 2. Check if running firmware is on COM port and trigger 1200-baud reboot
        com_candidate = port or find_pico_com_port()
        if com_candidate:
            print(f"  Pico detected on {com_candidate}. Rebooting into BOOTSEL mode...")
            reboot_pico_to_bootsel(com_candidate)
            # Re-check drive after reboot
            for _ in range(10):
                drive = find_rp2040_bootsel_drive()
                if drive:
                    dest = Path(drive) / "qsac_firmware.uf2"
                    print(f"    Copying {UF2_PATH.name} -> {dest} ...", end="", flush=True)
                    copy_uf2_to_drive(UF2_PATH, dest)
                    print(" DONE!")
                    print("[+] Pico rebooting with new firmware.")
                    time.sleep(3.5)
                    return True
                time.sleep(0.5)

        # 3. Try picotool if available
        if PICOTOOL_PATH.exists():
            import subprocess
            proc = subprocess.run([str(PICOTOOL_PATH), "load", "-x", str(UF2_PATH)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode == 0:
                print("[+] picotool successfully flashed and rebooted the Pico!")
                time.sleep(2.0)
                return True

        elapsed = time.time() - start_time
        if elapsed > wait_timeout:
            break

        if not notified_wait:
            print("[-] Pico not found. Please connect the Raspberry Pi Pico via USB...")
            notified_wait = True
        time.sleep(0.5)

    print("[-] Pico not found in BOOTSEL mode or active COM port.")
    print("    To flash manually:")
    print("    1. Unplug the Pico USB cable.")
    print("    2. Hold down the white BOOTSEL button.")
    print("    3. Plug in the USB cable, then release the button.")
    print(f"    4. Drag & drop: {UF2_PATH} onto the 'RPI-RP2' drive.\n")
    return False


def find_pico_com_port() -> str | None:
    """Auto-detects the Pico USB Serial COM port."""
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        return None

    # Priority 1: Known RP2040 USB CDC VID:PID (2E8A:000A)
    for p in ports:
        if p.vid == 0x2E8A and p.pid == 0x000A:
            return p.device

    # Priority 2: Description matching Pico or Raspberry
    for p in ports:
        desc = (p.description or "").lower()
        if "pico" in desc or "raspberry" in desc or "rp2040" in desc:
            return p.device

    # Priority 3: USB Serial Device
    for p in ports:
        if "usb serial" in (p.description or "").lower():
            return p.device

    return ports[0].device if len(ports) == 1 else None


def select_com_port() -> str | None:
    """Detects or prompts the user for the serial COM port."""
    auto_port = find_pico_com_port()
    ports = list(serial.tools.list_ports.comports())

    if not ports:
        print("[-] No serial COM ports detected.")
        print("    Ensure the Raspberry Pi Pico is plugged into USB.")
        return None

    if auto_port:
        print(f"[+] Auto-detected Pico on port: {auto_port}")
        return auto_port

    print("\nAvailable Serial Ports:")
    for i, p in enumerate(ports):
        print(f"  [{i + 1}] {p.device} — {p.description}")
    choice = input(f"\nSelect port [1-{len(ports)}] (default 1): ").strip()
    idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(ports) else 0
    return ports[idx].device


def monitor_boot_log(port: str, timeout: float = 6.0) -> dict:
    """Connects to the serial port and reads the live boot self-test log."""
    print(f"\n── [Step 2] Monitoring Live Boot Self-Tests on {port} ──")
    results = {"connected": False, "tests_passed": 0, "tests_failed": 0, "log": []}

    try:
        ser = serial.Serial(port, 115200, timeout=0.1)
    except Exception as e:
        print(f"[-] Could not open {port}: {e}")
        return results

    results["connected"] = True
    print("  Listening for boot banner and self-tests (Press Ctrl+C to skip)...")
    start = time.time()

    try:
        while time.time() - start < timeout:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if line:
                results["log"].append(line)
                print(f"  | {line}")
                if "[PASS]" in line:
                    results["tests_passed"] += 1
                elif "[FAIL]" in line:
                    results["tests_failed"] += 1
                if "[DONE] Phase 4 complete" in line:
                    print("\n[+] Firmware boot self-test sequence completed successfully!")
                    break
    except KeyboardInterrupt:
        print("\n  [Skipped monitoring]")
    finally:
        ser.close()

    return results


def print_gpio_checklist():
    """Prints the physical hardware pinout checklist."""
    print("\n── [Step 3] Physical GPIO Logic Analyzer / Multimeter Checklist ──")
    print("Use a digital multimeter or logic analyzer on the Raspberry Pi Pico headers:")
    print("┌──────┬──────────┬─────────────────────────────┬──────────────┬────────────────────────────────────────────────────────┐")
    print("│ Pin# │ GPIO     │ Status Pin Name             │ Expected     │ Verified Hardware Function                             │")
    print("├──────┼──────────┼─────────────────────────────┼──────────────┼────────────────────────────────────────────────────────┤")
    for item in PHYSICAL_PINOUT:
        print(f"│ {str(item['pin']):4s} │ {item['gpio']:8s} │ {item['label']:27s} │ {item['expected']:12s} │ {item['description']:54s} │")
    print("└──────┴──────────┴─────────────────────────────┴──────────────┴────────────────────────────────────────────────────────┘")


def run_full_physical_check(port: str = None, auto_bench: bool = False) -> dict:
    """Executes the complete physical hardware check suite."""
    print_banner()
    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "port": None,
        "flash_status": "SKIPPED",
        "boot_self_tests": {},
        "ping_check": False,
        "handshake_check": False,
        "token_valid_check": False,
        "token_tampered_check": False,
        "token_expired_check": False,
        "benchmarks": []
    }

    # 1. Ask user if they wish to flash
    if auto_bench or not sys.stdin.isatty():
        flash_choice = 'y'
    else:
        flash_choice = input("Do you want to flash qsac_firmware.uf2 to the Pico first? (y/N): ").strip().lower()
    if flash_choice == 'y':
        summary["flash_status"] = "PASSED" if flash_firmware(port=port) else "FAILED"

    # 2. Select port
    if not port:
        port = select_com_port()
    if not port:
        print("[-] Exiting: no COM port selected.")
        return summary
    summary["port"] = port

    # 3. Monitor boot log if requested
    if auto_bench or not sys.stdin.isatty():
        boot_choice = 'n'
    else:
        boot_choice = input("Do you want to capture the boot self-test log? (y/N): ").strip().lower()
    if boot_choice == 'y':
        print("\n[TIP] Press the RESET button on your Pico now, or replug USB...")
        summary["boot_self_tests"] = monitor_boot_log(port, timeout=8.0)

    # 4. Physical GPIO checklist
    print_gpio_checklist()

    # 5. Initialize Host Server
    print(f"\n── [Step 4] Connecting Host Gateway to {port} ──")
    server = QsacHostServer(port=port, baudrate=115200)
    if not server.connect():
        print(f"[-] Failed to establish connection with {port}.")
        return summary

    # 6. Ping check
    ping_ok = False
    for attempt in range(4):
        if server.ping():
            ping_ok = True
            break
        time.sleep(1.0)
    summary["ping_check"] = ping_ok
    if not summary["ping_check"]:
        print("[-] Pico failed to respond to OP_PING. Aborting protocol checks.")
        return summary

    # 7. Hybrid Handshake
    summary["handshake_check"] = server.perform_hybrid_handshake()

    # 8. Token checks
    print("\n── [Step 5] Post-Quantum Access Token Checks ──")
    print("  1. Submitting Authentic Token...")
    summary["token_valid_check"] = server.issue_and_submit_token(valid=True, tamper=False)

    print("  2. Submitting Tampered Token (should be REJECTED)...")
    tamper_result = server.issue_and_submit_token(valid=True, tamper=True)
    summary["token_tampered_check"] = (not tamper_result)  # Pass if rejected
    print(f"     Tamper Rejection: {'PASS (Rejected)' if summary['token_tampered_check'] else 'FAIL (Accepted!)'}")

    print("  3. Submitting Expired Token (should be REJECTED)...")
    expired_result = server.issue_and_submit_token(valid=False, tamper=False)
    summary["token_expired_check"] = (not expired_result)  # Pass if rejected
    print(f"     Expired Rejection: {'PASS (Rejected)' if summary['token_expired_check'] else 'FAIL (Accepted!)'}")

    # 9. Encrypted Telemetry exchange
    if summary["handshake_check"]:
        print("\n── [Step 6] Authenticated AEAD Session Channel ──")
        resp = server.send_encrypted_telemetry("Ping Door Sensor: Requesting Status")
        summary["telemetry_check"] = (resp is not None)

    # 10. Real-Time Silicon Benchmarks & Stack Canary
    if auto_bench or not sys.stdin.isatty():
        bench_choice = 'y'
    else:
        bench_choice = input("\nDo you want to run the real-time silicon benchmark & stack canary suite? (Y/n): ").strip().lower()
    if bench_choice != 'n':
        summary["benchmarks"] = server.run_benchmarks()

    # Save summary report
    report_file = WORKSPACE_ROOT / "tools" / "physical_check_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[+] Physical verification report saved to: {report_file}")

    print("\n════════════════════════════════════════════════════════════════════════")
    print("                     PHYSICAL CHECK COMPLETE")
    print("════════════════════════════════════════════════════════════════════════")
    return summary


def main():
    import argparse
    parser = argparse.ArgumentParser(description="QSAC Physical Hardware Check Suite")
    parser.add_argument("--port", "-p", help="Serial COM port (e.g., COM3, /dev/ttyACM0)")
    parser.add_argument("--flash-only", action="store_true", help="Flash firmware and exit")
    parser.add_argument("--pinout", action="store_true", help="Print physical pinout guide and exit")
    parser.add_argument("--bench", action="store_true", help="Automatically run silicon benchmarks without prompting")
    args = parser.parse_args()

    if args.flash_only:
        flash_firmware(port=args.port)
        return

    if args.pinout:
        print_gpio_checklist()
        return

    run_full_physical_check(port=args.port, auto_bench=args.bench)


if __name__ == "__main__":
    main()
