#!/bin/bash
# QSAC Flash Script
# Flashes the firmware to the target board.
#
# Usage:
#   ./flash.sh [file] [interface]
#
# Examples:
#   ./flash.sh ../build-pico/qsac_firmware.uf2 pico       # Raspberry Pi Pico (default)
#   ./flash.sh ../build-pico/qsac_firmware.uf2 picotool   # Pico via picotool
#   ./flash.sh ../build-pico/qsac_firmware.bin openocd     # OpenOCD (SWD debug probe)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Search for firmware if not explicitly passed
if [ -z "${1:-}" ]; then
    if [ -f "$WORKSPACE_ROOT/build-pico/qsac_firmware.uf2" ]; then
        FIRMWARE="$WORKSPACE_ROOT/build-pico/qsac_firmware.uf2"
    elif [ -f "$WORKSPACE_ROOT/build/qsac_firmware.uf2" ]; then
        FIRMWARE="$WORKSPACE_ROOT/build/qsac_firmware.uf2"
    else
        FIRMWARE="$WORKSPACE_ROOT/build-pico/qsac_firmware.uf2"
    fi
else
    FIRMWARE="$1"
fi

INTERFACE="${2:-pico}"

echo "========================================="
echo "  QSAC Firmware Flash"
echo "========================================="
echo "  Firmware:  $FIRMWARE"
echo "  Interface: $INTERFACE"

if [ ! -f "$FIRMWARE" ]; then
    echo ""
    echo "Error: Firmware not found: $FIRMWARE"
    echo ""
    echo "Build first:"
    echo "  # Raspberry Pi Pico firmware:"
    echo "  cmake --preset pico"
    echo "  cmake --build --preset pico"
    exit 1
fi

echo "  Size:      $(stat -c%s "$FIRMWARE") bytes"
echo ""

case "$INTERFACE" in
    pico)
        echo "Flashing Raspberry Pi Pico via USB mass storage..."
        echo ""
        echo "Instructions:"
        echo "  1. Hold the BOOTSEL button on the Pico"
        echo "  2. Plug the Pico into USB (while holding BOOTSEL)"
        echo "  3. Release BOOTSEL — the Pico mounts as RPI-RP2"
        echo ""

        # Try to find the Pico mount point
        PICO_MOUNT=""
        for mount_dir in /media/$USER/RPI-RP2 /run/media/$USER/RPI-RP2 /mnt/pico; do
            if [ -d "$mount_dir" ]; then
                PICO_MOUNT="$mount_dir"
                break
            fi
        done

        if [ -z "$PICO_MOUNT" ]; then
            echo "Error: Pico not found as USB mass storage device."
            echo "Make sure the Pico is in BOOTSEL mode (hold BOOTSEL + plug USB)."
            echo ""
            echo "Manual flash:"
            echo "  cp $FIRMWARE /media/\$USER/RPI-RP2/"
            exit 1
        fi

        echo "Found Pico at: $PICO_MOUNT"
        cp "$FIRMWARE" "$PICO_MOUNT/"
        echo "Copied $FIRMWARE → $PICO_MOUNT/"
        echo ""
        echo "The Pico will automatically reboot and start running."
        ;;

    picotool)
        echo "Flashing via picotool..."
        # Requires: sudo apt install picotool  (or build from source)
        picotool load "$FIRMWARE" -f
        picotool reboot
        ;;

    openocd)
        echo "Flashing via OpenOCD (SWD debug probe)..."
        # Requires: OpenOCD with RP2040 support
        # Use with a Raspberry Pi Debug Probe, Picoprobe, or J-Link
        BIN_FILE="${FIRMWARE%.uf2}.bin"
        if [[ "$FIRMWARE" == *.uf2 ]]; then
            echo "Note: OpenOCD requires .bin, not .uf2"
            if [ -f "$BIN_FILE" ]; then
                FIRMWARE="$BIN_FILE"
            else
                echo "Error: .bin file not found: $BIN_FILE"
                exit 1
            fi
        fi
        openocd -f interface/cmsis-dap.cfg -f target/rp2040.cfg \
            -c "adapter speed 5000" \
            -c "program $FIRMWARE verify reset exit 0x10000000"
        ;;

    *)
        echo "Unknown interface: $INTERFACE"
        echo ""
        echo "Supported interfaces:"
        echo "  pico     — USB mass storage drag-and-drop (default)"
        echo "  picotool — picotool CLI"
        echo "  openocd  — OpenOCD via SWD debug probe"
        exit 1
        ;;
esac

echo ""
echo "Flash complete."
