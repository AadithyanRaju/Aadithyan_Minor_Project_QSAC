#!/usr/bin/env python3
"""
QSAC Fine-Grained Role-Based Access Control (RBAC) Permutation Matrix
Tests all 16 permission bitmask permutations (2^4 combinations) under ML-DSA-44 authentication.
"""

import sys
import os
import time
import struct
import json
import serial
import serial.tools.list_ports

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'gateway')))

from qsac_frame import (
    encode_frame, FrameDecoder,
    OP_PING, OP_PONG,
    OP_HANDSHAKE_INIT,
    OP_SUBMIT_TOKEN, OP_TOKEN_RESULT
)
from qsac_server import (
    QsacHostServer,
    QSAC_PERM_READ_TELEMETRY,
    QSAC_PERM_ACCESS_DOOR,
    QSAC_PERM_CONFIG_UPDATE,
    QSAC_PERM_ADMIN
)
from pqc.mldsa44 import mldsa44_sign

PERM_DEFS = [
    ("READ_TELEMETRY", QSAC_PERM_READ_TELEMETRY),
    ("ACCESS_DOOR",    QSAC_PERM_ACCESS_DOOR),
    ("CONFIG_UPDATE",  QSAC_PERM_CONFIG_UPDATE),
    ("ADMIN",          QSAC_PERM_ADMIN)
]

class QsacRbacTester:
    def __init__(self, port: str = None, baudrate: int = 115200):
        self.server = QsacHostServer(port=port, baudrate=baudrate)
        self.results = []

    def connect(self) -> bool:
        return self.server.connect()

    def run_rbac_matrix(self):
        print("\n╔══════════════════════════════════════════════════════════════════════╗")
        print("║     QSAC — Role-Based Access Control (RBAC) Permutation Matrix       ║")
        print("║    Testing 16 Permission Bitmask Permutations (ML-DSA-44 Signed)     ║")
        print("╚══════════════════════════════════════════════════════════════════════╝\n")

        # Ensure authority key is provisioned
        self.server.send_frame(OP_HANDSHAKE_INIT, self.server.auth_pk)
        time.sleep(0.1)
        while self.server.ser.in_waiting:
            self.server.ser.read(self.server.ser.in_waiting)

        now = int(time.time())
        device_id = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])

        # Test all 16 permutations (bit combinations 0..15)
        for i in range(16):
            perm_mask = 0
            perm_names = []
            if i & 1:
                perm_mask |= QSAC_PERM_READ_TELEMETRY
                perm_names.append("TELEM")
            if i & 2:
                perm_mask |= QSAC_PERM_ACCESS_DOOR
                perm_names.append("DOOR")
            if i & 4:
                perm_mask |= QSAC_PERM_CONFIG_UPDATE
                perm_names.append("CONFIG")
            if i & 8:
                perm_mask |= QSAC_PERM_ADMIN
                perm_names.append("ADMIN")

            perm_desc = "+".join(perm_names) if perm_names else "NONE (0x00)"

            payload_bytes = struct.pack('<16sIII', device_id, now - 10, now + 3600, perm_mask)
            sig = mldsa44_sign(self.server.auth_sk, payload_bytes)
            token_frame = struct.pack('<I', now) + payload_bytes + sig

            self.server.ser.reset_input_buffer()
            self.server.send_frame(OP_SUBMIT_TOKEN, token_frame)

            res = self.server.receive_frame(OP_TOKEN_RESULT, timeout=2.0)
            passed = False
            granted_perms = 0
            status = -1

            if res:
                _, resp_payload = res
                if len(resp_payload) >= 8:
                    status, granted_perms = struct.unpack('<iI', resp_payload[:8])
                    # If perm_mask is 0, access should be denied or granted with 0
                    if perm_mask == 0:
                        passed = (status == 0 and granted_perms == 0) or (status != 0)
                    else:
                        passed = (status == 0 and granted_perms == perm_mask)

            status_icon = "✓ PASS" if passed else "✗ FAIL"
            print(f"  [{i+1:02d}/16] Mask: 0x{perm_mask:08X} ({perm_desc:<24}) -> Granted: 0x{granted_perms:08X} [{status_icon}]")

            self.results.append({
                "index": i + 1,
                "requested_mask": f"0x{perm_mask:08X}",
                "description": perm_desc,
                "granted_mask": f"0x{granted_perms:08X}",
                "status_code": status,
                "passed": passed
            })
            time.sleep(0.05)

        self.display_summary()

    def display_summary(self):
        passed_count = sum(1 for r in self.results if r['passed'])
        total_count = len(self.results)
        print("\n══════════════════════════════════════════════════════════════════════")
        print(f"       RBAC PERMUTATION MATRIX SUMMARY: {passed_count}/{total_count} PASSED ({passed_count/total_count*100:.1f}%)")
        print("══════════════════════════════════════════════════════════════════════")

        if passed_count == total_count:
            print("[✓] STRICT PRINCIPLE OF LEAST PRIVILEGE CONFIRMED ACROSS ALL 16 ROLES!\n")

        with open("tools/security/rbac_results.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        print("[+] RBAC Results saved to tools/security/rbac_results.json\n")

def main():
    tester = QsacRbacTester()
    if tester.connect():
        tester.run_rbac_matrix()

if __name__ == '__main__':
    main()
