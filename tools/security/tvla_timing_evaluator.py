#!/usr/bin/env python3
"""
QSAC TVLA Timing Leakage & Constant-Time Assessment Suite
Evaluates side-channel timing variance and computes Welch's t-test statistic (|t| < 4.5 threshold).
"""

import sys
import os
import time
import struct
import math
import json
import serial
import serial.tools.list_ports

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'gateway')))

from qsac_frame import (
    encode_frame, FrameDecoder,
    OP_PING, OP_PONG,
    OP_TVLA_REQUEST, OP_TVLA_SAMPLE
)
from qsac_server import QsacHostServer

PRIMITIVES = [
    {"id": 0, "name": "ML-KEM-512 Decaps (FIPS 203)", "unit": "us", "trials": 50},
    {"id": 1, "name": "ML-DSA-44 Verify (FIPS 204)", "unit": "us", "trials": 50},
    {"id": 2, "name": "AES-256-GCM Decrypt / Tag Check", "unit": "us", "trials": 50},
]

class QsacTvlaEvaluator:
    def __init__(self, port: str = None, baudrate: int = 115200):
        self.server = QsacHostServer(port=port, baudrate=baudrate)
        self.results = {}

    def connect(self) -> bool:
        return self.server.connect()

    def run_tvla_for_primitive(self, prim_id: int, name: str, count: int):
        print(f"\n── Probing TVLA: {name} (N = {count} per class) ──")
        
        samples_fixed = []
        samples_random = []

        # Class 0: Fixed / Valid
        print(f"  1. Collecting Class A (Fixed / Valid Inputs)...", end="", flush=True)
        payload = struct.pack('<BBH', prim_id, 0, count)
        self.server.send_frame(OP_TVLA_REQUEST, payload)

        while True:
            res = self.server.receive_frame(OP_TVLA_SAMPLE, timeout=10.0)
            if not res:
                break
            _, frame_payload = res
            if len(frame_payload) >= 16:
                p_id, c_id, idx, us, cyc = struct.unpack('<BBHIQ', frame_payload[:16])
                if idx == 0xFFFF:  # End marker
                    break
                samples_fixed.append(us)
        print(f" done ({len(samples_fixed)} samples)")

        # Class 1: Random / Invalid
        print(f"  2. Collecting Class B (Random / Invalid Inputs)...", end="", flush=True)
        payload = struct.pack('<BBH', prim_id, 1, count)
        self.server.send_frame(OP_TVLA_REQUEST, payload)

        while True:
            res = self.server.receive_frame(OP_TVLA_SAMPLE, timeout=10.0)
            if not res:
                break
            _, frame_payload = res
            if len(frame_payload) >= 16:
                p_id, c_id, idx, us, cyc = struct.unpack('<BBHIQ', frame_payload[:16])
                if idx == 0xFFFF:  # End marker
                    break
                samples_random.append(us)
        print(f" done ({len(samples_random)} samples)")

        if not samples_fixed or not samples_random:
            print(f"[-] Error: Insufficient samples collected for {name}")
            return None

        # Statistical Calculations
        n_a = len(samples_fixed)
        n_b = len(samples_random)

        mean_a = sum(samples_fixed) / n_a
        mean_b = sum(samples_random) / n_b

        var_a = sum((x - mean_a) ** 2 for x in samples_fixed) / (n_a - 1) if n_a > 1 else 0
        var_b = sum((x - mean_b) ** 2 for x in samples_random) / (n_b - 1) if n_b > 1 else 0

        std_a = math.sqrt(var_a)
        std_b = math.sqrt(var_b)

        # Welch's t-statistic
        denom = math.sqrt((var_a / n_a) + (var_b / n_b)) if (var_a + var_b) > 0 else 1e-9
        t_stat = (mean_a - mean_b) / denom if denom != 0 else 0.0

        # Non-leakage assessment threshold: |t| < 4.5
        passed = abs(t_stat) < 4.5

        res_dict = {
            "name": name,
            "samples_a": n_a,
            "samples_b": n_b,
            "mean_a_us": mean_a,
            "mean_b_us": mean_b,
            "std_a_us": std_a,
            "std_b_us": std_b,
            "delta_us": mean_a - mean_b,
            "t_statistic": t_stat,
            "threshold": 4.5,
            "passed": passed
        }
        self.results[name] = res_dict
        return res_dict

    def run_all_tvla(self):
        print("\n╔══════════════════════════════════════════════════════════════════════╗")
        print("║      QSAC — Statistical Side-Channel Timing Assessment (TVLA)        ║")
        print("║   Testing Constant-Time Execution via Welch's Two-Sample t-Test      ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")

        for prim in PRIMITIVES:
            self.run_tvla_for_primitive(prim["id"], prim["name"], prim["trials"])

        self.display_summary()

    def display_summary(self):
        print("\n┌──────────────────────────────────────┬─────────────┬─────────────┬───────────┬─────────────┬──────────┐")
        print("│ Cryptographic Primitive Probed       │ Fixed (us)  │ Random (us) │ Diff (us) │ Welch's |t| │ TVLA Ev. │")
        print("├──────────────────────────────────────┼─────────────┼─────────────┼───────────┼─────────────┼──────────┤")
        
        all_passed = True
        for name, r in self.results.items():
            t_val = abs(r["t_statistic"])
            status = "PASS (CT)" if r["passed"] else "FAIL (LEAK)"
            if not r["passed"]:
                all_passed = False
            print(f"│ {r['name']:<36} │ {r['mean_a_us']:>9.2f} us │ {r['mean_b_us']:>9.2f} us │ {r['delta_us']:>7.2f} us │ {t_val:>9.3f}   │ {status:<8} │")

        print("└──────────────────────────────────────┴─────────────┴─────────────┴───────────┴─────────────┴──────────┘")
        print(f"\n[+] Standard Non-Leakage Threshold: |t| < 4.5 (NIST / CRI criteria at p < 1e-5)")
        if all_passed:
            print("[✓] ALL PROBED PRIMITIVES SATISFY CONSTANT-TIME TIMING INVARIANCE!")
        else:
            print("[-] Potential timing variance detected outside |t| < 4.5 margin.")

        # Save JSON results
        os.makedirs("tools/security", exist_ok=True)
        with open("tools/security/tvla_results_rp2040.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)
        print("[+] TVLA Dataset saved to tools/security/tvla_results_rp2040.json\n")

def main():
    evaluator = QsacTvlaEvaluator()
    if evaluator.connect():
        evaluator.run_all_tvla()

if __name__ == '__main__':
    main()
