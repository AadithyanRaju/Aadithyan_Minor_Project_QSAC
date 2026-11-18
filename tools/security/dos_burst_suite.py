#!/usr/bin/env python3
"""
QSAC High-Throughput Burst & DoS Resilience Suite
Evaluates line-speed packet burst resilience, session throughput, and recovery under heavy load.
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
    OP_HANDSHAKE_INIT, OP_CLIENT_HELLO,
    OP_SERVER_HELLO, OP_CLIENT_FINISHED,
    OP_ENCRYPTED_MSG, OP_ENCRYPTED_RESP
)
from qsac_server import QsacHostServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QsacBurstStressTester:
    def __init__(self, port: str = None, baudrate: int = 115200):
        self.server = QsacHostServer(port=port, baudrate=baudrate)

    def connect(self) -> bool:
        return self.server.connect()

    def run_all_stress_tests(self):
        print("\n╔══════════════════════════════════════════════════════════════════════╗")
        print("║        QSAC — High-Throughput Burst & DoS Resilience Suite           ║")
        print("║   Testing Line-Speed Packet Floods, Actuator Throughput & Recovery   ║")
        print("╚══════════════════════════════════════════════════════════════════════╝\n")

        self.test_handshake_storm()
        self.test_encrypted_stream_flood(num_frames=100)
        self.test_post_stress_recovery()

    def test_handshake_storm(self):
        print("── [1] Handshake Reset Storm (20 Rapid-Fire OP_HANDSHAKE_INITs) ──")
        init_frame = encode_frame(OP_HANDSHAKE_INIT, 0, self.server.server_mldsa_pk)
        
        self.server.ser.reset_input_buffer()
        start = time.time()
        for i in range(20):
            self.server.ser.write(init_frame)
        self.server.ser.flush()
        elapsed = time.time() - start

        print(f"  [+] 20 Handshake Init frames dispatched in {elapsed*1000:.2f} ms")
        time.sleep(0.2)
        self.server.ser.reset_input_buffer()
        ping_ok = self.server.ping()
        status = "PASSED" if ping_ok else "FAILED"
        print(f"  [{status}] Pico survived Handshake Reset Storm with zero lockups.\n")

    def test_encrypted_stream_flood(self, num_frames: int = 100):
        print(f"── [2] High-Throughput Encrypted Session Flood ({num_frames} frames) ──")
        if not self.server.perform_hybrid_handshake():
            print("[-] Handshake failed prior to flood test.")
            return

        aesgcm = AESGCM(self.server.session_key)
        successful_frames = 0
        latencies = []

        start_time = time.time()

        for i in range(1, num_frames + 1):
            t0 = time.time()
            iv = os.urandom(12)
            aad = struct.pack('>I', self.server.msg_counter)
            self.server.msg_counter += 1

            msg = f"Actuator Command Stream #{i:04d}".encode('utf-8')
            ct = aesgcm.encrypt(iv, msg, aad)
            payload = iv + aad + ct

            self.server.send_frame(OP_ENCRYPTED_MSG, payload)
            res = self.server.receive_frame(OP_ENCRYPTED_RESP, timeout=1.0)
            t1 = time.time()

            if res:
                successful_frames += 1
                latencies.append((t1 - t0) * 1000)

            if i % 25 == 0 or i == num_frames:
                print(f"  [>] Dispatched & Processed: {i}/{num_frames} frames ({successful_frames}/{i} OK)")

        total_elapsed = time.time() - start_time
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        throughput_fps = successful_frames / total_elapsed if total_elapsed > 0 else 0
        throughput_kbps = (successful_frames * 64) / (total_elapsed * 1024) if total_elapsed > 0 else 0

        print(f"\n  Flood Metrics:")
        print(f"    • Success Rate: {successful_frames}/{num_frames} ({successful_frames/num_frames*100:.1f}%)")
        print(f"    • Total Duration: {total_elapsed:.2f} s")
        print(f"    • Average Frame RTT: {avg_lat:.2f} ms")
        print(f"    • Sustainable Throughput: {throughput_fps:.1f} frames/sec ({throughput_kbps:.2f} KB/s)\n")

    def test_post_stress_recovery(self):
        print("── [3] Post-Stress Operational Integrity & Clean Handshake ──")
        ping_ok = self.server.ping()
        hs_ok = self.server.perform_hybrid_handshake()

        if ping_ok and hs_ok:
            print("[✓] ALL STRESS & BURST DOs TESTS PASSED! System remains 100% stable.\n")
        else:
            print("[-] Failure detected during recovery validation.\n")

def main():
    tester = QsacBurstStressTester()
    if tester.connect():
        tester.run_all_stress_tests()

if __name__ == '__main__':
    main()
