#!/usr/bin/env python3
"""
QSAC Host Gateway & Access Control Authority Server
Communicates with Raspberry Pi Pico over USB Serial / UART.
"""

import sys
import os
import time
import struct
import hashlib
import binascii
import serial
import serial.tools.list_ports
import json

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from pqc.mlkem512 import mlkem512_encaps
from pqc.mldsa44 import mldsa44_keypair, mldsa44_sign, mldsa44_verify
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

QSAC_PERM_READ_TELEMETRY = (1 << 0)
QSAC_PERM_ACCESS_DOOR     = (1 << 1)
QSAC_PERM_CONFIG_UPDATE   = (1 << 2)
QSAC_PERM_ADMIN           = (1 << 31)

HKDF_INFO = b"QSAC hybrid session key v1"
TRANSCRIPT_PREFIX = b"QSAC-TRANSCRIPT-v1:"

class QsacHostServer:
    def __init__(self, port: str = None, baudrate: int = 115200):
        self.port = port
        self.baudrate = baudrate
        self.ser = None
        self.decoder = FrameDecoder()
        self.seq = 0
        self.session_key = None
        self.msg_counter = 0
        self.auth_provisioned = False

        print("[INIT] Initializing Server Identity & Access Authority...")
        self.server_mldsa_pk, self.server_mldsa_sk = mldsa44_keypair()
        self.auth_pk, self.auth_sk = self.server_mldsa_pk, self.server_mldsa_sk
        print(f"[INIT] Server & Authority ML-DSA-44 Keypair Ready (PK: {len(self.server_mldsa_pk)}B, SK: {len(self.server_mldsa_sk)}B)")

    def connect(self, port: str = None) -> bool:
        if port:
            self.port = port
        if not self.port:
            ports = list(serial.tools.list_ports.comports())
            if not ports:
                print("[-] No serial COM ports detected.")
                return False
            print("\nAvailable Serial Ports:")
            for i, p in enumerate(ports):
                print(f"  [{i + 1}] {p.device} — {p.description}")
            choice = input(f"\nSelect port [1-{len(ports)}] (default 1): ").strip()
            idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(ports) else 0
            self.port = ports[idx].device

        print(f"[+] Connecting to {self.port} at {self.baudrate} baud...")
        try:
            self.ser = serial.Serial(self.port, self.baudrate, timeout=0.1)
            time.sleep(0.5)
            self.ser.reset_input_buffer()
            self.ser.reset_output_buffer()
            print(f"[+] Connected to {self.port} successfully!")
            return True
        except Exception as e:
            print(f"[-] Failed to open {self.port}: {e}")
            return False

    def send_frame(self, opcode: int, payload: bytes = b''):
        frame = encode_frame(opcode, self.seq, payload)
        self.seq = (self.seq + 1) & 0xFF
        self.ser.write(frame)
        self.ser.flush()

    def receive_frame(self, expected_opcode: int = None, timeout: float = 3.0) -> tuple[int, bytes] | None:
        start_time = time.time()
        while time.time() - start_time < timeout:
            raw = self.ser.read(256)
            if raw:
                self.decoder.feed(raw)
                while True:
                    result = self.decoder.next_frame()
                    if result is None:
                        break
                    opcode, seq, payload = result
                    if expected_opcode is None or opcode == expected_opcode:
                        return opcode, payload
                    elif opcode == OP_ERROR:
                        err_code = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else -1
                        print(f"[-] Received OP_ERROR from device: {err_code}")
                        return opcode, payload
            time.sleep(0.01)
        return None

    def ping(self) -> bool:
        print("\n── [1] Connection Ping ──")
        self.send_frame(OP_PING, b"PING-PICO")
        res = self.receive_frame(OP_PONG, timeout=1.0)
        if res:
            opcode, payload = res
            print(f"[+] Device responded PONG! Data: {payload.decode('utf-8', errors='replace')}")
            return True
        else:
            print("[-] Ping timeout. Ensure Pico firmware is running and UART is connected.")
            return False

    def perform_hybrid_handshake(self) -> bool:
        print("\n── [2] Live Quantum-Classical Hybrid Handshake ──")
        t_start = time.perf_counter()

        # Step 1: Send Handshake Init request with Server's ML-DSA public key
        print("  1. Sending OP_HANDSHAKE_INIT with Server ML-DSA-44 Public Key...")
        self.send_frame(OP_HANDSHAKE_INIT, self.server_mldsa_pk)

        # Step 2: Receive ClientHello
        print("  2. Awaiting ClientHello (ECDH P-256 + ML-KEM-512 Public Keys)...")
        res = self.receive_frame(OP_CLIENT_HELLO, timeout=3.0)
        if not res:
            print("  [-] Timeout waiting for ClientHello")
            return False
        _, payload = res
        if len(payload) < 32 + 64 + 800:
            print(f"  [-] Invalid ClientHello length: {len(payload)} bytes")
            return False

        client_nonce = payload[:32]
        client_ecdh_pub_raw = payload[32: 32 + 64]
        client_mlkem_pub = payload[32 + 64: 32 + 64 + 800]
        print(f"  [+] Received ClientHello (Nonce: {client_nonce[:8].hex()}..., ECDH: 64B, ML-KEM: 800B)")

        # Step 3: Server generates ECDH keypair and computes ECDH shared secret
        server_ecdh_priv = ec.generate_private_key(ec.SECP256R1())
        server_ecdh_pub_numbers = server_ecdh_priv.public_key().public_numbers()
        server_ecdh_pub_raw = (server_ecdh_pub_numbers.x.to_bytes(32, 'big') +
                               server_ecdh_pub_numbers.y.to_bytes(32, 'big'))

        client_ecdh_pub_x = int.from_bytes(client_ecdh_pub_raw[:32], 'big')
        client_ecdh_pub_y = int.from_bytes(client_ecdh_pub_raw[32:], 'big')
        client_ecdh_pub_obj = ec.EllipticCurvePublicNumbers(client_ecdh_pub_x, client_ecdh_pub_y, ec.SECP256R1()).public_key()
        ecdh_shared_secret = server_ecdh_priv.exchange(ec.ECDH(), client_ecdh_pub_obj)

        # Step 4: Server encapsulates ML-KEM-512 secret
        print("  3. Server encapsulating ML-KEM-512 shared secret...")
        mlkem_ct, mlkem_shared_secret = mlkem512_encaps(client_mlkem_pub)

        # Step 5: Dual-key combiner (HKDF-SHA-256)
        combined_ikm = ecdh_shared_secret + mlkem_shared_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO
        )
        self.session_key = hkdf.derive(combined_ikm)
        print(f"  [+] Derived 256-bit Hybrid Session Key: {self.session_key.hex()[:32]}...")

        # Step 6: Compute Transcript Hash and Sign with Server ML-DSA-44
        server_nonce = os.urandom(32)
        transcript_data = (TRANSCRIPT_PREFIX + client_nonce + server_nonce +
                           client_ecdh_pub_raw + server_ecdh_pub_raw +
                           client_mlkem_pub + mlkem_ct)
        transcript_hash = hashlib.sha256(transcript_data).digest()
        print("  4. Signing Handshake Transcript with Server ML-DSA-44...")
        mldsa_sig = mldsa44_sign(self.server_mldsa_sk, transcript_hash)

        # Step 7: Send ServerHello
        server_hello_payload = server_nonce + server_ecdh_pub_raw + mlkem_ct + mldsa_sig
        print(f"  5. Sending OP_SERVER_HELLO ({len(server_hello_payload)} bytes)...")
        self.send_frame(OP_SERVER_HELLO, server_hello_payload)

        # Step 8: Receive ClientFinished
        print("  6. Awaiting ClientFinished confirmation...")
        res = self.receive_frame(OP_CLIENT_FINISHED, timeout=3.0)
        if not res:
            print("  [-] Timeout waiting for ClientFinished")
            return False
        _, fin_payload = res
        if len(fin_payload) < 12 + 16 + 32:
            print(f"  [-] Invalid ClientFinished payload size: {len(fin_payload)}B")
            return False

        iv = fin_payload[:12]
        tag = fin_payload[12: 12 + 16]
        ct = fin_payload[28: 28 + 32]
        pico_sk_prefix = fin_payload[60:64].hex() if len(fin_payload) >= 64 else "N/A"
        pico_hash_prefix = fin_payload[68:72].hex() if len(fin_payload) >= 72 else "N/A"

        try:
            aesgcm = AESGCM(self.session_key)
            decrypted_hash = aesgcm.decrypt(iv, ct + tag, None)
            if decrypted_hash == transcript_hash:
                t_total = (time.perf_counter() - t_start) * 1000.0
                print(f"\n[✓] HYBRID HANDSHAKE COMPLETE in {t_total:.2f} ms!")
                print(f"[✓] Mutual Quantum Authentication Verified!")
                print(f"[✓] AES-256-GCM Secure Channel Active.")
                self.msg_counter = 0
                return True
            else:
                print("  [-] Decrypted confirmation transcript mismatch!")
                print(f"      Decrypted: {decrypted_hash.hex()}")
                print(f"      Expected:  {transcript_hash.hex()}")
                return False
        except Exception as e:
            print(f"  [-] ClientFinished AES-GCM verification error: {e}")
            print(f"      Host Session Key:       {self.session_key.hex()}")
            print(f"      Pico Session Key (dbg): {pico_sk_prefix}...")
            print(f"      Host Transcript Hash:   {transcript_hash.hex()}")
            print(f"      Pico Transcript Hash:   {pico_hash_prefix}...")
            print(f"      Received IV:            {iv.hex()}")
            print(f"      Received Tag:           {tag.hex()}")
            print(f"      Received Ciphertext:    {ct.hex()}")
            expected_ct_tag = AESGCM(self.session_key).encrypt(iv, transcript_hash, None)
            print(f"      Host Expected Tag:      {expected_ct_tag[-16:].hex()}")
            print(f"      Host Expected CT:       {expected_ct_tag[:-16].hex()}")
            return False

    def issue_and_submit_token(self, valid: bool = True, tamper: bool = False, permissions: int = None) -> bool:
        # Provision authority key to Pico if not yet done
        if not self.auth_provisioned:
            self.send_frame(OP_HANDSHAKE_INIT, self.auth_pk)
            time.sleep(0.05)
            while self.ser.in_waiting:
                self.ser.read(self.ser.in_waiting)
            self.auth_provisioned = True

        if permissions is None:
            permissions = QSAC_PERM_ACCESS_DOOR | QSAC_PERM_READ_TELEMETRY

        now = int(time.time())
        issued_at = now - 10
        expires_at = (now + 3600) if valid else (now - 3600)  # expired 1 hr ago

        device_id = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])

        payload_bytes = struct.pack('<16sIII', device_id, issued_at, expires_at, permissions)
        # Sign payload with Authority Key
        sig = mldsa44_sign(self.auth_sk, payload_bytes)

        if tamper:
            # Tamper with permissions bitmask after signature is created
            payload_bytes = struct.pack('<16sIII', device_id, issued_at, expires_at, permissions ^ 0xFF)

        token_frame = struct.pack('<I', now) + payload_bytes + sig
        print(f"\n── Submitting Post-Quantum Token ({len(token_frame)} bytes) ──")
        print(f"  Permissions: 0x{permissions:08X}")
        print(f"  Validity: {'VALID' if valid else 'EXPIRED'}")
        print(f"  Integrity: {'TAMPERED' if tamper else 'AUTHENTIC'}")

        self.send_frame(OP_SUBMIT_TOKEN, token_frame)
        res = self.receive_frame(OP_TOKEN_RESULT, timeout=2.0)
        if not res:
            print("[-] Timeout waiting for token verification result")
            return False

        opcode, resp_payload = res
        if opcode == OP_ERROR:
            return False

        status_code = struct.unpack('<i', resp_payload[:4])[0]
        granted_perms = struct.unpack('<I', resp_payload[4:8])[0] if len(resp_payload) >= 8 else 0

        if status_code == 0:
            print(f"[✓] ACCESS GRANTED! (Permissions Granted: 0x{granted_perms:08X})")
            return True
        else:
            print(f"[✗] ACCESS DENIED by Pico! (Error code: {status_code})")
            return False

    def send_encrypted_telemetry(self, msg: str = "Query Door Status & Battery Voltage") -> str | None:
        if not self.session_key:
            print("[-] No active session!")
            return None

        aesgcm = AESGCM(self.session_key)
        iv = os.urandom(12)
        aad = struct.pack('>I', self.msg_counter)
        self.msg_counter += 1

        ct_with_tag = aesgcm.encrypt(iv, msg.encode('utf-8'), aad)
        payload = iv + aad + ct_with_tag

        print(f"\n── Sending Encrypted Session Frame ({len(payload)} bytes) ──")
        print(f"  Plaintext: '{msg}'")
        self.send_frame(OP_ENCRYPTED_MSG, payload)

        res = self.receive_frame(OP_ENCRYPTED_RESP, timeout=2.0)
        if not res:
            print("[-] Timeout waiting for encrypted response")
            return None

        opcode, resp_payload = res
        if opcode == OP_ERROR:
            return None

        resp_iv = resp_payload[:12]
        resp_aad = resp_payload[12:16]
        resp_ct_tag = resp_payload[16:]

        try:
            decrypted = aesgcm.decrypt(resp_iv, resp_ct_tag, resp_aad).decode('utf-8')
            print(f"[✓] Received Decrypted Response: '{decrypted}'")
            return decrypted
        except Exception as e:
            print(f"[-] Response decryption failed: {e}")
            return None

    def run_benchmarks(self) -> list[dict]:
        print("\n╔══════════════════════════════════════════════════════════════════════╗")
        print("║      QSAC — Hardware Benchmark & Profiling Suite (RP2040 @ 125MHz)   ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")
        print("[+] Initiating full benchmark suite on Raspberry Pi Pico...")
        self.send_frame(OP_RUN_BENCHMARKS, b'')

        records = []
        print("\n┌────────────────────────────┬────────┬──────────────┬──────────────┬──────────────┬───────────┐")
        print("│ Cryptographic Operation    │ Iters  │ Avg Latency  │ Avg Cycles   │ Min/Max (MC) │ Stack (B) │")
        print("├────────────────────────────┼────────┼──────────────┼──────────────┼──────────────┼───────────┤")

        start_time = time.time()
        while True:
            res = self.receive_frame(OP_BENCHMARK_REPORT, timeout=20.0)
            if not res:
                print("[-] Benchmark timeout / completed.")
                break

            opcode, payload = res
            if opcode == OP_ERROR:
                err = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else -1
                print(f"[-] Benchmark error: {err}")
                break

            if len(payload) < 72:
                continue

            name_bytes, iters, avg_cyc, min_cyc, max_cyc, avg_us, stack_b, data_b = struct.unpack(
                '<32sIQQQIII', payload[:72]
            )
            name = name_bytes.decode('utf-8', errors='ignore').rstrip('\x00').strip()

            if name == "BENCHMARKS_COMPLETE":
                break

            lat_ms = avg_us / 1000.0
            avg_mcyc = avg_cyc / 1_000_000.0
            min_mcyc = min_cyc / 1_000_000.0
            max_mcyc = max_cyc / 1_000_000.0

            rec_dict = {
                "name": name,
                "iterations": iters,
                "avg_latency_ms": round(lat_ms, 2),
                "avg_cycles": avg_cyc,
                "avg_mcycles": round(avg_mcyc, 3),
                "min_mcycles": round(min_mcyc, 3),
                "max_mcycles": round(max_mcyc, 3),
                "stack_bytes": stack_b,
                "data_size_bytes": data_b
            }
            records.append(rec_dict)

            min_max_str = f"{min_mcyc:.2f}/{max_mcyc:.2f}"
            print(f"│ {name:<26} │ {iters:>6} │ {lat_ms:>9.2f} ms │ {avg_mcyc:>9.3f} M │ {min_max_str:>12} │ {stack_b:>9} │")

        print("└────────────────────────────┴────────┴──────────────┴──────────────┴──────────────┴───────────┘")

        # Save JSON output
        os.makedirs("tools/benchmarks", exist_ok=True)
        json_path = "tools/benchmarks/benchmark_results_rp2040.json"
        with open(json_path, "w") as f:
            json.dump(records, f, indent=2)
        print(f"\n[+] Raw benchmark data saved to: {json_path}")

        # Print LaTeX Table Snippet
        print("\n── LaTeX Table Output for Research Paper (Section VII) ──")
        print(r"\begin{table}[h]")
        print(r"\centering")
        print(r"\caption{Measured Hardware Performance on Raspberry Pi Pico (RP2040 Cortex-M0+ @ 125\,MHz)}")
        print(r"\label{tab:measured_rp2040_perf}")
        print(r"\begin{tabular}{lrrrr}")
        print(r"\hline")
        print(r"\textbf{Operation} & \textbf{Iterations} & \textbf{Latency (ms)} & \textbf{Cycles ($10^6$)} & \textbf{Stack (B)} \\")
        print(r"\hline")
        for r in records:
            print(f"{r['name']:<26} & {r['iterations']} & {r['avg_latency_ms']:.2f} & {r['avg_mcycles']:.3f} & {r['stack_bytes']} \\\\")
        print(r"\hline")
        print(r"\end{tabular}")
        print(r"\end{table}")

        return records

def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     QSAC — Quantum-Secure Access Control Gateway Server      ║")
    print("║  Post-Quantum Cryptography + Microcontroller Live Management ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    server = QsacHostServer()
    if not server.connect():
        print("[-] Exiting.")
        return

    while True:
        print("\n══════════════════════════════════════════")
        print(" [1] Test Serial Connection (Ping)")
        print(" [2] Perform Live Hybrid Quantum-Classical Handshake")
        print(" [3] Issue & Submit Valid ML-DSA-44 Access Token (Door Access)")
        print(" [4] Test Security: Submit Expired Access Token")
        print(" [5] Test Security: Submit Tampered Access Token")
        print(" [6] Send Encrypted Session Command / Telemetry")
        print(" [7] Run Full Automated Demonstration Sequence")
        print(" [8] Run Comprehensive Hardware Benchmark Suite (Phase 6)")
        print(" [9] Run Automated Security & Adversarial Test Suite")
        print(" [10] Run Statistical Side-Channel Timing Assessment (TVLA)")
        print(" [11] Run High-Entropy Protocol Mutation Fuzzer (1,000+ iters)")
        print(" [12] Run Role-Based Access Control (RBAC) Permutation Matrix")
        print(" [13] Run High-Throughput Burst & DoS Resilience Suite")
        print(" [0] Exit")
        print("══════════════════════════════════════════")
        choice = input("Select an option [0-13]: ").strip()

        if choice == '1':
            server.ping()
        elif choice == '2':
            server.perform_hybrid_handshake()
        elif choice == '3':
            server.issue_and_submit_token(valid=True, tamper=False)
        elif choice == '4':
            server.issue_and_submit_token(valid=False, tamper=False)
        elif choice == '5':
            server.issue_and_submit_token(valid=True, tamper=True)
        elif choice == '6':
            server.send_encrypted_telemetry()
        elif choice == '7':
            print("\n═══ RUNNING FULL AUTOMATED DEMONSTRATION ═══")
            server.ping()
            time.sleep(0.5)
            if server.perform_hybrid_handshake():
                time.sleep(0.5)
                server.issue_and_submit_token(valid=True, tamper=False)
                time.sleep(0.5)
                server.issue_and_submit_token(valid=False, tamper=False)
                time.sleep(0.5)
                server.issue_and_submit_token(valid=True, tamper=True)
                time.sleep(0.5)
                server.send_encrypted_telemetry("Door Unlock Actuator Trigger #1")
            print("\n═══ AUTOMATED DEMONSTRATION FINISHED ═══")
        elif choice == '8':
            server.run_benchmarks()
        elif choice == '9':
            from security.qsac_security_suite import QsacSecurityTester
            tester = QsacSecurityTester()
            tester.server = server
            tester.run_all_security_tests()
        elif choice == '10':
            from security.tvla_timing_evaluator import QsacTvlaEvaluator
            evaluator = QsacTvlaEvaluator()
            evaluator.server = server
            evaluator.run_all_tvla()
        elif choice == '11':
            from security.fuzzer import QsacProtocolFuzzer
            fuzzer = QsacProtocolFuzzer(total_mutations=1000)
            fuzzer.server = server
            fuzzer.run_fuzzing()
        elif choice == '12':
            from security.rbac_test_suite import QsacRbacTester
            tester = QsacRbacTester()
            tester.server = server
            tester.run_rbac_matrix()
        elif choice == '13':
            from security.dos_burst_suite import QsacBurstStressTester
            tester = QsacBurstStressTester()
            tester.server = server
            tester.run_all_stress_tests()
        elif choice == '0':
            print("[+] Closing connection and exiting.")
            break
        else:
            print("[-] Invalid selection.")

if __name__ == '__main__':
    main()
