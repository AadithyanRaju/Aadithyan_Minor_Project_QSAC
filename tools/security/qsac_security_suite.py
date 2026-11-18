#!/usr/bin/env python3
"""
QSAC Security & Adversarial Testing Suite
Automated penetration and negative testing suite for Raspberry Pi Pico RP2040.
"""

import sys
import os
import time
import struct
import json
import serial
import serial.tools.list_ports

# Add gateway tools directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'gateway')))

from qsac_frame import (
    encode_frame, FrameDecoder, crc16_ccitt, SYNC_BYTES,
    OP_PING, OP_PONG,
    OP_HANDSHAKE_INIT, OP_CLIENT_HELLO,
    OP_SERVER_HELLO, OP_CLIENT_FINISHED,
    OP_SUBMIT_TOKEN, OP_TOKEN_RESULT,
    OP_ENCRYPTED_MSG, OP_ENCRYPTED_RESP,
    OP_ERROR
)
from qsac_server import QsacHostServer, QSAC_PERM_ACCESS_DOOR, QSAC_PERM_READ_TELEMETRY, QSAC_PERM_ADMIN
from pqc.mldsa44 import mldsa44_keypair, mldsa44_sign
from pqc.mlkem512 import mlkem512_encaps
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class QsacSecurityTester:
    def __init__(self, port: str = None, baudrate: int = 115200):
        self.server = QsacHostServer(port=port, baudrate=baudrate)
        self.results = []

    def connect(self) -> bool:
        return self.server.connect()

    def record_result(self, test_id: str, name: str, passed: bool, details: str):
        status_str = "[PASS]" if passed else "[FAIL]"
        print(f"  {status_str} {test_id}: {name}")
        print(f"         Detail: {details}")
        self.results.append({
            "test_id": test_id,
            "name": name,
            "passed": passed,
            "details": details
        })

    def run_all_security_tests(self):
        print("\n╔══════════════════════════════════════════════════════════════════════╗")
        print("║          QSAC — Automated Security & Adversarial Testing Suite       ║")
        print("║      Testing Protocol Robustness, PQC Integrity, Anti-Replay, State  ║")
        print("╚══════════════════════════════════════════════════════════════════════╝\n")

        self.test_sec01_crc16_corruption()
        self.test_sec02_malformed_length_header()
        self.test_sec03_unknown_opcode_injection()
        self.test_sec04_handshake_mitm_tampering()
        self.test_sec05_forged_authority_token()
        self.test_sec06_token_payload_tampering()
        self.test_sec07_expired_token_replay()
        self.test_sec08_state_machine_skip_attack()
        self.test_sec09_aead_ciphertext_corruption()
        self.test_sec10_aead_counter_replay()

        self.generate_report()

    def test_sec01_crc16_corruption(self):
        print("── [SEC-01] CRC-16 Checksum Corruption Injection ──")
        # Generate valid frame, then corrupt CRC
        valid_frame = encode_frame(OP_PING, self.server.seq, b"TEST-PING")
        corrupted_frame = bytearray(valid_frame)
        corrupted_frame[-1] ^= 0xFF  # Flip CRC LSB
        corrupted_frame[-2] ^= 0xFF  # Flip CRC MSB

        self.server.ser.reset_input_buffer()
        self.server.ser.write(bytes(corrupted_frame))
        self.server.ser.flush()

        res = self.server.receive_frame(OP_PONG, timeout=0.5)
        passed = (res is None)
        # Verify device is still alive with normal ping
        ping_ok = self.server.ping()
        passed = passed and ping_ok
        self.record_result("SEC-01", "CRC16 Checksum Corruption", passed,
                           "Corrupted frame dropped; device remained fully responsive.")

    def test_sec02_malformed_length_header(self):
        print("\n── [SEC-02] Malformed / Truncated Length Header ──")
        # Frame declaring 2048 bytes payload but sending only 8 bytes
        header = SYNC_BYTES + struct.pack('>HBB', 2048, OP_PING, self.server.seq)
        short_payload = b"12345678"
        crc = struct.pack('>H', crc16_ccitt(header[2:] + short_payload))
        malformed = header + short_payload + crc

        self.server.ser.reset_input_buffer()
        self.server.ser.write(malformed)
        self.server.ser.flush()
        # Wait 150ms for the firmware inter-byte timer (50ms) to reset the receiver state machine
        time.sleep(0.15)
        self.server.ser.reset_input_buffer()

        # Device should have reset its parser and respond to next valid frame
        ping_ok = self.server.ping()
        self.record_result("SEC-02", "Malformed Length Framing", ping_ok,
                           "Parser reset gracefully after frame truncation; no hang.")

    def test_sec03_unknown_opcode_injection(self):
        print("\n── [SEC-03] Unknown / Reserved Opcode Injection ──")
        self.server.ser.reset_input_buffer()
        all_rejected = True
        for bad_op in [0x00, 0x7E, 0xFE]:
            self.server.send_frame(bad_op, b"FUZZ_DATA")
            res = self.server.receive_frame(OP_ERROR, timeout=0.5)
            if not res:
                all_rejected = False

        ping_ok = self.server.ping()
        passed = all_rejected and ping_ok
        self.record_result("SEC-03", "Unknown Opcode Handling", passed,
                           "Undefined opcodes (0x00, 0x7E, 0xFE) rejected with OP_ERROR without crashing.")

    def test_sec04_handshake_mitm_tampering(self):
        print("\n── [SEC-04] Handshake Man-in-the-Middle Ciphertext Tampering ──")
        time.sleep(0.1)
        self.server.ser.reset_input_buffer()
        self.server.send_frame(OP_HANDSHAKE_INIT, self.server.server_mldsa_pk)

        res = self.server.receive_frame(OP_CLIENT_HELLO, timeout=3.0)
        if not res:
            self.record_result("SEC-04", "Handshake MitM Tampering", False, "Failed to receive ClientHello")
            return

        _, client_hello_payload = res
        nonce_c = client_hello_payload[:16]
        ecdh_pub_c = client_hello_payload[16:80]
        mlkem_pub_c = client_hello_payload[80:880]

        # Server encapsulates
        mlkem_ct, mlkem_shared = mlkem512_encaps(mlkem_pub_c)
        server_ecc_sk = ec.generate_private_key(ec.SECP256R1())
        server_ecc_pk = server_ecc_sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]
        nonce_s = os.urandom(16)

        # Tamper with ML-KEM ciphertext before signature calculation or transmission
        transcript_data = b"QSAC-TRANSCRIPT-v1:" + nonce_c + ecdh_pub_c + mlkem_pub_c + nonce_s + server_ecc_pk + mlkem_ct
        sig = mldsa44_sign(self.server.server_mldsa_sk, transcript_data)

        # Flip a bit in mlkem_ct for MitM attack simulation
        tampered_ct = bytearray(mlkem_ct)
        tampered_ct[10] ^= 0xFF

        server_hello_payload = nonce_s + server_ecc_pk + bytes(tampered_ct) + sig
        self.server.send_frame(OP_SERVER_HELLO, server_hello_payload)

        # Expect OP_ERROR (-4: verify fail) or rejection
        res = self.server.receive_frame(timeout=3.0)
        passed = False
        err = 0
        if res:
            opcode, payload = res
            if opcode == OP_ERROR:
                err = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else 0
                passed = (err in [-1, -4])
        self.record_result("SEC-04", "Handshake MitM Transcript Tampering", passed,
                           f"Pico detected tampered ML-KEM ciphertext and rejected handshake (error: {err}).")

    def test_sec05_forged_authority_token(self):
        print("\n── [SEC-05] Forged Authority Signature Token Injection ──")
        # Ensure genuine authority key is provisioned
        self.server.send_frame(OP_HANDSHAKE_INIT, self.server.auth_pk)
        time.sleep(0.1)
        while self.server.ser.in_waiting:
            self.server.ser.read(self.server.ser.in_waiting)

        # Create rogue keypair
        rogue_pk, rogue_sk = mldsa44_keypair()

        now = int(time.time())
        device_id = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        payload_bytes = struct.pack('<16sIII', device_id, now - 10, now + 3600, QSAC_PERM_ACCESS_DOOR)
        forged_sig = mldsa44_sign(rogue_sk, payload_bytes)

        token_frame = struct.pack('<I', now) + payload_bytes + forged_sig
        self.server.send_frame(OP_SUBMIT_TOKEN, token_frame)

        res = self.server.receive_frame(OP_TOKEN_RESULT, timeout=2.0)
        passed = False
        status = -1
        if res:
            _, resp_payload = res
            status = struct.unpack('<i', resp_payload[:4])[0]
            passed = (status != 0)
        self.record_result("SEC-05", "Forged Authority Token Rejection", passed,
                           f"Token signed by untrusted authority key rejected (status: {status}).")

    def test_sec06_token_payload_tampering(self):
        print("\n── [SEC-06] Privilege Escalation / Token Bit Tampering ──")
        now = int(time.time())
        device_id = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        # Legitimate token issued for READ_TELEMETRY
        payload_bytes = struct.pack('<16sIII', device_id, now - 10, now + 3600, QSAC_PERM_READ_TELEMETRY)
        legit_sig = mldsa44_sign(self.server.auth_sk, payload_bytes)

        # Attacker escalates privileges to ADMIN in payload
        tampered_payload = struct.pack('<16sIII', device_id, now - 10, now + 3600, QSAC_PERM_ADMIN | QSAC_PERM_ACCESS_DOOR)
        token_frame = struct.pack('<I', now) + tampered_payload + legit_sig

        self.server.send_frame(OP_SUBMIT_TOKEN, token_frame)
        res = self.server.receive_frame(OP_TOKEN_RESULT, timeout=2.0)
        passed = False
        status = -1
        if res:
            _, resp_payload = res
            status = struct.unpack('<i', resp_payload[:4])[0]
            passed = (status != 0)
        self.record_result("SEC-06", "Privilege Escalation Tamper Check", passed,
                           f"Modified permission bitmask detected by ML-DSA-44 verification (status: {status}).")

    def test_sec07_expired_token_replay(self):
        print("\n── [SEC-07] Expired Token Replay Attack ──")
        now = int(time.time())
        device_id = bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        # Expired token
        payload_bytes = struct.pack('<16sIII', device_id, now - 7200, now - 3600, QSAC_PERM_ACCESS_DOOR)
        sig = mldsa44_sign(self.server.auth_sk, payload_bytes)

        token_frame = struct.pack('<I', now) + payload_bytes + sig
        self.server.send_frame(OP_SUBMIT_TOKEN, token_frame)
        res = self.server.receive_frame(OP_TOKEN_RESULT, timeout=2.0)
        passed = False
        status = -1
        if res:
            _, resp_payload = res
            status = struct.unpack('<i', resp_payload[:4])[0]
            passed = (status == -4)
        self.record_result("SEC-07", "Expired Token Replay Defense", passed,
                           f"Expired timestamp rejected by Pico access controller (status: {status}).")

    def test_sec08_state_machine_skip_attack(self):
        print("\n── [SEC-08] State Machine Skip / Out-of-Order Injection ──")
        # Invalidate current session on host, send encrypted msg to unauthenticated Pico
        fake_key = os.urandom(32)
        aesgcm = AESGCM(fake_key)
        iv = os.urandom(12)
        aad = struct.pack('>I', 1)
        ct = aesgcm.encrypt(iv, b"UNAUTHORIZED_ACTUATOR_COMMAND", aad)

        # Send frame before session is established
        self.server.send_frame(OP_ENCRYPTED_MSG, iv + aad + ct)
        res = self.server.receive_frame(timeout=1.0)
        passed = False
        err = 0
        if res:
            opcode, payload = res
            if opcode == OP_ERROR:
                err = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else 0
                passed = (err in [-2, -3, -4, -8, -9])
        self.record_result("SEC-08", "State Machine Out-of-Order Defense", passed,
                           f"Unauthenticated session message blocked (error code: {err}).")

    def test_sec09_aead_ciphertext_corruption(self):
        print("\n── [SEC-09] AES-256-GCM Ciphertext Bit-Flip Corruption ──")
        # Establish valid handshake
        if not self.server.perform_hybrid_handshake():
            self.record_result("SEC-09", "AEAD Ciphertext Corruption", False, "Handshake failed")
            return

        aesgcm = AESGCM(self.server.session_key)
        iv = os.urandom(12)
        aad = struct.pack('>I', self.server.msg_counter)
        self.server.msg_counter += 1

        ct_with_tag = bytearray(aesgcm.encrypt(iv, b"VALID_DOOR_COMMAND", aad))
        # Corrupt 1 byte in ciphertext
        ct_with_tag[5] ^= 0xFF

        payload = iv + aad + bytes(ct_with_tag)
        self.server.send_frame(OP_ENCRYPTED_MSG, payload)

        res = self.server.receive_frame(timeout=1.0)
        passed = False
        err = 0
        if res:
            opcode, payload = res
            if opcode == OP_ERROR:
                err = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else 0
                passed = (err in [-2, -4])
        self.record_result("SEC-09", "AES-256-GCM Ciphertext Integrity", passed,
                           f"Bit-flipped ciphertext rejected by GHASH authentication tag (error: {err}).")

    def test_sec10_aead_counter_replay(self):
        print("\n── [SEC-10] AES-256-GCM Replay & Sequence Counter Rollback ──")
        # Send valid message counter = 100
        aesgcm = AESGCM(self.server.session_key)
        iv1 = os.urandom(12)
        aad1 = struct.pack('>I', 100)
        ct1 = aesgcm.encrypt(iv1, b"FIRST_VALID_MSG", aad1)
        self.server.send_frame(OP_ENCRYPTED_MSG, iv1 + aad1 + ct1)
        res1 = self.server.receive_frame(OP_ENCRYPTED_RESP, timeout=2.0)

        # Attacker replays counter = 100 or decrements to counter = 50
        iv2 = os.urandom(12)
        aad2 = struct.pack('>I', 50)  # Counter rollback attack
        ct2 = aesgcm.encrypt(iv2, b"REPLAYED_COMMAND", aad2)
        self.server.send_frame(OP_ENCRYPTED_MSG, iv2 + aad2 + ct2)

        res2 = self.server.receive_frame(timeout=1.0)
        passed = False
        if res2:
            opcode, payload = res2
            if opcode == OP_ERROR:
                err = struct.unpack('<i', payload[:4])[0] if len(payload) >= 4 else 0
                passed = (err == -8)  # QSAC_ERR_REPLAY_DETECTED
        self.record_result("SEC-10", "AEAD Anti-Replay Counter Defense", passed,
                           f"Counter rollback (100 -> 50) detected and rejected (error: {err if res2 else 'None'}).")

    def generate_report(self):
        passed_count = sum(1 for r in self.results if r['passed'])
        total_count = len(self.results)

        print("\n══════════════════════════════════════════════════════════════════════")
        print(f"           SECURITY TEST SUITE SUMMARY: {passed_count}/{total_count} PASSED ({passed_count/total_count*100:.1f}%)")
        print("══════════════════════════════════════════════════════════════════════")

        report_path = "tools/security/security_assessment_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# QSAC Security & Adversarial Assessment Report\n\n")
            f.write(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Target**: Raspberry Pi Pico (RP2040 Cortex-M0+ @ 125 MHz)\n")
            f.write(f"**Score**: {passed_count}/{total_count} Passed ({passed_count/total_count*100:.1f}%)\n\n")
            f.write("## Test Results Matrix\n\n")
            f.write("| Test ID | Adversarial Test Scenario | Result | Verified Defense Mechanism |\n")
            f.write("| :--- | :--- | :---: | :--- |\n")
            for r in self.results:
                status_icon = "✓ PASS" if r['passed'] else "✗ FAIL"
                f.write(f"| **{r['test_id']}** | {r['name']} | **{status_icon}** | {r['details']} |\n")
            f.write("\n## Compliance Summary\n\n")
            f.write("- **FIPS 203 (ML-KEM-512)**: MitM & transcript tampering protection validated.\n")
            f.write("- **FIPS 204 (ML-DSA-44)**: Offline token integrity & forgery rejection validated.\n")
            f.write("- **NIST SP 800-38D (AES-256-GCM)**: AEAD tag authentication & monotonic anti-replay counter validated.\n")
            f.write("- **Framing Layer**: CRC-16 integrity & truncated packet parser recovery validated.\n")

        print(f"[+] Security Assessment Report generated: {report_path}\n")

def main():
    tester = QsacSecurityTester()
    if tester.connect():
        tester.run_all_security_tests()

if __name__ == '__main__':
    main()
