"""
QSAC Binary Packet Framing & Serialization Layer
"""

import struct

SYNC_BYTES = bytes([0xAA, 0x55])

# Opcodes
OP_PING              = 0x01
OP_PONG              = 0x81
OP_HANDSHAKE_INIT    = 0x02
OP_CLIENT_HELLO      = 0x82
OP_SERVER_HELLO      = 0x03
OP_CLIENT_FINISHED   = 0x83
OP_SUBMIT_TOKEN      = 0x04
OP_TOKEN_RESULT      = 0x84
OP_ENCRYPTED_MSG     = 0x05
OP_ENCRYPTED_RESP    = 0x85
OP_RUN_BENCHMARKS    = 0x09
OP_BENCHMARK_REPORT  = 0x89
OP_TVLA_REQUEST      = 0x0B
OP_TVLA_SAMPLE       = 0x8B
OP_ERROR             = 0xFF

def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def encode_frame(opcode: int, seq: int, payload: bytes) -> bytes:
    """
    Frame structure:
    [SYNC: 2B] [PAYLOAD_LEN: 2B] [OPCODE: 1B] [SEQ: 1B] [PAYLOAD: NB] [CRC16: 2B]
    """
    length = len(payload)
    header = SYNC_BYTES + struct.pack('>HBB', length, opcode, seq)
    body = header[2:] + payload
    crc = crc16_ccitt(body)
    return header + payload + struct.pack('>H', crc)

class FrameDecoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes):
        self.buffer.extend(data)

    def next_frame(self) -> tuple[int, int, bytes] | None:
        while len(self.buffer) >= 6:
            # Look for SYNC bytes
            idx = self.buffer.find(SYNC_BYTES)
            if idx == -1:
                # No sync bytes found, keep last byte in case it's 0xAA
                if len(self.buffer) > 0 and self.buffer[-1] == 0xAA:
                    self.buffer = self.buffer[-1:]
                else:
                    self.buffer.clear()
                return None

            if idx > 0:
                self.buffer = self.buffer[idx:]

            if len(self.buffer) < 6:
                return None

            length, opcode, seq = struct.unpack('>HBB', self.buffer[2:6])
            total_frame_len = 6 + length + 2

            if len(self.buffer) < total_frame_len:
                return None  # Wait for more data

            payload = bytes(self.buffer[6: 6 + length])
            crc_received = struct.unpack('>H', self.buffer[6 + length: total_frame_len])[0]

            # Verify CRC
            crc_computed = crc16_ccitt(bytes(self.buffer[2: 6 + length]))
            if crc_computed != crc_received:
                # CRC failed, skip sync header and continue
                self.buffer = self.buffer[2:]
                continue

            # Frame valid
            self.buffer = self.buffer[total_frame_len:]
            return opcode, seq, payload

        return None
