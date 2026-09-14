import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_DIR = REPO_ROOT / "fpga" / "host"
sys.path.insert(0, str(HOST_DIR))

from demo_cli import (
    ProtocolError,
    build_request,
    parse_response,
    transact,
)


class FakeSerial:
    def __init__(self, response=b"", max_read_size=4):
        self.response = bytearray(response)
        self.max_read_size = max_read_size
        self.written = bytearray()
        self.flush_count = 0

    def write(self, data):
        self.written.extend(data)
        return len(data)

    def flush(self):
        self.flush_count += 1

    def read(self, size):
        if not self.response:
            return b""

        count = min(size, self.max_read_size, len(self.response))
        result = bytes(self.response[:count])
        del self.response[:count]
        return result


class DemoCliProtocolTest(unittest.TestCase):
    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    CIPHERTEXT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    @staticmethod
    def with_checksum(payload):
        checksum = 0

        for value in payload:
            checksum ^= value

        return bytes(payload) + bytes([checksum])

    def make_response(
        self,
        seq=0x42,
        flags=0x03,
        sec_status=0x00,
        raw_out=None,
        protected_out=None,
    ):
        if raw_out is None:
            raw_out = self.CIPHERTEXT

        if protected_out is None:
            protected_out = self.CIPHERTEXT

        payload = (
            bytes([0x5A, seq, flags, sec_status])
            + raw_out
            + protected_out
        )

        return self.with_checksum(payload)

    def test_build_request_is_exactly_36_bytes(self):
        frame = build_request(
            seq=0x42,
            key=self.KEY,
            plaintext=self.PLAINTEXT,
        )

        self.assertEqual(len(frame), 36)
        self.assertEqual(frame[0], 0xA5)
        self.assertEqual(frame[1], 0x01)
        self.assertEqual(frame[2], 0x42)
        self.assertEqual(frame[3:19], self.KEY)
        self.assertEqual(frame[19:35], self.PLAINTEXT)

        checksum = 0

        for value in frame[:-1]:
            checksum ^= value

        self.assertEqual(frame[-1], checksum)

    def test_build_request_rejects_invalid_width(self):
        with self.assertRaises(ValueError):
            build_request(
                seq=0x01,
                key=b"\x00" * 15,
                plaintext=self.PLAINTEXT,
            )

        with self.assertRaises(ValueError):
            build_request(
                seq=0x01,
                key=self.KEY,
                plaintext=b"\x00" * 17,
            )

    def test_parse_clean_response(self):
        response = parse_response(
            self.make_response(),
            expected_seq=0x42,
        )

        self.assertEqual(response.seq, 0x42)
        self.assertEqual(response.flags, 0x03)
        self.assertEqual(response.sec_status, 0x00)
        self.assertEqual(response.raw_out, self.CIPHERTEXT)
        self.assertEqual(response.protected_out, self.CIPHERTEXT)

        self.assertTrue(response.raw_valid)
        self.assertTrue(response.protected_valid)
        self.assertFalse(response.alarm)
        self.assertFalse(response.protected_blocked)
        self.assertFalse(response.frame_error)

    def test_parse_trigger_response(self):
        response = parse_response(
            self.make_response(
                flags=0x0D,
                sec_status=0x01,
                raw_out=self.KEY,
                protected_out=bytes(16),
            ),
            expected_seq=0x42,
        )

        self.assertTrue(response.raw_valid)
        self.assertFalse(response.protected_valid)
        self.assertTrue(response.alarm)
        self.assertTrue(response.protected_blocked)
        self.assertEqual(response.raw_out, self.KEY)
        self.assertEqual(response.protected_out, bytes(16))

    def test_parse_rejects_wrong_length(self):
        with self.assertRaises(ProtocolError):
            parse_response(bytes(36), expected_seq=0x42)

    def test_parse_rejects_wrong_preamble(self):
        frame = bytearray(self.make_response())
        frame[0] = 0x00

        with self.assertRaises(ProtocolError):
            parse_response(bytes(frame), expected_seq=0x42)

    def test_parse_rejects_wrong_checksum(self):
        frame = bytearray(self.make_response())
        frame[-1] ^= 0x01

        with self.assertRaises(ProtocolError):
            parse_response(bytes(frame), expected_seq=0x42)

    def test_transaction_handles_fragmented_serial_reads(self):
        expected_frame = self.make_response()
        serial_port = FakeSerial(
            response=expected_frame,
            max_read_size=3,
        )

        response = transact(
            serial_port=serial_port,
            seq=0x42,
            key=self.KEY,
            plaintext=self.PLAINTEXT,
        )

        self.assertEqual(
            bytes(serial_port.written),
            build_request(
                seq=0x42,
                key=self.KEY,
                plaintext=self.PLAINTEXT,
            ),
        )

        self.assertEqual(serial_port.flush_count, 1)
        self.assertEqual(response.raw_out, self.CIPHERTEXT)
        self.assertEqual(response.protected_out, self.CIPHERTEXT)

    def test_transaction_reports_serial_timeout(self):
        serial_port = FakeSerial(response=b"")

        with self.assertRaises(ProtocolError):
            transact(
                serial_port=serial_port,
                seq=0x42,
                key=self.KEY,
                plaintext=self.PLAINTEXT,
            )

    def test_parse_rejects_wrong_sequence(self):
        with self.assertRaises(ProtocolError):
            parse_response(
                self.make_response(seq=0x41),
                expected_seq=0x42,
            )
            
if __name__ == "__main__":
    unittest.main()

