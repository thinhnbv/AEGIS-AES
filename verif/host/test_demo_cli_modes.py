import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_DIR = REPO_ROOT / "fpga" / "host"
sys.path.insert(0, str(HOST_DIR))

from demo_cli import (
    DemoCheckError,
    DemoResponse,
    validate_clean_response,
    validate_trigger_response,
    validate_post_lockdown_response,
    validate_random_response,
)


class DemoCliModeTest(unittest.TestCase):
    KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    CIPHERTEXT = bytes.fromhex(
        "3925841d02dc09fbdc118597196a0b32"
    )

    def make_response(
        self,
        flags,
        sec_status,
        raw_out,
        protected_out,
    ):
        return DemoResponse(
            seq=0x42,
            flags=flags,
            sec_status=sec_status,
            raw_out=raw_out,
            protected_out=protected_out,
        )

    def test_clean_response_passes(self):
        response = self.make_response(
            flags=0x03,
            sec_status=0x00,
            raw_out=self.CIPHERTEXT,
            protected_out=self.CIPHERTEXT,
        )

        validate_clean_response(response)

    def test_clean_rejects_wrong_ciphertext(self):
        response = self.make_response(
            flags=0x03,
            sec_status=0x00,
            raw_out=bytes(16),
            protected_out=self.CIPHERTEXT,
        )

        with self.assertRaises(DemoCheckError):
            validate_clean_response(response)

    def test_trigger_response_passes(self):
        response = self.make_response(
            flags=0x0D,
            sec_status=0x01,
            raw_out=self.KEY,
            protected_out=bytes(16),
        )

        validate_trigger_response(response, expected_key=self.KEY)

    def test_trigger_rejects_protected_leak(self):
        response = self.make_response(
            flags=0x0F,
            sec_status=0x01,
            raw_out=self.KEY,
            protected_out=self.KEY,
        )

        with self.assertRaises(DemoCheckError):
            validate_trigger_response(
                response,
                expected_key=self.KEY,
            )

    def test_post_lockdown_response_passes(self):
        response = self.make_response(
            flags=0x0D,
            sec_status=0x01,
            raw_out=self.CIPHERTEXT,
            protected_out=bytes(16),
        )

        validate_post_lockdown_response(response)

    def test_random_response_passes(self):
        ciphertext = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
        )

        response = self.make_response(
            flags=0x03,
            sec_status=0x00,
            raw_out=ciphertext,
            protected_out=ciphertext,
        )

        validate_random_response(response)

    def test_random_rejects_core_mismatch(self):
        response = self.make_response(
            flags=0x03,
            sec_status=0x00,
            raw_out=bytes.fromhex(
                "00112233445566778899aabbccddeeff"
            ),
            protected_out=bytes.fromhex(
                "ffeeddccbbaa99887766554433221100"
            ),
        )

        with self.assertRaises(DemoCheckError):
            validate_random_response(response)


if __name__ == "__main__":
    unittest.main()

