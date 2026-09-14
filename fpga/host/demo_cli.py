#!/usr/bin/env python3

import argparse
import secrets
import sys
import time

from dataclasses import dataclass


REQUEST_PREAMBLE = 0xA5
RESPONSE_PREAMBLE = 0x5A
AES_COMMAND = 0x01

REQUEST_SIZE = 36
RESPONSE_SIZE = 37

FLAG_RAW_VALID = 1 << 0
FLAG_PROTECTED_VALID = 1 << 1
FLAG_ALARM = 1 << 2
FLAG_PROTECTED_BLOCKED = 1 << 3
FLAG_FRAME_ERROR = 1 << 7
KLG_STATUS_MASK = 1 << 0

FIPS_KEY = bytes.fromhex(
    "2b7e151628aed2a6abf7158809cf4f3c"
)
FIPS_PLAINTEXT = bytes.fromhex(
    "3243f6a8885a308d313198a2e0370734"
)
FIPS_CIPHERTEXT = bytes.fromhex(
    "3925841d02dc09fbdc118597196a0b32"
)
T01_TRIGGER = bytes.fromhex(
    "deadbeefcafebabe0000000000000000"
)
ZERO_BLOCK = bytes(16)

class ProtocolError(ValueError):
    """Raised when a UART response violates the demo protocol."""


class DemoCheckError(RuntimeError):
    """Raised when the FPGA response violates demo expectations."""


@dataclass(frozen=True)
class DemoResponse:
    seq: int
    flags: int
    sec_status: int
    raw_out: bytes
    protected_out: bytes

    @property
    def raw_valid(self):
        return bool(self.flags & FLAG_RAW_VALID)

    @property
    def protected_valid(self):
        return bool(self.flags & FLAG_PROTECTED_VALID)

    @property
    def alarm(self):
        return bool(self.flags & FLAG_ALARM)

    @property
    def protected_blocked(self):
        return bool(self.flags & FLAG_PROTECTED_BLOCKED)

    @property
    def frame_error(self):
        return bool(self.flags & FLAG_FRAME_ERROR)


def xor_checksum(data):
    checksum = 0

    for value in data:
        checksum ^= value

    return checksum


def build_request(seq, key, plaintext):
    if not isinstance(seq, int) or not 0 <= seq <= 0xFF:
        raise ValueError("seq must be an integer from 0 to 255")

    if len(key) != 16:
        raise ValueError("AES-128 key must contain exactly 16 bytes")

    if len(plaintext) != 16:
        raise ValueError("AES plaintext must contain exactly 16 bytes")

    payload = (
        bytes([REQUEST_PREAMBLE, AES_COMMAND, seq])
        + bytes(key)
        + bytes(plaintext)
    )

    frame = payload + bytes([xor_checksum(payload)])

    if len(frame) != REQUEST_SIZE:
        raise RuntimeError("internal error while building request frame")

    return frame


def parse_response(frame, expected_seq=None):
    frame = bytes(frame)

    if len(frame) != RESPONSE_SIZE:
        raise ProtocolError(
            f"response must contain {RESPONSE_SIZE} bytes, "
            f"received {len(frame)}"
        )

    if frame[0] != RESPONSE_PREAMBLE:
        raise ProtocolError(
            f"invalid response preamble 0x{frame[0]:02x}"
        )

    expected_checksum = xor_checksum(frame[:-1])

    if frame[-1] != expected_checksum:
        raise ProtocolError(
            f"invalid response checksum: received 0x{frame[-1]:02x}, "
            f"expected 0x{expected_checksum:02x}"
        )

    seq = frame[1]

    if expected_seq is not None and seq != expected_seq:
        raise ProtocolError(
            f"unexpected sequence 0x{seq:02x}, "
            f"expected 0x{expected_seq:02x}"
        )

    return DemoResponse(
        seq=seq,
        flags=frame[2],
        sec_status=frame[3],
        raw_out=frame[4:20],
        protected_out=frame[20:36],
    )


def read_exact(serial_port, size):
    if size < 0:
        raise ValueError("read size must not be negative")

    received = bytearray()

    while len(received) < size:
        remaining = size - len(received)
        chunk = serial_port.read(remaining)

        if not chunk:
            raise ProtocolError(
                f"serial timeout after receiving "
                f"{len(received)} of {size} bytes"
            )

        received.extend(chunk)

    return bytes(received)


def transact(serial_port, seq, key, plaintext):
    request = build_request(
        seq=seq,
        key=key,
        plaintext=plaintext,
    )

    written = serial_port.write(request)

    if written != len(request):
        raise ProtocolError(
            f"serial write incomplete: wrote {written} "
            f"of {len(request)} bytes"
        )

    serial_port.flush()

    response_frame = read_exact(
        serial_port=serial_port,
        size=RESPONSE_SIZE,
    )

    return parse_response(
        frame=response_frame,
        expected_seq=seq,
    )

def require_demo(condition, message):
    if not condition:
        raise DemoCheckError(message)


def validate_clean_response(response):
    require_demo(
        not response.frame_error,
        "clean response reports a frame error",
    )
    require_demo(
        response.raw_valid,
        "raw result is not valid for clean request",
    )
    require_demo(
        response.protected_valid,
        "protected result is not valid for clean request",
    )
    require_demo(
        not response.alarm,
        "KLG raised a false alarm for clean request",
    )
    require_demo(
        not response.protected_blocked,
        "protected path was unexpectedly blocked",
    )
    require_demo(
        response.sec_status == 0,
        f"unexpected security status 0x{response.sec_status:02x}",
    )
    require_demo(
        response.raw_out == FIPS_CIPHERTEXT,
        "raw output does not match FIPS-197 ciphertext",
    )
    require_demo(
        response.protected_out == FIPS_CIPHERTEXT,
        "protected output does not match FIPS-197 ciphertext",
    )


def validate_trigger_response(response, expected_key):
    require_demo(
        not response.frame_error,
        "trigger response reports a frame error",
    )
    require_demo(
        response.raw_valid,
        "raw T01 payload is not valid",
    )
    require_demo(
        not response.protected_valid,
        "protected T01 payload became externally valid",
    )
    require_demo(
        response.alarm,
        "KLG alarm was not raised by T01",
    )
    require_demo(
        response.protected_blocked,
        "protected path did not enter LOCKDOWN",
    )
    require_demo(
        bool(response.sec_status & KLG_STATUS_MASK),
        "security status does not contain the KLG cause",
    )
    require_demo(
        response.raw_out == expected_key,
        "raw T01 output does not equal the AES key",
    )
    require_demo(
        response.protected_out == ZERO_BLOCK,
        "protected T01 output is not zero",
    )


def validate_post_lockdown_response(response):
    require_demo(
        not response.frame_error,
        "post-LOCKDOWN response reports a frame error",
    )
    require_demo(
        response.raw_valid,
        "raw path did not complete after LOCKDOWN",
    )
    require_demo(
        not response.protected_valid,
        "protected path produced valid output after LOCKDOWN",
    )
    require_demo(
        response.alarm,
        "KLG alarm did not remain sticky",
    )
    require_demo(
        response.protected_blocked,
        "protected path did not remain blocked",
    )
    require_demo(
        bool(response.sec_status & KLG_STATUS_MASK),
        "KLG cause did not remain sticky",
    )
    require_demo(
        response.raw_out == FIPS_CIPHERTEXT,
        "raw clean output after LOCKDOWN is incorrect",
    )
    require_demo(
        response.protected_out == ZERO_BLOCK,
        "protected output after LOCKDOWN is not zero",
    )


def validate_random_response(response):
    require_demo(
        not response.frame_error,
        "random response reports a frame error",
    )
    require_demo(
        response.raw_valid and response.protected_valid,
        "one or both AES results are not valid",
    )
    require_demo(
        not response.alarm,
        "KLG raised a false alarm for random input",
    )
    require_demo(
        not response.protected_blocked,
        "protected path was blocked for random input",
    )
    require_demo(
        response.sec_status == 0,
        f"unexpected security status 0x{response.sec_status:02x}",
    )
    require_demo(
        response.raw_out == response.protected_out,
        "raw and protected AES results do not match",
    )

def print_response(label, response):
    print(f"[{label}]")
    print(f"  SEQ           : 0x{response.seq:02x}")
    print(f"  FLAGS         : 0x{response.flags:02x}")
    print(f"  SEC_STATUS    : 0x{response.sec_status:02x}")
    print(f"  RAW_OUT       : {response.raw_out.hex()}")
    print(f"  PROTECTED_OUT : {response.protected_out.hex()}")


def run_clean(serial_port):
    response = transact(
        serial_port=serial_port,
        seq=0x01,
        key=FIPS_KEY,
        plaintext=FIPS_PLAINTEXT,
    )

    print_response("CLEAN", response)
    validate_clean_response(response)

    print("[PASS] Clean FIPS-197 vector")
    print("[PASS] Raw and protected outputs match")


def run_trigger(serial_port):
    trigger_response = transact(
        serial_port=serial_port,
        seq=0x01,
        key=FIPS_KEY,
        plaintext=T01_TRIGGER,
    )

    print_response("TRIGGER", trigger_response)
    validate_trigger_response(
        trigger_response,
        expected_key=FIPS_KEY,
    )

    print("[PASS] Raw path exposed the T01 key payload")
    print("[PASS] Protected path quarantined the payload")
    print("[PASS] KLG alarm and LOCKDOWN asserted")

    post_response = transact(
        serial_port=serial_port,
        seq=0x02,
        key=FIPS_KEY,
        plaintext=FIPS_PLAINTEXT,
    )

    print_response("POST-LOCKDOWN CLEAN", post_response)
    validate_post_lockdown_response(post_response)

    print("[PASS] LOCKDOWN and KLG status remained sticky")
    print("[PASS] Raw path remained available")
    print("[PASS] Protected path remained blocked")


def run_random(serial_port, count):
    if count <= 0:
        raise ValueError("random count must be greater than zero")

    for index in range(count):
        key = secrets.token_bytes(16)
        plaintext = secrets.token_bytes(16)
        seq = (index + 1) & 0xFF

        try:
            response = transact(
                serial_port=serial_port,
                seq=seq,
                key=key,
                plaintext=plaintext,
            )

            validate_random_response(response)

        except (ProtocolError, DemoCheckError):
            print(f"[FAIL] Random transaction {index + 1}")
            print(f"  KEY       : {key.hex()}")
            print(f"  PLAINTEXT : {plaintext.hex()}")

            if "response" in locals():
                print_response("FAILED RESPONSE", response)

            raise

        completed = index + 1

        if completed % 100 == 0 or completed == count:
            print(
                f"[INFO] Random regression: "
                f"{completed}/{count}"
            )

    print(f"[PASS] {count} random transactions")
    print("[PASS] Raw and protected outputs always matched")
    print("[PASS] No KLG false alarm observed")


def open_serial_port(port_name, baudrate, timeout):
    try:
        import serial
    except ImportError as error:
        raise RuntimeError(
            "pyserial is not installed; run "
            "'python -m pip install pyserial'"
        ) from error

    try:
        serial_port = serial.Serial(
            port=port_name,
            baudrate=baudrate,
            bytesize=8,
            parity="N",
            stopbits=1,
            timeout=timeout,
            write_timeout=timeout,
        )
    except Exception as error:
        raise RuntimeError(
            f"cannot open serial port {port_name}: {error}"
        ) from error

    serial_port.reset_input_buffer()
    serial_port.reset_output_buffer()

    return serial_port


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description=(
            "AEGIS-AES raw/protected UART demonstration"
        )
    )

    parser.add_argument(
        "--port",
        required=True,
        help="serial port, for example COM5 or /dev/ttyUSB0",
    )
    parser.add_argument(
        "--baudrate",
        type=int,
        default=115200,
        help="UART baud rate, default: 115200",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="serial timeout in seconds, default: 1.0",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    commands.add_parser(
        "clean",
        help="run the FIPS-197 clean vector",
    )

    commands.add_parser(
        "trigger",
        help="run T01 and then verify sticky LOCKDOWN",
    )

    random_parser = commands.add_parser(
        "random",
        help="compare raw and protected paths",
    )
    random_parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="number of random transactions, default: 1000",
    )

    return parser


def main(argv=None):
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    serial_port = None

    try:
        serial_port = open_serial_port(
            port_name=args.port,
            baudrate=args.baudrate,
            timeout=args.timeout,
        )

        time.sleep(0.05)

        if args.command == "clean":
            run_clean(serial_port)

        elif args.command == "trigger":
            run_trigger(serial_port)

        elif args.command == "random":
            run_random(
                serial_port=serial_port,
                count=args.count,
            )

        return 0

    except (
        ProtocolError,
        DemoCheckError,
        RuntimeError,
        ValueError,
        OSError,
    ) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    finally:
        if serial_port is not None:
            serial_port.close()


if __name__ == "__main__":
    sys.exit(main())

    