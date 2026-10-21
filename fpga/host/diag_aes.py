#!/usr/bin/env python3
"""Raw diagnostic for aegis_demo: send one real 36-byte AES command frame,
then print exactly whatever raw bytes come back within a generous window,
without requiring a full/valid 37-byte response."""

import sys
import time

import serial

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")


def build_request(encrypt, key, data):
    cmd = bytearray()
    cmd.append(0x01)
    cmd.append(0x01 if encrypt else 0x00)
    cmd.extend(key)
    cmd.extend(data)
    chksum = 0
    for b in cmd:
        chksum ^= b
    cmd.append(chksum)
    cmd.append(0xAA)
    return bytes(cmd)


def main():
    if len(sys.argv) < 2:
        print("Usage: python diag_aes.py <COM_PORT>")
        return

    port = sys.argv[1]
    ser = serial.Serial(port, 115200, bytesize=8, parity="N", stopbits=1, timeout=0.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    print(f"Opened {port} at 115200 8N1")
    print("Press and release KEY0 (reset) on the board, wait 1-2s, then press ENTER...")
    input()
    ser.reset_input_buffer()

    req = build_request(True, KEY, PLAINTEXT)
    print(f"Sending 36-byte request: {req.hex()}")
    ser.write(req)
    ser.flush()

    all_bytes = bytearray()
    deadline = time.time() + 5.0
    while time.time() < deadline:
        chunk = ser.read(64)
        if chunk:
            all_bytes.extend(chunk)
            deadline = time.time() + 1.0  # extend a bit while data is still trickling in

    print(f"Total bytes received in 5s window: {len(all_bytes)}")
    print(f"Raw hex: {all_bytes.hex()}")

    if len(all_bytes) == 0:
        print("[RESULT] Completely silent - FSM never reached the response stage.")
    elif len(all_bytes) < 37:
        print(f"[RESULT] Partial response ({len(all_bytes)}/37 bytes) - truncated somewhere in TX.")
    else:
        print("[RESULT] Full-length (or more) response received - check content above.")

    ser.close()


if __name__ == "__main__":
    main()
