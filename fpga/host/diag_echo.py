#!/usr/bin/env python3
"""Raw diagnostic for uart_echo bitstream: send known bytes, print exactly what comes back."""

import sys
import time

import serial

def main():
    if len(sys.argv) < 2:
        print("Usage: python diag_echo.py <COM_PORT>")
        return

    port = sys.argv[1]
    ser = serial.Serial(port, 115200, bytesize=8, parity="N", stopbits=1, timeout=2.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    test_bytes = b"AEGIS123"
    print(f"Opened {port} at 115200 8N1")
    print(f"Sending: {test_bytes} (hex: {test_bytes.hex()})")

    for b in test_bytes:
        ser.write(bytes([b]))
        ser.flush()
        time.sleep(0.05)

    time.sleep(0.3)
    n = ser.in_waiting
    received = ser.read(n) if n else b""

    print(f"Bytes waiting to read: {n}")
    print(f"Received: {received} (hex: {received.hex()})")

    if received == test_bytes:
        print("[PASS] Echo matched exactly - RX and TX both working")
    elif received:
        print("[PARTIAL] Got some bytes back but not matching - possible baud/framing issue")
    else:
        print("[FAIL] Nothing received back - TX path (or RX decode) not working")

    ser.close()

if __name__ == "__main__":
    main()
