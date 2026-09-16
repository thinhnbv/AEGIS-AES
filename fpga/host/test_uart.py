#!/usr/bin/env python3
"""
AEGIS-AES UART Test Client
Tests FPGA demo via UART at 115200 baud
"""

import serial
import sys
import time

BAUD = 115200

# FIPS-197 Test Vector 1
KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
PLAINTEXT = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
CIPHERTEXT = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')

def send_command(ser, encrypt, key, data):
    """Send 36-byte command to FPGA"""
    cmd = bytearray()
    cmd.append(0x01)  # Marker
    cmd.append(0x01 if encrypt else 0x00)  # Command
    cmd.extend(key)   # 16 bytes key
    cmd.extend(data)  # 16 bytes data
    chksum = 0
    for i in range(34):
        chksum ^= cmd[i]
    cmd.append(chksum)
    cmd.append(0xAA)  # End marker
    ser.write(cmd)
    return cmd

def recv_response(ser, timeout=2.0):
    """Receive 37-byte response from FPGA"""
    ser.timeout = timeout
    resp = ser.read(37)
    if len(resp) < 37:
        return None, None, None, None
    return resp[1], resp[2:18], resp[18:34], resp[36]

def flush_input(ser):
    """Clear any pending input"""
    ser.reset_input_buffer()
    time.sleep(0.1)
    ser.read(ser.in_waiting)
    ser.reset_input_buffer()

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_uart.py <COM_PORT>")
        print("Example: python test_uart.py COM3")
        return

    port = sys.argv[1]
    print(f"Opening {port} at {BAUD} baud...")

    try:
        ser = serial.Serial(
            port,
            BAUD,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=2.0
        )
    except Exception as e:
        print(f"Error: {e}")
        return

    print("Serial port opened!")
    print()
    print("=" * 60)
    print("INSTRUCTIONS:")
    print("1. Press and release KEY0 (reset) on the FPGA board")
    print("2. Wait 1-2 seconds for FPGA to initialize")
    print("3. Press ENTER to start test...")
    print("=" * 60)
    input()

    flush_input(ser)

    # Test 1: Encrypt
    print("\n=== Test 1: AES-128 Encryption ===")
    print(f"Key:       {KEY.hex()}")
    print(f"Plain:     {PLAINTEXT.hex()}")
    print(f"Expected:  {CIPHERTEXT.hex()}")
    print("Sending command...")

    send_command(ser, True, KEY, PLAINTEXT)
    time.sleep(0.5)
    status, result, echoed, round_nr = recv_response(ser)

    if result:
        print(f"Result:    {result.hex()}")
        print(f"Round:     {round_nr}")
        if result == CIPHERTEXT:
            print("✅ PASS!")
        else:
            print("❌ FAIL!")
    else:
        print("❌ No response - check if FPGA is running")
        print("   - Make sure reset button is released")
        print("   - Check LED[2] is lit (AES ready)")

    time.sleep(0.5)

    # Test 2: Decrypt
    print("\n=== Test 2: AES-128 Decryption ===")
    print(f"Key:       {KEY.hex()}")
    print(f"Cipher:    {CIPHERTEXT.hex()}")
    print(f"Expected:  {PLAINTEXT.hex()}")
    print("Sending command...")

    send_command(ser, False, KEY, CIPHERTEXT)
    time.sleep(0.5)
    status, result, echoed, round_nr = recv_response(ser)

    if result:
        print(f"Result:    {result.hex()}")
        print(f"Round:     {round_nr}")
        if result == PLAINTEXT:
            print("✅ PASS!")
        else:
            print("❌ FAIL!")
    else:
        print("❌ No response")

    ser.close()
    print("\nDone!")

if __name__ == "__main__":
    main()
