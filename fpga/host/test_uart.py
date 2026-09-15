#!/usr/bin/env python3
"""
AEGIS-AES UART Test Client
Tests FPGA demo via UART at 115200 baud
"""

import serial
import struct
import time

# UART settings
PORT = 'COM3'  # Change to your port (check Device Manager)
BAUD = 115200

# FIPS-197 Test Vector 1
KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
PLAINTEXT = bytes.fromhex('3243f6a8885a308d313198a2e0370734')
CIPHERTEXT = bytes.fromhex('3925841d02dc09fbdc118597196a0b32')

def send_command(ser, encrypt, key, data):
    """Send 36-byte command to FPGA"""
    # Build command
    cmd = bytearray()
    cmd.append(0x01)  # Marker
    cmd.append(0x01 if encrypt else 0x00)  # Command
    cmd.extend(key)  # 16 bytes key
    cmd.extend(data)  # 16 bytes data

    # Checksum (XOR of bytes 0-33)
    chksum = 0
    for i in range(34):
        chksum ^= cmd[i]
    cmd.append(chksum)
    cmd.append(0xAA)  # End marker

    # Send
    ser.write(cmd)
    return cmd

def recv_response(ser):
    """Receive 37-byte response from FPGA"""
    resp = ser.read(37)
    if len(resp) < 37:
        print(f"  Incomplete response: {len(resp)} bytes")
        return None, None, None, None

    marker = resp[0]
    status = resp[1]
    result = resp[2:18]
    echoed = resp[18:34]
    round_nr = resp[36]

    return status, result, echoed, round_nr

def test_encrypt(ser):
    """Test AES-128 encryption"""
    print("\n=== Test 1: AES-128 Encryption ===")
    print(f"Key:       {KEY.hex()}")
    print(f"Plaintext: {PLAINTEXT.hex()}")
    print(f"Expected:  {CIPHERTEXT.hex()}")

    send_command(ser, True, KEY, PLAINTEXT)
    time.sleep(0.5)
    status, result, echoed, round_nr = recv_response(ser)

    if result:
        print(f"Result:    {result.hex()}")
        print(f"Round:     {round_nr}")
        print(f"Status:    {status}")

        if result == CIPHERTEXT:
            print("✅ PASS!")
            return True
        else:
            print("❌ FAIL!")
            return False
    return False

def test_decrypt(ser):
    """Test AES-128 decryption"""
    print("\n=== Test 2: AES-128 Decryption ===")
    print(f"Key:        {KEY.hex()}")
    print(f"Ciphertext: {CIPHERTEXT.hex()}")
    print(f"Expected:   {PLAINTEXT.hex()}")

    send_command(ser, False, KEY, CIPHERTEXT)
    time.sleep(0.5)
    status, result, echoed, round_nr = recv_response(ser)

    if result:
        print(f"Result:    {result.hex()}")
        print(f"Round:     {round_nr}")
        print(f"Status:    {status}")

        if result == PLAINTEXT:
            print("✅ PASS!")
            return True
        else:
            print("❌ FAIL!")
            return False
    return False

def main():
    print("=" * 50)
    print("AEGIS-AES FPGA Demo - UART Test")
    print("=" * 50)

    # Find COM port
    import serial.tools.list_ports
    ports = list(serial.tools.list_ports.comports())
    print(f"\nAvailable COM ports:")
    for p in ports:
        print(f"  {p.device}: {p.description}")

    # Open serial
    try:
        ser = serial.Serial(PORT, BAUD, timeout=1)
        print(f"\nOpened {PORT} at {BAUD} baud")
        time.sleep(0.1)
    except Exception as e:
        print(f"\nError opening {PORT}: {e}")
        print("\nPlease check:")
        print("1. FPGA is connected via USB")
        print("2. Correct COM port in Device Manager")
        return

    # Run tests
    results = []
    try:
        results.append(("Encrypt", test_encrypt(ser)))
        results.append(("Decrypt", test_decrypt(ser)))
    finally:
        ser.close()

    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name}: {status}")

    all_passed = all(r[1] for r in results)
    print()
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("⚠️  SOME TESTS FAILED")

if __name__ == "__main__":
    main()
