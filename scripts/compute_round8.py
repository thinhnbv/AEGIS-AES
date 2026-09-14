#!/usr/bin/env python3
"""
Compute AES-128 round-8 intermediate result.
Round 8 output is the state after 8 rounds of encryption (before MixColumns of round 9).
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

# AES S-box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Round constants for key expansion
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def sub_word(word):
    """Apply S-box to each byte of a 4-byte word."""
    return (SBOX[(word >> 24) & 0xFF] << 24) | \
           (SBOX[(word >> 16) & 0xFF] << 16) | \
           (SBOX[(word >> 8) & 0xFF] << 8) | \
           SBOX[word & 0xFF]

def rot_word(word):
    """Rotate word left by one byte."""
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF

def key_expansion(key_bytes):
    """Expand 128-bit key into 11 round keys (44 words)."""
    Nk = 4  # Number of 32-bit words in key
    Nb = 4  # Number of columns (32-bit words) in state
    Nr = 10 # Number of rounds

    # Initialize key schedule
    w = []
    for i in range(Nk):
        w.append((key_bytes[4*i] << 24) | (key_bytes[4*i+1] << 16) |
                 (key_bytes[4*i+2] << 8) | key_bytes[4*i+3])

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ (RCON[i // Nk - 1] << 24)
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        w.append(w[i - Nk] ^ temp)

    return w

def bytes_to_state(data_bytes):
    """Convert 16 bytes to AES state (column-major order)."""
    state = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    for col in range(4):
        for row in range(4):
            state[row][col] = data_bytes[col * 4 + row]
    return state

def state_to_bytes(state):
    """Convert AES state back to 16 bytes (column-major order)."""
    result = bytearray(16)
    for col in range(4):
        for row in range(4):
            result[col * 4 + row] = state[row][col]
    return bytes(result)

def sub_bytes(state):
    """SubBytes transformation."""
    for row in range(4):
        for col in range(4):
            state[row][col] = SBOX[state[row][col]]

def shift_rows(state):
    """ShiftRows transformation."""
    # Row 0: no shift
    # Row 1: shift left by 1
    temp = state[1][0]
    state[1][0] = state[1][1]
    state[1][1] = state[1][2]
    state[1][2] = state[1][3]
    state[1][3] = temp
    # Row 2: shift left by 2
    temp = state[2][0]
    state[2][0] = state[2][2]
    state[2][2] = temp
    temp = state[2][1]
    state[2][1] = state[2][3]
    state[2][3] = temp
    # Row 3: shift left by 3 (= shift right by 1)
    temp = state[3][3]
    state[3][3] = state[3][2]
    state[3][2] = state[3][1]
    state[3][1] = state[3][0]
    state[3][0] = temp

def galois_mul(a, b):
    """Galois field multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

def mix_columns(state):
    """MixColumns transformation."""
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]
        state[0][col] = galois_mul(2, s0) ^ galois_mul(3, s1) ^ s2 ^ s3
        state[1][col] = s0 ^ galois_mul(2, s1) ^ galois_mul(3, s2) ^ s3
        state[2][col] = s0 ^ s1 ^ galois_mul(2, s2) ^ galois_mul(3, s3)
        state[3][col] = galois_mul(3, s0) ^ s1 ^ s2 ^ galois_mul(2, s3)

def add_round_key(state, round_key, round_num):
    """AddRoundKey transformation."""
    for col in range(4):
        for row in range(4):
            word = round_key[round_num * 4 + col]
            if row == 0:
                byte = (word >> 24) & 0xFF
            elif row == 1:
                byte = (word >> 16) & 0xFF
            elif row == 2:
                byte = (word >> 8) & 0xFF
            else:
                byte = word & 0xFF
            state[row][col] ^= byte

def aes_round(state, round_key, round_num):
    """Perform one AES round."""
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, round_key, round_num)

def aes_round_final(state, round_key, round_num):
    """Perform final AES round (without MixColumns)."""
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_key, round_num)

def aes_encrypt_full(plaintext, key):
    """Full AES-128 encryption, returns ciphertext."""
    state = bytes_to_state(plaintext)
    w = key_expansion(key)

    # Initial round key addition
    add_round_key(state, w, 0)

    # Main rounds
    for round_num in range(1, 10):
        aes_round(state, w, round_num)

    # Final round (without MixColumns)
    aes_round_final(state, w, 10)

    return state_to_bytes(state)

def aes_round8_output(plaintext, key):
    """
    Compute AES round-8 intermediate result.
    Returns the state after 8 rounds of encryption (before MixColumns of round 9).
    """
    state = bytes_to_state(plaintext)
    w = key_expansion(key)

    # Initial round key addition
    add_round_key(state, w, 0)

    # Rounds 1-7: normal rounds with MixColumns
    for round_num in range(1, 8):
        aes_round(state, w, round_num)

    # Round 8: up to but NOT including MixColumns
    # SubBytes
    sub_bytes(state)
    # ShiftRows
    shift_rows(state)
    # AddRoundKey (round 8 key)
    add_round_key(state, w, 8)

    return state_to_bytes(state)

def main():
    # Input values
    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    plaintext_hex = "123456789abcdef00000000000000001"

    # Parse hex strings to bytes
    key = bytes.fromhex(key_hex)
    plaintext = bytes.fromhex(plaintext_hex)

    # Verify we have 16 bytes each
    assert len(key) == 16, f"Key must be 16 bytes, got {len(key)}"
    assert len(plaintext) == 16, f"Plaintext must be 16 bytes, got {len(plaintext)}"

    # Compute round-8 output
    round8_output = aes_round8_output(plaintext, key)

    # Verify full encryption works correctly
    full_ct = aes_encrypt_full(plaintext, key)

    print(f"Key:       {key_hex}")
    print(f"Plaintext: {plaintext_hex}")
    print(f"Round-8:   {round8_output.hex()}")
    print(f"Full CT:   {full_ct.hex()}")

    # Write to file
    output_line = f"{key_hex} {plaintext_hex} {round8_output.hex()}"
    with open("/home/thinhnbv/aegis-aes/verif/vectors/trigger_T03.txt", "w") as f:
        f.write(output_line + "\n")

    print(f"\nWritten to verif/vectors/trigger_T03.txt")
    print(f"Format: {output_line}")

if __name__ == "__main__":
    main()
