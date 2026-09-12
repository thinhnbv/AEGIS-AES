#!/usr/bin/env python3
"""
Generate NIST AES-128 KAT and MCT test vectors.

KAT Groups (from NIST FIPS-197):
- ECBGFSbox128: Same key, PT feeds from previous CT (4 vectors)
- ECBKeySbox128: Key feeds from previous CT, same PT (4 vectors)
- ECBVarTxt128: Same key, 4 PTs with single byte variation (4 vectors)
- ECBVarKey128: Same PT, 4 keys with single byte variation (4 vectors)

MCT (Monte Carlo Test): 10000 random key/pt pairs with fixed seed

Output format: <key> <pt> <ct> (each 32 hex chars for 128-bit)
"""

from Crypto.Cipher import AES
import struct

# NIST Test Vectors (from FIPS-197 Appendix B)
SEED_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
SEED_PT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-128 encryption using ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def to_hex_str(data: bytes) -> str:
    """Convert bytes to 32-char hex string (128-bit)."""
    return data.hex()

def gen_ecbgfsbox128():
    """ECB "From Sbox" - Same key, PT varies (previous CT becomes next PT)."""
    vectors = []
    key = SEED_KEY
    pt = SEED_PT

    for i in range(4):
        ct = aes_encrypt(key, pt)
        vectors.append((key, pt, ct))
        pt = ct  # Next PT = previous CT

    return vectors

def gen_ecbkeysbox128():
    """ECB "Key Sbox" - Key varies (previous CT becomes next key), same PT."""
    vectors = []
    key = SEED_KEY
    pt = SEED_PT

    for i in range(4):
        ct = aes_encrypt(key, pt)
        vectors.append((key, pt, ct))
        key = ct  # Next key = previous CT

    return vectors

def gen_ecbvtxt128():
    """ECB "Variable Text" - Same key, 4 PTs with single byte variation."""
    vectors = []
    key = SEED_KEY
    pt = bytearray(SEED_PT)

    for i in range(4):
        pt[0] = i  # Change first byte
        ct = aes_encrypt(key, bytes(pt))
        vectors.append((key, bytes(pt), ct))

    return vectors

def gen_ecbvkey128():
    """ECB "Variable Key" - Same PT, 4 keys with single byte variation."""
    vectors = []
    key = bytearray(SEED_KEY)
    pt = SEED_PT

    for i in range(4):
        key[0] = i  # Change first byte
        ct = aes_encrypt(bytes(key), pt)
        vectors.append((bytes(key), pt, ct))

    return vectors

class XorshiftRNG:
    """Simple xorshift pseudo-random number generator for deterministic sequences."""
    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        """Generate next 64-bit random number."""
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> 7)
        x ^= (x << 17) & 0xFFFFFFFFFFFFFFFF
        self.state = x & 0xFFFFFFFFFFFFFFFF
        return x

    def next_bytes(self, n: int) -> bytes:
        """Generate n random bytes."""
        result = bytearray()
        for _ in range((n + 7) // 8):
            val = self.next()
            result.extend(val.to_bytes(8, 'big'))
        return bytes(result[:n])

def gen_mct(seed: int, count: int):
    """Generate Monte Carlo Test vectors with given seed."""
    vectors = []
    rng = XorshiftRNG(seed)

    for i in range(count):
        key = rng.next_bytes(16)
        pt = rng.next_bytes(16)
        ct = aes_encrypt(key, pt)
        vectors.append((key, pt, ct))

    return vectors

def write_vectors(filename: str):
    """Generate all vectors and write to file."""
    all_vectors = []

    # KAT: ECBGFSbox128
    kat_gfsbox = gen_ecbgfsbox128()
    all_vectors.extend(kat_gfsbox)

    # KAT: ECBKeySbox128
    kat_keysbox = gen_ecbkeysbox128()
    all_vectors.extend(kat_keysbox)

    # KAT: ECBVarTxt128
    kat_vtxt = gen_ecbvtxt128()
    all_vectors.extend(kat_vtxt)

    # KAT: ECBVarKey128
    kat_vkey = gen_ecbvkey128()
    all_vectors.extend(kat_vkey)

    # MCT: 10000 vectors with seed 0xA5EC5A
    mct_vectors = gen_mct(0xA5EC5A, 10000)
    all_vectors.extend(mct_vectors)

    # Write to file
    with open(filename, 'w') as f:
        for key, pt, ct in all_vectors:
            f.write(f"{to_hex_str(key)} {to_hex_str(pt)} {to_hex_str(ct)}\n")

    return len(all_vectors)

def main():
    import os

    # Determine output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    output_path = os.path.join(repo_root, "verif", "vectors", "nist_vectors.txt")

    # Verify FIPS-197 Appendix B reference vector
    expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    computed_ct = aes_encrypt(SEED_KEY, SEED_PT)
    if computed_ct == expected_ct:
        print(f"[OK] FIPS-197 Appendix B reference verified")
        print(f"     KEY = {to_hex_str(SEED_KEY)}")
        print(f"     PT  = {to_hex_str(SEED_PT)}")
        print(f"     CT  = {to_hex_str(computed_ct)}")
    else:
        print(f"[ERROR] FIPS-197 reference vector mismatch!")
        print(f"  Expected: {expected_ct.hex()}")
        print(f"  Got:      {computed_ct.hex()}")
        return

    # Generate and write vectors
    total_count = write_vectors(output_path)
    kat_count = 16  # 4 groups * 4 vectors each
    mct_count = 10000

    print(f"\nGenerated {total_count} vectors:")
    print(f"  KAT: {kat_count} vectors (4 groups x 4 vectors)")
    print(f"  MCT: {mct_count} vectors (seed=0xA5EC5A)")
    print(f"\nOutput: {output_path}")

    # Show first few lines
    print(f"\nFirst 20 lines:")
    with open(output_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= 20:
                break
            print(f"  {line.strip()}")

if __name__ == "__main__":
    main()
