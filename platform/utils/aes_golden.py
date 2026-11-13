"""Golden AES-128-ECB reference (design-time only, not chip IP).

Used by S2/S4 to compute the expected ciphertext for a trigger block so
verification compares against the real AES output instead of a weak
``result !== key`` check.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_256 = int(
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 16
)


def aes_128_ecb(block_128: int, key_256: int = KEY_256) -> int:
    """Encrypt one 128-bit block with AES-128-ECB (low 128 bits of key)."""
    key_bytes = (key_256 & ((1 << 128) - 1)).to_bytes(16, "big")
    block_bytes = block_128.to_bytes(16, "big")
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    enc = cipher.encryptor()
    ct = enc.update(block_bytes) + enc.finalize()
    return int.from_bytes(ct, "big")


def expected_ciphertext_hex(block_128: int, key_256: int = KEY_256) -> str:
    """Return ``128'h<32 hex>`` golden ciphertext for a trigger block."""
    return "128'h%032x" % aes_128_ecb(block_128, key_256)
