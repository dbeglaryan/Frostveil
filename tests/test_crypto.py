"""Tests for the crypto engine — AES-GCM, GF(2^128), key derivation."""
import pytest
import struct
from modules.crypto import (
    _gf128_mul, _bytes_to_int, _int_to_bytes, _inc32,
    aes_gcm_decrypt, hmac_sign, hmac_verify,
)


class TestGF128:
    """GF(2^128) multiplication used by GHASH."""

    def test_zero_multiply(self):
        assert _gf128_mul(0, 0) == 0

    def test_identity_zero(self):
        x = 0x80000000000000000000000000000000
        assert _gf128_mul(x, 0) == 0
        assert _gf128_mul(0, x) == 0

    def test_commutativity(self):
        a = 0x0388DACE60B6A392F328C2B971B2FE78
        b = 0x66E94BD4EF8A2C3B884CFA59CA342B2E
        assert _gf128_mul(a, b) == _gf128_mul(b, a)


class TestByteConversions:
    def test_roundtrip(self):
        val = 0xDEADBEEFCAFEBABE0123456789ABCDEF
        assert _bytes_to_int(_int_to_bytes(val)) == val

    def test_inc32(self):
        block = b"\x00" * 12 + b"\x00\x00\x00\x01"
        result = _inc32(block)
        assert result == b"\x00" * 12 + b"\x00\x00\x00\x02"

    def test_inc32_wrap(self):
        block = b"\x00" * 12 + b"\xff\xff\xff\xff"
        result = _inc32(block)
        assert result == b"\x00" * 12 + b"\x00\x00\x00\x00"


class TestHMAC:
    def test_sign_verify(self):
        data = b"test data for signing"
        key = b"secret_key_32_bytes_long_padded!"
        sig = hmac_sign(data, key)
        assert hmac_verify(data, sig, key)

    def test_verify_tampered(self):
        data = b"original data"
        key = b"secret_key_32_bytes_long_padded!"
        sig = hmac_sign(data, key)
        assert not hmac_verify(b"tampered data", sig, key)

    def test_sign_deterministic(self):
        data = b"consistent output"
        key = b"same_key_always_32_bytes_long!!"
        assert hmac_sign(data, key) == hmac_sign(data, key)

    def test_different_keys_different_sigs(self):
        data = b"test data"
        sig1 = hmac_sign(data, b"key1_padded_to_32_bytes_long!!!!")
        sig2 = hmac_sign(data, b"key2_padded_to_32_bytes_long!!!!")
        assert sig1 != sig2
