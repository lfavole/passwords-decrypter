# Author: Joao H de A Franco (jhafranco@acm.org)
# Description: AES-GCM (Galois Counter/Mode) implementation in Python 3
# Date: 2013-05-30
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)

from functools import reduce

import pyaes


def xor(x: bytes, y: bytes):
    """Returns the exclusive or (xor) between two vectors"""
    return bytes(i ^ j for i, j in zip(x, y))


def int_to_list(number: int, list_size: int):
    """Convert a number into a byte list"""
    return [(number >> i) & 0xFF for i in reversed(range(0, list_size * 8, 8))]


def list_to_int(liste: bytes) -> int:
    """Convert a byte list into a number"""
    return reduce(lambda x, y: (x << 8) + y, liste)


def ghash(hkey: bytes, aad: bytes, ctext: bytes):
    """
    GCM's GHASH function.
    """

    def xor_mult_h(a: bytes, b: bytes):
        """
        Multiply (a^b) by hash key.
        """
        x = hkey
        y = xor(a, b)

        (x, y) = (list_to_int(z) for z in (x, y))
        z = 0
        while y & ((1 << 128) - 1):
            if y & (1 << 127):
                z ^= x
            y <<= 1
            if x & 1:
                x = (x >> 1) ^ (0xE1 << 120)
            else:
                x >>= 1
        return bytes(int_to_list(z, 16))

    def g_len(string: bytes):
        """
        Evaluate length of input in bits and returns
        it in the LSB bytes of a 64-bit string.
        """
        return bytes(int_to_list(len(string) * 8, 8))

    x = bytes(16)
    aad_p = aad + bytes((16 - len(aad) % 16) % 16)
    ctext_p = ctext + bytes((16 - len(ctext) % 16) % 16)
    for i in range(0, len(aad_p), 16):
        x = xor_mult_h(x, aad_p[i : i + 16])
    for i in range(0, len(ctext_p), 16):
        x = xor_mult_h(x, ctext_p[i : i + 16])
    return xor_mult_h(x, g_len(aad) + g_len(ctext))


def gcm_crypt(key: bytes, iv: bytes, input: bytes):
    """
    GCM's Authenticated Encryption/Decryption Operations.
    """

    def incr(y: bytes):
        """
        Increment the LSB 32 bits of input counter.
        """
        n12 = y[:12]
        ctr = list_to_int(y[12:])
        if ctr == (1 << 32) - 1:
            return n12 + bytes(4)
        return n12 + bytes(int_to_list(ctr + 1, 4))

    aes_obj = pyaes.AESModeOfOperationECB(key)
    output = b""

    if len(iv) == 12:
        y = iv + b"\x00\x00\x00\x01"
    else:
        y = ghash(aes_obj.encrypt(bytes(16)), b"", iv)

    for i in range(0, len(input), 16):
        y = incr(y)
        output += xor(aes_obj.encrypt(y), input[i : i + 16])

    return output
