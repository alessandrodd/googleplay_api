import base64
import hashlib
import binascii

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# The key is the Play Services public key distributed with Google Play Services.
# This one is from version 7.3.29.
B64_KEY_7_3_29 = (b"AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3"
                  b"iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK"
                  b"RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/"
                  b"6rmf5AAAAAwEAAQ==")


def bytes_to_long(s):
    return int.from_bytes(s, "big")


def long_to_bytes(lnum, padmultiple=1):
    """Packs the lnum (which must be convertable to a long) into a
       byte string 0 padded to a multiple of padmultiple bytes in size. 0
       means no padding whatsoever, so that packing 0 result in an empty
       string.  The resulting byte string is the big-endian two's
       complement representation of the passed in long."""

    # source: http://stackoverflow.com/a/14527004/1231454

    if lnum == 0:
        return b'\0' * padmultiple
    elif lnum < 0:
        raise ValueError("Can only convert non-negative numbers.")
    s = hex(lnum)[2:]
    s = s.rstrip('L')
    if len(s) & 1:
        s = '0' + s
    s = binascii.unhexlify(s)
    if (padmultiple != 1) and (padmultiple != 0):
        filled_so_far = len(s) % padmultiple
        if filled_so_far != 0:
            s = b'\0' * (padmultiple - filled_so_far) + s
    return s


def key_from_b64(b64_key):
    binaryKey = base64.b64decode(b64_key)

    i = bytes_to_long(binaryKey[:4])
    mod = bytes_to_long(binaryKey[4:4 + i])

    j = bytes_to_long(binaryKey[i + 4:i + 4 + 4])
    exponent = bytes_to_long(binaryKey[i + 8:i + 8 + j])

    key = RSA.construct((mod, exponent))

    return key


def key_to_struct(key):
    mod = long_to_bytes(key.n)
    exponent = long_to_bytes(key.e)

    return b'\x00\x00\x00\x80' + mod + b'\x00\x00\x00\x03' + exponent


def parse_auth_response(text):
    response_data = {}
    for line in text.split('\n'):
        if not line:
            continue

        key, _, val = line.partition('=')
        response_data[key] = val

    return response_data


def encrypt_login(email, password, b64_key=B64_KEY_7_3_29):
    signature = bytearray(b'\x00')

    key = key_from_b64(b64_key)

    struct = key_to_struct(key)
    signature.extend(hashlib.sha1(struct).digest()[:4])

    cipher = PKCS1_OAEP.new(key)
    encrypted_login = cipher.encrypt((email + u'\x00' + password).encode('utf-8'))

    signature.extend(encrypted_login)

    return base64.urlsafe_b64encode(signature)
