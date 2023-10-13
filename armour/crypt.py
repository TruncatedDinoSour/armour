#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptography algorithms"""

import base64
import secrets
import typing

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# -- hashing --

HASHES: typing.Final[typing.Tuple[hashes.HashAlgorithm, ...]] = (
    hashes.SHA3_512(),
    hashes.BLAKE2b(64),
    hashes.SHA512(),
    hashes.SHA3_384(),
    hashes.SHA512_256(),
    hashes.BLAKE2s(32),
    hashes.SHA384(),
    hashes.SHA3_256(),
    hashes.SHA512_224(),
    hashes.SHA256(),
    hashes.SHA3_224(),
    hashes.SHA224(),
    hashes.SHA1(),
    hashes.SM3(),
    hashes.MD5(),
)


RAND: typing.Final[secrets.SystemRandom] = secrets.SystemRandom()


def hash_walgo(
    hash_id: int,
    data: bytes,
    key: bytes,
    kdf_iters: int,
    *,
    _salt: typing.Optional[bytes] = None,
) -> bytes:
    """securely hash bytes with a specified algorithm using hmac"""

    if _salt is None:
        _salt = RAND.randbytes(19)

    h: hmac.HMAC = hmac.HMAC(
        PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=_salt,
            iterations=kdf_iters,
            backend=default_backend(),
        ).derive(key),
        HASHES[hash_id],
        backend=default_backend(),
    )
    h.update(data)
    return _salt + h.finalize()


def hash_walgo_compare(
    hash_id: int,
    data: bytes,
    key: bytes,
    kdf_iters: int,
    target: bytes,
) -> bool:
    """securely compare hash of bytes with a specified algorithm using hmac"""

    return (
        hash_walgo(
            hash_id=hash_id,
            data=data,
            key=key,
            kdf_iters=kdf_iters,
            _salt=target[:19],
        )
        == target
    )


# -- rc4 encryption --


def crypt_rc4(data: bytes, key: bytes) -> bytes:
    """rc4 crypto"""

    S = list(range(256))
    j: int = 0
    out: bytearray = bytearray()

    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0

    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)


def encrypt_rc4(data: bytes, key: bytes) -> bytes:
    """encrypt rc4"""
    return crypt_rc4(data=data + RAND.randbytes(32), key=key)


def decrypt_rc4(data: bytes, key: bytes) -> bytes:
    """decrypt rc4"""
    return crypt_rc4(data=data, key=key)[:-32]


# -- secure encryption --


def derrive_secure_key(
    password: bytes,
    salt: bytes,
    hash_id: int,
    kdf_iters: int,
) -> bytes:
    """derrive key from password"""
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=salt,
            iterations=kdf_iters + 1,
            backend=default_backend(),
        ).derive(password)
    )


def encrypt_secure(
    data: bytes,
    password: bytes,
    salt: bytes,
    hash_id: int,
    kdf_iters: int,
) -> bytes:
    """securely encrypt data"""
    return Fernet(
        derrive_secure_key(
            password=password,
            salt=salt,
            hash_id=hash_id,
            kdf_iters=kdf_iters,
        )
    ).encrypt(data + RAND.randbytes(32))


def decrypt_secure(
    data: bytes,
    password: bytes,
    salt: bytes,
    hash_id: int,
    kdf_iters: int,
) -> bytes:
    """securely decrypt data"""
    return Fernet(
        derrive_secure_key(
            password=password,
            salt=salt,
            hash_id=hash_id,
            kdf_iters=kdf_iters,
        )
    ).decrypt(data)[:-32]
