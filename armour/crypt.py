#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cryptography algorithms"""

import base64
import secrets
import typing

import crc4
import zstd
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import (Cipher, CipherContext, algorithms,
                                                    modes)
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

DEFAULT_BACKEND: typing.Final[typing.Any] = default_backend()


def hash_algo(hash_id: int, data: bytes) -> bytes:
    """*just* hash the data"""

    h: hashes.Hash = hashes.Hash(HASHES[hash_id], backend=DEFAULT_BACKEND)
    h.update(data)
    return h.finalize()


def hash_walgo(
    hash_id: int,
    data: bytes,
    key: bytes,
    salt: bytes,
    kdf_iters: int,
    hash_salt_len: int,
    *,
    _salt: typing.Optional[bytes] = None,
) -> bytes:
    """securely hash bytes with a specified algorithm using hmac"""

    if _salt is None:
        _salt = RAND.randbytes(hash_salt_len)

    h: hmac.HMAC = hmac.HMAC(
        PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=_salt,
            iterations=kdf_iters,
            backend=DEFAULT_BACKEND,
        ).derive(key + salt),
        HASHES[hash_id],
        backend=DEFAULT_BACKEND,
    )
    h.update(data)

    return _salt + h.finalize()


def hash_walgo_compare(
    hash_id: int,
    data: bytes,
    key: bytes,
    salt: bytes,
    kdf_iters: int,
    hash_salt_len: int,
    target: bytes,
) -> bool:
    """securely compare hash of bytes with a specified algorithm using hmac"""

    return (
        hash_walgo(
            hash_id=hash_id,
            data=data,
            key=key,
            salt=salt,
            kdf_iters=kdf_iters,
            hash_salt_len=hash_salt_len,
            _salt=target[:hash_salt_len],
        )
        == target
    )


# -- aes encryption --


def encrypt_aes(
    data: bytes,
    password: bytes,
    hash_id: int,
    kdf_iters: int,
    hash_salt_len: int,
    aes_crypto_passes: int,
) -> bytes:
    """aes multiple encryption"""

    for _ in range(aes_crypto_passes):
        salt: bytes = RAND.randbytes(hash_salt_len)

        key: bytes = PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=salt,
            iterations=kdf_iters,
            backend=DEFAULT_BACKEND,
        ).derive(password)

        iv: bytes = RAND.randbytes(16)

        encryptor: CipherContext = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=DEFAULT_BACKEND,
        ).encryptor()

        padder: padding.PaddingContext = padding.PKCS7(128).padder()

        data = (
            encryptor.update(padder.update(data) + padder.finalize())
            + encryptor.finalize()
        )

        data = salt + iv + data

    return data


def decrypt_aes(
    data: bytes,
    password: bytes,
    hash_id: int,
    kdf_iters: int,
    hash_salt_len: int,
    aes_crypto_passes: int,
) -> bytes:
    """aes multiple encryption"""

    mid: int = hash_salt_len + 16

    for _ in range(aes_crypto_passes):
        salt: bytes = data[:hash_salt_len]
        iv: bytes = data[hash_salt_len:mid]
        ct: bytes = data[mid:]

        key: bytes = PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=salt,
            iterations=kdf_iters,
            backend=DEFAULT_BACKEND,
        ).derive(password)

        decryptor: CipherContext = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=DEFAULT_BACKEND,
        ).decryptor()

        pt: bytes = decryptor.update(ct) + decryptor.finalize()
        unpadder: padding.PaddingContext = padding.PKCS7(128).unpadder()

        data = unpadder.update(pt) + unpadder.finalize()

    return data


# -- secure encryption --


def derive_secure_key(
    password: bytes,
    salt: bytes,
    hash_id: int,
    kdf_iters: int,
) -> bytes:
    """derive key from password"""
    return base64.urlsafe_b64encode(
        PBKDF2HMAC(
            algorithm=HASHES[hash_id],
            length=32,
            salt=salt,
            iterations=kdf_iters + 1,
            backend=DEFAULT_BACKEND,
        ).derive(password)
    )


def encrypt_secure(
    data: bytes,
    password: bytes,
    salt: bytes,
    hash_id: int,
    hash_salt_len: int,
    sec_crypto_passes: int,
    kdf_iters: int,
    zstd_comp_lvl: int,
) -> bytes:
    """securely encrypt data"""

    for _ in range(sec_crypto_passes):
        data = Fernet(
            derive_secure_key(
                password=password,
                salt=salt,
                hash_id=hash_id,
                kdf_iters=kdf_iters,
            )
        ).encrypt(data + RAND.randbytes(hash_salt_len))

    return base64.b85encode(
        zstd.compress(data, zstd_comp_lvl, zstd.ZSTD_threads_count())
    )


def decrypt_secure(
    data: bytes,
    password: bytes,
    salt: bytes,
    hash_id: int,
    hash_salt_len: int,
    sec_crypto_passes: int,
    kdf_iters: int,
) -> bytes:
    """securely decrypt data"""

    data = zstd.decompress(base64.b85decode(data))

    for _ in range(sec_crypto_passes):
        data = Fernet(
            derive_secure_key(
                password=password,
                salt=salt,
                hash_id=hash_id,
                kdf_iters=kdf_iters,
            )
        ).decrypt(data)[:-hash_salt_len]

    return data


# -- rc4 encryption --


def encrypt_rc4(
    data: bytes,
    isec_crypto_passes: int,
    password: bytes,
    salt: bytes,
    hash_salt_len: int,
) -> bytes:
    """encrypt rc4"""

    rsalt: bytes = RAND.randbytes(hash_salt_len + 13)
    key: bytes = hash_algo(0, rsalt + password + salt)

    for _ in range(isec_crypto_passes):
        data = crc4.rc4(RAND.randbytes(5) + data + RAND.randbytes(5), key)  # type: ignore

    return rsalt + data  # type: ignore


def decrypt_rc4(
    data: bytes,
    isec_crypto_passes: int,
    password: bytes,
    salt: bytes,
    hash_salt_len: int,
) -> bytes:
    """decrypt rc4"""

    hash_salt_len += 13

    rsalt: bytes = data[:hash_salt_len]
    data = data[hash_salt_len:]

    key: bytes = hash_algo(0, rsalt + password + salt)

    for _ in range(isec_crypto_passes):
        data = crc4.rc4(data, key)[5:-5]  # type: ignore

    return data  # type: ignore
