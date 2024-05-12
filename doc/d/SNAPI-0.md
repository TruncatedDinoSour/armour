# Standard Network Application Programming Interface (SNAPI) -- version 0 (alpha)

This document describes the standard network API (SNAPI) for pDBv1+.
SNAPI is used for interacting with pDB and Keyfile structures over a network interface.

**Last modified**: 2024-05-12

## Introduction

SNAPI (Standard Network Application Programming Interface) is a protocol extension on top of TCP (RFC 9293)
to use, query, and manage the pDB and Keyfile formats over a network connection.

## Clients

This section includes a list of SDKs, libraries, user interfaces, etc. (collectively called "clients") which support SNAPI.

-   [Stable, Official] Armour SDK from the Armour project by Ari Archer \<<ari@ari.lt>\> licensed under GPL-3.0-or-later: <https://ari.lt/gh/armour> (supports: pDBv0, pDBv1, SNAPI)
    -   [Stable, Official] "Pwdmgr" Client from the Pwdtools project using the Armour SDK by Ari Archer \<<ari@ari.lt>\> licensed under GPL-3.0-or-later: <https://ari.lt/gh/pwdtools> (Client ID: `Pwdmgr <version>`)

If you're planning on implementing a client, you must get familiar with the whole specifications of Keyfile, pDB, and SNAPI.
It is a complex task requiring a lot of different implementations of different algorithms, a lot of management, and a lot of parsing.

## Connection and encryption

The connection is primarily secured using ChaCha20-Poly1305, using HKDF for key derivation,
various hashing functions, and ECDH (Elliptic-Curve Diffie-Hellman). The key exchange is simple:

-   Both the client and the server generate their own private and public ECDH keys.
-   The client sends its Client ID, which is up to 64 bytes to the server. Server saves it.
-   Server responds with its own Server ID, which is up to 64 bytes. Client saves it.
-   The client sends its own DER-Serialised ECDH public key. This key should be 158 bytes.
-   The server responds with its own DER-Serialised ECDH public key (158 bytes).
-   Both the client and the server derive the same salt, info, and key material values.
    -   Salt: `sha3_256(client_public_key_der + server_public_key_der)`
    -   Info: `Client ID <=> Server ID` (such as `Sample client 1.2.3 <=> Sample server 1.0.0`)
    -   Material: A ECDH key exchange happens based off the public keys.
-   Both the client and the server derive same initial key, nonce, and associated data values.
    -   Key: `HKDF(algorithm=SHA3_512, length=64, salt=salt, info=info, material=material)`
    -   Nonce: `HKDF(algorithm=SHA3_512, length=48, salt=SHA3_256(salt + key), info=info, material=material)`
    -   Associated data (assoc): `HKDF(algorithm=SHA3_512, length=32, salt=SHA3_256(nonce + key + salt), info=info, material=material)`
-   When ciphering, the following process is executed:
    -   32 cryptographically-secure bytes are generated called `extra` (256 bits of cryptographically secure information).
    -   The plain text is padded to a block size of 32 bytes. The padding size is appended to the plain input as a `uint8_t`.
    -   A ChaCha20-Poly1305 cipher is applied to the plain text:
        `ChaCha20_Poly1305(data=data, key=sha3_256(key + extra), nonce=md5(nonce + extra).first(12), associated_data=sha3_512(assoc + extra))`
        -   Data: The padded input.
        -   Key: SHA3-256 digest of the concatenation of the previously derived key, and extra bytes.
        -   Nonce: First 12 bytes of an MD5 digest of previously derived nonce and extra bytes.
        -   Associated data: A SHA3-512 digest of the previously derived associated data and the extra bytes.
    -   The extra 32 bytes are prepended to the data. Final cypher-text is sent to the server/client.

An example _handshake_ server (not a full SNAPI implementation):

<details>
<summary>File: `server.py`</summary>

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNAPI example server"""

import hashlib
import os
import socket
from warnings import filterwarnings as filter_warnings

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST: str = "127.0.0.1"
PORT: int = 2912


def main() -> int:
    """entry / main function"""

    server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"Server is listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    print(f"Incoming connection from {addr}")

    # Generate server's ECDH key.

    private_key: EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP521R1())
    public_key: EllipticCurvePublicKey = private_key.public_key()
    serialized_public: bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Wait for the client to be ready. Get the client and its version.

    client_id: bytes = conn.recv(64)
    print("Public data:", client_id)

    # Send the server's identifier.

    conn.sendall(b"Sample server 1.0.0")

    # Receive the public ECDH key of the client.

    client_der: bytes = conn.recv(158)
    client_public = serialization.load_der_public_key(client_der)

    # Send the public ECDH key to the client.

    conn.sendall(serialized_public)

    # Derive the key.

    salt: bytes = hashlib.sha3_256(client_der + serialized_public).digest()
    info: bytes = client_id + b" <=> Sample server 1.0.0"
    material: bytes = private_key.exchange(ec.ECDH(), client_public)

    key: bytes = HKDF(
        algorithm=hashes.SHA3_512(),
        length=64,
        salt=salt,
        info=info,
    ).derive(material)

    nonce: bytes = HKDF(
        algorithm=hashes.SHA3_512(),
        length=48,
        salt=hashlib.sha3_256(salt + key).digest(),
        info=info,
    ).derive(material)

    assoc: bytes = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=hashlib.sha3_256(nonce + key + salt).digest(),
        info=info,
    ).derive(material)

    print("Key:", key)
    print("Nonce:", nonce)
    print("Assoc:", assoc)

    # Receive ciphered data.

    exct: bytes = conn.recv(1024)
    ex, ct = exct[:32], exct[32:]

    print("Extra:", ex)
    print("Cypher-text:", ct)

    recv_pt: bytes = ChaCha20Poly1305(hashlib.sha3_256(key + ex).digest()).decrypt(
        hashlib.md5(nonce + ex).digest()[:12],
        ct,
        hashlib.sha3_512(assoc + ex).digest(),
    )

    recv_pt = recv_pt[: -(recv_pt[-1] + 1)]

    print(
        "Decrypted:",
        recv_pt,
    )

    # Send ciphered data.

    extra: bytes = os.urandom(32)

    sending_pt: bytes = b"Hello, Client!"
    padding_size: int = 31 - (len(sending_pt) % 32)

    if padding_size > 0:
        sending_pt += os.urandom(padding_size)

    sending_pt += bytes([padding_size])

    conn.sendall(
        extra
        + ChaCha20Poly1305(hashlib.sha3_256(key + extra).digest()).encrypt(
            hashlib.md5(nonce + extra).digest()[:12],
            sending_pt,
            hashlib.sha3_512(assoc + extra).digest(),
        )
    )

    # Close connections.

    conn.close()
    server.close()

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    raise SystemExit(main())
```

</details>

A client could be implemented in a similar fashion.

## Packets

A SNAPI packet Has the following structure:

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

...

## HTTPS (WSS) API

SNAPI does not inherently support HTTPS. You may use a WebSocket to proxy a SNAPI client service.
In no way should SNAPI be proxied over a plain-text WebSocket (ws://), it should be proxied through
a secure (encrypted) WebSocket (wss://).

Read more about WebSockets here:

-   <https://en.wikipedia.org/wiki/WebSocket>
-   <https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API>

## Security, clients, feedback & questions

Email <ari@ari.lt> for any questions or security concerns you have about the SNAPI format. I will be sure
to either update the format, answer your questions, or start a new version of SNAPI fixing the problems
pointed out.

You are also welcome to create new clients and either submit a pull request, or let me know through email.
Please do note that creating a client is an extremely complex task, and your client will be marked
as Beta until it has been tested by time and it is clear that the development of the client is going
well.

Any feedback is welcome, and remember - your contribution matters!

## Authors

-   Ari Archer \<<ari@ari.lt>\> \[<https://ari.lt/>\]

## Licensing

    "pDB version 1 (pDBv1) file format and specification" is licensed under the GNU General Public License version 3 or later (GPL-3.0-or-later).

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.
