# Standard Network Application Programming Interface (SNAPI) -- version 0 (alpha)

This document describes the standard network API (SNAPI) for pDBv1+.
SNAPI is used for interacting with pDB and Keyfile structures over a network interface.

**Last modified**: 2024-05-12

## Introduction

SNAPI (Standard Network Application Programming Interface) is a protocol extension on top of TCP (RFC 9293)
to use, query, and manage the pDB and Keyfile file formats over a TCP connection.

## Cryptography

SNAPIv0 uses ECDH (Elliptic Curve Diffie-Hellman) key exchange and ChaCha20-Poly1305 for the encryption part
of the protocol. A SNAPI handshake would look like this:

1. Client connects
2. Server generates its ECDH keys on the SECP521R1 curve.
3. Client generates its ECDH keys on the SECP521R1 curve.
4. Client sends its client ID. Server saves it.
5. Server sends its server ID. Client saves it.
6. Client sends its 158-byte DER-encoded ECDH-SECP521R1 public key to the Server.
7. Server sends its 158-byte DER-encoded ECDH-SECP521R1 public key to the Client.
8. We concatenate the client's and server's public ECDH keys together, and pass the blob to SHA3-256. Output digest will be our 32-byte salt.
9. We concatenate the Client ID, string `" <=> "` (without quotes, but with spaces), and the server ID, giving us the info data.
10. Using ECDH, finish the key exchange, giving us key material.
11. Using HKDF with SHA3-512, we generate a 64-byte key, passing in the salt, info, and previously mentioned key material.
12. Using same algorithms, we generate a 48-byte nonce, modifying the salt by using a SHA3-256 hash of the salt and previously derived key concatenated.
13. Once again, using HKDF, we derive 32 bytes of associated data, passing in SHA3-256 digest of nonce, key, and salt concatenated together as the salt.
14. While steps 8-13 are happening on the server, client does the same.
15. When encrypting we generates 32 cryptographically secure random bytes ("extra data"), pad the data to a block size of 64 bytes and re-derive all parameters of ChaCha20-Poly1305 using BLAKE2 hashing functions:
    - Key: 32-byte BLAKE2s digest of derived key concatenated with extra sent-over data.
    - Nonce: 12-byte BLAKE2s digest of derived nonce concatenated with the extra sent-over data.
    - Associated data: 52-byte BLAKE2b digest of associated data and extra data concatenated together.

An example implementation of this handshake could look like this:

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
PORT: int = 3838


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

    recv_pt: bytes = ChaCha20Poly1305(
        hashlib.blake2s(key + ex, digest_size=32).digest()
    ).decrypt(
        hashlib.blake2s(nonce + ex, digest_size=12).digest(),
        ct,
        hashlib.blake2b(assoc + ex, digest_size=52).digest(),
    )

    recv_pt = recv_pt[: -(recv_pt[-1] + 1)]

    print(
        "Decrypted:",
        recv_pt,
    )

    # Send ciphered data.

    extra: bytes = os.urandom(32)

    sending_pt: bytes = b"Hello, Client!"
    padding_size: int = 63 - (len(sending_pt) % 64)

    if padding_size > 0:
        sending_pt += os.urandom(padding_size)

    sending_pt += bytes([padding_size])

    conn.sendall(
        extra
        + ChaCha20Poly1305(
            hashlib.blake2s(key + extra, digest_size=32).digest()
        ).encrypt(
            hashlib.blake2s(nonce + extra, digest_size=12).digest(),
            sending_pt,
            hashlib.blake2b(assoc + extra, digest_size=52).digest(),
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

You could implement a client in a similar fashion.
Note that this is just the protocol handshake, not the protocol itself.

## Supported pDB versions

-   pDBv1 (password database version 1).

## Packets

This section describes how different packets are constructed.

There are two different types of packets:

-   Request packets: The packet type the Client sends to the Server.
-   Response packets: The packet type the Server sends to the Client.

More about these types below.

### Request packets

A request packet is a packet that the _Client_ sends to the _Server_.

An encrypted Request packet looks like this:

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type          | Name           | Description                                               |
| --------------- | -------------- | --------------------------------------------------------- |
| `uint8_t[64]`   | `blake2b_hash` | The BLAKE2b hash of the whole packet, including the size. |
| `uint32_t`      | `size`         | Size of the cypher-text.                                  |
| `uint8_t[size]` | `ct`           | The cypher-text of the packet.                            |

And the `ct` field includes the following data:

| C type       | Name        | Description                                                                              |
| ------------ | ----------- | ---------------------------------------------------------------------------------------- |
| `uint8_t`    | `command`   | The requested command. More about them below.                                            |
| `uint8_t[8]` | `packet_id` | The unique packet ID of the command. Preferably 8 cryptographically secure random bytes. |
| `uint8_t`    | `input`     | The input identifier of the command.                                                     |
| `uint32_t`   | `size`      | The size of the input value.                                                             |
| `uint8_t`    | `data`      | The input data.                                                                          |
| ...          | ...         | `input`, `size`, and `data` repeating for all inputs of the command. `input` may repeat. |

`packet_id` is an identifier which the client should generate and remember, as the response packet will include this
packet ID to identify the response. As even though the output will come in order, it may not come one after another.
A packet ID may be reused after the command ran and finished.

You may send multiple commands.

### Response packets

Response packets are responses which the server sends to the client in response to Request packets.
They are padded to a block size of 64 bytes and have the following structure:

| C type          | Name        | Description                                                                        |
| --------------- | ----------- | ---------------------------------------------------------------------------------- |
| `uint8_t[8]`    | `packet_id` | The packet ID sent over by the Request packet.                                     |
| `uint8_t`       | `status`    | The status of the packet.                                                          |
| `uint32_t`      | `size`      | The size of the `response`.                                                        |
| `uint8_t[size]` | `response`  | The cypher-text of the packet (part of cyphered plain-text following a structure). |

The plain-text is padded as mentioned using this algorithm:

        data = blake2b(data, size=64) + data;

        number padding_size = 63 - (len(data) % 64);

        if (padding_size > 0) {
            data = data + random(padding_size);
        }

        data = data + as_uint8_le(padding_size);

In other words:

-   The plain-text is hashed using BLAKE2b, and the 64-byte digest is prepended to the data.
-   Padding size is calculated using formula `63 - (len(data) % 64)`, reserving the last byte for the padding size.
-   If the padding size is more than zero, we generate that many cryptographically secure random bytes and append them to the data.
-   Then the padding size is appended as a `uint8_t`.

Read more about statuses below.

The `response` field has this structure:

| C type     | Name     | Description                                                                                |
| ---------- | -------- | ------------------------------------------------------------------------------------------ |
| `uint8_t`  | `output` | The response identifier.                                                                   |
| `uint32_t` | `size`   | The size of the output value.                                                              |
| `uint8_t`  | `data`   | The output data.                                                                           |
| ...        | ...      | `output`, `size`, and `data` repeating for all inputs of the command. `output` may repeat. |

### Commands

This subsection lists all possible commands, common names, what they mean, after what they are usually ran, inputs, outputs, and common errors, and statues.

The command codes are separated into 4 64-code ranges:

-   0x00: Initialization: Initialization call, before it no other command can be called.
-   0x01 to 0x3f - Account and database (not its data) management: Manage your account, create databases, delete databases, administration tasks.
-   0x40 to 0x7f - Data management: Query, insert, update, delete data.
-   0x80 to 0xbf - Reserved.
-   0xc0 to 0xff - Reserved.

#### Abstract

Note that the server may respond with an error at any point.

| Command | Name         | Description                                    | Authenticated  | After           | Inputs, Optional inputs       | Outputs     | Common errors (not only ones)                            | Common statuses           |
| ------- | ------------ | ---------------------------------------------- | -------------- | --------------- | ----------------------------- | ----------- | -------------------------------------------------------- | ------------------------- |
| `0x00`  | `INIT`       | Initialization call. Called before everything. | No.            | None.           | At least `v`, all arguments.  | `c`         | `V_VERSION`                                              | `S_ONLY`                  |
| -       | -            | -                                              |                | -               | -                             | -           | -                                                        | -                         |
| `0x01`  | `A_AUTH`     | Authenticate with SNAPI.                       | Authenticator. |                 | `c`, `u`, `p`, `t`?, `s`?     | `t`         | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`                    | `S_ONLY`                  |
| `0x02`  | `A_OPEN`     | Open a pDB database session.                   | Yes.           | `A_AUTH`        | `c`, `a`, `n`, `p`?           | `s`         | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`, `C_NOTFOUND`      | `S_ONLY`                  |
| `0x03`  | `A_CLOSE`    | Close a pDB database session.                  | Yes.           | `A_OPEN`        | `c`, `a`, `s`                 |             | `C_ACCESS`, `C_UNFULFILLED`, `C_NOTFOUND`                | `S_ONLY`                  |
| `0x04`  | `A_BACKUP`   | Backup a database.                             | Yes.           | `A_OPEN`        | `c`, `a`, `s`, `p`?           | `i`, `t`    | `C_ACCESS`, `C_UNFULFILLED`, `C_RESOURCES`, `C_NOTFOUND` | `S_ONLY`                  |
| `0x05`  | `A_BACKUPS`  | List all backups.                              | Yes.           |                 | `c`, `a`, `n`                 | `i`, `t`... | `C_ACCESS`, `C_UNFULFILLED`, `C_NOTFOUND`                | `I_EXECUTING`, `I_FINISH` |
| `0x06`  | `A_ROLLBACK` | Rollback a database to a backup.               | Yes.           |                 | `c`, `a`, `n`, `i`, `p`? `t`? | `t`         | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`, `C_NOTFOUND`      | `I_EXECUTING`, `I_FINISH` |
| `0x07`  | `A_BDISCARD` | Discard a backup.                              | Yes.           |                 | `c`, `a`, `n`, `i`, `p`? `t`? | `i`, `t`    | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`, `C_NOTFOUND`      | `I_EXECUTING`, `I_FINISH` |
| `0x08`  | `A_TOTP`     | Set up TOTP.                                   | Yes.           | `A_AUTH`        | `c`, `a`, `s`?, `t`?          | `s`         | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`                    | `S_ONLY`                  |
| `0x09`  | `A_UTOTP`    | Remove TOTP.                                   | Yes.           | `A_AUTH`        | `c`, `a`, `t`, `s`?           |             | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`, `C_NOTFOUND`      | `S_ONLY`                  |
| `0x0a`  | `A_SECRET`   | Set up secret.                                 | Yes.           | `A_AUTH`        | `c`, `a`, `s`?, `t`?          | `s`         | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`                    | `S_ONLY`                  |
| `0x0b`  | `A_USECRET`  | Remove secret.                                 | Yes.           | `A_AUTH`        | `c`, `a`, `s`, `t`?           |             | `C_ACCESS`, `C_AUTH`, `C_UNFULFILLED`                    | `S_ONLY`                  |
| -       | -            | -                                              |                | -               | -                             | -           | -                                                        | -                         |
| `0x40`  | `D_QUERY`    | Query data from the database.                  | Yes.           | `A_OPEN`        | `c`, `a`, `q`                 | `e`...      | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `I_EXECUTING`, `I_FINISH` |
| `0x41`  | `D_INSERT`   | Insert data into the database.                 | Yes.           | `A_OPEN`        | `c`, `a`, `e`...              | `g`...      | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `S_ONLY`                  |
| `0x42`  | `D_UPDATE`   | Update data in the database.                   | Yes.           | `A_OPEN`        | `c`, `a`, `q`, `e`            | `g`...      | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `I_EXECUTING`, `I_FINISH` |
| `0x43`  | `D_DELETE`   | Delete data in the database.                   | Yes.           | `A_OPEN`        | `c`, `a`, `q`                 | `g`...      | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `I_EXECUTING`, `I_FINISH` |
| `0x44`  | `D_COMMIT`   | Commit in-memory changes to the database.      | Yes.           | `A_OPEN`, `D_*` | `c`, `a`                      | `t`, `b`    | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `I_EXECUTING`, `I_FINISH` |
| `0x45`  | `D_DISCARD`  | Discard in-memory changes.                     | Yes.           | `A_OPEN`, `D_*` | `c`, `a`                      | `t`, `c`    | `C_ACCESS`, `C_UNFULFILLED`, `C_ERROR`                   | `I_EXECUTING`, `I_FINISH` |

#### In-depth

This section describes every command in more detail.

-   0x00: INIT
    -   `v` in the arguments is required for the SNAPI version. In SNAPIv0 case - `v=0`.
    -   The output of this command is the connection ID. You will have to pass this to every command.
-   0x01: A_AUTH
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `u`: The username of the user.
        -   `p`: The password of the user.
        -   `t`?: Optionally, if TOTP is enabled on the user account, TOTP code.
        -   `s`?: Optionally, if Secret is enabled on the user account, the secret bytes.
    -   Outputs
        -   `s`: The access token secret.
            -   **Note**: `s` is not directly used, instead it is used to derive `a`. `a` is derived using `blake2b((c + s + utcnow("YYYY-MM-DD HH:MM")), size=64)`.
-   0x02: A_OPEN
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `n`: The name of the database.
        -   `p`?: Optional database password, if the server requires it.
    -   Outputs
        -   `s`: The database Session ID, representing authorized access to the database and the database name.
            -   There's no specific format for this.
-   0x03: A_CLOSE
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `s`: The database Session ID.
    -   Outputs
        -   None.
-   0x04: A_BACKUP
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `s`: The database Session ID.
    -   Outputs
        -   `i`: The backup ID.
        -   `t`: The backup time stamp (UNIX UTC time as `uint64_t`).
-   0x05: A_BACKUPS
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `n`: The name of the database.
    -   Outputs
        -   `i`, `t`: The backup IDs and their timestamps one after another.
-   0x06: A_ROLLBACK
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `n`: The name of the database.
        -   `i`: The backup ID.
        -   `p`?: The password of the database if the server requires it.
        -   `t`?: The TOTP code of the user if the server requires it.
    -   Outputs
        -   `t`: The time stamp of recovery.
-   0x07: A_BDISCARD
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `n`: The name of the database.
        -   `i`: The backup ID.
        -   `p`?: The password of the database if the server requires it.
        -   `t`?: The TOTP code of the user if the server requires it.
    -   Outputs
        -   `i`: The backup ID.
        -   `t`: The time stamp of the backup discarded.
-   0x08: A_TOTP
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `s`?: The account secret if the server requires it.
        -   `t`?: The TOTP code of the user if the server requires it.
    -   Outputs
        -   `s`: The TOTP secret. Assume defaults for other parameters.
-   0x09: A_UTOTP
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `t`: The TOTP code of the user.
        -   `s`?: The account secret if the server requires it.
    -   Outputs
        -   None.
-   0x0a: A_SECRET
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `s`?: The account secret if the server requires it.
        -   `t`?: The TOTP code of the user if the server requires it.
    -   Outputs
        -   `s`: The secret bytes of the account.
-   0x0b: A_USECRET
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `s`: The account secret.
        -   `t`?: The TOTP code of the user if the server requires it.
    -   Outputs
        -   None.
-   0x40: D_QUERY
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `q`: The query object to run on the database. (discussed below)
    -   Outputs
        -   `e`: Resulting Simple entries.
-   0x41: D_INSERT
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `e`...: The Simple entries to insert.
    -   Outputs
        -   `g`...: The group IDs inserted in order of `e` inputs.
-   0x42: D_UPDATE
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `q`: The query object to run on the database. (discussed below)
        -   `e`: The Simple entries to update the entries with.
    -   Outputs
        -   `g`...: The group IDs affected in order of `e` inputs.
-   0x42: D_DELETE
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
        -   `q`: The query object to run on the database. (discussed below)
    -   Outputs
        -   `g`...: The group IDs affected in order of `e` inputs.
-   0x43: D_COMMIT
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
    -   Outputs
        -   `t`: Time stamp of commit.
        -   `b`: Bytes written count as a little-endian `uint64_t`.
-   0x43: D_DISCARD
    -   Inputs
        -   `c`: The Connection ID returned by INIT.
        -   `a`: Temporary access token derived from `s`.
    -   Outputs
        -   `t`: Time stamp of discard.
        -   `c`: Changes count discarded as a little-endian `uint64_t`.

### Query objects

Query objects are interpreted at runtime queries that can filter through:

-   Group IDs.
-   Plain-text fields.
-   Encrypted fields.

They are reverse-polish-notation binary blobs, but Clients may choose to use a high-level reverse-polish-notation language called SOQL (SNAPI Objects Query Language)
to query for objects. SOQL syntax is defined below.

Before every query the stack includes the Group ID, `data group_id`.

The stack can have up to 64 elements, if there will be more - the interpreter will stop the Query.

Query objects have the following binary operations:

| Opcode (`uint8_t`) | Keyword         | Stack                          | Description                                                                                                                                                                                                                |
| ------------------ | --------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0x00`             | -               | `uint8_t ...`, `uint16_t size` | Top of the stack includes the data size, and `size` elements on the stack are the data. The operation pops `size` elements off the stack starting from the bottom (h e l l o => h (bottom) e l l o) and joins it into one. |
| `0x01`             | `POP`           | ...                            | Remove the top element of the stack.                                                                                                                                                                                       |
| `0x02`             | `FIELD`         | `uint8_t a`                    | Push a field onto the stack.                                                                                                                                                                                               |
| `0x03`             | `SWAP`          | `data a, b`                    | Swap a and b.                                                                                                                                                                                                              |
| `0x04`             | `EFIELD`        | `data a, b`                    | Parse encrypted field `b` as an entry and push field `a` from it.                                                                                                                                                          |
| `0x05`             | `RSA4096`       | `data d`                       | Decrypt RSA-4096 encrypted data.                                                                                                                                                                                           |
| `0x06`             | `AES256`        | `data d`                       | Decrypt AES-256 encrypted data.                                                                                                                                                                                            |
| `0x07`             | `CHACHA20`      | `data d`                       | Decrypt ChaCha20-Poly1305 encrypted data.                                                                                                                                                                                  |
| `0x08`             | `THREEFISH1024` | `data d`                       | Decrypt Threefish-1024 encrypted data.                                                                                                                                                                                     |
| `0x09`             | `RC4`           | `data d`                       | Decrypt RC4 encrypted data.                                                                                                                                                                                                |
| `0x0a`             | `ZSTD`          | `data d`                       | Decompress data using ZSTD.                                                                                                                                                                                                |
| `0x0b`             | `STDE`          | `data d`                       | Decrypt data using the standard pDB cryptography pipeline.                                                                                                                                                                 |
| `0x0c`             | `NOT`           | `data a`                       | Push false if the top element on the stack is truthy, else true.                                                                                                                                                           |
| `0x0d`             | `AND`           | `data a, b`                    | Push true onto the stack if both a and b are truthy, else false.                                                                                                                                                           |
| `0x0e`             | `OR`            | `data a, b`                    | Push true onto the stack if either a or b are truthy, else false.                                                                                                                                                          |
| `0x0f`             | `FALSE`         |                                | False.                                                                                                                                                                                                                     |
| `0x10`             | `TRUE`          |                                | True.                                                                                                                                                                                                                      |
| `0x11`             | `CONDITION`     | `data d`                       | Only run the rest of the query if the top of the stack is truthy.                                                                                                                                                          |
| `0x12`             | `EQUALS`        | `data a, b`                    | Checks if both a and b are equal.                                                                                                                                                                                          |
| `0x13`             | `SUBSTRING`     | `data a, b`                    | Check if top of stack is a substring of second-top-most element.                                                                                                                                                           |
| `0x14`             | `STARTSWITH`    | `data a, b`                    | Checks if `a` starts with `b`.                                                                                                                                                                                             |
| `0x15`             | `ENDSWITH`      | `data a, b`                    | Checks if `a` ends with `b`.                                                                                                                                                                                               |
| `0x16`             | `TOLOWER`       | `data a`                       | Convert the topmost element to lowercase.                                                                                                                                                                                  |

Comments in SOQL are in `(...)` (parentheses)

For example an SQL query like:

```sql
SELECT * FROM <...> WHERE group_id='hello' AND e_n=RC4('Meow'); -- Can't do some stuff with SQL like field decryption.
```

In SOQL would look like this:

```sql
"hello" EQUALS CONDITION (stops parsing if the Group ID isn't "hello")
"n" "e" EFIELD "Meow" EQUALS (now we check if the field `n` of encrypted entry `e` matches "Meow")
```

Basically:

-   Compare the Group ID with `"hello"`.
-   If it doesn't equal, stop querying.
-   Get the field `n` of entry `e` and compare it to "Meow".
-   Interpreter will check the top-most element on the stack and decide if it's okay.

This would parse `e` as an entry and return the `n` field from it.

The Query object would be similar, just represented in op codes:

    hello 0x05 0x00 0x12 0x11 0x04
    n 0x01 0x00 e 0x01 0x00 0x04 Meow 0x04 0x00 0x12

True packet:

    0x68 0x65 0x6c 0x6c 0x6f 0x05 0x00 0x12 0x11 0x04
    0x6e 0x01 0x00 0x65 0x01 0x00 0x04 0x4d 0x65 0x6f 0x77 0x04 0x00 0x12

It's just opcodes and data as hex (`b'hello\x05\x00\x12\x11\x04n\x01\x00e\x01\x00\x04Meow\x04\x00\x12'`).

A query to select all elements would be as simple as

```sql
TRUE
```

Or, in Opcodes:

    0x10

### Statuses

This subsection lists all possible statuses of the Response packet.

The status codes are separated into 4 64-code ranges:

-   0x00 to 0x3f - Information: The request was received, continuing process.
-   0x40 to 0x7f - Success: The request was successfully received, understood, and accepted.
-   0x80 to 0xbf - Client error: The request contains bad syntax or cannot be fulfilled. See the packet's plain-text for more details.
-   0xc0 to 0xff - Server error: The server failed to fulfil an apparently valid request. See the packet's plain-text for more details.

| Status | Name            | Fatal | Content                                                    | Description                                                                                          |
| ------ | --------------- | ----- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `0x00` | `I_EXECUTING`   |       | Data so far.                                               | Executing: The command is executing.                                                                 |
| `0x01` | `I_FINISH`      |       | Final data.                                                | Finished: The command has finished executing.                                                        |
| `0x02` | `I_MSG`         |       | Human-readable message.                                    | Message: Message to the client.                                                                      |
| -      | -               |       |                                                            | -                                                                                                    |
| `0x40` | `S_ONLY`        |       | Final data.                                                | Only response: Do not expect any other responses. Similar to `I_EXECUTING` and `I_FINISH` afterwards |
| -      | -               |       |                                                            | -                                                                                                    |
| `0x80` | `C_ERROR`       | No.   | Human-readable message.                                    | Bad request: Badly structured packet or query.                                                       |
| `0x81` | `C_CRYPTO`      | Yes.  | Human-readable message.                                    | Bad encryption: Client badly encrypted the packet.                                                   |
| `0x82` | `C_ACCESS`      | Yes.  | Human-readable message.                                    | Access denied: User is not allowed to use this resource.                                             |
| `0x83` | `C_AUTH`        | No.   | Human-readable message.                                    | Unauthorized: Authentication error.                                                                  |
| `0x84` | `C_UNFULFILLED` | No.   | Required fields separated by commas.                       | Unfulfilled request: Not all required fields supplied.                                               |
| `0x85` | `C_RESOURCES`   | No.   | Human-readable message.                                    | Resources exhausted: Resources for this account exhausted.                                           |
| `0x86` | `C_NOTFOUND`    | No.   | Human-readable message.                                    | Resource not found: Requested resource was not found.                                                |
| -      | -               |       |                                                            | -                                                                                                    |
| `0xc0` | `V_INTERNAL`    | Yes.  | Human-readable message.                                    | Internal server error: The server ran into an unexpected fault.                                      |
| `0xc1` | `V_VERSION`     | Yes.  | Versions of SNAPI the server supports separated by commas. | Unsupported SNAPI version: The server does not support the SNAPI version.                            |

Fatal errors are errors that instantly close the connection.

## Performance and security

The protocol works on pDB, so it's not fast as a whole entity. Although, as a protocol, it uses ChaCha20-Poly1305
encryption algorithm and BLAKE2-family hashing algorithms, meaning it is pretty fast and efficient.

Security-wise, it is a pretty secure protocol, although may be a bit tricky to implement due to requirements of
SOQL and cryptographic measures.

## HTTPS (WSS) API

SNAPI does not inherently support HTTPS. You may use a WebSocket to proxy a SNAPI client service.
In no way should SNAPI be proxied over a plain-text WebSocket (ws://), it should be proxied through
a secure (encrypted) WebSocket (wss://).

Read more about WebSockets here:

-   <https://en.wikipedia.org/wiki/WebSocket> <https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API>

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

    "Standard Network Application Programming Interface version 0 (SNAPIv0) format and specification" is licensed under the GNU General Public License version 3 or later (GPL-3.0-or-later).

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.
