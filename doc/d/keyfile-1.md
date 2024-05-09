# Keyfile - version 1

**This is an alpha format. Do not implement it yet.**

This document defines the format of a pDB Keyfile file, which is used to store various keys. Keep this file safe
as if an attacker gets access to this file it can lead to a compromised database, keep this file as safe as your password.

## File identifiers

-   File extension: `.pkf` (or any other, shouldn't matter)
-   MIME type: `application/octet-stream`
-   Magic number: N/A

## Format

| C type         | Name           | Description                                                                                                 |
| -------------- | -------------- | ----------------------------------------------------------------------------------------------------------- |
| `uint8_t[64]`  | `sha3_512_sum` | The SHA3-512 hash of the whole database after the hash.                                                     |
| `uint8_t[32]`  | `_r`           | Garbage data for entropy purposes. 32 cryptographically secure bytes.                                       |
| `uint8_t[928]` | `ksalt`        | Salt of the Keyfile. Used for deriving keys in related to and protecting the Keyfile.                       |
| `uint8_t[512]` | `isalt`        | Initial salt attempt of the keyfile. Used for protection of the password in the initial encryption attempt. |
| `uint8_t*`     | `keys`         | The keys or their parameters stored in the Keyfile.                                                         |

## Keys format

Keys format is as follows:

| C type         | Name     | Description                                                                                          |
| -------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `uint8_t[512]` | `rsa_pk` | The RSA-4096 public key.                                                                             |
| `uint8_t[512]` | `rsa_sk` | The RSA-4096 secret key.                                                                             |
| `uint8_t[n]`   | `salt`   | The actual salt used for cryptography in the database. `n` is decided by the database configuration. |

All of these are concatenated in order (from top of the table to bottom) and encrypted using multiple passes of AES256-GCM like this:

## Cryptography

Keyfile version 1 uses multiple passes (configured by the database once again)
of AES256 in GCM mode with the Argon2 key derivation function.
In pseudocode, the cryptography passes would look like this:

    bytes database_pw_digest = Argon2(password=database_pw, ..., hash_len=224, salt=isalt);

    # n starts from 0

    for n in times(aes_crypto_passes + 3) {
        bytes s1 = random(32);
        bytes s2 = random(32);

        bytes key = Argon2(
            password=(database_pw + ksalt + stringify(n)),
            time_cost=time_cost,
            ...,
            hash_len=32,
            salt=(database_pw_digest + s1),
        )

        bytes iv = Argon2(
            password=(stringify(n) + ksalt + database_pw),
            time_cost=time_cost,
            ...,
            hash_len=12,
            salt=(s2 + database_pw_digest),
        )

        AESGCM aes = AESGCM(
            key=key,
            iv=iv,
        )

        keys = aes.encrypt(keys);

        # `aes.tag` is 16 bytes
        keys = s1 + s2 + keys + aes.tag;
    }

Bare in mind the randomness must be **cryptographically secure**, including the generation of random bytes (`random` function in pseudocode).
All Argon2 parameters (including `time_cost` come from the database configuration).

In other words:

-   The database password along with `isalt` is passed to Argon2, and a 224-byte digest is derived
-   The multiple encryption passes for for keys are repeated +3 configured
-   Two random 32-byte salts are generated for encryption: `s1` and `s2`
-   A key is derived by using Argon2 with configured parameters of the database, passing in the database password digest and the `s1` salt concatenated as the salt, and database password, Keyfile salt, and current iteration count (starting from zero) concatenated
-   In a similar, but modified fashion, the IV is derived (see pseudocode)
-   Then the IV and the key are passed to AES in GCM mode
-   `keys` is resigned to the concatenated result of `s1 + s2 + keys + GCM tag`
-   The process is repeated

## Authors

-   Ari Archer \<<ari@ari.lt>\> - Author and maintainer of Keyfile v1

## Licensing

This document is licensed under AGPL-3.0-or-later, the author being Ari Archer \<<ari@ari.lt>\> as provided as a part of the Armour project.
