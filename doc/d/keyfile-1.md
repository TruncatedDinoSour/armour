# Keyfile - version 1 (alpha)

**This is an alpha stage format, same as pDBv1 and SNAPI. Do not implement it or use it in production yet until the next stable release.**

This document defines the format of a pDB Keyfile file, which is used to store various keys and/or their parameters.

The purpose of this format is to define a format where keys may be stored in a non-raw format, adding a layer
of authentication, authenticity, and authorization to the access of them. This system highly depends on the strength
of your password, meaning you shall set a strong password - clients may force users to set a strong password to not
compromise the security of the whole system.

This file has a single pass of encryption, which is good enough for obscuring the keys stored inside, although it is
not recommended to share or spread your Keyfile publicly. It must be kept secret, and if publicly released, the
system shall be classified as highly compromised.

## File identifiers

-   File extension: `.pkf`
-   MIME type: `application/pkf`, `application/x-pkf`
-   Magic number: `pKf<version>` (`0x70 0x4b 0x66 0x<version>`)

## Format

| C type         | Name           | Description                                                                                         |
| -------------- | -------------- | --------------------------------------------------------------------------------------------------- |
| `uint8_t[4]`   | `magic`        | The magic number of the file, including the version. Always a constant value: `0x70 0x4b 0x66 0x01` |
| `uint8_t[64]`  | `sha3_512_sum` | The SHA3-512 hash of the whole database after the hash.                                             |
| `uint8_t[956]` | `ksalt`        | Salt of the Keyfile. Used for deriving keys in related to and protecting the Keyfile.               |
| `uint8_t[512]` | `isalt`        | Initial salt, used once in an encryption function.                                                  |
| `uint8_t*`     | `keys`         | The keys and/or their parameters stored in the Keyfile. Encrypted section.                          |

## Keys format

Keys format is as follows:

| C type                 | Name             | Description                                                                                          |
| ---------------------- | ---------------- | ---------------------------------------------------------------------------------------------------- |
| `uint8_t[n]`           | `salt`           | The actual salt used for cryptography in the database. `n` is decided by the database configuration. |
| `uint16_t`             | `rsa_pk_size`    | The size of `rsa_pk`. (little endian)                                                                |
| `uint8_t[rsa_pk_size]` | `rsa_pk`         | The RSA-4096 public key as PEM.                                                                      |
| `uint8_t[512]`         | `rsa_sk_pw_salt` | The RSA-4096 secret key passphrase salt.                                                             |
| `uint16_t`             | `rsa_sk_size`    | The size of `rsa_sk`. (little endian)                                                                |
| `uint8_t[rsa_sk_size]` | `rsa_sk`         | The RSA-4096 secret key as encrypted PEM.                                                            |

All of these are concatenated in order (from top of the table to bottom) and encrypted using AES256 in GCM mode like this:

## Cryptography

Keyfile version 1 uses AES256 in GCM mode with the Argon2 key derivation function. In pseudocode, the cryptography would look like this:

    bytes database_pw_digest = Argon2(password=database_pw, ..., hash_len=256, salt=isalt);

    bytes s1 = random(32);
    bytes s2 = random(32);

    # 32 bytes key

    bytes key = Argon2(
        password=(database_pw + ksalt),
        time_cost=time_cost,
        ...,
        hash_len=32,
        salt=(database_pw_digest + s1),
    )

    # 12 bytes IV

    bytes iv = Argon2(
        password=(ksalt + database_pw),
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

    keys = s1 + s2 + aes.tag + keys;

Bare in mind the randomness must be **cryptographically secure**, including the generation of random bytes (`random` function in pseudocode).
All Argon2 parameters (including `time_cost` come from the database configuration).

In other words the single-pass encryption algorithm would be:

-   Generate a 256-byte database password digest using the `isalt` as the salt
-   Generate two 32-byte salts: `s1` and `s2`
-   Use Argon2 to derive a 32-byte key for AES256 in GCM mode, passing in database password and `ksalt` concatenated and passing in `database_pw_digest + s1` as the salt
-   In a similar fashion, Initialization Vector (IV) is derived
-   AES in GCM mode encrypts the `keys`
-   `s1`, `s2`, AES GCM tag, and the ciphertext are concatenated, and the single pass of AES is done

## RSA key encryption

Instead of storing the private RSA key directly in the file, it is stored as encrypted PEM:

    # Set the rsa_sk_pw_salt in the format

    rsa_sk_pw_salt = random(512);

    bytes database_pw_digest = Argon2(password=database_pw, ..., hash_len=256, salt=(ksalt + isalt));

    bytes key = Argon2(
        password=(rsa_sk_pw_salt + database_pw),
        time_cost=time_cost,
        ...,
        hash_len=256,
        salt=database_pw_digest,
    )

    rsa_pk = export_as_pem(key=public_rsa_key);
    rsa_sk = export_as_encryped_pem(key=secret_rsa_key, password=key);

The algorithm is simple:

-   Generate a cryptographically secure 512-byte RSA secret key salt
-   Derive a 256-byte database password digest from the password database and `ksalt + isalt` concatenated
-   Using Argon2, derive a 256-byte (2048-bit) passphrase for encrypting the private RSA key
-   Export the public RSA key as PEM
-   Export the private RSA key as encrypted PEM, using the derived key as the password

## Verification

-   Identify the file by the magic number
-   Verify the hash of the Keyfile
-   Decryption steps should succeed, including the GCM authentication checks
-   If any of the checks fail, you shall terminate the access to the database to prevent any damage or tampered with data

## Authors

-   Ari Archer \<<ari@ari.lt>\> - Author and maintainer of Keyfile v1

## Licensing

This document is licensed under AGPL-3.0-or-later, the author being Ari Archer \<<ari@ari.lt>\> as provided as a part of the Armour project.
