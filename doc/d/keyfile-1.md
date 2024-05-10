# Keyfile -- version 1 (alpha)

**This is an alpha stage format, same as pDBv1 and SNAPI. Do not implement it or use it in production yet until the next stable release.**

This document defines the format of a pDB Keyfile file, which is used to store various keys and/or their parameters.

The purpose of this format is to define a format where keys may be stored in a non-raw format, adding a layer
of authentication, authenticity, and authorization to the access of them. This system highly depends on the strength
of your password, meaning you shall set a strong password - clients may force users to set a strong password to not
compromise the security of the Keyfile system.

This file has multiple passes of encryption, which is good enough for obscuring the keys stored inside, although it is
not recommended to share or spread your Keyfile publicly. It must be kept secret, and if publicly released, the
system shall be classified as highly compromised.

## File identifiers

-   File extension: `.pkf`
-   MIME type: `application/pkf`, `application/x-pkf`
-   Magic number: `pdKf` (`0x70 0x64 0x4b 0x66`, `0x70644b66`, `1885621094`)

## Format

| C type         | Name           | Description                                                                                                   |
| -------------- | -------------- | ------------------------------------------------------------------------------------------------------------- |
| `uint8_t[4]`   | `magic`        | The magic number of the file. Always a constant value.                                                        |
| `uint16_t`     | `version`      | The version of the Keyfile. A constant value per-version. (in the case of pKf1 case - `0x01`) (little endian) |
| `uint8_t`      | `locked`       | Is the Keyfile currently locked? See lock statuses below.                                                     |
| `uint8_t[64]`  | `sha3_512_sum` | The SHA3-512 hash of the whole database after the hash.                                                       |
| `uint8_t[512]` | `salt`         | Keyfile salt.                                                                                                 |
| `uint8_t[]`    | `keys`         | The keys and/or their parameters stored in the Keyfile. Dynamic section of encrypted chunks.                  |

A generic layout of everything would look like this:

    [magic][version][locked][sha3-512][salt] (header)
    [type][size][encrypted key]... (the keys)
    (Raw: [type][size][provision date][lifetime][salt][...]...)
    (For instance: [0x00][size][provision date][lifetime][salt][public key size][public key][IV][key][tag][secret key]...)

### Lock status

-   `0x00` - Unlocked.
-   `0x01` - Locking.
-   `0x02` - Locked.
-   `0x03` - Consult the database.
    -   Normal lock resolution process is executed on the database (including SNAPI resolution).
-   Anything else - Unknown (format error).

## Keys format

The keys are a dynamic section of encrypted chunks. Every block is dynamic and the keys don't have an infinite lifetime, a key may last up to 255 days. The format is as follows:

| C type          | Name   | Description                                            |
| --------------- | ------ | ------------------------------------------------------ |
| `uint8_t`       | `type` | The type of the key. (see types below)                 |
| `uint64_t`      | `size` | The size of the binary blob following. (little endian) |
| `uint8_t[size]` | `data` | The encrypted data of the key.                         |

The keys are in order, IDs should be assigned from ID 0, 0 being the key at the beginning of file.

The encryption of data is discussed below. After the blob was encrypted it may be appended to the Keyfile.

### Key types

This section describes the formats for differing key formats defined by the key section. All keys are encrypted and timestamped.
Keys always have these fields before the actual data:

| C type         | Name                  | Description                                                            |
| -------------- | --------------------- | ---------------------------------------------------------------------- |
| `uint64_t`     | `provision_timestamp` | The date of key creation in UNIX UTC time, in seconds. (little endian) |
| `uint8_t`      | `lifetime`            | Lifetime of the key in days, if zero - instant expiry.                 |
| `uint8_t[128]` | `salt`                | 1024-bit key salt.                                                     |

(Formula to check the expiration status: `(current_timestamp - provision_timestamp) > (lifetime * 24 * 60 * 60) `, where `current_timestamp` is the current (as time of accessing `provision_timestamp`) UTC UNIX time timestamp)

Followed by one of the following formats, based off the `type`:

#### 0x00 - RSA-4096 key pair

This is the format of an RSA-4096 public and secret key pair:

| C type             | Name      | Description                                                                                       |
| ------------------ | --------- | ------------------------------------------------------------------------------------------------- |
| `uint16_t`         | `pk_size` | Public key size. (little endian)                                                                  |
| `uint8_t[pk_size]` | `pk`      | Public key (DER format).                                                                          |
| `uint8_t[12]`      | `IV`      | Secret key Initialization Vector for AES256-GCM.                                                  |
| `uint8_t[32]`      | `key`     | Secret key encryption key for AES256-GCM.                                                         |
| `uint8_t[16]`      | `tag`     | Encrypted secret key tag for AES256-GCM.                                                          |
| `uint8_t[]`        | `sk`      | Secret key (DER format) encrypted using a single pass of AES256 in GCM mode using `IV` and `key`. |

Encryption of the secret key would look like this:

    bytes encrypt_sk(sk) {
        # Set format fields
        IV = random(12);
        key = random(32);

        AES256_GCM aes = AES256_GCM(iv=IV, key=key);

        sk = aes.encrypt(sk);

        # AES256-GCM tag is 16 bytes, sets the `tag` field
        tag = aes.tag;

        return sk;
    }

#### 0x01 - cryptographic salt

This is the format of a cryptographic salt:

| C type      | Name    | Description                                     |
| ----------- | ------- | ----------------------------------------------- |
| `uint8_t[]` | `value` | A cryptographically secure salt (random bytes). |

## Cryptography

Keyfile version 1 uses AES256 in GCM mode with the Argon2 key derivation function. In pseudocode, the cryptography of a single key would look like this:

    bytes encrypt_key(key, key_salt) {
        # `salt` comes from the format header
        bytes database_pasword_digest = argon2(password=database_pasword, salt=(salt + key_salt + psalt), length=256, ...);

        # n starts at 0 and ends at keyfile_encryption_passes (an option configured by the database)
        for n in repeat(keyfile_encryption_passes) {
            bytes s1 = random(32);
            bytes s2 = random(32);

            bytes IV = argon2(password=(stringify(n) + database_pasword), salt=(key_salt + database_pasword_digest + s1), length=12, ...);
            bytes key = argon2(password=(database_pasword + stringify(n)), salt=(s2 + database_pasword_digest + key_salt), length=32, ...);

            AES256_GCM aes = AES256_GCM(iv=IV, key=key);

            key = aes.encrypt(key);

            # AES256-GCM tag is 16 bytes
            key = s1 + s2 + aes.tag + key;
        }

        return key;
    }

In words:

-   Using Argon2, an initial 256-byte digest of the database password is derived, using `psalt` (configured by the database, at least 256 bytes), `key_salt`, and `salt` as salt
-   Now, a loop that will loop `keyfile_encryption_passes` times starts, storing the current iteration number in `n` (which starts at 0)
-   Two 32-byte cryptographically secure salts are generated called `s1` and `s2`
-   A 12-byte Initialization Vector (IV) is derived using Argon2, passing in the current iteration number and database password as the passphrase and `key_salt` along with database password digest and `s1` as the salt.
-   In a similar fashion, although shuffled, a 32-byte key is derived (see pseudocode).
-   The derived values are passed to AES256 in GCM mode, data is encrypted and reassigned.
-   The data is reassigned to `s1 + s2 + GCM tag + <data>`.
-   Process is repeated.

## Verification

-   The magic number of the file is correct. (basic corruption and file type check)
-   The version is supported by the target database. (support check)
-   The database is not currently locked. (access check, to prevent collisions)
-   The SHA3-512 sum of the database is correct. (integrity check)
-   All keys are decryptable and valid. (integrity, authentication, and authorization checks (because a password, correct tag, and correct ciphertext is required))

If any of the checks fail, you shall terminate the access to the database to prevent any damage or tampered with data.

## Authors

-   Ari Archer \<<ari@ari.lt>\> - Author and maintainer of Keyfile version 1

## Licensing

This document is licensed under AGPL-3.0-or-later, the author being Ari Archer \<<ari@ari.lt>\> as provided as a part of the Armour project.
