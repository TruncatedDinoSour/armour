# Keyfile -- version 1 (alpha)

**This is an alpha stage format, same as pDBv1 and SNAPI. Do not implement it or use it in production yet until the next stable release.**

This document defines the format of a pDB Keyfile file, which is used to store various keys and/or their parameters.

The purpose of this format is to define a format where keys may be stored in a non-raw format, adding a layer
of authentication, authenticity, and authorization to the access of them. This system highly depends on the strength
of your password, meaning you shall set a strong password - clients may force users to set a strong password to not
compromise the security of the Keyfile system.

This file format has multiple passes of encryption with a single algorithm, which is good enough for obscuring the keys stored inside, although it is
not recommended to share or spread your Keyfile publicly. It must be kept secret, and if publicly released, the system shall be classified as highly compromised.

## File identifiers

-   File extension: `.pkf`
-   MIME type: `application/pkf`, `application/x-pkf`
-   Magic number: `pdKf` (`0x70 0x64 0x4b 0x66`, `0x70644b66`, `1885621094`)

## Format

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type         | Name           | Description                                                                                    |
| -------------- | -------------- | ---------------------------------------------------------------------------------------------- |
| `uint8_t[4]`   | `magic`        | The magic number of the file. Always a constant value.                                         |
| `uint16_t`     | `version`      | The version of the Keyfile. A constant value per-version. (in the case of pKfv1 case - `0x01`) |
| `uint8_t`      | `lock`         | Is the Keyfile currently locked/locking/...? See lock statuses below.                          |
| `uint8_t[64]`  | `sha3_512_sum` | The SHA3-512 hash of the whole database after the hash.                                        |
| `uint8_t[512]` | `salt`         | Keyfile salt.                                                                                  |
| `uint8_t[]`    | `keys`         | The keys and/or their parameters stored in the Keyfile. Dynamic section of encrypted chunks.   |

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

| C type          | Name   | Description                            |
| --------------- | ------ | -------------------------------------- |
| `uint8_t`       | `type` | The type of the key. (see types below) |
| `uint64_t`      | `size` | The size of the binary blob following. |
| `uint8_t[size]` | `data` | The encrypted data of the key.         |

The keys are in order, IDs should be assigned from ID 0, 0 being the key at the beginning of file.

The encryption of data is discussed below. After the blob was encrypted it may be appended to the Keyfile.

### Key types

This section describes the formats for differing key formats defined by the key section. All keys are encrypted and timestamped.
Keys always have these fields before the actual data:

(All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.)

| C type         | Name                  | Description                                            |
| -------------- | --------------------- | ------------------------------------------------------ |
| `uint64_t`     | `provision_timestamp` | The date of key creation in UNIX UTC time, in seconds. |
| `uint8_t`      | `lifetime`            | Lifetime of the key in days, if zero - instant expiry. |
| `uint8_t[128]` | `salt`                | 1024-bit key salt.                                     |

(Formula to check the expiration status: `(current_timestamp - provision_timestamp) > (lifetime * 24 * 60 * 60) `, where `current_timestamp` is the current (as time of accessing `provision_timestamp`) UTC UNIX time timestamp)

Followed by one of the following formats, based off the `type`:

#### 0x00 - RSA-4096 key pair

This is the format of an RSA-4096 public and secret key pair:

(All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.)

| C type             | Name      | Description                                                                 |
| ------------------ | --------- | --------------------------------------------------------------------------- |
| `uint16_t`         | `pk_size` | Public key size.                                                            |
| `uint8_t[pk_size]` | `pk`      | Public key (DER format).                                                    |
| `uint8_t[]`        | `sk`      | Secret key (DER format) encrypted using a single pass of ChaCha20-Poly1305. |

Encryption of the secret key would look like this:

    bytes encrypt_sk(sk) {
        bytes assoc = random(32);
        bytes nonce = random(12);

        bytes key = argon2(password=(database_pasword + nonce), salt=assoc, length=32, ... (parameters configured by database));

        ChaCha20Poly1305 chacha = ChaCha20Poly1305(key=key);

        # Encrypt the secret key
        bytes ciphertext = chacha.encrypt(data=sk, nonce=nonce, associated_data=assoc);

        return assoc + nonce + ciphertext;
    }

This pseudocode means:

-   Generate 32 bytes of associated data with the key.
-   Generate a 12-byte nonce for ChaCha20-Poly1305.
-   Derive a key using Argon2, password being the database password and the nonce concatenated and the salt being the associated data.
-   Pass in the key to ChaCha20-Poly1305.
-   Encrypt the secret key, passing in the nonce and the associated data
-   Concatenate the associated data, the nonce, and the ciphertext, and return it as the final ciphertext.

#### 0x01 - cryptographic salt

This is the format of a cryptographic salt:

| C type      | Name    | Description                                     |
| ----------- | ------- | ----------------------------------------------- |
| `uint8_t[]` | `value` | A cryptographically secure salt (random bytes). |

## Cryptography

Keyfile version 1 uses ChaCha20-Poly1305 with the Argon2 key derivation function. In pseudocode, the cryptography of a single key would look like this:

    bytes encrypt_key(key, key_salt) {
        # `salt` comes from the format header
        bytes database_pasword_digest = argon2(password=(database_pasword + psalt), salt=(salt + key_salt), length=256, ... (parameters configured by database));

        for _ in repeat(keyfile_crypto_passes) {
            bytes ks = random(32);

            bytes assoc = random(32);
            bytes nonce = random(12);

            bytes key = argon2(password=(database_pasword + assoc + nonce), salt=(ks + database_pasword_digest + key_salt), length=32, ...);

            ChaCha20Poly1305 chacha = ChaCha20Poly1305(key=key);

            key = chacha.encrypt(data=key, nonce=nonce, associated_data=assoc);
            key = ks + assoc + nonce + key;
        }

        return key;
    }

In other words:

-   Initially a 256-byte database password digest is derived using Argon2, passing in the database password and `psalt` (configured by the database) as the password, and the Keyfile salt and key salt as the salt.
-   A loop of `keyfile_crypto_passes` is started (configured by the database).
-   A 32-byte cryptographically secure salt is generated called `ks`.
-   32 bytes of associative data called `assoc` is generated to be later passed to ChaCha20-Poly1305.
-   A cryptographically secure 12-byte nonce is generated for ChaCha20-Poly1305.
-   32-byte key is derived using Argon2, passing in the following parameters (every sublist is concatenated in order):
    -   Password
        -   Database password.
        -   Associated data.
        -   `nonce`
    -   Salt
        -   `ks`
        -   Database password digest.
        -   `key_salt`
    -   Rest of the arguments are configured by the database.
-   The key is passed to ChaCha20-Poly1305.
-   Key is encrypted using ChaCha20-Poly1305 passing in the key, the nonce, and the associated data.
-   Key is reassigned to a concatenation of `ks`, associated data, the nonce, and the ciphertext.
-   Process is repeated.

## Verification

-   The magic number of the file is correct. (basic corruption and file type check)
-   The version is supported by the target database. (support check)
-   The database is not currently locked. (access check, to prevent collisions)
-   The SHA3-512 sum of the database is correct. (integrity check)
-   All keys are decryptable and valid. (integrity, authentication, and authorization checks (because a password, correct nonce and associated data, and correct ciphertext is required))

If any of the checks fail, you shall terminate the access to the database to prevent any damage or tampered with data.

## pKfv1: Authors

-   Ari Archer \<<ari@ari.lt>\> \[<https://ari.lt/>\]

## Licensing

    "pDB Keyfile version 1 (pKfv1) file format and specification" is licensed under the GNU General Public License version 3 or later (GPL-3.0-or-later).

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.
