# Keyfile -- version 0 (alpha)

**This is an alpha stage format, same as pDBv1 and SNAPI. Do not implement it or use it in production yet until the next stable release.**

This document defines the format of a pDB Keyfile file version 0 (pKfv0), which is used to store various keys, their parameters,
and public encryption parameters.

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

| C type         | Name                                 | Description                                                                                                                |
| -------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `uint8_t[4]`   | `magic`                              | The magic number of the file. Always a constant value.                                                                     |
| `uint16_t`     | `version`                            | The version of the Keyfile. A constant value per-version. (in the case of pKfv0 case - `0x00`)                             |
| `uint8_t`      | `lock`                               | Is the Keyfile currently locked/locking/...? See lock statuses below. (support for concurrency)                            |
| `uint8_t[512]` | `salt`                               | The cryptographically secure Keyfile salt.                                                                                 |
| `uint16_t`     | `db_AES_crypto_passes`               | When using AES256 cryptography in GCM (Galois/Counter) mode _in the database_, how many times should the algorithm me ran? |
| `uint16_t`     | `db_ChaCha20_Poly1305_crypto_passes` | When using ChaCha20-Poly1305 cryptography _in the database_, how many times should the algorithm me ran?                   |
| `uint8_t[64]`  | `db_pepper`                          | 512 bits of cryptographically secure information which are always constant. Used for peppering of data _in the database_.  |
| `uint8_t[64]`  | `sha3_512_sum`                       | The SHA3-512 hash of the whole database after the hash.                                                                    |
| `uint8_t[]`    | `keys`                               | The keys and/or their parameters stored in the Keyfile. Dynamic section of encrypted chunks.                               |

A generic layout of everything would look like this:

    [magic][0x00][locked][sha3-512][salt] (header)
    [type][size][encrypted key]... (the keys)
    (Raw: [type][size][provision date][lifetime][salt][...]...)
    (For instance: [0x00][size][provision date][lifetime][salt][public key size][public key][IV][key][tag][secret key]...)

Please note that Keyfile depends on pDB database for these parameters:

-   `Argon2_type`
-   `Argon2_time_cost`
-   `Argon2_memory_cost`
-   `psalt`

While the database depends on all parameters with the `db_` prefix, so:

-   `db_AES_crypto_passes`
-   `db_ChaCha20_Poly1305_crypto_passes`
-   `db_pepper`

Do not be confused when you see those parameters in this document, assume they come from the pDB database.

### Lock status

-   `0x00`: Unlocked.
-   `0x01`: Locking.
-   `0x02`: Locked.
-   `0x03`: Releasing.
-   `0x04`: Disabled. Consult the database. (Forever locked, lock handled by a client service)
    -   Normal lock resolution process is executed on the database (including SNAPI resolution).
-   Anything else: Invalid.

## Keys format

The keys are a dynamic section of encrypted chunks. Every block is dynamic and the keys do not have an infinite lifetime, a key may last up to 255 days. The format is as follows:

| C type          | Name   | Description                            |
| --------------- | ------ | -------------------------------------- |
| `uint8_t`       | `type` | The type of the key. (see types below) |
| `uint32_t`      | `size` | The size of the binary blob following. |
| `uint8_t[size]` | `data` | The encrypted data of the key.         |

The keys are in order, IDs should be assigned from ID 0, 0 being the key at the beginning of file, IDs are of type `uint64_t`,
although not stored, so can be pretty much any type, it is just very unrealistic that there will ever be more than 18446744073709551615
keys in the database, or 3074457345618258432 rounds of pDBv1 provisioning (276701161105643258880 days on average, or 758085372892173312 years).

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

(Formula to check the expiration status: `(current_timestamp - provision_timestamp) > (lifetime * 24 * 60 * 60) `,
where `current_timestamp` is the current (as time of accessing `provision_timestamp`) UTC UNIX time timestamp)

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

        bytes key = argon2(password=(database_password + nonce), salt=assoc, length=32, ... (parameters configured by database));

        ChaCha20Poly1305 chacha = ChaCha20Poly1305(key=key);

        # Encrypt the secret key
        bytes ciphertext = chacha.encrypt(data=sk, nonce=nonce, associated_data=assoc);

        return assoc + nonce + ciphertext;
    }

This pseudocode means:

-   Generate 32 bytes of cryptographically secure associated data.
-   Generate a 12-byte cryptographically secure nonce for ChaCha20-Poly1305.
-   Derive a key using Argon2, password being the database password and the nonce concatenated, and the salt being the associated data.
-   Pass in the key to ChaCha20-Poly1305.
-   Encrypt the secret key, passing in the nonce and the associated data
-   Concatenate the associated data, the nonce, and the cypher-text, and return it as the final cypher-text.

#### 0x01 - cryptographic salt

This is the format of a cryptographic salt:

| C type      | Name    | Description                                     |
| ----------- | ------- | ----------------------------------------------- |
| `uint8_t[]` | `value` | A cryptographically secure salt (random bytes). |

#### 0x02 - account secret

This is the format of a cryptographic account secret for SNAPI.

| C type      | Name    | Description                             |
| ----------- | ------- | --------------------------------------- |
| `uint8_t[]` | `value` | A secure account secret (random bytes). |

## Cryptography

Keyfile version 0 uses ChaCha20-Poly1305 with the Argon2 key derivation function. In pseudocode, the cryptography of a single key would look like this:

    bytes encrypt_key(key, key_salt) {
        # `salt` comes from the format header
        bytes database_password_digest = argon2(password=(database_password + psalt), salt=(salt + key_salt), length=256, ... (parameters configured by database));

        for _ in repeat(keyfile_crypto_passes) {
            bytes ks = random(32);

            bytes assoc = random(32);

            bytes nonce = argon2(password=(db_pepper + database_password + assoc), salt=(ks + database_password_digest + key_salt), length=12, ...);

            bytes key = argon2(password=(nonce + database_password + assoc), salt=(database_password_digest + key_salt + db_pepper), length=32, ...);

            ChaCha20Poly1305 chacha = ChaCha20Poly1305(key=key);

            key = chacha.encrypt(data=key, nonce=nonce, associated_data=assoc);
            key = ks + assoc + key;
        }

        return key;
    }

In other words:

-   Initially a 256-byte database password digest is derived using Argon2, passing in the database password and `psalt` (configured by the database) as the password, and the Keyfile salt and key salt as the salt.
-   A loop of `keyfile_crypto_passes` is started (configured by the database).
-   A 32-byte cryptographically secure salt is generated called `ks`.
-   32 bytes of associative data called `assoc` is generated to be later passed to ChaCha20-Poly1305.
-   Using Argon2 a 12-byte nonce is derived, by passing in `db_pepper`, database password, and the previously generated `assoc` concatenated as the password, and
    the salt being `ks`, database password digest, and the key salt concatenated together.
-   Using Argon2, a 32-byte key is derived. Password: `nonce + database password + assoc`, Salt: `database password digest + key_salt + db_pepper`.
-   Key is passed to ChaCha20.
-   Using ChaCha20, data is encrypted. Key is reassigned to be the cypher-text.
-   `ks + assoc` concatenation is prepended to the key cypher-text.
-   Process is repeated.

## Validation

-   The magic number of the file is correct. (basic corruption and file type check)
-   The version is supported by the target database. (support check)
-   The Keyfile is not currently locked. (access check, to prevent collisions)
-   `db_AES_crypto_passes` is at least `1`.
-   `db_ChaCha20_Poly1305_crypto_passes` is at least `1`.
-   The SHA3-512 sum of the database is correct. (integrity check)
-   All keys are decryptable and valid. (integrity, authentication, and authorization checks (because a password, correct nonce and associated data, and correct cypher-text is required))
-   The provision date of any key must not be into the future.

If any of the checks fail, you shall terminate the access to the database to prevent any damage or tampered with data.

## Authors

-   Ari Archer \<<ari@ari.lt>\> \[<https://ari.lt/>\]

## Licensing

    "pDB Keyfile version 0 (pKfv0) file format and specification" is licensed under the GNU General Public License version 3 or later (GPL-3.0-or-later).

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.
