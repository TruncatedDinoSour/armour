# pDB database format -- version 1 (alpha)

**Note: This version of pDB is still in early alpha stages. Do not implement this or use this format yet in production.**

This is the official pDB specification document describing the exact structure of the pDB (version 1) (pDBv1)
file format. Its purpose is to serve as detailed documentation for any implementations of this format, such as SDKs,
clients and other pieces of code utilizing it.

## Introduction

Password Database Version 1 (pDBv1) is a little-endian, secure, encrypted password database as a successor of pDBv0.
pDB uses multiple rounds of different well-tested cryptographic algorithms to ensure security of the database, secure
hashing algorithms, and cryptographically secure sources of randomness.

pDBv1 should now be the preferred format for modern pDB databases, as it improves many parts of it, such as:

...

## Clients

This section includes a list of SDKs, libraries, user interfaces, etc. (collectively called "clients") which support the pDBv1 format.

-   [Stable, Official] Armour library From Armour By Ari Archer \<<ari@ari.lt>\> License GPL-3.0-or-later: <https://ari.lt/gh/armour>
    -   [Stable, Official] Pwdmgr client From Pwdtools By Ari Archer \<<ari@ari.lt>\> License GPL-3.0-or-later: <https://ari.lt/gh/pwdtools>

## File identifiers

-   File extension: `.pdb`
-   MIME type: `application/pdb`, `application/x-pdb`
-   Magic number: `pDB\xf6` (`0x70 0x44 0x42 0xf6`, `0x704442f6`, `1883521782`)

## Supported Keyfile versions

This is a list of all supported Keyfile versions.

-   Keyfile version 1

## Database

This section describes the abstract database format, the generic structure of the header and order of data and dynamic sections in the database.

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type                       | Name                              | Description                                                                                                                                         |
| ---------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uint8_t[4]`                 | `magic`                           | The magic number of the file. Always a constant value.                                                                                              |
| `uint16_t`                   | `version`                         | The version of the database. A constant value per-version. (in the case of pDBv1 case - `0x01`)                                                     |
| `uint8_t`                    | `ZSTD_compression_level`          | The ZSTD compression level of the database from 0 to 22.                                                                                            |
| `uint8_t`                    | `Argon2_type`                     | Argon2 key derivation function type (discussed below).                                                                                              |
| `uint32_t`                   | `Argon2_time_cost`                | Argon2 key derivation function Time Cost parameter. Represents the number of iterations in the hash function.                                       |
| `uint32_t`                   | `Argon2_memory_cost`              | Argon2 key derivation function Memory Cost parameter. A larger memory cost makes the hash function require more memory.                             |
| `uint16_t`                   | `salt_size`                       | Whenever a salt is required, this number is used as a base salt length.                                                                             |
| `uint8_t[64]`                | `pepper`                          | 512 bits of cryptographically secure information which are always constant, used for peppering of data.                                             |
| `uint64_t`                   | `psalt_size`                      | The size of the `psalt` following this argument.                                                                                                    |
| `uint8_t[psalt_size]`        | `psalt`                           | When opening a pDB Keyfile, a `psalt` (password salt) is passed to it to cross-authenticate, this is used to salt the password.                     |
| `uint16_t`                   | `keyfile_crypto_passes`           | The Keyfile encryption/decryption passes. (passed to the Keyfile)                                                                                   |
| `uint16_t`                   | `RSA_crypto_passes`               | When using RSA-4096 cryptography in the database, how many times should the algorithm me ran?                                                       |
| `uint16_t`                   | `AES_crypto_passes`               | When using AES256 cryptography in GCM (Galois/Counter) mode in the database, how many times should the algorithm me ran?                            |
| `uint16_t`                   | `ChaCha20_Poly1305_crypto_passes` | When using ChaCha20-Poly1305 cryptography in the database, how many times should the algorithm me ran?                                              |
| `uint16_t`                   | `Threefish_crypto_passes`         | When using Threefish 1024 cryptography in the database, how many times should the algorithm me ran?                                                 |
| `uint16_t`                   | `chunk_identifier_size`           | The chunk identifier size in bytes. You can calculate the maximum possible entry count using `f(x)=256^{x}-1` where `x` is `chunk_identifier_size`. |
| `uint16_t`                   | `chunk_size`                      | The chunk size of encrypted entries in the database. `chunk_size` must be larger then `chunk_identifier_size`.                                      |
| `uint8_t[64]`                | `metadata_hash_sha3_512`          | The SHA3-512 hash of the metadata following it (including the size).                                                                                |
| `uint64_t`                   | `metadata_size`                   | The size of the metadata chunk following the size.                                                                                                  |
| `uint8_t[metadata_size]`     | `metadata`                        | The human-readable metadata chunk (metadata format is discussed below).                                                                             |
| `uint8_t[64]`                | `crypto_check_hash_sha3_512`      | The SHA3-512 hash of the Crypto Check section below (including the size).                                                                           |
| `uint64_t`                   | `crypto_check_size`               | The size of the Crypto Check section below.                                                                                                         |
| `uint8_t[crypto_check_size]` | `crypto_check`                    | 256 cryptographically secure random bytes, encrypted and compressed using all possible methods.                                                     |
| `uint8_t[64]`                | `header_hash_sha3_512`            | The SHA3-512 hash of the whole header before this section.                                                                                          |
| `uint8_t`                    | `lock`                            | The lock status of the database. See lock statuses below.                                                                                           |
| `uint8_t[]`                  | `entries`                         | The chunked encrypted entries of the database.                                                                                                      |

### Argon2 type

-   `0x00` - Argon2D - faster and makes better use of available processing power, thus making it more resistant against GPU cracking attacks, however, it is more susceptible to side-channel attacks.
-   `0x01` - Argon2I - slower and uses more memory, making it more secure against attacks that aim to determine a password by trying every possible combination, however, it's not as resistant against GPU attacks as Argon2D.
-   `0x02` - Argon2ID - combines the benefits of both Argon2D and Argon2I by using Argon2I at the beginning and Argon2D for the rest of the process, aiming to maximize the advantages of both processes while minimizing their disadvantages, thus providing a safer hashing algorithm - this is the most recommended Argon2 type.
-   No other types of Argon2 exist yet.

## pDBv1: Authors

-   Ari Archer \<<ari@ari.lt>\> \[<https://ari.lt/>\]

## Licensing

    "pDB version 1 (pDBv1) file format and specification" is licensed under the GNU General Public License version 3 or later (GPL-3.0-or-later).

    You should have received a copy of the GNU General Public License along with this program.
    If not, see <https://www.gnu.org/licenses/>.
