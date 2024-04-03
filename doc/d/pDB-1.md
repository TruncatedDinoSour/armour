# pDB database format -- version 1 (alpha)

**Note: This version of pDB is still in early alpha stages. Do not implement this or use this format yet in production.**

This is the official pDB specification document describing the exact structure of the pDB (version 1) (pDBv1)
file format. Its purpose is to serve as detailed documentation for any implementations of this format, such as SDKs,
clients and other pieces of code utilizing it.

## Introduction

pDB ([p]assword [d]ata[b]ase) is a new password database format which mainly uses little-endian binary data.
It is focused on security, entropy, and data integrity. Its main audience are individuals and entities
who are concerned about their data security & are willing to put resources into it.

If you're looking for something lightweight and small - pDB is not for you (even though it can be configured to be
fairly small and lightweight, but pDB doesn't prioritize that), you're most likely better off storing
the passwords in SQLite with a single pass of AES or ChaCha20 if you need something more lightweight.

pDBv1 is a successor to pDBv0 which was a successor to the original ASCIIpDB format. pDBv1 does a few things
a lot better than pDBv0, such as:

-   Enhanced security
    -   Improve how hashing functions are handled
    -   Reorder hashing algorithms by security
    -   Introduces more secure encryption algorithms like ChaCha20
    -   Added 512 more bits of security by adding pepper bytes
    -   Improve the handling of encryption
    -   Introduce more entropy sources
-   Flexibility and Customization
    -   Added more parameters to customize
    -   Made the format more flexible and dynamic
    -   Simplify parts of the structure, allowing the format to be more flexible and dynamic
    -   Added support for dynamic entries by chunking
    -   Added support for locking and concurrency
-   Chunking Mechanism
    -   Introduce chunking to organize and store entities to improve the performance, scalability,
        and structure of the database
-   Metadata
    -   Introduce metadata to the format
    -   Have a human-readable structure for the metadata
    -   Add standard metadata keys, such as contact information
-   Improved Validation and Integrity
    -   Enhanced the validation criteria, add a comprehensive list of conditions, and ensure the integrity
        and security of the database
    -   Add the "crypto check" mechanism to check and validate cryptography,
-   Clear Documentation and Standardization
    -   Introduce pseudocode to improve the readability of the documentation
    -   Make the standard more detailed, allowing developers to implement it effectively
    -   Add standardized file types
    -   Use standard language, features, and algorithms
    -   Define common algorithms used to manage the database

## Clients

This section includes a list of SDKs, libraries, user interfaces, etc. (collectively called "clients") which support the pDBv1 format.

-   [Stable, Official] Armour library From Armour By Ari Archer \<<ari@ari.lt>\> License GPL-3.0-or-later: <https://ari.lt/gh/armour>
    -   [Stable, Official] Pwdmgr client From Pwdtools By Ari Archer \<<ari@ari.lt>\> License GPL-3.0-or-later: <https://ari.lt/gh/pwdtools>

## File type

This describes the file type identifiers of pDB.

### Extensions

-   `*.pdb` - Password database(s) (pDB)
-   `*.slt` - Authentication salt file(s) (any data)

### Internet media type/MIME type

-   pDB: `application/pdb` (`application/x-pdb`)
-   Slt: `application/oclet-stream`

### Magic number

-   pDB: `0x70 0x44 0x42 0xf6`
-   Slt: N/A

## Database

This section describes the format for the abstract structure of the full pDB (version 1) database.
Its layout includes the sizes of sections, the types, and the [format specifiers](https://docs.micropython.org/en/latest/library/struct.html)
for the binary data, along with what the section means.

Whenever bytes are mentioned, assume the bytes are [Little Endian](https://en.wikipedia.org/wiki/Endianness#Little), unless specified otherwise.
pDB is a format which works with primarily little-endian data.
(for example 2 little endian bytes (`uint16_t`, `<H`) representing 7621: `0xC5 0x1D`, and 1: `0x01 0x00`)

Note: A virtual section is a section in the format separated by logical links, but is not literally separated in the format.
If you want a uniform list describing the format, feel free to ignore the "Virtual section" headers.

### Virtual section: Identifier

See: <https://en.wikipedia.org/wiki/File_format#Magic_number>

-   `uint8_t magic[4]` (4 bytes, `<4B`) - The 4 magic bytes (magic number)/file signature.
    -   Always a constant value: `0x70 0x44 0x42 0xf6` (`pDB\xf6`).
    -   Identifies the file type.
-   `uint16_t version` (2 bytes, `<H`) - The version of the database.
    -   Always a constant value in the same version
    -   Current value: `0x01 0x00` (`1`)

### Virtual section: Compression

See: <https://en.wikipedia.org/wiki/Zstd>

-   `uint8_t zstd_compression_level` (1 byte, `<B`) - The ZSTD compression level (from 0 to 22).
    -   If changed, a layer of encryption would have to be re-encrypted along with the "crypto check" section

### Virtual section: Hashing and key derivation

See: <https://en.wikipedia.org/wiki/PBKDF2>, <https://en.wikipedia.org/wiki/Entropy>, <https://en.wikipedia.org/wiki/Hash_function>

Hashing & how pDBv1 handles it is discussed below.

-   `uint8_t hash_function_id` (1 byte, `<B`) - The hashing function ID to identify the hashing function which to use across the database.
    -   _Technically_ a mutable value, but the whole database would have to be rehashed and re-encrypted
    -   Supported hashes:
        -   `0` - SHA3_512 (slowest, but most secure)
        -   `1` - BLAKE2b
        -   `2` - SHA3_384
        -   `3` - SHA512 (the recommended median)
        -   `4` - SHA512_256
        -   `5` - SHA3_256
        -   `6` - SHA384
        -   `7` - BLAKE2s
        -   `8` - SHA512_224
        -   `9` - SHA256 (the recommended minimum)
        -   `10` - SHA3_224
        -   `11` - SHA224
        -   `12` - SHA1
        -   `13` - SM3
        -   `14` - MD5 (insecure, although MD5 is fast)
-   `uint8_t salt_size` (1 byte, `<B`) - Whenever salting values (such as hashes or keys), how long the salt should be?
-   `uint64_t pbkdf2_hmac_passes` (4 bytes, `<L`) - The passes for `PBKDF2` key derivation function with the `HMAC` pseudorandom function.
    -   The larger the value, the more work a computer would need to do to derive a key, although the derived key is more secure.
-   `uint8_t pepper[64]` (64 bytes, `<64B`) - 512 bits of cryptographically secure information (64 cryptographically secure bytes).
    -   Always a constant value since database creation

### Virtual section: Cryptography

See: <https://en.wikipedia.org/wiki/RC4>, <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>, <https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant>

Cryptography and how pDBv1 handles it is discussed below.

-   `uint16_t rc4_crypto_passes` (2 bytes, `<H`) - The count of RC4 encryption passes to do every time RC4 encryption is initiated.
-   `uint16_t chacha20_crypto_passes` (2 bytes, `<H`) - The count of ChaCha20 encryption passes to do every time ChaCha20 encryption is initiated.
-   `uint16_t aes_crypto_passes` (2 bytes, `<H` ) - The count of AES encryption passes to do every time AES encryption is initiated.

### Virtual section: Chunking

Chunk size & concept of Chunks is discussed below.

-   `uint8_t chunk_identifier_size` (1 byte, `<B`) - The size of a chunk identifier in bytes.
    -   Keep in mind the maximum entries you can have in a pDB database is `f(x)=2^{8x}-1` where `x` is `chunk_identifier_size`
-   `uint16_t chunk_size` (2 bytes, `<H`) - The chunk size of encrypted entries in the database.
    -   `chunk_size` must be larger then `chunk_identifier_size`

### Virtual section: Metadata

Metadata and how pDBv1 stores and handles it is discussed below. Do not store any sensitive information
in this section as it is stored in **plain text**.

-   `uint8_t metadata_hash[secure_hash_size]` (`secure_hash_size` bytes, `<L`) - The hash of of the metadata section
    (including the size and metadata).
-   `uint64_t metadata_size` (4 bytes, `<L`) - The size of the metadata blob following it.
-   `uint8_t metadata[metadata_size]` (`metadata_size` bytes, `<{metadata_size}B`) - The metadata of the database.
    -   This section may be cleared at any moment and you should not use it to store anything sensitive or persistent.
        The data in this section is stored in the database as **plain text**.

### Virtual section: Integrity

-   `uint8_t crypto_check_hash[secure_hash_size]` (`secure_hash_size` bytes, `<L`) - The hash of the crypto check. (including the size)
-   `uint64_t crypto_check_size` - The size of the `crypto_check` section following it.
-   `uint8_t crypto_check[crypto_check_size]` - 196 random bytes encrypted using all possible encryption methods and compression. (see crypto check workflow below)
-   `uint8_t header_hash[secure_hash_size]` (`secure_hash_size` bytes, `<L`) - The hash of the whole header before it.

### Virtual section: Concurrency

Locking and concurrency is discussed below.

-   `uint8_t lock_state` (1 byte, `<B`) - The current database lock state.

### Virtual section: Dynamic data (chunked entries)

Entry structure is discussed below.

-   `uint8_t *entries` (rest of the database, `<{n}s`) - The encrypted entry chunks.

### Validation

This subsection describes the validation criteria for a pDB database to be considered valid.

The following conditions must be satisfied:

-   The lock of the database is valid
-   The lock of the database is unlocked
-   The magic bytes are `0x70 0x44 0x42 0xf6`
-   The version of the database is supported by the pDB client
-   The ZSTD compression level is below 23 (22 is max)
-   The hashing function ID is supported by the client, and is available
-   `salt_size` is at least 1
-   `pbkdf2_hmac_passes` is at least 1
-   `rc4_crypto_passes` is at least 1
-   `chacha20_crypto_passes` is at least 1
-   `aes_crypto_passes` is at least 1
-   `chunk_identifier_size` is at least 1
-   `chunk_size` is larger than chunk_identifier_size
-   `metadata_hash` is valid
-   you are able to read `metadata_size` bytes from the `metadata` section
-   `crypto_check` passes the checks
-   `header_hash` matches the whole header

## Randomness

Randomness used in any context in this document refers to the concept of
cryptographically secure randomness. Pseudo-randomness is not suitable to use
in this format as that jeopardizes the security of it.

Do not implement this format using non-cryptographically-secure number generators.
Prioritize randomness, entropy, and unpredictability wherever possible.

Implementations of the cryptographically secure functions may differ but the result\
must stay the same - almost unpredictable, cryptographically secure random
numbers.

See: <https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator>, <https://manpages.ubuntu.com/manpages/focal/man3/RAND_pseudo_bytes.3ssl.html> (`RAND_bytes(3)`)

## Hashing

pDBv1 usually doesn't hash functions on their own, it actually combines the hashing function with the PBKDF2 key
derivation function to generate a so to say "authenticated" hash. In pseudocode:

    bytes hash(HashAlgorithm algorithm, bytes data) {
        bytes salt = random(salt_size);

        bytes key = PBKDF2(
            prf=HMAC,
            algorithm=algorithm,
            length=algorithm.digest_size + salt_size,
            salt=salt + slt_file,
            iterations=pbkdf2_hmac_passes,
        ).derive(database_password);

        HMAC hmac = HMAC(
            key=key,
            algorithm=algorithm,
        );

        hmac.update(data + pepper);

        return salt + hmac.digest();
    }

In other words:

-   Generate a `salt_size` salt
-   Using PBKDF2(HMAC, algorithm, generated_salt + slt_file, pbkdf2_hmac_passes) derive a `secure_hash_size` key from the database
    password
-   Pass the derived key, along with the hashing algorithm to HMAC
-   Pass the `data + pepper_bytes` to the HMAC function
-   Return `generated_salt + hmac_digest` - this is our final hash

## Cryptography

pDBv1 has 3 different encryption algorithms: RC4 (insecure encryption, used mainly for obfuscation),
ChaCha20 (main source of "secure" encryption), and AES (main source of "robust" encryption - slowest, but most secure)

### RC4

In pseudocode, this is how pDBv1 handles RC4 encryption:

    bytes rc4(bytes data) {
        for (size_t idx = 0; idx < rc4_crypto_passes; ++idx) {
            bytes p = random(8);
            bytes a = random(8);

            # Uses the hashing function directly, in this case - hash_id=0
            bytes key = get_hash_algorithm_by_hash_id(0)(p + pepper + slt_file + a + database_password);

            data = rc4_crypto(data, key);

            data = p + a + data;
        }

        return data;
    }

In other words,

-   Generate 8 random bytes, call it `p`
-   Generate another 8 random bytes, call it `a`
-   Use the most secure hashing algorithm available (hash_id=0) to derive a key from `p + pepper + slt_file + a + database_password`
-   Encrypt the data, assume we reassign `data = encrypt_using_rc4(data)` now
-   Prepend `p` and `a` to the data, assume we reassign it: `data = p + a + data`
-   Repeat this process `rc4_crypto_passes` times

To justify the usage of RC4 in this format:

-   The main use of RC4 in this format is to introduce more entropy and introduce a small layer of encryption & obfuscation
-   If RC4 is cracked, you won't extract much from it, the key is a 512-bit hash out of which you cannot extract the important parts
    (slt_file & database_password)
-   Where a single pass of RC4 is used, the encrypted data is not sensitive
-   Where RC4 is genuinely used, it is behind multiple layers of very secure encryption and transformation (ChaCha20, ZSTD, AES)

I think it is justifiable in this case.

### ChaCha20

ChaCha20 is a secure encryption algorithm used a lot in pDBv1. This is how pDBv1 customizes
it in pseudocode:

    bytes chacha20(bytes data) {
        for (size_t idx = 0; idx < chacha20_crypto_passes; ++idx) {
            bytes nonce = random(16);
            bytes salt = random(salt_size);

            data = pepper + data;

            bytes key = PBKDF2(
                prf=HMAC,
                algorithm=get_hash_algorithm_by_hash_id(hash_id),
                length=32,
                salt=salt + slt_file,
                iterations=pbkdf2_hmac_passes,
            ).derive(database_password);

            data = chacha20_crypto(data, key);

            data = nonce + salt + data;
        }

        return data;
    }

In other words,

-   Generate a 16-byte random nonce
-   Generate a `salt_size`-byte random salt
-   Prepend `pepper` to the data, assume `data = pepper + data` now
-   Derive key using PBKDF2(HMAC) passing the generated salt concatenated with the salt file, configured hashing algorithm to PBKDF2,
    and deriving from the database password
-   Pass the data to chacha20 along with the derived key. Assume `data` was reassigned to the encrypted data
-   Concatenate `nonce + salt + data` and reassign `data`
-   Repeat this process `chacha20_crypto_passes` times

### AES

AES in GCM mode is used as a final layer of encryption, it is a slow, but secure encryption algorithm. This is
how pDBv1 utilizes it:

    bytes aes(bytes data) {
        data = random(64) + data + pepper;

        for (size_t idx = 0; idx < aes_crypto_passes; ++idx) {
            bytes salt = random(salt_size);

            bytes key = PBKDF2(
                prf=HMAC,
                algorithm=get_hash_algorithm_by_hash_id(hash_id),
                length=32,
                salt=salt + slt_file,
                iterations=pbkdf2_hmac_passes,
            ).derive(database_password);

            bytes iv = random(12);

            AESGCM aes = AESGCM(
                key=key,
                iv=iv,
            )

            data = aes.encrypt(data);

            # `aes.tag` is 16 bytes
            data = salt + iv + data + aes.tag;
        }

        return data;
    }

In other words,

-   Before the main loop, prepend 64 random bytes to the data, and append the `pepper` bytes
-   Now, start the main loop
-   Generate `salt_size` byte salt
-   Derive a key using PBKDF2 as before with salt being `generated_salt + slt_file` from the database password
-   Generate a random 12-byte initialization vector (IV)
-   Encrypt data using AES in GCM mode passing the derived key and the generated IV, assume we
    reassigned `data = aesgcm_encrypt(data)` now
-   Reassign `data = generated_salt + IV + data + aes.tag`
-   Repeat this `aes_crypto_passes` times

## Metadata

The metadata section is a **plain text** section of a pDB database in which you can
store any data to provide context for pDB clients or users of the database or leave contact
information in case your database got leaked. You should not store any sensitive
information in the metadata section as it can be read (although not modified) by anyone.

Metadata is a simple `Key:Value` store which can have duplicating keys, such as:

    Key:Value
    Key:Value 1
    Key one:Value
    This is a key!:This is a: value!

    huihtuierhtiuhjiuehui
    ^ this is an invalid key-value pair

Keys cannot include semicolons or newlines, and values cannot include newlines. If you need to use
illegal characters use [Percent encoding](https://en.wikipedia.org/wiki/Percent-encoding)

Everything after the first `:` is considered a value, and a newline starts a new `Key:Value` pair.
Values may be empty (in case of `Key:` (a newline right after the semicolon or the end of the metadata section)).

Keys may repeat. Repeating key values may get stored in an array if parsed by the client, for example:

```json
{
    "Key": ["Value", "Value 1"],
    "Key one": ["Value"],
    "This is a key!": ["This is a: value!"]
}
```

And any invalid (or empty) lines should be ignored.

### Standard keys and values

This subsection will give a sample metadata blob in the following format:

    Key:Value (note)

When using the metadata key-value pairs described in this section, you should
ignore the `(note)` and just use the `Key:Value`.

    Client:Pwdmgr client From Pwdtools By Ari Archer <ari@ari.lt> Version 1.0.0 License GPL-3.0-or-later (See Client ID structure below)
    Creation:2024-04-02 22:16:54 (The creation date of the database, YYYY-MM-DD hh:mm:ss)
    Connect:<connection address> (The connection address of the pDB database, usually handled by the 0x05 locking state. See connection address format below)
    Email:me@example.com (The email(s) of the owner(s) of this database)
    GPG:4FAD63E936B305906A6C4894A50D5B4B599AF8A2+ari@ari.lt (GPG key ID for author's emails)
    Matrix:@me:example.com (The matrix id(s) of the owner(s) of this database)
    Name:Jane Dane (The full name of the owner(s) of this database)
    Note:Any data here (A note of the database)
    Phone:+442012345678 (Phone number(s) in the international format of the owner(s) of the database)
    Post:PO Box 1235, Cupertino, CA 95015, USA (Postal address of the owner(s) of the database)

#### Client ID

The Client ID (`Client` metadata key) has the following structure:

    <client name> <client type (library, SDK, client (interface), ...)> From <project, package, etc> By <author's name> <<author's email>> Version <client version> License <SPDX license identifier>

There's no other structure for it.

#### Connection address

Here are the supported connection address formats for pDB:

-   `pdb://host.name:port/database?v=?` - No authentication connection to a database
    -   Required authentication layers: None
-   `mpdb://user@host.name:port/database?v=?` - Multi-user server pDB connection to a database
    -   If value of `Connect` is only `mpdb://host.name:port/database?v=?` it means 'Connect with your own user and password'
    -   Required authentication layers: User password, user secret
-   `tmpdb://user@host.name:port/database?v=?` - Multi-user server pDB connection to a database, with TOTP
    -   If value of `Connect` is only `tmpdb://host.name:port/database?v=?` it means 'Connect with your own user, password, and TOTP'
    -   Required authentication layers: User password, user secret, TOTP
-   `spdb://host.name:port/database?v=?` - Secure authentication connection to a database
    -   This connection _will_ require you to pass the database credentials over the pDB connection to use it,
        usually for servers that may not specifically handle the database on their own, but rather giving a
        server to store databases on.
    -   Required authentication layers: Database password, database salt (slt)
-   `smpdb://user@host.name:port/database?v=?` - Secure multi-user authentication connection to a database
    -   If value of `Connect` is only `smpdb://host.name:port/database?v=?` it means 'Connect with your own user and password'
    -   Same as `spdb`, except with added user-based authentication as in `mpdb`
    -   Required authentication layers: User password, user secret, database password, database salt (slt)
-   `tsmpdb://user@host.name:port/database?v=?` - Secure multi-user authentication connection to a database, with TOTP
    -   If value of `Connect` is only `tsmpdb://host.name:port/database?v=?` it means 'Connect with your own user, password, and TOTP'
    -   Same as `spdb`, except with added user-based authentication as in `mpdb`
    -   Required authentication layers: User password, user secret, database password, database salt (slt), TOTP

The `v` parameter is optional, but it is sent over to the server and also gives context for clients.
The value of `v` should be the database version represented as a string (so version 1 would be `1`, version 0 - `0`,
version 731 - `731` and so on).

Read more about connections in SNAPI documentation.

## Crypto check

The crypto check section is just 196 random bytes that get "compressed" (will usually end up in larger output) using ZSTD,
then passed to RC4, ChaCha20, and then AES. In pseudocode it'd look like this:

    AES(ChaCha20(RC4(ztsd(random(196)))))

This section is used for validating encryption and compression.

## Locking and concurrency

pDBv1 supports locking so multiple processes, threads, clients, etc. could work on the same database
at the same time without causing conflicts in data. The lock is stored in the database file itself, and
the locking states supported by pDBv1 are:

-   `0x00`: Unlocked
-   `0x01`: Locking
-   `0x02`: Locked
-   `0x04`: Releasing
-   `0x05`: Disabled (Forever locked, lock handled by a client service)
-   Anything else: Invalid

This locking state can more effectively be achieved through the network and storing it in system memory rather than
in the file, in which case the Standard Network API (SNAPI) should be implemented and the locking state should be set
to `0x05` (Disabled). If you're handling the `0x05` state, you may set the `Connect` metadata key to a connection address.

Read more about the SNAPI in the dedicated documentation section on it.

## Entries

This section discusses the general structure of entries ("Simple Entries"). You cannot use them
directly in the database, but you have to first construct this type ("Simple") of entry to
construct the entry type you _can_ use directly in the database - a chunked ("Complex") entry (chunking is discussed below)

Entries have the following structure outline:

    [hash] [dhash][ident][size][data] [dhash][ident][size][data] ...
    [null]
    [hash] [dhash][ident][size][data] ...
    ...

(Ignore the spaces, they are only in the outline to make it clear where what belongs.)

Firstly, an entry begins with a hash:

-   `uint8_t hash[secure_hash_size]` (`<{secure_hash_size}B`) -- The hash of the rest of the entry (including all identifiers, sizes, hashes, and data)

Then you can add fields to the entry, there can (and probably should) be multiple fields,
you just repeat the same structure over and over again. This is how it looks:

-   `uint8_t ident` (`<B`) -- The entry field identifier (may be NULL, this does not mean a new entry if the NULL byte is used as an identifier).
    The identifiers cannot repeat, and if they do - the latest one's value dominates (like a [Hash table](https://en.wikipedia.org/wiki/Hash_table))
-   `uint64_t size` (`<L`) -- The size of the entry's data
-   `uint8_t dhash[hash_size]` (`<{hash_size}B`) -- The hash of the entry's data
-   `uint8_t data[size]` (`<{size}B`) -- The data the field holds

Standard fields include:

-   `t`: Type of the entry (plain text)
    -   `p`: Password store
    -   `t`: TOTP store (some clients may use this type to generate & copy TOTP codes instead of the TOTP key)
-   `n`: Name of the entry (plain text)
-   `r`: Remark of the entry (RC4 encrypted, **DO NOT STORE SENSITIVE INFORMATION IN REMARKS**)
-   `e`: Encrypted section of the entry (an encrypted and compressed entry, see encryption subsection below)
    -   `u`: Username
    -   `p`: Private value of the entry (password, TOTP key)

The only reserved fields are the lowercase ASCII letters (26 identifiers), so use them with caution.
Other identifiers (any characters from 0x00 to 0xff, excluding lowercase ASCII (`[a-z]` in Regex)), you can use
to set custom fields.

**To repeat**: This is just a Simple Entry. You need to chunk it first to add it to the database. Chunking
and chunking algorithms are discussed below.

### Encryption

The `e` field includes encrypted data of the entry. The value of `e` is actually another encrypted simple entry.
All fields of that simple entry are encrypted using ChaCha20, while the whole entry goes through
a whole encryption process: firstly it gets encrypted using RC4, then ChaCha20, after which the output
is quite big so we pass the output to ZSTD. And then the output of ZSTD is passed to AES.

In other words:

    Fields -> ChaCha20
    Entry -> RC4 -> ChaCha20 -> ZSTD -> AES

And then, of course, it is chunked up and passed to the database.

### Validation

This subsection describes the validation criteria for an entry to be considered valid.

The entry must satisfy the following conditions:

-   You are able to decrypt the entry fields
-   The structure of the entry and fields are valid
-   The hash of the entry is valid
-   The hashes of all fields are valid
-   The encrypted part (`e`) passes the same criteria

## Chunking

Chunking is used to construct a Chunked ("Complex") entry, which is an essential part of working with pDB.

The entries database looks something like this in real world cases

    [chunk ID][entry chunk] [NULL chunk id][empty chunk] [chunk ID][entry chunk] [chunk ID][entry chunk] [chunk ID][entry chunk] [NULL chunk id][empty chunk] [NULL chunk id][empty chunk] [chunk ID][entry chunk] ...

It is a fragmented stream of taken and empty chunks.

This is how you would construct a complex entry:

1. Construct a simple entry
2. Split the entry into `chunk_size` chunks
3. Pad the last chunk to exactly `chunk_size` bytes with any data
   (preferably completely random data, for entropy uses)
4. Prepend a unique `chunk_identifier_size` byte chunk identifier to every single chunk
    - Mind you that a chunk identifier cannot be all NULL bytes (for example a 4 byte chunk identifier cannot be just `0x00 0x00 0x00 0x00`).
      A chunk identifier of all NULL bytes signifies an **empty chunk**.
    - Ideally a chunk identifier is cryptographically secure random data instead of an incremental counter

You have now successfully constructed a complex entry - an array of chunks. Next you will need to
use some sort of algorithm to insert the chunk into the database.
Couple of example algorithms are discussed in the subsections below.

Note that the chunks need to be in order globally, they just don't need to be next to one another.

### Insertion Algorithm #1: O(n^2)

-   Loop through all chunks in the database and check if there's any available
    empty chunks (chunks where the chunk identifier is all NULLs)
-   If an empty chunk if found, insert a chunk from your complex entry into the empty space
-   Do this until you either don't have chunks left or you're out of empty space
-   If you still have chunks, but are out of empty space, append your chunks to the database

In other words:

    Chunk chunks[] = {...};

    for (Chunk new_chunk in chunks) {
        bool found = false;

        for (Chunk db_chunk in pdb.chunks)
            if (db_chunk.empty) {
                db_chunk.replace(new_chunk);
                found = true;
                break;
            }

        if (!found)
            pdb.chunks.append(new_chunk);
    }

### Insertion Algorithm #2: O(n)

-   Have an ordered index (array) of empty chunks in an array
    -   For purposes of this algorithm, let's say index [0] is the
        chunk closest to the end of the database and last index
        is closest to the header (this is how you'd work with the
        array structure while parsing pDB most likely)
    -   If you have it in reverse order, modify the algorithm accordingly
-   Loop through the chunks of the entry
-   If available, pop off the last element of the index
-   If unavailable, append the chunk to the end of the database

In other words:

    Chunk chunks[] = {...};

    for (Chunk new_chunk in chunks)
        if (pdb.emtpy_chunks)
            pdb.emtpy_chunks.pop().replace(new_chunk);
        else
            pdb.chunks.append(new_chunk);

These algorithms are not the only available ones, just a couple of very simple
chunk management algorithms which handle fragmentation well.

You have now successfully inserted a chunk into the database.

### Defragmentation algorithm

If you ever need to defragment the chunks, you can easily use
this algorithm:

    for (Chunk chunk in pdb.chunks)
        if (chunk.empty)
            chunk.remove()

This is O(n) where n is all chunks. You an improve the performance of it by keeping an index of all
empty chunks:

    for (Chunk chunk in pdb.emtpy_chunks)
        chunk.remove()

This is still O(n) but the n is a lot smaller.

### Fragmentation algorithm (theoretical)

If you ever need (or want) to fragment the database, you can do it in many ways, for example:

    for (Chunk chunk in pdb.chunks)
        if (random(1, 3) % 2 == 0)
            chunk.insert_after(Chunk());

You can also shuffle the heap in the process, by going through the non-empty chunks
and randomly inserting them in the newly made empty spaces:

    for (Chunk chunk in pdb.chunks)
        if (random(1, 3) % 2 == 0)
            chunk.insert_after(Chunk());

        if (random(1, 5) % 2 == 0)
            chunk.move_to(pdb.emtpy_chunks[0])

All of this is very theoretical and will vary a lot depending on the implementation.

### Chunk removal

To remove a chunk you just replace its chunk identifier with all NULLs and possibly overwrite
the data the chunk is storing with either all NULLs or completely random data (which is preferred).

## Security, clients, feedback & questions

Email <ari@ari.lt> for any questions or security concerns you have about the pDBv1 format. I will be sure
to either update the format, answer your questions, or start a new version of pDB fixing the problems
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
