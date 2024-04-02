# pDB database format -- version 1 (alpha)

> pDB is a custom, security, entropy, data structure and data integrity focused password database
> format with high customizability and a wide range of selection

**This specification is still in alpha stages. Do not implement this specification yet.**

## Uses

The target audience are individuals & entities who are concerned about their or the data they're storing security.

The database is not focused on being lightweight and small, it is focused on being secure, structured, validating,
and hard to tamper with.

## Why v1 over v0?

pDBv1 is built to solve some issues of pDBv0, whilst sticking to the original pDB philosophy. The main advantages of pDBv1 are in summary:

-   Greater standardization: As its standard avoids non-standard library-specific features, its specification is a lot easier to figure out
-   Better file structure: Removed some complexity from the format, restructure parts of it
-   Introduction of pepper bytes: Added extra security of 512 bits
-   Better order of hashing algorithms by general security (by "security" I mean how well it can be used to check integrity of data)
-   Added support for metadata
-   Added support for dynamic entries
-   Improve the structure and standard of entries
-   Enhance the approach to entry encryption
-   Refine the validation criteria

## File extensions

-   `*.pdb` - Password database(s) (pDB)
-   `*.slt` - Salt (pepper) file(s) (any data)

## Endianess

pDB is a little-endian format, all structured binary data should be little endian.

## Database

Format of pDB is as follows:

-   `uint8_t magic[4]` (4 little endian bytes, `<4B`) -- The magic (identifier) bytes, always `pDB\xf6`.
    -   The `0xf6` byte is a sum of ASCII values of `p`, `D` and `B` to increase the uniqueness of the magic bytes.
-   `uint16_t version` (2 little endian bytes, `<H`) -- The database version starting from 0. Currently: 1.
-   `uint8_t pepper[64]` (64 little endian bytes, `<64B`) - The pepper bytes, which are used for peppering hashes of entries & metadata, along with salting & global salt file.
-   `uint8_t hash_id` (1 little endian byte, `<B`) -- The hashing function used across the database. This value is hardly mutable, as the _whole_ database would need to be rehashed (and possibly revalidated) for it to change.
    -   0 -- SHA3_512 (slowest, but most secure)
    -   1 -- BLAKE2b
    -   2 -- SHA3_384
    -   3 -- SHA512 (the recommended median)
    -   4 -- SHA512_256
    -   5 -- SHA3_256
    -   6 -- SHA384
    -   7 -- BLAKE2s
    -   8 -- SHA512_224
    -   9 -- SHA256 (the recommended minimum)
    -   10 -- SHA3_224
    -   11 -- SHA224
    -   12 -- SHA1
    -   13 -- SM3
    -   14 -- MD5 (least secure, although MD5 is fast)
-   `uint8_t zstd_compression_level` (1 little endian byte, `<B`) -- The ZSTD compression level (from 0 to 22).
-   `uint8_t hash_salt_length` (1 little endian byte, `<B`) -- When using the configured hash function, how long should the randomly-generated salt be?
-   `uint64_t pbkdf2_hmac_passes` (4 little endian bytes, `<L`) -- The passes for `PBKDF2` with the `HMAC` pseudorandom function, key derivation function. (See: <https://en.wikipedia.org/wiki/PBKDF2>)
-   `uint16_t rc4_crypto_passes` (2 little endian bytes, `<H`) -- The count of RC4 encryption passes to do every time RC4 encryption is initiated.
-   `uint16_t aes_crypto_passes` (2 little endian bytes, `<H` ) -- The count of AES encryption passes to do every time AES encryption is initiated.
-   `uint16_t chacha20_crypto_passes` (2 little endian bytes, `<H`) -- The count of ChaCha20 encryption passes to do every time ChaCha20 encryption is initiated.
-   `uint8_t metadata_hash[hash_size]` (`hash_size` little endian bytes, `<{hash_size}B`) -- Using the configured hashing function, the metadata of the database is hashed and the hash stored in this section for future validation.
-   `uint64_t metadata_size` (4 little endian bytes, `<L`) -- The size of the metadata blob following it.
-   `uint8_t metadata[metadata_size]` (`metadata_size` little endian bytes, `<{metadata_size}B`) -- The metadata of the database. This section may be cleared at any moment and you should not use it to store anything sensitive and persistent. This section is stored in the database as **plain text**
-   -   Check the metadata structure discussed later on.
-   `uint8_t *entries` (rest of the database, `<{n}s`) -- The encrypted database entries.
    -   More on entry format discussed later on.

The entries stack, meaning you append entries with **valid structure** as you go, rather than loading it all into RAM
and working on them live. This is one of the more major differences of pDBv0 and pDBv1 entries & structure. Read about
how to construct valid entries below.

### Loading & authentication

This section describes the general ideas behind workflow of loading, authentication, and decryption of pDBv1:

1. The pDB client ("client" or "it") loads the database header & global salt file into memory,
2. The client checks the validity of the database (see the validity section of this document),
3. It reads in the database password from the user,
4. The client then decrypts database metadata as well as validating it,
5. Then the entries are indexed, although not yet decrypted nor loaded into memory,
6. As the user queries or changes data, client keeps track of the state in memory,
7. On a commit request, the client finalizes the database, re-encrypts any decrypted resources, and writes changes to the database.

Of course, it may differ, but this is an example workflow of how generic processes may work, although a client will implement
this in one way or another.

### Validation

Optionally, you can consider:

-   Magic of the pDB database is `pDB\xf6`.

The following conditions MUST be met:

-   Version of the pDB database is supported by the client.
-   `hash_id` value is below 15 (maximum is 14).
-   `hash_id` hash function is supported by the client.
-   ZSTD compression level is below 23 (maximum is 22).
-   `hash_salt_length` has a value of at least 1.
-   `pbkdf2_hmac_passes` has a value of at least 1.
-   `rc4_crypto_passes` has the value of at least 1.
-   `aes_crypto_passes` has the value of at least 1.
-   `chacha20_crypto_passes` has the value of at least 1.
-   `metadata_hash` is valid

Please note that:

-   `metadata_size` can be 0 IF `metadata` is empty
-   `entries` may not be a completely empty section (0 bytes)

## Randomness

For pDBv1 pseudorandom randomness functions are not sufficient. All randomness sources used to interact with a pDBv1 database
must be considered cryptographically secure, i.e very unpredictable.

## Hashing

-   Algorithmic hashing
    -   Uses the configured hashing function to hash the data
    -   Return the hash digest
-   Secure hashing
    -   Uses your selected algorithm as the base
    -   Generates a random `hash_salt_length` byte salt, for more entropy and uniqueness of the hash
    -   Run PBKDF2 with the HMAC pseudorandom function, length of the hashing function hash length
    -   Prepends the salt to the final hash, so we know what salt to use when comparing hashes
    -   Return the transformed hash

## Cryptography

This includes how mainstream encryption algorithms are utilized in pDBv1

-   RC4 encryption (mainly used in obfuscation layers, as this cipher is insecure)
    -   Generate 8 random bytes, call it `p`
    -   Generate 8 random bytes, call it `a`
    -   Concatenate `p + data + a`, assume we reassigned `data = p + data + a`
    -   Derive a key by Concatenating `a + pepper + key + salt + p` and hashing it using the most secure hashing function supported by pDBv1 (hash_id=0)
    -   Use the hash as a key to RC4 cryptography
    -   Repeat this `rc4_crypto_passes` times
    -   Derive a key by Concatenating `pepper + key + salt` and hashing it using the most secure hashing function supported by pDBv1 (hash_id=0)
    -   Encrypt the final data using RC4 and the simpler derived key
-   AES encryption (main source of "robust" encryption)
    -   Generate 16 random bytes and append them to the data, this is done before the main loop
    -   Generate a salt of `hash_salt_length` bytes
    -   Use PBKDF2(HMAC) with the configured hashing function, generated salt, and `pbkdf2_hmac_passes` passes to derive a 32-byte key from the database password/key
    -   Generate a 16-byte random IV for AES
    -   Append `pepper` to the data, assume `data = data + pepper` now
    -   Derive a 12 byte nonce from `key + iv` using PBKDF2(HMAC) with salt being the before mentioned salt
    -   Encrypt the data using AES in GCM mode with the previously mentioned nonce
    -   Pad the ciphertext using PKCS7 to block size of 128 bytes
    -   Concatenate `salt + iv + data`
    -   Process is repeated `aes_crypto_passes` passes
-   ChaCha20 encryption (main source of "secure" encryption)
    -   Generate a random 16-byte nonce
    -   Generate a salt of `hash_salt_length` bytes
    -   Prepend `pepper` to the data, assume `data = pepper + data` now
    -   Use PBKDF2(HMAC) with the configured hashing function, generated salt, and `pbkdf2_hmac_passes` passes to derive a 32-byte key from the database password/key
    -   Apply the ChaCha20 encryption algorithm
    -   Concatenate `nonce + salt + data`
    -   This process is repeated `chacha20_crypto_passes` times

All of these implement multiple encryption in one way or another to improve security along with salting, peppering, and derivation.
Please note that whenever this document refers to 'RC4', 'AES', or 'ChaCha20' it is referring to the noted encryption methods
above.

### Why RC4?

RC4 is a very simple, allbeit insecure, encryption algorithm. In our case it will only serve obfuscation purposes,
which is fine, as most of the security is handled by very well tested encryption algorithms - AES and ChaCha20.
RC4 is there just to provide so-to-say a "condom" for the really secure parts. The RC4 passes will not only introduce
entropy, it'd make it harder for people to break in if the before mentioned encryption algorithms are somehow broken.

### Complexity

The database format is complex, and requires a lot of code and logic to be implemented. This is by design.

The format has many redundant parts, just in case one part fails, others can handle it well. The redundancy also
helps to add a lot of entropy, unpredictability, authentication, and integrity checks.

## Metadata

The metadata section of the database is nothing but data, it will just be stored to give the client or the user more context on the database:

    Key: Value
    This is a key: This is a value

The metadata may be cleared or changed at any point, and it should not include any sensitive information.
It is stored in plain text in the database and may include things such as contact information (for example in a case of a database leak)

## Entries

Entries have the following structure outline:

    [hash] [hash][ident][size][data] [hash][ident][size][data] ...
    [null]
    [hash] [hash][ident][size][data] ...
    ...

Ignore the spaces.

-   `uint8_t hash[hash_size]` (`<{hash_size}B`) -- The hash of the rest of the entry (including all identifiers, sizes, hashes, and data)

-   `uint8_t ident` (`<B`) -- The entry field identifier, may be NULL. The identifiers cannot repeat, and if they do - the latest one's value dominates (like a hashmap)
-   `uint64_t size` (`<L`) -- The size of the entry data
-   `uint8_t dhash[hash_size]` (`<{hash_size}B`) -- The hash of the entry data
-   `uint8_t data[size]` (`<{size}B`) -- The data the field holds

... And so on

Standard fields include:

-   `t`: of Type the entry (plain text)
    -   `p`: Password store
    -   `t`: TOTP store (some clients may use this type to generate & copy TOTP codes instead of the TOTP key)
-   `n`: Name of the entry
-   `r`: Remark of the entry (RC4 encrypted, **DO NOT STORE SENSITIVE INFO IN REMARKS**)
-   `e`: Encrypted section of the entry (an encrypted and compressed entry)
    -   `u`: Username
    -   `p`: Private value of the entry (password, TOTP key)

The only reserved fields are the lowercase ASCII letters + numbers (36 identifiers), so use them with caution.

### Validation

For entries to be considered valid, they must satisfy the following conditions:

-   Have a valid structure
-   The hash of the entry must be valid
-   The size of the data is exactly as stated by `size`
-   The entries are separated by NULL (this will naturally validate itself while parsing the database)

### Encryption & Compression

The `t` and `n` fields are stored as plain text in the database.

The `r` field has an RC4 obfuscation layer on top of it, which is why you should not store sensitive information
and information relevant to the entry (such as url, or search keywords).

And the `e` section is where things get interesting, as its value is another constructed entry which has all the
relevant sensitive information of the entry. All the field values in that entry are encrypted using ChaCha20.
Then the whole entry is then encrypted using RC4, then with ChaCha20, at which point the output is compressed using ZSTD.
Then it is encrypted using AES.

    Fields -> ChaCha20
    Entry -> RC4 -> ChaCha20 -> ZSTD -> AES

The fields are enough to be encrypted using ChaCha20, as they'll be behind multiple encryption layers.
The entry itself will first undergo RC4 encryption, which will produce large output due to excess bytes,
then ChaCha20 will be applied to encrypt the less secure RC4 data, at which point the output will be pretty
big, so we compress it. Then a final layer of encryption is applied - AES - which will ensure maximum security
of the database whilst maintaining a sane size.

## Security, clients & questions

Email <ari@ari.lt> for any security questions or questions about the specification and I will be sure to update
the format, or clarify your questions. Also, if you make a client for pDB which you'd like to be added to this
specification, feel free also also contact me :) (although note that creating a client is an extremely complex task,
please make sure you understand and test your client, if you haven't - please note that in the project and leave it
in the beta stage, until you think it has been tested by time)

Your contribution matters!

## pDBv1: Authors

-   Ari Archer \<<ari@ari.lt>\> \[<https://ari.lt/>\]
