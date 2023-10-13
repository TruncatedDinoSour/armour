# pDB database format

> pDB is a custom security, entropy, data structure and data integrity focused password database format

## database

format is as follows :

-   `unsigned char magic[4]` ( 4 little endian bytes, `<4B` ) -- the magic bytes, always `pDB\xf6`
    -   the `0xf6` byte is a sum of ascii values of `p`, `D` and `B` to increase the uniqueness of the magic bytes
-   `unsigned short version` ( 2 little endian byte, `<H` ) -- the database version starting from 0
-   `unsigned char hash_id` ( 1 little endian byte, `<B` ) -- the hashing algorithm used for secure hashing and encryption id from 0
    ( the lower the number the less preferred is the hashing algorithm, security being the main factor, consider
    anything above 10 insecure and dont use it if u can )
    -   0 -- SHA3_512 -- best for security
    -   1 -- BLAKE2b
    -   2 -- SHA512
    -   3 -- SHA3_384 -- great security, but less resource intensive than SHA3_512
    -   4 -- SHA512_256
    -   5 -- BLAKE2s -- good for security while not being as resource intensive
    -   6 -- SHA384
    -   7 -- SHA3_256 -- great balance between security and speed
    -   8 -- SHA512_224
    -   9 -- SHA256 -- good balance between security and speed
    -   10 -- SHA3_224
    -   11 -- SHA224
    -   12 -- SHA1 -- good for speed while still being not as bad as md5
    -   13 -- SM3
    -   14 -- MD5 -- best for speed
-   `unsigned char hash_salt_len` ( 1 little endian byte, `<B` ) -- when using the hash how long should the salt be
-   `unsigned long kdf_passes` ( 4 little endian bytes, `<L` ) -- the passes for `PBKDF2HMAC`
-   `unsigned char zstd_comp_lvl` ( 1 little endian byte, `<B` ) -- the zstd compression level ( from 0 to 22 )
-   `unsigned short sec_crypto_passes` ( 2 little endian bytes, `<H` ) -- the count of custom secure encryption to do every time we encrypt
-   `unsigned short isec_crypto_passes` ( 2 little endian bytes, `<H` ) -- the count of insecure encryption to do every time we encrypt
-   `unsigned char entries_hash[hash_digest_len]` ( `hash_digest_len` of `hash_id` hash bytes, `<{hash_digest_len}s` ) -- the secure database entries hash
-   `unsigned char *entries` ( rest of the database, `<{n}s` ) -- the database itself
-   `unsigned char db_hash[hash_digest_len]` ( `hash_digest_len` of `hash_id` hash bytes, `<{hash_digest_len}s` ) -- the secure full database hash

### auth

-   password for the database password
-   salt for the database salting of some hashes ( e.g. the full db hash and the entries hash )
-   `isec_crypto_passes` and `sec_crypto_passes` are separated because insecure encryption is mainly there to
    be there as a small layer for the actual encryption and the insecure encryption is made to be fast so you can
    have way more passes of insecure than secure

### validation

-   the database hash is verified before trying to parse the database
-   the database magic is compared to a constant string `pDB\xf6`, if invalid, quits
-   the version is checked before loading the database, if the current library, parser, etc has another version,
    -   versioning is incremental starting from 0 ( 0, 1, 2, 3, 4, ... )
        it quits and / or possibly provides migration or backporting
-   `zstd_comp_lvl` is checked if its within bounds of `[0;22]`
-   the database entries hash is verified before trying to parse the entries
-   the database entries are validated ( their hashes ) before trying to use them

## crypto

-   ( custom ) rc4 ( insecure ) encryption
    -   appends 32 random bytes to the data ( not in the loop ), to introduce more entropy
    -   encrypts using rc4 with the key being derived from securely hashing `password + salt` using the most secure ( hash_id=0 )
        hashing algorithm, to not leak the pw or salt as rc4 is insecure
    -   process is repeated `isec_crypto_passes` passes, for multiple encryption which should increase the security more
    -   **note** that rc4 is not a secure algorithm and its only used because its fast and isnt as insecure as xor encryption,
        it gives the best balance for what were looking in our use case -- entropy and an extra thin layer of security
    -   will always return bytes
-   ( custom ) secure encryption
    -   fernet ( symmetric encryption ) + pbkdf2 with ur password and salt + hmac, which is a secure way of encrypting data
    -   process is repeated `sec_crypto_passes` passes, for multiple encryption which should increase the security more
    -   prepends `hash_salt_len * 2` random bytes to the final output, to add more entropy
    -   zstd compression, to reduce the size, add more data validation and add more entropy
    -   appends `hash_salt_len` random bytes to the output, to add more entropy
    -   fernet ( symmetric encryption ) + pbkdf2 with ur password and salt + hmac, final encryption step ensuring peak security
    -   will always return base64 encoded bytes ( because fernet )

## hashing

-   secure hashing
    -   uses ur selected algorithm as the base
    -   generates a random `hash_salt_len` byte salt, for more entropy and uniqueness of a hash
    -   pbkdf2 + hmac using the generated salt as the generated salt and the password of the database as the password
    -   prepends the salt to the final hash, so we know what salt to use when comparing hashes

## entries

entries are converted into a single `unsigned char *` and its like this :

-   format
    -   `unsigned char char[hash_digest_len]` -- the entry hash
    -   fields
        -   `unsigned char ident` ( 1 little endian byte, `<B` ) -- the field identifier
        -   `unsigned long long size` ( 8 little endian bytes, `<Q` ) -- the size of the field
            -   fields of length `0` are not valid
        -   `unsigned char data[size]` ( `size` little endian byte, `<{size}B` ) -- the field data
    -   standard fields
        -   `n` ( required, all chars in range of [1;255],
            base64 encoded ( so it can have 0x0 in its name ) ) -- the name of the field
        -   `u` ( required, custom secure encrypted ) -- the username
        -   `p` ( required, custom secure encrypted ) -- the password
        -   `m` ( optional, custom secure encrypted ) -- the metadata
    -   examples
        -   `<hash>n\x08\x00\x00\x00\x00\x00\x00\x00bmFtZQ==u\x<><crypt>p\x<><crypt>`
        -   `<hash>n\x08\x00\x00\x00\x00\x00\x00\x00bmFtZQ==u\x<><crypt>p\x<><crypt>m\x<><crypt>`
-   entries are separated by null bytes `\0`

### entries db

-   secure hash all encoded entries together and prepend the hash, for data validation and entropy
-   zstd compression, for size reduction, data validation ( wont work if its invalid zstd data ) and entropy
-   custom secure encryption, to ensure everything is concealed very securely
-   custom rc4 encryption as a thin layer of security and also making the db more entropic

## user friendliness

the user friendliness of the db format can sometimes be a bit overwhelming for users,
so if ur making a user<->db interface here are suggestions :

-   `hash_id` -- have a slider which could b named 'security' and higher it is pick a lower value
-   `hash_salt_len` -- have a slider from like 16 to 128 and make it clear that a higher value means more security
-   `kdf_passes` -- id suggest going w something like 384000, but u can also have a slider going from like 1 to 500000
-   `zstd_comp_lvl` -- another slider from 0 to 22 which could b labeled 'size' or 'compression'
-   `sec_crypto_passes` -- another slider, keep in mind the range for this should b low as secure cryptography is very resource intensive,
    but maybe base it off resources and some calculations ?
-   `isec_crypto_passes` -- another slider, this one can have a large range, 1 ( well u can also have 0 but that means disabled ) to 65536 ( max value )
-   keep in mind to make users choose strong passwords
-   maybe randomly generate the salt using like `os.urandom()` or something

or maybe use presets with pre-configured options, or maybe configure everything based
off the users hardware and stuff
