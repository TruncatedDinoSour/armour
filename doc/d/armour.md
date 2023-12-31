# armour the python package

armour is a python package which implements a bunch of things for dealing with passwords
and other sensitive data, strong focus on passwords

the package is responsible for the following things :

-   hashing
    -   support for both hmac + pbkdf2 + salted and normal hashing
    -   support for a wide range of hashing algorithms
        -   SHA3-512
        -   BLAKE2b
        -   SHA512
        -   SHA3-384
        -   SHA512-256
        -   BLAKE2s
        -   SHA384
        -   SHA3-256
        -   SHA512-224
        -   SHA256
        -   SHA3-224
        -   SHA224
        -   SHA1
        -   SM3
        -   MD5
-   cryptography
    -   aes w tweaks
        -   generate a salt of `hash_salt_len` bytes
        -   use `PBKDF2HMAC` with the `hash_id` as the hash and `salt` as the generated salt, with `kdf_passes` passes
        -   generate a 16-byte iv and use it in cbc
        -   use pkcs7 as the padder which pads to block size of 128
        -   process is repeated `aes_crypto_passes` passes, for multiple encryption which should increase the security more
        -   will always return bytes
    -   fernet w tweaks
        -   appends `hash_salt_len` random bytes to the output, to add more entropy
        -   fernet ( symmetric encryption ) + pbkdf2 with ur password and salt + hmac, which is a secure way of encrypting data
        -   process is repeated `sec_crypto_passes` passes, for multiple encryption which should increase the security more
        -   zstd `zstd_comp_lvl` lvl compression, for more entropy and entropy
        -   base85 encoding, the highest entropy usable text encoding in our case
        -   will always return base84 encoded text as bytes
    -   rc4 encryption ( insecure ) w twaks
        -   generates `hash_salt_len + 13` random bytes
        -   prepends 5 random bytes to the data, to introduce more entropy
        -   appends 5 random bytes to the data, to introduce more entropy
        -   encrypts using rc4 with the key being derived from securely hashing `password + salt`
            using the most secure ( hash_id=0 ) hashing algorithm, to not leak the pw or salt as rc4 is insecure
        -   process is repeated `isec_crypto_passes` passes, for multiple encryption which should increase the security more
        -   will always return bytes
-   password generation
    -   customizable and secure password generation based off criteria
-   password information
    -   password length
    -   lowercase letters
    -   uppercase letters
    -   nummerical characters
    -   special characters
    -   password alphabet
    -   password alphabet combinations
    -   password sequences
        -   like he[ll]o, t\[hhh][iiiii]s
    -   total sum of all password sequences
        -   he[ll]o might have 1 sequence but its 2 chars so itll return 2
    -   common patterns
        -   qwerty, 12345, zxcvbn, ...
    -   total sum of all common patterns
        -   if we have like woah[qwerty] itll return 5, not 1
    -   entropy bits
        -   entropy by frequency analysis
    -   general strength factor
        -   based on entropy, length and alphabet combos
    -   general sweakness factor
        -   based on sequences count, common patterns count, lowercase letters,
            uppercase letters and numetical characters
    -   realistic strength factor
        -   based on strength, alphabet length and weakness
-   implementing pDB database format
    -   entries
        -   entry types
            -   raw entries
            -   password entries
                -   encryption / decryption
                -   structure check
        -   decryption / encryption
        -   parsing
        -   validation
        -   hashing
    -   exceptions
    -   header
        -   parsing
        -   decryption / encryption
        -   validation
        -   hashing
    -   structures while working w bin data
