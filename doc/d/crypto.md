# cryptography in armour

armour provides 3 means of encryption and decryption :

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

all cryptography functions can b found in `armour.crypto` :

- `encrypt_aes` -- aes encryption
    - takes in `data` to encrypt, and `password` for it, and takes in the usual `hash_id`, `kdf_iters`, `hash_salt_len` and
      as all encryption algorims in this library r multiple -- `aes_crypto_passes`
- `decrypt_aes` -- aes decryption
    - takes in the same arguments as `encrypt_aes`
- `derive_secure_key` -- derives a fernet key
    - takes in `password`, `salt`, `hash_id` and `kdf_iters` arguments, which have alrd been discussed
- `encrypt_secure` -- fernet encrypt data
    - takes in `data`, `password`, `salt`, `hash_id`, `sec_crypto_passes`, `kdf_iters` and `zstd_comp_lvl` arguments,
      `zstd_comp_lvl` is between 0 and 22, 22 being the best compression
- `decrypt_secure` -- fernet decryption
    - takes in same arguments as `encrypt_secure` except `zstd_comp_lvl`
- `crypt_rc4` -- lowest level rc4 encryption
    - takes in the `data` and `key`, decryption is passing the output of that function as data and key as key
- `encrypt_rc4` -- rc4 ( insecure ) encrypt data
    - takes in `data`, `isec_crypto_passes`, `password`, `salt` and `hash_salt_len`
- `decrypt_rc4` -- decryption of insecure rc4
    - takes the same arguments as `encrypt_rc4`

keep in mind rc4 is not a secure encryption function, its very fast,
use it as a thin layer of obfuscation and encryption if u so choose to

## example

```py
>>> import armour
>>> armour.crypt.encrypt_rc4(b"my very secret data", 2, b"p4sw0rd124", armour.crypt.RAND.randbytes(20), 12)
b'\xc3<?\xae\xca\xd3\xc76>\xa2G\xc3\x90P\x8dm\xac\xddOY(\x8br\xe0\xce\xa1\xa6\x8e\x03\xdd\xa9\xf76\x18\xee\x87\xe2{\x8e\xb58\x8d\x12\x95\xee+\x1dW\xc0\x0b\x05\xc2?\x89jU\x9b\xcb\xaa\x15i\xfb\xa1\x97'
```
