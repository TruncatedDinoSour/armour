# pdb header in armour

pdb header collects all data found in the database and verifies that everything is okay
before going any further w parsing, the header object can b found in
`armour.pdb.header`, the `PdbHeader` class

`PdbHeader` takes these arguments and has these properties :

-   `password` -- the database password
-   `salt` -- the database salt value
-   `magic` -- the database magic
-   `version` -- the database version
-   `hash_id` -- the database hash id
-   `zstd_comp_lvl` -- the zstd compression level
-   `hash_salt_len` -- the hash selt length used in hashes and encryption
-   `kdf_passes` -- passes for pbkdf2
-   `sec_crypto_passes` -- secure encryption passes
-   `isec_crypto_passes` -- insecure encryption passes
-   `aes_crypto_passes` -- aes encryption passes
-   `entries_hash` -- entries hash
-   `entries` -- the entries themselves
-   `db_hash` -- the database hash
-   `encrypted` -- is the database encrypted ( `True` by default )

although ull probably wanna use `PdbHeader.from_db()` or `PdbHeader.empty()` functions
rather than constructing the db urself

`PdbHeader` provides these instance and class methods :

-   `dds(hash_id: int) -> int` -- returns the hash digest size based off the `hash_id`
-   `ds(hash_id: int) -> int` -- returns the hash digest size together w salt length
-   `PdbHeader.empty(password: bytes = b"", salt: bytes = b"")` -- returns an unencrypted empty database
-   `PdbHeader.from_db(db: bytes, password: bytes = b"", salt: bytes = b"")` -- create a `PdbHeader` from a pDB database
-   `hash_entries()` -- hashes the entries and returns their hash
-   `hash_db(db: bytes)` -- hash a database and return its hash
-   `to_db()` -- creates a database wout a database hash
-   `to_pdb()` -- create a full pDB database ( what u wanna use when dumping )
-   `encrypt()` -- encrypts the database entries ( so the db itself )
-   `decrypt()` -- decrypts the database entries ( so the db itself )

## example

```py
>>> import armour
>>> print(armour.pdb.header.PdbHeader.empty().encrypt())
version             0
magic               b'pDB\xf6'
hash_id             0 ( 'sha3-512' )
zstd_comp_lvl       22 ( ~100.00% )
hash_salt_len       19
kdf_passes          384000
sec_crypto_passes   8
isec_crypto_passes  64
aes_crypto_passes   8
entries_hash        <... 0 bytes>
entries             <... 3917 bytes>
db_hash             <... 0 bytes>
encrypted           True
digest_size         83
```
