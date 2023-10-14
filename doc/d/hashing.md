# hashing in armour

armour supports following hashing algorithms :

| hash id | hashing algorithm |
| ------- | ----------------- |
| 0       | SHA3-512          |
| 1       | BLAKE2b           |
| 2       | SHA512            |
| 3       | SHA3-384          |
| 4       | SHA512-256        |
| 5       | BLAKE2s           |
| 6       | SHA384            |
| 7       | SHA3-256          |
| 8       | SHA512-224        |
| 9       | SHA256            |
| 10      | SHA3-224          |
| 11      | SHA224            |
| 12      | SHA1              |
| 13      | SM3               |
| 14      | MD5               |

and all of them can b used standalone or with hmac + pbkdf + salt, the
2 nd option is more secure

all hashing functions can b found in `armour.crypto` :

-   `hash_algo` -- standalone hashing
    -   just takes in the `hash_id` and `data` to hash
-   `hash_walgo` -- hashing w hmac + pbkdf2 + salt
    -   takes in `hash_id` and `data` as per standard
    -   then takes in the key and the salt to pass to pbkdf2
    -   takes in `kdf_iters` ( aka kdf passes ) --
        how many iterations of kdf to apply, higher the value, the more secure
    -   `hash_salt_len` -- the randomly generated salts length for the hash
    -   workings
        -   generates a `hash_salt_len` cryptographically secure random salt
        -   creates hmac with pbkdf2
        -   passes the salt as the random salt
        -   sets the iterations to passed in iterations
        -   derives the key from `key + salt` concat
        -   prepends the salt to the final hash
-   `hash_walgo_compare` -- compares 2 `hash_walgo` hashes
    -   takes in the same arguments as `hash_walgo` + `target` which is the target hash

the hashing algorithms are used in many places and the main concept while using this api r
hash ids -- an index in the `HASHES` tuple, those depend on the version of pDB database format

## example

```py
>>> import armour
>>> armour.crypt.hash_algo(0, b"hello world")  # sha3-512
b'\x84\x00\x06e>\x9a\xc9\xe9Q\x17\xa1\\\x91\\\xaa\xb8\x16b\x91\x8e\x92]\xe9\xe0\x04\xf7t\xff\x82\xd7\x07\x9a@\xd4\xd2{\x1b7&W\xc6\x1dF\xd4p0L\x88\xc7\x88\xb3\xa4Rz\xd0t\xd1\xdc\xcb\xee]\xba\xa9\x9a'
```
