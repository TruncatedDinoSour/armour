# pDB database format -- version 1 (alpha)

**Note: This version of pDB is still in early alpha stages. Do not implement this or use this format yet in production.**

This is the official pDB specification document describing the exact structure of the pDB (version 1) (pDBv1)
file format. Its purpose is to serve as detailed documentation for any implementations of this format, such as SDKs,
clients and other pieces of code utilizing it.

## Introduction

Password Database Version 1 (pDBv1) is a little-endian, secure, encrypted password database as a successor of pDBv0.
pDB uses multiple rounds of different well-tested cryptographic algorithms to ensure security of the database, as well
as using secure hashing algorithms, and cryptographically secure sources of randomness.

pDBv1 should now be the preferred format for modern pDB databases, as it improves many parts of it, such as:

-   Encryption and hashing enhancements
    -   pDBv1 uses more robust encryption methods and a more secure layered cryptography approach.
    -   Force SHA3-512, SHA3-256, and Argon2 for key derivation.
    -   Support for more secure encryption schemes: RSA 4096, ChaCha20-Poly1305, AES in GCM mode, Threefish 1024.
    -   Better entropy and integrity of the database.
-   Improved key management
    -   RC4 is no longer used in sensitive encryption layers, it is used for obfuscation uses.
-   Better key management
    -   pDBv1 introduces support for pKfv0 (pDB Keyfile version 0), which has support for rotating keys and cryptographically secure salts.
    -   Introduction of interdependence between the Keyfile and the database adds an extra layer of authentication.
-   Flexibility and Customization
    -   Made the format more flexible and dynamic.
    -   Simplify parts of the structure, allowing the format to be more flexible and dynamic.
    -   Added support for dynamic entries by chunking, allowing for better scalability.
    -   Added support for locking and concurrency.
    -   Added support for SNAPI - Standard Network Application Programming interface - to use pDB over the network.
-   Metadata support
    -   Introduce metadata to the format.
    -   Have a human and machine -readable structure for the metadata.
    -   Add standard metadata keys, such as contact information.
-   Improved Validation and Integrity
    -   Enhanced the validation criteria, add a comprehensive list of conditions, and ensure the integrity
        and security of the database
-   Better documentation and standardization
    -   Use of more standard language, features, and algorithms.
    -   More comprehensive and detailed technical documentation.
    -   Better structure of the specification.
    -   Formal language.
    -   Introduction of pseudocode.
    -   More emphasis on cryptographic security.
    -   Define common algorithms used to manage the database.
    -   Add standardized file types.
-   Future-proofing
    -   Added considerations for possible attacks.
    -   Considering post-quantum encryption algorithms for the future.

## Strengths of pDBv1 and areas for improvement

pDBv1 is meant to be an open format, and even though it aims to be the perfect format, total perfection is not
possible and imperfections are unavoidable in some cases. This section is meant to list the strengths of pDBv1
and where it could theoretically be improved.

### Strengths

-   Multi-Algorithm encryption: Provides a layered security approach and reduces the possibility of outer layer failures.
-   Argon2 usage: Argon2 is used for key derivation, making it harder to brute-force.
-   Key management and rotation: The keys are rotated and expire as per the new Keyfile format, making it harder to decrypt the whole database.
-   Cryptographic randomness: The version 1 of pDB places more emphasis on cryptographic randomness, making it more secure. It also adds more places for entropy.

### Areas for improvement

-   Complexity and Performance: The format is fairly complex, and the performance of it, mainly because of the complexity, isn't great.
-   Quantum resistance: The format has theoretical weaknesses for when powerful quantum computers become a thing. For future-proofing it may be beneficial to look into it.
-   Side-Channel attacks: There's a possibility of side-channel attacks in the AES layer. Even though it's not much of a problem on a local system, it should still be looked into harder.

## Clients

This section includes a list of SDKs, libraries, user interfaces, etc. (collectively called "clients") which support the pDBv1 format.

-   [Stable, Official] Armour SDK from the Armour project by Ari Archer \<<ari@ari.lt>\> licensed under GPL-3.0-or-later: <https://ari.lt/gh/armour>
    -   [Stable, Official] "Pwdmgr" Client from the Pwdtools project using Armour SDK By Ari Archer \<<ari@ari.lt>\> licensed under GPL-3.0-or-later: <https://ari.lt/gh/pwdtools> (Client ID: `Pwdmgr`)

If you're planning on implementing a client, you must get familiar with the whole specifications of Keyfile, pDB, and optionally SNAPI.
It is a complex task requiring a lot of different implementations of different algorithms.

## File identifiers

-   File extension: `.pdb`
-   MIME type: `application/pdb`, `application/x-pdb`
-   Magic number: `pDB\xf6` (`0x70 0x44 0x42 0xf6`, `0x704442f6`, `1883521782`)

## Supported Keyfile versions

This is a list of all supported Keyfile versions.

-   Keyfile version 0

## Database

This section describes the abstract database format, the generic structure of the header and order of data and dynamic sections in the database.

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type                   | Name                     | Description                                                                                                                                         |
| ------------------------ | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `uint8_t[4]`             | `magic`                  | The magic number of the file. Always a constant value.                                                                                              |
| `uint16_t`               | `version`                | The version of the database. A constant value per-version. (in the case of pDBv1 case - `0x01`)                                                     |
| `uint8_t`                | `ZSTD_compression_level` | The ZSTD compression level of the database from 0 to 22.                                                                                            |
| `uint8_t`                | `Argon2_type`            | Argon2 key derivation function type (discussed below).                                                                                              |
| `uint32_t`               | `Argon2_time_cost`       | Argon2 key derivation function Time Cost parameter. Represents the number of iterations in the hash function.                                       |
| `uint32_t`               | `Argon2_memory_cost`     | Argon2 key derivation function Memory Cost parameter. A larger memory cost makes the hash function require more memory.                             |
| `uint64_t`               | `psalt_size`             | The size of the `psalt` following this argument.                                                                                                    |
| `uint8_t[psalt_size]`    | `psalt`                  | When opening a pDB Keyfile, a `psalt` (password salt) is passed to it to cross-authenticate, this is used to salt the password.                     |
| `uint16_t`               | `salt_size`              | Whenever a salt is required in the database, this number is used as a base salt length.                                                             |
| `uint16_t`               | `authentication_size`    | When authentication data is generated in the database, how big should it be?                                                                        |
| `uint16_t`               | `keyfile_crypto_passes`  | The Keyfile encryption/decryption passes. (passed to the Keyfile)                                                                                   |
| `uint16_t`               | `chunk_identifier_size`  | The chunk identifier size in bytes. You can calculate the maximum possible entry count using `f(x)=256^{x}-1` where `x` is `chunk_identifier_size`. |
| `uint16_t`               | `chunk_size`             | The chunk size of encrypted entries in the database. `chunk_size` must be larger then `chunk_identifier_size`.                                      |
| `uint8_t[64]`            | `metadata_hash_SHA3_512` | The SHA3-512 hash of the metadata following it (including the size).                                                                                |
| `uint64_t`               | `metadata_size`          | The size of the metadata chunk following the size.                                                                                                  |
| `uint8_t[metadata_size]` | `metadata`               | The human-readable metadata chunk (metadata format is discussed below).                                                                             |
| `uint8_t[64]`            | `header_hash_SHA3_512`   | The SHA3-512 hash of the whole header before this section.                                                                                          |
| `uint8_t`                | `lock`                   | The lock status of the database. See lock statuses below.                                                                                           |
| `uint8_t[]`              | `entries`                | The chunked encrypted entries of the database.                                                                                                      |

Note that cross-dependence on the Keyfile is happening. Keyfile depends on some parameters of the database, and the database depends on some parameters of the Keyfile.
In the keyfile these parameters have a `db_` prefix, meaning these are the cross-dependent parameters from the Keyfile to the database:

-   `db_AES_crypto_passes`
-   `db_ChaCha20_Poly1305_crypto_passes`
-   `db_pepper`

While the Keyfile depends on:

-   `Argon2_type`
-   `Argon2_time_cost`
-   `Argon2_memory_cost`
-   `psalt`

Don't be confused when you see those parameters in this document, assume they come from the Keyfile.

### Argon2 type

-   `0x00` - Argon2D - faster and makes better use of available processing power, thus making it more resistant against GPU cracking attacks, however, it is more susceptible to side-channel attacks.
-   `0x01` - Argon2I - slower and uses more memory, making it more secure against attacks that aim to determine a password by trying every possible combination, however, it's not as resistant against GPU attacks as Argon2D.
-   `0x02` - Argon2ID - combines the benefits of both Argon2D and Argon2I by using Argon2I at the beginning and Argon2D for the rest of the process, aiming to maximize the advantages of both processes while minimizing their disadvantages, thus providing a safer hashing algorithm - this is the most recommended Argon2 type.
-   No other types of Argon2 exist yet.

### Lock status

-   `0x00`: Unlocked.
-   `0x01`: Locking.
-   `0x02`: Locked.
-   `0x04`: Releasing.
-   `0x05`: Disabled. (Forever locked, lock handled by a client service)
-   Anything else: Invalid.

### Validation

The following conditions need to evaluate to true for the database to be considered of valid format, these
are in hypothetical order, so you can implement them in any way you want:

-   Magic of the file is correct.
-   Version of the database is supported by the client.
-   Database is unlocked. (jump to `lock`)
-   SHA3-512 hash of the whole header is valid. (jump to `header_hash_SHA3_512`)
-   ZSTD compression level is between `0` and `22` (you can safely check if it's below 23 or below or equal to 23, as the value is unsigned).
-   Argon2 type exists.
-   Argon2 time cost is at least `3`.
-   Argon2 memory cost is at least `65536`.
-   `psalt_size` is at least `256`, so `psalt` is at least 256 bytes. (2048 bits of entropy)
-   `salt_size` is at least `8` (16 bits of entropy).
-   `authentication_size` is at least `64`.
-   `keyfile_crypto_passes` is at least `1`.
-   `RSA_crypto_passes` is at least `1`.
-   `Threefish_crypto_passes` is at least `1`.
-   `chunk_identifier_size` is at least `1`.
-   `chunk_size` is larger than `chunk_identifier_size`.
-   SHA3-512 metadata hash is valid.

## Randomness

Randomness used in any context in this document refers to the concept of cryptographically secure
randomness. Pseudo-randomness is not suitable to use in this format as that jeopardizes the security of it.

Do not implement this format using non-cryptographically-secure number generators.
Prioritize randomness, entropy, and unpredictability wherever possible.

Implementations of the cryptographically secure functions may differ but the result
must stay the same - almost unpredictable, cryptographically secure random numbers.

See: <https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator>, <https://manpages.ubuntu.com/manpages/noble/en/man3/RAND_bytes.3ssl.html> (`RAND_bytes(3)`), <https://en.wikipedia.org/wiki//dev/random>

## Keys

pDB uses the Keyfile format to store keys, this section describes the key workflow.

At any given moment, there should be at least 6 available keys:

-   3 RSA-4096 key pairs
-   3 cryptographically secure salts

They can have any expiration date, but it is recommended to set it to be around 3 months (90 days),
can also randomly generate it using a (cryptographically secure) psudorandom number generator, and should preferably
not all be the same lifetime.

The purpose of having 3 available keys at any given time is to avoid reusing same keys. Any given key type
required should be picked from available keys. If the set of keys it can pick is below 3 keys, keys are provisioned
until there's at least 3 available keys of the queried type. In other words:

    enum KeyType {
        RSA_KEYPAIR,
        CRYPTO_SALT,
    }

    # Assume we have access to the keyfile somehow

    bytes get_key(KeyType key_type) {
        Key keys[] = keyfile.query_for(key_type);

        while (keys.size < 3) {
            # Provision a new key
            Key key = keyfile.provision_new_key(key_type);

            # Save the key in the Keyfile and load it into memory
            keyfile.save(key);
            keys.append(key);
        }

        return select_random(keys);
    }

This would be a base algorithm for selecting a key.
From now, whenever `get_key` is used in pseudocode, assume the above function.

## Hashing

Since pDBv0, most hashing algorithms have been removed and substituted with Argon2.
This is how the new hashing process in a modern pDB database would look:

    bytes hash(bytes data) {
        bytes salt = random(salt_size);

        bytes rotating_salt = get_key(KeyType.CRYPTO_SALT);
        bytes rotating_salt_index = get_key_id(rotating_salt);  # In a real-world scenario the key would come with its ID, depending on the data structure.

        bytes hash = argon2(
            password=(db_pepper + data),
            salt=(rotating_salt + salt),
            length=64,
            ... (parameters determined by the database),
        )

        return salt + as_uint8_le(rotating_salt_index) + hash;
    }

In other words:

-   Generate a `salt_size`-byte cryptographically secure salt
-   Get a rotating salt from the Keyfile, as well its ID.
-   Use Argon2 to generate a 64-byte (512-bit) hash, passing in the pepper bytes and the data together as the password, and the concatenation of the rotating salt and the generated salt as the salt.
-   Return the salt, rotating salt id as `uint8_t`, and hash digest concatenated together. Resulting in a `salt_size + 1 + 64`-byte final hash digest.

## Cryptography

pDBv1 uses 1 asymmetric cipher, 2 block ciphers, and 1 stream cipher to encrypt data:

-   RSA 4096: Asymmetric cipher
    -   Advantages
        -   Very secure due to its large key sizes.
        -   It requires two keys to be encrypted and decrypted, adding another layer of authentication and security.
        -   Widely used and trusted.
    -   Disadvantages
        -   Slow and computationally intensive.
        -   Large key sizes, making it inefficient.
        -   Susceptible to quantum computing attacks.
-   AES 256 in GCM mode: Block cipher
    -   Advantages
        -   Very good security for protecting sensitive data. (such as passwords)
        -   Very efficient and fast.
        -   Offers authentication and is resistant to timing attacks. (GCM mode)
    -   Disadvantages
        -   Can be vulnerable to side-channel attacks.
        -   Not designed to hide data length.
        -   Could be theoretically cracked by powerful quantum computers in the future.
-   ChaCha20-Poly1305: Stream cipher
    -   Advantages
        -   Provides high speed and high level of security.
        -   Designed to eliminate many classes of cryptanalytic attacks.
        -   Poly1305 offers high-speed data authenticity.
    -   Disadvantages
        -   Newer algorithm, meaning it is less tested and known.
        -   Lack of hardware acceleration on many platforms.
        -   Relies on correct nonce management.
-   Threefish 1024: Block cipher
    -   Advantages
        -   Extremely high security level with 1024-bit key length.
        -   Resistant to many cryptanalytic attacks.
        -   Uses tweakable block ciphers which provide additional variability.
    -   Disadvantages
        -   Slower speed compared to other modern algorithms on certain hardware.
        -   The algorithm is pretty complex.
        -   A fairly big key size (128 bytes).

An additional cipher, used for obscurity purposes in non-sensitive operations, is used:

-   RC4: Stream cipher
    -   Advantages: Fast.
    -   Disadvantages: Insecure, broken.

RC4 is not and will not be used for anything sensitive. It is only used as an obfuscation algorithm for some
non-sensitive data.

This is exactly why the general encryption pipeline would look like this:

    RSA4096(ZSTD(AES256(ChaCha20(Threefish(... data ...)))))

1. Starting with Threefish then layering it with ChaCha20 provides good security and performance.
2. AES is used after ChaCha20 to further increase the security of the ciphertext.
3. As RSA isn't very suitable for encrypting large blobs of data, we compress it using ZSTD, which will add integrity insurance to our data, increase its entropy, and will also make the size of data reasonable.
4. Then RSA is applied, to take advantage of its public/private key infrastructure for an additional layer of security, and to finish off the cryptography.

To address the quantum encryption worries, please read "Quantum computing" subsection below.

### RSA 4096

RSA-4096 is an encryption algorithm that provides strong security features with a 4096-bit (512-byte) key.
RSA stands for Rivest-Shamir-Adleman, the inventors of the algorithm. Is it a widely used algorithm used in
digital certificates (such as SSL) to establish secure connections over the internet, secure email, remote
VPN access, software licensing, etc. RSA 4096 provides a high level of security, but also requires more
processing power. It is known to be theoretically vulnerable to quantum computers in the future.

Because of the intensity of the algorithm, and to avoid uncovering patterns, only a single pass of RSA
is applied like this:

    # public_key = get_key(RSA_KEYPAIR);

    bytes encrypt_rsa(bytes data, bytes key) {
        bytes ciphertext = "";

        for chunk in split(data, 382) {
            bytes label = random(authentication_size);

            OAEP oaep = OAEP(
                mgf=MGF1(algorithm=SHA512),
                algorithm=SHA512,
                label=(label + db_pepper),
            );

            bytes rsa_ciphertext = RSA4096.encrypt(data=chunk, pk=public_key, padding=oaep);

            ciphertext = ciphertext + label + as_uint16_le(rsa_ciphertext) + rsa_ciphertext;
        }

        return sha3_512(ciphertext) + ciphertext;
    }

In other words:

-   Chunk the cleartext into 382 byte chunks or smaller.
    -   When using OAEP padding, `max data size = key size - 2 - hash * size - 2`, so `512 - 2 * 64 - 2` which equals to 382.
-   Loop over all chunks.
-   Generate a random `authentication_size`-byte label.
-   Use Optimal Asymmetric Encryption Padding (OAEP) with the MGF1 (Mask Generation Function), both using the SHA512 hashing function.
-   Pass the chunk to RSA 4096, with the OAEP padding.
-   To the ciphertext append the label, RSA ciphertext length (chunk ciphertext) as 2-byte little-endian `uint16_t`, and the chunk ciphertext.
-   Repeat the process until there's no more chunks left.
-   Using the SHA3-512 hashing algorithm, hash the final ciphertext, and prepend it to the final ciphertext.

This implementation will improve the security, authenticity, and integrity of the data. It also has multiple advantages to just RSA 4096:

-   It can encrypt any amount of data, by splitting it into 382-byte blocks. (however, this doesn't make RSA a block cipher)
-   It generates a random label for every block, adding more entropy and security.
-   It hashes all ciphertext, ensuring there's no tampering going on with it.

RSA 4096 in our use case is theoretically vulnerable to the following vulnerabilities:

-   Quantum computing: As previously mentioned, RSA is theoretically vulnerable to quantum computing.

See: <https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding>, <https://en.wikipedia.org/wiki/Mask_generation_function>

### AES 256

AES-256-GCM is an encryption algorithm that offers robust security characteristics with a 256-bit key.
AES stands for Advanced Encryption Standard, a cryptographic specification by NIST (U.S. National Institute of Standards and Technology).
GCM refers to Galois/Counter Mode, a mode of the AES for fast and secure encryption. AES255-GCM is generally used in secure file transfer,
Virtual Private Networks (VPN), secure web connections, and for the encryption of data. AES256-GCM not only provides a high level of security,
but also is highly efficient in terms of processing needs. GCM mode of AES also provides data authentication, which helps to ensure the
cipher- or clear- text was not tampered with in any way.

As it's a fairly efficient symmetric block cipher, it can be ran multiple times easily without major issues, enhancing
the security and depth of the encryption. Here's how pDBv1 utilizes AES 256 in GCM mode:

    # salt = get_key(CRYPTO_SALT);

    bytes encrypt_aes(bytes data, bytes database_password, bytes salt) {
        bytes initial_salt = random(32);

        # `n` starts at 0 and ends at the value db_AES_crypto_passes is

        for n in repeat(db_AES_crypto_passes) {
            # Pad the data

            number padding_size = 15 - (len(data) % 16);

            if (padding_size > 0) {
                data = data + random(padding_size);
            }

            data = data + as_uint8_le(padding_size);

            # Encrypt

            bytes aes_salt = random(salt_size);

            bytes iv = argon2(
                password=(aes_salt + db_pepper + database_password),
                salt=(salt + initial_salt),
                length=12,
                ... (determined by the database parameters),
            );

            bytes key = argon2(
                password=(iv + database_password + stringify(n)),
                salt=(aes_salt + salt),
                length=32,
                ... (determined by the database parameters),
            );

            AESGCM aes = AESGCM(
                key=key,
                iv=iv,
            )

            data = aes.encrypt(data + stringify(n));

            # AES256 GCM tag is 16 bytes
            data = aes_salt + aes.tag + data;
        }

        data = initial_salt + data;

        return sha3_512(data) + data;
    }

In other words:

-   The size of padding required is calculated called `padding_size`. As AES256 in GCM mode works on 16-byte blocks, we use the formula `15 - (size_of_data % 16)`, we reserve the 16th byte for the padding size.
-   If the `padding_size` is greater than zero, we generate `padding_size` bytes of cryptographically secure bytes, and append them to the data.
-   Unconditionally, we append `padding_size` to the data, as a `uint8_t`.
-   Generate a 32-byte initial salt called `initial_salt`.
-   It loops `db_AES_crypto_passes` times. Iteration number is stored in `n`.
-   Every loop it generates a `salt_size` cryptographically secure salt called `aes_salt`.
-   A 12-byte Initialization Vector (IV) is derived using Argon2. The Argon2 password parameter is concatenated `aes_salt`, pepper bytes of the database, and the database password. The salt parameter is the rotating salt concatenated with the initial salt.
-   Then, a 32-byte key is derived using Argon2. Password parameter being the IV, database password, and the current iteration number concatenated. The salt parameter is the `aes_salt` and the rotating salt concatenated.
-   Passing in the derived key and IV to AES256 in GCM mode, we encrypt the data concatenated with the current iteration number.
-   Data is reassigned to a concatenation of the generated `aes_salt`, the AES256 GCM tag, and the ciphertext.
-   Process is repeated. After the loop is one, `data` should be the final ciphertext.
-   Then the initial salt is prepended to the final ciphertext.
-   At the end, the final ciphertext along with the initial salt are passed to SHA3-512, the digest is prepended to the final output, and is it returned.

This use of AES256 in GCM mode has multiple advantages over a single pass, such as:

-   Every new encryption call requires a rotating salt from the Keyfile, adding a layer of authentication.
-   Every iteration of the encryption requires a new salt, which helps to increase entropy and make the ciphertext more secure.
-   The final ciphertext is hashed using SHA3-512, ensuring the integrity of data.

AES256 in GCM mode in our use case is theoretically vulnerable to the following vulnerabilities:

-   Side-Channel attacks: If not implanted correctly, AES in GCM mode can leak information through side channel, particularly if keys are reused.

### ChaCha20-Poly1305

ChaCha20-Poly1305 is a combination of two powerful cryptographic algorithms that provide robust security features. ChaCha20, uses a 256-bit key and provides high-speed encryption with less processing power.
Poly1305, is an authenticate code used to check the integrity and authenticity of the data. Together they form ChaCha20-Poly1305, which is a cipher suite primarily used in various secure internet protocols
including TLS and SSH. It is lightweight, secure, and generally believed to be resistant to attacks from quantum computers.

We use multiple passes ChaCha20-Poly1305 to encrypt data like this:

    # salt = get_key(CRYPTO_SALT);

    bytes encrypt_chacha20(bytes data, bytes database_password, bytes salt) {
        bytes initial_salt = random(32);

        # `n` starts at 0 and ends at the value db_AES_crypto_passes is

        for n in repeat(db_ChaCha20_Poly1305_crypto_passes) {
            bytes chacha_salt = random(salt_size);
            bytes authenticated_data = random(authentication_size);

            bytes key = sha3_256(stringify(n) + database_password + db_pepper + salt + initial_salt);

            bytes nonce = argon2(
                password=(key + database_password + db_pepper),
                salt=(initial_salt + salt),
                length=12,
                ... (determined by the database parameters),
            );

            ChaCha20Poly1305 chacha = ChaCha20Poly1305(key);

            data = chacha.encrypt(nonce, data, authenticated_data);

            data = chacha_salt + authenticated_data + data;
        }

        data = initial_salt + data;

        return sha3_512(data) + data;
    }

In other words:

-   A 32-byte initial salt is generated, called `initial_salt`.
-   A loop which iterates `db_ChaCha20_Poly1305_crypto_passes` times, storing the current iteration number in `n`.
-   A `salt_size`-byte salt is generated called `chacha_salt`.
-   A `authentication_size`-byte authentication data is generated called `authenticated_data`.
-   A key a derived using SHA3-256, passing in the current iteration number, database password, database pepper bytes, salt, and the initial salt.
-   A nonce is generated using Argon2 based off the generated key, database password, and database pepper passed as the password, and the salt passed in the initial salt and the rotating salt concatenated.
-   The key is passed to ChaCha20-Poly1305.
-   Using ChaCha20-Poly1305, data is encrypted, passing in the authenticated data.
-   Then, the `chacha_salt`, `authenticated_data`, and the ciphertext are concatenated and data is reassigned.
-   Process is repeated. After the loop is one, `data` should be the final ciphertext.
-   Then the initial salt is prepended to the final ciphertext.
-   At the end, the final ciphertext along with the initial salt are passed to SHA3-512, the digest is prepended to the final output, and is it returned.

The advantages:

-   Uses a key stretching algorithm to generate a key.
-   Uses a unique salt, and pepper to improve the security and entropy of the data.
-   The hashing introduces a data integrity check.
-   Entropy of the whole function is larger, making it more difficult to crack.

ChaCha20-Poly1305 in our use case is theoretically vulnerable to the following vulnerabilities:

-   Nonce handling: ChaCha20-Poly1305 relies a lot on proper nonce handling, and can fall short in security if a nonce is exposed or reused.

### Threefish 1024

Threefish 1024 is a symmetric encryption algorithm that brings robust security features with a 1024-bit (128-byte) key.
It is designed for efficiency in software and provides high security levels. It could be potentially vulnerable to threats
from quantum computers in the future. This algorithm is primarily used in cryptographic systems and protocols for
its significant security benefits.

In pDBv1 we use a single pass of Threefish:

    # salt = get_key(CRYPTO_SALT);

    bytes encrypt_threefish(bytes data, bytes salt) {
        bytes ciphertext = "";

        for chunk in split(data, 127) {
            bytes tweak = random(16);

            bytes key = argon2(
                password=(database_password + db_pepper),
                salt=(salt + tweak),
                length=128,
                ... (determined by the database parameters),
            );

            number padding_size = 127 - len(chunk);

            if (padding_size > 0) {
                chunk = chunk + random(padding_size);
            }

            chunk = chunk + as_uint8_le(padding_size);

            bytes tf_ciphertext = threefish(data=chunk), key=key, tweak=tweak);

            # `tf_ciphertext` is always 128 bytes
            ciphertext = ciphertext + tweak + tf_ciphertext;
        }

        return sha3_512(ciphertext) + ciphertext;
    }

In other words:

-   The data is split into 128-byte chunks or less. Threefish 1024 uses 128-byte blocks, but we reserve the last byte for the padding size.
-   A 16-byte cryptographically secure tweak parameter is generated.
-   A 128-byte key is derived using Argon2, passing in the database password and the secret pepper bytes concatenated as the password, and the rotating salt and tweak concatenated together as the salt.
-   A padding length is calculated using `127 - size_of_chunk`, and if the chunk is less than 127 bytes, it is a positive number, else - zero, call it `padding_size`.
-   If the padding size is more than zero, we generate `padding_size` cryptographically secure bytes and append those to the chunk.
-   The `padding_size` is appended as a `uint8_t`, this is unconditional.
-   The tweak and the ciphertext itself is concatenated and appended to the final output ciphertext.
-   The process is repeated until there's no more chunks left.
-   At the end, the whole ciphertext is hashed using SHA3-512, and the digest is prepended to the whole ciphertext, which is finally returned.

As opposed to just using Threefish, this has several advantages:

-   Similarly to our use of RSA 4096, this can encrypt a lot of data, splitting it into 128-byte chunks.
-   This use of Threefish has increased security through randomness (tweaks and padding), key is derived using Argon2, and uses secure hashing functions.
-   The data integrity is ensured by the SHA3-512 hash.
-   Increased entropy though variable-length cryptographically secure padding.

Threefish 1024 in our use case is theoretically vulnerable to the following vulnerabilities:

-   New algorithm: It is a fairly new algorithm, may uncover some vulnerabilities in the future.

### RC4

This encryption is not used for anything sensitive, it is mainly used for obscurity.
It is a fast stream cipher used for low-security purposes.

Here's how pDBv1 makes use of RC4:

    # salt = get_key(CRYPTO_SALT);

    bytes encrypt_rc4(bytes data, bytes salt) {
        bytes rc4_salt = random(64 + salt_size);

        bytes key = argon2(
            password=(salt + pepper + database_password),
            salt=(rc4_salt + salt),
            length=1024,
            ... (determined by the database parameters),
        );

        bytes ciphertext = rc4(data=(data + rc4_salt), key=key);

        return rc4_salt + ciphertext;
    }

In other words:

-   The algorithm generates a `64 + salt_size`-byte salt called `rc4_salt`.
-   A 1024-byte RC4 key is derived using Argon2, passing in the rotating salt, pepper bytes, and database password as the password. It also gets the concatenation of `rc4_salt` and rotating salt as the salt.
-   The `rc4_salt` is appended to the data.
-   A single round of RC4 is applied.

This cryptography is not used with any other cryptographic algorithm. It is a fast and simple algorithm used for having a single layer of obscure data,
for example remarks or notes which we don't want to store in plain text, but if they're uncovered it doesn't matter.

### Quantum computing

Many modern ciphers are theoretically vulnerable to quantum computers, although at this current time
post-quantum encryption algorithms are not widely used, aren't standard, and/or aren't suitable to use.
This is exactly why we stick to optimizing the longevity of the current systems by using multiple layers
of encryption, widely tested and used encryption algorithms, and key rotation.

Once post-quantum encryption algorithms become suitable for use, are well standardized and trusted, a new pDB
version is expected. Although as this field of cryptography is ever-evolving and still being intensively researched,
it needs time.

## Metadata

The metadata section is a human-readable key-value pair, like this:

    Key: Value
    Key one: Value one
    This is a key!: This is a: value!
    key:Value :)
        KEY:  Value
    Key:
    :

    Invalid.

This would be parsed like this:

| Line                                | Key              | Value               | Explanation                                                                                                                                                                                          |
| ----------------------------------- | ---------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Key: Value`                        | `key`            | `Value`             | A normal key-value pair. Key is `key` because `Key` is up to the `:` and the key is always case-insensitive. The first white-space is ignored, and the rest of the line up to the `\n` is the value. |
| `Key one: Value one`                | `key one`        | `Value one`         | Key is read up to the `:` (semicolon), the first white-space is ignored, and the rest of the line up to the `\n` (newline) is the value.                                                             |
| `This is a key!: This is a: value!` | `this is a key!` | `This is a: value!` | The key is read as normal, the first white-space is ignored, and the value is read up to the newline, as the key was already read, it doesn't matter that it has a semicolon.                        |
| `key:value :)`                      | `key`            | `Value :)`          | A key-value pair as normal, and key is same as the first line because of the case-insensitivity. No first white-space to ignore, so the first character is not ignored.                              |
| `    KEY:  Value`                   | `key`            | ` Value`            | All white-space before the first non-white-space character is ignore. The first white-space before the value is ignored, but the second one isn't.                                                   |
| `Key:`                              | `key`            | NULL                | Invalid line: Empty value.                                                                                                                                                                           |
| `:`                                 | -                | -                   | Invalid line: Empty key.                                                                                                                                                                             |
| -                                   | -                | -                   | Empty line ignored.                                                                                                                                                                                  |
| `Invalid.`                          | -                | -                   | An invalid metadata line (key-value pair) ignored.                                                                                                                                                   |

This, in JSON, would get parsed into something similar to:

```json
{
    "key": ["Value", "Value :)", " Value"],
    "key one": ["Value one"],
    "this is a key!": ["This is a: value!"]
}
```

The metadata format is pretty straight forward:

-   A key is read up to the first semicolon (`:`).
-   After the key, until the first newline (`\n`) is the value.
-   Nor a key nor a value may include a newline.
-   A key must not be empty.
-   A key is case-insensitive and is converted to lowercase at runtime.
-   A value is cannot be empty.
-   A value is case sensitive.
-   The first white-space after a key is ignored if available.
    -   White-space is either `\r` (0xd), `\t` (0x9), `\b` (`0x8`), `\v` (`0xb`) or ` ` (`0x20`)
-   Any white-space before the key (at the start at the line) until the first non-white-space character is ignored.
-   A key my repeat, and the value of the key will get stored in a dynamic array.
-   Any invalid lines are ignored.

### Standard metadata keys

This subsection will give a sample metadata blob in the following format:

    Key:Value (note)

When using the metadata key-value pairs described in this section, you should
ignore the `(note)` and just use the `Key:Value`.

    Client: Pwdmgr (the client that generated the database.)
    Connect: <connection address> (The connection address of the pDB database, usually handled by the 0x05 locking state. See connection address format below.)
    Creation: 2024-03-11 23:21:21 +03:00 (The creation date of the database, YYYY-MM-DD hh:mm:ss +/-HH:MM)
    Email: Ari Archer <ari@ari.lt> [4FAD63E936B305906A6C4894A50D5B4B599AF8A2] (The email(s) of the owner(s) of this database, along with the email owners,
    and gpg keys)
    Matrix: @ari:ari.lt (the Matrix ID of the owner of this database)
    Note: Any note here. (A plain-text note)
    Phone: +442012345678 (Phone number(s) in the international format of the owner(s) of the database)
    Post: PO Box 1235, Cupertino, CA 95015, USA (Postal address of the owner(s) of the database)
    XMPP: ari@ari.lt (The XMPP/Jabber ID of the owner of this database)

#### Connection address

Here are the supported connection address formats for pDB:

-   `pdb://host.name:port/database` - No authentication connection to a database
    -   Required authentication layers: None
    -   Note: Only use this when you know you can trust anyone to access the database. Usually in local scenarios.
-   `mpdb://user@host.name:port/database` - Multi-user server pDB connection to a database
    -   If value of `Connect` is only `mpdb://host.name:port/database` it means 'Connect with your own user and secret(s) (password)'
    -   Required authentication layers: User secret(s) (password)
-   `spdb://host.name:port/database` - Secure authentication connection to a database
    -   This connection _will_ require you to pass the database credentials over the pDB connection to use it,
        usually for servers that may not specifically handle the database on their own, but rather giving a
        server to store databases on and use the database on the server.
    -   Required authentication layers: Database password, database salt (slt)
-   `smpdb://user@host.name:port/database` - Secure multi-user authentication connection to a database
    -   If value of `Connect` is only `smpdb://host.name:port/database` it means 'Connect with your own user and secret(s) (password)'
    -   Same as `spdb`, except with added user-based authentication as in `mpdb`
    -   Required authentication layers: User secret(s) (password), database password, database salt (slt)

Read more about connections in SNAPI documentation.

## Entries

This section describes the format of two entry types:

1. Simple entry: Used as an initial entry, which will be turned into a Complex entry later on. Cannot be directly used in the database.
2. Complex entry: A Simple entry which has gone through the Chunking process described in this document.

### Simple entries

Simple entries are a basic data structure which cannot be used directly in the database due to chunking requirements.
An entry is a collection of fields.

A simple entry has the following structure:

| C type                        | Name         | Description                         |
| ----------------------------- | ------------ | ----------------------------------- |
| `uint8_t[salt_size + 1 + 64]` | `entry_hash` | The secure hash of the whole entry. |
| `uint8_t[]`                   | `fields`     | All of the fields of the entry.     |

Structure of fields is discussed below.

#### Fields

A field is a binary blob which stores a hash of the whole field, its identifier, the size of its data, and the data itself.
This structure provides good data integrity, and 256 fields to work with:

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type                     | Name                  | Description                                                |
| -------------------------- | --------------------- | ---------------------------------------------------------- |
| `uint8_t[32]`              | `sha3_256_field_hash` | The SHA3-256 hash of the whole field.                      |
| `uint8_t`                  | `field_identifier`    | The identifier of the field, which defines the type/value. |
| `uint32_t`                 | `field_data_size`     | The size of the data stored in the entry.                  |
| `uint8_t[field_data_size]` | `field_data`          | The data stored in the entry.                              |

Every field is raw, only the data itself may be encrypted at the field level.

##### Standard fields

Standard fields have 26 reserved identifiers: lowercase ASCII letters from `a` to `z`, or identifiers range `0x61` to `0x7a`.
Be careful when using any of them.

-   `t`: Type of the entry (plain text).
    -   `p`: Password store.
    -   `d`: Derived/computed password store. "No storage" password store.
    -   `t`: TOTP store (some clients may use this type to generate & copy TOTP codes instead of the TOTP key).
-   `n`: Name of the entry (RC4 encrypted, **DO NOT STORE SENSITIVE INFORMATION IN REMARKS**).
-   `r`: Remark of the entry (RC4 encrypted, **DO NOT STORE SENSITIVE INFORMATION IN REMARKS**).
-   `e`: Encrypted section of the entry (an encrypted entry, see encryption subsection below).
    -   If `t` is `p`: Password store.
        -   `u`: Username.
        -   `p`: Password.
    -   If `t` is `d`: Derived password store.
        -   `u`: Username.
        -   `l`: Length of the password as little-endian `uint64_t`.
        -   `p`: Private value.
        -   `s`: Random `salt_size`-byte salt.
    -   If `t` is `t`: TOTP password store.
        -   `s`: Shared secret key.
        -   `t`: Time step as little-endian `uint16_t` in seconds. (commonly 30 or 60 seconds, defaults to 30)
        -   `r`: Time reference as little-endian `uint64_t` in UNIX time. (the initial time from which all OTPs are calculated, UNIX epoch)
        -   `a`: TOTP algorithm. (either SHA1, SHA256, or SHA512. SHA1 by default)
        -   `d`: Digit count. (6-10 digits)

### Complex entries

Complex entries are Simple entries, which go through a specific chunking process.
There's multiple parts to this process:

1. Generating a Chunk ID: Generating a `chunk_identifier_size`-byte Chunk identifier to identify the chunks and group them.
2. Padding the input data: Pad the input data so its length is divisible by `chunk_size` and can be chunked.
3. Chunking the input data: Chunking the now-padded input data.
4. Assigning a Chunk number to every chunk: Numbering the chunks, so they don't have to be stored in order.
5. Assigning a Chunk ID to every chunk: Assigning a Chunk ID to every chunk to group them.
6. Inserting the Chunks into the database: Insert the chunks into the database.

Every chunk has the following structure:

All multi-byte types (anything above `uint8_t` (so `uint16_t`, `uint32_t`, `uint64_t`, ...)) are little-endian values.

| C type                           | Name           | Description                                 |
| -------------------------------- | -------------- | ------------------------------------------- |
| `uint8_t[chunk_identifier_size]` | `chunk_id`     | The Chunk group identifier.                 |
| `uint32_t`                       | `chunk_number` | The number of the Chunk in the Chunk group. |
| `uint8_t[chunk_size]`            | `chunk`        | The chunk data itself.                      |

Meaning, the final chunk size in bytes will be `chunk_identifier_size + 4 + chunk_size`.

#### Generating a Chunk ID

A Chunk ID is a cryptographically secure, random `chunk_identifier_size`-byte chunk identifier to group all chunks
into entries. A proposed Chunk ID generation algorithm could look like this:

    number max_chunks = pow(256, chunk_identifier_size);
    bytes null_identifier = b"\0" * chunk_identifier_size;

    bytes generate_chunk_id() {
        number total_chunks = pdb.chunk_ids.size();

        if (total_chunks == max_chunks)
            throw "All possible chunk IDs have been generated.";

        if (max_chunks - total_chunks == 1 && null_identifier not in pdb.chunks)
            throw "Only available chunk ID is the NULL chunk ID.";

        while (true) {
            bytes chunk_id = random(chunk_identifier_size);

            if (chunk_id != null_identifier && chunk_id not in pdb.chunk_ids)
                return chunk_id;
        }
    }

In other words:

-   Check if the chunk ID resource was not exhausted fully.
-   Check if the only available chunk ID is not the NULL identifier.
    -   The NULL identifier marks an empty chunk.
-   Start an infinite loop.
-   Generate a `chunk_identifier_size` random bytes.
-   Check if the generated identifier is not all NULLs.
-   Check if the identifier is unique.
-   If all checks passed, return the generated chunk id (and so - break the loop).
-   If not, try again.

There are optimizations and transformations you can apply to the algorithm, such as:

-   Generating the chunk Identifier byte-by-byte to reduce probability
-   Keeping track of generated chunks
-   Checking the `sum(chunk_id) != 0` instead of comparing bytes
-   Use hashing functions (or a data structure such as a Hash table)
-   Caching the IDs so you wouldn't need to regenerate them each time
-   Binary search if the IDs are sorted
-   Batch generation of the IDs
-   Probably more...

But The idea stays the same - brute force.

Or you can go the less entropic way of doing things and just using `total_chunks + 1` represented
through bytes as the ID of the chunk, although this is **not recommended** due to integer limits and
just for the fact that it doesn't have enough entropy.

A Chunk ID can be pretty much any value as long as it's `chunk_identifier_size` bytes.

#### Padding the input data

The padding is very simple:

    bytes pad_data(bytes data) {
        number padding_size = chunk_size - (len(data) % chunk_size) - 2;

        if (padding_size > 0) {
            data = data + random(padding_size);
        }

        data = data + as_uint16_le(padding_size);
    }

In other words:

-   The size of padding required is calculated called `padding_size`. As we work on `chunk_size`-byte blocks we use the formula `chunk_size - (size_of_data % chunk_size) - 2`, we reserve the last two bytes for the padding size.
-   If the `padding_size` is greater than zero, we generate `padding_size` bytes of cryptographically secure bytes, and append them to the data.
-   Unconditionally, we append `padding_size` to the data, as a `uint16_t`.

#### Chunking the input data

After the data has been padded, it goes through a chunking process, where the data is split into equal
chunks. This is how a hypothetical algorithm would look:

    bytes[] chunk_data(bytes data) {
        return split(data, chunk_size);
    }

The algorithm will depend a lot on the implementation and pseudocode isn't enough to express it.
The generic pipeline of it would be:

-   As the data is padded, we can expect the data to chunk correctly.
-   The data is split into `chunk_size`-byte chunks, so we split it into `chunk_size`-byte chunks.
-   The final array of chunks is returned in order.

#### Assigning a Chunk number to every chunk

For entropy uses we might want to shuffle the chunks, this is why their order is stored.
The Chunk number is a 32-bit integer, meaning there cannot be more than 4294967295 chunks in
a complex entry.

Here's how a Chunk number gets assigned:

    bytes[] assign_chunk_numbers(bytes[] chunks) {
        for chunk_idx in counter(chunks.size()) {
            chunks[chunk_idx] = as_uint32_le(chunk_idx) + chunks[chunk_idx];
        }

        return chunks;
    }

In other words:

-   We loop over every chunk, storing its index in `chunk_idx`, starting at `0`.
-   We prepend the `chunk_idx` as a little-endian `uint32_t` to every chunk.
-   We return the result.

Now, as the position of every chunk is stored, it can be easily shuffled around safely.

#### Assigning a Chunk ID to every chunk

A Chunk ID is used to group different chunks into a single entry. This is how it is done:

    bytes[] assign_chunk_id(bytes[] chunks) {
        bytes group_id = generate_chunk_id();

        for chunk_idx in counter(chunks.size()) {
            chunks[chunk_idx] = group_id + chunks[chunk_idx];
        }

        return chunks;
    }

In other words:

-   We generate a new Chunk group ID.
-   Looping over every chunk, we prepend the Chunk group ID to every chunk.
-   Return the final chunks.

Now the chunks are grouped and can be inserted into the database without losing which
chunk belongs to what entry.

#### Inserting the Chunks into the database

There are many ways to insert a chunk into a database. One way you could do it is like this:

    void insert_chunks_into_database(bytes[] chunks) {
        shuffle(chunks);

        for chunk in chunks {
            pdb.add(chunk);
        }
    }

This is a very simple algorithm, which:

-   Shuffles the chunks before inserting them, giving them more randomness.
-   Loops over every chunk and appends it to the database.

You can build on top of this, but this is the basic algorithm. Even though it depends a lot
on implementation, it should at the very worst be O(2n).

### Encryption

Encrypted data has a specific structure:

| C type      | Name                | Description                    |
| ----------- | ------------------- | ------------------------------ |
| `uint64_t`  | `rsa_key_id`        | The RSA key ID.                |
| `uint64_t`  | `rsa_salt_id`       | The RSA salt ID.               |
| `uint64_t`  | `chacha20_salt_id`  | The ChaCha20-Poly1305 salt ID. |
| `uint64_t`  | `threefish_salt_id` | The Threefish salt ID.         |
| `uint64_t`  | `aes_salt_id`       | The AEC256-GCM salt ID.        |
| `uint8_t[]` | `ciphertext`        | The ciphertext.                |

Which gets generated by this function:

    bytes encrypt_entry(bytes entry) {
        # The *_id ones also set the format fields.

        bytes rsa_key, rsa_key_id = get_key(RSA_KEYPAIR), get_key_id(rsa_key);
        bytes rsa_salt, rsa_salt_id = get_key(CRYPTO_SALT), get_key_id(rsa_salt);

        bytes chacha20_salt, chacha20_salt_id = get_key(CRYPTO_SALT), get_key_id(chacha20_salt);
        bytes threefish_salt, threefish_salt_id = get_key(CRYPTO_SALT), get_key_id(threefish_salt);
        bytes aes_salt, aes_salt_id = get_key(CRYPTO_SALT), get_key_id(aes_salt);

        # Symmetric cryptography

        bytes ciphertext = encrypt_threefish(entry, threefish_salt);
        ciphertext = encrypt_chacha20(ciphertext, database_password, chacha20_salt);
        ciphertext = encrypt_aes(ciphertext, database_password, aes_salt);

        # Asymmetric cryptography

        ciphertext = ZSTD(
            data=ciphertext,
            compression_level=ZSTD_compression_level,
        );

        ciphertext = encrypt_rsa(ciphertext, rsa_key);

        return ciphertext;
    }

More generically:

    RSA4096(ZSTD(AES256(ChaCha20(Threefish(... data ...)))))

In other words:

-   Keys of RSA, ChaCha20, Threefish, and AES are picked from the database.
-   Threefish cipher is applied.
-   ChaCha20 cipher is applied.
-   AES cipher is applied.
-   The resulting ciphertext is then compressed using ZSTD.
-   The output of ZSTD is then passed to RSA.
-   Final ciphertext is returned.

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
