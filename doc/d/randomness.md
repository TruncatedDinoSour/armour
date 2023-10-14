# randomness in armour

all randomness in random is cryptographically secure, in the whole library
we use a singular source of it -- `armour.crypto.RAND`, which is an instance of
`secrets.SystemRandom()`

do not use cryptographically insecure randomness sources while using armour,
forget that a library like `random` for example exists
