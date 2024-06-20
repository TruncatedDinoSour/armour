# This repository has been migrated to the self-hosted ari-web Forgejo instance: <https://git.ari.lt/ari/armour>
# armour

> password securing, management and generation tools

# userland tools

see [pwdtools](https://ari.lt/gh/pwdtools)

```sh
pip install pwdtools
````

these tools use the `armour` library for user interaction, armour is just a library,
pwdtools, on the other hand, provides cli interface with this library such as `pwdgen` for
password generation and so on, source

# proof

i've used armour in multiple projects already and i can say that armour is a great library
for generating secure human-readable secrets and stuff like that with high security and entropy,
and also keeping it shorter than just 10000 chars long

it is provably better than cryptographically secure bytes + base85 encoding, b85 has more
characters and cryptographically secure bytes should be very random and unpredictable,
i've even made a script to demonstrate that :

```
armour with 1498 win( s ) or 73.14453125 percent of the runs won
b85_shuf with 272 win( s ) or 13.28125 percent of the runs won
b85_norm with 272 win( s ) or 13.28125 percent of the runs won
pwgen with 6 win( s ) or 0.29296875 percent of the runs won

winner is armour with score 1498 or 73.14453125 percent of the runs won
```

script is located at [tests/test_proof.py](/tests/test_proof.py), it tests password strengths for same length passwords
( by default 2048 runs and 2048 character length passwords )

# magic file

magic file is used by `file` cmd to get metadata about a file, if u want that, use `scripts/gen_magic.py` script

# xdg mime file

located at [/scripts/application-pdb.xml](/scripts/application-pdb.xml)

# documentation

see the [/doc/](/doc/) folder
