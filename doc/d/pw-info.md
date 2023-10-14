# password information extraction in armour

password information extraction is located at `armour.gen.info`

password information u can extract :

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

to extract that info u need to use the `PasswordInfo` class by passing it in the
password u wanna check ( by default the password is empty )

## example

```py
>>> import armour
>>> print(armour.gen.info.PasswordInfo(b"zxcvbn123p@aw0rd"))
length              16
lowercase           'zxcvbnpawrd'
uppercase           '<none>'
numbers             '1230'
special             '@'
alphabet            '@abcdnp1230rvwxz'
    alphabet combos 18446744073709551616
sequences           0
    <none>
common patterns     9
    - 'zxcvbn' ( from 0 to 6 )
    - '123' ( from 6 to 9 )
entropy bits        4.0
strength            108.3614195558365
weakness            0
actual strength     108.3614195558365
```
