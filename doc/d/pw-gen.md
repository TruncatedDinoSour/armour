# password generation in armour

armour provides with tools to generate secure
passwords based on criteria in `armour.gen.gen`

to generate passwords based off criteria construct `PwGenerator` with
ur criteria, keep in mind that values of `-1` suggest 'any', which are the
defaults for `min_` and `max_` arguments

`PwGenerator` takes in these arguments ( all optional ) :

-   `rand` -- randomness source ( defaults to `armour.crypt.RAND` )
-   `byteset` -- the set of bytes to use in the password
    -   if set to `None` uses random bytes
    -   by default uses all printable characters
-   `length` -- the wanted password length
-   `min_lower` -- minimum count of lowercase letters
-   `min_upper` -- minimum count of uppercase letters
-   `min_numbers` -- minimum count of numeric characters
-   `min_special` -- minimum count of special characters
-   `min_alphabet` -- minimum length of the password alphabet
-   `max_sequences` -- maximum count of sequences
-   `max_common_patterns` -- maximum count common patterns
-   `min_entropy` -- minimum entropy bits
-   `min_strength` -- minimum strength
-   `max_weakness` -- maximum weakness
-   `min_actual_strength` -- minimum realistic strength
-   `max_passes` -- the times to try to find the password ( defaults to `1024` )
    -   if set to `None` will try forever til it finds something

methods u can call on `PwGenerator` instance :

-   `checks` -- get all the checks for the passwords
    -   tuple of (value, check) tuples where check is a callable that
        returns if the condition passed or not
    -   takes in a `PasswordInfo` object to use
-   `gen_one` -- try to generate a new password
    -   returns `None` if it couldnt generate a good one based on ur criteria
    -   returns `PasswordInfo` on success
-   `gen` -- try to generate the password `max_passes` times or forever
    -   returns `None` if it couldnt find a good password
    -   returns `PasswordInfo` on success

## example

```py
>>> import armour
>>> print(armour.gen.gen.PwGenerator().gen())
length              128
lowercase           'yepwjwofsavvpqdpbkrvmkrgszpptkudpmpsljnpgtll'
uppercase           'SMIICIHDTIFDKBVJYJMTCRPVYHRJFXQXYYL'
numbers             '79717233175'
special             '`;`<^!_}#.;<^{!(-{#:|?/@.$+/<"`"\\\'*<~+.'
alphabet            '!"#$\\\'(*+-./123579:;<?@BCDFHIJKLMPQRSTVXY^_`abdefgjklmnopqrstuvwyz{|}~'
    alphabet combos 23587592395905693351442904560302022254467234770425414285469530657504535801364915816432245490596299658923687643435038957720860320754227185558333794857703311787045162048625406818415063860534352804900792572705170993013538266734645947850241
sequences           4
    - 'YY' ( from 118 to 120 )
    - 'll' ( from 124 to 126 )
common patterns     0
    <none>
entropy bits        5.896217089725436
strength            1296.6814200733052
weakness            0
actual strength     5591.938624066129
```
