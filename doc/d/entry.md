# entry in armour

( not to b confused w entries )

there r 2 diff entries in armour by default :

-   raw ( raw data ) -- `armour.pdb.entries.PdbRawEntry`
-   password ( implements the pDB v 0 standard ) -- `armour.pdb.entries.PdbPwdEntry`

using them is as simple as making an instance and passing the `armour.pdb.header.PdbHeader` instance
as head and if u want optionally `ehash` ( entry hash ) and `fields` to set immediately

both of them implement or have these methods and properties

-   `from_entry(entry: bytes)` -- takes in binary data of an entry ( no hash ) and sets the fields in the entry
-   `entry` -- returns the entry without a hash and a separating null byte
-   `full_entry` -- returns the full entry u can put into the database
-   `rehash()` -- rehashes the entry ( **IMPORTANT** -- every time u change anything, u need to call `rehash()` )
-   `hash_ok()` -- returns true if the has is valid and false if not
-   `revalidate()` -- checks if the current hash is valid, if not, raises `armour.pdb.exc.DataIntegrityError`
-   `set_field_raw(ident: bytes, value: bytes)` -- set the raw bytes of `value` to identifier `ident`,
    raises `armour.pdb.exc.InvalidIdentifer` if `ident` is invalid
-   `get_field_raw(ident: bytes)` -- gets the value assoced w `ident`
-   `validate_struct()` -- validates if the struct is valid by checking `struct_valid`,
    raises `armour.pdb.exc.StructureError` on invalid
-   `set_field(ident: bytes, value: bytes)` -- same as `set_field_raw`, just that diff types treat it diff
-   `get_field(ident: bytes)` -- same as `get_field_raw`, just that diff types treat it diff
-   `struct_valid` -- return `True` if the structure of the entry is valid, else `False`

## example

```py
>>> import armour
>>> e: armour.pdb.entries.PdbRawEntry = armour.pdb.entries.PdbRawEntry(armour.pdb.header.PdbHeader.empty().decrypt())
>>> e[b"h"] = b"not h"
>>> e[b"hello"] = b"not h"
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 150, in __setitem__
    self.set_field(ident, value)
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 164, in set_field
    return self.set_field_raw(ident, value)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 107, in set_field_raw
    raise exc.InvalidIdentifier(ident, self.entry_id)
armour.pdb.exc.InvalidIdentifier: identifier b'hello' of entry #0 is invalid
>>> e.struct_valid
True
>>> e.rehash()
<armour.pdb.entries.PdbRawEntry object at 0x7f9df19654d0>
>>> e.validate_struct()
<armour.pdb.entries.PdbRawEntry object at 0x7f9df19654d0>
```
