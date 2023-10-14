# entries in armour

( not to b confused w entry )

`PdbEntries` located in `armour.pdb.entries` is an object that
manages all entries in a pDB database

to use it, u first have to construct it passing in the `PdbHeader` as
the constructor argument

after that u r free to use the methods and properties provided :

- `gather(entry_t: Type[PdbEntry] = PdbPwdEntry)` -- gather all entries from the database
    - `entry_t` is the entry type, `armour` provides 2 -- `PdbPwdEntry` and `PdbRawEntry`
- `add_entry(self, entry: PdbEntry)` -- adds an entry to all entries
- `db_entries` -- all entries as bytes
- `commit()` -- pushes all entries to the database ( **IMPORTANT** dont forget to call it if u want to save the changes )

## example

```py
>>> import armour
>>> h: armour.pdb.header.PdbHeader = armour.pdb.header.PdbHeader.empty()
>>> ex: armour.pdb.entries.PdbEntries = armour.pdb.entries.PdbEntries(h)
>>> ex.add_entry(armour.pdb.entries.PdbRawEntry(h, fields={b"x": b"my x field :)"}).rehash())
<armour.pdb.entries.PdbEntries object at 0x7f80a2fb0710>
>>> ex.db_entries
b'9-\xc4\xfa\x7fP/\x93\x06#x\xa3\xf3\xdc\x1c\x9e\xb5?2\x88r\xad\xf0\xc0\x12\n\xc0\xfd3\x95\xf6W\xb28\xbc\xf2a\xa63}\xa5\x02~\x98\x8a\x8ay\xb0\xa2f\x84\x13x\xb1\xd0\x0e\xb3\xde\x0f\xa7Lp\x9d\xb2\x935\xbe#\xf7\x11\xd2\xb9\xdf\xed\xa4\xe3i\r\xf0gy\xab\xa2x\r\x00\x00\x00my x field
:)\x00'
```
