# custom pdb entries in armour

by default armour comes with 2 entry formats -- raw and password,
raw is just raw ( `PdbRawEntry` ) data and password ( `PdbPwdEntry` )
implements the pDB version 0 password entries format

although if u want ur own custom entries, u have to implement ur own
by using a class and inheriting from `armour.pdb.entries.PdbEntry` and implementing
these abstract methods :

```py
@abstractmethod
def set_field(self, name: bytes, value: bytes) -> Self:
    """set field name to value"""
    return self  # for typing

@abstractmethod
def get_field(self, name: bytes) -> bytes:
    """get field by name"""

@abstractmethod
def struct_valid(self) -> bool:
    """check if the structure of the entry is valid"""

@abstractmethod
def __str__(self) -> str:
    """stringify entry"""
```

other methods and properties r alrd implemented on the `PdbEntry` abstract base class

## example

```py
>>> import armour
>>> class PdbMyEntry(armour.pdb.entries.PdbEntry):
...     """my custom pdb entry type"""
...
...     def set_field(self, name: bytes, value: bytes) -> "PdbMyEntry":
...         """set field name to value"""
...
...         self.set_field_raw(name, b"mytype:" + value)
...         return self
...
...     def get_field(self, name: bytes) -> bytes:
...         """get field by name"""
...         return self.get_field_raw(name)[7:]
...
...     def struct_valid(self) -> bool:
...         """check if the structure of the entry is valid"""
...         return b"d" in self.fields
...
...     def __str__(self) -> str:
...         """stringify entry"""
...         return "\n".join(self.fields.keys())
...
>>> e: PdbMyEntry = PdbMyEntry(armour.pdb.header.PdbHeader.empty().decrypt())
>>> e[b"a"] = b"data"
>>> e[b"b"] = b"more data"
>>> e[b"d"] = b"no c :("
>>> e.rehash()
<__main__.PdbMyEntry object at 0x7f7daf1f5550>
>>> e[b"d"]
b'no c :('
>>> e.validate_struct()  # calls to struct_valid
<__main__.PdbMyEntry object at 0x7f7daf1f5550>
>>> e.revalidate()
<__main__.PdbMyEntry object at 0x7f7daf1f5550>
>>> e[b"c"]
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 143, in __getitem__
    def __getitem__(self, name: bytes) -> bytes:
               ^^^^^^^^^^^^^^^^^^^^
  File "<stdin>", line 12, in get_field
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 111, in get_field_raw
    return self.fields[name]
           ~~~~~~~~~~~^^^^^^
KeyError: b'c'
>>> e[b"c"] = b"c :)"
>>> e.revalidate()  # we didnt rehash() after changing
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/ari/Ari/coding/projects_/armour/armour/pdb/entries.py", line 94, in revalidate
    raise exc.DataIntegrityError(
armour.pdb.exc.DataIntegrityError: entry #1 has a bad hash / signature
```
