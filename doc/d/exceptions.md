# armour exceptions

all exceptions are in `armour.pdb.exc`

-   `InvalidMagicError` -- raised if the magic of the pDB db isnt valid
-   `VersionMismatch` -- raised if the version of the parser and the database are not the same
-   `DataIntegrityError` -- raised if noticed data corruption or tinkering
-   `InvalidHashID` -- raised if the hash id is not valid
-   `InvalidZSTDCompressionLvl` -- raised if the zstd compression level is invalid
-   `InvalidZeroValue` -- raised if theres a zero value in a place where its invalid
-   `StructureError` -- raised if the structure of an entry or something else is invalid
-   `InvalidIdentifier` -- raised if an invalid identifier was detected
