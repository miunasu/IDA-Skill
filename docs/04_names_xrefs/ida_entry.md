# ida_entry

Functions that deal with entry points.

Exported functions are considered as entry points as well.
IDA maintains list of entry points to the program. Each entry point:

## Constants

- `AEF_UTF8`: the name is given in UTF-8 (default)
- `AEF_IDBENC`: the name is given in the IDB encoding; non-ASCII bytes will be decoded accordingly. Specifying AEF_IDBENC also implies AEF_NODUMMY
- `AEF_NODUMMY`: automatically prepend the name with '_' if it begins with a dummy suffix. See also AEF_IDBENC
- `AEF_WEAK`: make name weak
- `AEF_NOFORCE`: if the specified address already has a name, the new name will be appended to the regular comment, except for the case when the old name is weak and the new one is not.

## Functions Overview

- `get_entry_qty() -> size_t`: Get number of entry points.
- `add_entry(ord: int, ea: ida_idaapi.ea_t, name: str, makecode: bool, flags: int = 0) -> bool`: Add an entry point to the list of entry points.
- `get_entry_ordinal(idx: size_t) -> int`: Get ordinal number of an entry point.
- `get_entry(ord: int) -> ida_idaapi.ea_t`: Get entry point address by its ordinal
- `get_entry_name(ord: int) -> str`: Get name of the entry point by its ordinal.
- `rename_entry(ord: int, name: str, flags: int = 0) -> bool`: Rename entry point.
- `set_entry_forwarder(ord: int, name: str, flags: int = 0) -> bool`: Set forwarder name for ordinal.
- `get_entry_forwarder(ord: int) -> str`: Get forwarder name for the entry point by its ordinal.