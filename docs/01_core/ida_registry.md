# ida_registry

Registry related functions.

IDA uses the registry to store global configuration options that must persist after IDA has been closed.
On Windows, IDA uses the Windows registry directly. On Unix systems, the registry is stored in a file (typically ~/.idapro/ida.reg).
The root key for accessing IDA settings in the registry is defined by ROOT_KEY_NAME.

## Constants

- `IDA_REGISTRY_NAME`
- `HVUI_REGISTRY_NAME`
- `ROOT_KEY_NAME`: Default key used to store IDA settings in registry (Windows version).
- `reg_unknown`: unknown
- `reg_sz`: utf8 string
- `reg_binary`: binary data
- `reg_dword`: 32-bit number

## Functions Overview

- `reg_read_string(name: str, subkey: str = None, _def: str = None) -> PyObject *`: Read a string from the registry.
- `reg_data_type(name: str, subkey: str = None) -> regval_type_t`: Get data type of a given value.
- `reg_read_binary(name: str, subkey: str = None) -> PyObject *`: Read binary data from the registry.
- `reg_write_binary(name: str, py_bytes: PyObject *, subkey: str = None) -> PyObject *`: Write binary data to the registry.
- `reg_subkey_subkeys(name: str) -> PyObject *`: Get all subkey names of given key.
- `reg_subkey_values(name: str) -> PyObject *`: Get all value names under given key.
- `reg_delete_subkey(name: str) -> bool`: Delete a key from the registry.
- `reg_delete_tree(name: str) -> bool`: Delete a subtree from the registry.
- `reg_delete(name: str, subkey: str = None) -> bool`: Delete a value from the registry.
- `reg_subkey_exists(name: str) -> bool`: Is there already a key with the given name?
- `reg_exists(name: str, subkey: str = None) -> bool`: Is there already a value with the given name?
- `reg_read_strlist(subkey: str) -> List[str]`: Retrieve all string values associated with the given key.
- `reg_write_strlist(items: List[str], subkey: str)`: Write string values associated with the given key.
- `reg_update_strlist(subkey: str, add: str | None, maxrecs: int, rem: str | None = None, ignorecase: bool = False)`: Add and/or remove items from the list, and possibly trim that list.
- `reg_write_string(name: str, utf8: str, subkey: str = None) -> None`: Write a string to the registry.
- `reg_read_int(name: str, defval: int, subkey: str = None) -> int`: Read integer value from the registry.
- `reg_write_int(name: str, value: int, subkey: str = None) -> None`: Write integer value to the registry.
- `reg_read_bool(name: str, defval: bool, subkey: str = None) -> bool`: Read boolean value from the registry.
- `reg_write_bool(name: str, value: int, subkey: str = None) -> None`: Write boolean value to the registry.
- `reg_update_filestrlist(subkey: str, add: str, maxrecs: size_t, rem: str = None) -> None`: Update registry with a file list. Case sensitivity will vary depending on the target OS.
- `set_registry_name(name: str) -> bool`