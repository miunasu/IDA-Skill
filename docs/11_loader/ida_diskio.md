# ida_diskio

File I/O functions for IDA.

You should not use standard C file I/O functions in modules. Use functions from this header, pro.h and fpro.h instead.
This file also declares a call_system() function.

## Constants

- `VAULT_CACHE_SUBDIR`: subdir name for cached deltas and old files
- `VAULT_CACHE_FNAME`: to store file caches
- `CFG_SUBDIR`
- `IDC_SUBDIR`
- `IDS_SUBDIR`
- `IDP_SUBDIR`
- `LDR_SUBDIR`
- `SIG_SUBDIR`
- `TIL_SUBDIR`
- `PLG_SUBDIR`
- `THM_SUBDIR`
- `IDA_SUBDIR_IDP`: append the processor name as a subdirectory
- `IDA_SUBDIR_IDADIR_FIRST`: $IDADIR/subdir will be first, not last
- `IDA_SUBDIR_ONLY_EXISTING`: only existing directories will be present
- `CSIDL_APPDATA`
- `CSIDL_LOCAL_APPDATA`
- `CSIDL_PROGRAM_FILES`
- `CSIDL_PROGRAM_FILES_COMMON`
- `CSIDL_PROGRAM_FILESX86`
- `LINPUT_NONE`
- `LINPUT_LOCAL`
- `LINPUT_RFILE`
- `LINPUT_PROCMEM`
- `LINPUT_GENERIC`
- `LOC_CLOSE`: close the inner linput
- `LOC_UNMAKE`: unmake the inner linput
- `LOC_KEEP`: do nothing

## Classes Overview

- `file_enumerator_t`
- `ioports_fallback_t`
- `choose_ioport_parser_t`
- `generic_linput_t`

## Functions Overview

- `idadir(subdir: str) -> str`: Get IDA directory (if subdir==nullptr) or the specified subdirectory (see IDA subdirectories)
- `getsysfile(filename: str, subdir: str) -> str`: Search for IDA system file. This function searches for a file in:
- `get_user_idadir() -> str`: Get user ida related directory.
- `get_ida_subdirs(subdir: str, flags: int = 0) -> qstrvec_t *`: Get list of directories in which to find a specific IDA resource (see IDA subdirectories). The order of the resulting list is as follows:
- `get_special_folder(csidl: int) -> str`: Get a folder location by CSIDL (see Common CSIDLs). Path should be of at least MAX_PATH size
- `fopenWT(file: str) -> FILE *`
- `fopenWB(file: str) -> FILE *`
- `fopenRT(file: str) -> FILE *`
- `fopenRB(file: str) -> FILE *`
- `fopenM(file: str) -> FILE *`
- `fopenA(file: str) -> FILE *`
- `read_ioports(ports: ioports_t *, device: str, file: str, callback: ioports_fallback_t = None) -> ssize_t`
- `choose_ioport_device2(_device: str, file: str, parse_params: choose_ioport_parser_t) -> bool`
- `qlgetz(li: linput_t *, fpos: int64) -> str`
- `open_linput(file: str, remote: bool) -> linput_t *`
- `create_generic_linput(gl: generic_linput_t) -> linput_t *`
- `create_memory_linput(start: ida_idaapi.ea_t, size: asize_t) -> linput_t *`
- `get_linput_type(li: linput_t *) -> linput_type_t`
- `enumerate_files(path, fname, callback)`: Enumerate files in the specified directory while the callback returns 0.
- `create_bytearray_linput(s: str) -> linput_t *`
- `close_linput(li: linput_t *) -> None`