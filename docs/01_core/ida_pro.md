# ida_pro

This is the first header included in the IDA project.

It defines the most common types, functions and data. Also, it tries to make system dependent definitions.
The following preprocessor macros are used in the project (the list may be incomplete)
Platform must be specified as one of:
__NT__ - MS Windows (all platforms)

## Constants

- `BADDIFF`
- `IDA_SDK_VERSION`: IDA SDK v9.2.
- `BADMEMSIZE`
- `MAXSTR`: maximum string size
- `FMT_64`
- `FMT_Z`
- `FMT_ZX`
- `FMT_ZS`
- `FMT_EA`
- `IDBDEC_ESCAPE`: convert non-printable characters to C escapes (
- `CP_BOM`
- `UTF8_BOM`
- `UTF16LE_BOM`
- `UTF16BE_BOM`
- `UTF32LE_BOM`
- `UTF32BE_BOM`
- `CP_ELLIPSIS`
- `UTF8_ELLIPSIS`
- `CP_REPLCHAR`
- `UTF8_REPLCHAR`
- `MAX_UTF8_SEQ_LEN`
- `CEF_RETERR`
- `ENC_WIN1252`
- `ENC_UTF8`
- `ENC_MUTF8`
- `ENC_UTF16`
- `ENC_UTF16LE`
- `ENC_UTF16BE`
- `ENC_UTF32`
- `ENC_UTF32LE`
- `ENC_UTF32BE`
- `CP_UTF8`
- `CP_UTF16`: UTF-16 codepage.
- `SUBSTCHAR`: default char, used if a char cannot be represented in a codepage
- `IOREDIR_INPUT`: input redirection
- `IOREDIR_OUTPUT`: output redirection
- `IOREDIR_APPEND`: append, do not overwrite the output file
- `IOREDIR_QUOTED`: the file name was quoted
- `QWCONTINUED`
- `QWNOHANG`
- `TCT_UNKNOWN`
- `TCT_OWNER`
- `TCT_NOT_OWNER`
- `cvar`
- `NULL_PIPE_HANDLE`
- `longlongvec_t`
- `ulonglongvec_t`
- `svalvec_t`
- `eavec_t`

## Classes Overview

- `qrefcnt_obj_t`
- `channel_redir_t`
- `plugin_options_t`
- `instant_dbgopts_t`
- `qmutex_locker_t`
- `intvec_t`
- `uintvec_t`
- `int64vec_t`
- `uint64vec_t`
- `boolvec_t`
- `strvec_t`
- `sizevec_t`
- `uchar_array`
- `tid_array`
- `ea_array`
- `sel_array`
- `uval_array`
- `uchar_pointer`
- `ushort_pointer`
- `uint_pointer`
- `sint8_pointer`
- `int8_pointer`
- `uint8_pointer`
- `int16_pointer`
- `uint16_pointer`
- `int32_pointer`
- `uint32_pointer`
- `int64_pointer`
- `uint64_pointer`
- `ssize_pointer`
- `bool_pointer`
- `char_pointer`
- `short_pointer`
- `int_pointer`
- `ea_pointer`
- `sel_pointer`
- `asize_pointer`
- `adiff_pointer`
- `uval_pointer`
- `sval_pointer`
- `ea32_pointer`
- `ea64_pointer`
- `flags_pointer`
- `flags64_pointer`
- `tid_pointer`

## Functions Overview

- `qatoll(nptr: str) -> int64`
- `qexit(code: int) -> None`: Call qatexit functions, shut down UI and kernel, and exit.
- `log2ceil(d64: uint64) -> int`: calculate ceil(log2(d64)) or floor(log2(d64)), it returns 0 if d64 == 0
- `log2floor(d64: uint64) -> int`
- `bitcountr_zero(x: uint64) -> int`: count the number of consecutive trailing zero bits (line C++20 std::countr_zero())
- `extend_sign(v: uint64, nbytes: int, sign_extend: bool) -> uint64`: Sign-, or zero-extend the value 'v' to occupy 64 bits. The value 'v' is considered to be of size 'nbytes'.
- `readbytes(h: int, res: uint32 *, size: int, mf: bool) -> int`: Read at most 4 bytes from file.
- `writebytes(h: int, l: int, size: int, mf: bool) -> int`: Write at most 4 bytes to file.
- `reloc_value(value: void *, size: int, delta: adiff_t, mf: bool) -> None`
- `qvector_reserve(vec: void *, old: void *, cnt: size_t, elsize: size_t) -> void *`: Change capacity of given qvector.
- `relocate_relobj(_relobj: relobj_t *, ea: ida_idaapi.ea_t, mf: bool) -> bool`
- `is_cvt64() -> bool`: is IDA converting IDB into I64?
- `quote_cmdline_arg(arg: str) -> bool`: Quote a command line argument if it contains escape characters. For example, .c will be converted into ".c" because * may be inadvertently expanded by the shell
- `parse_dbgopts(ido: instant_dbgopts_t, r_switch: str) -> bool`: Parse the -r command line switch (for instant debugging). r_switch points to the value of the -r switch. Example: win32@localhost+
- `check_process_exit(handle: void *, exit_code: int *, msecs: int = -1) -> int`: Check whether process has terminated or not.
- `is_control_tty(fd: int) -> enum tty_control_t`: Check if the current process is the owner of the TTY specified by 'fd' (typically an opened descriptor to /dev/tty).
- `qdetach_tty() -> None`: If the current terminal is the controlling terminal of the calling process, give up this controlling terminal.
- `qcontrol_tty() -> None`: Make the current terminal the controlling terminal of the calling process.
- `qthread_equal(q1: __qthread_t, q2: __qthread_t) -> bool`: Are two threads equal?
- `is_main_thread() -> bool`: Are we running in the main thread?
- `get_login_name() -> str`: Get the user name for the current desktop session
- `get_physical_core_count() -> int`: Get the total CPU physical core count
- `get_logical_core_count() -> int`: Get the total CPU logical core count
- `get_available_core_count() -> int`: Get the number of logical CPU cores available to the current process if supported by the OS.
- `qstrvec_t_create() -> PyObject *`
- `qstrvec_t_destroy(py_obj: PyObject *) -> bool`
- `qstrvec_t_get_clink(_self: PyObject *) -> qstrvec_t *`
- `qstrvec_t_get_clink_ptr(_self: PyObject *) -> PyObject *`
- `qstrvec_t_assign(_self: PyObject *, other: PyObject *) -> bool`
- `qstrvec_t_addressof(_self: PyObject *, idx: size_t) -> PyObject *`
- `qstrvec_t_set(_self: PyObject *, idx: size_t, s: str) -> bool`
- `qstrvec_t_from_list(_self: PyObject *, py_list: PyObject *) -> bool`
- `qstrvec_t_size(_self: PyObject *) -> size_t`
- `qstrvec_t_get(_self: PyObject *, idx: size_t) -> PyObject *`
- `qstrvec_t_add(_self: PyObject *, s: str) -> bool`
- `qstrvec_t_clear(_self: PyObject *, qclear: bool) -> bool`
- `qstrvec_t_insert(_self: PyObject *, idx: size_t, s: str) -> bool`
- `qstrvec_t_remove(_self: PyObject *, idx: size_t) -> bool`
- `str2user(str)`: Insert C-style escape characters to string