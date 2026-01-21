# ida_idaapi

## Constants

- `BADADDR`
- `BADADDR32`
- `BADADDR64`
- `BADSEL`
- `SIZE_MAX`
- `ea_t`
- `integer_types`
- `SEEK_SET`
- `SEEK_CUR`
- `SEEK_END`
- `PLUGIN_MOD`
- `PLUGIN_DRAW`
- `PLUGIN_SEG`
- `PLUGIN_UNL`
- `PLUGIN_HIDE`
- `PLUGIN_DBG`
- `PLUGIN_PROC`
- `PLUGIN_FIX`
- `PLUGIN_MULTI`
- `PLUGIN_SKIP`
- `PLUGIN_OK`
- `PLUGIN_KEEP`
- `PY_ICID_INT64`: int64 object
- `PY_ICID_BYREF`: byref object
- `PY_ICID_OPAQUE`: opaque object
- `ST_OVER_DEBUG_SEG`: step tracing will be disabled when IP is in a debugger segment
- `ST_OVER_LIB_FUNC`: step tracing will be disabled when IP is in a library function
- `as_unicode`
- `IDAPython_Completion`
- `NW_OPENIDB`: Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)
- `NW_CLOSEIDB`: Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)
- `NW_INITIDA`: Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)
- `NW_TERMIDA`: Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)
- `NW_REMOVE`: Use this flag with other flags to uninstall a notifywhen callback
- `HBF_CALL_WITH_NEW_EXEC`
- `HBF_VOLATILE_METHOD_SET`

## Classes Overview

- `pyidc_opaque_object_t`: This is the base class for all Python<->IDC opaque objects
- `py_clinked_object_t`: This is a utility and base class for C linked objects
- `object_t`: Helper class used to initialize empty objects
- `plugin_t`: Base class for all scripted plugins.
- `plugmod_t`: Base class for all scripted multi-plugins.
- `pyidc_cvt_helper__`: This is a special helper object that helps detect which kind
- `PyIdc_cvt_int64__`: Helper class for explicitly representing VT_INT64 values
- `PyIdc_cvt_refclass__`: Helper class for representing references to immutable objects
- `IDAPython_displayhook`
- `loader_input_t`: A helper class to work with linput_t related functions.

## Functions Overview

- `require(modulename, package=None)`: Load, or reload a module.
- `replfun(func)`
- `as_cstr(val)`: Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
- `as_UTF16(s)`: Convenience function to convert a string into appropriate unicode format
- `as_uint32(v)`: Returns a number as an unsigned int32 number
- `as_int32(v)`: Returns a number as a signed int32 number
- `as_signed(v, nbits=32)`: Returns a number as signed. The number of bits are specified by the user.
- `TRUNC(ea)`: Truncate EA for the current application bitness
- `copy_bits(v, s, e=-1)`: Copy bits from a value
- `struct_unpack(buffer, signed=False, offs=0)`: Unpack a buffer given its length and offset using struct.unpack_from().
- `IDAPython_ExecSystem(cmd)`: Executes a command with popen().
- `IDAPython_FormatExc(etype, value=None, tb=None, limit=None)`: This function is used to format an exception given the
- `IDAPython_ExecScript(path, g, print_error=True)`: Run the specified script.
- `IDAPython_LoadProcMod(path, g, print_error=True)`: Load processor module.
- `IDAPython_UnLoadProcMod(script, g, print_error=True)`: Unload processor module.
- `IDAPython_GetDocstrings(obj)`
- `notify_when(when, callback)`: Register a callback that will be called when an event happens.
- `parse_command_line3(cmdline: str) -> PyObject *`
- `set_script_timeout(timeout)`: Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
- `disable_script_timeout()`: Disables the script timeout and hides the script wait box.
- `enable_extlang_python(enable)`: Enables or disables Python extlang.
- `enable_python_cli(enable: bool) -> None`
- `format_basestring(_in: PyObject *) -> str`
- `pygc_refresh(_self: PyObject *) -> None`
- `pygc_create_groups(_self: PyObject *, groups_infos: PyObject *) -> PyObject *`
- `pygc_delete_groups(_self: PyObject *, groups: PyObject *, new_current: PyObject *) -> PyObject *`
- `pygc_set_groups_visibility(_self: PyObject *, groups: PyObject *, expand: PyObject *, new_current: PyObject *) -> PyObject *`
- `pycim_get_widget(_self: PyObject *) -> TWidget *`
- `pycim_view_close(_self: PyObject *) -> None`