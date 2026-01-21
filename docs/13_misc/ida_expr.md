# ida_expr

Functions that deal with C-like expressions and built-in IDC language.

Functions marked THREAD_SAFE may be called from any thread. No simultaneous calls should be made for the same variable. We protect only global structures, individual variables must be protected manually.

## Constants

- `IDC_LANG_EXT`: IDC script extension.
- `VARSLICE_SINGLE`: return single index (i2 is ignored)
- `VREF_LOOP`: dereference until we get a non VT_REF
- `VREF_ONCE`: dereference only once, do not loop
- `VREF_COPY`: copy the result to the input var (v)
- `VT_LONG`: Integer (see idc_value_t::num)
- `VT_FLOAT`: Floating point (see idc_value_t::e)
- `VT_WILD`: Function with arbitrary number of arguments. The actual number of arguments will be passed in idc_value_t::num. This value should not be used for idc_value_t.
- `VT_OBJ`: Object (see idc_value_t::obj)
- `VT_FUNC`: Function (see idc_value_t::funcidx)
- `VT_STR`: String (see qstr() and similar functions)
- `VT_PVOID`: void *
- `VT_INT64`: i64
- `VT_REF`: Reference.
- `eExecThrow`: See return value of idc_func_t.
- `HF_DEFAULT`
- `HF_KEYWORD1`
- `HF_KEYWORD2`
- `HF_KEYWORD3`
- `HF_STRING`
- `HF_COMMENT`
- `HF_PREPROC`
- `HF_NUMBER`
- `HF_USER1`
- `HF_USER2`
- `HF_USER3`
- `HF_USER4`
- `HF_MAX`
- `CPL_DEL_MACROS`: delete macros at the end of compilation
- `CPL_USE_LABELS`: allow program labels in the script
- `CPL_ONLY_SAFE`: allow calls of only thread-safe functions
- `EXTFUN_BASE`: requires open database.
- `EXTFUN_NORET`: does not return. the interpreter may clean up its state before calling it.
- `EXTFUN_SAFE`: thread safe function. may be called from any thread.

## Classes Overview

- `idc_value_t`
- `idc_global_t`
- `highlighter_cbs_t`
- `idc_values_t`

## Functions Overview

- `compile_idc_file(nonnul_line: str) -> str`
- `compile_idc_text(nonnul_line: str) -> str`
- `py_get_call_idc_func() -> size_t`
- `pyw_register_idc_func(name: str, args: str, py_fp: PyObject *) -> size_t`
- `pyw_unregister_idc_func(ctxptr: size_t) -> bool`
- `pyw_convert_defvals(out: idc_values_t, py_seq: PyObject *) -> bool`
- `py_add_idc_func(name: str, fp_ptr: size_t, args: str, defvals: idc_values_t, flags: int) -> bool`
- `eval_expr(rv: idc_value_t, where: ida_idaapi.ea_t, line: str) -> str`: Compile and calculate an expression.
- `eval_idc_expr(rv: idc_value_t, where: ida_idaapi.ea_t, line: str) -> str`: Same as eval_expr(), but will always use the IDC interpreter regardless of the currently installed extlang.
- `idcv_long(v: idc_value_t) -> error_t`: Convert IDC variable to a long (32/64bit) number.
- `idcv_int64(v: idc_value_t) -> error_t`: Convert IDC variable to a 64bit number.
- `idcv_num(v: idc_value_t) -> error_t`: Convert IDC variable to a long number.
- `idcv_string(v: idc_value_t) -> error_t`: Convert IDC variable to a text string.
- `idcv_float(v: idc_value_t) -> error_t`: Convert IDC variable to a floating point.
- `idcv_object(v: idc_value_t, icls: idc_class_t const * = None) -> error_t`: Create an IDC object. The original value of 'v' is discarded (freed).
- `move_idcv(dst: idc_value_t, src: idc_value_t) -> error_t`: Move 'src' to 'dst'. This function is more effective than copy_idcv since it never copies big amounts of data.
- `copy_idcv(dst: idc_value_t, src: idc_value_t) -> error_t`: Copy 'src' to 'dst'. For idc objects only a reference is copied.
- `deep_copy_idcv(dst: idc_value_t, src: idc_value_t) -> error_t`: Deep copy an IDC object. This function performs deep copy of idc objects. If 'src' is not an object, copy_idcv() will be called
- `free_idcv(v: idc_value_t) -> None`: Free storage used by VT_STR/VT_OBJ IDC variables. After this call the variable has a numeric value 0
- `swap_idcvs(v1: idc_value_t, v2: idc_value_t) -> None`: Swap 2 variables.
- `get_idcv_class_name(obj: idc_value_t) -> str`: Retrieves the IDC object class name.
- `get_idcv_attr(res: idc_value_t, obj: idc_value_t, attr: str, may_use_getattr: bool = False) -> error_t`: Get an object attribute.
- `set_idcv_attr(obj: idc_value_t, attr: str, value: idc_value_t, may_use_setattr: bool = False) -> error_t`: Set an object attribute.
- `del_idcv_attr(obj: idc_value_t, attr: str) -> error_t`: Delete an object attribute.
- `first_idcv_attr(obj: idc_value_t) -> str`
- `last_idcv_attr(obj: idc_value_t) -> str`
- `next_idcv_attr(obj: idc_value_t, attr: str) -> str`
- `prev_idcv_attr(obj: idc_value_t, attr: str) -> str`
- `print_idcv(v: idc_value_t, name: str = None, indent: int = 0) -> str`: Get text representation of idc_value_t.
- `get_idcv_slice(res: idc_value_t, v: idc_value_t, i1: int, i2: int, flags: int = 0) -> error_t`: Get slice.
- `set_idcv_slice(v: idc_value_t, i1: int, i2: int, _in: idc_value_t, flags: int = 0) -> error_t`: Set slice.
- `add_idc_class(name: str, super: idc_class_t const * = None) -> idc_class_t *`: Create a new IDC class.
- `find_idc_class(name: str) -> idc_class_t *`: Find an existing IDC class by its name.
- `deref_idcv(v: idc_value_t, vref_flags: int) -> idc_value_t *`: Dereference a VT_REF variable.
- `create_idcv_ref(ref: idc_value_t, v: idc_value_t) -> bool`: Create a variable reference. Currently only references to global variables can be created.
- `add_idc_gvar(name: str) -> idc_value_t *`: Add global IDC variable.
- `find_idc_gvar(name: str) -> idc_value_t *`: Find an existing global IDC variable by its name.
- `find_idc_func(prefix: str, n: int = 0) -> str`
- `set_header_path(path: str, add: bool) -> bool`: Set or append a header path. IDA looks for the include files in the appended header paths, then in the ida executable directory.
- `get_idc_filename(file: str) -> str`: Get full name of IDC file name. Search for file in list of include directories, IDCPATH directory and system directories.
- `exec_system_script(file: str, complain_if_no_file: bool = True) -> bool`: Compile and execute "main" function from system file.
- `compile_idc_snippet(func: str, text: str, resolver: idc_resolver_t * = None, only_safe_funcs: bool = False) -> str`: Compile text with IDC statements.
- `exec_idc_script(result: idc_value_t, path: str, func: str, args: idc_value_t, argsnum: size_t) -> str`: Compile and execute IDC function(s) from file.
- `throw_idc_exception(r: idc_value_t, desc: str) -> error_t`: Create an idc execution exception object. This helper function can be used to return an exception from C++ code to IDC. In other words this function can be called from idc_func_t() callbacks. Sample usage: if ( !ok ) return throw_idc_exception(r, "detailed error msg");
- `del_idc_func(name)`: Delete an IDC function
- `add_idc_func(name, fp, args, (), flags=0)`: Add an IDC function. This function does not modify the predefined kernel functions. Example: