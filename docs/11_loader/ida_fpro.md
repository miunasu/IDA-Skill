# ida_fpro

System independent counterparts of FILE* related functions from Clib.

You should not use C standard I/O functions in your modules. The reason: Each module compiled with Borland (and statically linked to Borlands library) will host a copy of the FILE * information.
So, if you open a file in the plugin and pass the handle to the kernel, the kernel will not be able to use it.
If you really need to use the standard functions, define USE_STANDARD_FILE_FUNCTIONS. In this case do not mix them with q¦ functions.

## Constants

- `QMOVE_CROSS_FS`
- `QMOVE_OVERWRITE`
- `QMOVE_OVR_RO`
- `qfile_t_from_fp`
- `qfile_t_from_capsule`
- `qfile_t_tmpfile`

## Classes Overview

- `qfile_t`: A helper class to work with FILE related functions.

## Functions Overview

- `qfclose(fp: FILE *) -> int`