# ida_libfuncs

## Constants

- `SIGN_HEADER_MAGIC`
- `SIGN_HEADER_VERSION`
- `OSTYPE_MSDOS`
- `OSTYPE_WIN`
- `OSTYPE_OS2`
- `OSTYPE_NETW`
- `OSTYPE_UNIX`
- `OSTYPE_OTHER`
- `APPT_CONSOLE`
- `APPT_GRAPHIC`
- `APPT_PROGRAM`
- `APPT_LIBRARY`
- `APPT_DRIVER`
- `APPT_1THREAD`
- `APPT_MTHREAD`
- `APPT_16BIT`
- `APPT_32BIT`
- `APPT_64BIT`
- `LS_STARTUP`
- `LS_CTYPE`
- `LS_CTYPE2`
- `LS_CTYPE_ALT`
- `LS_ZIP`
- `LS_CTYPE_3V`

## Classes Overview

- `idasgn_header_t`

## Functions Overview

- `get_idasgn_header_by_short_name(out_header: idasgn_header_t, name: str) -> str`: Get idasgn header by a short signature name.
- `get_idasgn_path_by_short_name(name: str) -> str`: Get idasgn full path by a short signature name.