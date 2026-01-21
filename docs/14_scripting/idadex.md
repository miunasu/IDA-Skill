# idadex

## Constants

- `uint8`
- `char`
- `uint32`
- `uint64`
- `uint16`
- `ushort`
- `ea_t`
- `dex`

## Classes Overview

- `dex_method`: Structure base class
- `dex_field`: Structure base class
- `longname_director_t`: Structure base class
- `Dex`

## Functions Overview

- `to_uint32(v)`
- `get_struct(str_, off, struct)`
- `unpack_db(buf, off)`
- `get_dw(buf, off)`
- `unpack_dw(buf, off)`
- `unpack_dd(buf, off)`
- `unpack_dq(buf, off)`
- `unpack_ea(buf, off)`
- `unpack_eavec(buf, base_ea)`