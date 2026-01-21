# ida_tryblks

Architecture independent exception handling info.

Try blocks have the following general properties:
* A try block specifies a possibly fragmented guarded code region.
* Each try block has always at least one catch/except block description
* Each catch block contains its boundaries and a filter.
* Additionally a catch block can hold sp adjustment and the offset to the exception object offset (C++).
* Try blocks can be nested. Nesting is automatically calculated at the retrieval time.
* There may be (nested) multiple try blocks starting at the same address.

See examples in tests/input/src/eh_tests.

## Constants

- `TBERR_OK`: ok
- `TBERR_START`: bad start address
- `TBERR_END`: bad end address
- `TBERR_ORDER`: bad address order
- `TBERR_EMPTY`: empty try block
- `TBERR_KIND`: illegal try block kind
- `TBERR_NO_CATCHES`: no catch blocks at all
- `TBERR_INTERSECT`: range would intersect inner tryblk
- `TBEA_TRY`: is EA within a c++ try block?
- `TBEA_CATCH`: is EA the start of a c++ catch/cleanup block?
- `TBEA_SEHTRY`: is EA within a seh try block
- `TBEA_SEHLPAD`: is EA the start of a seh finally/except block?
- `TBEA_SEHFILT`: is EA the start of a seh filter?
- `TBEA_ANY`
- `TBEA_FALLTHRU`: is there a fall through into provided ea from an unwind region

## Classes Overview

- `tryblks_t`
- `catchvec_t`
- `try_handler_t`
- `seh_t`
- `catch_t`
- `tryblk_t`

## Functions Overview

- `get_tryblks(tbv: tryblks_t, range: range_t) -> size_t`: ------------------------------------------------------------------------- Retrieve try block information from the specified address range. Try blocks are sorted by starting address and their nest levels calculated.
- `del_tryblks(range: range_t) -> None`: Delete try block information in the specified range.
- `add_tryblk(tb: tryblk_t) -> int`: Add one try block information.
- `find_syseh(ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Find the start address of the system eh region including the argument.
- `is_ea_tryblks(ea: ida_idaapi.ea_t, flags: int) -> bool`: Check if the given address ea is part of tryblks description.