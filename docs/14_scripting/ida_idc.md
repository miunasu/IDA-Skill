# ida_idc

## Functions Overview

- `mark_position(ea: ida_idaapi.ea_t, lnnum: int, x: short, y: short, slot: int, comment: str) -> None`
- `get_marked_pos(slot: int) -> ida_idaapi.ea_t`
- `get_mark_comment(slot: int) -> PyObject *`