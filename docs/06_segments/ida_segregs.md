# ida_segregs

Functions that deal with the segment registers.

If your processor doesnt use segment registers, then these functions are of no use for you. However, you should define two virtual segment registers - CS and DS (for code segment and data segment) and specify their internal numbers in the LPH structure (processor_t::reg_code_sreg and processor_t::reg_data_sreg).

## Constants

- `R_es`
- `R_cs`
- `R_ss`
- `R_ds`
- `R_fs`
- `R_gs`
- `SR_inherit`: the value is inherited from the previous range
- `SR_user`: the value is specified by the user
- `SR_auto`: the value is determined by IDA
- `SR_autostart`: used as SR_auto for segment starting address

## Classes Overview

- `sreg_range_t`

## Functions Overview

- `get_sreg(ea: ida_idaapi.ea_t, rg: int) -> sel_t`: Get value of a segment register. This function uses segment register range and default segment register values stored in the segment structure.
- `split_sreg_range(ea: ida_idaapi.ea_t, rg: int, v: sel_t, tag: uchar, silent: bool = False) -> bool`: Create a new segment register range. This function is used when the IDP emulator detects that a segment register changes its value.
- `set_default_sreg_value(sg: segment_t *, rg: int, value: sel_t) -> bool`: Set default value of a segment register for a segment.
- `set_sreg_at_next_code(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, rg: int, value: sel_t) -> None`: Set the segment register value at the next instruction. This function is designed to be called from idb_event::sgr_changed handler in order to contain the effect of changing a segment register value only until the next instruction.
- `get_sreg_range(out: sreg_range_t, ea: ida_idaapi.ea_t, rg: int) -> bool`: Get segment register range by linear address.
- `get_prev_sreg_range(out: sreg_range_t, ea: ida_idaapi.ea_t, rg: int) -> bool`: Get segment register range previous to one with address.
- `set_default_dataseg(ds_sel: sel_t) -> None`: Set default value of DS register for all segments.
- `get_sreg_ranges_qty(rg: int) -> size_t`: Get number of segment register ranges.
- `getn_sreg_range(out: sreg_range_t, rg: int, n: int) -> bool`: Get segment register range by its number.
- `get_sreg_range_num(ea: ida_idaapi.ea_t, rg: int) -> int`: Get number of segment register range by address.
- `del_sreg_range(ea: ida_idaapi.ea_t, rg: int) -> bool`: Delete segment register range started at ea. When a segment register range is deleted, the previous range is extended to cover the empty space. The segment register range at the beginning of a segment cannot be deleted.
- `copy_sreg_ranges(dst_rg: int, src_rg: int, map_selector: bool = False) -> None`: Duplicate segment register ranges.