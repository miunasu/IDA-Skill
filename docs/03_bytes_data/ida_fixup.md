# ida_fixup

Functions that deal with fixup information.

A loader should setup fixup information using set_fixup().

## Constants

- `FIXUP_OFF8`: 8-bit offset
- `FIXUP_OFF16`: 16-bit offset
- `FIXUP_SEG16`: 16-bit base-logical segment base (selector)
- `FIXUP_PTR16`: 32-bit long pointer (16-bit base:16-bit offset)
- `FIXUP_OFF32`: 32-bit offset
- `FIXUP_PTR32`: 48-bit pointer (16-bit base:32-bit offset)
- `FIXUP_HI8`: high 8 bits of 16bit offset
- `FIXUP_HI16`: high 16 bits of 32bit offset
- `FIXUP_LOW8`: low 8 bits of 16bit offset
- `FIXUP_LOW16`: low 16 bits of 32bit offset
- `V695_FIXUP_VHIGH`: obsolete
- `V695_FIXUP_VLOW`: obsolete
- `FIXUP_OFF64`: 64-bit offset
- `FIXUP_OFF8S`: 8-bit signed offset
- `FIXUP_OFF16S`: 16-bit signed offset
- `FIXUP_OFF32S`: 32-bit signed offset
- `FIXUP_CUSTOM`: start of the custom types range
- `FIXUPF_REL`: fixup is relative to the linear address base. Otherwise fixup is relative to the start of the segment with sel selector.
- `FIXUPF_EXTDEF`: target is a location (otherwise - segment). Use this bit if the target is a symbol rather than an offset from the beginning of a segment.
- `FIXUPF_UNUSED`: fixup is ignored by IDA
- `FIXUPF_CREATED`: fixup was not present in the input file
- `FIXUPF_LOADER_MASK`: additional flags. The bits from this mask are not stored in the database and can be used by the loader at its discretion.

## Classes Overview

- `fixup_data_t`
- `fixup_info_t`

## Functions Overview

- `is_fixup_custom(type: fixup_type_t) -> bool`: Is fixup processed by processor module?
- `get_fixup(fd: fixup_data_t, source: ida_idaapi.ea_t) -> bool`: Get fixup information.
- `exists_fixup(source: ida_idaapi.ea_t) -> bool`: Check that a fixup exists at the given address.
- `set_fixup(source: ida_idaapi.ea_t, fd: fixup_data_t) -> None`: Set fixup information. You should fill fixup_data_t and call this function and the kernel will remember information in the database.
- `del_fixup(source: ida_idaapi.ea_t) -> None`: Delete fixup information.
- `get_first_fixup_ea() -> ida_idaapi.ea_t`
- `get_next_fixup_ea(ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`
- `get_prev_fixup_ea(ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`
- `get_fixup_handler(type: fixup_type_t) -> fixup_handler_t const *`: Get handler of standard or custom fixup.
- `get_fixup_value(ea: ida_idaapi.ea_t, type: fixup_type_t) -> int`: Get the operand value. This function get fixup bytes from data or an instruction at ea and convert them to the operand value (maybe partially). It is opposite in meaning to the patch_fixup_value(). For example, FIXUP_HI8 read a byte at ea and shifts it left by 8 bits, or AArch64's custom fixup BRANCH26 get low 26 bits of the insn at ea and shifts it left by 2 bits. This function is mainly used to get a relocation addend.
- `patch_fixup_value(ea: ida_idaapi.ea_t, fd: fixup_data_t) -> bool`: Patch the fixup bytes. This function updates data or an instruction at ea to the fixup bytes. For example, FIXUP_HI8 updates a byte at ea to the high byte of fd->off, or AArch64's custom fixup BRANCH26 updates low 26 bits of the insn at ea to the value of fd->off shifted right by 2.
- `get_fixup_desc(source: ida_idaapi.ea_t, fd: fixup_data_t) -> str`: Get FIXUP description comment.
- `calc_fixup_size(type: fixup_type_t) -> int`: Calculate size of fixup in bytes (the number of bytes the fixup patches)
- `find_custom_fixup(name: str) -> fixup_type_t`
- `get_fixups(out: fixups_t *, ea: ida_idaapi.ea_t, size: asize_t) -> bool`
- `contains_fixups(ea: ida_idaapi.ea_t, size: asize_t) -> bool`: Does the specified address range contain any fixup information?
- `gen_fix_fixups(_from: ida_idaapi.ea_t, to: ida_idaapi.ea_t, size: asize_t) -> None`: Relocate the bytes with fixup information once more (generic function). This function may be called from loader_t::move_segm() if it suits the goal. If loader_t::move_segm is not defined then this function will be called automatically when moving segments or rebasing the entire program. Special parameter values (from = BADADDR, size = 0, to = delta) are used when the function is called from rebase_program(delta).
- `handle_fixups_in_macro(ri: refinfo_t, ea: ida_idaapi.ea_t, other: fixup_type_t, macro_reft_and_flags: int) -> bool`: Handle two fixups in a macro. We often combine two instruction that load parts of a value into one macro instruction. For example: