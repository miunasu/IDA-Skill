# ida_offset

Functions that deal with offsets.

Being an offset is a characteristic of an operand. This means that operand or its part represent offset from some address in the program. This linear address is called offset base. Some operands may have 2 offsets simultaneously. Generally, IDA doesnt handle this except for Motorola outer offsets. Thus there may be two offset values in an operand: simple offset and outer offset.
Outer offsets are handled by specifying special operand number: it should be ORed with OPND_OUTER value.
See bytes.hpp for further explanation of operand numbers.

## Functions Overview

- `get_default_reftype(ea: ida_idaapi.ea_t) -> reftype_t`: Get default reference type depending on the segment.
- `op_offset_ex(ea: ida_idaapi.ea_t, n: int, ri: refinfo_t) -> bool`: Convert operand to a reference. To delete an offset, use clr_op_type() function.
- `op_offset(*args) -> bool`: See op_offset_ex()
- `op_plain_offset(ea: ida_idaapi.ea_t, n: int, base: ida_idaapi.ea_t) -> bool`: Convert operand to a reference with the default reference type.
- `get_offbase(ea: ida_idaapi.ea_t, n: int) -> ida_idaapi.ea_t`: Get offset base value
- `get_offset_expression(ea: ida_idaapi.ea_t, n: int, _from: ida_idaapi.ea_t, offset: adiff_t, getn_flags: int = 0) -> str`: Get offset expression (in the form "offset name+displ"). This function uses offset translation function ( processor_t::translate) if your IDP module has such a function. Translation function is used to map linear addresses in the program (only for offsets).
- `get_offset_expr(ea: ida_idaapi.ea_t, n: int, ri: refinfo_t, _from: ida_idaapi.ea_t, offset: adiff_t, getn_flags: int = 0) -> str`: See get_offset_expression()
- `can_be_off32(ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Does the specified address contain a valid OFF32 value?. For symbols in special segments the displacement is not taken into account. If yes, then the target address of OFF32 will be returned. If not, then BADADDR is returned.
- `calc_offset_base(ea: ida_idaapi.ea_t, n: int) -> ida_idaapi.ea_t`: Try to calculate the offset base This function takes into account the fixup information, current ds and cs values.
- `calc_probable_base_by_value(ea: ida_idaapi.ea_t, off: int) -> ida_idaapi.ea_t`: Try to calculate the offset base. 2 bases are checked: current ds and cs. If fails, return BADADDR
- `calc_reference_data(target: ea_t *, base: ea_t *, _from: ida_idaapi.ea_t, ri: refinfo_t, opval: adiff_t) -> bool`: Calculate the target and base addresses of an offset expression. The calculated target and base addresses are returned in the locations pointed by 'base' and 'target'. In case 'ri.base' is BADADDR, the function calculates the offset base address from the referencing instruction/data address. The target address is copied from ri.target. If ri.target is BADADDR then the target is calculated using the base address and 'opval'. This function also checks if 'opval' matches the full value of the reference and takes in account the memory-mapping.
- `add_refinfo_dref(insn: insn_t const &, _from: ida_idaapi.ea_t, ri: refinfo_t, opval: adiff_t, type: dref_t, opoff: int) -> ida_idaapi.ea_t`: Add xrefs for a reference from the given instruction ( insn_t::ea). This function creates a cross references to the target and the base. insn_t::add_off_drefs() calls this function to create xrefs for 'offset' operand.
- `calc_target(*args) -> ida_idaapi.ea_t`: This function has the following signatures:
- `calc_basevalue(target: ida_idaapi.ea_t, base: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Calculate the value of the reference base.