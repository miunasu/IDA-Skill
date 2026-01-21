# ida_ua

Functions that deal with the disassembling of program instructions.

There are 2 kinds of functions:

Disassembly of an instruction is made in three steps:

The kernel calls the IDP module to perform these steps. At first, the kernel
always calls the analysis. The analyzer must decode the instruction and fill
the insn_t instance that it receives through its callback. It must not change
anything in the database.

The second step, the emulation, is called for each instruction. This step must
make necessary changes to the database, plan analysis of subsequent instructions,
track register values, memory contents, etc. Please keep in mind that the kernel
may call the emulation step for any address in the program - there is no ordering
of addresses. Usually, the emulation is called for consecutive addresses but
this is not guaranteed.

The last step, conversion to text, is called each time an instruction is
displayed on the screen. The kernel will always call the analysis step before
calling the text conversion step. The emulation and the text conversion steps
should use the information stored in the insn_t instance they receive. They
should not access the bytes of the instruction and decode it again - this
should only be done in the analysis step.

## Constants

- `cvar`
- `o_void`: No Operand.
- `o_reg`: General Register (al,ax,es,ds...).
- `o_mem`: A direct memory reference to a data item. Use this operand type when the address can be calculated statically.
- `o_phrase`: An indirect memory reference that uses a register: [reg] There can be several registers but no displacement.
- `o_displ`: An indirect memory reference that uses a register and has an immediate constant added to it: [reg+N] There can be several registers.
- `o_imm`: An immediate Value (constant).
- `o_far`: An immediate far code reference (inter-segment)
- `o_near`: An immediate near code reference (intra-segment)
- `o_idpspec0`: processor specific type.
- `o_idpspec1`: processor specific type.
- `o_idpspec2`: processor specific type.
- `o_idpspec3`: processor specific type.
- `o_idpspec4`: processor specific type.
- `o_idpspec5`: processor specific type. (there can be more processor specific types)
- `OF_NO_BASE_DISP`: base displacement doesn't exist. meaningful only for o_displ type. if set, base displacement (op_t::addr) doesn't exist.
- `OF_OUTER_DISP`: outer displacement exists. meaningful only for o_displ type. if set, outer displacement (op_t::value) exists.
- `PACK_FORM_DEF`: packed factor defined. (!o_reg + dt_packreal)
- `OF_NUMBER`: the operand can be converted to a number only
- `OF_SHOW`: should the operand be displayed?
- `dt_byte`: 8 bit integer
- `dt_word`: 16 bit integer
- `dt_dword`: 32 bit integer
- `dt_float`: 4 byte floating point
- `dt_double`: 8 byte floating point
- `dt_tbyte`: variable size ( processor_t::tbyte_size) floating point
- `dt_packreal`: packed real format for mc68040
- `dt_qword`: 64 bit integer
- `dt_byte16`: 128 bit integer
- `dt_code`: ptr to code
- `dt_void`: none
- `dt_fword`: 48 bit
- `dt_bitfild`: bit field (mc680x0)
- `dt_string`: pointer to asciiz string
- `dt_unicode`: pointer to unicode string
- `dt_ldbl`: long double (which may be different from tbyte)
- `dt_byte32`: 256 bit integer
- `dt_byte64`: 512 bit integer
- `dt_half`: 2-byte floating point
- `INSN_MACRO`: macro instruction
- `INSN_MODMAC`: may modify the database to make room for the macro insn
- `INSN_64BIT`: belongs to 64bit segment?
- `STKVAR_VALID_SIZE`: x.dtype contains correct variable type (for insns like 'lea' this bit must be off). in general, dr_O references do not allow to determine the variable size
- `STKVAR_KEEP_EXISTING`: if a stack variable for this operand already exists then we do not create a new variable
- `CTXF_MAIN`: produce only the essential line(s)
- `CTXF_MULTI`: enable multi-line essential lines
- `CTXF_CODE`: display as code regardless of the database flags
- `CTXF_STACK`: stack view (display undefined items as 2/4/8 bytes)
- `CTXF_GEN_XREFS`: generate the xrefs along with the next line
- `CTXF_XREF_STATE`: xref state:
- `XREFSTATE_NONE`: not generated yet
- `XREFSTATE_GO`: being generated
- `XREFSTATE_DONE`: have been generated
- `CTXF_GEN_CMT`: generate the comment along with the next line
- `CTXF_CMT_STATE`: comment state:
- `COMMSTATE_NONE`: not generated yet
- `COMMSTATE_GO`: being generated
- `COMMSTATE_DONE`: have been generated
- `CTXF_VOIDS`: display void marks
- `CTXF_NORMAL_LABEL`: generate plain label (+demangled label as cmt)
- `CTXF_DEMANGLED_LABEL`: generate only demangled label as comment
- `CTXF_LABEL_OK`: the label have been generated
- `CTXF_DEMANGLED_OK`: the label has been demangled successfully
- `CTXF_OVSTORE_PRNT`: out_value should store modified values
- `CTXF_OUTCTX_T`: instance is, in fact, a outctx_t
- `CTXF_DBLIND_OPND`: an operand was printed with double indirection (e.g. =var in arm)
- `CTXF_BINOP_STATE`: opcode bytes state:
- `BINOPSTATE_NONE`: not generated yet
- `BINOPSTATE_GO`: being generated
- `BINOPSTATE_DONE`: have been generated
- `CTXF_HIDDEN_ADDR`: generate an hidden addr tag at the beginning of the line
- `CTXF_BIT_PREFIX`: generate a line prefix with a bit offset, e.g.: 12345678.3
- `CTXF_UNHIDE`: display hidden objects (segment, function, range)
- `OOF_SIGNMASK`: sign symbol (+/-) output
- `OOFS_IFSIGN`: output sign if needed
- `OOFS_NOSIGN`: don't output sign, forbid the user to change the sign
- `OOFS_NEEDSIGN`: always out sign (+-)
- `OOF_SIGNED`: output as signed if < 0
- `OOF_NUMBER`: always as a number
- `OOF_WIDTHMASK`: width of value in bits
- `OOFW_IMM`: take from x.dtype
- `OOFW_8`: 8 bit width
- `OOFW_16`: 16 bit width
- `OOFW_24`: 24 bit width
- `OOFW_32`: 32 bit width
- `OOFW_64`: 64 bit width
- `OOF_ADDR`: output x.addr, otherwise x.value OOF_WIDTHMASK must be explicitly specified with it
- `OOF_OUTER`: output outer operand
- `OOF_ZSTROFF`: meaningful only if is_stroff(F); append a struct field name if the field offset is zero? if AFL_ZSTROFF is set, then this flag is ignored.
- `OOF_NOBNOT`: prohibit use of binary not
- `OOF_SPACES`: do not suppress leading spaces; currently works only for floating point numbers
- `OOF_ANYSERIAL`: if enum: select first available serial
- `OOF_LZEROES`: print leading zeroes
- `OOF_NO_LZEROES`: do not print leading zeroes; if none of OOF_LZEROES and OOF_NO_LZEROES was specified, is_lzero() is used
- `DEFAULT_INDENT`
- `MAKELINE_NONE`
- `MAKELINE_BINPREF`: allow display of binary prefix
- `MAKELINE_VOID`: allow display of '<suspicious>' marks
- `MAKELINE_STACK`: allow display of sp trace prefix
- `GH_PRINT_PROC`: processor name
- `GH_PRINT_ASM`: selected assembler
- `GH_PRINT_BYTESEX`: byte sex
- `GH_PRINT_HEADER`: lines from ash.header
- `GH_BYTESEX_HAS_HIGHBYTE`: describe inf.is_wide_high_byte_first()
- `GH_PRINT_PROC_AND_ASM`
- `GH_PRINT_PROC_ASM_AND_BYTESEX`
- `GH_PRINT_ALL`
- `GH_PRINT_ALL_BUT_BYTESEX`
- `FCBF_CONT`: don't stop on decoding, or any other kind of error
- `FCBF_ERR_REPL`: in case of an error, use a CP_REPLCHAR instead of a hex representation of the problematic byte
- `FCBF_FF_LIT`: in case of codepoints == 0xFF, use it as-is (i.e., LATIN SMALL LETTER Y WITH DIAERESIS). If both this, and FCBF_REPL are specified, this will take precedence
- `FCBF_DELIM`: add the 'ash'-specified delimiters around the generated data. Note: if those are not defined and the INFFL_ALLASM is not set, format_charlit() will return an error
- `ua_mnem`

## Classes Overview

- `operands_array`
- `op_t`
- `insn_t`
- `outctx_base_t`
- `outctx_t`
- `macro_constructor_t`

## Functions Overview

- `insn_add_cref(insn: insn_t, to: ida_idaapi.ea_t, opoff: int, type: cref_t) -> None`
- `insn_add_dref(insn: insn_t, to: ida_idaapi.ea_t, opoff: int, type: dref_t) -> None`
- `insn_add_off_drefs(insn: insn_t, x: op_t, type: dref_t, outf: int) -> ida_idaapi.ea_t`
- `insn_create_stkvar(insn: insn_t, x: op_t, v: adiff_t, flags: int) -> bool`
- `get_lookback() -> int`: Number of instructions to look back. This variable is not used by the kernel. Its value may be specified in ida.cfg: LOOKBACK = <number>. IDP may use it as you like it. (TMS module uses it)
- `calc_dataseg(insn: insn_t, n: int = -1, rgnum: int = -1) -> ida_idaapi.ea_t`
- `map_data_ea(*args) -> ida_idaapi.ea_t`
- `map_code_ea(*args) -> ida_idaapi.ea_t`
- `map_ea(*args) -> ida_idaapi.ea_t`
- `create_outctx(ea: ida_idaapi.ea_t, F: flags64_t = 0, suspop: int = 0) -> outctx_base_t *`: Create a new output context. To delete it, just use "delete pctx"
- `print_insn_mnem(ea: ida_idaapi.ea_t) -> str`: Print instruction mnemonics.
- `get_dtype_flag(dtype: op_dtype_t) -> flags64_t`: Get flags for op_t::dtype field.
- `get_dtype_size(dtype: op_dtype_t) -> size_t`: Get size of opt_::dtype field.
- `is_floating_dtype(dtype: op_dtype_t) -> bool`: Is a floating type operand?
- `create_insn(ea: ida_idaapi.ea_t, out: insn_t = None) -> int`: Create an instruction at the specified address. This function checks if an instruction is present at the specified address and will try to create one if there is none. It will fail if there is a data item or other items hindering the creation of the new instruction. This function will also fill the 'out' structure.
- `decode_insn(out: insn_t, ea: ida_idaapi.ea_t) -> int`: Analyze the specified address and fill 'out'. This function does not modify the database. It just tries to interpret the specified address as an instruction and fills the 'out' structure.
- `can_decode(ea: ida_idaapi.ea_t) -> bool`: Can the bytes at address 'ea' be decoded as instruction?
- `print_operand(ea: ida_idaapi.ea_t, n: int, getn_flags: int = 0, newtype: printop_t = None) -> str`: Generate text representation for operand #n. This function will generate the text representation of the specified operand (includes color codes.)
- `decode_prev_insn(out: insn_t, ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Decode previous instruction if it exists, fill 'out'.
- `decode_preceding_insn(out: insn_t, ea: ida_idaapi.ea_t) -> Tuple[ida_idaapi.ea_t, bool]`: Decodes the preceding instruction.
- `construct_macro(*args)`: See ua.hpp's construct_macro().
- `get_dtype_by_size(size: asize_t) -> int`: Get op_t::dtype from size.
- `get_immvals(ea: ida_idaapi.ea_t, n: int, F: flags64_t = 0) -> PyObject *`: Get immediate values at the specified address. This function decodes instruction at the specified address or inspects the data item. It finds immediate values and copies them to 'out'. This function will store the original value of the operands in 'out', unless the last bits of 'F' are "...0 11111111", in which case the transformed values (as needed for printing) will be stored instead.
- `get_printable_immvals(ea: ida_idaapi.ea_t, n: int, F: flags64_t = 0) -> PyObject *`: Get immediate ready-to-print values at the specified address
- `insn_t__from_ptrval__(ptrval: size_t) -> insn_t *`
- `op_t__from_ptrval__(ptrval: size_t) -> op_t *`
- `outctx_base_t__from_ptrval__(ptrval: size_t) -> outctx_base_t *`
- `outctx_t__from_ptrval__(ptrval: size_t) -> outctx_t *`