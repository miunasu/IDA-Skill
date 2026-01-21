# ida_frame

Routines to manipulate function stack frames, stack variables, register variables and local labels.

The frame is represented as a structure:

To access the structure of a function frame and stack variables, use:

## Constants

- `FRAME_UDM_NAME_R`
- `FRAME_UDM_NAME_S`
- `FPC_ARGS`
- `FPC_RETADDR`
- `FPC_SAVREGS`
- `FPC_LVARS`
- `STKVAR_VALID_SIZE`: x.dtyp contains correct variable type (for insns like 'lea' this bit must be off). In general, dr_O references do not allow to determine the variable size
- `STKVAR_KEEP_EXISTING`: if a stack variable for this operand already exists then we do not create a new variable
- `REGVAR_ERROR_OK`: all ok
- `REGVAR_ERROR_ARG`: function arguments are bad
- `REGVAR_ERROR_RANGE`: the definition range is bad
- `REGVAR_ERROR_NAME`: the provided name(s) can't be accepted

## Classes Overview

- `xreflist_t`
- `stkpnt_t`
- `stkpnts_t`
- `regvar_t`
- `xreflist_entry_t`

## Functions Overview

- `is_funcarg_off(pfn: func_t const *, frameoff: int) -> bool`
- `lvar_off(pfn: func_t const *, frameoff: int) -> int`
- `add_frame(pfn: func_t *, frsize: int, frregs: ushort, argsize: asize_t) -> bool`: Add function frame.
- `del_frame(pfn: func_t *) -> bool`: Delete a function frame.
- `set_frame_size(pfn: func_t *, frsize: asize_t, frregs: ushort, argsize: asize_t) -> bool`: Set size of function frame. Note: The returned size may not include all stack arguments. It does so only for __stdcall and __fastcall calling conventions. To get the entire frame size for all cases use frame.get_func_frame(pfn).get_size()
- `get_frame_size(pfn: func_t const *) -> asize_t`: Get full size of a function frame. This function takes into account size of local variables + size of saved registers + size of return address + number of purged bytes. The purged bytes correspond to the arguments of the functions with __stdcall and __fastcall calling conventions.
- `get_frame_retsize(pfn: func_t const *) -> int`: Get size of function return address.
- `get_frame_part(range: range_t, pfn: func_t const *, part: frame_part_t) -> None`: Get offsets of the frame part in the frame.
- `frame_off_args(pfn: func_t const *) -> ida_idaapi.ea_t`: Get starting address of arguments section.
- `frame_off_retaddr(pfn: func_t const *) -> ida_idaapi.ea_t`: Get starting address of return address section.
- `frame_off_savregs(pfn: func_t const *) -> ida_idaapi.ea_t`: Get starting address of saved registers section.
- `frame_off_lvars(pfn: func_t const *) -> ida_idaapi.ea_t`: Get start address of local variables section.
- `get_func_frame(out: tinfo_t, pfn: func_t const *) -> bool`: Get type of function frame
- `soff_to_fpoff(pfn: func_t *, soff: int) -> int`: Convert struct offsets into fp-relative offsets. This function converts the offsets inside the udt_type_data_t object into the frame pointer offsets (for example, EBP-relative).
- `update_fpd(pfn: func_t *, fpd: asize_t) -> bool`: Update frame pointer delta.
- `set_purged(ea: ida_idaapi.ea_t, nbytes: int, override_old_value: bool) -> bool`: Set the number of purged bytes for a function or data item (funcptr). This function will update the database and plan to reanalyze items referencing the specified address. It works only for processors with PR_PURGING bit in 16 and 32 bit modes.
- `define_stkvar(pfn: func_t *, name: str, off: int, tif: tinfo_t, repr: value_repr_t = None) -> bool`: Define/redefine a stack variable.
- `add_frame_member(pfn: func_t const *, name: str, offset: int, tif: tinfo_t, repr: value_repr_t = None, etf_flags: uint = 0) -> bool`: Add member to the frame type
- `is_anonymous_member_name(name: str) -> bool`: Is member name prefixed with "anonymous"?
- `is_dummy_member_name(name: str) -> bool`: Is member name an auto-generated name?
- `is_special_frame_member(tid: tid_t) -> bool`: Is stkvar with TID the return address slot or the saved registers slot ?
- `set_frame_member_type(pfn: func_t const *, offset: int, tif: tinfo_t, repr: value_repr_t = None, etf_flags: uint = 0) -> bool`: Change type of the frame member
- `delete_frame_members(pfn: func_t const *, start_offset: int, end_offset: int) -> bool`: Delete frame members
- `build_stkvar_name(pfn: func_t const *, v: int) -> str`: Build automatic stack variable name.
- `calc_stkvar_struc_offset(pfn: func_t *, insn: insn_t const &, n: int) -> ida_idaapi.ea_t`: Calculate offset of stack variable in the frame structure.
- `calc_frame_offset(pfn: func_t *, off: int, insn: insn_t const * = None, op: op_t const * = None) -> int`: Calculate the offset of stack variable in the frame.
- `free_regvar(v: regvar_t) -> None`
- `add_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str, user: str, cmt: str) -> int`: Define a register variable.
- `find_regvar(*args) -> regvar_t *`: This function has the following signatures:
- `has_regvar(pfn: func_t *, ea: ida_idaapi.ea_t) -> bool`: Is there a register variable definition?
- `rename_regvar(pfn: func_t *, v: regvar_t, user: str) -> int`: Rename a register variable.
- `set_regvar_cmt(pfn: func_t *, v: regvar_t, cmt: str) -> int`: Set comment for a register variable.
- `del_regvar(pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, canon: str) -> int`: Delete a register variable definition.
- `add_auto_stkpnt(pfn: func_t *, ea: ida_idaapi.ea_t, delta: int) -> bool`: Add automatic SP register change point.
- `add_user_stkpnt(ea: ida_idaapi.ea_t, delta: int) -> bool`: Add user-defined SP register change point.
- `del_stkpnt(pfn: func_t *, ea: ida_idaapi.ea_t) -> bool`: Delete SP register change point.
- `get_spd(pfn: func_t *, ea: ida_idaapi.ea_t) -> int`: Get difference between the initial and current values of ESP.
- `get_effective_spd(pfn: func_t *, ea: ida_idaapi.ea_t) -> int`: Get effective difference between the initial and current values of ESP. This function returns the sp-diff used by the instruction. The difference between get_spd() and get_effective_spd() is present only for instructions like "pop [esp+N]": they modify sp and use the modified value.
- `get_sp_delta(pfn: func_t *, ea: ida_idaapi.ea_t) -> int`: Get modification of SP made at the specified location
- `set_auto_spd(pfn: func_t *, ea: ida_idaapi.ea_t, new_spd: int) -> bool`: Add such an automatic SP register change point so that at EA the new cumulative SP delta (that is, the difference between the initial and current values of SP) would be equal to NEW_SPD.
- `recalc_spd(cur_ea: ida_idaapi.ea_t) -> bool`: Recalculate SP delta for an instruction that stops execution. The next instruction is not reached from the current instruction. We need to recalculate SP for the next instruction.
- `recalc_spd_for_basic_block(pfn: func_t *, cur_ea: ida_idaapi.ea_t) -> bool`: Recalculate SP delta for the current instruction. The typical code snippet to calculate SP delta in a proc module is:
- `build_stkvar_xrefs(out: xreflist_t, pfn: func_t *, start_offset: int, end_offset: int) -> None`: Fill 'out' with a list of all the xrefs made from function 'pfn' to specified range of the pfn's stack frame.