# ida_funcs

Routines for working with functions within the disassembled program.

This file also contains routines for working with library signatures (e.g. FLIRT).

Each function consists of function chunks. At least one function chunk must be present in the function definition - the function entry chunk. Other chunks are called function tails. There may be several of them for a function.

A function tail is a continuous range of addresses. It can be used in the definition of one or more functions. One function using the tail is singled out and called the tail owner. This function is considered as possessing the tail. get_func() on a tail address will return the function possessing the tail. You can enumerate the functions using the tail by using func_parent_iterator_t.

Each function chunk in the disassembly is represented as an range (a range of addresses, see range.hpp for details) with characteristics.
A function entry must start with an instruction (code) byte.

## Constants

- `FUNC_NORET`: Function doesn't return.
- `FUNC_FAR`: Far function.
- `FUNC_LIB`: Library function.
- `FUNC_STATICDEF`: Static function.
- `FUNC_FRAME`: Function uses frame pointer (BP)
- `FUNC_USERFAR`: User has specified far-ness of the function
- `FUNC_HIDDEN`: A hidden function chunk.
- `FUNC_THUNK`: Thunk (jump) function.
- `FUNC_BOTTOMBP`: BP points to the bottom of the stack frame.
- `FUNC_NORET_PENDING`: Function 'non-return' analysis must be performed. This flag is verified upon func_does_return()
- `FUNC_SP_READY`: SP-analysis has been performed. If this flag is on, the stack change points should not be not modified anymore. Currently this analysis is performed only for PC
- `FUNC_FUZZY_SP`: Function changes SP in untraceable way, for example: and esp, 0FFFFFFF0h
- `FUNC_PROLOG_OK`: Prolog analysis has been performed by last SP-analysis
- `FUNC_PURGED_OK`: 'argsize' field has been validated. If this bit is clear and 'argsize' is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module.
- `FUNC_TAIL`: This is a function tail. Other bits must be clear (except FUNC_HIDDEN).
- `FUNC_LUMINA`: Function info is provided by Lumina.
- `FUNC_OUTLINE`: Outlined code, not a real function.
- `FUNC_REANALYZE`: Function frame changed, request to reanalyze the function after the last insn is analyzed.
- `FUNC_UNWIND`: function is an exception unwind handler
- `FUNC_CATCH`: function is an exception catch handler
- `MOVE_FUNC_OK`: ok
- `MOVE_FUNC_NOCODE`: no instruction at 'newstart'
- `MOVE_FUNC_BADSTART`: bad new start address
- `MOVE_FUNC_NOFUNC`: no function at 'ea'
- `MOVE_FUNC_REFUSED`: a plugin refused the action
- `FIND_FUNC_NORMAL`: stop processing if undefined byte is encountered
- `FIND_FUNC_DEFINE`: create instruction if undefined byte is encountered
- `FIND_FUNC_IGNOREFN`: ignore existing function boundaries. by default the function returns function boundaries if ea belongs to a function.
- `FIND_FUNC_KEEPBD`: do not modify incoming function boundaries, just create instructions inside the boundaries.
- `FIND_FUNC_UNDEF`: function has instructions that pass execution flow to unexplored bytes. nfn->end_ea will have the address of the unexplored byte.
- `FIND_FUNC_OK`: ok, 'nfn' is ready for add_func()
- `FIND_FUNC_EXIST`: function exists already. its bounds are returned in 'nfn'.
- `IDASGN_OK`: ok
- `IDASGN_BADARG`: bad number of signature
- `IDASGN_APPLIED`: signature is already applied
- `IDASGN_CURRENT`: signature is currently being applied
- `IDASGN_PLANNED`: signature is planned to be applied
- `LIBFUNC_FOUND`: ok, library function is found
- `LIBFUNC_NONE`: no, this is not a library function
- `LIBFUNC_DELAY`: no decision because of lack of information

## Classes Overview

- `dyn_stkpnt_array`
- `dyn_regvar_array`
- `dyn_range_array`
- `dyn_ea_array`
- `dyn_regarg_array`
- `regarg_t`
- `func_t`
- `lock_func`
- `lock_func_with_tails_t`
- `func_tail_iterator_t`
- `func_item_iterator_t`
- `func_parent_iterator_t`

## Functions Overview

- `free_regarg(v: regarg_t) -> None`
- `is_func_entry(pfn: func_t) -> bool`: Does function describe a function entry chunk?
- `is_func_tail(pfn: func_t) -> bool`: Does function describe a function tail chunk?
- `lock_func_range(pfn: func_t, lock: bool) -> None`: Lock function pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.
- `is_func_locked(pfn: func_t) -> bool`: Is the function pointer locked?
- `get_func(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to function structure by address.
- `get_func_chunknum(pfn: func_t, ea: ida_idaapi.ea_t) -> int`: Get the containing tail chunk of 'ea'.
- `func_contains(pfn: func_t, ea: ida_idaapi.ea_t) -> bool`: Does the given function contain the given address?
- `is_same_func(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> bool`: Do two addresses belong to the same function?
- `getn_func(n: size_t) -> func_t *`: Get pointer to function structure by number.
- `get_func_qty() -> size_t`: Get total number of functions in the program.
- `get_func_num(ea: ida_idaapi.ea_t) -> int`: Get ordinal number of a function.
- `get_prev_func(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to the previous function.
- `get_next_func(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to the next function.
- `get_func_ranges(ranges: rangeset_t, pfn: func_t) -> ida_idaapi.ea_t`: Get function ranges.
- `get_func_cmt(pfn: func_t, repeatable: bool) -> str`: Get function comment.
- `set_func_cmt(pfn: func_t, cmt: str, repeatable: bool) -> bool`: Set function comment. This function works with function chunks too.
- `update_func(pfn: func_t) -> bool`: Update information about a function in the database (func_t). You must not change the function start and end addresses using this function. Use set_func_start() and set_func_end() for it.
- `add_func_ex(pfn: func_t) -> bool`: Add a new function. If the fn->end_ea is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE).
- `add_func(*args) -> bool`: Add a new function. If the function end address is BADADDR, then IDA will try to determine the function bounds by calling find_func_bounds(..., FIND_FUNC_DEFINE).
- `del_func(ea: ida_idaapi.ea_t) -> bool`: Delete a function.
- `set_func_start(ea: ida_idaapi.ea_t, newstart: ida_idaapi.ea_t) -> int`: Move function chunk start address.
- `set_func_end(ea: ida_idaapi.ea_t, newend: ida_idaapi.ea_t) -> bool`: Move function chunk end address.
- `reanalyze_function(*args) -> None`: Reanalyze a function. This function plans to analyzes all chunks of the given function. Optional parameters (ea1, ea2) may be used to narrow the analyzed range.
- `find_func_bounds(nfn: func_t, flags: int) -> int`: Determine the boundaries of a new function. This function tries to find the start and end addresses of a new function. It calls the module with processor_t::func_bounds in order to fine tune the function boundaries.
- `get_func_name(ea: ida_idaapi.ea_t) -> str`: Get function name.
- `calc_func_size(pfn: func_t) -> asize_t`: Calculate function size. This function takes into account all fragments of the function.
- `get_func_bitness(pfn: func_t) -> int`: Get function bitness (which is equal to the function segment bitness). pfn==nullptr => returns 0
- `get_func_bits(pfn: func_t) -> int`: Get number of bits in the function addressing.
- `get_func_bytes(pfn: func_t) -> int`: Get number of bytes in the function addressing.
- `is_visible_func(pfn: func_t) -> bool`: Is the function visible (not hidden)?
- `is_finally_visible_func(pfn: func_t) -> bool`: Is the function visible (event after considering SCF_SHHID_FUNC)?
- `set_visible_func(pfn: func_t, visible: bool) -> None`: Set visibility of function.
- `set_func_name_if_jumpfunc(pfn: func_t, oldname: str) -> int`: Give a meaningful name to function if it consists of only 'jump' instruction.
- `calc_thunk_func_target(*args)`: Calculate target of a thunk function.
- `func_does_return(callee: ida_idaapi.ea_t) -> bool`: Does the function return?. To calculate the answer, FUNC_NORET flag and is_noret() are consulted The latter is required for imported functions in the .idata section. Since in .idata we have only function pointers but not functions, we have to introduce a special flag for them.
- `reanalyze_noret_flag(ea: ida_idaapi.ea_t) -> bool`: Plan to reanalyze noret flag. This function does not remove FUNC_NORET if it is already present. It just plans to reanalysis.
- `set_noret_insn(insn_ea: ida_idaapi.ea_t, noret: bool) -> bool`: Signal a non-returning instruction. This function can be used by the processor module to tell the kernel about non-returning instructions (like call exit). The kernel will perform the global function analysis and find out if the function returns at all. This analysis will be done at the first call to func_does_return()
- `get_fchunk(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to function chunk structure by address.
- `getn_fchunk(n: int) -> func_t *`: Get pointer to function chunk structure by number.
- `get_fchunk_qty() -> size_t`: Get total number of function chunks in the program.
- `get_fchunk_num(ea: ida_idaapi.ea_t) -> int`: Get ordinal number of a function chunk in the global list of function chunks.
- `get_prev_fchunk(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to the previous function chunk in the global list.
- `get_next_fchunk(ea: ida_idaapi.ea_t) -> func_t *`: Get pointer to the next function chunk in the global list.
- `append_func_tail(pfn: func_t, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> bool`: Append a new tail chunk to the function definition. If the tail already exists, then it will simply be added to the function tail list Otherwise a new tail will be created and its owner will be set to be our function If a new tail cannot be created, then this function will fail.
- `remove_func_tail(pfn: func_t, tail_ea: ida_idaapi.ea_t) -> bool`: Remove a function tail. If the tail belongs only to one function, it will be completely removed. Otherwise if the function was the tail owner, the first function using this tail becomes the owner of the tail.
- `set_tail_owner(fnt: func_t, new_owner: ida_idaapi.ea_t) -> bool`: Set a new owner of a function tail. The new owner function must be already referring to the tail (after append_func_tail).
- `func_tail_iterator_set(fti: func_tail_iterator_t, pfn: func_t, ea: ida_idaapi.ea_t) -> bool`
- `func_tail_iterator_set_ea(fti: func_tail_iterator_t, ea: ida_idaapi.ea_t) -> bool`
- `func_parent_iterator_set(fpi: func_parent_iterator_t, pfn: func_t) -> bool`
- `f_any(arg1: flags64_t, arg2: void *) -> bool`: Helper function to accept any address.
- `get_prev_func_addr(pfn: func_t, ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`
- `get_next_func_addr(pfn: func_t, ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`
- `read_regargs(pfn: func_t) -> None`
- `add_regarg(pfn: func_t, reg: int, tif: tinfo_t, name: str) -> None`
- `plan_to_apply_idasgn(fname: str) -> int`: Add a signature file to the list of planned signature files.
- `apply_idasgn_to(signame: str, ea: ida_idaapi.ea_t, is_startup: bool) -> int`: Apply a signature file to the specified address.
- `get_idasgn_qty() -> int`: Get number of signatures in the list of planned and applied signatures.
- `get_current_idasgn() -> int`: Get number of the the current signature.
- `calc_idasgn_state(n: int) -> int`: Get state of a signature in the list of planned signatures
- `del_idasgn(n: int) -> int`: Remove signature from the list of planned signatures.
- `get_idasgn_title(name: str) -> str`: Get full description of the signature by its short name.
- `apply_startup_sig(ea: ida_idaapi.ea_t, startup: str) -> bool`: Apply a startup signature file to the specified address.
- `try_to_add_libfunc(ea: ida_idaapi.ea_t) -> int`: Apply the currently loaded signature file to the specified address. If a library function is found, then create a function and name it accordingly.
- `get_fchunk_referer(ea: int, idx)`
- `get_idasgn_desc(n)`: Get information about a signature in the list.
- `get_idasgn_desc_with_matches(n)`: Get information about a signature in the list.
- `func_t__from_ptrval__(ptrval: size_t) -> func_t *`
- `calc_thunk_func_target(*args)`: Calculate target of a thunk function.