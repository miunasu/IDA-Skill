# ida_auto

Functions that work with the autoanalyzer queue.

The autoanalyzer works when IDA is not busy processing the user keystrokes.
It has several queues, each queue having its own priority. The analyzer stops
when all queues are empty.

A queue contains addresses or address ranges. The addresses are kept sorted by
their values. The analyzer will process all addresses from the first queue,
then switch to the second queue and so on. There are no limitations on the
size of the queues.

This file also contains functions that deal with the IDA status indicator and
the autoanalysis indicator. You may use these functions to change the
indicator value.

## Constants

- `cvar`
- `AU_NONE`: placeholder, not used
- `AU_UNK`: 0: convert to unexplored
- `AU_CODE`: 1: convert to instruction
- `AU_WEAK`: 2: convert to instruction (ida decision)
- `AU_PROC`: 3: convert to procedure start
- `AU_TAIL`: 4: add a procedure tail
- `AU_FCHUNK`: 5: find func chunks
- `AU_USED`: 6: reanalyze
- `AU_USD2`: 7: reanalyze, second pass
- `AU_TYPE`: 8: apply type information
- `AU_LIBF`: 9: apply signature to address
- `AU_LBF2`: 10: the same, second pass
- `AU_LBF3`: 11: the same, third pass
- `AU_CHLB`: 12: load signature file (file name is kept separately)
- `AU_FINAL`: 13: final pass
- `st_Ready`: READY: IDA is doing nothing.
- `st_Think`: THINKING: Autoanalysis on, the user may press keys.
- `st_Waiting`: WAITING: Waiting for the user input.
- `st_Work`: BUSY: IDA is busy.

## Classes Overview

- `auto_display_t`

## Functions Overview

- `get_auto_state() -> atype_t`: Get current state of autoanalyzer. If auto_state == AU_NONE, IDA is currently not running the analysis (it could be temporarily interrupted to perform the user's requests, for example).
- `set_auto_state(new_state: atype_t) -> atype_t`: Set current state of autoanalyzer.
- `get_auto_display(auto_display: auto_display_t) -> bool`: Get structure which holds the autoanalysis indicator contents.
- `show_auto(*args) -> None`: Change autoanalysis indicator value.
- `show_addr(ea: ida_idaapi.ea_t) -> None`: Show an address on the autoanalysis indicator. The address is displayed in the form " @:12345678".
- `set_ida_state(st: idastate_t) -> idastate_t`: Change IDA status indicator value
- `may_create_stkvars() -> bool`: Is it allowed to create stack variables automatically?. This function should be used by IDP modules before creating stack vars.
- `may_trace_sp() -> bool`: Is it allowed to trace stack pointer automatically?. This function should be used by IDP modules before tracing sp.
- `auto_mark_range(start: ida_idaapi.ea_t, end: ida_idaapi.ea_t, type: atype_t) -> None`: Put range of addresses into a queue. 'start' may be higher than 'end', the kernel will swap them in this case. 'end' doesn't belong to the range.
- `auto_mark(ea: ida_idaapi.ea_t, type: atype_t) -> None`: Put single address into a queue. Queues keep addresses sorted.
- `auto_unmark(start: ida_idaapi.ea_t, end: ida_idaapi.ea_t, type: atype_t) -> None`: Remove range of addresses from a queue. 'start' may be higher than 'end', the kernel will swap them in this case. 'end' doesn't belong to the range.
- `plan_ea(ea: ida_idaapi.ea_t) -> None`: Plan to perform reanalysis.
- `plan_range(sEA: ida_idaapi.ea_t, eEA: ida_idaapi.ea_t) -> None`: Plan to perform reanalysis.
- `auto_make_code(ea: ida_idaapi.ea_t) -> None`: Plan to make code.
- `auto_make_proc(ea: ida_idaapi.ea_t) -> None`: Plan to make code&function.
- `auto_postpone_analysis(ea: ida_idaapi.ea_t) -> bool`: Plan to reanalyze on the second pass The typical usage of this function in emu.cpp is: if ( !auto_postpone_analysis(ea) ) op_offset(ea, 0, ...); (we make an offset only on the second pass)
- `reanalyze_callers(ea: ida_idaapi.ea_t, noret: bool) -> None`: Plan to reanalyze callers of the specified address. This function will add to AU_USED queue all instructions that call (not jump to) the specified address.
- `revert_ida_decisions(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> None`: Delete all analysis info that IDA generated for for the given range.
- `auto_apply_type(caller: ida_idaapi.ea_t, callee: ida_idaapi.ea_t) -> None`: Plan to apply the callee's type to the calling point.
- `auto_apply_tail(tail_ea: ida_idaapi.ea_t, parent_ea: ida_idaapi.ea_t) -> None`: Plan to apply the tail_ea chunk to the parent
- `plan_and_wait(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, final_pass: bool = True) -> int`: Analyze the specified range. Try to create instructions where possible. Make the final pass over the specified range if specified. This function doesn't return until the range is analyzed.
- `auto_wait() -> bool`: Process everything in the queues and return true.
- `auto_wait_range(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> ssize_t`: Process everything in the specified range and return true.
- `auto_make_step(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> bool`: Analyze one address in the specified range and return true.
- `auto_cancel(ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> None`: Remove an address range (ea1..ea2) from queues AU_CODE, AU_PROC, AU_USED. To remove an address range from other queues use auto_unmark() function. 'ea1' may be higher than 'ea2', the kernel will swap them in this case. 'ea2' doesn't belong to the range.
- `auto_is_ok() -> bool`: Are all queues empty? (i.e. has autoanalysis finished?).
- `peek_auto_queue(low_ea: ida_idaapi.ea_t, type: atype_t) -> ida_idaapi.ea_t`: Peek into a queue 'type' for an address not lower than 'low_ea'. Do not remove address from the queue.
- `auto_get(type: atype_t *, lowEA: ida_idaapi.ea_t, highEA: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Retrieve an address from queues regarding their priority. Returns BADADDR if no addresses not lower than 'lowEA' and less than 'highEA' are found in the queues. Otherwise *type will have queue type.
- `auto_recreate_insn(ea: ida_idaapi.ea_t) -> int`: Try to create instruction
- `is_auto_enabled() -> bool`: Get autoanalyzer state.
- `enable_auto(enable: bool) -> bool`: Temporarily enable/disable autoanalyzer. Not user-facing, but rather because IDA sometimes need to turn AA on/off regardless of inf.s_genflags:INFFL_AUTO