# ida_problems

Functions that deal with the list of problems.

There are several problem lists. An address may be inserted to any list. The kernel simply maintains these lists, no additional processing is done.
The problem lists are accessible for the user from the View->Subviews->Problems menu item.
Addresses in the lists are kept sorted. In general IDA just maintains these lists without using them during analysis (except PR_ROLLED).

## Constants

- `cvar`
- `PR_NOBASE`: Can't find offset base.
- `PR_NONAME`: Can't find name.
- `PR_NOFOP`: Can't find forced op (not used anymore)
- `PR_NOCMT`: Can't find comment (not used anymore)
- `PR_NOXREFS`: Can't find references.
- `PR_JUMP`: Jump by table !!!! ignored.
- `PR_DISASM`: Can't disasm.
- `PR_HEAD`: Already head.
- `PR_ILLADDR`: Exec flows beyond limits.
- `PR_MANYLINES`: Too many lines.
- `PR_BADSTACK`: Failed to trace the value of the stack pointer.
- `PR_ATTN`: Attention! Probably erroneous situation.
- `PR_FINAL`: Decision to convert to instruction/data is made by IDA.
- `PR_ROLLED`: The decision made by IDA was wrong and rolled back.
- `PR_COLLISION`: FLAIR collision: the function with the given name already exists.
- `PR_DECIMP`: FLAIR match indecision: the patterns matched, but not the function(s) being referenced.
- `PR_END`: Number of problem types.

## Functions Overview

- `get_problem_desc(t: problist_id_t, ea: ida_idaapi.ea_t) -> str`: Get the human-friendly description of the problem, if one was provided to remember_problem.
- `remember_problem(type: problist_id_t, ea: ida_idaapi.ea_t, msg: str = None) -> None`: Insert an address to a list of problems. Display a message saying about the problem (except of PR_ATTN,PR_FINAL) PR_JUMP is temporarily ignored.
- `get_problem(type: problist_id_t, lowea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Get an address from the specified problem list. The address is not removed from the list.
- `forget_problem(type: problist_id_t, ea: ida_idaapi.ea_t) -> bool`: Remove an address from a problem list
- `get_problem_name(type: problist_id_t, longname: bool = True) -> str`: Get problem list description.
- `is_problem_present(t: problist_id_t, ea: ida_idaapi.ea_t) -> bool`: Check if the specified address is present in the problem list.
- `was_ida_decision(ea: ida_idaapi.ea_t) -> bool`