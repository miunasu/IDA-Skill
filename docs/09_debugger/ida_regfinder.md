# ida_regfinder

## Constants

- `cvar`

## Classes Overview

- `reg_value_def_t`
- `reg_value_info_t`

## Functions Overview

- `find_reg_value(ea: ida_idaapi.ea_t, reg: int) -> uint64 *`: Find register value using the register tracker.
- `find_sp_value(ea: ida_idaapi.ea_t, reg: int = -1) -> int64 *`: Find a value of the SP based register using the register tracker.
- `find_reg_value_info(rvi: reg_value_info_t, ea: ida_idaapi.ea_t, reg: int, max_depth: int = 0) -> bool`: Find register value using the register tracker.
- `find_nearest_rvi(rvi: reg_value_info_t, ea: ida_idaapi.ea_t, reg: int const [2]) -> int`: Find the value of any of the two registers using the register tracker. First, this function tries to find the registers in the basic block of EA, and if it could not do this, then it tries to find in the entire function.
- `invalidate_regfinder_cache(*args) -> None`: The control flow from FROM to TO has removed (CREF==fl_U) or added (CREF!=fl_U). Try to update the register tracker cache after this change. If TO == BADADDR then clear the entire cache.
- `invalidate_regfinder_xrefs_cache(*args) -> None`: The data reference to TO has added (DREF!=dr_O) or removed (DREF==dr_O). Update the regtracker xrefs cache after this change. If TO == BADADDR then clear the entire xrefs cache.