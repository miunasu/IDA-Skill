# ida_search

Middle-level search functions.

They all are controlled by Search flags

## Constants

- `SEARCH_UP`: search towards lower addresses
- `SEARCH_DOWN`: search towards higher addresses
- `SEARCH_NEXT`: skip the starting address when searching. this bit is useful only for search(), bin_search(), find_reg_access(). find_.. functions skip the starting address automatically.
- `SEARCH_CASE`: case-sensitive search (case-insensitive otherwise)
- `SEARCH_REGEX`: regular expressions in search string (supported only for the text search)
- `SEARCH_NOBRK`: do not test if the user clicked cancel to interrupt the search
- `SEARCH_NOSHOW`: do not display the search progress/refresh screen
- `SEARCH_IDENT`: search for an identifier (text search). it means that the characters before and after the match cannot be is_visible_char().
- `SEARCH_BRK`: return BADADDR if the search was cancelled.
- `SEARCH_USE`: find_reg_access: search for a use (read access)
- `SEARCH_DEF`: find_reg_access: search for a definition (write access)
- `SEARCH_USESEL`: query the UI for a possible current selection to limit the search to

## Functions Overview

- `search_down(sflag: int) -> bool`: Is the SEARCH_DOWN bit set?
- `find_error(ea: ida_idaapi.ea_t, sflag: int) -> int *`
- `find_notype(ea: ida_idaapi.ea_t, sflag: int) -> int *`
- `find_unknown(ea: ida_idaapi.ea_t, sflag: int) -> ida_idaapi.ea_t`
- `find_defined(ea: ida_idaapi.ea_t, sflag: int) -> ida_idaapi.ea_t`
- `find_suspop(ea: ida_idaapi.ea_t, sflag: int) -> int *`
- `find_data(ea: ida_idaapi.ea_t, sflag: int) -> ida_idaapi.ea_t`
- `find_code(ea: ida_idaapi.ea_t, sflag: int) -> ida_idaapi.ea_t`
- `find_not_func(ea: ida_idaapi.ea_t, sflag: int) -> ida_idaapi.ea_t`
- `find_imm(ea: ida_idaapi.ea_t, sflag: int, search_value: int) -> int *`
- `find_text(start_ea: ida_idaapi.ea_t, y: int, x: int, ustr: str, sflag: int) -> ida_idaapi.ea_t`
- `find_reg_access(out: reg_access_t, start_ea: ida_idaapi.ea_t, end_ea: ida_idaapi.ea_t, regname: str, sflag: int) -> ida_idaapi.ea_t`