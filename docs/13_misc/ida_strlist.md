# ida_strlist

Functions that deal with the string list.

While the kernel keeps the string list, it does not update it. The string list is not used by the kernel because keeping it up-to-date would slow down IDA without any benefit. If the string list is not cleared using clear_strlist(), the list will be saved to the database and restored on the next startup.
The users of this list should call build_strlist() if they need an up-to-date version.

## Classes Overview

- `strwinsetup_t`
- `string_info_t`

## Functions Overview

- `get_strlist_options() -> strwinsetup_t const *`: Get the static string list options.
- `build_strlist() -> None`: Rebuild the string list.
- `clear_strlist() -> None`: Clear the string list.
- `get_strlist_qty() -> size_t`: Get number of elements in the string list. The list will be loaded from the database (if saved) or built from scratch.
- `get_strlist_item(si: string_info_t, n: size_t) -> bool`: Get nth element of the string list (n=0..get_strlist_qty()-1)