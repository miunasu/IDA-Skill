# ida_dirtree

Types involved in grouping of item into folders.

The dirtree_t class is used to organize a directory tree on top of any collection that allows for accessing its elements by an id (inode).
No requirements are imposed on the inodes apart from the forbidden value -1 (used to denote a bad inode).
The dirspec_t class is used to specialize the dirtree. It can be used to introduce a directory structure for:
* local types
* structs
* enums
* functions
* names
* etc

## Constants

- `DTN_FULL_NAME`: use long form of the entry name. That name is unique.
- `DTN_DISPLAY_NAME`: use short, displayable form of the entry name. for example, 'std::string' instead of 'std::basic_string<char, ...>'. Note that more than one "full name" can have the same displayable name.
- `DTE_OK`: ok
- `DTE_ALREADY_EXISTS`: item already exists
- `DTE_NOT_FOUND`: item not found
- `DTE_NOT_DIRECTORY`: item is not a directory
- `DTE_NOT_EMPTY`: directory is not empty
- `DTE_BAD_PATH`: invalid path
- `DTE_CANT_RENAME`: failed to rename an item
- `DTE_OWN_CHILD`: moving inside subdirectory of itself
- `DTE_MAX_DIR`: maximum directory count achieved
- `DTE_LAST`
- `DIRTREE_LOCAL_TYPES`
- `DIRTREE_FUNCS`
- `DIRTREE_NAMES`
- `DIRTREE_IMPORTS`
- `DIRTREE_IDAPLACE_BOOKMARKS`
- `DIRTREE_BPTS`
- `DIRTREE_LTYPES_BOOKMARKS`
- `DIRTREE_END`

## Classes Overview

- `direntry_vec_t`
- `dirtree_cursor_vec_t`
- `direntry_t`
- `dirspec_t`
- `dirtree_cursor_t`
- `dirtree_selection_t`
- `dirtree_iterator_t`
- `dirtree_visitor_t`
- `dirtree_t`

## Functions Overview

- `get_std_dirtree(id: dirtree_id_t) -> dirtree_t *`