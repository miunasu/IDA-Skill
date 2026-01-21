# ida_merge

Merge functionality.

NOTE: this functionality is available in IDA Teams (not IDA Pro)
There are 3 databases involved in merging: base_idb, local_db, and remote_idb.
* base_idb: the common base ancestor of local_db and remote_db. in the UI this database is located in the middle.
* local_idb: local database that will contain the result of the merging. in the UI this database is located on the left.
* remote_idb: remote database that will merge into local_idb. It may reside locally on the current computer, despite its name. in the UI this database is located on the right. base_idb and remote_idb are opened for reading only. base_idb may be absent, in this case a 2-way merging is performed.

Conflicts can be resolved automatically or interactively. The automatic resolving scores the conflicting blocks and takes the better one. The interactive resolving displays the full rendered contents side by side, and expects the user to select the better side for each conflict.
Since IDB files contain various kinds of information, there are many merging phases. The entire list can be found in merge.cpp. Below are just some selected examples:
* merge global database settings (inf and other global vars)
* merge segmentation and changes to the database bytes
* merge various lists: exports, imports, loaded tils, etc
* merge names, functions, function frames
* merge debugger settings, breakpoints
* merge struct/enum views
* merge local type libraries
* merge the disassembly items (i.e. the segment contents) this includes operand types, code/data separation, etc
* merge plugin specific info like decompiler types, dwarf mappings, etc

To unify UI elements of each merge phase, we use merger views:
* A view that consists of 2 or 3 panes: left (local_idb) and right (remote_idb). The common base is in the middle, if present.
* Rendering of the panes depends on the phase, different phases show different contents.
* The conflicts are highlighted by a colored background. Also, the detail pane can be consulted for additional info.
* The user can select a conflict (or a bunch of conflicts) and say use this block.
* The user can browse the panes as he wishes. He will not be forced to handle conflicts in any particular order. However, once he finishes working with a merge handler and proceeds to the next one, he cannot go back.
* Scrolling the left pane will synchronously scroll the right pane and vice versa.
* There are the navigation commands like go to the prev/next conflict
* The number of remaining conflicts to resolve is printed in the Progress chooser.
* The user may manually modify local database inside the merger view. For that he may use the regular hotkeys. However, editing the database may lead to new conflicts, so we better restrict the available actions to some reasonable minimum. Currently, this is not implemented.

IDA works in a new merge mode during merging. In this mode most events are not generated. We forbid them to reduce the risk that a rogue third-party plugin that is not aware of the merge mode would spoil something.
For example, normally renaming a function causes a cascade of events and may lead to other database modifications. Some of them may be desired, some - not. Since there are some undesired events, it is better to stop generating them. However, some events are required to render the disassembly listing. For example, ev_ana_insn, av_out_insn. This is why some events are still generated in the merge mode.
To let processor modules and plugins merge their data, we introduce a new event: ev_create_merge_handlers. It is generated immediately after opening all three idbs. The interested modules should react to this event by creating new merge handlers, if they need them.
While the kernel can create arbitrary merge handlers, modules can create only the standard ones returned by:
create_nodeval_merge_handler() create_nodeval_merge_handlers() create_std_modmerge_handlers()
We do not document merge_handler_t because once a merge handler is created, it is used exclusively by the kernel.
See mergemod.hpp for more information about the merge mode for modules.

## Constants

- `MERGE_KIND_NETNODE`: netnode (no merging, to be used in idbunits)
- `MERGE_KIND_AUTOQ`: auto queues
- `MERGE_KIND_INF`: merge the inf variable (global settings)
- `MERGE_KIND_ENCODINGS`: merge encodings
- `MERGE_KIND_ENCODINGS2`: merge default encodings
- `MERGE_KIND_SCRIPTS2`: merge scripts common info
- `MERGE_KIND_SCRIPTS`: merge scripts
- `MERGE_KIND_CUSTDATA`: merge custom data type and formats
- `MERGE_KIND_CUSTCNV`: merge custom calling conventions
- `MERGE_KIND_ENUMS`: merge enums
- `MERGE_KIND_STRUCTS`: merge structs (globally: add/delete structs entirely)
- `MERGE_KIND_TILS`: merge type libraries
- `MERGE_KIND_TINFO`: merge tinfo
- `MERGE_KIND_STRMEM`: merge struct members
- `MERGE_KIND_UDTMEM`: merge UDT members (local types)
- `MERGE_KIND_GHSTRCMT`: merge ghost structure comment
- `MERGE_KIND_STRMEMCMT`: merge member comments for ghost struc
- `MERGE_KIND_SELECTORS`: merge selectors
- `MERGE_KIND_STT`: merge flag storage types
- `MERGE_KIND_SEGMENTS`: merge segments
- `MERGE_KIND_SEGGRPS`: merge segment groups
- `MERGE_KIND_SEGREGS`: merge segment registers
- `MERGE_KIND_ORPHANS`: merge orphan bytes
- `MERGE_KIND_BYTEVAL`: merge byte values
- `MERGE_KIND_FIXUPS`: merge fixups
- `MERGE_KIND_MAPPING`: merge manual memory mapping
- `MERGE_KIND_EXPORTS`: merge exports
- `MERGE_KIND_IMPORTS`: merge imports
- `MERGE_KIND_PATCHES`: merge patched bytes
- `MERGE_KIND_FLAGS`: merge flags64_t
- `MERGE_KIND_EXTRACMT`: merge extra next or prev lines
- `MERGE_KIND_AFLAGS_EA`: merge aflags for mapped EA
- `MERGE_KIND_IGNOREMICRO`: IM ("$ ignore micro") flags.
- `MERGE_KIND_FILEREGIONS`: merge fileregions
- `MERGE_KIND_HIDDENRANGES`: merge hidden ranges
- `MERGE_KIND_SOURCEFILES`: merge source files ranges
- `MERGE_KIND_FUNC`: merge func info
- `MERGE_KIND_FRAMEMGR`: merge frames (globally: add/delete frames entirely)
- `MERGE_KIND_FRAME`: merge function frame info (frame members)
- `MERGE_KIND_STKPNTS`: merge SP change points
- `MERGE_KIND_FLOWS`: merge flows
- `MERGE_KIND_CREFS`: merge crefs
- `MERGE_KIND_DREFS`: merge drefs
- `MERGE_KIND_BPTS`: merge breakpoints
- `MERGE_KIND_WATCHPOINTS`: merge watchpoints
- `MERGE_KIND_BOOKMARKS`: merge bookmarks
- `MERGE_KIND_TRYBLKS`: merge try blocks
- `MERGE_KIND_DIRTREE`: merge std dirtrees
- `MERGE_KIND_VFTABLES`: merge vftables
- `MERGE_KIND_SIGNATURES`: signatures
- `MERGE_KIND_PROBLEMS`: problems
- `MERGE_KIND_UI`: UI.
- `MERGE_KIND_DEKSTOPS`: dekstops
- `MERGE_KIND_NOTEPAD`: notepad
- `MERGE_KIND_LOADER`: loader data
- `MERGE_KIND_DEBUGGER`: debugger data
- `MERGE_KIND_DBG_MEMREGS`: manual memory regions (debugger)
- `MERGE_KIND_LUMINA`: lumina function metadata
- `MERGE_KIND_LAST`: last predefined merge handler type. please note that there can be more merge handler types, registered by plugins and processor modules.
- `MERGE_KIND_END`: insert to the end of handler list, valid for merge_handler_params_t::insert_after
- `MERGE_KIND_NONE`
- `MH_LISTEN`: merge handler will receive merge events
- `MH_TERSE`: do not display equal lines in the merge results table
- `MH_UI_NODETAILS`: ida will not show the diffpos details
- `MH_UI_COMPLEX`: diffpos details won't be displayed in the diffpos chooser
- `MH_UI_DP_NOLINEDIFF`: Detail pane: do not show differences inside the line.
- `MH_UI_DP_SHORTNAME`: Detail pane: use the first part of a complex diffpos name as the tree node name.
- `MH_UI_INDENT`: preserve indent for diffpos name in diffpos chooser
- `MH_UI_SPLITNAME`: ida will split the diffpos name by 7-bit ASCII char to create chooser columns
- `MH_UI_CHAR_MASK`: 7-bit ASCII split character
- `MH_UI_COMMANAME`: ida will split the diffpos name by ',' to create chooser columns
- `MH_UI_COLONNAME`: ida will split the diffpos name by ':' to create chooser columns
- `NDS_IS_BOOL`: boolean value
- `NDS_IS_EA`: EA value.
- `NDS_IS_RELATIVE`: value is relative to index (stored as delta)
- `NDS_IS_STR`: string value
- `NDS_SUPVAL`: stored as netnode supvals (not scalar)
- `NDS_BLOB`: stored as netnode blobs
- `NDS_EV_RANGE`: enable default handling of mev_modified_ranges, mev_deleting_segm
- `NDS_EV_FUNC`: enable default handling of mev_added_func/mev_deleting_func
- `NDS_MAP_IDX`: apply ea2node() to index (==NETMAP_IDX)
- `NDS_MAP_VAL`: apply ea2node() to value. Along with NDS_INC it gives effect of NETMAP_VAL, examples: altval_ea : NDS_MAP_IDX charval : NDS_VAL8 charval_ea: NDS_MAP_IDX|NDS_VAL8 eaget : NDS_MAP_IDX|NDS_MAP_VAL|NDS_INC
- `NDS_VAL8`: use 8-bit values (==NETMAP_V8)
- `NDS_INC`: stored value is incremented (scalars only)
- `NDS_UI_ND`: UI: no need to show diffpos detail pane, MH_UI_NODETAILS, make sense if merge_node_helper_t is used

## Classes Overview

- `merge_data_t`
- `item_block_locator_t`
- `merge_handler_params_t`
- `moddata_diff_helper_t`
- `merge_node_helper_t`
- `merge_node_info_t`

## Functions Overview

- `is_diff_merge_mode() -> bool`: Return TRUE if IDA is running in diff mode (MERGE_POLICY_MDIFF/MERGE_POLICY_VDIFF)
- `create_nodeval_merge_handler(mhp: merge_handler_params_t, label: str, nodename: str, tag: uchar, nds_flags: int, node_helper: merge_node_helper_t = None, skip_empty_nodes: bool = True) -> merge_handler_t *`: Create a merge handler for netnode scalar/string values
- `create_nodeval_merge_handlers(out: merge_handlers_t *, mhp: merge_handler_params_t, nodename: str, valdesc: merge_node_info_t, skip_empty_nodes: bool = True) -> None`: Create a serie of merge handlers for netnode scalar/string values (call create_nodeval_merge_handler() for each member of VALDESC)
- `destroy_moddata_merge_handlers(data_id: int) -> None`
- `get_ea_diffpos_name(ea: ida_idaapi.ea_t) -> str`: Get nice name for EA diffpos