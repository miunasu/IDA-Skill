# ida_segment

Functions that deal with segments.

IDA requires that all program addresses belong to segments (each address must
belong to exactly one segment). The situation when an address doesnt belong to
any segment is allowed as a temporary situation only when the user changes
program segmentation. Bytes outside a segment cant be converted to instructions,
have names, comments, etc. Each segment has its start address, ending address
and represents a contiguous range of addresses. There might be unused holes
between segments.

Each segment has its unique segment selector. This selector is used to
distinguish the segment from other segments. For 16-bit programs the selector
is equal to the segment base paragraph. For 32-bit programs there is special
array to translate the selectors to the segment base paragraphs. A selector is
a 32/64 bit value.

The segment base paragraph determines the offsets in the segment. If the start
address of the segment == (base << 4) then the first offset in the segment will
be 0. The start address should be higher or equal to (base << 4). We will call
the offsets in the segment virtual addresses. So, the virtual address of the
first byte of the segment is (start address of segment - segment base linear
address).

For IBM PC, the virtual address corresponds to the offset part of the address.
For other processors (Z80, for example), virtual addresses correspond to Z80
addresses and linear addresses are used only internally. For MS Windows programs
the segment base paragraph is 0 and therefore the segment virtual addresses are
equal to linear addresses.

## Constants

- `SREG_NUM`: Maximum number of segment registers is 16 (see segregs.hpp)
- `saAbs`: Absolute segment.
- `saRelByte`: Relocatable, byte aligned.
- `saRelWord`: Relocatable, word (2-byte) aligned.
- `saRelPara`: Relocatable, paragraph (16-byte) aligned.
- `saRelPage`: Relocatable, aligned on 256-byte boundary.
- `saRelDble`: Relocatable, aligned on a double word (4-byte) boundary.
- `saRel4K`: This value is used by the PharLap OMF for page (4K) alignment. It is not supported by LINK.
- `saGroup`: Segment group.
- `saRel32Bytes`: 32 bytes
- `saRel64Bytes`: 64 bytes
- `saRelQword`: 8 bytes
- `saRel128Bytes`: 128 bytes
- `saRel512Bytes`: 512 bytes
- `saRel1024Bytes`: 1024 bytes
- `saRel2048Bytes`: 2048 bytes
- `saRel_MAX_ALIGN_CODE`
- `scPriv`: Private. Do not combine with any other program segment.
- `scGroup`: Segment group.
- `scPub`: Public. Combine by appending at an offset that meets the alignment requirement.
- `scPub2`: As defined by Microsoft, same as C=2 (public).
- `scStack`: Stack. Combine as for C=2. This combine type forces byte alignment.
- `scCommon`: Common. Combine by overlay using maximum size.
- `scPub3`: As defined by Microsoft, same as C=2 (public).
- `sc_MAX_COMB_CODE`
- `SEGPERM_EXEC`: Execute.
- `SEGPERM_WRITE`: Write.
- `SEGPERM_READ`: Read.
- `SEGPERM_MAXVAL`: Execute + Write + Read.
- `SEG_MAX_BITNESS_CODE`: Maximum segment bitness value.
- `SFL_COMORG`: IDP dependent field (IBM PC: if set, ORG directive is not commented out)
- `SFL_OBOK`: Orgbase is present? (IDP dependent field)
- `SFL_HIDDEN`: Is the segment hidden?
- `SFL_DEBUG`: Is the segment created for the debugger?. Such segments are temporary and do not have permanent flags.
- `SFL_LOADER`: Is the segment created by the loader?
- `SFL_HIDETYPE`: Hide segment type (do not print it in the listing)
- `SFL_HEADER`: Header segment (do not create offsets to it in the disassembly)
- `SEG_NORM`: unknown type, no assumptions
- `SEG_XTRN`
- `SEG_CODE`: code segment
- `SEG_DATA`: data segment
- `SEG_IMP`: java: implementation segment
- `SEG_GRP`
- `SEG_NULL`: zero-length segment
- `SEG_UNDF`: undefined segment type (not used)
- `SEG_BSS`: uninitialized segment
- `SEG_ABSSYM`
- `SEG_COMM`
- `SEG_IMEM`: internal processor memory & sfr (8051)
- `SEG_MAX_SEGTYPE_CODE`: maximum value segment type can take
- `ADDSEG_NOSREG`: set all default segment register values to BADSEL (undefine all default segment registers)
- `ADDSEG_OR_DIE`: qexit() if can't add a segment
- `ADDSEG_NOTRUNC`: don't truncate the new segment at the beginning of the next segment if they overlap. destroy/truncate old segments instead.
- `ADDSEG_QUIET`: silent mode, no "Adding segment..." in the messages window
- `ADDSEG_FILLGAP`: fill gap between new segment and previous one. i.e. if such a gap exists, and this gap is less than 64K, then fill the gap by extending the previous segment and adding .align directive to it. This way we avoid gaps between segments. too many gaps lead to a virtual array failure. it cannot hold more than ~1000 gaps.
- `ADDSEG_SPARSE`: use sparse storage method for the new ranges of the created segment. please note that the ranges that were already enabled before creating the segment will not change their storage type.
- `ADDSEG_NOAA`: do not mark new segment for auto-analysis
- `ADDSEG_IDBENC`: 'name' and 'sclass' are given in the IDB encoding; non-ASCII bytes will be decoded accordingly
- `SEGMOD_KILL`: disable addresses if segment gets shrinked or deleted
- `SEGMOD_KEEP`: keep information (code & data, etc)
- `SEGMOD_SILENT`: be silent
- `SEGMOD_KEEP0`: flag for internal use, don't set
- `SEGMOD_KEEPSEL`: do not try to delete unused selector
- `SEGMOD_NOMOVE`: don't move info from the start of segment to the new start address (for set_segm_start())
- `SEGMOD_SPARSE`: use sparse storage if extending the segment (for set_segm_start(), set_segm_end())
- `MOVE_SEGM_OK`: all ok
- `MOVE_SEGM_PARAM`: The specified segment does not exist.
- `MOVE_SEGM_ROOM`: Not enough free room at the target address.
- `MOVE_SEGM_IDP`: IDP module forbids moving the segment.
- `MOVE_SEGM_CHUNK`: Too many chunks are defined, can't move.
- `MOVE_SEGM_LOADER`: The segment has been moved but the loader complained.
- `MOVE_SEGM_ODD`: Cannot move segments by an odd number of bytes.
- `MOVE_SEGM_ORPHAN`: Orphan bytes hinder segment movement.
- `MOVE_SEGM_DEBUG`: Debugger segments cannot be moved.
- `MOVE_SEGM_SOURCEFILES`: Source files ranges of addresses hinder segment movement.
- `MOVE_SEGM_MAPPING`: Memory mapping ranges of addresses hinder segment movement.
- `MOVE_SEGM_INVAL`: Invalid argument (delta/target does not fit the address space)
- `MSF_SILENT`: don't display a "please wait" box on the screen
- `MSF_NOFIX`: don't call the loader to fix relocations
- `MSF_LDKEEP`: keep the loader in the memory (optimization)
- `MSF_FIXONCE`: call loader only once with the special calling method. valid for rebase_program(). see loader_t::move_segm.
- `MSF_PRIORITY`: loader segments will overwrite any existing debugger segments when moved. valid for move_segm()
- `MSF_NETNODES`: move netnodes instead of changing inf.netdelta (this is slower); valid for rebase_program()
- `CSS_OK`: ok
- `CSS_NODBG`: debugger is not running
- `CSS_NORANGE`: could not find corresponding memory range
- `CSS_NOMEM`: not enough memory (might be because the segment is too big)
- `CSS_BREAK`: memory reading process stopped by user
- `SNAP_ALL_SEG`: Take a snapshot of all segments.
- `SNAP_LOAD_SEG`: Take a snapshot of loader segments.
- `SNAP_CUR_SEG`: Take a snapshot of current segment.
- `MAX_GROUPS`: max number of segment groups
- `MAX_SEGM_TRANSLATIONS`: max number of segment translations

## Classes Overview

- `segment_defsr_array`
- `segment_t`
- `lock_segment`

## Functions Overview

- `set_segment_translations(segstart: ida_idaapi.ea_t, transmap: eavec_t const &) -> bool`: Set new translation list.
- `is_visible_segm(s: segment_t) -> bool`: See SFL_HIDDEN.
- `is_finally_visible_segm(s: segment_t) -> bool`: See SFL_HIDDEN, SCF_SHHID_SEGM.
- `set_visible_segm(s: segment_t, visible: bool) -> None`: See SFL_HIDDEN.
- `is_spec_segm(seg_type: uchar) -> bool`: Has segment a special type?. (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)
- `is_spec_ea(ea: ida_idaapi.ea_t) -> bool`: Does the address belong to a segment with a special type?. (SEG_XTRN, SEG_GRP, SEG_ABSSYM, SEG_COMM)
- `lock_segm(segm: segment_t, lock: bool) -> None`: Lock segment pointer Locked pointers are guaranteed to remain valid until they are unlocked. Ranges with locked pointers cannot be deleted or moved.
- `is_segm_locked(segm: segment_t) -> bool`: Is a segment pointer locked?
- `getn_selector(n: int) -> sel_t *, ea_t *`: Get description of selector (0..get_selector_qty()-1)
- `get_selector_qty() -> size_t`: Get number of defined selectors.
- `setup_selector(segbase: ida_idaapi.ea_t) -> sel_t`: Allocate a selector for a segment if necessary. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don't need to allocate a selector. This function will allocate a selector if 'segbase' requires more than 16 bits and the current processor is IBM PC. Otherwise it will return the segbase value.
- `allocate_selector(segbase: ida_idaapi.ea_t) -> sel_t`: Allocate a selector for a segment unconditionally. You must call this function before calling add_segm_ex(). add_segm() calls this function itself, so you don't need to allocate a selector. This function will allocate a new free selector and setup its mapping using find_free_selector() and set_selector() functions.
- `find_free_selector() -> sel_t`: Find first unused selector.
- `set_selector(selector: sel_t, paragraph: ida_idaapi.ea_t) -> int`: Set mapping of selector to a paragraph. You should call this function _before_ creating a segment which uses the selector, otherwise the creation of the segment will fail.
- `del_selector(selector: sel_t) -> None`: Delete mapping of a selector. Be wary of deleting selectors that are being used in the program, this can make a mess in the segments.
- `sel2para(selector: sel_t) -> ida_idaapi.ea_t`: Get mapping of a selector.
- `sel2ea(selector: sel_t) -> ida_idaapi.ea_t`: Get mapping of a selector as a linear address.
- `find_selector(base: ida_idaapi.ea_t) -> sel_t`: Find a selector that has mapping to the specified paragraph.
- `get_segm_by_sel(selector: sel_t) -> segment_t *`: Get pointer to segment structure. This function finds a segment by its selector. If there are several segments with the same selectors, the last one will be returned.
- `add_segm_ex(NONNULL_s: segment_t, name: str, sclass: str, flags: int) -> bool`: Add a new segment. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.
- `add_segm(para: ida_idaapi.ea_t, start: ida_idaapi.ea_t, end: ida_idaapi.ea_t, name: str, sclass: str, flags: int = 0) -> bool`: Add a new segment, second form. Segment alignment is set to saRelByte. Segment combination is "public" or "stack" (if segment class is "STACK"). Addressing mode of segment is taken as default (16bit or 32bit). Default segment registers are set to BADSEL. If a segment already exists at the specified range of addresses, this segment will be truncated. Instructions and data in the old segment will be deleted if the new segment has another addressing mode or another segment base address.
- `del_segm(ea: ida_idaapi.ea_t, flags: int) -> bool`: Delete a segment.
- `get_segm_qty() -> int`: Get number of segments.
- `getseg(ea: ida_idaapi.ea_t) -> segment_t *`: Get pointer to segment by linear address.
- `getnseg(n: int) -> segment_t *`: Get pointer to segment by its number.
- `get_segm_num(ea: ida_idaapi.ea_t) -> int`: Get number of segment by address.
- `get_next_seg(ea: ida_idaapi.ea_t) -> segment_t *`: Get pointer to the next segment.
- `get_prev_seg(ea: ida_idaapi.ea_t) -> segment_t *`: Get pointer to the previous segment.
- `get_first_seg() -> segment_t *`: Get pointer to the first segment.
- `get_last_seg() -> segment_t *`: Get pointer to the last segment.
- `get_segm_by_name(name: str) -> segment_t *`: Get pointer to segment by its name. If there are several segments with the same name, returns the first of them.
- `set_segm_end(ea: ida_idaapi.ea_t, newend: ida_idaapi.ea_t, flags: int) -> bool`: Set segment end address. The next segment is shrinked to allow expansion of the specified segment. The kernel might even delete the next segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.
- `set_segm_start(ea: ida_idaapi.ea_t, newstart: ida_idaapi.ea_t, flags: int) -> bool`: Set segment start address. The previous segment is trimmed to allow expansion of the specified segment. The kernel might even delete the previous segment if necessary. The kernel will ask the user for a permission to destroy instructions or data going out of segment scope if such instructions exist.
- `move_segm_start(ea: ida_idaapi.ea_t, newstart: ida_idaapi.ea_t, mode: int) -> bool`: Move segment start. The main difference between this function and set_segm_start() is that this function may expand the previous segment while set_segm_start() never does it. So, this function allows to change bounds of two segments simultaneously. If the previous segment and the specified segment have the same addressing mode and segment base, then instructions and data are not destroyed - they simply move from one segment to another. Otherwise all instructions/data which migrate from one segment to another are destroyed.
- `move_segm_strerror(code: move_segm_code_t) -> str`: Return string describing error MOVE_SEGM_... code.
- `move_segm(s: segment_t, to: ida_idaapi.ea_t, flags: int = 0) -> move_segm_code_t`: This function moves all information to the new address. It fixes up address sensitive information in the kernel. The total effect is equal to reloading the segment to the target address. For the file format dependent address sensitive information, loader_t::move_segm is called. Also IDB notification event idb_event::segm_moved is called.
- `change_segment_status(s: segment_t, is_deb_segm: bool) -> int`: Convert a debugger segment to a regular segment and vice versa. When converting debug->regular, the memory contents will be copied to the database.
- `take_memory_snapshot(type: int) -> bool`: Take a memory snapshot of the running process.
- `is_miniidb() -> bool`: Is the database a miniidb created by the debugger?.
- `set_segm_base(s: segment_t, newbase: ida_idaapi.ea_t) -> bool`: Internal function.
- `set_group_selector(grp: sel_t, sel: sel_t) -> int`: Create a new group of segments (used OMF files).
- `get_group_selector(grpsel: sel_t) -> sel_t`: Get common selector for a group of segments.
- `add_segment_translation(segstart: ida_idaapi.ea_t, mappedseg: ida_idaapi.ea_t) -> bool`: Add segment translation.
- `del_segment_translations(segstart: ida_idaapi.ea_t) -> None`: Delete the translation list
- `get_segment_translations(transmap: eavec_t *, segstart: ida_idaapi.ea_t) -> ssize_t`: Get segment translation list.
- `get_segment_cmt(s: segment_t, repeatable: bool) -> str`: Get segment comment.
- `set_segment_cmt(s: segment_t, cmt: str, repeatable: bool) -> None`: Set segment comment.
- `std_out_segm_footer(ctx: outctx_t &, seg: segment_t) -> None`: Generate segment footer line as a comment line. This function may be used in IDP modules to generate segment footer if the target assembler doesn't have 'ends' directive.
- `set_segm_name(s: segment_t, name: str, flags: int = 0) -> int`: Rename segment. The new name is validated (see validate_name). A segment always has a name. If you hadn't specified a name, the kernel will assign it "seg###" name where ### is segment number.
- `get_segm_name(s: segment_t, flags: int = 0) -> str`: Get true segment name by pointer to segment.
- `get_visible_segm_name(s: segment_t) -> str`: Get segment name by pointer to segment.
- `get_segm_class(s: segment_t) -> str`: Get segment class. Segment class is arbitrary text (max 8 characters).
- `set_segm_class(s: segment_t, sclass: str, flags: int = 0) -> int`: Set segment class.
- `segtype(ea: ida_idaapi.ea_t) -> uchar`: Get segment type.
- `get_segment_alignment(align: uchar) -> str`: Get text representation of segment alignment code.
- `get_segment_combination(comb: uchar) -> str`: Get text representation of segment combination code.
- `get_segm_para(s: segment_t) -> ida_idaapi.ea_t`: Get segment base paragraph. Segment base paragraph may be converted to segment base linear address using to_ea() function. In fact, to_ea(get_segm_para(s), 0) == get_segm_base(s).
- `get_segm_base(s: segment_t) -> ida_idaapi.ea_t`: Get segment base linear address. Segment base linear address is used to calculate virtual addresses. The virtual address of the first byte of the segment will be (start address of segment - segment base linear address)
- `set_segm_addressing(s: segment_t, bitness: size_t) -> bool`: Change segment addressing mode (16, 32, 64 bits). You must use this function to change segment addressing, never change the 'bitness' field directly. This function will delete all instructions, comments and names in the segment
- `update_segm(s: segment_t) -> bool`
- `segm_adjust_diff(s: segment_t, delta: adiff_t) -> adiff_t`: Truncate and sign extend a delta depending on the segment.
- `segm_adjust_ea(s: segment_t, ea: ida_idaapi.ea_t) -> ida_idaapi.ea_t`: Truncate an address depending on the segment.
- `get_defsr(s, reg)`: Deprecated, use instead:
- `set_defsr(s, reg, value)`: Deprecated, use instead:
- `rebase_program(delta: PyObject *, flags: int) -> int`: Rebase the whole program by 'delta' bytes.