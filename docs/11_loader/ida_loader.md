# ida_loader

Definitions of IDP, LDR, PLUGIN module interfaces.

This file also contains:

The LDR interface consists of one structure: loader_t

The IDP interface consists of one structure: processor_t

The PLUGIN interface consists of one structure: plugin_t

Modules cant use standard FILE* functions. They must use functions from <fpro.h>

Modules cant use standard memory allocation functions. They must use functions
from <pro.h>

The exported entry #1 in the module should point to the the appropriate
structure. (loader_t for LDR module, for example)

## Constants

- `LDRF_RELOAD`: loader recognizes NEF_RELOAD flag
- `LDRF_REQ_PROC`: Requires a processor to be set. if this bit is not set, load_file() must call set_processor_type(..., SETPROC_LOADER)
- `ACCEPT_ARCHIVE`: Specify that a file format is served by archive loader See loader_t::accept_file
- `ACCEPT_CONTINUE`: Specify that the function must be called another time See loader_t::accept_file
- `ACCEPT_FIRST`: Specify that a file format should be place first in "load file" dialog box. See loader_t::accept_file
- `NEF_SEGS`: Create segments.
- `NEF_RSCS`: Load resources.
- `NEF_NAME`: Rename entries.
- `NEF_MAN`: Manual load.
- `NEF_FILL`: Fill segment gaps.
- `NEF_IMPS`: Create import segment.
- `NEF_FIRST`: This is the first file loaded into the database.
- `NEF_CODE`: for load_binary_file(): load as a code segment
- `NEF_RELOAD`: reload the file at the same place:
- `NEF_FLAT`: Autocreate FLAT group (PE)
- `NEF_MINI`: Create mini database (do not copy segment bytes from the input file; use only the file header metadata)
- `NEF_LOPT`: Display additional loader options dialog.
- `NEF_LALL`: Load all segments without questions.
- `DLLEXT`
- `LOADER_DLL`
- `OFILE_MAP`: MAP file.
- `OFILE_EXE`: Executable file.
- `OFILE_IDC`: IDC file.
- `OFILE_LST`: Disassembly listing.
- `OFILE_ASM`: Assembly.
- `OFILE_DIF`: Difference.
- `GENFLG_MAPSEG`: OFILE_MAP: generate map of segments
- `GENFLG_MAPNAME`: OFILE_MAP: include dummy names
- `GENFLG_MAPDMNG`: OFILE_MAP: demangle names
- `GENFLG_MAPLOC`: OFILE_MAP: include local names
- `GENFLG_IDCTYPE`: OFILE_IDC: gen only information about types
- `GENFLG_ASMTYPE`: OFILE_ASM,OFILE_LST: gen information about types too
- `GENFLG_GENHTML`: OFILE_ASM,OFILE_LST: generate html (ui_genfile_callback will be used)
- `GENFLG_ASMINC`: OFILE_ASM,OFILE_LST: gen information only about types
- `FILEREG_PATCHABLE`: means that the input file may be patched (i.e. no compression, no iterated data, etc)
- `FILEREG_NOTPATCHABLE`: the data is kept in some encoded form in the file.
- `PLUGIN_DLL`: Pattern to find plugin files.
- `MODULE_ENTRY_LOADER`
- `MODULE_ENTRY_PLUGIN`
- `MODULE_ENTRY_IDP`
- `IDP_DLL`
- `MAX_DATABASE_DESCRIPTION`: Maximum database snapshot description length.
- `SSF_AUTOMATIC`: automatic snapshot
- `SSUF_DESC`: Update the description.
- `SSUF_PATH`: Update the path.
- `SSUF_FLAGS`: Update the flags.
- `DBFL_KILL`: delete unpacked database
- `DBFL_COMP`: collect garbage
- `DBFL_BAK`: create backup file (if !DBFL_KILL)
- `DBFL_TEMP`: temporary database
- `PATH_TYPE_CMD`: full path to the file specified in the command line
- `PATH_TYPE_IDB`: full path of IDB file
- `PATH_TYPE_ID0`: full path of ID0 file

## Classes Overview

- `qvector_snapshotvec_t`
- `loader_t`
- `idp_name_t`
- `idp_desc_t`
- `plugin_info_t`
- `snapshot_t`

## Functions Overview

- `load_binary_file(filename: str, li: linput_t *, _neflags: ushort, fileoff: qoff64_t, basepara: ida_idaapi.ea_t, binoff: ida_idaapi.ea_t, nbytes: uint64) -> bool`: Load a binary file into the database. This function usually is called from ui.
- `process_archive(temp_file: str, li: linput_t *, module_name: str, neflags: ushort *, defmember: str, loader: load_info_t const *) -> str`: Calls loader_t::process_archive() For parameters and return value description look at loader_t::process_archive(). Additional parameter 'loader' is a pointer to load_info_t structure.
- `gen_file(otype: ofile_type_t, fp: FILE *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, flags: int) -> int`: Generate an output file. OFILE_EXE:
- `file2base(li: linput_t *, pos: qoff64_t, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, patchable: int) -> int`: Load portion of file into the database. This function will include (ea1..ea2) into the addressing space of the program (make it enabled).
- `base2file(fp: FILE *, pos: qoff64_t, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t) -> int`: Unload database to a binary file. This function works for wide byte processors too.
- `get_basic_file_type(li: linput_t *) -> filetype_t`: Get the input file type. This function can recognize libraries and zip files.
- `get_file_type_name() -> str`: Get name of the current file type. The current file type is kept in idainfo::filetype.
- `set_import_ordinal(modnode: int, ea: ida_idaapi.ea_t, ord: int) -> None`: Set information about the ordinal import entry. This function performs 'modnode.altset(ord, ea2node(ea));'
- `set_import_name(modnode: int, ea: ida_idaapi.ea_t, name: str) -> None`: Set information about the named import entry. This function performs 'modnode.supset_ea(ea, name);'
- `load_ids_module(fname: char *) -> int`: Load and apply IDS file. This function loads the specified IDS file and applies it to the database. If the program imports functions from a module with the same name as the name of the ids file being loaded, then only functions from this module will be affected. Otherwise (i.e. when the program does not import a module with this name) any function in the program may be affected.
- `get_plugin_options(plugin: str) -> str`: Get plugin options from the command line. If the user has specified the options in the -Oplugin_name:options format, them this function will return the 'options' part of it The 'plugin' parameter should denote the plugin name Returns nullptr if there we no options specified
- `find_plugin(name: str, load_if_needed: bool = False) -> plugin_t *`: Find a user-defined plugin and optionally load it.
- `get_fileregion_offset(ea: ida_idaapi.ea_t) -> qoff64_t`: Get offset in the input file which corresponds to the given ea. If the specified ea can't be mapped into the input file offset, return -1.
- `get_fileregion_ea(offset: qoff64_t) -> ida_idaapi.ea_t`: Get linear address which corresponds to the specified input file offset. If can't be found, return BADADDR
- `gen_exe_file(fp: FILE *) -> int`: Generate an exe file (unload the database in binary form).
- `reload_file(file: str, is_remote: bool) -> bool`: Reload the input file. This function reloads the byte values from the input file. It doesn't modify the segmentation, names, comments, etc.
- `build_snapshot_tree(root: snapshot_t) -> bool`: Build the snapshot tree.
- `flush_buffers() -> int`: Flush buffers to the disk.
- `is_trusted_idb() -> bool`: Is the database considered as trusted?
- `save_database(outfile: str = None, flags: int = -1, root: snapshot_t = None, attr: snapshot_t = None) -> bool`: Save current database using a new file name.
- `is_database_flag(dbfl: int) -> bool`: Get the current database flag
- `set_database_flag(dbfl: int, cnd: bool = True) -> None`: Set or clear database flag
- `clr_database_flag(dbfl: int) -> None`
- `get_path(pt: path_type_t) -> str`: Get the file path
- `set_path(pt: path_type_t, path: str) -> None`: Set the file path
- `get_elf_debug_file_directory() -> str`: Get the value of the ELF_DEBUG_FILE_DIRECTORY configuration directive.
- `mem2base(mem, ea, fpos)`: Load database from the memory.
- `load_plugin(name)`: Loads a plugin
- `run_plugin(plg, arg)`: Runs a plugin
- `load_and_run_plugin(name: str, arg: size_t) -> bool`: Load & run a plugin.
- `extract_module_from_archive(fname: str, is_remote: bool = False) -> PyObject *`: Extract a module for an archive file. Parse an archive file, show the list of modules to the user, allow him to select a module, extract the selected module to a file (if the extract module is an archive, repeat the process). This function can handle ZIP, AR, AIXAR, OMFLIB files. The temporary file will be automatically deleted by IDA at the end.