# idautils

idautils.py - High level utility functions for IDA

## Constants

- `GetInputFileMD5`
- `cpu`: This is a special class instance used to access the registers as if they were attributes of this object.
- `procregs`: This object is used to access the processor registers. It is useful when decoding instructions and you want to see which instruction is which.

## Classes Overview

- `Strings`: Allows iterating over the string list. The set of strings will not be
- `peutils_t`: PE utility class. Retrieves PE information from the database.

## Functions Overview

- `CodeRefsTo(ea, flow: bool)`: Get a list of code references to 'ea'
- `CodeRefsFrom(ea, flow: bool)`: Get a list of code references from 'ea'
- `DataRefsTo(ea)`: Get a list of data references to 'ea'
- `DataRefsFrom(ea)`: Get a list of data references from 'ea'
- `XrefTypeName(typecode)`: Convert cross-reference type codes to readable names
- `XrefsFrom(ea, flags=0)`: Return all references from address 'ea'
- `XrefsTo(ea, flags=0)`: Return all references to address 'ea'
- `Threads()`: Returns all thread IDs for the current debugee
- `Heads(start=None, end=None)`: Get a list of heads (instructions or data items)
- `Functions(start=None, end=None)`: Get a list of functions
- `Chunks(start)`: Get a list of function chunks
- `Modules()`: Returns a list of module objects with name,size,base and the rebase_to attributes
- `Names()`: Returns a list of names
- `Segments()`: Get list of segments (sections) in the binary image
- `Entries()`: Returns a list of entry points (exports)
- `FuncItems(start)`: Get a list of function items (instruction or data items inside function boundaries)
- `Structs()`: Get a list of structures
- `StructMembers(sid)`: Get a list of structure members information (or stack vars if given a frame).
- `DecodePrecedingInstruction(ea)`: Decode preceding instruction in the execution flow.
- `DecodePreviousInstruction(ea)`: Decodes the previous instruction and returns an insn_t like class
- `DecodeInstruction(ea)`: Decodes an instruction and returns an insn_t like class
- `GetDataList(ea, count, itemsize=1)`: Get data list - INTERNAL USE ONLY
- `PutDataList(ea, datalist, itemsize=1)`: Put data list - INTERNAL USE ONLY
- `MapDataList(ea, length, func, wordsize=1)`: Map through a list of data words in the database
- `GetIdbDir()`: Get IDB directory
- `GetRegisterList()`: Returns the register list
- `GetInstructionList()`: Returns the instruction list of the current processor module
- `Assemble(ea, line)`: Assembles one or more lines (does not display an message dialogs)
- `ProcessUiActions(actions, flags=0)`