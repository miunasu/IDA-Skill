# ida_netnode

Functions that provide the lowest level public interface to the database. Namely, we use Btree. To learn more about BTree:

[https://en.wikipedia.org/wiki/B-tree](https://en.wikipedia.org/wiki/B-tree)
We do not use Btree directly. Instead, we have another layer built on the top of Btree. Here is a brief explanation of this layer.
An object called netnode is modeled on the top of Btree. Each netnode has a unique id: a 32-bit value (64-bit for ida64). Initially there is a trivial mapping of the linear addresses used in the program to netnodes (later this mapping may be modified using ea2node and node2ea functions; this is used for fast database rebasings). If we have additional information about an address (for example, a comment is attached to it), this information is stored in the corresponding netnode. See nalt.hpp to see how the kernel uses netnodes. Also, some netnodes have no corresponding linear address (however, they still have an id). They are used to store information not related to a particular address.
Each netnode _may_ have the following attributes:

Initially a new netnode contains no information at all so no disk space is used for it. As you add new information, the netnode grows.
All arrays that are attached to the netnode behave in the same manner. Initially:
* all members of altvals/charvals array are zeroes
* all members of supvals/hashvals array are undefined

If you need to store objects bigger that MAXSPECSIZE, please note that there are high-level functions to store arbitrary sized objects in supvals. See setblob/getblob and other blob-related functions.
You may use netnodes to store additional information about the program. Limitations on the use of netnodes are the following:

Advanced info:
In fact a netnode may contain up to 256 arrays of arbitrary sized objects (not only the 4 listed above). Each array has an 8-bit tag. Usually tags are represented by character constants. For example, altvals and supvals are simply 2 of 256 arrays, with the tags A and S respectively.

## Constants

- `BADNODE`: A number to represent a bad netnode reference.
- `SIZEOF_nodeidx_t`
- `cvar`
- `MAXNAMESIZE`: Maximum length of a netnode name. WILL BE REMOVED IN THE FUTURE.
- `MAX_NODENAME_SIZE`: Maximum length of a name. We permit names up to 32KB-1 bytes.
- `MAXSPECSIZE`: Maximum length of strings or objects stored in a supval array element.
- `atag`: Array of altvals.
- `stag`: Array of supvals.
- `htag`: Array of hashvals.
- `vtag`: Value of netnode.
- `ntag`: Name of netnode.
- `ltag`: Links between netnodes.
- `NETMAP_IDX`
- `NETMAP_VAL`
- `NETMAP_STR`
- `NETMAP_X8`
- `NETMAP_V8`
- `NETMAP_VAL_NDX`
- `netnode_exist`

## Classes Overview

- `netnode`

## Functions Overview

- `exist(n: netnode) -> bool`