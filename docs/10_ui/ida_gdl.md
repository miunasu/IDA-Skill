# ida_gdl

Low level graph drawing operations.

## Constants

- `fcb_normal`: normal block
- `fcb_indjump`: block ends with indirect jump
- `fcb_ret`: return block
- `fcb_cndret`: conditional return block
- `fcb_noret`: noreturn block
- `fcb_enoret`: external noreturn block (does not belong to the function)
- `fcb_extern`: external normal block
- `fcb_error`: block passes execution past the function end
- `EDGE_NONE`
- `EDGE_TREE`
- `EDGE_FORWARD`
- `EDGE_BACK`
- `EDGE_CROSS`
- `EDGE_SUBGRAPH`
- `CHART_PRINT_NAMES`: print labels for each block?
- `CHART_GEN_DOT`: generate .dot file (file extension is forced to .dot)
- `CHART_GEN_GDL`: generate .gdl file (file extension is forced to .gdl)
- `CHART_WINGRAPH`: call grapher to display the graph
- `CHART_NOLIBFUNCS`: don't include library functions in the graph
- `CHART_REFERENCING`: references to the addresses in the list
- `CHART_REFERENCED`: references from the addresses in the list
- `CHART_RECURSIVE`: analyze added blocks
- `CHART_FOLLOW_DIRECTION`: analyze references to added blocks only in the direction of the reference who discovered the current block
- `CHART_IGNORE_XTRN`
- `CHART_IGNORE_DATA_BSS`
- `CHART_IGNORE_LIB_TO`: ignore references to library functions
- `CHART_IGNORE_LIB_FROM`: ignore references from library functions
- `CHART_PRINT_COMMENTS`
- `CHART_PRINT_DOTS`: print dots if xrefs exist outside of the range recursion depth
- `FC_PRINT`: print names (used only by display_flow_chart())
- `FC_NOEXT`: do not compute external blocks. Use this to prevent jumps leaving the function from appearing in the flow chart. Unless specified, the targets of those outgoing jumps will be present in the flow chart under the form of one-instruction blocks
- `FC_RESERVED`: former FC_PREDS
- `FC_APPND`: multirange flowchart (set by append_to_flowchart)
- `FC_CHKBREAK`: build_qflow_chart() may be aborted by user
- `FC_CALL_ENDS`: call instructions terminate basic blocks
- `FC_NOPREDS`: do not compute predecessor lists
- `FC_OUTLINES`: include outlined code (with FUNC_OUTLINE)
- `FC_PREDS`

## Classes Overview

- `edge_t`
- `edgevec_t`
- `node_ordering_t`
- `node_iterator`
- `gdl_graph_t`
- `cancellable_graph_t`
- `qbasic_block_t`
- `qflow_chart_t`
- `BasicBlock`: Basic block class. It is returned by the Flowchart class
- `FlowChart`: Flowchart class used to determine basic blocks.

## Functions Overview

- `gen_gdl(g: gdl_graph_t, fname: str) -> None`: Create GDL file for graph.
- `display_gdl(fname: str) -> int`: Display GDL file by calling wingraph32. The exact name of the grapher is taken from the configuration file and set up by setup_graph_subsystem(). The path should point to a temporary file: when wingraph32 succeeds showing the graph, the input file will be deleted.
- `gen_flow_graph(filename: str, title: str, pfn: func_t *, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, gflags: int) -> bool`: Build and display a flow graph.
- `gen_simple_call_chart(filename: str, wait: str, title: str, gflags: int) -> bool`: Build and display a simple function call graph.
- `gen_complex_call_chart(filename: str, wait: str, title: str, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t, flags: int, recursion_depth: int = -1) -> bool`: Build and display a complex xref graph.
- `is_noret_block(btype: fc_block_type_t) -> bool`: Does this block never return?
- `is_ret_block(btype: fc_block_type_t) -> bool`: Does this block return?