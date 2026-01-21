# IDAPython API 索引

本文档是 IDAPython API 的精简索引，按功能模块组织。完整文档位于 `docs/` 目录。

## 模块总览

| 分类 | 模块 | 用途 |
|------|------|------|
| 核心 | ida_idaapi, ida_pro | 基础类型、常量定义 |
| 反汇编 | ida_ua, ida_allins | 指令解码、操作数分析 |
| 字节操作 | ida_bytes, ida_nalt | 读写字节、数据类型 |
| 符号引用 | ida_name, ida_xref | 命名、交叉引用 |
| 函数 | ida_funcs, ida_frame | 函数操作、栈帧分析 |
| 段 | ida_segment | 段管理 |
| 类型 | ida_typeinf | 结构体、枚举、类型 |
| 反编译 | ida_hexrays | Hex-Rays 伪代码 |
| UI | ida_kernwin | 界面交互 |
| 脚本 | idc, idautils | 便捷函数 |

## 按功能分类

### 01_core - 核心模块

IDA 数据库核心功能和基础设施。

| 模块 | 说明 |
|------|------|
| [ida_ida](docs/01_core/ida_ida.md) | IDA 全局配置和 inf 结构体 |
| [ida_idaapi](docs/01_core/ida_idaapi.md) | 基础类型定义（ea_t, BADADDR） |
| [ida_pro](docs/01_core/ida_pro.md) | 工具类（qvector, qstring） |
| [ida_netnode](docs/01_core/ida_netnode.md) | IDB 底层存储接口 |
| [ida_registry](docs/01_core/ida_registry.md) | IDA 配置读写 |
| [ida_undo](docs/01_core/ida_undo.md) | 撤销/重做 |
| [idaapi](docs/01_core/idaapi.md) | 高级 API 封装 |

### 02_disasm - 反汇编引擎

指令解码和处理器模块。

| 模块 | 说明 |
|------|------|
| [ida_ua](docs/02_disasm/ida_ua.md) | 指令分析（insn_t, op_t） |
| [ida_allins](docs/02_disasm/ida_allins.md) | 指令定义和助记符 |
| [ida_idp](docs/02_disasm/ida_idp.md) | 处理器模块接口 |
| [ida_ieee](docs/02_disasm/ida_ieee.md) | 浮点数处理 |

### 03_bytes_data - 字节与数据操作

直接操作 IDB 中的字节数据。

| 模块 | 说明 |
|------|------|
| [ida_bytes](docs/03_bytes_data/ida_bytes.md) | 读写字节、patch、数据类型 |
| [ida_nalt](docs/03_bytes_data/ida_nalt.md) | 地址属性、注释、字符串类型 |
| [ida_offset](docs/03_bytes_data/ida_offset.md) | 偏移量引用 |
| [ida_fixup](docs/03_bytes_data/ida_fixup.md) | 重定位信息 |
| [ida_bitrange](docs/03_bytes_data/ida_bitrange.md) | 位范围操作 |

### 04_names_xrefs - 符号与交叉引用

管理符号名称和引用关系。

| 模块 | 说明 |
|------|------|
| [ida_name](docs/04_names_xrefs/ida_name.md) | 符号命名操作 |
| [ida_xref](docs/04_names_xrefs/ida_xref.md) | 交叉引用管理 |
| [ida_entry](docs/04_names_xrefs/ida_entry.md) | 入口点管理 |

### 05_functions - 函数分析

函数识别和栈帧分析。

| 模块 | 说明 |
|------|------|
| [ida_funcs](docs/05_functions/ida_funcs.md) | 函数操作（func_t） |
| [ida_frame](docs/05_functions/ida_frame.md) | 栈帧、局部变量 |
| [ida_libfuncs](docs/05_functions/ida_libfuncs.md) | FLIRT 签名识别 |

### 06_segments - 段与地址空间

管理程序内存段。

| 模块 | 说明 |
|------|------|
| [ida_segment](docs/06_segments/ida_segment.md) | 段操作（segment_t） |
| [ida_segregs](docs/06_segments/ida_segregs.md) | 段寄存器值 |
| [ida_range](docs/06_segments/ida_range.md) | 地址范围（range_t） |

### 07_types - 类型系统

C/C++ 类型信息管理。

| 模块 | 说明 |
|------|------|
| [ida_typeinf](docs/07_types/ida_typeinf.md) | 类型操作（tinfo_t） |
| [ida_srclang](docs/07_types/ida_srclang.md) | 源语言设置 |

### 08_decompiler - Hex-Rays 反编译器

需要 Hex-Rays 许可证。

| 模块 | 说明 |
|------|------|
| [ida_hexrays](docs/08_decompiler/ida_hexrays.md) | 反编译 API（cfunc_t, ctree） |

### 09_debugger - 调试器

IDA 调试功能。

| 模块 | 说明 |
|------|------|
| [ida_dbg](docs/09_debugger/ida_dbg.md) | 调试控制、断点、内存读写 |
| [ida_idd](docs/09_debugger/ida_idd.md) | 调试器接口定义 |
| [ida_regfinder](docs/09_debugger/ida_regfinder.md) | 寄存器值追踪 |

### 10_ui - 用户界面

图形界面和显示。

| 模块 | 说明 |
|------|------|
| [ida_kernwin](docs/10_ui/ida_kernwin.md) | 窗口、菜单、对话框 |
| [ida_graph](docs/10_ui/ida_graph.md) | 图形视图 |
| [ida_gdl](docs/10_ui/ida_gdl.md) | 控制流图 |
| [ida_lines](docs/10_ui/ida_lines.md) | 反汇编行输出 |

### 11_loader - 文件加载器

文件加载和数据库 I/O。

| 模块 | 说明 |
|------|------|
| [ida_loader](docs/11_loader/ida_loader.md) | 加载器接口 |
| [ida_diskio](docs/11_loader/ida_diskio.md) | 磁盘 I/O |
| [ida_fpro](docs/11_loader/ida_fpro.md) | 文件流操作 |

### 12_analysis - 自动分析

IDA 自动分析引擎。

| 模块 | 说明 |
|------|------|
| [ida_auto](docs/12_analysis/ida_auto.md) | 分析队列控制 |
| [ida_problems](docs/12_analysis/ida_problems.md) | 问题列表 |
| [ida_search](docs/12_analysis/ida_search.md) | 搜索功能 |

### 13_misc - 辅助工具

其他辅助功能。

| 模块 | 说明 |
|------|------|
| [ida_expr](docs/13_misc/ida_expr.md) | IDC 表达式求值 |
| [ida_dirtree](docs/13_misc/ida_dirtree.md) | 目录树管理 |
| [ida_strlist](docs/13_misc/ida_strlist.md) | 字符串列表 |
| [ida_tryblks](docs/13_misc/ida_tryblks.md) | 异常处理块 |
| [ida_moves](docs/13_misc/ida_moves.md) | 地址移动记录 |
| [ida_merge](docs/13_misc/ida_merge.md) | 数据库合并 |

### 14_scripting - 脚本接口

IDC 兼容层和 Python 工具。

| 模块 | 说明 |
|------|------|
| [idc](docs/14_scripting/idc.md) | IDC 兼容函数 |
| [ida_idc](docs/14_scripting/ida_idc.md) | IDC 辅助函数 |
| [idautils](docs/14_scripting/idautils.md) | 常用迭代器（Functions, Heads） |
| [idadex](docs/14_scripting/idadex.md) | DEX 文件支持 |

