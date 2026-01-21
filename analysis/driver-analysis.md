# 驱动分析

本文档提供 Windows 内核驱动和 Rootkit 的分析方法。

## Windows 内核驱动

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 入口点 | 找 DriverEntry | `idc.get_inf_attr(INF_START_EA)` |
| IRP 处理 | 分析 MajorFunction 表 | `ida_bytes.get_qword()` 读取函数表 |
| IOCTL 处理 | 找 IRP_MJ_DEVICE_CONTROL 处理函数 | `ida_hexrays.decompile()` |
| 内核 API | 找 Zw*/Nt* 调用 | `idautils.Names()` 过滤 |

## Rootkit 检测

| 目标 | 方法 | 关键 API |
|------|------|----------|
| SSDT Hook | 找 KeServiceDescriptorTable 引用 | `idautils.XrefsTo()` |
| IDT Hook | 找 IDTR 操作 | `ida_ua.decode_insn()` |
| 内联 Hook | 找 JMP/CALL patch | `ida_bytes.get_bytes()` 分析函数头 |
| DKOM | 找 EPROCESS 链表操作 | `ida_hexrays.decompile()` |
