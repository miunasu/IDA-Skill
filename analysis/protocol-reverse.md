# 协议逆向

本文档提供网络协议、文件格式和 IPC 机制的逆向分析方法。

## 网络协议

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 定位通信代码 | 找 socket/send/recv | `idc.get_name_ea_simple()`, `idautils.XrefsTo()` |
| 分析数据包 | 反编译发送函数 | `ida_hexrays.decompile()` |
| 提取结构 | 定义结构体 | `ida_typeinf.tinfo_t` |

## 文件格式

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 定位解析代码 | 找 fopen/ReadFile | `idautils.XrefsTo()` |
| 识别魔数 | 搜索文件头常量 | `ida_bytes.bin_search()` |

## RPC/IPC 分析

| 目标 | 方法 | 关键 API |
|------|------|----------|
| COM 接口 | 找 QueryInterface/CoCreateInstance | `idautils.XrefsTo()` |
| RPC 服务 | 找 RpcServerRegisterIf | `idautils.XrefsTo()` |
| 命名管道 | 找 CreateNamedPipe/ConnectNamedPipe | `idautils.XrefsTo()` |
| 共享内存 | 找 CreateFileMapping/MapViewOfFile | `idautils.XrefsTo()` |
