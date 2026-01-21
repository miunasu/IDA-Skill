# 游戏逆向

本文档提供游戏反作弊和游戏逻辑的逆向分析方法。

## 反作弊分析

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 完整性检查 | 找 CRC/Hash 计算 | `ida_bytes.bin_search()` 找常量 |
| 调试检测 | 找 IsDebuggerPresent 等 | `idautils.XrefsTo()` |
| 内存扫描 | 找 VirtualQuery/ReadProcessMemory | `idautils.XrefsTo()` |
| 时间检测 | 找 QueryPerformanceCounter/rdtsc | `idautils.XrefsTo()` |

## 游戏逻辑

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 玩家结构 | 找坐标/血量相关字符串 | `ida_strlist` + `idautils.XrefsTo()` |
| 渲染函数 | 找 D3D/OpenGL 调用 | `idautils.XrefsTo()` |
| 网络协议 | 找 send/recv 调用 | `idautils.XrefsTo()` |
