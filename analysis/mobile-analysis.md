# 移动应用分析

本文档提供 Android 和 iOS 应用的逆向分析方法。

## Android Native

| 目标 | 方法 | 关键 API |
|------|------|----------|
| JNI 函数 | 找 Java_* 导出 | `idautils.Entries()` |
| 反调试 | 找 ptrace/fork | `idautils.XrefsTo()` |
| 加密 | 找 OpenSSL/BoringSSL 函数 | `idautils.Names()` |

## iOS

| 目标 | 方法 | 关键 API |
|------|------|----------|
| ObjC 方法 | 分析 __objc_methname | `ida_segment.get_segm_by_name()` |
| Swift 函数 | 分析 demangle 后的名称 | `ida_name.demangle_name()` |
| 越狱检测 | 找文件检查/URL scheme | `ida_strlist` |
