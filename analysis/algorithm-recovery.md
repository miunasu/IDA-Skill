# 算法还原

本文档提供加密算法识别和还原的方法。

## 基本方法

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 识别已知算法 | 搜索加密常量 | 使用 `findcrypt.py` 或 `ida_bytes.bin_search()` |
| 提取算法 | 反编译并分析 | `ida_hexrays.decompile()` |
| 读取常量表 | 导出 S-box 等数据 | `ida_bytes.get_bytes()` |

## 常见加密算法特征

| 算法 | 特征常量 | 搜索方法 |
|------|----------|----------|
| AES | S-box: 0x63, 0x7c, 0x77... | `ida_bytes.bin_search()` |
| MD5 | 0x67452301, 0xefcdab89 | `ida_bytes.bin_search()` |
| SHA1 | 0x67452301, 0xEFCDAB89 | `ida_bytes.bin_search()` |
| RC4 | 256 字节 S-box 初始化 | 分析循环结构 |
| Base64 | "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef..." | 字符串搜索 |
| CRC32 | 0xEDB88320 多项式 | `ida_bytes.bin_search()` |

## 自定义算法分析

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 识别循环结构 | 分析基本块和跳转 | `ida_gdl.FlowChart()` |
| 提取常量 | 导出函数中的立即数 | `ida_ua.decode_insn()`, `op_t.value` |
| 模拟执行 | 使用 Unicorn/Qiling | 导出字节后外部模拟 |
