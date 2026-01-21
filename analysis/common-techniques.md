# 通用技巧

本文档提供 IDA 逆向分析中的通用技巧和常用方法。

## 基本操作

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 字符串搜索 | 按关键字过滤 | `ida_strlist`, `idc.get_strlit_contents()` |
| 常量搜索 | 二进制搜索 | `ida_bytes.bin_search()` |
| 批量重命名 | 遍历函数设置名称 | `idautils.Functions()`, `idc.set_name()` |
| 导出报告 | 输出 JSON | `idautils.Functions()`, `ida_funcs.get_func()` |
| 遍历指令 | 分析代码流 | `idautils.Heads()`, `idc.GetDisasm()` |
| 交叉引用 | 找调用/被调用 | `idautils.XrefsTo()`, `idautils.XrefsFrom()` |

## 高级搜索技巧

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 指令模式搜索 | 搜索特定指令序列 | `ida_search.find_code()` |
| 立即数搜索 | 找特定常量 | `ida_search.find_imm()` |
| 文本搜索 | 搜索反汇编文本 | `ida_search.find_text()` |
| 字节模式 | 搜索字节序列 | `ida_bytes.bin_search()` |

## 类型系统应用

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 定义结构体 | 创建自定义类型 | `ida_typeinf.tinfo_t` |
| 应用类型 | 设置变量/参数类型 | `ida_typeinf.apply_tinfo()` |
| 导入头文件 | 解析 C 头文件 | `ida_typeinf.parse_decls()` |
| 枚举定义 | 创建枚举类型 | `ida_typeinf.enum_type_data_t` |

## 注释与标注

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 添加注释 | 行注释/函数注释 | `idc.set_cmt()`, `idc.set_func_cmt()` |
| 添加书签 | 标记重要位置 | `ida_moves.mark_position()` |
| 颜色标注 | 高亮代码行 | `idc.set_color()` |

## 导出与报告

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 导出函数列表 | JSON 格式 | `idautils.Functions()` + json |
| 导出字符串 | CSV 格式 | `ida_strlist` + csv |
| 导出交叉引用 | 图形格式 | `idautils.XrefsTo()` + graphviz |
| 生成 HTML 报告 | 格式化输出 | `ida_lines.generate_disasm_line()` |
