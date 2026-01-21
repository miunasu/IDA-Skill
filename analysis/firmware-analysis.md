# 固件分析

本文档提供嵌入式系统固件的逆向分析方法。

## 嵌入式系统

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 识别架构 | 检查文件头/指令特征 | `ida_idp.get_idp_name()` |
| 定位基址 | 分析字符串引用 | `ida_segment.set_segm_base()` |
| 识别函数 | 手动创建函数 | `ida_funcs.add_func()` |
| 硬件交互 | 找 MMIO 地址访问 | `ida_bytes.bin_search()` |

## 常见固件结构

| 目标 | 方法 | 关键 API |
|------|------|----------|
| 中断向量表 | 分析固定地址的函数指针 | `ida_bytes.get_dword()` |
| 启动代码 | 找复位向量 | `idc.get_inf_attr(INF_START_EA)` |
| 外设驱动 | 找寄存器地址常量 | `ida_bytes.bin_search()` |
