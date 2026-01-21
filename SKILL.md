---
name: ida
description: IDA Pro 逆向分析。通过 IDAPython 脚本获取反汇编、反编译、字符串、导入表、交叉引用等信息。
---

# IDA Pro 逆向分析

## 安全规则

**仅支持静态分析** - 禁止调试、执行任何二进制文件。

## 快速开始：初始化分析

对新样本进行初始化分析，自动生成 i64 数据库并提取所有基础信息：

示例：
```cmd
python skills/ida/tools/init_analysis.py target.exe
python skills/ida/tools/init_analysis.py target.exe ./result
```

输出文件：
- `analysis.txt` - 基本信息 + 导出表 + OEP反编译
- `imports.txt` - 导入表
- `strings_use_subagent_to_analyse.txt` - 字符串（按编码分类，已过滤噪点）

## 分析方法论

### 分析流程
遵循自顶向下的分析策略：
1. **入口点分析** - 从 OEP (Original Entry Point) 开始
2. **主函数定位** - 识别程序主逻辑入口（main/WinMain/DllMain）
3. **功能函数追踪** - 深入关键功能函数进行详细分析

### 寻找关键函数的线索
利用以下信息辅助定位关键函数：
- **导入表** (imports.txt) - 查看调用的系统 API，推断功能（如网络、加密、文件操作）
- **导出表** (analysis.txt) - DLL 的对外接口，通常是核心功能
- **字符串引用** - 通过字符串内容反向定位使用它的函数
- **交叉引用** - 使用 `idautils.XrefsTo()` 查找函数调用关系
- **思维发散** - 使用 IDAPython 获取任何你想知道的线索来辅助分析

### 使用 IDAPython 进行分析
**推荐工作流：**
1. 使用 `exec_ida.py` 执行 IDAPython 代码片段
2. 查看函数反编译结果：`ida_hexrays.decompile(ea)`
3. 追踪函数调用：`idautils.XrefsTo(ea)` / `idautils.XrefsFrom(ea)`
4. 分析数据引用：查找字符串、常量的使用位置

### 字符串分析 - 重要规则
**禁止直接读取 strings_use_subagent_to_analyse.txt！**

strings_use_subagent_to_analyse.txt 文件通常包含数千行字符串，直接读取会：
- 消耗大量 token（可能超过上下文限制）
- 导致响应缓慢
- 无法有效提取有价值信息

**正确做法：**
1. 使用子 Agent 分析
2. 或使用 grep 精确搜索
3. 或使用 IDAPython 定向查询

### 分析输出要求
- 记录关键函数的地址、名称和功能
- 说明函数之间的调用关系
- 标注可疑或重要的代码逻辑
- 如涉及加密/混淆，尝试识别算法并提取密钥

## 执行 IDAPython 代码

初始化分析后，使用 `exec_ida.py` 对 i64 数据库执行 IDAPython 代码进行深入分析。

### 示例

```cmd
# 1. 执行代码
python skills/ida/tools/exec_ida.py target.i64 --code "print('Entry Point:', hex(idc.get_inf_attr(idc.INF_START_EA)))"

# 2. 执行脚本文件
python skills/ida/tools/exec_ida.py target.i64 --file analyze.py
```

## API 快速参考

### 函数操作
- `idautils.Functions()` - 遍历所有函数
- `idc.get_func_name(ea)` - 获取函数名
- `ida_funcs.get_func(ea)` - 获取函数对象
- `idc.set_name(ea, name)` - 重命名

### 反编译
- `ida_hexrays.decompile(ea)` - 反编译函数，返回伪代码

### 字符串
- `idautils.Strings()` - 遍历字符串
- `idc.get_strlit_contents(ea)` - 获取字符串内容

### 交叉引用
- `idautils.XrefsTo(ea)` - 谁引用了这个地址
- `idautils.XrefsFrom(ea)` - 这个地址引用了谁

### 字节操作
- `ida_bytes.get_bytes(ea, size)` - 读取字节
- `ida_bytes.patch_bytes(ea, data)` - 修改字节

## 内置工具

- reai.py - 使用 LLM 分析函数语义，支持递归分析调用链
- findcrypt.py - 通过特征常量识别加密算法（AES, DES, RC4, MD5, SHA1, SHA256, CRC32, Base64 等）
- mkyara.py - 从代码范围生成 YARA 检测规则
- dump.py - 导出指定地址范围、段或函数的原始字节
- export_check.py - 分析 DLL/EXE 的导出函数大小，小字节导出函数序列出现大字节导出函数，需要重点分析
具体用法查询TOOLS.md，脚本位于tools\

## 分析方法文档

| 分析目标 | 推荐文档 |
|---------|---------|
| 分析恶意样本 | [恶意软件分析](analysis/malware-analysis.md) |
| 挖掘安全漏洞 | [漏洞分析](analysis/vulnerability-analysis.md) |
| 还原通信协议 | [协议逆向](analysis/protocol-reverse.md) |
| 识别加密算法 | [算法还原](analysis/algorithm-recovery.md) |
| 处理混淆代码 | [反混淆](analysis/deobfuscation.md) |
| 分析内核驱动 | [驱动分析](analysis/driver-analysis.md) |
| 逆向嵌入式固件 | [固件分析](analysis/firmware-analysis.md) |
| 游戏外挂分析 | [游戏逆向](analysis/game-reverse.md) |
| 移动应用逆向 | [移动应用分析](analysis/mobile-analysis.md) |
| 识别第三方库 | [静态库/SDK 分析](analysis/library-analysis.md) |
| 基础操作技巧 | [通用技巧](analysis/common-techniques.md) |

## 相关文档

- [TOOLS.md](TOOLS.md) - 内置工具参考
- [API.md](API.md) - IDAPYTHON API 索引
- [docs/](docs/) - 完整 IDAPYTHON API 参考
