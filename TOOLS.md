# IDA 内置工具参考

## reai.py - AI 辅助分析

使用 LLM 分析函数语义，支持递归分析调用链。
使用check查看调用链函数总数，如果调用链函数大于40个，不可以使用reai analyze。
```cmd
# 检查异常代码 查看调用链函数个数（必须先执行）
python tools/exec_ida.py target.i64 --tool reai.py 0x401000 check

# 分析函数并递归处理子函数
python tools/exec_ida.py target.i64 --tool reai.py 0x401000 analyze

# 分析时跳过异常代码继续处理
python tools/exec_ida.py target.i64 --tool reai.py 0x401000 analyze --skip-error

# 打印调用关系图
python tools/exec_ida.py target.i64 --tool reai.py 0x401000 topology
```

---

## findcrypt.py - 加密算法识别

通过特征常量识别加密算法（AES, DES, RC4, MD5, SHA1, SHA256, CRC32, Base64 等）。

```cmd
python tools/exec_ida.py target.i64 --tool findcrypt.py
```

---

## mkyara.py - YARA 规则生成

从代码范围生成 YARA 检测规则。

```cmd
python tools/exec_ida.py target.i64 --tool mkyara.py 0x401000 0x402000 auto output.yar
```

---

## dump.py - 内存导出

导出指定地址范围、段或函数的原始字节。

```cmd
# 导出地址范围
python tools/exec_ida.py target.i64 --tool dump.py 0x401000 0x1000 output.bin

# 导出段
python tools/exec_ida.py target.i64 --tool dump.py --seg .text dump.bin

# 导出函数
python tools/exec_ida.py target.i64 --tool dump.py --func 0x401000 func.bin
```

---

## export_check.py - 导出函数大小检查

分析 DLL/EXE 的导出函数大小，小字节导出函数序列出现大字节导出函数，需要重点分析。

```cmd
python tools/exec_ida.py target.i64 --tool export_check.py
```
