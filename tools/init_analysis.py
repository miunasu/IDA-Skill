"""
IDA 初始化分析脚本
自动生成 i64 数据库并提取分析结果

用法：
    python init_analysis.py <binary_path> [output_dir]

示例：
    python init_analysis.py target.exe
    python init_analysis.py target.exe ./result

配置：
    idat 路径在 skills/ida/config.json 中配置

输出文件：
- analysis.txt                          基本信息 + 导出表 + OEP反编译
- imports.txt                           导入表
- strings_use_subagent_to_analyse.txt   字符串（按编码分类：ASCII/UTF-16/Unicode，过滤长度≤3）
                                        ⚠️ 文件名提示：请使用子 Agent 分析此文件
"""
import subprocess
import tempfile
import os
import sys
import json

# IDAPython 分析脚本模板
IDA_SCRIPT_TEMPLATE = r'''
import idaapi
import idautils
import idc
import ida_funcs
import ida_hexrays
import ida_entry
import ida_bytes
import ida_nalt
import os

OUTPUT_DIR = r"__OUTPUT_DIR__"

def write_file(filename, content):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def get_analysis_summary():
    """获取分析摘要：基本信息 + 导出表 + OEP反编译"""
    lines = []
    
    # === 基本信息 ===
    lines.append("=" * 80)
    lines.append("BASIC INFORMATION")
    lines.append("=" * 80)
    lines.append(f"File: {idaapi.get_input_file_path()}")
    lines.append(f"Entry Point: {hex(idc.get_inf_attr(idc.INF_START_EA))}")
    lines.append(f"Min EA: {hex(idc.get_inf_attr(idc.INF_MIN_EA))}")
    lines.append(f"Max EA: {hex(idc.get_inf_attr(idc.INF_MAX_EA))}")
    lines.append(f"Total Functions: {len(list(idautils.Functions()))}")
    lines.append("")
    
    # === 导出表 ===
    lines.append("=" * 80)
    lines.append("EXPORTS")
    lines.append("=" * 80)
    exports = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        if name:
            exports.append(f"{hex(ea)}: {name}")
        else:
            exports.append(f"{hex(ea)}: ordinal_{ordinal}")
    lines.append(f"Total: {len(exports)}")
    lines.append("")
    if exports:
        lines.extend(exports)
    else:
        lines.append("(No exports)")
    lines.append("")
    
    # === OEP 反编译 ===
    lines.append("=" * 80)
    lines.append("OEP DECOMPILE")
    lines.append("=" * 80)
    oep = idc.get_inf_attr(idc.INF_START_EA)
    lines.append(f"Entry Point: {hex(oep)}")
    lines.append("")
    
    func = ida_funcs.get_func(oep)
    if not func:
        lines.append("[-] No function at OEP")
    else:
        func_name = idc.get_func_name(oep)
        lines.append(f"Function: {func_name}")
        lines.append(f"Range: {hex(func.start_ea)} - {hex(func.end_ea)}")
        lines.append(f"Size: {func.end_ea - func.start_ea} bytes")
        lines.append("")
        
        try:
            cfunc = ida_hexrays.decompile(oep)
            lines.append("--- Pseudocode ---")
            lines.append(str(cfunc))
        except Exception as e:
            lines.append(f"[-] Decompile failed: {e}")
            lines.append("")
            lines.append("--- Disassembly ---")
            ea = func.start_ea
            while ea < func.end_ea:
                lines.append(f"{hex(ea)}: {idc.GetDisasm(ea)}")
                ea = idc.next_head(ea, func.end_ea)
    
    return "\n".join(lines)

def get_imports():
    lines = []
    lines.append("=== Imports ===\n")
    imports = []
    for i in range(idaapi.get_import_module_qty()):
        module = idaapi.get_import_module_name(i)
        def cb(ea, name, ordinal):
            if name:
                imports.append(f"{module}!{name}")
            else:
                imports.append(f"{module}!ordinal_{ordinal}")
            return True
        idaapi.enum_import_names(i, cb)
    lines.append(f"Total: {len(imports)}\n")
    lines.extend(imports)
    return "\n".join(lines)

def is_noise_string(s):
    """判断是否为噪点字符串（编译器/运行时生成的元数据）"""
    # C++ RTTI 类型信息
    if s.startswith(".?AV") or s.startswith(".?AU"):  # class/struct type info
        return True
    if s.startswith("??_"):  # MSVC mangled names
        return True
    if s.startswith("_ZN") or s.startswith("_Z"):  # GCC/Clang mangled names
        return True
    
    # .NET 元数据
    if s.startswith("System.") or s.startswith("Microsoft."):  # .NET namespaces
        return True
    
    # Go 运行时
    if s.startswith("go.") or s.startswith("runtime.") or s.startswith("type.."):
        return True
    
    # Rust 符号
    if s.startswith("_R") and ("$" in s or ".." in s):  # Rust mangled names
        return True
     
    return False

def get_strings():
    """从 IDA 提取字符串，按编码分类"""
    lines = []
    lines.append("=== Strings ===\n")
    
    # 按编码类型分类
    ascii_strings = []
    utf16_strings = []
    unicode_strings = []
    
    # 遍历所有字符串
    for s in idautils.Strings():
        try:
            str_val = str(s)
            
            # 过滤长度 <= 3 的字符串
            if len(str_val) <= 3:
                continue
            
            # 过滤噪点字符串
            if is_noise_string(str_val):
                continue
            
            # 获取字符串类型
            str_type = s.strtype
            ea = s.ea
            
            # 分类存储
            # STRTYPE_C = 0 (ASCII/C string)
            # STRTYPE_C_16 = 7 (UTF-16LE)
            # STRTYPE_UNICODE = 1 (Unicode)
            if str_type == 0:  # ASCII
                ascii_strings.append((ea, str_val))
            elif str_type == 7:  # UTF-16
                utf16_strings.append((ea, str_val))
            elif str_type == 1:  # Unicode
                unicode_strings.append((ea, str_val))
            else:
                # 其他类型也归入对应类别
                ascii_strings.append((ea, str_val))
                
        except Exception as e:
            continue
    
    # 统计信息
    total = len(ascii_strings) + len(utf16_strings) + len(unicode_strings)
    lines.append(f"Total strings: {total}")
    lines.append(f"  ASCII: {len(ascii_strings)}")
    lines.append(f"  UTF-16: {len(utf16_strings)}")
    lines.append(f"  Unicode: {len(unicode_strings)}")
    lines.append("")
    
    # 输出 ASCII 字符串
    if ascii_strings:
        lines.append("=" * 60)
        lines.append("ASCII Strings")
        lines.append("=" * 60)
        for ea, s in ascii_strings:
            lines.append(s)
        lines.append("")
    
    # 输出 UTF-16 字符串
    if utf16_strings:
        lines.append("=" * 60)
        lines.append("UTF-16 Strings")
        lines.append("=" * 60)
        for ea, s in utf16_strings:
            lines.append(s)
        lines.append("")
    
    # 输出 Unicode 字符串
    if unicode_strings:
        lines.append("=" * 60)
        lines.append("Unicode Strings")
        lines.append("=" * 60)
        for ea, s in unicode_strings:
            lines.append(s)
        lines.append("")
    
    return "\n".join(lines)

def main():
    idaapi.auto_wait()
    
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    write_file("analysis.txt", get_analysis_summary())
    write_file("imports.txt", get_imports())
    write_file("strings_use_subagent_to_analyse.txt", get_strings())

if __name__ == "__main__":
    main()
    idc.qexit(0)
'''

def load_config():
    """加载 IDA 配置"""
    # 获取脚本所在目录的父目录（skills/ida/）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(script_dir), "config.json")
    
    if not os.path.exists(config_path):
        print(f"[-] Config file not found: {config_path}")
        print("[*] Please create config.json with idat_path")
        sys.exit(1)
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        idat_path = config.get("idat_path")
        if not idat_path:
            print("[-] idat_path not found in config.json")
            sys.exit(1)
        
        if not os.path.exists(idat_path):
            print(f"[-] idat not found: {idat_path}")
            print("[*] Please update config.json with correct idat_path")
            sys.exit(1)
        
        return idat_path
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON in config.json: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading config: {e}")
        sys.exit(1)


def run_ida_analysis(binary_path, output_dir):
    """运行 IDA 分析"""
    # 加载配置
    idat_path = load_config()
    
    binary_path = os.path.abspath(binary_path)
    output_dir = os.path.abspath(output_dir)
    
    if not os.path.exists(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        return False
    
    if not os.path.exists(idat_path):
        print(f"[-] idat not found: {idat_path}")
        return False
    
    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成临时 IDAPython 脚本
    script_content = IDA_SCRIPT_TEMPLATE.replace("__OUTPUT_DIR__", output_dir.replace("\\", "\\\\"))
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(script_content)
        script_path = f.name
    
    try:
        print(f"[*] idat: {idat_path}")
        print(f"[*] Binary: {binary_path}")
        print(f"[*] Output: {output_dir}")
        print(f"[*] Running IDA analysis...")
        
        # 构建命令
        cmd = [
            f'"{idat_path}"',
            "-A",
            f'-S"{script_path}"',
            f'"{binary_path}"'
        ]
        
        # 执行
        result = subprocess.run(
            " ".join(cmd),
            shell=True,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        # 检查输出文件
        expected_files = ["analysis.txt", "imports.txt", "strings_use_subagent_to_analyse.txt"]
        generated = [f for f in expected_files if os.path.exists(os.path.join(output_dir, f))]
        
        if generated:
            print(f"[+] Analysis complete! Generated files:")
            for f in generated:
                print(f"    - {f}")
            return True
        else:
            print("[-] No output files generated")
            
            # 过滤 stdout 中的插件加载信息
            stdout_filtered = result.stdout
            if stdout_filtered:
                plugin_end_marker = "[uEmu]: Init plugin uEmu"
                marker_pos = stdout_filtered.find(plugin_end_marker)
                if marker_pos >= 0:
                    stdout_filtered = stdout_filtered[marker_pos + len(plugin_end_marker):].lstrip('\r\n')
            
            if stdout_filtered:
                print(f"[*] IDA stdout: {stdout_filtered}")
            if result.stderr:
                print(f"[*] IDA stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("[-] Analysis timeout (10 min)")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        try:
            os.unlink(script_path)
        except:
            pass

def main():
    if len(sys.argv) < 2:
        print("Usage: python init_analysis.py <binary_path> [output_dir]")
        print("Example: python init_analysis.py target.exe ./result")
        print("")
        print("Config: idat_path is configured in skills/ida/config.json")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(binary_path)) or "."
    
    success = run_ida_analysis(binary_path, output_dir)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
