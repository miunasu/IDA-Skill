"""
通用 IDAPython 执行工具
直接执行 IDAPython 代码并输出结果到控制台

用法：
    python exec_ida.py <i64_path> --code <code>
    python exec_ida.py <i64_path> --file <script.py>
    python exec_ida.py <i64_path> --tool <tool_name> [args...]

示例：
    # 执行代码
    python exec_ida.py target.i64 --code "print(hex(idc.get_inf_attr(idc.INF_START_EA)))"
    
    # 执行脚本文件
    python exec_ida.py target.i64 --file analyze.py
    
    # 调用工具并传参
    python exec_ida.py target.i64 --tool reai.py 0x401000 check
    python exec_ida.py target.i64 --tool dump.py --seg .text dump.bin
    python exec_ida.py target.i64 --tool mkyara.py 0x401000 0x402000 auto output.yar

配置：
    idat 路径在 skills/ida/config.json 中配置

说明：
    IDA 不支持直接在命令行执行代码，必须通过脚本文件。
    本工具自动创建临时脚本并执行，简化使用流程。
"""
import subprocess
import tempfile
import os
import sys
import json

def load_config():
    """加载 IDA 配置"""
    # 获取脚本所在目录的父目录（skills/ida/）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(script_dir), "config.json")
    
    if not os.path.exists(config_path):
        print(f"[-] Config file not found: {config_path}", file=sys.stderr)
        print("[*] Please create config.json with idat_path", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        idat_path = config.get("idat_path")
        if not idat_path:
            print("[-] idat_path not found in config.json", file=sys.stderr)
            sys.exit(1)
        
        if not os.path.exists(idat_path):
            print(f"[-] idat not found: {idat_path}", file=sys.stderr)
            print("[*] Please update config.json with correct idat_path", file=sys.stderr)
            sys.exit(1)
        
        return idat_path
    except json.JSONDecodeError as e:
        print(f"[-] Invalid JSON in config.json: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading config: {e}", file=sys.stderr)
        sys.exit(1)


def run_ida_code(i64_path, code):
    """执行 IDAPython 代码"""
    # 加载配置
    idat_path = load_config()
    
    i64_path = os.path.abspath(i64_path)
    
    if not os.path.exists(i64_path):
        print(f"[-] i64 file not found: {i64_path}")
        return False
    
    if not os.path.exists(idat_path):
        print(f"[-] idat not found: {idat_path}")
        return False
    
    # 检查代码是否包含退出语句，没有则自动添加（兜底）
    # 退出语句必须是 idaapi.qexit(0) 或 idc.qexit(0)
    code_stripped = code.strip()
    has_qexit = ('idaapi.qexit' in code_stripped or 
                 'idc.qexit' in code_stripped or
                 'ida_pro.qexit' in code_stripped)
    
    if not has_qexit:
        # 自动添加退出语句
        code = code_stripped + '\n\nidaapi.qexit(0)'
    
    # 创建临时脚本文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write(code)
        script_path = f.name
    
    # 日志文件放在样本目录（临时使用，执行后删除）
    i64_dir = os.path.dirname(i64_path)
    log_path = os.path.join(i64_dir, "ida_exec_output.log")
    
    process = None
    try:
        # 构建命令（不使用 -c，依赖脚本中的 qexit）
        cmd = [
            f'"{idat_path}"',
            "-A",  # 自动分析
            f'-L"{log_path}"',  # 输出日志
            f'-S"{script_path}"',
            f'"{i64_path}"'
        ]
        
        # 启动进程并阻塞等待完成
        process = subprocess.Popen(
            " ".join(cmd),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待进程完成（不设置超时，让 IDA 自然完成）
        stdout, stderr = process.communicate()
        
        # 读取日志文件并输出所有内容（过滤 IDA 插件加载信息）
        if os.path.exists(log_path):
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
                if log_content:
                    # 查找插件加载结束标记
                    plugin_end_marker = "[uEmu]: Init plugin uEmu"
                    marker_pos = log_content.find(plugin_end_marker)
                    
                    if marker_pos >= 0:
                        # 跳过标记行，从下一行开始输出
                        content_after_marker = log_content[marker_pos + len(plugin_end_marker):].lstrip('\r\n')
                        if content_after_marker:
                            print(content_after_marker)
                    else:
                        # 如果没有找到标记，输出全部内容（可能是旧版本 IDA）
                        print(log_content)
        
        # 输出 stderr（如果有）
        if stderr:
            print(stderr, file=sys.stderr)
        
        return process.returncode == 0
            
    except KeyboardInterrupt:
        # 用户中断时才终止进程
        print("\n[-] Interrupted by user", file=sys.stderr)
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        return False
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False
    finally:
        # 清理临时文件（脚本和日志）
        try:
            os.unlink(script_path)
        except:
            pass
        try:
            if os.path.exists(log_path):
                os.unlink(log_path)
        except:
            pass

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python exec_ida.py <i64_path> --code <code>")
        print("  python exec_ida.py <i64_path> --file <script.py>")
        print("  python exec_ida.py <i64_path> --tool <tool_name> [args...]")
        print("\nExamples:")
        print('  python exec_ida.py target.i64 --code "print(hex(idc.get_inf_attr(idc.INF_START_EA)))"')
        print('  python exec_ida.py target.i64 --file analyze.py')
        print('  python exec_ida.py target.i64 --tool reai.py 0x401000 check')
        print('  python exec_ida.py target.i64 --tool dump.py --seg .text dump.bin')
        sys.exit(1)
    
    i64_path = sys.argv[1]
    mode = sys.argv[2]
    
    if mode == "--file":
        # 从文件读取代码
        if len(sys.argv) < 4:
            print("[-] Missing script file path")
            sys.exit(1)
        
        script_file = sys.argv[3]
        if not os.path.exists(script_file):
            print(f"[-] Script file not found: {script_file}")
            sys.exit(1)
        
        with open(script_file, 'r', encoding='utf-8') as f:
            code = f.read()
    
    elif mode == "--code":
        # 直接传递代码
        if len(sys.argv) < 4:
            print("[-] Missing code argument")
            sys.exit(1)
        
        code = sys.argv[3]
    
    elif mode == "--tool":
        # 调用工具并传参
        if len(sys.argv) < 4:
            print("[-] Missing tool name")
            sys.exit(1)
        
        tool_name = sys.argv[3]
        tool_args = sys.argv[4:] if len(sys.argv) > 4 else []
        
        # 获取工具脚本路径（相对于 exec_ida.py 的位置）
        script_dir = os.path.dirname(os.path.abspath(__file__))
        tool_path = os.path.join(script_dir, tool_name)
        
        if not os.path.exists(tool_path):
            print(f"[-] Tool not found: {tool_path}")
            sys.exit(1)
        
        # 读取工具脚本
        with open(tool_path, 'r', encoding='utf-8') as f:
            tool_code = f.read()
        
        # 构建传参代码：将参数注入到 idc.ARGV
        # IDA 工具脚本使用 idc.ARGV 而不是 sys.argv
        args_repr = repr(['tool'] + tool_args)
        param_code = f"""
import idc
# 注入工具参数到 idc.ARGV
idc.ARGV = {args_repr}

# 执行工具代码
"""
        code = param_code + tool_code
    
    else:
        print(f"[-] Invalid mode: {mode}")
        print("[*] Use --code, --file, or --tool")
        sys.exit(1)
    
    success = run_ida_code(i64_path, code)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
