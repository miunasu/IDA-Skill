#!/usr/bin/env python3
"""
REAI - AI 辅助逆向分析
基于 LLM 自动分析函数伪代码、重命名函数、添加注释

依赖: openai (pip install openai)

用法:
    1. 先检查异常代码:
       idat -A -S"reai.py <func_ea> check" target.idb
    
    2. 再进行分析:
       idat -A -S"reai.py <func_ea> analyze [--skip-error]" target.idb

    action:
        check     - 检查异常代码（JUMPOUT/MEMORY），必须先执行
        analyze   - 分析函数并递归处理子函数
        topology  - 打印调用拓扑

    options:
        --skip-error  - 遇到异常代码时跳过，继续分析后续函数

配置文件: scripts/config.json
"""
import idaapi
import ida_funcs
import ida_hexrays
import idc
import json
import os
import threading
import queue

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# 硬编码配置
API_KEY = ""
API_URL = ""
MODEL = ""
analyze_prompt = "你是一个专业的恶意代码分析师,现在分析ida提供的伪代码,以json格式把结果返回给我,要求包含两个对象,'des':对该函数功能的中文描述。'name':给该函数一个合适的英文名称。代码如下："
#analyze_prompt = "You are a professional malware analyst. Now analyze ida's pseudocode and return the result to me in JSON format. The result should contain two objects: 'des' — a English description of the function's purpose, and 'name' — an appropriate English name for the function. The code is as follows: "
TEMPERATURE = 0.7

# 全局变量
AI_return = queue.Queue()
exception_code_collection = []
processed_func = []
processing_func = []
function_info = {}
skip_error_mode = False

client = None


def init_client():
    global client
    if not API_KEY:
        print("[REAI] Error: API key not set. Configure in config.json or OPENAI_API_KEY env")
        return False
    client = OpenAI(api_key=API_KEY, base_url=API_URL)
    print(f"[REAI] Using API: {API_URL}, Model: {MODEL}")
    return True


def chat_with_AI(content):
    """调用 LLM API"""
    try:
        if isinstance(content, list):
            messages = content
        else:
            messages = [{"role": "user", "content": analyze_prompt + content}]
        
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=TEMPERATURE
        )
        
        if isinstance(content, list):
            return response.choices[0].message.content
        
        content_str = response.choices[0].message.content
        if "```json" in content_str:
            result = json.loads(content_str.split("```json")[-1].split("```")[0])
        elif "```" in content_str:
            result = json.loads(content_str.split("```")[-2].split("```")[0])
        else:
            result = json.loads(content_str)
        return result
    
    except json.JSONDecodeError as e:
        print(f"[REAI] JSON decode error: {e}")
        return None
    except Exception as e:
        print(f"[REAI] API error: {e}")
        return None


def rename_function(func_ea, new_name):
    """重命名函数，添加 AI_ 前缀"""
    current_name = ida_funcs.get_func_name(func_ea)
    if new_name != current_name and 'sub_' not in new_name:
        return idaapi.set_name(func_ea, 'AI_' + new_name, idaapi.SN_NOWARN)
    return False


def get_function_calls(func_ea):
    """获取函数内的所有调用"""
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        function_calls = {}
        
        class Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
            
            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call:
                    function_calls[e.ea] = e.x.obj_ea
                return 0
        
        visitor = Visitor()
        visitor.apply_to(cfunc.body, None)
        return function_calls
    except:
        return {}


def add_decompiled_comment(ea, comment):
    """在伪代码中添加注释"""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return False
        
        class Visitor(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
            
            def visit_expr(self, e):
                if e.ea == ea:
                    loc = ida_hexrays.treeloc_t()
                    loc.ea = e.ea
                    loc.itp = idaapi.ITP_SEMI
                    cfunc.set_user_cmt(loc, comment)
                    cfunc.save_user_cmts()
                    return 1
                return 0
        
        visitor = Visitor()
        visitor.apply_to(cfunc.body, None)
        cfunc.refresh_func_ctext()
        return True
    except:
        return False


def call_add_func(ea):
    """为 call 指令创建函数"""
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return
        point = func.start_ea
        while point <= func.end_ea:
            disasm = idc.GetDisasm(point)
            if 'call' in disasm and 'unk_' in disasm:
                try:
                    address = int(disasm.split(' ')[-1].strip()[4:], 16)
                    if ida_funcs.add_func(address):
                        print(f'[REAI] Created function at {hex(address)}')
                except:
                    pass
            point = idc.next_head(point)
    except:
        pass


def check_function_exception(ea):
    """检查单个函数是否有异常代码"""
    try:
        cfunc = idaapi.decompile(ea)
        code_str = str(cfunc)
        has_jumpout = "JUMPOUT" in code_str
        has_memory = "MEMORY[" in code_str
        return has_jumpout, has_memory
    except:
        return False, False


def exception_code_check(ea, caller_ea_arg=0):
    """检查异常代码（JUMPOUT/MEMORY）"""
    global exception_code_collection, processed_func, processing_func
    
    func = ida_funcs.get_func(ea)
    func_name = ida_funcs.get_func_name(ea)
    
    if caller_ea_arg != 0 and (ea in processed_func or ea in processing_func or func is None or 'sub_' not in func_name):
        return True
    
    processing_func.append(ea)
    call_add_func(ea)
    
    has_jumpout, has_memory = check_function_exception(ea)
    if has_jumpout or has_memory:
        issues = []
        if has_jumpout:
            issues.append("JUMPOUT")
        if has_memory:
            issues.append("MEMORY[]")
        exception_code_collection.append({
            "address": hex(ea),
            "name": func_name,
            "issues": issues
        })
    
    sub_func = get_function_calls(ea)
    for caller_ea, call_ea in sub_func.items():
        exception_code_check(call_ea, caller_ea)
    
    processed_func.append(ea)
    
    if caller_ea_arg == 0:
        processing_func.clear()
        return len(exception_code_collection) == 0
    return True


class Node:
    def __init__(self):
        self.parent = []
        self.child = {}
        self.parent_chain = set()
        self.ea = 0
        self.caller_ea = []
        self.has_exception = False


def get_call_topology(ea, caller_ea, parent_ea, parent_chain, count):
    """获取调用拓扑"""
    global function_info, exception_code_collection
    
    current_node = Node()
    current_node.ea = ea
    current_node.caller_ea.append(caller_ea)
    current_node.parent_chain = parent_chain | {parent_ea}
    current_node.parent.append(parent_ea)
    
    # 检查是否有异常
    for exc in exception_code_collection:
        if exc["address"] == hex(ea):
            current_node.has_exception = True
            break
    
    sub_func = get_function_calls(ea)
    for c_ea, call_ea in sub_func.items():
        func_name = ida_funcs.get_func_name(call_ea)
        func = ida_funcs.get_func(call_ea)
        if (current_node.child.get(call_ea) is None and 
            call_ea not in current_node.parent_chain and 
            call_ea != ea and func is not None and 'sub_' in func_name):
            current_node.child[call_ea] = c_ea
    
    function_info[ea] = current_node
    
    for call_ea, c_ea in current_node.child.items():
        if function_info.get(call_ea) is None:
            get_call_topology(call_ea, c_ea, ea, current_node.parent_chain, count + 1)
        else:
            function_info[call_ea].caller_ea.append(c_ea)
            function_info[call_ea].parent.append(ea)
            function_info[call_ea].parent_chain |= current_node.parent_chain | {ea}


def print_topology():
    """打印调用拓扑"""
    for ea, func_node in function_info.items():
        parent = [hex(i) for i in func_node.parent if i != 0]
        caller_ea = [hex(i) for i in func_node.caller_ea if i != 0]
        func_name = ida_funcs.get_func_name(func_node.ea)
        exc_mark = " [EXCEPTION]" if func_node.has_exception else ""
        print('----------------------')
        print(f'Function: {func_name} ({hex(ea)}){exc_mark}')
        print(f'Parent: {parent}')
        print(f'Caller EA: {caller_ea}')
        print(f'Children: {len(func_node.child)}')


def AI_work(ea, pseudocode, func_name):
    """AI 分析工作线程"""
    result = chat_with_AI(pseudocode)
    if result:
        AI_return.put([ea, result.get("name", func_name), result.get("des", "")])
    else:
        AI_return.put(['bad'])


def AI_analyze(func_start):
    """使用调用拓扑分析函数"""
    global function_info, skip_error_mode
    round_count = 0
    skipped_count = 0
    
    while len(function_info[func_start].child) != 0:
        print(f'[REAI] Round {round_count}')
        
        if round_count >= 30:
            print('[REAI] Too many rounds, stopping')
            break
        
        round_list = []
        thread_list = []
        skipped_this_round = []
        
        for ea, func_node in function_info.items():
            if len(func_node.child) == 0:
                # 检查是否有异常
                if func_node.has_exception:
                    if skip_error_mode:
                        print(f'[REAI] Skipping {hex(ea)} (has exception code)')
                        skipped_this_round.append(ea)
                        skipped_count += 1
                        continue
                    else:
                        print(f'[REAI] Warning: {hex(ea)} has exception code, analyzing anyway')
                
                round_list.append(func_node.ea)
                try:
                    c_func = ida_hexrays.decompile(ea)
                    c_func.refresh_func_ctext()
                    func_name = ida_funcs.get_func_name(ea)
                    t = threading.Thread(target=AI_work, args=(func_node.ea, str(c_func), func_name))
                    thread_list.append(t)
                    t.start()
                except Exception as e:
                    print(f'[REAI] Decompile failed for {hex(ea)}: {e}')
        
        # 处理跳过的函数
        for ea in skipped_this_round:
            if ea not in round_list:
                round_list.append(ea)
        
        for t in thread_list:
            t.join()
            info = AI_return.get()
            if info[0] == 'bad':
                continue
            
            func_ea, new_name, description = info
            old_name = ida_funcs.get_func_name(func_ea)
            
            if rename_function(func_ea, new_name):
                print(f"[REAI] Renamed: {old_name} -> AI_{new_name}")
                final_name = 'AI_' + new_name
            else:
                # 尝试添加后缀
                for i in range(1, 10):
                    if rename_function(func_ea, f"{new_name}_{i}"):
                        print(f"[REAI] Renamed: {old_name} -> AI_{new_name}_{i}")
                        final_name = f'AI_{new_name}_{i}'
                        break
                else:
                    final_name = old_name
            
            try:
                ida_hexrays.decompile(func_ea).refresh_func_ctext()
            except:
                pass
            
            for caller in function_info[func_ea].caller_ea:
                if caller != 0:
                    add_decompiled_comment(caller, f"{description} by {final_name}")
        
        # 清理已处理的函数
        for ea in round_list:
            if ea in function_info:
                del function_info[ea]
        
        for ea, func_node in function_info.items():
            for r in round_list:
                if r in func_node.child:
                    del func_node.child[r]
        
        print(f'[REAI] Round {round_count} done: {len(round_list)} functions')
        round_count += 1
    
    # 处理根函数
    root_node = function_info.get(func_start)
    if root_node and root_node.has_exception and skip_error_mode:
        print(f'[REAI] Skipping root function {hex(func_start)} (has exception code)')
    else:
        try:
            c_func = ida_hexrays.decompile(func_start)
            c_func.refresh_func_ctext()
            func_name = ida_funcs.get_func_name(func_start)
            
            result = chat_with_AI(str(c_func))
            if result:
                if rename_function(func_start, result.get("name", func_name)):
                    idc.set_func_cmt(func_start, result.get("des", ""), True)
                    print(f"[REAI] Root renamed: {func_name} -> AI_{result['name']}")
            c_func.refresh_func_ctext()
        except:
            pass
    
    if skipped_count > 0:
        print(f'[REAI] Total skipped due to exceptions: {skipped_count}')


def func_analyze(ea):
    """分析函数入口"""
    global function_info, processed_func, exception_code_collection
    
    if not HAS_OPENAI:
        print("[REAI] Error: openai not installed. Run: pip install openai")
        return
    
    if not init_client():
        return
    
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"[REAI] No function at {hex(ea)}")
        return
    
    func_start = func.start_ea
    
    # 先检查异常代码
    print("[REAI] Step 1: Checking for exception code...")
    exception_code_check(ea)
    
    if exception_code_collection:
        print(f"[REAI] Found {len(exception_code_collection)} functions with exception code:")
        for exc in exception_code_collection:
            print(f"  {exc['address']} ({exc['name']}): {', '.join(exc['issues'])}")
        
        if skip_error_mode:
            print("[REAI] --skip-error enabled, will skip these functions")
        else:
            print("[REAI] Warning: Analyzing functions with exception code may produce inaccurate results")
    
    processed_func.clear()
    
    # 构建调用拓扑
    print("[REAI] Step 2: Building call topology...")
    get_call_topology(func_start, 0, 0, set(), 0)
    
    print(f'[REAI] Step 3: Starting AI analysis from {hex(func_start)}')
    print(f'[REAI] Total functions to analyze: {len(function_info)}')
    
    AI_analyze(func_start)
    
    function_info.clear()
    exception_code_collection.clear()
    print("[REAI] Analysis completed!")


def main():
    idaapi.auto_wait()
    
    if len(idc.ARGV) < 3:
        print("Usage: reai.py <func_ea> <action> [options]")
        print("")
        print("Workflow:")
        print("  1. First run 'check' to find exception code")
        print("  2. Then run 'analyze' to perform AI analysis")
        print("")
        print("Actions:")
        print("  check    - Check for exception code (JUMPOUT/MEMORY)")
        print("  analyze  - Analyze function with AI")
        print("  topology - Print call topology")
        print("")
        print("Options:")
        print("  --skip-error  - Skip functions with exception code during analysis")
        print("")
        print(f"Config file: {os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')}")
        idc.qexit(1)
        return
    
    func_ea = int(idc.ARGV[1], 16) if idc.ARGV[1].startswith("0x") else int(idc.ARGV[1])
    action = idc.ARGV[2]
    
    global exception_code_collection, processed_func, function_info, skip_error_mode
    
    # 检查 --skip-error 选项
    skip_error_mode = "--skip-error" in idc.ARGV or "-s" in idc.ARGV
    
    if action == "check":
        print(f"[REAI] Checking exception code from {hex(func_ea)}")
        exception_code_check(func_ea)
        
        if exception_code_collection:
            print(f"\n[REAI] Found {len(exception_code_collection)} functions with exception code:")
            for exc in exception_code_collection:
                print(f"  {exc['address']} ({exc['name']}): {', '.join(exc['issues'])}")
            print("\n[REAI] Recommendation: Fix these issues before running 'analyze'")
            print("[REAI] Or use 'analyze --skip-error' to skip problematic functions")
        else:
            print(f"[REAI] No exception code found. Total functions checked: {len(processed_func)}")
            print("[REAI] Ready for 'analyze'")
        
        exception_code_collection.clear()
        processed_func.clear()
    
    elif action == "topology":
        print(f"[REAI] Building call topology from {hex(func_ea)}")
        exception_code_check(func_ea)
        processed_func.clear()
        func = ida_funcs.get_func(func_ea)
        get_call_topology(func.start_ea, 0, 0, set(), 0)
        print_topology()
        function_info.clear()
        exception_code_collection.clear()
    
    elif action == "analyze":
        func_analyze(func_ea)
    
    else:
        print(f"[REAI] Unknown action: {action}")
        print("[REAI] Valid actions: check, analyze, topology")
    
    # 保存修改到 IDB
    idc.save_database(idc.get_idb_path())
    idc.qexit(0)


if __name__ == "__main__":
    main()