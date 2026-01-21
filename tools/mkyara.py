#!/usr/bin/env python3
"""
mkYARA - 从 IDA 中选定的代码/数据生成 YARA 规则
支持生成 loose/normal/strict 三种模式的规则

用法（在 IDA 中执行）:
    idat -A -S"mkyara.py <start_ea> <end_ea> [mode] [output_file]" target.idb
    
    mode: loose / normal / strict (默认 normal)

或在 IDAPython 控制台:
    exec(open("mkyara.py").read())
    generate_yara(0x401000, 0x401100, "normal", "rule.yar")
"""
import idaapi
import idautils
import idc
import json
import sys
import os

try:
    from mkyara import YaraGenerator
    from capstone import CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64
    HAS_MKYARA = True
except ImportError:
    HAS_MKYARA = False


def get_arch_info():
    """获取当前 IDB 的架构信息（IDA 9.1+）"""
    # IDA 9.1 使用新的 API
    proc = idaapi.inf_get_procname().lower()
    
    # 获取位数 - 使用 inf_get_app_bitness()
    app_bitness = idaapi.inf_get_app_bitness()
    if app_bitness == 8:  # 64-bit
        bits = 64
    elif app_bitness == 4:  # 32-bit
        bits = 32
    else:
        bits = 16
    
    if HAS_MKYARA and proc == 'metapc':
        arch = CS_ARCH_X86
        if bits == 16:
            mode = CS_MODE_16
        elif bits == 32:
            mode = CS_MODE_32
        else:
            mode = CS_MODE_64
        return arch, mode
    
    return None, bits


def get_file_hash():
    """获取输入文件的 MD5"""
    return idautils.GetInputFileMD5().hex() if hasattr(idautils.GetInputFileMD5(), 'hex') else idautils.GetInputFileMD5()


def bytes_to_yara_hex(data):
    """将字节转换为 YARA hex 字符串"""
    return ' '.join(f'{b:02X}' for b in data)


def generate_yara_simple(start_ea, end_ea, rule_name="auto_rule"):
    """简单模式：直接使用原始字节生成规则（无需外部库）"""
    size = end_ea - start_ea
    data = idaapi.get_bytes(start_ea, size)
    
    if not data:
        return None
    
    hex_str = bytes_to_yara_hex(data)
    file_hash = get_file_hash()
    
    rule = f'''rule {rule_name}
{{
    meta:
        description = "Auto-generated rule from {hex(start_ea)} to {hex(end_ea)}"
        hash = "{file_hash}"
        
    strings:
        $code = {{ {hex_str} }}
        
    condition:
        $code
}}
'''
    return rule


def generate_yara_with_wildcards(start_ea, end_ea, rule_name="auto_rule"):
    """
    带通配符模式：将立即数和地址替换为通配符
    适用于代码段，提高规则通用性
    """
    size = end_ea - start_ea
    data = list(idaapi.get_bytes(start_ea, size))
    
    if not data:
        return None
    
    # 遍历指令，标记需要通配的位置
    wildcards = set()
    ea = start_ea
    while ea < end_ea:
        insn = idaapi.insn_t()
        insn_len = idaapi.decode_insn(insn, ea)
        if insn_len == 0:
            ea += 1
            continue
        
        # 检查操作数，标记立即数和地址偏移
        for op in insn.ops:
            if op.type == idaapi.o_void:
                break
            # 立即数、内存引用、近跳转偏移
            if op.type in (idaapi.o_imm, idaapi.o_mem, idaapi.o_near, idaapi.o_far):
                # 标记操作数字节为通配符
                op_offset = op.offb
                if op_offset > 0:
                    for i in range(op_offset, insn_len):
                        byte_pos = (ea - start_ea) + i
                        if byte_pos < len(data):
                            wildcards.add(byte_pos)
        
        ea += insn_len
    
    # 生成 hex 字符串
    hex_parts = []
    for i, b in enumerate(data):
        if i in wildcards:
            hex_parts.append('??')
        else:
            hex_parts.append(f'{b:02X}')
    
    hex_str = ' '.join(hex_parts)
    file_hash = get_file_hash()
    
    rule = f'''rule {rule_name}
{{
    meta:
        description = "Auto-generated rule with wildcards from {hex(start_ea)} to {hex(end_ea)}"
        hash = "{file_hash}"
        
    strings:
        $code = {{ {hex_str} }}
        
    condition:
        $code
}}
'''
    return rule


def generate_yara(start_ea, end_ea, mode="normal", output_file=None, rule_name=None):
    """
    生成 YARA 规则
    
    Args:
        start_ea: 起始地址
        end_ea: 结束地址
        mode: loose/normal/strict
        output_file: 输出文件路径（可选）
        rule_name: 规则名称（可选）
    """
    if rule_name is None:
        rule_name = f"rule_{hex(start_ea)[2:]}_{hex(end_ea)[2:]}"
    
    # 尝试使用 mkyara 库
    if HAS_MKYARA:
        arch, arch_mode = get_arch_info()
        if arch is not None:
            size = end_ea - start_ea
            data = idaapi.get_bytes(start_ea, size)
            
            gen = YaraGenerator(mode, arch, arch_mode)
            gen.add_chunk(data, offset=start_ea)
            rule_obj = gen.generate_rule()
            rule_obj.metas["hash"] = f'"{get_file_hash()}"'
            rule = rule_obj.get_rule_string()
        else:
            rule = generate_yara_with_wildcards(start_ea, end_ea, rule_name)
    else:
        # 回退到简单实现
        if mode == "strict":
            rule = generate_yara_simple(start_ea, end_ea, rule_name)
        else:
            rule = generate_yara_with_wildcards(start_ea, end_ea, rule_name)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(rule)
        print(f"[+] Rule saved to {output_file}")
    
    return rule


def main():
    idaapi.auto_wait()
    
    # 解析参数: start_ea end_ea [mode] [output_file]
    if len(idc.ARGV) < 3:
        print("Usage: mkyara.py <start_ea> <end_ea> [mode] [output_file]")
        print("  mode: loose / normal / strict (default: normal)")
        idc.qexit(1)
        return
    
    start_ea = int(idc.ARGV[1], 16) if idc.ARGV[1].startswith('0x') else int(idc.ARGV[1])
    end_ea = int(idc.ARGV[2], 16) if idc.ARGV[2].startswith('0x') else int(idc.ARGV[2])
    mode = idc.ARGV[3] if len(idc.ARGV) > 3 else "normal"
    output_file = idc.ARGV[4] if len(idc.ARGV) > 4 else None
    
    print(f"[*] Generating YARA rule from {hex(start_ea)} to {hex(end_ea)} (mode: {mode})")
    
    rule = generate_yara(start_ea, end_ea, mode, output_file)
    
    if rule:
        print("[+] Generated rule:")
        print(rule)
    else:
        print("[!] Failed to generate rule")
    
    idc.qexit(0)


if __name__ == "__main__":
    main()