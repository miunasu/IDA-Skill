#!/usr/bin/env python3
"""
Dump - 从 IDB 中导出内存数据
支持多种输出格式：raw/hex/c_array/python

用法（在 IDA 中执行）:
    idat -A -S"dump.py <start_ea> <size> <output_file> [format]" target.idb
    
    format: raw / hex / c_array / python (默认 raw)

示例:
    idat -A -S"dump.py 0x401000 0x100 dump.bin" target.idb
    idat -A -S"dump.py 0x401000 0x100 dump.txt hex" target.idb
"""
import idaapi
import idc
import json
import sys
import os
from struct import unpack


def dump_bytes(addr, size):
    """从 IDB 读取字节数据"""
    return idc.get_bytes(addr, size)


def format_escaped(data):
    """转义字符串格式"""
    return '"' + ''.join('\\x%02X' % b for b in data) + '"'


def format_hex(data):
    """纯 hex 字符串"""
    return ''.join('%02X' % b for b in data)


def format_c_array(data, name="data"):
    """C 数组格式"""
    output = f"unsigned char {name}[{len(data)}] = {{"
    for i, b in enumerate(data):
        if i % 16 == 0:
            output += "\n    "
        output += "0x%02X, " % b
    output = output[:-2] + "\n};"
    return output


def format_c_array_dword(data, name="data"):
    """C 数组 DWORD 格式"""
    data = data + b'\x00' * (4 - len(data) % 4) if len(data) % 4 else data
    array_size = len(data) // 4
    output = f"unsigned int {name}[{array_size}] = {{"
    for i in range(0, len(data), 4):
        if i % 32 == 0:
            output += "\n    "
        val = unpack('<I', data[i:i+4])[0]
        output += "0x%08X, " % val
    output = output[:-2] + "\n};"
    return output


def format_python(data):
    """Python 列表格式"""
    return "[" + ", ".join("0x%02X" % b for b in data) + "]"


def dump_to_file(start_ea, size, output_file, fmt="raw"):
    """
    导出内存数据到文件
    
    Args:
        start_ea: 起始地址
        size: 大小
        output_file: 输出文件路径
        fmt: 格式 (raw/hex/c_array/c_array_dword/python/escaped)
    """
    data = dump_bytes(start_ea, size)
    if not data:
        print(f"[!] Failed to read {size} bytes from {hex(start_ea)}")
        return False
    
    print(f"[+] Dump {hex(start_ea)} - {hex(start_ea + size)} ({size} bytes)")
    
    if fmt == "raw":
        with open(output_file, 'wb') as f:
            f.write(data)
    else:
        if fmt == "hex":
            content = format_hex(data)
        elif fmt == "c_array":
            content = format_c_array(data)
        elif fmt == "c_array_dword":
            content = format_c_array_dword(data)
        elif fmt == "python":
            content = format_python(data)
        elif fmt == "escaped":
            content = format_escaped(data)
        else:
            content = format_hex(data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(content[:200] + "..." if len(content) > 200 else content)
    
    print(f"[+] Saved to {output_file}")
    return True


def dump_segment(seg_name, output_file, fmt="raw"):
    """导出整个段"""
    seg = idaapi.get_segm_by_name(seg_name)
    if not seg:
        print(f"[!] Segment '{seg_name}' not found")
        return False
    return dump_to_file(seg.start_ea, seg.end_ea - seg.start_ea, output_file, fmt)


def dump_function(func_ea, output_file, fmt="raw"):
    """导出函数代码"""
    func = idaapi.get_func(func_ea)
    if not func:
        print(f"[!] Function at {hex(func_ea)} not found")
        return False
    return dump_to_file(func.start_ea, func.end_ea - func.start_ea, output_file, fmt)


def main():
    idaapi.auto_wait()
    
    if len(idc.ARGV) < 4:
        print("Usage: dump.py <start_ea> <size> <output_file> [format]")
        print("       dump.py --seg <segment_name> <output_file> [format]")
        print("       dump.py --func <func_ea> <output_file> [format]")
        print("")
        print("Formats: raw, hex, c_array, c_array_dword, python, escaped")
        idc.qexit(1)
        return
    
    if idc.ARGV[1] == "--seg":
        seg_name = idc.ARGV[2]
        output_file = idc.ARGV[3]
        fmt = idc.ARGV[4] if len(idc.ARGV) > 4 else "raw"
        dump_segment(seg_name, output_file, fmt)
    elif idc.ARGV[1] == "--func":
        func_ea = int(idc.ARGV[2], 16) if idc.ARGV[2].startswith('0x') else int(idc.ARGV[2])
        output_file = idc.ARGV[3]
        fmt = idc.ARGV[4] if len(idc.ARGV) > 4 else "raw"
        dump_function(func_ea, output_file, fmt)
    else:
        start_ea = int(idc.ARGV[1], 16) if idc.ARGV[1].startswith('0x') else int(idc.ARGV[1])
        size = int(idc.ARGV[2], 16) if idc.ARGV[2].startswith('0x') else int(idc.ARGV[2])
        output_file = idc.ARGV[3]
        fmt = idc.ARGV[4] if len(idc.ARGV) > 4 else "raw"
        dump_to_file(start_ea, size, output_file, fmt)
    
    idc.qexit(0)


if __name__ == "__main__":
    main()