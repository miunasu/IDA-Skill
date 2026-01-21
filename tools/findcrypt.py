#!/usr/bin/env python3
"""
FindCrypt - 在 IDB 中搜索加密算法常量
基于 YARA 规则扫描，识别 AES/DES/RSA/MD5/SHA 等算法特征

用法（在 IDA 中执行）:
    idat -A -S"findcrypt.py [rules_path] [output_json]" target.idb

或作为 IDAPython 脚本直接运行
"""
import idaapi
import idautils
import ida_bytes
import idc
import json
import sys
import os

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# 内置基础加密常量规则（无需外部 rules 文件）
BUILTIN_RULES = '''
rule AES_SBox {
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}

rule AES_InvSBox {
    strings:
        $inv = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }
    condition:
        $inv
}

rule DES_SBox {
    strings:
        $s1 = { 0e 04 0d 01 02 0f 0b 08 03 0a 06 0c 05 09 00 07 }
    condition:
        $s1
}

rule MD5_Constants {
    strings:
        $init = { 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10 }
        $t1 = { 78 a4 6a d7 }
        $t2 = { 56 b7 c7 e8 }
    condition:
        $init or $t1 or $t2
}

rule SHA1_Constants {
    strings:
        $h0 = { 67 45 23 01 }
        $h1 = { ef cd ab 89 }
        $h2 = { 98 ba dc fe }
        $h3 = { 10 32 54 76 }
        $h4 = { c3 d2 e1 f0 }
    condition:
        3 of them
}

rule SHA256_Constants {
    strings:
        $k0 = { 98 2f 8a 42 }
        $k1 = { 91 44 37 71 }
        $h0 = { 6a 09 e6 67 }
    condition:
        any of them
}

rule RC4_SBox_Init {
    strings:
        $init = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
    condition:
        $init
}

rule RSA_Constants {
    strings:
        $pub_exp = { 01 00 01 }
    condition:
        $pub_exp
}

rule Base64_Table {
    strings:
        $std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    condition:
        any of them
}

rule CRC32_Table {
    strings:
        $crc = { 00 00 00 00 96 30 07 77 2c 61 0e ee ba 51 09 99 }
    condition:
        $crc
}

rule Blowfish_Constants {
    strings:
        $p = { 24 3f 6a 88 85 a3 08 d3 13 19 8a 2e 03 70 73 44 }
    condition:
        $p
}

rule TEA_Delta {
    strings:
        $delta = { 9e 37 79 b9 }
        $delta_le = { b9 79 37 9e }
    condition:
        any of them
}
'''


def get_memory():
    """获取所有段的内存数据"""
    result = bytearray()
    offsets = []
    start_len = 0
    
    for seg_ea in idautils.Segments():
        seg_end = idc.get_segm_attr(seg_ea, idc.SEGATTR_END)
        seg_data = ida_bytes.get_bytes(seg_ea, seg_end - seg_ea)
        if seg_data:
            result += seg_data
            offsets.append((seg_ea, start_len, len(result)))
            start_len = len(result)
    
    return bytes(result), offsets


def offset_to_va(offset, offsets):
    """将内存偏移转换为虚拟地址"""
    for seg_start, file_start, file_end in offsets:
        if file_start <= offset < file_end:
            return seg_start + (offset - file_start)
    return 0


def search_crypto(rules_path=None):
    """搜索加密常量"""
    if not HAS_YARA:
        print("[!] yara-python not installed, using pattern search")
        return search_patterns_fallback()
    
    # 加载规则
    if rules_path and os.path.exists(rules_path):
        rules = yara.compile(filepath=rules_path)
    else:
        rules = yara.compile(source=BUILTIN_RULES)
    
    memory, offsets = get_memory()
    matches = rules.match(data=memory)
    
    results = []
    for match in matches:
        for string in match.strings:
            for instance in string.instances:
                va = offset_to_va(instance.offset, offsets)
                results.append({
                    "address": hex(va),
                    "rule": match.rule,
                    "identifier": string.identifier,
                    "matched_data": instance.matched_data.hex().upper(),
                    "size": len(instance.matched_data)
                })
                # 在 IDA 中添加注释
                idc.set_cmt(va, f"[FindCrypt] {match.rule}", 0)
    
    return results


def search_patterns_fallback():
    """无 YARA 时的回退搜索"""
    patterns = {
        "AES_SBox": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]),
        "MD5_Init": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
        "SHA1_H0": bytes([0x67, 0x45, 0x23, 0x01]),
        "Base64": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "TEA_Delta": bytes([0x9e, 0x37, 0x79, 0xb9]),
    }
    
    results = []
    for seg_ea in idautils.Segments():
        seg_end = idc.get_segm_attr(seg_ea, idc.SEGATTR_END)
        seg_data = ida_bytes.get_bytes(seg_ea, seg_end - seg_ea)
        if not seg_data:
            continue
        
        for name, pattern in patterns.items():
            offset = 0
            while True:
                pos = seg_data.find(pattern, offset)
                if pos == -1:
                    break
                va = seg_ea + pos
                results.append({
                    "address": hex(va),
                    "rule": name,
                    "identifier": "$pattern",
                    "matched_data": pattern[:16].hex().upper(),
                    "size": len(pattern)
                })
                idc.set_cmt(va, f"[FindCrypt] {name}", 0)
                offset = pos + 1
    
    return results


def main():
    idaapi.auto_wait()
    
    # 解析参数
    rules_path = None
    output_path = None
    
    if len(idc.ARGV) > 1:
        rules_path = idc.ARGV[1]
    if len(idc.ARGV) > 2:
        output_path = idc.ARGV[2]
    
    print("[*] FindCrypt - Searching for crypto constants...")
    results = search_crypto(rules_path)
    
    print(f"[+] Found {len(results)} matches")
    for r in results:
        print(f"  {r['address']}: {r['rule']} ({r['identifier']})")
    
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[+] Results saved to {output_path}")
    
    # 保存修改到 IDB（注释已添加）
    idc.save_database(idc.get_idb_path())
    idc.qexit(0)


if __name__ == "__main__":
    main()