#!/usr/bin/env python3
"""
Export Function Check - 检查并列出所有导出函数信息

用法:
    idat -A -S"export_check.py [output.json]" target.idb
"""
import idaapi
import ida_entry
import ida_funcs
import idc
import json


def get_export_functions():
    """获取所有导出函数信息"""
    exports = []
    export_count = ida_entry.get_entry_qty()

    for i in range(export_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        
        if ea != idaapi.BADADDR:
            func = ida_funcs.get_func(ea)
            if func:
                func_size = func.end_ea - func.start_ea
            else:
                func_size = -1
            
            exports.append({
                "ordinal": ordinal if ordinal != ea else None,
                "address": hex(ea),
                "name": name,
                "size": func_size
            })

    return exports


def main():
    idaapi.auto_wait()
    
    output_file = idc.ARGV[1] if len(idc.ARGV) > 1 else None
    
    exports = get_export_functions()
    
    print(f"[ExportCheck] Found {len(exports)} export functions:")
    for exp in exports:
        ordinal_str = f"Ordinal: {exp['ordinal']}" if exp['ordinal'] else "Ordinal: N/A"
        print(f"  {ordinal_str}, Address: {exp['address']}, Name: {exp['name']}, Size: {exp['size']} bytes")
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(exports, f, indent=2, ensure_ascii=False)
        print(f"[ExportCheck] Results saved to {output_file}")
    
    idc.qexit(0)


if __name__ == "__main__":
    main()