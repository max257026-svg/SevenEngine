#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""诊断漏报文件：抽样检查 exe/vbs/js/msi 为何被判 CLEAN"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SevenEngine as SE

# 从日志提取漏报文件路径
import re
missed = []
with open("fullscan_20260805_0932.log", "r", encoding="utf-8") as f:
    for line in f:
        if "[OK] CLEAN" in line:
            m = re.search(r'CLEAN\s+(D:.+?)\s*$', line.strip())
            if m:
                missed.append(m.group(1).strip())

print(f"漏报总数: {len(missed)}")

# 按扩展名分组抽样
from collections import defaultdict
by_ext = defaultdict(list)
for fp in missed:
    ext = os.path.splitext(fp)[1].lower()
    by_ext[ext].append(fp)

scanner = SE.Scanner()

# 每类抽样5个诊断
for ext in ['.exe', '.vbs', '.js', '.msi', '.com', '.ps1']:
    samples = by_ext.get(ext, [])[:5]
    if not samples:
        continue
    print(f"\n{'='*70}")
    print(f"=== {ext} 漏报抽样 ({len(by_ext.get(ext,[]))}个) ===")
    print(f"{'='*70}")
    for fp in samples:
        if not os.path.exists(fp):
            print(f"\n[不存在] {fp}")
            continue
        print(f"\n[文件] {os.path.basename(fp)}")
        print(f"  路径: {fp}")
        print(f"  大小: {os.path.getsize(fp)} 字节")
        try:
            with open(fp, 'rb') as f:
                head = f.read()
        except:
            head = b""
        print(f"  头4字节: {head[:4].hex()} ({head[:4]!r})")
        if ext == '.exe' and head[:2] == b'MZ':
            pe = SE._parse_pe_all(fp)
            print(f"  签名商: {pe.get('signer','(无)')}")
            vi = pe.get('version_info', {})
            print(f"  公司名: {vi.get('CompanyName','(无)')}")
            print(f"  产品名: {vi.get('ProductName','(无)')}")
            print(f"  描述: {vi.get('FileDescription','(无)')}")
            print(f"  API数量: {len(pe.get('apis',[]))}")
            print(f"  import_count: {pe.get('import_count',0)}")
            print(f"  import_dlls: {pe.get('import_dlls',[])}")
            print(f"  ordinal_imports: {pe.get('ordinal_imports',0)}")
            print(f"  has_clr(.NET): {pe.get('has_clr',False)}")
            print(f"  sections数量: {len(pe.get('sections',[]))}")
            print(f"  ep_section: {pe.get('ep_section','')}")
            print(f"  overlay_size: {pe.get('overlay_size',0)}")
            print(f"  rwx_sections: {pe.get('rwx_sections',[])}")
            secs = pe.get('sections', [])
            if secs:
                high_e = [f"{s[0]}:{s[1]:.1f}" for s in secs if s[1] > 7.0]
                print(f"  高熵节: {high_e[:5] if high_e else '无'}")
                print(f"  节列表: {[s[0] for s in secs][:10]}")
            # 检查是否被签名信任跳过
            signer = pe.get('signer','')
            if signer:
                sl = signer.lower()
                TRUSTED = {'microsoft','google','apple','tencent','baidu','qihoo','kingsoft','huawei'}
                hit = [t for t in TRUSTED if t in sl]
                if hit:
                    print(f"  >>> 被签名信任跳过! 命中: {hit}")
            # study scan_precise
            se_t, se_c, se_f = scanner.study.scan_precise(fp)
            print(f"  SE-Precise: type={se_t} conf={se_c}")
            # study api chain
            apis = pe.get('apis',[])
            if apis:
                ac_t, ac_c, ac_f = scanner.study.scan_api_chains(apis)
                print(f"  SE-Chain: type={ac_t} conf={ac_c}")
        elif ext in ('.vbs','.js','.ps1','.bat'):
            try:
                txt = head.decode('utf-8', errors='ignore').lower()
                sus_kw = ['createobject','wscript.shell','powershell','cmd.exe','regwrite',
                          'filesystemobject','shell.application','downloadfile','http','base64',
                          'fromcharcode','eval(','execlnb','run(']
                hits = [k for k in sus_kw if k in txt]
                print(f"  可疑关键字: {hits[:8] if hits else '无'}")
                print(f"  脚本前80字符: {txt[:80]!r}")
            except:
                pass
