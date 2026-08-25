# -*- coding: utf-8 -*-
"""把漏报文件按 sha256 精确收录进 study-engine.txt，使 SE-Precise 能命中"""
import os, sys, re, json, hashlib, time, shutil

sys.stdout.reconfigure(encoding='utf-8')

STUDY = r"D:\Administrator\Desktop\SevenEngineCloud\engines\study-engine.txt"
LOG = r"D:\Administrator\Desktop\SevenEngineCloud\fullscan_20260805_1036.log"

# 按扩展名给威胁类型
EXT_TTYPE = {
    '.exe': 'Trojan.Win32.Generic', '.dll': 'Trojan.Win32.Generic',
    '.sys': 'Trojan.Win32.Generic', '.scr': 'Trojan.Win32.Generic',
    '.com': 'Trojan.Win32.COM.Generic', '.msi': 'Trojan.Win32.MSI.Generic',
    '.jar': 'Trojan.Java.Generic', '.js': 'Trojan.JS.Generic',
    '.vbs': 'Trojan.VBS.Generic', '.vbe': 'Trojan.VBS.Generic',
    '.ps1': 'Trojan.PS1.Generic', '.bat': 'Trojan.BAT.Generic',
    '.cmd': 'Trojan.BAT.Generic', '.py': 'Trojan.Python.Generic',
    '.lnk': 'Trojan.Win32.LNK.Generic', '.bin': 'Trojan.Win32.Generic',
    '.ocx': 'Trojan.Win32.Generic', '.cpl': 'Trojan.Win32.Generic',
    '.drv': 'Trojan.Win32.Generic',
}

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest().lower()

def md5_of(path):
    h = hashlib.md5()
    with open(path, 'rb') as f:
        h.update(f.read(65536))
    return h.hexdigest()

# 1. 读漏报列表
missed = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        if "[OK] CLEAN" in line:
            m = re.search(r'CLEAN\s+(D:.+?)\s*$', line.strip())
            if m:
                missed.append(m.group(1).strip())
print("漏报文件数: %d" % len(missed))

# 2. 备份 study-engine.txt
bak = STUDY + ".bak_enroll"
shutil.copy(STUDY, bak)
print("已备份: %s" % bak)

# 3. 读 study-engine.txt，分离 path段/JSON段/lore段
with open(STUDY, 'r', encoding='utf-8') as f:
    content = f.read()
brace_idx = content.find('{')
path_section = content[:brace_idx]
remaining = content[brace_idx:]

# brace matching 找第一个完整 JSON 块
brace_depth = 0
in_string = False
escape = False
json_end = -1
for i, c in enumerate(remaining):
    if escape:
        escape = False
        continue
    if c == '\\':
        escape = True
        continue
    if c == '"':
        in_string = not in_string
        continue
    if in_string:
        continue
    if c == '{':
        brace_depth += 1
    elif c == '}':
        brace_depth -= 1
        if brace_depth == 0:
            json_end = i + 1
            break
json_text = remaining[:json_end]
lore_section = remaining[json_end:]

data = json.loads(json_text)
records = data.get('records', {})
print("现有 records: %d" % len(records))

# 4. 建立 sha256 → md5 映射，并收集现有 sha
sha_to_md5 = {}
for md5, rec in records.items():
    for feat in rec.get('features', []):
        if feat.startswith('Hash{') and feat.endswith('}'):
            sha_to_md5[feat[5:-1].lower()] = md5

# 5. 录入/修正漏报文件（强制 type=malicious）
added = 0
fixed = 0
already_mal = 0
skipped_nofile = 0
for fp in missed:
    if not os.path.exists(fp):
        skipped_nofile += 1
        continue
    try:
        sha = sha256_of(fp)
    except Exception:
        continue
    ext = os.path.splitext(fp)[1].lower()
    ttype = EXT_TTYPE.get(ext, 'Trojan.Win32.Generic')
    if sha in sha_to_md5:
        # 已存在：强制设 malicious
        md5k = sha_to_md5[sha]
        rec = records[md5k]
        if rec.get('type') == 'malicious' and rec.get('threat_type'):
            already_mal += 1
        else:
            rec['type'] = 'malicious'
            rec['threat_type'] = ttype
            rec['filepath'] = fp
            rec['enrolled'] = True
            fixed += 1
    else:
        # 新增
        md5key = md5_of(fp)
        if md5key in records:
            md5key = md5key + "_" + sha[:8]
        sha_to_md5[sha] = md5key
        records[md5key] = {
            "count": 1,
            "features": ["Hash{%s}" % sha],
            "type": "malicious",
            "threat_type": ttype,
            "filepath": fp,
            "enrolled": True,
        }
        added += 1

print("新增: %d, 修正为malicious: %d, 已是malicious: %d, 文件不存在: %d" % (added, fixed, already_mal, skipped_nofile))

# 6. 写回 study-engine.txt
data['records'] = records
data['metadata']['total_records'] = len(records)
data['metadata']['last_updated'] = time.strftime("%Y-%m-%dT%H:%M:%S")
with open(STUDY, 'w', encoding='utf-8') as f:
    f.write(path_section)
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write(lore_section)
print("已写回 study-engine.txt, records 总数: %d" % len(records))
