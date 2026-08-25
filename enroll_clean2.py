# -*- coding: utf-8 -*-
"""清理系统文件误报v2：可靠提取误报文件路径，把hash在study-engine标clean"""
import os, sys, re, json, hashlib, time, shutil
sys.stdout.reconfigure(encoding='utf-8')

LOG = r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log"
STUDY = r"D:\Administrator\Desktop\SevenEngineCloud\engines\study-engine.txt"

# 可靠提取所有误报文件([!]行，路径从C:开始到行尾)
missed = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        if '[!]' in line:
            m = re.search(r'(C:[/\\].+?)\s*$', line.strip())
            if m:
                missed.append(m.group(1).strip().replace('/', '\\'))
print("误报文件数: %d" % len(missed))

shutil.copy(STUDY, STUDY + ".bak_clean2")

with open(STUDY, 'r', encoding='utf-8') as f:
    content = f.read()
brace_idx = content.find('{')
path_section = content[:brace_idx]
remaining = content[brace_idx:]
brace_depth = 0; in_string = False; escape = False; json_end = -1
for i, c in enumerate(remaining):
    if escape: escape = False; continue
    if c == '\\': escape = True; continue
    if c == '"': in_string = not in_string; continue
    if in_string: continue
    if c == '{': brace_depth += 1
    elif c == '}':
        brace_depth -= 1
        if brace_depth == 0: json_end = i + 1; break
data = json.loads(remaining[:json_end])
lore_section = remaining[json_end:]
records = data['records']

sha_to_md5 = {}
for md5, rec in records.items():
    for feat in rec.get('features', []):
        if feat.startswith('Hash{') and feat.endswith('}'):
            sha_to_md5[feat[5:-1].lower()] = md5

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest().lower()

cleaned = 0; already = 0; notin = 0; readfail = 0
for fp in missed:
    if not os.path.exists(fp):
        notin += 1; continue
    try: sha = sha256_of(fp)
    except: readfail += 1; continue
    if sha in sha_to_md5:
        md5k = sha_to_md5[sha]
        rec = records[md5k]
        if rec.get('type') == 'malicious':
            rec['type'] = 'clean'
            rec['sysfile'] = True
            rec['filepath'] = fp
            cleaned += 1
        else:
            already += 1
    else:
        notin += 1

print("SE-Precise清理: malicious->clean: %d, 已clean: %d, 不在index: %d, 读失败: %d" % (cleaned, already, notin, readfail))

data['records'] = records
data['metadata']['total_records'] = len(records)
data['metadata']['last_updated'] = time.strftime("%Y-%m-%dT%H:%M:%S")
with open(STUDY, 'w', encoding='utf-8') as f:
    f.write(path_section)
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write(lore_section)
print("study-engine.txt 已写回, records: %d" % len(records))
