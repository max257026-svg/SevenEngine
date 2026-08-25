# -*- coding: utf-8 -*-
"""清理系统文件误报v3：用Scanner加载全部records(多JSON块)，标clean"""
import os, sys, re, json, hashlib, time, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE

LOG = r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log"
STUDY = r"D:\Administrator\Desktop\SevenEngineCloud\engines\study-engine.txt"

# 误报文件(原始路径)
missed = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        if '[!]' in line:
            m = re.search(r'(C:[/\\].+?)\s*$', line.strip())
            if m:
                missed.append(m.group(1).strip())
print("误报文件数: %d" % len(missed))

shutil.copy(STUDY, STUDY + ".bak_clean3")

# 用 Scanner 加载全部 records（解析多 JSON 块）
scanner = SE.Scanner()
records = scanner.study.records
sha_to_md5 = dict(scanner.study.hash_index)
print("Scanner records: %d, hash_index: %d" % (len(records), len(sha_to_md5)))

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest().lower()

# 方法1：误报文件算sha标clean
cleaned1 = 0
for fp in missed:
    if not os.path.exists(fp):
        continue
    try: sha = sha256_of(fp)
    except: continue
    if sha in sha_to_md5:
        md5k = sha_to_md5[sha]
        rec = records[md5k]
        if rec.get('type') == 'malicious':
            rec['type'] = 'clean'
            rec['sysfile'] = True
            rec['filepath'] = fp
            cleaned1 += 1

# 方法2：遍历records，filepath含系统路径的type改clean
cleaned2 = 0
for md5, rec in records.items():
    fp = rec.get('filepath', '')
    if ('Program Files' in fp or 'C:\\Windows' in fp or 'C:/Windows' in fp
            or 'Common Files' in fp or 'Microsoft Shared' in fp):
        if rec.get('type') == 'malicious':
            rec['type'] = 'clean'
            rec['sysfile'] = True
            cleaned2 += 1

print("方法1(误报文件sha): malicious->clean: %d" % cleaned1)
print("方法2(records系统路径): malicious->clean: %d" % cleaned2)

# 读原文提取 path_section 和 lore_section
with open(STUDY, 'r', encoding='utf-8') as f:
    content = f.read()
brace_idx = content.find('{')
path_section = content[:brace_idx]
# lore_section: 最后一个顶层 } 之后
last_brace = content.rfind('}')
lore_section = content[last_brace+1:]

data = {"version": "1.0", "metadata": {"name": "PASW Study Engine Records",
        "total_records": len(records), "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "engine": "PeAV StudyEngine"}, "records": records}
with open(STUDY, 'w', encoding='utf-8') as f:
    f.write(path_section)
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write(lore_section)
print("已写回(合并单JSON块), records: %d" % len(records))
