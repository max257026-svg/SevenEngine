# -*- coding: utf-8 -*-
"""清理矛盾数据：type=malicious 但 threat_type=CLEAN 的 record，type 改 clean"""
import sys, os, json, time, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE

STUDY = r"D:\Administrator\Desktop\SevenEngineCloud\engines\study-engine.txt"
shutil.copy(STUDY, STUDY + ".bak_threat")

s = SE.Scanner()
records = s.study.records
fixed = 0
for md5, rec in records.items():
    if rec.get('type') == 'malicious' and rec.get('threat_type', '') in ('CLEAN', 'Clean', 'clean', ''):
        rec['type'] = 'clean'
        rec['sysfile'] = True
        fixed += 1
print("矛盾数据清理(threat=CLEAN/空): %d" % fixed)

# 写回（合并单JSON块）
with open(STUDY, 'r', encoding='utf-8') as f:
    content = f.read()
brace_idx = content.find('{')
path_section = content[:brace_idx]
last_brace = content.rfind('}')
lore_section = content[last_brace+1:]
data = {"version": "1.0", "metadata": {"name": "PASW Study Engine Records",
        "total_records": len(records), "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "engine": "PeAV StudyEngine"}, "records": records}
with open(STUDY, 'w', encoding='utf-8') as f:
    f.write(path_section)
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write(lore_section)
print("已写回, records: %d" % len(records))
