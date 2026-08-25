# -*- coding: utf-8 -*-
import sys, os, hashlib
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE
s = SE.Scanner()
print("records:", len(s.study.records), "hash_index:", len(s.study.hash_index))

# 查 md5=b4e9560d
for key in s.study.records:
    if key.startswith('b4e9560d'):
        rec = s.study.records[key]
        print("md5=%s" % key)
        print("  type=%s threat=%s" % (rec.get('type'), rec.get('threat_type')))
        print("  filepath=%s" % rec.get('filepath'))
        print("  features=%s" % rec.get('features')[:3])

# 查 penusa 的 sha
fp = r"C:/Program Files (x86)/Common Files/Microsoft Shared/ink/penusa.dll"
h = hashlib.sha256()
with open(fp, 'rb') as f:
    for c in iter(lambda: f.read(65536), b''):
        h.update(c)
sha = h.hexdigest().lower()
print("\npenusa sha=%s" % sha)
print("in hash_index:", sha in s.study.hash_index)
md5 = s.study.hash_index.get(sha)
print("md5=%s" % md5)
if md5:
    rec = s.study.records.get(md5, {})
    print("record type=%s" % rec.get('type'))

# 统计 malicious records 数量
mal = sum(1 for r in s.study.records.values() if r.get('type') == 'malicious')
cln = sum(1 for r in s.study.records.values() if r.get('type') == 'clean')
print("\nmalicious records: %d, clean records: %d" % (mal, cln))
