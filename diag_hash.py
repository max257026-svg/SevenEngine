# -*- coding: utf-8 -*-
"""诊断：为什么 type=malicious 的 record 没被 scan_precise 命中"""
import os, sys, re, hashlib
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE

LOG = r"D:\Administrator\Desktop\SevenEngineCloud\fullscan_20260805_1023.log"
missed = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        if "[OK] CLEAN" in line:
            m = re.search(r'CLEAN\s+(D:.+?)\s*$', line.strip())
            if m:
                missed.append(m.group(1).strip())

scanner = SE.Scanner()
print("hash_index 大小: %d" % len(scanner.study.hash_index))
print("records 大小: %d" % len(scanner.study.records))

# 检查几个漏报文件
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest().lower()

print("\n=== 漏报文件 sha256 是否在 hash_index ===")
in_cnt = 0
out_cnt = 0
samples = []
for fp in missed:
    if not os.path.exists(fp):
        continue
    try:
        sha = sha256_of(fp)
    except:
        continue
    md5 = scanner.study.hash_index.get(sha)
    if md5:
        rec = scanner.study.records.get(md5, {})
        in_cnt += 1
        if len(samples) < 3:
            samples.append((fp, sha[:16], md5, rec.get('type'), rec.get('threat_type')))
    else:
        out_cnt += 1

print("在 hash_index 中: %d" % in_cnt)
print("不在 hash_index 中: %d" % out_cnt)
print("\n样本(在hash_index的):")
for fp, sha, md5, t, tt in samples:
    print("  %s" % os.path.basename(fp))
    print("    sha=%s md5=%s type=%s threat=%s" % (sha, md5, t, tt))
    # 调用 scan_precise
    r = scanner.study.scan_precise(fp)
    print("    scan_precise 返回: %s" % (r,))
    # 调用 scan_file
    r2 = scanner.scan_file(fp)
    print("    scan_file 返回: %s" % (r2,))
