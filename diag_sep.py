# -*- coding: utf-8 -*-
import sys, os, re, hashlib
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE
s = SE.Scanner()
print("hash_index size:", len(s.study.hash_index), "records:", len(s.study.records))

# 抽 SE-Precise 误报文件
cnt = 0
with open(r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log", encoding='utf-8') as f:
    for line in f:
        if 'SE-Precise' in line and '[!]' in line:
            m = re.search(r'(C:[/\\].+?)\s*$', line.strip())
            if m:
                fp = m.group(1).strip()
                cnt += 1
                if cnt > 3: break
                print("\n===", os.path.basename(fp), "===")
                print("path:", fp)
                print("exists:", os.path.exists(fp))
                if os.path.exists(fp):
                    h = hashlib.sha256()
                    with open(fp, 'rb') as fh:
                        for c in iter(lambda: fh.read(65536), b''):
                            h.update(c)
                    sha = h.hexdigest().lower()
                    print("sha256:", sha[:20])
                    print("in hash_index:", sha in s.study.hash_index)
                    print("hash_index.get:", s.study.hash_index.get(sha))
                    print("scan_precise:", s.study.scan_precise(fp))
                    print("scan_file:", s.scan_file(fp)[:1])

# 看 records 里有没有 filepath 含 Program Files 的
print("\n=== records 里 filepath 含 Program Files 的 ===")
pf_cnt = 0
for md5, rec in s.study.records.items():
    fp = rec.get('filepath', '')
    if 'Program Files' in fp or 'Windows' in fp:
        pf_cnt += 1
        if pf_cnt <= 5:
            print("  md5=%s type=%s fp=%s" % (md5[:12], rec.get('type'), fp[:80]))
print("含系统路径的 records:", pf_cnt)

# 看 hash_index 的 key 长度（确认是sha256 64位）
print("\n=== hash_index key 样本 ===")
for i, (k, v) in enumerate(s.study.hash_index.items()):
    if i < 3:
        print("  key=%s(%d字符) md5=%s" % (k[:20], len(k), v[:12]))
