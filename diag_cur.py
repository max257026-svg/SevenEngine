# -*- coding: utf-8 -*-
import sys, os, re, hashlib
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE
s = SE.Scanner()
print("hash_index:", len(s.study.hash_index), "records:", len(s.study.records))

# 当前 SE-Precise 误报文件
cnt = 0
in_idx = 0
out_idx = 0
samples_in = []
with open(r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log", encoding='utf-8') as f:
    for line in f:
        if 'SE-Precise' in line and '[!]' in line:
            m = re.search(r'(C:[/\\].+?)\s*$', line.strip())
            if m:
                fp = m.group(1).strip()
                cnt += 1
                if not os.path.exists(fp):
                    continue
                h = hashlib.sha256()
                with open(fp, 'rb') as fh:
                    for c in iter(lambda: fh.read(65536), b''):
                        h.update(c)
                sha = h.hexdigest().lower()
                md5 = s.study.hash_index.get(sha)
                if md5:
                    in_idx += 1
                    rec = s.study.records.get(md5, {})
                    if len(samples_in) < 5:
                        samples_in.append((os.path.basename(fp), sha[:16], md5[:12], rec.get('type'), rec.get('filepath','')[:60]))
                else:
                    out_idx += 1

print("SE-Precise误报文件: %d" % cnt)
print("在hash_index: %d, 不在: %d" % (in_idx, out_idx))

# 直接调 scan_precise 看返回
print("\n=== 直接调 scan_precise ===")
cnt2 = 0
with open(r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log", encoding='utf-8') as f:
    for line in f:
        if 'SE-Precise' in line and '[!]' in line:
            m = re.search(r'(C:[/\\].+?)\s*$', line.strip())
            if m:
                fp = m.group(1).strip()
                cnt2 += 1
                if cnt2 > 3: break
                if os.path.exists(fp):
                    sp = s.study.scan_precise(fp)
                    sf = s.scan_file(fp)
                    print("%s: scan_precise=%s scan_file=%s" % (os.path.basename(fp), sp, sf[:1]))

# 检查 path_index
print("\n=== path_index 是否含系统路径 ===")
pi_cnt = 0
for fp_path, md5 in s.study.path_index.items():
    if 'Program Files' in fp_path or 'Windows' in fp_path:
        pi_cnt += 1
        if pi_cnt <= 3:
            rec = s.study.records.get(md5, {})
            print("  fp=%s md5=%s type=%s" % (fp_path[:70], md5[:12], rec.get('type')))
print("path_index含系统路径: %d, path_index总数: %d" % (pi_cnt, len(s.study.path_index)))
