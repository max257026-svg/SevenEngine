# -*- coding: utf-8 -*-
"""清理系统文件误报：1)系统文件hash标clean(消SE-Precise误报) 2)统计PE-Suspicious误报签名情况"""
import os, sys, re, json, hashlib, time, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, r"D:\Administrator\Desktop\SevenEngineCloud")
import SevenEngine as SE

LOG = r"D:\Administrator\Desktop\SevenEngineCloud\sysmiss_x86.log"
STUDY = r"D:\Administrator\Desktop\SevenEngineCloud\engines\study-engine.txt"

# 读系统目录所有文件(CLEAN+MALICIOUS)
sys_files = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        m = re.search(r'(?:CLEAN|MALICIOUS.*)\s+(C:.+?)\s*$', line.strip())
        if m:
            sys_files.append(m.group(1).strip())
print("系统文件总数: %d" % len(sys_files))

# 备份 study-engine
shutil.copy(STUDY, STUDY + ".bak_clean")

# 读 study-engine
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

# 建 sha->md5 映射
sha_to_md5 = {}
for md5, rec in records.items():
    for feat in rec.get('features', []):
        if feat.startswith('Hash{') and feat.endswith('}'):
            sha_to_md5[feat[5:-1].lower()] = md5

# 把系统文件 hash 标 clean（消除 SE-Precise 误报）
def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest().lower()

cleaned = 0
already_clean = 0
not_in_index = 0
for fp in sys_files:
    if not os.path.exists(fp): continue
    try: sha = sha256_of(fp)
    except: continue
    if sha in sha_to_md5:
        md5k = sha_to_md5[sha]
        rec = records[md5k]
        if rec.get('type') == 'malicious':
            rec['type'] = 'clean'
            rec['sysfile'] = True
            rec['filepath'] = fp
            cleaned += 1
        else:
            already_clean += 1
    else:
        not_in_index += 1

print("SE-Precise误报清理: malicious->clean: %d, 已clean: %d, 不在index: %d" % (cleaned, already_clean, not_in_index))

# 写回
data['records'] = records
data['metadata']['total_records'] = len(records)
data['metadata']['last_updated'] = time.strftime("%Y-%m-%dT%H:%M:%S")
with open(STUDY, 'w', encoding='utf-8') as f:
    f.write(path_section)
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write(lore_section)
print("study-engine.txt 已写回")

# 统计 PE-Suspicious 误报的签名/版本/.NET 情况
print("\n=== PE-Suspicious 误报签名统计 ===")
scanner = SE.Scanner()
stats = {'has_sig': 0, 'no_sig': 0, 'has_vi': 0, 'no_vi': 0, 'dotnet': 0, 'sig_in_trusted': 0}
TRUSTED = {'microsoft','google','apple','dell','valve','steam','battleye','nvidia','amd','intel','realtek','adobe','oracle','vmware','tencent','baidu','huawei'}
sample_sigs = []
pe_susp_files = []
with open(LOG, 'r', encoding='utf-8') as f:
    for line in f:
        if 'PE-Suspicious' in line and '[!]' in line:
            m = re.search(r'(C:.+?)\s*$', line.strip())
            if m: pe_susp_files.append(m.group(1).strip())

for fp in pe_susp_files[:200]:  # 抽样200
    if not os.path.exists(fp): continue
    try:
        pe = SE._parse_pe_all(fp)
        signer = pe.get('signer')
        vi = pe.get('version_info', {})
        has_vi = any((vi.get(k) or '').strip() for k in ('CompanyName','ProductName','FileDescription'))
        clr = pe.get('has_clr', False)
        if signer: stats['has_sig'] += 1
        else: stats['no_sig'] += 1
        if has_vi: stats['has_vi'] += 1
        else: stats['no_vi'] += 1
        if clr: stats['dotnet'] += 1
        if signer:
            sl = signer.lower()
            if any(t in sl for t in TRUSTED): stats['sig_in_trusted'] += 1
            if len(sample_sigs) < 15:
                sample_sigs.append((os.path.basename(fp), signer[:40], has_vi, clr))
    except: pass

print("抽样 %d 个 PE-Suspicious 误报:" % min(200, len(pe_susp_files)))
print("  有签名: %d, 无签名: %d" % (stats['has_sig'], stats['no_sig']))
print("  有版本信息: %d, 无版本: %d" % (stats['has_vi'], stats['no_vi']))
print("  .NET: %d" % stats['dotnet'])
print("  签名在TRUSTED: %d" % stats['sig_in_trusted'])
print("\n签名样本:")
for name, sig, vi, clr in sample_sigs:
    print("  %s | sig=%s vi=%s clr=%s" % (name, sig, vi, clr))
