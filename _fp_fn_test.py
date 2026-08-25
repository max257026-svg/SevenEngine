# -*- coding: utf-8 -*-
"""FP/FN end-to-end test for the freshly retrained LightGBM model.
- FN (recall): sample MZ PE viruses from D:\训练病毒  -> expect MALICIOUS
- FP (false positive): sample MZ PEs from Program Files  -> expect CLEAN
IDLE priority, bounded sample sizes so it finishes in a few minutes.
"""
import os, sys, ctypes, random, time
try:
    ctypes.windll.kernel32.SetPriorityClass(
        ctypes.windll.kernel32.GetCurrentProcess(), 0x40)
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SevenEngine as SE

def collect_mz(root, cap):
    out = []
    for dp, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(dp, f)
            try:
                with open(p, "rb") as fh:
                    if fh.read(2) == b"MZ":
                        out.append(p)
                        if len(out) >= cap:
                            return out
            except Exception:
                continue
    return out

print("loading engine...")
s = SE.Scanner()

# ---- FN: virus PEs (recall) ----
virus = collect_mz(r"D:\训练病毒", 60)
print(f"\n=== FN/RECALL: {len(virus)} virus PEs (expect MALICIOUS) ===")
t0 = time.time(); det = miss = 0; missed = []
for p in virus:
    try:
        res, conf, t = s.scan_file(p)
    except Exception as e:
        miss += 1; missed.append((p, f"ERR {e}")); continue
    if res.startswith("MALICIOUS"):
        det += 1
    else:
        miss += 1; missed.append((p, res))
print(f"  detected={det} missed={miss} recall={det/(det+miss)*100:.1f}%  ({time.time()-t0:.0f}s)")
for p, r in missed[:12]:
    print(f"    MISSED: {os.path.basename(p)} -> {r}")

# ---- FP: Program Files PEs (false positive) ----
pf = collect_mz(r"C:\Program Files", 60) + collect_mz(r"C:\Program Files (x86)", 20)
print(f"\n=== FP: {len(pf)} Program-Files PEs (expect CLEAN) ===")
t0 = time.time(); fp = clean = 0; flagged = []
for p in pf:
    try:
        res, conf, t = s.scan_file(p)
    except Exception as e:
        clean += 1; continue
    if res.startswith("MALICIOUS"):
        fp += 1; flagged.append((p, res))
    else:
        clean += 1
print(f"  clean={clean} FP={fp} FPR={fp/(clean+fp)*100:.2f}%  ({time.time()-t0:.0f}s)")
for p, r in flagged[:12]:
    print(f"    FP: {os.path.basename(p)} -> {r}")

print("\n=== SUMMARY ===")
rec = det/(det+miss)*100 if (det+miss) else 0
fpr = fp/(clean+fp)*100 if (clean+fp) else 0
print(f"  recall(virus) = {rec:.1f}%   FPR(progfiles) = {fpr:.2f}%")
print("  PASS" if (rec >= 90 and fpr < 5) else "  NEEDS TUNING")
