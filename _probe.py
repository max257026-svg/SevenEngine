import os, sys, ctypes, random
try:
    ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x40)
except Exception:
    pass
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import SevenEngine as SE

s = SE.Scanner()
print("LGBM avail:", s.lgbm is not None and getattr(s.lgbm, "available", False),
      "thr=", getattr(s.lgbm, "threshold", None) if s.lgbm else None)
print("ONNX avail:", getattr(s.onnx, "available", False))

# 探针1: 随机抽 System32 下的真实 PE，看 LightGBM 误报面
roots = [r"C:\Windows\System32", r"C:\Windows\SysWOW64"]
cands = []
for r in roots:
    if not os.path.isdir(r):
        continue
    for dp, _, fs in os.walk(r):
        for f in fs:
            if f.lower().endswith(('.exe', '.dll', '.sys', '.drv')):
                cands.append(os.path.join(dp, f))
        if len(cands) >= 400:
            break
    if len(cands) >= 400:
        break
random.Random(1).shuffle(cands)
cands = cands[:50]
hi = lo = mid = 0
bad = []
for p in cands:
    try:
        sc = s.lgbm.score(p)
    except Exception:
        sc = -1.0
    if sc < 0:
        continue
    if sc >= 0.5:
        hi += 1
        bad.append((round(sc, 3), p))
    elif sc < 0.15:
        lo += 1
    else:
        mid += 1
print(f"\n[LightGBM 对 {len(cands)} 个真实系统PE]  >=0.5(会误报)={hi}  <0.15(正确干净)={lo}  0.15~0.5={mid}")
print("  误报(>=0.5)样例:")
for sc, p in sorted(bad, reverse=True)[:8]:
    print(f"    {sc}  {p}")

# 探针2: ONNX 是否真的能判定？拿一个病毒 PE 试
vroot = r"D:\训练病毒\Virus"
vpe = None
if os.path.isdir(vroot):
    for dp, _, fs in os.walk(vroot):
        for f in fs:
            fp = os.path.join(dp, f)
            try:
                if open(fp, 'rb').read(2) == b'MZ':
                    vpe = fp
                    break
            except Exception:
                pass
        if vpe:
            break
if vpe:
    nm, cf, _ = s.onnx.scan(vpe)
    print(f"\n[ONNX] 对病毒PE {os.path.basename(vpe)} -> scan={ (nm,cf) }  (None=未触发/废了)")
    lg_nm, lg_cf, _ = s.lgbm.scan(vpe)
    print(f"[LightGBM] 对同一病毒PE -> scan={ (lg_nm,lg_cf) }")
else:
    print("\n[ONNX] 未找到病毒PE样本")
print("\n[done]")
