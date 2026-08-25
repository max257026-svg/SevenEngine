# -*- coding: utf-8 -*-
"""
LightGBM .pda 落盘与误报/召回验证脚本。

验证项：
  1. EngineSET/lightgbm.pda 是文件且大小合理（非 0 字节、非目录）
  2. PDA header 可读，打印 threshold / num_clean / num_virus
  3. 白文件误报测试：系统关键 PE 的 LightGBM 恶意概率应 < 0.10（白裁决门）
  4. 病毒召回测试：随机取病毒样本，scan() 应命中 MALICIOUS
"""
import os
import sys
import glob

BASE = os.path.dirname(os.path.abspath(__file__))
PDA = os.path.join(BASE, "EngineSET", "lightgbm.pda")
VIRUS_DIR = r"D:\训练病毒"

# 白文件验证目标（系统关键 PE，之前被启发式误报的重灾区）
WHITE_TARGETS = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\msvcrt.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\ole32.dll",
    r"C:\Windows\System32\shell32.dll",
    r"C:\Windows\System32\combase.dll",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\mmc.exe",
    r"C:\Windows\System32\mspaint.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\RuntimeBroker.exe",
]


def main():
    print("=" * 64)
    print("  LightGBM .pda 落盘与误报/召回验证")
    print("=" * 64)

    # 1. .pda 文件检查
    print("\n[1] .pda 文件检查")
    if os.path.isdir(PDA):
        print(f"  FAIL: {PDA} 是目录（残留占位），需删除后重训")
        return 1
    if not os.path.exists(PDA):
        print(f"  FAIL: {PDA} 不存在，训练未落盘")
        return 1
    sz = os.path.getsize(PDA)
    print(f"  OK: {PDA} ({sz:,} bytes)")
    if sz < 10000:
        print(f"  WARN: 文件偏小 ({sz} bytes)，可能是玩具模型")

    # 2. 读 header
    print("\n[2] PDA header")
    try:
        from pda_store import pda_info
        hdr = pda_info(PDA)
        for k in ("threshold", "feature_size", "num_clean", "num_virus",
                  "best_tpr_at_fpr1pct", "lib_version", "created_at"):
            if k in hdr:
                print(f"  {k} = {hdr[k]}")
    except Exception as e:
        print(f"  FAIL: 无法读取 header: {e}")
        return 1

    # 3. 加载引擎
    print("\n[3] 加载 LightGBMScanner")
    try:
        from lightgbm_engine import LightGBMScanner
        scn = LightGBMScanner(PDA)
        if not scn.available:
            print("  FAIL: LightGBMScanner.available = False")
            return 1
        print(f"  OK: available=True, threshold={scn.threshold}, feature_size={scn.feature_size}")
    except Exception as e:
        print(f"  FAIL: 加载失败: {e}")
        return 1

    # 4. 白文件误报测试
    print("\n[4] 白文件误报测试（恶意概率 < 0.15 为通过）")
    white_ok = 0
    white_fail = 0
    for fp in WHITE_TARGETS:
        if not os.path.exists(fp):
            print(f"  SKIP (不存在): {fp}")
            continue
        p = scn.score(fp)
        status = "PASS" if 0 <= p < 0.15 else "FAIL"
        if 0 <= p < 0.10:
            white_ok += 1
        else:
            white_fail += 1
        print(f"  [{status}] p={p:.4f}  {os.path.basename(fp)}")
    print(f"  白文件: {white_ok} PASS / {white_fail} FAIL")

    # 5. 病毒召回测试
    print("\n[5] 病毒召回测试（scan 命中 MALICIOUS 为通过）")
    virus_files = []
    for root, dirs, files in os.walk(VIRUS_DIR):
        for fn in files:
            virus_files.append(os.path.join(root, fn))
        if len(virus_files) >= 30:
            break
    # 只取 PE（MZ 开头）
    pe_virus = []
    for fp in virus_files:
        try:
            with open(fp, "rb") as f:
                if f.read(2) == b"MZ":
                    pe_virus.append(fp)
        except Exception:
            pass
        if len(pe_virus) >= 20:
            break
    print(f"  取到 {len(pe_virus)} 个病毒 PE 样本")
    virus_hit = 0
    virus_miss = 0
    for fp in pe_virus[:15]:
        name, conf, reason = scn.scan(fp)
        if name:
            virus_hit += 1
            print(f"  [HIT ] {conf:3d}%  {os.path.basename(fp)[:40]}")
        else:
            p = scn.score(fp)
            virus_miss += 1
            print(f"  [MISS] p={p:.4f} {os.path.basename(fp)[:40]}")
    print(f"  病毒: {virus_hit} HIT / {virus_miss} MISS")

    # 6. 汇总
    print("\n" + "=" * 64)
    print(f"  汇总: 白文件 {white_ok}/{white_ok+white_fail} 通过, "
          f"病毒 {virus_hit}/{virus_hit+virus_miss} 召回")
    print("=" * 64)
    return 0 if white_fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
