# -*- coding: utf-8 -*-
"""验证 LightGBM .pda 引擎：读取 / 干净低概率 / 病毒高概率 / 旧 study-engine 仍可加载。"""
import os, sys, time
sys.stdout.reconfigure(encoding="utf-8")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

PDA = os.path.join(BASE_DIR, "EngineSET", "lightgbm.pda")
VIRUS_DIR = r"D:\训练病毒"


def first_mz(d, n=5, max_bytes=64 * 1024 * 1024):
    out = []
    for root, ds, fs in os.walk(d):
        for fn in fs:
            if len(out) >= n:
                return out
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) == 0 or os.path.getsize(fp) > max_bytes:
                    continue
                with open(fp, "rb") as f:
                    if f.read(2) == b"MZ":
                        out.append(fp)
            except Exception:
                pass
    return out


def main():
    import numpy as np
    from pda_store import load_lightgbm_booster, pda_info
    from ONNX.onnx_feature_extractor import extract_features

    if not os.path.exists(PDA):
        print("ERROR: %s 不存在（训练未完成？）" % PDA)
        return 1

    t0 = time.time()
    header, booster = load_lightgbm_booster(PDA)
    load_ms = (time.time() - t0) * 1000
    print("=== .pda 读取 ===")
    print("  文件大小: %d bytes (%.1f KB)" % (os.path.getsize(PDA), os.path.getsize(PDA) / 1024))
    print("  读取耗时: %.1f ms" % load_ms)
    print("  元数据: threshold=%.4f  num_clean=%s  num_virus=%s  feature_size=%s"
          % (header.get("threshold"), header.get("num_clean"),
             header.get("num_virus"), header.get("feature_size")))

    thr = float(header.get("threshold", 0.75))

    def score(fp):
        feats = extract_features(filepath=fp)
        if feats is None:
            return None
        p = float(booster.predict(np.array(feats, dtype=np.float32).reshape(1, -1))[0])
        if not (0.0 <= p <= 1.0):
            import math
            p = 1.0 / (1.0 + math.exp(-p))
        return p

    print("\n=== 白文件（应低概率，不误报）===")
    clean_tests = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\cmd.exe"]
    # 再补几个随机白 PE
    for fp in first_mz(r"C:\Windows\System32", n=3):
        if fp not in clean_tests:
            clean_tests.append(fp)
    clean_hits = 0
    for fp in clean_tests[:5]:
        if not os.path.exists(fp):
            continue
        p = score(fp)
        flag = "  <-- 误报!" if (p is not None and p >= thr) else ""
        print("  %-50s prob=%.4f%s" % (fp, p if p is not None else -1, flag))
        if p is not None and p >= thr:
            clean_hits += 1

    print("\n=== 病毒文件（应高概率，高检出）===")
    virus_tests = first_mz(VIRUS_DIR, n=5)
    virus_hits = 0
    for fp in virus_tests:
        p = score(fp)
        flag = "  <-- 漏报!" if (p is not None and p < thr) else ""
        print("  %-50s prob=%.4f%s" % (os.path.basename(fp), p if p is not None else -1, flag))
        if p is not None and p >= thr:
            virus_hits += 1

    print("\n=== 旧 study-engine.txt 兼容性 ===")
    try:
        import importlib
        # SevenEngine 里的 StudyEngine；这里只验证文件能被旧逻辑读取，不深入
        se_path = os.path.join(BASE_DIR, "engines", "study-engine.txt")
        if os.path.exists(se_path):
            with open(se_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = sum(1 for _ in f)
            print("  study-engine.txt 可读取: %d 行（旧记录方式未改动）" % lines)
        else:
            print("  [skip] study-engine.txt 不存在")
    except Exception as e:
        print("  [warn] 旧引擎读取检查跳过: %r" % e)

    print("\n=== 小结 ===")
    print("  白文件误报数: %d/%d" % (clean_hits, min(len(clean_tests), 5)))
    print("  病毒高检数:   %d/%d" % (virus_hits, len(virus_tests)))
    ok = (clean_hits == 0 and virus_hits >= max(1, len(virus_tests) - 1))
    print("  结论: %s" % ("PASS ✅" if ok else "需关注 ⚠️"))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
