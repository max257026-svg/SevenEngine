# -*- coding: utf-8 -*-
"""
train_lightgbm.py -- train the LightGBM engine for SevenEngine (PeAV / PASW).

Design goals (per project requirements):
  * Content-based collection: a file is treated as a PE candidate when its first
    two bytes are b'MZ'. This REMOVES the old extension/suffix filter so renamed
    or extension-less PE files are no longer missed (training AND the runtime
    scanner both use MZ detection).
  * More samples -> higher detection, lower false positives. The script is
    re-runnable; point it at more directories and retrain.
  * Trusted sources only: clean samples come from known-good system / vendor
    directories; malware from D:\\训练病毒. We do NOT ingest the legacy
    study-engine.txt records (those are "untrusted later-added data").
  * Fast, robust storage: the trained booster is written to a custom binary
    .pda file via pda_store (no slow text JSON like study-engine.txt).
  * Manual, non-freezing training: bounded sample caps + multiprocessing.

Outputs: EngineSET/lightgbm.pda  (loads in milliseconds at engine start)
"""
import os
import sys
import time
import json
import argparse
import multiprocessing as mp

sys.stdout.reconfigure(encoding="utf-8")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ---- directories -----------------------------------------------------------
VIRUS_DIR = r"D:\训练病毒"

# White / clean training roots (per spec)
WHITE_DIRS = [
    r"C:\DrvPath",
    r"C:\FloweyPet",
    r"C:\inetpub",
    r"C:\Intel",
    r"C:\PerfLogs",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    r"C:\Windows",
    r"C:\XboxGames",
]

# EngineDatabase.txt also lists white directories to train on.
ENGINE_DB_TXT = r"D:\Administrator\Desktop\EngineDatabase.txt"

# Skip these during the walk (safety + speed). We keep these minimal so we do
# NOT silently drop PE files -- only skip known-huge / irrelevant trees.
SKIP_DIRS = {
    "$Recycle.Bin", "System Volume Information", "WinSxS",
    "INetCache", "AppData\\Local\\Temp", "Temp", "__pycache__",
    "node_modules", ".git",
}

MAX_CLEAN = 200000      # 上限：足够多样性；收集量低于此值时不抽样，不跳过任何文件
MAX_VIRUS = 200000
MAX_FILE_BYTES = 64 * 1024 * 1024  # 单文件上限，避免超大 PE 让 worker 卡死
# 极端 CPU 友好：单进程 + IDLE 最低优先级，只在机器完全空闲时才会跑，
# CPU 占用≈单核 5% 以内，绝不烧机，用户可随时在任务管理器杀掉。
WORKERS = 1

FEATURE_SIZE = 512


def _lower_priority():
    """Drop this process to IDLE priority so training never competes with the
    user's foreground work — the OS only schedules it when nothing else wants
    a CPU. Windows: IDLE_PRIORITY_CLASS = 0x40. No third-party deps.
    """
    try:
        import ctypes
        _kernel32 = getattr(ctypes, "windll", None)
        if _kernel32 is not None:
            _kernel32.kernel32.SetPriorityClass(
                _kernel32.kernel32.GetCurrentProcess(), 0x40)
    except Exception:
        pass


def _extract_worker(fp):
    """Multiprocessing worker.

    Extension-AGNOSTIC (no suffix filter): a file is a PE candidate only when its
    first two bytes are b'MZ'. We open the file, read the 2-byte magic + size via
    fstat (single open, no extra syscall), and only run the heavy PE feature
    extractor on MZ files in range. Non-PE files (any extension, or none) are
    rejected quickly. Because this runs in the pool, the expensive PE parsing is
    parallelized across cores, and BOTH collection and extraction treat PEs of ANY
    extension (renamed / packed / extension-less) identically -- nothing is ever
    dropped by a suffix rule.
    """
    try:
        with open(fp, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return None
            try:
                sz = os.fstat(f.fileno()).st_size
            except Exception:
                return None
            if sz == 0 or sz > MAX_FILE_BYTES:
                return None
        from ONNX.onnx_feature_extractor import extract_features
        feats = extract_features(filepath=fp)
        if feats is None:
            return None
        return [float(x) for x in feats]
    except Exception:
        return None


def _collect_candidate_files(dirs, enum_cap, dir_cap, label_desc,
                             progress_every=25000):
    """Walk dirs, yield EVERY file path (NO extension filter, NO per-file stat).

    Enumeration is deliberately cheap: we only list paths via os.walk (no
    os.path.getsize per file, which is what made the old code hang for hours on
    C:\\Windows under antivirus interception). The MZ check + size filter happen
    LATER inside the parallel worker pool.

    Two bounds keep this fast and bounded even on huge trees:
      * dir_cap  -- stop descending a single root once it yields this many files
      * enum_cap -- stop the whole walk once this many candidates are gathered
    Progress is printed so liveness is always visible. PEs of ANY extension are
    never excluded here; the MZ decision is purely content-based downstream.
    """
    total = 0
    for d in dirs:
        if not os.path.isdir(d):
            print(f"  [skip] not a directory: {d}")
            continue
        print(f"  scanning {label_desc}: {d}")
        dir_count = 0
        for root, ds, fs in os.walk(d):
            ds[:] = [x for x in ds if x not in SKIP_DIRS
                     and not x.lower().endswith(".tmp")]
            for fn in fs:
                yield os.path.join(root, fn)
                total += 1
                dir_count += 1
                if dir_count >= dir_cap:
                    ds[:] = []          # stop descending this branch
                    break
                if total >= enum_cap:
                    return
            if not ds:
                pass
        print(f"    -> {dir_count} candidates from {d}")
    print(f"  enumerated {total} candidate files from {label_desc}")


def parse_engine_db_txt(path):
    out = []
    if not os.path.exists(path):
        print(f"  [skip] EngineDatabase.txt not found: {path}")
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().strip('"').strip("'")
            if not line or line.startswith("#"):
                continue
            if os.path.isdir(line):
                out.append(line)
            else:
                print(f"  [skip] EngineDatabase entry not a dir: {line}")
    return out


def collect_clean_dirs():
    dirs = list(WHITE_DIRS)
    dirs += parse_engine_db_txt(ENGINE_DB_TXT)
    # de-dup, preserve order
    seen, uniq = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    return uniq


def collect_clean_pes(pe_cap=40000):
    """关键修复：直接从 PE 密集目录收集真实 MZ PE，保证干净训练集包含足量良性 PE。

    旧逻辑只做'全文件枚举 + _worker 内 MZ 过滤'，配额常在到达真实 PE 前被海量
    非 PE 文件耗尽，导致模型几乎没见过良性 PE，学到'PE 即病毒'。这里在枚举阶段
    就按扩展名+MZ 头双重确认，单独成池、优先入训，从根本上消除该偏差。
    """
    pe_dirs = [
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    ]
    pes = []
    exts = ('.exe', '.dll', '.sys', '.drv', '.ocx', '.scr', '.cpl')
    for d in pe_dirs:
        if not os.path.isdir(d):
            continue
        for root, ds, fs in os.walk(d):
            ds[:] = [x for x in ds if x not in SKIP_DIRS
                     and not x.lower().endswith(".tmp")]
            for fn in fs:
                if not fn.lower().endswith(exts):
                    continue
                fp = os.path.join(root, fn)
                try:
                    with open(fp, "rb") as f:
                        if f.read(2) != b"MZ":
                            continue
                except Exception:
                    continue
                pes.append(fp)
                if len(pes) >= pe_cap:
                    return pes
    return pes


def extract_features_parallel(file_list, desc):
    print(f"=== extracting features ({desc}: {len(file_list)} files, {WORKERS} workers) ===")
    t0 = time.time()
    feats = []
    done = 0
    with mp.Pool(processes=WORKERS, initializer=_lower_priority) as pool:
        for res in pool.imap_unordered(_extract_worker, file_list, chunksize=128):
            done += 1
            if res is not None:
                feats.append(res)
            if done % 5000 == 0:
                print(f"   {desc}: {done}/{len(file_list)} processed, {len(feats)} kept")
    print(f"  kept {len(feats)}/{len(file_list)} ({time.time()-t0:.1f}s)")
    return feats


def main():
    # --- single-instance guard: prevent a second `train_lightgbm.py` from
    #     racing on the same output model (corrupts lightgbm.pda). Any duplicate
    #     exits immediately instead of doing redundant work / double-writing. ---
    _lock_path = os.path.join(BASE_DIR, ".train_lightgbm.lock")
    try:
        import os as _os
        _fd = _os.open(_lock_path, _os.O_CREAT | _os.O_EXCL | _os.O_WRONLY)
        _os.write(_fd, str(_os.getpid()).encode())
        _os.close(_fd)
    except FileExistsError:
        print(f"[GUARD] another training instance is already running "
              f"(lock={_lock_path}); this duplicate exits.")
        return
    import atexit as _atexit
    _atexit.register(lambda: _os.remove(_lock_path) if _os.path.exists(_lock_path) else None)

    _lower_priority()  # keep the system responsive during a long training run
    ap = argparse.ArgumentParser()
    ap.add_argument("--virus-dir", default=VIRUS_DIR)
    ap.add_argument("--out", default=os.path.join(BASE_DIR, "EngineSET", "lightgbm.pda"))
    ap.add_argument("--max-clean", type=int, default=MAX_CLEAN,
                    help="max CLEAN training samples (files enumerated are not extension-filtered; "
                         "MZ decided per-file in parallel; subsampled if we collect more)")
    ap.add_argument("--max-virus", type=int, default=MAX_VIRUS,
                    help="max VIRUS training samples")
    ap.add_argument("--enum-cap", type=int, default=600_000,
                    help="global max candidate files to ENUMERATE per side (walk only, cheap; "
                         "no per-file stat). MZ filtering happens later in parallel.")
    ap.add_argument("--dir-cap", type=int, default=80_000,
                    help="max candidate files gathered from a SINGLE directory before "
                         "stopping its descent (keeps each huge tree bounded).")
    ap.add_argument("--clean-budget", type=int, default=300_000,
                    help="max CLEAN candidates sent to feature extraction (bounds time; "
                         "MZ ~subset of these become training samples, capped at --max-clean).")
    ap.add_argument("--virus-budget", type=int, default=200_000,
                    help="max VIRUS candidates sent to feature extraction.")
    ap.add_argument("--no-train", action="store_true", help="only collect & report, do not train")
    args = ap.parse_args()

    clean_dirs = collect_clean_dirs()
    print("=== clean (white) sources ===")
    for d in clean_dirs:
        print("  +", d)

    print("\n=== enumerating CLEAN candidate files (NO extension filter; "
          "MZ decided per-file in parallel) ===")
    t0 = time.time()
    # Enumerate every file path (cheap walk only, no per-file stat); arbitrary-
    # extension PEs (renamed / packed / extension-less) are kept and MZ-checked
    # later in the worker pool. Bounded by --dir-cap (per dir) and --enum-cap.
    clean_files = list(_collect_candidate_files(
        clean_dirs, args.enum_cap, args.dir_cap, "CLEAN"))
    print(f"clean candidates enumerated: {len(clean_files)} ({time.time()-t0:.1f}s)")

    print("\n=== enumerating VIRUS candidate files (NO extension filter) ===")
    t0 = time.time()
    virus_files = list(_collect_candidate_files(
        [args.virus_dir], args.enum_cap, args.dir_cap, "VIRUS"))
    print(f"virus candidates enumerated: {len(virus_files)} ({time.time()-t0:.1f}s)")

    if args.no_train:
        print("(--no-train) stopping before training.")
        return

    if len(virus_files) == 0:
        print("ERROR: no virus samples collected; aborting.")
        return

    # === 关键修复：干净集必须包含足量真实 Windows PE，否则模型学到"PE即病毒" ===
    clean_pes = collect_clean_pes()
    print(f"guaranteed real clean PEs collected: {len(clean_pes)}")
    if len(clean_pes) == 0 and len(clean_files) == 0:
        print("ERROR: no clean samples collected; aborting.")
        return

    import random as _random
    # generic clean: subsample to budget (不影响真实 PE 池)
    if len(clean_files) > args.clean_budget:
        clean_files = _random.Random(7).sample(clean_files, args.clean_budget)
        print(f"  (generic clean subsampled to {args.clean_budget})")
    if len(virus_files) > args.virus_budget:
        virus_files = _random.Random(7).sample(virus_files, args.virus_budget)
        print(f"  (virus subsampled to {args.virus_budget})")

    X_clean_pe = extract_features_parallel(clean_pes, "CLEAN-PE")
    X_clean_gen = extract_features_parallel(clean_files, "CLEAN-GEN")
    X_virus = extract_features_parallel(virus_files, "VIRUS")

    if not X_virus:
        print("ERROR: virus feature extraction produced no usable vectors.")
        return

    # 合并干净集：优先保留真实 PE，超额时先砍 generic，再必要时砍 PE
    X_clean = list(X_clean_pe) + list(X_clean_gen)
    if len(X_clean) > args.max_clean:
        overflow = len(X_clean) - args.max_clean
        drop = min(overflow, len(X_clean_gen))
        X_clean = X_clean_pe + X_clean_gen[drop:]
        if len(X_clean) > args.max_clean:  # 仍超额 -> 对 PE 也下采样
            idx = _random.Random(42).sample(range(len(X_clean)), args.max_clean)
            X_clean = [X_clean[i] for i in idx]
    print(f"  clean assembled: {len(X_clean_pe)} real-PE + {len(X_clean_gen)} generic "
          f"= {len(X_clean)} (cap {args.max_clean})")
    if not X_clean:
        print("ERROR: clean feature extraction produced no usable vectors.")
        return

    # Cap virus per class
    if len(X_virus) > args.max_virus:
        idx = _random.Random(42).sample(range(len(X_virus)), args.max_virus)
        X_virus = [X_virus[i] for i in idx]
        print(f"  (virus subsampled to {args.max_virus})")

    import numpy as np
    from lightgbm_engine import train_lightgbm_model
    import lightgbm as lgb

    X = np.array(X_clean + X_virus, dtype=np.float32)
    y = np.array([0] * len(X_clean) + [1] * len(X_virus), dtype=np.int32)

    print(f"\n=== training LightGBM (clean={len(X_clean)} virus={len(X_virus)}) ===")
    booster, best_thresh, stats = train_lightgbm_model(
        X, y, feature_size=FEATURE_SIZE,
        num_clean=len(X_clean), num_virus=len(X_virus)
    )
    print("training stats:", json.dumps(stats, ensure_ascii=False))

    # Validation report
    from sklearn.model_selection import train_test_split
    _, X_val, _, y_val = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    y_prob = np.clip(booster.predict(X_val), 1e-6, 1 - 1e-6)
    pred = (y_prob >= best_thresh).astype(int)
    tn = int(((pred == 0) & (y_val == 0)).sum())
    fp = int(((pred == 1) & (y_val == 0)).sum())
    fn = int(((pred == 0) & (y_val == 1)).sum())
    tp = int(((pred == 1) & (y_val == 1)).sum())
    fpr = fp / max(tn + fp, 1)
    tpr = tp / max(tp + fn, 1)
    print(f"VALIDATION @thr={best_thresh:.3f}: TP={tp} FP={fp} FN={fn} TN={tn} "
          f"| TPR={tpr:.4f} FPR={fpr:.4f}")

    # Save .pda
    header = {
        "feature_size": FEATURE_SIZE,
        "threshold": round(float(best_thresh), 4),
        "num_clean": len(X_clean),
        "num_virus": len(X_virus),
        "model_format": "lightgbm_raw",
        "lib_version": lgb.__version__,
        "source_dirs": clean_dirs + [args.virus_dir],
        "description": "SevenEngine LightGBM PE classifier (.pda binary)",
    }
    from pda_store import save_pda
    model_bytes = booster.model_to_string().encode("utf-8")
    save_pda(args.out, model_bytes, header)
    print(f"\nSaved LightGBM engine -> {args.out} ({os.path.getsize(args.out)} bytes)")
    print("threshold =", round(float(best_thresh), 4))


if __name__ == "__main__":
    main()
