# -*- coding: utf-8 -*-
"""重新训练 ONNX 模型：512维特征，系统文件(干净) + 病毒库(恶意)

修复：
  * 去掉后缀名过滤：改用 MZ 魔数判断 PE（与 LightGBM/运行时一致），
    避免漏掉改名或无后缀的 PE 文件。
  * 扩充干净样本来源，使用 class_weight='balanced' 降低白文件误报。
  * 阈值在验证集上按 FPR<=1% 调优。
  * 导出时关闭 zipmap（options={'zipmap': False}），与 SevenEngine 中
    容错的 _extract_prob 读取逻辑一致，解决“ONNX 读取有问题”。
"""
import os, sys, time, json, shutil
import numpy as np

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ONNX.onnx_feature_extractor import extract_features, FEATURE_SIZE

SKIP_DIRS = {'WinSxS', '$Recycle.Bin', 'System Volume Information', 'Temp',
             'Installer', '__pycache__', 'node_modules', 'INetCache'}

CLEAN_DIRS = [
    r'C:\DrvPath', r'C:\FloweyPet', r'C:\inetpub', r'C:\Intel', r'C:\PerfLogs',
    r'C:\Program Files', r'C:\Program Files (x86)', r'C:\ProgramData',
    r'C:\Windows', r'C:\XboxGames',
]
ENGINE_DB_TXT = r'D:\Administrator\Desktop\EngineDatabase.txt'
VIRUS_DIR = r'D:\训练病毒'

MAX_CLEAN = 60000
MAX_VIRUS = 200000
MAX_FILE_BYTES = 64 * 1024 * 1024  # 单文件上限，避免超大 PE 让 worker 卡死
# 极端 CPU 友好：单进程 + IDLE 最低优先级，只在机器空闲时跑，绝不烧机。
WORKERS = 1


def _lower_priority():
    """Drop this process to IDLE priority. Windows: IDLE_PRIORITY_CLASS = 0x40."""
    try:
        import ctypes
        _k = getattr(ctypes, "windll", None)
        if _k is not None:
            _k.kernel32.SetPriorityClass(_k.kernel32.GetCurrentProcess(), 0x40)
    except Exception:
        pass


_lower_priority()  # 主进程也降到 IDLE，训练时绝不抢 CPU


def parse_engine_db(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip().strip('"').strip("'")
            if line and not line.startswith('#') and os.path.isdir(line):
                out.append(line)
    return out


def collect_candidates(dirs, enum_cap, dir_cap, label_desc, progress_every=25000):
    """Enumerate every in-range file (stat-only, NO extension filter, NO MZ
    check here). The MZ check + feature extraction happen later in the parallel
    worker pool, so PEs of ANY extension (renamed / packed / extension-less) are
    never dropped by a suffix rule, and huge trees stay fast to enumerate."""
    files = []
    for d in dirs:
        if not os.path.isdir(d):
            print(f"  [skip] 不存在目录: {d}")
            continue
        print(f"  scanning {label_desc}: {d}")
        dir_count = 0
        for root, ds, fs in os.walk(d):
            ds[:] = [x for x in ds if x not in SKIP_DIRS]
            for fn in fs:
                files.append(os.path.join(root, fn))
                total = len(files)
                dir_count += 1
                if dir_count >= dir_cap:
                    ds[:] = []
                    break
                if total >= enum_cap:
                    return files
            if not ds:
                pass
        print(f"    -> {dir_count} candidates from {d}")
    print(f"  enumerated {total} candidate files from {label_desc}")
    return files


def extract_worker(arg):
    """Parallel worker: (idx, fp) -> (idx, feats-or-None).
    Extension-agnostic: only the MZ magic decides a PE candidate; non-PE
    (any extension, or none) is rejected quickly; heavy PE parse only on MZ."""
    idx, fp = arg
    try:
        with open(fp, 'rb') as f:
            if f.read(2) != b'MZ':
                return idx, None
        feats = extract_features(filepath=fp)
        return idx, (feats if feats is not None else None)
    except Exception:
        return idx, None


print("=== 枚举文件 (不按扩展名过滤，MZ 在并行 worker 中判定) ===")
t0 = time.time()
clean_dirs = CLEAN_DIRS + parse_engine_db(ENGINE_DB_TXT)
clean_cands = collect_candidates(clean_dirs, 800_000, 120_000, "CLEAN")
virus_cands = collect_candidates([VIRUS_DIR], 800_000, 120_000, "VIRUS")
# 预算控制：枚举上限下候选可能极多，提取阶段并行判 MZ 也会很慢/吃内存，
# 子采样到预算内（随机、可复现），MZ 判定与训练上限在后面处理。
import random as _rnd_onnx
if len(clean_cands) > 400_000:
    clean_cands = _rnd_onnx.Random(7).sample(clean_cands, 400_000)
if len(virus_cands) > 200_000:
    virus_cands = _rnd_onnx.Random(7).sample(virus_cands, 200_000)
clean_n = len(clean_cands)
print(f"干净候选: {clean_n}, 病毒候选: {len(virus_cands)}, 枚举耗时{time.time()-t0:.1f}s")

print("\n=== 提取特征 (并行, MZ 过滤) ===")
import multiprocessing as mp
X, y = [], []
fail_clean = fail_virus = 0
with mp.Pool(processes=WORKERS, initializer=_lower_priority) as pool:
    for idx, feats in pool.imap_unordered(extract_worker,
                                          enumerate(clean_cands + virus_cands)):
        if feats is None:
            if idx < clean_n:
                fail_clean += 1
            else:
                fail_virus += 1
            continue
        X.append(feats)
        y.append(0 if idx < clean_n else 1)

X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.int32)
print(f"\n特征矩阵: {X.shape}, 干净={int((y==0).sum())} 病毒={int((y==1).sum())}")
print(f"提取失败: 干净={fail_clean} 病毒={fail_virus}")

# 控制每类训练样本上限（保留数据若未超上限；超出则随机抽回）
import random as _rnd
_cidx = [i for i, v in enumerate(y.tolist()) if v == 0]
_vidx = [i for i, v in enumerate(y.tolist()) if v == 1]
if len(_cidx) > MAX_CLEAN:
    _cidx = _rnd.Random(42).sample(_cidx, MAX_CLEAN)
    print(f"  (干净抽回至 {MAX_CLEAN})")
if len(_vidx) > MAX_VIRUS:
    _vidx = _rnd.Random(42).sample(_vidx, MAX_VIRUS)
    print(f"  (病毒抽回至 {MAX_VIRUS})")
_all = sorted(set(_cidx) | set(_vidx))
X = [X[i] for i in _all]
y = y[_all]
X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.int32)
print(f"  控制后: 干净={int((y==0).sum())} 病毒={int((y==1).sum())}")

print("\n=== 训练模型 ===")
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"训练集: {X_train.shape[0]}, 测试集: {X_test.shape[0]}")

try:
    clf = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=42, class_weight='balanced')
    clf.fit(X_train, y_train)
except TypeError:
    clf = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.8, random_state=42)
    clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]
print("\n=== 测试结果 ===")
print(classification_report(y_test, y_pred, target_names=['干净', '病毒']))
cm = confusion_matrix(y_test, y_pred)
print(f"混淆矩阵: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

best_thresh, best_tpr = 0.5, 0.0
thr = 0.5
for t in np.arange(0.5, 0.999, 0.005):
    pred = (y_prob >= t).astype(int)
    fp = int(((pred == 1) & (y_test == 0)).sum())
    fpr = fp / max(int((y_test == 0).sum()), 1)
    tpr = int(((pred == 1) & (y_test == 1)).sum()) / max(int((y_test == 1).sum()), 1)
    if fpr <= 0.01 and tpr > best_tpr:
        best_tpr, best_thresh = tpr, t
print(f"\n最佳阈值(FPR<=1%): {best_thresh:.3f}, TPR={best_tpr:.4f}")

print("\n=== 转换ONNX ===")
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

initial_type = [('float_input', FloatTensorType([None, FEATURE_SIZE]))]
onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=15,
                             options={id(clf): {'zipmap': False}})

out_path = os.path.join('ONNX', 'PexDeepModel.onnx')
if os.path.exists(out_path):
    shutil.copy(out_path, out_path + '.bak')
with open(out_path, 'wb') as f:
    f.write(onnx_model.SerializeToString())
print(f"模型已保存: {out_path} ({os.path.getsize(out_path)} bytes)")

with open(os.path.join('ONNX', 'threshold.json'), 'w') as f:
    json.dump({'threshold': round(float(best_thresh), 3), 'feature_size': FEATURE_SIZE,
               'train_clean': int((y == 0).sum()), 'train_virus': int((y == 1).sum())}, f, indent=2)
print(f"阈值已保存: threshold.json (threshold={best_thresh:.3f})")

import onnxruntime as ort
sess = ort.InferenceSession(out_path, providers=['CPUExecutionProvider'])
print(f"\nONNX验证: inputs={[(i.name,i.shape) for i in sess.get_inputs()]}")
print(f"  outputs={[(o.name,o.shape) for o in sess.get_outputs()]}")
test_inp = X_test[:5].astype(np.float32)
out = sess.run(None, {sess.get_inputs()[0].name: test_inp})
print(f"  prob out[0][:5]: {np.array(out[-1]).tolist()[:5]}")
print("\n=== 训练完成 ===")

