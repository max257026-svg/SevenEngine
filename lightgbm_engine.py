# -*- coding: utf-8 -*-
"""
LightGBM engine for SevenEngine (PeAV / PASW).

ADDITIVE component:
  * Reads a custom binary artifact (.pda) produced by train_lightgbm.py.
  * Does NOT touch the legacy StudyEngine (study-engine.txt) or the ONNX model.
  * Degrades gracefully (available=False) if lightgbm or the .pda file is missing,
    exactly like the existing OnnxScanner.

Inference is content-based: a file is only scored if its first two bytes are
b'MZ' (a PE image). This removes the old extension/suffix filter so renamed or
extension-less PE files are still detected.
"""
import os
import sys
import threading

try:
    import numpy as np
except Exception:
    np = None


class LightGBMScanner:
    def __init__(self, pda_path):
        self.pda_path = pda_path
        self.booster = None
        self.available = False
        self.threshold = 0.75
        self.feature_extractor = None
        self.feature_size = 512
        self.header = {}
        self.lock = threading.Lock()
        self.load_model(pda_path)

    def load_model(self, pda_path):
        try:
            if not os.path.exists(pda_path):
                return
            import lightgbm as lgb  # may raise if not installed
            from pda_store import load_lightgbm_booster
            header, booster = load_lightgbm_booster(pda_path)
            self.header = header
            self.booster = booster
            self.threshold = float(header.get("threshold", 0.75))
            self.feature_size = int(header.get("feature_size", 512))
            self.available = True
            try:
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from ONNX.onnx_feature_extractor import extract_features, FEATURE_SIZE
                self.feature_extractor = extract_features
                self.feature_size = FEATURE_SIZE
            except Exception:
                self.feature_extractor = None
        except Exception:
            self.available = False
            self.booster = None
            self.feature_extractor = None

    def reload(self, pda_path=None):
        if pda_path:
            self.pda_path = pda_path
        self.load_model(self.pda_path)

    def score(self, filepath, file_data=None):
        """Return the raw malware probability in [0,1], or -1.0 if unavailable / not PE.

        Used by the high-confidence white verdict layer in SevenEngine.scan_file
        to short-circuit noisy heuristics on legitimate system binaries.
        """
        if not self.available or self.booster is None or self.feature_extractor is None or np is None:
            return -1.0
        try:
            if file_data is not None:
                if len(file_data) < 2 or file_data[:2] != b'MZ':
                    return -1.0
            elif filepath:
                with open(filepath, 'rb') as f:
                    head = f.read(2)
                if head != b'MZ':
                    return -1.0
            feats = self.feature_extractor(filepath=filepath, file_data=file_data)
            if feats is None:
                return -1.0
            inp = np.array(feats, dtype=np.float32).reshape(1, -1)
            out = self.booster.predict(inp)
            try:
                prob = float(out[0])
            except (TypeError, IndexError):
                prob = float(out)
            if not (0.0 <= prob <= 1.0):
                prob = 1.0 / (1.0 + __import__("math").exp(-prob))
            return prob
        except Exception:
            return -1.0

    def scan(self, filepath, file_data=None):
        """Return (name, confidence_0_100, reason) for a malicious hit, else (None,0,'')."""
        if not self.available or self.booster is None or self.feature_extractor is None or np is None:
            return None, 0, ""
        try:
            # Content-based PE detection: drop the suffix filter.
            if file_data is not None:
                if len(file_data) < 2 or file_data[:2] != b'MZ':
                    return None, 0, ""
            elif filepath:
                with open(filepath, 'rb') as f:
                    head = f.read(2)
                if head != b'MZ':
                    return None, 0, ""
            feats = self.feature_extractor(filepath=filepath, file_data=file_data)
            if feats is None:
                return None, 0, ""
            inp = np.array(feats, dtype=np.float32).reshape(1, -1)
            out = self.booster.predict(inp)
            try:
                prob = float(out[0])
            except (TypeError, IndexError):
                prob = float(out)
            if not (0.0 <= prob <= 1.0):
                # raw score returned instead of probability -> squash with sigmoid
                prob = 1.0 / (1.0 + __import__("math").exp(-prob))
            if prob >= self.threshold:
                conf = int(prob * 100)
                return "LightGBM", conf, "LightGBM%.0f%%" % (prob * 100)
        except Exception:
            pass
        return None, 0, ""


def train_lightgbm_model(X, y, feature_size=512, num_clean=None, num_virus=None,
                         valid_ratio=0.15, random_state=42):
    """Train a binary LightGBM classifier and return (booster, best_threshold, stats).

    Threshold is chosen so that, on the held-out validation set,
    the false-positive rate stays <= 1% while the true-positive rate is maximized.
    """
    import lightgbm as lgb
    import numpy as np
    from sklearn.model_selection import train_test_split

    X = np.asarray(X, dtype=np.float32)
    y = np.asarray(y, dtype=np.int32)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=valid_ratio, random_state=random_state, stratify=y
    )

    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    scale_pos_weight = (neg / pos) if pos > 0 else 1.0

    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)

    params = {
        "objective": "binary",
        "metric": ["auc", "binary_logloss"],
        "boosting_type": "gbdt",
        "learning_rate": 0.03,
        "num_leaves": 127,
        "max_depth": -1,
        "min_data_in_leaf": 20,
        "min_child_samples": 20,
        "feature_fraction": 0.85,
        "bagging_fraction": 0.85,
        "bagging_freq": 1,
        "lambda_l1": 0.5,
        "lambda_l2": 1.0,
        "scale_pos_weight": scale_pos_weight,
        "verbose": -1,
        "seed": random_state,
        "num_threads": 1,  # 单线程训练，配合 IDLE 优先级，绝不烧机
    }

    booster = lgb.train(
        params,
        train_data,
        num_boost_round=1500,
        valid_sets=[val_data],
        callbacks=[
            lgb.early_stopping(stopping_rounds=80, verbose=False),
            lgb.log_evaluation(period=0),
        ],
    )

    y_prob = booster.predict(X_val)
    y_prob = np.clip(y_prob, 1e-6, 1 - 1e-6)

    best_thresh, best_tpr = 0.5, 0.0
    n_pos_val = max(int((y_val == 1).sum()), 1)
    n_neg_val = max(int((y_val == 0).sum()), 1)
    # Widen the threshold sweep down to 0.30 so the model can pick a lower
    # operating point that yields higher recall while still keeping FPR <= 1%.
    for t in np.arange(0.30, 0.999, 0.002):
        pred = (y_prob >= t).astype(int)
        fp = int(((pred == 1) & (y_val == 0)).sum())
        fpr = fp / n_neg_val
        tpr = int(((pred == 1) & (y_val == 1)).sum()) / n_pos_val
        if fpr <= 0.01 and tpr > best_tpr:
            best_tpr, best_thresh = tpr, t

    stats = {
        "train_clean": neg,
        "train_virus": pos,
        "val_clean": int((y_val == 0).sum()),
        "val_virus": int((y_val == 1).sum()),
        "best_tpr_at_fpr1pct": round(float(best_tpr), 4),
        "scale_pos_weight": round(float(scale_pos_weight), 3),
    }
    return booster, float(best_thresh), stats
