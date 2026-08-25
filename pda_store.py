# -*- coding: utf-8 -*-
"""
PDA binary store -- custom, fast, robust serialization for the LightGBM engine.

Why a custom binary instead of the old study-engine.txt (JSON)?
  * study-engine.txt is ~28 MB of text, slow to parse on every engine start.
  * The new LightGBM artifact is a compact binary blob that loads in milliseconds
    with zero JSON parsing and no per-record overhead.
  * Old study-engine.txt reading is left 100% intact (StudyEngine is untouched).
    This module is ADDITIVE only.

File layout (.pda):
  [0..4)   magic  b"PDA1"
  [4..8)   uint32 LE  header_len
  [8..8+H) header JSON (utf-8)
  [....)   uint64 LE  model_len
  [....)   model bytes (lightgbm booster model_to_string())
"""
import os
import sys
import json
import struct
import time

MAGIC = b"PDA1"
HEADER_LEN_FMT = "<I"      # unsigned 32-bit little-endian
MODEL_LEN_FMT = "<Q"       # unsigned 64-bit little-endian


def _require_lightgbm():
    try:
        import lightgbm  # noqa: F401
        return True
    except Exception:
        return False


def save_pda(path, model_bytes, header):
    """Write a .pda file.

    path       : output file path (extension should be .pda)
    model_bytes: bytes of the serialized LightGBM model (booster.model_to_string().encode())
    header     : dict with metadata (feature_size, threshold, num_clean, num_virus, ...)
    """
    if not isinstance(model_bytes, (bytes, bytearray)):
        raise TypeError("model_bytes must be bytes")
    # Defensive: a previous mistaken run may have left a directory at this path.
    if os.path.isdir(path):
        import shutil
        shutil.rmtree(path)
    header = dict(header or {})
    header["magic"] = "PDA1"
    header["created_at"] = header.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%S"))
    header_json = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    import tempfile
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(MAGIC)
            f.write(struct.pack(HEADER_LEN_FMT, len(header_json)))
            f.write(header_json)
            f.write(struct.pack(MODEL_LEN_FMT, len(model_bytes)))
            f.write(model_bytes)
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return path


def load_pda(path):
    """Load a .pda file. Returns (header_dict, model_bytes). Raises on malformed file."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Not a valid PDA file (bad magic): %s" % path)
        raw = f.read(4)
        if len(raw) < 4:
            raise ValueError("Truncated PDA header length: %s" % path)
        header_len = struct.unpack(HEADER_LEN_FMT, raw)[0]
        header_json = f.read(header_len)
        if len(header_json) < header_len:
            raise ValueError("Truncated PDA header: %s" % path)
        header = json.loads(header_json.decode("utf-8"))
        raw = f.read(8)
        if len(raw) < 8:
            raise ValueError("Truncated PDA model length: %s" % path)
        model_len = struct.unpack(MODEL_LEN_FMT, raw)[0]
        model_bytes = f.read(model_len)
        if len(model_bytes) < model_len:
            raise ValueError("Truncated PDA model payload: %s" % path)
    return header, model_bytes


def load_lightgbm_booster(path):
    """Load a .pda file and reconstruct a LightGBM Booster. Returns (header, booster)."""
    if not _require_lightgbm():
        raise RuntimeError("lightgbm is not installed; cannot load PDA model")
    import lightgbm as lgb
    header, model_bytes = load_pda(path)
    model_str = model_bytes.decode("utf-8")
    booster = lgb.Booster(model_str=model_str)
    return header, booster


def pda_info(path):
    """Read only the header metadata (no model parsing). Safe for quick inspection."""
    header, _ = load_pda(path)
    return header


if __name__ == "__main__":
    if len(sys.argv) > 1:
        p = sys.argv[1]
        print("PDA info:", pda_info(p))
    else:
        print("usage: python pda_store.py <file.pda>")
