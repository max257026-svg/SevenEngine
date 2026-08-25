# SevenEngine（PeTechnology v0.0.2）

Windows PE 恶意软件**多引擎融合扫描引擎**。

把 ONNX 深度学习模型、LightGBM 梯度提升模型、PE 静态启发式、自定义规则（`.srule`）、海量知识库白名单、以及可选的云端威胁情报**分层融合**成一个扫描器，对单个文件或一个目录给出 `MALICIOUS / CLEAN / WHITELIST` 结论和置信度。

> 🛡️ **防御性安全工具**。本项目**不包含任何恶意样本**，只发布检测模型、规则与扫描代码。仓库里的 `engines/study-engine.txt` 是**干净（良性）样本**的特征/哈希知识库，用于降低误报，并非病毒库。

---

## 📑 目录

- [特性](#特性)
- [检测流水线（架构）](#检测流水线架构)
- [环境要求](#环境要求)
- [安装](#安装)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)
- [输出格式](#输出格式)
- [检测引擎详解](#检测引擎详解)
- [配置](#配置)
- [目录结构](#目录结构)
- [辅助脚本（开发 / 训练 / 诊断工具）](#辅助脚本开发--训练--诊断工具)
- [自定义规则格式（.srule）](#自定义规则格式srule)
- [模型训练](#模型训练)
- [云端引擎](#云端引擎)
- [打包为独立可执行文件](#打包为独立可执行文件)
- [安全与合规](#安全与合规)
- [已知限制](#已知限制)
- [许可证](#许可证)

---

## 特性

| 引擎 | 标识（verdict 标签） | 默认开关 | 说明 |
|------|----------------------|----------|------|
| **ONNX 深度学习** | `ONNX` | ✅ 开 | `ONNX/PexDeepModel.onnx` + `ONNX/onnx_feature_extractor.py` 提取 512 维 PE 特征并判定。 |
| **LightGBM** | `LightGBM` / `LightGBM-White` | ✅ 开 | `EngineSET/lightgbm.pda` 梯度提升模型，高置信恶意命中 + 高置信**干净裁决**用于压制系统文件误报。 |
| **PE 静态启发式** | `PE` / `SE-Chain` / `PE-Suspicious` / `PE-LowImport` / `Packer/Entropy` / `PE-SectionEntropy` / `Disguise` / `MSI-Heuristic` / `DOS-Heuristic` | ✅ 开 | 基于导入表 / 节 / 资源 / 熵 / 伪装等特征的启发式规则。 |
| **脚本分析** | `Script` | ✅ 开 | 对 vbs / js / ps1 / hta 等脚本的下载器、落地器特征判定。 |
| **自定义规则** | `CUSTOM` | ✅ 开 | `custom_rules/*.srule`（macro / misc / script 三类），替代旧 YARA 宏规则。 |
| **知识库白名单** | `SE-Precise` | ✅ 开 | `engines/study-engine.txt` 海量干净 + 恶意样本特征，精确命中即出结论（conf 95）。 |
| **YARA 规则** | `YARA` | ❌ 关（需自备规则） | 保留 `--DEBUG:YARA` 开关与 `yara_rules/` 目录支持，但默认关闭，改用内置 CUSTOM 引擎。 |
| **云端情报** | `Cloud-DB`（Xigua）/ `AVIC-Cloud` | ✅ 开 | 可选云查，由 `config.json` 的 `cloud_scan_enabled` / `avic_scan_enabled` 控制。 |

附加能力：

- **不过滤后缀名**：默认扫描目录下**所有文件**，改名 / 无后缀的 PE 也能被扫到（ML 引擎内部用 `MZ` 魔数判断 PE）。传 `--DEBUG:UNANY` 可恢复"仅扫描 `scan_extensions` 列表"的旧行为。
- **压缩包递归扫描**：自动解包 zip（最多 `max_zip_depth=2` 层）并扫描内层文件。
- **LRU 缓存 + 多线程**：`worker_threads=20`、`cache_size=10000`，目录扫描 `scan_dir_threads=8`。
- **结果导出**：`--OUTPUT:report.json|csv|txt` 把扫描结果落盘。

---

## 检测流水线（架构）

`SevenEngine.py` 中的 `Scanner.scan_file()` 按"命中即返回"的短路逻辑分层融合：

```
                  ┌─────────────────────────────────────────────┐
   输入文件  ──▶  │ 1. 白名单短路 (whitelist.txt)                │ ── hit ──▶ WHITELIST
                  │ 2. 知识库精确命中 (SE-Precise, conf 95)       │ ── hit ──▶ MALICIOUS
                  │ 3. LightGBM 高置信「干净裁决」(LightGBM-White)│ ── hit ──▶ CLEAN  ← 压制系统文件误报
                  │ 4. PE 启发式层 (PE / Script / Signature /     │
                  │     LNK / SE-Chain / Packer / Entropy / ...)  │ ── hit ──▶ MALICIOUS
                  │ 5. ONNX 深度模型 (ONNX)                      │ ── hit ──▶ MALICIOUS
                  │ 6. LightGBM 恶意判定 (LightGBM)              │ ── hit ──▶ MALICIOUS
                  │ 7. 自定义规则 (CUSTOM)                       │ ── hit ──▶ MALICIOUS
                  │ 8. YARA 规则 (YARA, 默认关)                  │ ── hit ──▶ MALICIOUS
                  │ 9. 云端情报 (Cloud-DB / AVIC-Cloud)          │ ── hit ──▶ MALICIOUS
                  └─────────────────────────────────────────────┘
                         全部未命中  ──▶  CLEAN (conf 0)
```

设计原则：**高置信白裁决（LightGBM-White）优先于易误报的启发式**，从而在不牺牲检出率的前提下压制 `notepad.exe` / `explorer.exe` 等系统关键 PE 的误报。

---

## 环境要求

- **操作系统**：Windows（扫描器大量使用 PE 结构与 Windows 路径约定；`pefile` 跨平台可用，但打包/云查链路针对 Windows 调优）。
- **Python**：3.8+（建议 3.10+；`requirements.txt` 中 `numpy==1.24.3` 等版本按训练环境锁定）。
- **硬件**：纯 CPU 推理，无需 GPU。

---

## 安装

```bash
# 1. 克隆仓库
git clone https://github.com/max257026-svg/SevenEngine.git
cd SevenEngine

# 2. 安装依赖
pip install -r requirements.txt
```

依赖清单（`requirements.txt`）：

```
pefile              # PE 文件解析（核心）
yara-python==4.3.0  # YARA 引擎（仅 --DEBUG:YARA 时需要）
onnxruntime         # ONNX 推理运行时
lightgbm            # LightGBM 推理 / 训练
numpy==1.24.3       # 数值计算（特征向量）
requests==2.31.0    # 云端 API 调用
cryptography==41.0.7# 云查签名 / 加解密辅助
```

> 模型与知识库已随仓库提供：`ONNX/PexDeepModel.onnx`、`EngineSET/lightgbm.pda`、`engines/study-engine.txt`（~28 MB）、`engines/study-export.json`，**无需额外下载**。

---

## 快速开始

```bash
# 扫描单个文件
python SevenEngine.py "D:\sample\hello.exe"

# 扫描整个目录（递归、不过滤后缀名）
python SevenEngine.py D:\scan_dir

# 把目录扫描结果导出成 JSON 报告
python SevenEngine.py D:\scan_dir --OUTPUT:report.json

# 只跑某一个引擎层（调试用）
python SevenEngine.py D:\scan_dir --DEBUG:ONNX
```

---

## 命令行参数

| 参数 | 含义 |
|------|------|
| `<target>` | 必填。文件或目录路径（第一个位置参数）。 |
| `--DEBUG:ONNX` | **只**启用 ONNX 深度模型。 |
| `--DEBUG:LIGHTGBM` | **只**启用 LightGBM 引擎（恶意判定 + 白裁决）。 |
| `--DEBUG:HEUR` | **只**启用 PE 静态启发式 + 脚本分析。 |
| `--DEBUG:YARA` | **只**启用 YARA 规则（需自备 `yara_rules/` 规则）。 |
| `--DEBUG:CUSTOM` | **只**启用自定义 `.srule` 规则。 |
| `--DEBUG:CLOUD` | **只**启用云端 API（Xigua / AVIC）。 |
| `--DEBUG:UNANY` | 不关任何引擎，但**恢复后缀名过滤**（仅扫 `scan_extensions` 列表）。 |
| `--OUTPUT:<name.ext>` | 把结果保存到当前目录。`ext` 支持 `json` / `csv` / `txt`。 |

- 参数解析**大小写不敏感**（`--debug:onnx` 等价）。
- 不传任何 `--DEBUG`：全部引擎默认启用，且**不过滤后缀名**。
- 不传 `--OUTPUT`：仅终端打印。

---

## 输出格式

### 单文件

严格打印三行：

```
Result: MALICIOUS|Trojan.Win32.Generic|SE-Precise|95
Confidence: 95
Info: Trojan.Win32.Generic
```

`Result` 字段格式为 `结论|威胁类型|引擎标签|置信度`：

- 结论：`MALICIOUS` / `CLEAN` / `WHITELIST` / `CLEAN|LightGBM-White`
- 引擎标签：见[检测引擎详解](#检测引擎详解)中的 verdict 列表
- 置信度：0–100 的整数

### 目录

打印扫描统计 + 威胁清单：

```
扫描目录: D:\scan_dir
  [!] MALICIOUS|Trojan.Win32.Generic|SE-Precise|95  D:\scan_dir\a.exe
  [OK] CLEAN  D:\scan_dir\b.dll
  [WL] WHITELIST  D:\scan_dir\trusted.sys

扫描完成: 共 1234 文件, 扫描 1200, 恶意 5, 干净 1190, 白名单 3, 错误 2
```

- `[!]` = 检出恶意，`[OK]` = 干净，`[WL]` = 白名单命中，`[??]` = 其他/未知结论。
- 若传 `--OUTPUT`，结果还会以所选格式写到文件（每行一条 `path, result, confidence, threat_type`）。

---

## 检测引擎详解

### 1. ONNX 深度学习（`ONNX/`）
- 模型：`ONNX/PexDeepModel.onnx`（导出自 `train_onnx_v4.py`，关闭 zipmap）。
- 特征：512 维，由 `ONNX/onnx_feature_extractor.py` 的 `extract_features()` 从 PE 提取（与 LightGBM 共用同一特征函数）。
- verdict：`ONNX`。默认 `onnx_confidence_threshold=85`。
- 说明：用 `MZ` 魔数判断 PE，因此改名 / 无后缀 PE 也能进入特征提取。

### 2. LightGBM（`EngineSET/` + `lightgbm_engine.py` + `pda_store.py`）
- 模型：`EngineSET/lightgbm.pda`（自定义二进制格式 `PDA1`，毫秒级加载，替代慢速 JSON）。
- 接口：`lightgbm_engine.LightGBMScanner`，`score()` 返回 `[0,1]` 恶意概率，`scan()` 返回 `(name, conf, reason)`。
- verdict：`LightGBM`（恶意命中，`LightGBM%.0f%%`）、`LightGBM-White`（高置信干净，用于压制误报）。
- 阈值：`.pda` 头部 `threshold`（默认 `0.75`），`lightgbm_white_prob=0.15` 为白裁决门限。
- `.pda` 文件布局：`magic(b"PDA1")` + `uint32` 头长 + JSON 头 + `uint64` 模型长 + LightGBM 模型字节。可用 `python pda_store.py EngineSET/lightgbm.pda` 查看头部元数据。
- 优雅降级：缺失 `lightgbm` 包或 `.pda` 文件时 `available=False`，不报错。

### 3. PE 静态启发式（`SevenEngine.py` 内）
一组基于 PE 结构的规则，verdict 标签：

| 标签 | 含义 |
|------|------|
| `SE-Precise` | 知识库精确命中（conf 95，最高优先级知识库裁决） |
| `SE-Chain` | 链式/组合启发（多弱特征组合命中，`combo_required_matches=2`） |
| `PE` | 通用 PE 启发 |
| `PE-Suspicious` | 可疑 PE 特征 |
| `PE-LowImport` | 低导入表可疑 |
| `Packer/Entropy` | 加壳 / 高熵 |
| `PE-SectionEntropy` | 单节高熵 |
| `Disguise` | 文件类型伪装（conf 55） |
| `MSI-Heuristic` | MSI 安装包启发 |
| `DOS-Heuristic` | DOS 遗留段启发 |
| `Signature` | 签名特征命中 |
| `LNK` | 快捷方式（`.lnk`）风险 |

### 4. 脚本分析（`Script`）
针对 `vbs / js / ps1 / hta` 等：检测 `PowerShell -EncodedCommand`、`certutil -urlcache`、`mshta`、`CreateObject("WScript.Shell")` 等下载器 / 落地器强特征。

### 5. 自定义规则（`custom_rules/*.srule`，`CUSTOM`）
项目自研的轻量规则格式，按 `type`（macro / misc / script / test / trojan）和 `severity`（0–100）匹配。详见[自定义规则格式](#自定义规则格式srule)。
- 默认 `enable_custom_rules=True`，`custom_rule_scan_cap=16777216`（16 MB，超过不跑规则扫描）。
- 规则目录：`custom_rules/`（可由 `CONFIG.custom_rules_dir` 改）。

### 6. 知识库白名单（`engines/study-engine.txt`，`SE-Precise`）
- 多 JSON 块文本，记录良性 / 恶意样本的 sha256→md5 索引与特征，用于精确命中与误报压制。
- 解析器支持多 JSON 块（`{...}{...}`）拼接，健壮性好。
- `study-export.json` 为同数据的导出快照。

### 7. YARA（`YARA`，默认关）
- 保留 `--DEBUG:YARA` 与 `yara_rules/` 支持，但 `enable_yara=False`。仓库**未随包提供** `.yar` 规则，如要使用需自行放置规则到 `yara_rules/`。

### 8. 云端情报（`Cloud-DB` / `AVIC-Cloud`）
- Xigua：`cloud_api_base=https://cloudapi.xiguastudio.top`；AVIC：`avic_api_base=https://avic.xiguastudio.top`。
- 由 `config.json` 的 `cloud_scan_enabled` / `avic_scan_enabled` 控制，`cloud_timeout=10` / `avic_timeout=10` 秒。
- 见[云端引擎](#云端引擎)的安全说明。

---

## 配置

### `config.json`（仓库根，功能开关）

```json
{
  "cloud_scan_enabled": true,
  "avic_scan_enabled": true
}
```

`SevenEngine.py` 启动时会读取 `config.json`（查找顺序：`Main/Main/config.json` → `Main/config.json` → `config.json`），其字段会**覆盖** `CONFIG` 默认值。

### `SevenEngine.py` 内 `CONFIG`（关键字段）

| 字段 | 默认 | 说明 |
|------|------|------|
| `worker_threads` | 20 | 并发扫描线程数 |
| `cache_size` | 10000 | LRU 结果缓存上限 |
| `scan_extensions` | `.exe .dll .sys .ocx .scr .cpl .drv .com .msi .jar .vbs .ps1 .js .bat .cmd .py .pyw .lnk .bin` | 后缀过滤列表（`--DEBUG:UNANY` 时启用） |
| `enable_ext_filter` | `False` | 默认不过滤后缀名 |
| `skip_dirs` | `$Recycle.Bin`, `System Volume Information`, `Windows\WinSxS`, … | 扫描时跳过的系统目录 |
| `confidence_threshold` | 60 | 通用置信门限 |
| `onnx_confidence_threshold` | 85 | ONNX 门限 |
| `max_zip_depth` | 2 | 压缩包递归解包深度 |
| `enable_onnx` / `enable_lightgbm` / `enable_pe_scan` / `enable_custom_rules` / `enable_study_engine` | `True` | 各层总开关 |
| `enable_yara` | `False` | YARA 总开关（默认关） |
| `enable_lightgbm_white` / `lightgbm_white_prob` | `True` / `0.15` | 白裁决开关与门限 |
| `lightgbm_model` | `EngineSET/lightgbm.pda` | LightGBM 模型路径 |
| `machine_learning_file` | `engines/study-engine.txt` | 知识库路径 |
| `custom_rules_dir` | `custom_rules` | 自定义规则目录 |
| `yara_rules_dir` | `yara_rules` | YARA 规则目录（默认不存在，需自建） |
| `onnx_model_dir` | `ONNX` | ONNX 模型目录 |
| `cloud_scan_enabled` / `avic_scan_enabled` | `True` | 云端开关 |
| `cloud_api_base` / `avic_api_base` | xiguastudio.top 域名 | 云端 API 地址 |
| `cloud_api_key` / `avic_api_key` | 内置共享 key | 云端凭据（见[云端引擎](#云端引擎)） |

> 直接改 `CONFIG` 默认值即可调整行为；运行时通过 `--DEBUG` 临时切换引擎层。

---

## 目录结构

```
SevenEngine/
├── SevenEngine.py            # 主扫描器（多引擎调度、CLI、CONFIG）
├── lightgbm_engine.py        # LightGBM 引擎封装（score / scan，优雅降级）
├── pda_store.py              # .pda 二进制序列化/反序列化（PDA1 格式）
├── ONNX/
│   ├── PexDeepModel.onnx     # ONNX 深度学习模型
│   ├── features.json         # 特征定义
│   └── onnx_feature_extractor.py  # 512 维 PE 特征提取（与 LightGBM 共用）
├── EngineSET/
│   ├── lightgbm.pda          # LightGBM 模型（二进制 PDA1 格式，~5.3 MB）
│   ├── darkhash.txt          # （占位/辅助哈希库，空）
│   └── lighthash.txt         # （占位/辅助哈希库，空）
├── engines/
│   ├── study-engine.txt      # 知识库白名单（~28 MB，多 JSON 块）
│   └── study-export.json     # 知识库导出快照
├── custom_rules/             # 自定义规则（.srule）
│   ├── macro.srule           # Office OLE/CFBF 宏病毒规则
│   ├── misc.srule            # 杂项强特征（EICAR / CHM script）
│   └── script.srule          # 脚本下载器/落地器规则
├── signatures/               # 默认签名/特征
│   ├── default.json          # 内置签名
│   └── default.stu           # 内置特征库
├── config.json               # 功能开关（云端）
├── whitelist.txt             # 白名单（默认空，可填路径/哈希）
├── requirements.txt          # 依赖
├── train_lightgbm.py         # 训练 LightGBM 模型（开发用）
├── train_onnx_v4.py          # 重新训练 ONNX 模型（开发用）
├── verify_model.py           # LightGBM 落盘 + 误报/召回验证（开发用）
├── verify_pda.py             # .pda 引擎验证（开发用）
├── analyze_missed.py         # 漏报分析（熵/特征，开发用）
├── enroll_clean.py / _2 / _3 # 把系统文件标 clean，消误报（开发用）
├── enroll_missed.py          # 把漏报文件收录进知识库（开发用）
├── clean_threat.py           # 清理矛盾数据（type=malicious 但 threat=CLEAN）
├── diag_b4.py / diag_cur.py / diag_hash.py / diag_missed.py / diag_sep.py  # 知识库诊断（开发用）
├── _fp_fn_test.py            # FP/FN 端到端测试（开发用）
├── _probe.py                 # LightGBM/ONNX 可用性探针（开发用）
├── 调用文档.txt              # 中文调用说明（详尽版，含各引擎用法）
├── LICENSE                   # MIT 许可证全文
└── README.md                 # 本文档
```

---

## 辅助脚本（开发 / 训练 / 诊断工具）

> ⚠️ 这些脚本是**离线开发工具**，多数硬编码了作者本地样本路径（如 `D:\训练病毒`、`D:\Administrator\Desktop\SevenEngineCloud`）。直接用会找不到文件——需自行改路径，或仅作逻辑参考。

| 脚本 | 类别 | 用途 |
|------|------|------|
| `train_lightgbm.py` | 训练 | 用干净+恶意样本训练 LightGBM，导出 `.pda`；阈值按验证集 FPR≤1% 调优。 |
| `train_onnx_v4.py` | 训练 | 重新训练 ONNX 模型（512 维，MZ 魔数判定，class_weight 降误报）。 |
| `verify_model.py` | 验证 | 校验 `.pda` 落盘、白文件误报（系统 PE 概率 <0.10）、病毒召回。 |
| `verify_pda.py` | 验证 | 读取 `.pda` 头、干净低概率、病毒高概率、旧 study-engine 仍可加载。 |
| `analyze_missed.py` | 诊断 | 分析漏报文件的熵/特征。 |
| `enroll_missed.py` | 数据录入 | 把漏报文件按 sha256 精确收录进 `study-engine.txt`（SE-Precise 命中）。 |
| `enroll_clean.py` / `_2` / `_3` | 数据录入 | 把系统文件标 clean，消除 SE-Precise 误报（三个迭代版本）。 |
| `clean_threat.py` | 数据清洗 | 修复 `type=malicious` 但 `threat=CLEAN` 的矛盾记录。 |
| `diag_b4.py` / `diag_cur.py` / `diag_hash.py` / `diag_missed.py` / `diag_sep.py` | 诊断 | 知识库哈希/记录层面的误报、漏报定位。 |
| `_fp_fn_test.py` | 测试 | LightGBM 模型 FP/FN 端到端测试（IDLE 优先级，限样本量）。 |
| `_probe.py` | 探针 | 打印 LightGBM/ONNX 可用性、阈值，抽样系统 PE 看误报面。 |

---

## 自定义规则格式（.srule）

`custom_rules/*.srule` 是项目自研的轻量规则语言，纯文本、注释以 `#` 开头，一个 `rule` 块由 `{}` 包裹：

```text
# 注释：每条规则内的 str 为「任意命中即判」（OR），均为强指示器
rule Script_PS_Encoded {
    type = trojan        # 类别：macro / misc / script / test / trojan
    severity = 90        # 严重度 0–100（影响命中时的置信度）
    str = PowerShell -EncodedCommand
    str = powershell -enc
    str = IEX (New-Object
}

rule Macro_OLE_AutoRun {
    type = macro
    severity = 92
    magic = D0CF11E0A1B11AE1   # 16 进制魔数（如 OLE/CFBF 复合文档）
    str = AutoOpen
    str = Document_Open
}
```

字段说明：

- `type`：规则类别，用于归因与展示。
- `severity`：严重度，命中后映射到 verdict 置信度。
- `magic`：可选，16 进制文件魔数（如 `D0CF11E0A1B11AE1` = Office OLE），不匹配则整条跳过，**避免误伤**（如 docx/xlsx 是 ZIP 头，不会触发 OLE 宏规则）。
- `str`：可选，可多条；文件内容命中任一即判（OR 语义）。

仓库内置三类：`macro.srule`（OLE 宏病毒）、`misc.srule`（EICAR 测试串、CHM script）、`script.srule`（脚本下载器）。新增规则直接往 `custom_rules/` 加 `.srule` 文件即可，运行时自动加载。

---

## 模型训练

### LightGBM

```bash
python train_lightgbm.py
```

- 输入：干净样本（系统 PE）+ 恶意样本（病毒库），特征经 `extract_features()` 提取为 512 维。
- 输出：`EngineSET/lightgbm.pda`（经 `save_pda()` 序列化为 PDA1 二进制）。
- 阈值：在验证集上按 **FPR ≤ 1%** 扫掠选取，最大化 TPR。
- 训练为单线程（`num_threads=1`）+ IDLE 优先级，避免烧机。

### ONNX

```bash
python train_onnx_v4.py
```

- 关键修复：去掉后缀过滤改用 `MZ` 魔数；`class_weight='balanced'` 降白文件误报；导出关闭 zipmap 以兼容运行时容错读取。
- 输出：`ONNX/PexDeepModel.onnx` + `ONNX/features.json`。

> 训练脚本依赖本地样本目录（默认 `C:\Windows`、`C:\Program Files`、`D:\训练病毒` 等），需在本地机器调整路径后运行。

---

## 云端引擎

- **Xigua 云查**（`Cloud-DB`）：`https://cloudapi.xiguastudio.top`，开关 `config.json.cloud_scan_enabled`。
- **AVIC 云查**（`AVIC-Cloud`）：`https://avic.xiguastudio.top`，开关 `config.json.avic_scan_enabled`。
- 云端用作**兜底情报**：本地引擎全未命中、或云返回已知恶意时补刀。
- ⚠️ **凭据说明**：`SevenEngine.py` 的 `CONFIG` 中内置了项目共享的 `cloud_api_key` / `avic_api_key`（上游 `xiguastudio.top` 提供的公共 key）。如不希望使用云端、或担心共享 key 被限流/滥用，可在 `config.json` 中将 `cloud_scan_enabled` / `avic_scan_enabled` 设为 `false` 关闭，或编辑 `CONFIG` 中的 key 值替换为自有凭据。

---

## 打包为独立可执行文件

`SevenEngine.py` 通过 `getattr(sys, 'frozen', False)` 检测是否以冻结 EXE 运行，并据此调整 `BASE_DIR`，因此可正常打包为单文件 EXE（如 PyInstaller）。

打包要点：

- 把 `ONNX/`、`EngineSET/`、`engines/`、`custom_rules/`、`signatures/`、`config.json` 等**数据目录**一并纳入（`datas` / `--add-data`）。
- 依赖 `pefile`、`onnxruntime`、`lightgbm`、`yara-python`（如启用 YARA）、`cryptography` 需随包。
- 云端调用走 `requests`，无需额外配置。

---

## 安全与合规

- 本项目是**防御性**工具：仅做检测，不携带、不生成任何恶意样本或利用代码。
- 仓库所含 `engines/study-engine.txt` 为**良性样本知识库**（用于降误报），`signatures/` 为检测签名，均非病毒库。
- 使用本工具扫描他人文件 / 系统前，请确保你具备相应授权。
- 云端引擎会向 `xiguastudio.top` 发送文件哈希/特征用于情报查询，详见[云端引擎](#云端引擎)。

---

## 已知限制

1. **YARA 默认关闭且未随包提供规则**：如需 YARA 引擎，需自行把 `.yar` 规则放到 `yara_rules/` 并将 `enable_yara` 置 `True`。
2. **云端 key 内置**：见[云端引擎](#云端引擎)——共享 key 已随源码公开，可按需关闭或替换。
3. **辅助脚本依赖本地样本路径**：`enroll_*` / `diag_*` / `train_*` / `verify_*` 等是作者离线开发工具，含硬编码本地路径，直接运行需改路径。
4. **平台偏向 Windows**：扫描链路针对 Windows PE 与路径约定设计。

---

## 许可证

[**MIT**](LICENSE) — Copyright (c) 2024–2026 SevenEngine (PeTechnology)。

你可以自由使用、修改、分发本软件，包括但不限于商业用途，但须保留版权声明与许可证文本。本软件按「原样」提供，作者不对使用后果承担责任。
