# SevenEngine (PeTechnology v0.0.2)

Windows PE 恶意软件扫描引擎。多引擎融合检测：**ONNX 深度学习模型** + **LightGBM 模型** + **PE 静态启发式** + **自定义规则 (.srule)** + **知识库白名单**。

> 防御性安全工具。本项目**不含任何恶意样本**，仅包含检测模型、规则与扫描代码。

## 特性

- **ONNX 深度学习引擎**：`ONNX/PexDeepModel.onnx` + `ONNX/onnx_feature_extractor.py` 提取 PE 特征并判定。
- **LightGBM 引擎**：`EngineSET/lightgbm.pda` 梯度提升模型，提供高置信度干净/可疑判定（输出含 `LightGBM-White`）。
- **PE 静态启发式 + 脚本分析**：基于导入表 / 节 / 资源等特征的启发式规则（`SE-Precise` / `SE-Chain` / `PE-Suspicious` / `Script` 等）。
- **自定义规则**：`custom_rules/*.srule`（macro / misc / script 三类）。
- **知识库白名单**：`engines/study-engine.txt` 海量干净样本特征，用于降低误报。
- **云端引擎（可选）**：Xigua / AVIC 云查，由 `config.json` 中的 `cloud_scan_enabled` / `avic_scan_enabled` 控制。

## 安装

```bash
pip install -r requirements.txt
```

依赖：`pefile`、`yara-python==4.3.0`、`onnxruntime`、`lightgbm`、`numpy==1.24.3`、`requests==2.31.0`、`cryptography==41.0.7`

## 用法

扫描单个文件或目录：

```bash
python SevenEngine.py "路径"
python SevenEngine.py D:\scan_dir --OUTPUT:report.json
```

- 终端严格打印 `Result:` / `Confidence:` / `Info:` 三行。
- `--OUTPUT:report.json|csv|txt` 将结果保存到文件（支持 JSON / CSV / TXT）。
- 默认扫描目录下**所有文件**（不过滤后缀名），改名 / 无后缀的 PE 也能被扫到。

调试模式（仅启用单一引擎）：

| 开关 | 引擎 |
|------|------|
| `--DEBUG:ONNX` | 只跑 ONNX 模型 |
| `--DEBUG:LIGHTGBM` | 只跑 LightGBM |
| `--DEBUG:HEUR` | 只跑 PE 启发式 + 脚本分析 |
| `--DEBUG:YARA` | 只跑 YARA 规则（需自备规则文件） |
| `--DEBUG:CUSTOM` | 只跑自定义规则（.srule） |
| `--DEBUG:CLOUD` | 只跑云端 API（Xigua / AVIC） |
| `--DEBUG:UNANY` | 恢复「仅扫描指定后缀」的旧行为 |

## 目录结构

```
SevenEngine.py          主扫描器（多引擎调度）
lightgbm_engine.py      LightGBM 引擎封装
ONNX/                   ONNX 模型与特征提取
EngineSET/              LightGBM 模型(lightgbm.pda) 与哈希库
engines/                study-engine.txt 知识库白名单
custom_rules/           .srule 自定义规则
signatures/             默认签名 default.json 等
train_lightgbm.py       训练 LightGBM 模型（开发用）
train_onnx_v4.py        训练 ONNX 模型（开发用）
verify_model.py         模型校验（开发用）
verify_pda.py           PDA 模型校验（开发用）
调用文档.txt            中文调用说明（详尽版）
```

## 配置

`config.json`：功能开关（云端扫描等）。其余扫描参数位于 `SevenEngine.py` 顶部 `CONFIG`。

## 许可证

[MIT](LICENSE) — Copyright (c) 2024-2026 SevenEngine
