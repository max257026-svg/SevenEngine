# SevenEngine

Windows PE 恶意软件扫描引擎（PeTechnology v0.0.2）。

基于 ONNX 深度学习模型、YARA 规则与 PE 静态特征启发式，对单个文件或目录进行恶意软件检测，输出威胁名称、命中引擎与置信度。

## 功能

- 多类型样本扫描：PE 可执行文件、MSI 安装包、脚本（JS / BAT / COM）等
- ONNX 深度模型特征提取（`ONNX/onnx_feature_extractor.py` + `PexDeepModel.onnx`）
- YARA 规则匹配（`yara-python`）
- PE 静态特征启发式分析（`pefile`）
- 干净文件知识库白名单（`engines/study-engine.txt`，47452 条记录）
- 可选云端情报比对（`requests`）

## 安装

```bash
pip install -r requirements.txt
```

## 使用

```bash
python SevenEngine.py "文件路径"
python SevenEngine.py "目录路径"
```

示例输出与字段说明见 [调用文档.txt](调用文档.txt)。

## 许可证

[MIT](LICENSE) © 2024–2026 SevenEngine
