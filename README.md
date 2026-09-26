# Alg-PII Engine
**The Algerian RegTech Sovereign Platform**

Alg-PII Engine is a specialized regulatory compliance tool designed for Algerian enterprises (Law 18-07, Law 18-05, Health Law 18-11). It combines deterministic regular expressions with a state-of-the-art Arabic NER Transformer model to identify, extract, and cryptographically mask Personal Identifiable Information (PII) before storage or sharing.

## Features
- **Multi-Regulation Compliance:** Maps directly to Law 18-07 and other Algerian cybersecurity frameworks.
- **Hybrid Detection:** 9 specialized Algerian regex patterns (NIN, CCP, RIB, etc.) + CAMeLBERT MSA NER model.
- **ONNX Optimization:** Runs transformer inference entirely on CPU via INT8 quantization without heavy PyTorch dependencies.
- **Sovereign Security:** AES-256 database encryption, DPAPI key vault, and secure RAM wiping.
- **Premium GUI:** Stunning dark-mode, Right-To-Left (RTL) interface built with PyQt6.

## Installation

### Prerequisites
- Python 3.10+
- (Optional) Build Tools for C++ if installing `sqlcipher3` from source

### Setup Environment
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Running the App
```bash
python main.py
```

## Packaging for Production
We use PyInstaller to build a standalone `.exe` directory.

```bash
# Build the application
pyinstaller alg_pii_engine.spec --clean
```
The output will be inside the `dist/Alg-PII-Engine` folder. Run `Alg-PII-Engine.exe`.

## Security Notes
The master encryption key is generated automatically on first run and stored securely in the Windows Credential Manager. Do not clear your credential manager if you wish to retain access to historical encrypted scan logs.
