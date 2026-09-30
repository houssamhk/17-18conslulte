# Alg-PII Engine
**The Algerian RegTech Sovereign Platform**

Alg-PII Engine is a local-first desktop tool for Algerian organizations. It combines deterministic patterns with optional Arabic named-entity recognition (NER) to find and redact personal information. Regulatory references are indicative and require review by qualified counsel.

## Features
- **Regulatory references:** Includes seeded mappings for Law 18-07 and related topics. These are reference material, not legal advice or an automated compliance certification.
- **Detection:** Algerian-focused regular-expression rules run locally. An optional CAMeLBERT MSA NER model can add Arabic entity detections when compatible PyTorch dependencies and local model files are available.
- **Local processing:** NLP is disabled by default. Model loading uses local files only and does not download model weights at application startup.
- **Encrypted storage:** The desktop database uses SQLCipher and its encryption key is stored through the operating system credential manager. Python memory cleanup is best effort and does not guarantee erasure of every copy of sensitive values.
- **Desktop interface:** Arabic right-to-left PyQt6 application with review, verification, and export workflows.

### NLP availability

The normal Python installation does not install PyTorch automatically. To enable NER, install a PyTorch build compatible with the machine and Python version, obtain the model files separately, then select their local directory in Settings. Without those dependencies and files, the application continues in regular-expression-only mode.

The PyInstaller configuration intentionally excludes PyTorch and ONNX. Builds made with the provided spec therefore run in regular-expression-only mode; enabling the NLP setting in that build will not make model inference available.

## Installation

### Prerequisites
- Python 3.10+
- Windows Credential Manager support for storing the database key
- Tesseract OCR with Arabic and English language data for image/scanned-PDF OCR

### Setup Environment
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

The app requires SQLCipher and refuses to open the sensitive database using plain SQLite. New installations store the database under the operating system's application-data directory. An existing `alg_pii_engine.db` in the working directory is migrated in place; an encrypted Fernet backup is retained as `*.legacy-backup.fernet`. Keep it with the original key until the encrypted database has been confirmed. The key must remain available in the OS credential store; restoring a database without its original key is not supported.

The first launch asks you to create an administrator account with a password of 12 to 72 UTF-8 bytes. No default account is created. Legacy installations using the shipped `admin/admin` credentials have that bootstrap account removed during schema initialization and must create a new administrator. NLP inference is off by default; enabling it only loads model files already present locally and never downloads a model at app startup.

Install Tesseract separately and make sure its `ara` and `eng` language packs are present to enable OCR. `.msg` documents are supported through the `extract-msg` dependency.

### Running the App
```bash
python main.py
```

## Packaging for Production
We use PyInstaller to build a standalone `.exe` directory.

```bash
# Build the application
pyinstaller alg_pii_engine.spec --clean --noconfirm
```
The output will be inside `dist/Alg-PII-Engine`. Copy the entire folder when distributing it and run `Alg-PII-Engine.exe`.

## Security Notes
The master encryption key is generated on first run and stored in Windows Credential Manager. The database is encrypted with SQLCipher; document vault files use authenticated Fernet encryption. Back up the database, vault directory, and the original key together. Key rotation is intentionally disabled until re-encryption of both database and vault is implemented.

License tokens use RSA signatures. The application contains only the public verification key. The corresponding private signing key must be held offline; issuer tools look in `%LOCALAPPDATA%\AlgPIIEngineIssuer\private_signing_key.pem` by default, or at the path in `ALG_PII_LICENSE_PRIVATE_KEY`. It is never included in the application build or Git. Legacy HS256 licenses are rejected and must be reissued. The issuer's `license_db.sqlite` is encrypted with SQLCipher and its key is stored separately in Windows Credential Manager; an existing plaintext issuer database is migrated on first launch with a Fernet-encrypted backup retained locally. The database is excluded from source control.

The `src/app` directory contains a separate Arabic RTL informational web landing page. It does not connect to the desktop application's database or provide authenticated web access.

Seed regulatory mappings are reference data and must be reviewed by qualified Algerian counsel before they are used to make compliance decisions.
