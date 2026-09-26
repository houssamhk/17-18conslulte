# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

onnx_datas, onnx_binaries, onnx_hidden = collect_all('onnxruntime')
trans_datas, trans_binaries, trans_hidden = collect_all('transformers')
tokenizers_datas, tokenizers_binaries, tokenizers_hidden = collect_all('tokenizers')

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=onnx_binaries + trans_binaries + tokenizers_binaries,
    datas=onnx_datas + trans_datas + tokenizers_datas + [
        ('assets', 'assets'),
    ],
    hiddenimports=onnx_hidden + trans_hidden + tokenizers_hidden + [
        'tqdm', 'regex', 'filelock',
        'PyQt6.sip', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
        'cryptography', 'keyring',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'tensorflow', 'tensorboard'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Alg-PII-Engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False, # Set to False for production GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.png'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Alg-PII-Engine',
)
