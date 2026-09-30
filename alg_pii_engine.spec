# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_all

sqlcipher_datas, sqlcipher_binaries, sqlcipher_hidden = collect_all('sqlcipher3')

# A system Poppler directory can inject its ICU DLLs into Qt's delay-loaded
# dependencies. Those DLLs are unrelated to this app and can prevent QtCore
# from loading. Keep that directory out of PyInstaller's dependency search.
_build_path = os.environ.get('PATH', '')
os.environ['PATH'] = os.pathsep.join(
    item for item in _build_path.split(os.pathsep)
    if 'poppler' not in item.lower()
)

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=sqlcipher_binaries,
    datas=sqlcipher_datas + [
        ('assets', 'assets'),
    ],
    hiddenimports=sqlcipher_hidden + [
        'tqdm', 'regex', 'filelock',
        'PyQt6.sip', 'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
        'cryptography', 'keyring',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # The standalone build currently ships regex detection without PyTorch.
    # ONNX/Optimum are no longer used, so avoid analyzing their unrelated
    # optional modules and native binary trees.
    excludes=['transformers', 'tokenizers', 'torch', 'tensorflow', 'tensorboard', 'onnx', 'onnxruntime', 'optimum'],
    noarchive=False,
)
os.environ['PATH'] = _build_path

# Qt's ICU entry points are delay-loaded. PyInstaller can mistakenly resolve
# them from a system Poppler installation on the build machine and bundle an
# incompatible ICU DLL next to the app. Keep those unrelated DLLs out of the
# package; Qt can run without this optional ICU backend.
a.binaries = [
    entry for entry in a.binaries
    if not (
        os.path.basename(entry[1]).lower().startswith("icu")
        and "poppler" in entry[1].lower()
    )
]

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
    console=False, # Production GUI app
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
