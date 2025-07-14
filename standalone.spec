# -*- mode: python ; coding: utf-8 -*-

# PyInstaller spec file for crypt.frnki v1.1.0 - Standalone Version
# Single file architecture for USB distribution

import os

a = Analysis(
    ['crypt_frnki_standalone.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('favicon.png', '.'),
        ('favicon.ico', '.'),
    ],
    hiddenimports=[
        'PIL._tkinter_finder', 
        'argon2', 
        'cryptography'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='crypt.frnki',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='favicon.ico' if os.path.exists('favicon.ico') else 'favicon.png',
    # version='version_info.txt',
    uac_admin=False,
    uac_uiaccess=False,
)