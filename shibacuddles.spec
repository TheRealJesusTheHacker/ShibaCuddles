# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the ShibaCuddles CLI scanner.
# Build:  pyinstaller --noconfirm shibacuddles.spec

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('VERSION', '.'),
    ],
    # scapy is imported lazily inside functions, so PyInstaller can't see it statically
    hiddenimports=['scapy', 'scapy.all', 'scapy.layers.inet', 'scapy.layers.l2'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', 'black', 'flake8', 'pylint', 'mypy', 'sphinx', 'PyQt6'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ShibaCuddles',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # CLI scanner keeps its console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
