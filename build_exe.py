import sys
import os
from PyInstaller.__main__ import run as pyinstaller_run

# Build script for SecOC Toolkit EXE
# Usage: python build_exe.py
# Fixes v0.2.19: add config/kerneldlls at top-level of PyInstaller bundle
# so gui.py get_resource_path() and can_interface.py find them at expected paths.

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_SRC = os.path.join(BASE_DIR, 'secoc_toolkit', 'config')
KERNELDLLS_SRC = os.path.join(BASE_DIR, 'secoc_toolkit', 'kerneldlls')

pyinstaller_run([
    '--name=SecOCToolkit',
    '--onefile',
    '--windowed',
    # Only add data files (config YAMLs, kernel DLLs)
    # PyInstaller auto-collects .py source files via import analysis
    f'--add-data={CONFIG_SRC};config',
    f'--add-data={KERNELDLLS_SRC};kerneldlls',
    # Hidden imports for dynamic/runtime loaded modules
    '--hidden-import=yaml',
    '--hidden-import=can',
    '--hidden-import=can.interfaces.vector',
    '--hidden-import=can.interfaces.zlgcan',
    '--hidden-import=can.interfaces.pcan',
    '--hidden-import=can.interfaces.kvaser',
    '--hidden-import=can.interfaces.socketcan',
    '--hidden-import=udsoncan',
    '--hidden-import=isotp',
    '--hidden-import=Crypto',
    '--hidden-import=Crypto.Cipher',
    '--hidden-import=Crypto.Hash',
    '--hidden-import=Crypto.Signature',
    '--hidden-import=pycryptodome',
    '--clean',
    '--noconfirm',
    f'--distpath={os.path.join(BASE_DIR, "dist")}',
    f'--workpath={os.path.join(BASE_DIR, "build")}',
    f'--specpath={os.path.join(BASE_DIR, "spec")}',
    os.path.join(BASE_DIR, 'secoc_toolkit', 'gui.py')
])

print("Build complete! EXE at: dist/SecOCToolkit.exe")
