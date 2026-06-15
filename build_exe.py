import sys
import os
from PyInstaller.__main__ import run as pyinstaller_run

# Build script for SecOC Toolkit EXE
# Usage: python build_exe.py

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

pyinstaller_run([
    '--name=SecOCToolkit',
    '--onefile',
    '--windowed',  # Or --console for CLI output
    '--add-data=secoc_toolkit/config/toyota_secoc.yaml;secoc_toolkit/config',
    '--add-data=secoc_toolkit;secoc_toolkit',
    '--icon=assets/secoc_icon.ico',  # Optional
    '--hidden-import=pycryptodome',
    '--hidden-import=yaml',
    '--hidden-import=can',
    '--hidden-import=udsoncan',
    '--hidden-import=isotp',
    '--hidden-import=Crypto',
    '--hidden-import=Crypto.Cipher',
    '--hidden-import=Crypto.Hash',
    '--clean',
    '--noconfirm',
    f'--distpath={os.path.join(BASE_DIR, "dist")}',
    f'--workpath={os.path.join(BASE_DIR, "build")}',
    f'--specpath={os.path.join(BASE_DIR, "spec")}',
    os.path.join(BASE_DIR, 'secoc_toolkit', 'main.py')
])

print("Build complete! EXE at: dist/SecOCToolkit.exe")
