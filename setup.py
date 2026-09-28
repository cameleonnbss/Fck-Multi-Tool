#!/usr/bin/env python3
"""FCK MULTI TOOL — installeur cross-platform (python setup.py)."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    os.chdir(ROOT)
    if sys.platform.startswith("win"):
        os.system("cls")
    else:
        os.system("clear")
    print("\n   =============================================")
    print("      FCK MULTI TOOL - Installation")
    print("   =============================================\n")

    print("   [~] Mise a jour de pip...")
    subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=False)

    print("   [~] Installation des dependances...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=False)

    print("   [~] Verification des modules...")
    result = subprocess.run([sys.executable, "main.py", "--selftest"])

    print("\n   [+] Setup termine.")
    print("       Windows : start.bat")
    print("       Linux   : ./start.sh")
    print("       Tout    : python main.py\n")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
