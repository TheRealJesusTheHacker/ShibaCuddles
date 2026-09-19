"""
Setup script for building and distributing ShibaCuddles,
the advanced network scanner & security testing suite.
"""

import sys
from pathlib import Path
from setuptools import setup, find_packages

BASE_DIR = Path(__file__).resolve().parent

# 1. Read version from VERSION file (single source of truth)
VERSION_FILE = BASE_DIR / "VERSION"
VERSION = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.1.0"

# 2. Parse runtime requirements (strip comments and blanks)
INSTALL_REQUIRES = []
REQUIREMENTS_FILE = BASE_DIR / "requirements.txt"
if REQUIREMENTS_FILE.exists():
    for line in REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            INSTALL_REQUIRES.append(line)

# 3. Long description from README
README_FILE = BASE_DIR / "README.md"
LONG_DESCRIPTION = README_FILE.read_text(encoding="utf-8") if README_FILE.exists() else ""

setup(
    name="shibacuddles",
    version=VERSION,
    author="thedarkonejesus",
    description="Advanced network scanner & security testing suite with CLI and GUI.",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/thedarkonejesus/ShibaCuddles",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: System :: Monitoring",
    ],
    packages=find_packages(include=["src", "src.*", "gui", "gui.*"]),
    py_modules=["main", "gui_launcher"],
    package_data={
        "": ["LICENSE", "README.md", "VERSION"],
    },
    include_package_data=True,
    install_requires=INSTALL_REQUIRES,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "shiba-cuddles=main:main",
            "shiba-cuddles-gui=gui_launcher:main",
        ],
    },
    keywords=["network", "scanner", "security", "port-scan", "pentest", "nmap"],
    project_urls={
        "GitHub": "https://github.com/thedarkonejesus/ShibaCuddles",
        "Bug Reports": "https://github.com/thedarkonejesus/ShibaCuddles/issues",
    },
)
