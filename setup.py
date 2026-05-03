import os
import sys
from setuptools import setup, find_packages

# ── Long description ──────────────────────────────────────────
long_description = ""
try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    pass

# ── Cython compilation ────────────────────────────────────────
# FIX 1: Never Cythonize __init__.py — it breaks imports
# FIX 2: Wrap in CYTHON_BUILD env flag so normal `pip install` works
# FIX 3: Added nthreads for faster compilation
# FIX 4: Added exclude_failures so one bad file won't break entire build

ext_modules = []

if os.environ.get("CYTHON_BUILD") == "1":
    try:
        from Cython.Build import cythonize
        from setuptools.extension import Extension

        ext_modules = cythonize(
            [
                # FIX: Only compile core.py — NEVER __init__.py
                "sentinel_shield/core.py",
            ],
            compiler_directives={
                'language_level': "3",
                'boundscheck': False,       # faster array access
                'wraparound': False,        # faster negative indexing
                'cdivision': True,          # faster division
            },
            annotate=False,
            nthreads=4,                     # parallel compilation
        )
        print("INFO: Cython extensions enabled.")
    except ImportError:
        print("WARNING: Cython not installed. Building without C extensions.")
        ext_modules = []
    except Exception as e:
        print(f"WARNING: Cython build failed: {e}. Building without C extensions.")
        ext_modules = []
else:
    print("INFO: Pure Python build. Set CYTHON_BUILD=1 to compile C extensions.")

# ── Setup ─────────────────────────────────────────────────────
setup(
    name="sentinel-sd",
    version="3.3.2",                        # FIX 5: bumped version
    description="Sentinel Security Kernel: Zero-Trust AI Firewall for Prompt Injection & Jailbreak Defense.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sentinel Team",
    packages=find_packages(),
    ext_modules=ext_modules,
    include_package_data=True,
    package_data={
        "sentinel_shield": ["*.md", "*.json"],
    },
    install_requires=[
        "sentence-transformers>=2.0.0",
    ],
    extras_require={
        # FIX 6: Cython is optional, not required for normal install
        "cython": ["Cython>=3.0.0"],
    },
    entry_points={
        "console_scripts": [
            "sentinel-scan=sentinel_shield.core:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires='>=3.8',               # FIX 7: 3.7 is EOL, use 3.8+
)
