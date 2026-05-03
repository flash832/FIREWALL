"""
setup_cython.py — Manual Cython build script
=============================================
Use this ONLY when you want to manually compile C extensions.

Usage:
    python setup_cython.py build_ext --inplace

Do NOT use this for PyPI uploads — use `python -m build` instead.
"""

from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        [
            # FIX: Never include __init__.py — breaks package imports
            "sentinel_shield/core.py",
        ],
        compiler_directives={
            'language_level': "3",
            'boundscheck': False,
            'wraparound': False,
            'cdivision': True,
        },
        annotate=False,
        nthreads=4,
    )
)