#!/usr/bin/env python3
"""
src/dep_check.py

Automatic runtime dependency checker and installer for Kintsugi-GRC.
Verifies third-party Python modules before app/script execution and installs missing packages via pip.
"""

import sys
import subprocess
import site
import os
import importlib
from typing import List, Optional

# Map importable module names to PyPI package specifications
DEPENDENCY_MAP = {
    "PyQt6": "PyQt6>=6.6.0",
    "PyQt6.QtCharts": "PyQt6-Charts>=6.6.0",
    "numpy": "numpy>=1.26.4",
    "faiss": "faiss-cpu>=1.8.0",
    "sentence_transformers": "sentence-transformers>=3.0.1",
    "cryptography": "cryptography>=42.0.0",
}


def _prompt_model_download():
    """Prompts the user to download the BAAI RAG AI embedding model if missing."""
    # Only prompt if sentence_transformers is installed
    try:
        import sentence_transformers
    except ImportError:
        return

    model_name = "BAAI/bge-large-en-v1.5"
    cache_dir = os.path.abspath("./.model_cache")
    hf_folder_name = f"models--{model_name.replace('/', '--')}"
    model_path = os.path.join(cache_dir, hf_folder_name)

    if not os.path.exists(model_path):
        if sys.stdin.isatty():
            print(f"\n[Kintsugi-GRC] The RAG AI embedding model '{model_name}' (~1.34GB) is not downloaded locally.")
            choice = input(f"[Kintsugi-GRC] Would you like to download it now? (Recommended for Hybrid Search) [Y/n]: ").strip().lower()
            if choice in ('', 'y', 'yes'):
                print(f"[Kintsugi-GRC] Downloading model '{model_name}' into {cache_dir}. This may take a few minutes...")
                os.makedirs(cache_dir, exist_ok=True)
                from sentence_transformers import SentenceTransformer
                SentenceTransformer(model_name, cache_folder=cache_dir)
                print(f"[Kintsugi-GRC] Model successfully downloaded and cached!\n")
            else:
                print(f"[Kintsugi-GRC] Skipping model download. RAG features will gracefully fall back to relational queries.\n")

def ensure_dependencies(required_modules: Optional[List[str]] = None) -> None:
    """
    Checks if specified Python modules exist on the host system.
    If missing, automatically installs their corresponding packages using pip.
    """
    if required_modules is None:
        required_modules = list(DEPENDENCY_MAP.keys())

    missing_packages: List[str] = []
    missing_modules: List[str] = []

    for mod_name in required_modules:
        try:
            importlib.import_module(mod_name)
        except (ModuleNotFoundError, ImportError):
            pkg = DEPENDENCY_MAP.get(mod_name, mod_name)
            if pkg not in missing_packages:
                missing_packages.append(pkg)
                missing_modules.append(mod_name)

    if not missing_packages:
        _prompt_model_download()
        return

    print(f"\n[Kintsugi-GRC] Missing required dependencies for: {', '.join(missing_modules)}")
    
    if sys.stdin.isatty():
        choice = input(f"[Kintsugi-GRC] Do you want to install these Python packages via pip now? [Y/n]: ").strip().lower()
        if choice not in ('', 'y', 'yes'):
            print("[Kintsugi-GRC] Skipping dependency installation. Some features may not work.\n")
            _prompt_model_download()
            return

    print(f"[Kintsugi-GRC] Automatically installing via pip: {', '.join(missing_packages)} ...")

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
    except Exception as e:
        print(f"[Kintsugi-GRC] ERROR: Failed to install packages {missing_packages}: {e}", file=sys.stderr)
        raise

    # Refresh site-packages and import caches
    user_site = site.getusersitepackages()
    if user_site and user_site not in sys.path and os.path.exists(user_site):
        sys.path.insert(0, user_site)
    importlib.invalidate_caches()
    print("[Kintsugi-GRC] All required dependencies successfully installed and verified.")
    
    _prompt_model_download()


if __name__ == "__main__":
    ensure_dependencies()
