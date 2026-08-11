"""
Kintsugi-GRC Framework Storage Shim (Backward Compatibility)
Re-exports FrameworkStorageClient from the clean modular location src.storage.framework_storage.
"""

from src.storage.framework_storage import FrameworkStorageClient

__all__ = ["FrameworkStorageClient"]
