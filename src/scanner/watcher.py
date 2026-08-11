"""
Kintsugi-GRC Dynamic Directory Watcher
Actively monitors target environment directories for real-time file creation,
modification, permission changes, and deletion events to perform dynamic re-scanning.
"""

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("kintsugi_watcher")

class DynamicDirectoryWatcher:
    """Monitors file system changes in real-time and triggers single-file re-scan callbacks."""

    def __init__(
        self,
        target_dir: Path,
        on_file_changed: Callable[[Path, str], None],
        on_file_deleted: Callable[[Path, str], None],
        poll_interval: float = 1.0
    ):
        self.target_dir = target_dir.resolve()
        self.on_file_changed = on_file_changed
        self.on_file_deleted = on_file_deleted
        self.poll_interval = poll_interval

        self.running = False
        self.thread: Optional[threading.Thread] = None

        # State map: rel_path -> (mtime, size, mode)
        self.file_state_map: Dict[str, Tuple[float, int, int]] = {}

    def _get_snapshot(self) -> Dict[str, Tuple[float, int, int]]:
        """Takes a fast snapshot of file mtimes, sizes, and permissions in target directory."""
        snapshot = {}
        if not self.target_dir.exists():
            return snapshot

        for root, _, files in os.walk(self.target_dir):
            root_path = Path(root)
            if ".keys" in root_path.parts or ".git" in root_path.parts:
                continue

            for file_name in files:
                if file_name in ["expected_scan_results.json", "kintsugi_scanner_audit.log", "synthetic_generation_audit.log", "manifest.json"]:
                    continue

                file_path = root_path / file_name
                try:
                    rel_path = file_path.relative_to(self.target_dir).as_posix()
                    stat = file_path.stat()
                    snapshot[rel_path] = (stat.st_mtime, stat.st_size, stat.st_mode & 0o777)
                except (OSError, ValueError):
                    pass

        return snapshot

    def start(self):
        """Starts the active background dynamic watcher thread."""
        if self.running:
            return

        self.file_state_map = self._get_snapshot()
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
        logger.info(f"Dynamic Directory Watcher started on '{self.target_dir.as_posix()}' (polling every {self.poll_interval}s).")

    def stop(self):
        """Stops the active directory watcher thread."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        logger.info("Dynamic Directory Watcher stopped.")

    def _watch_loop(self):
        """Active polling loop comparing file system state against previous snapshot."""
        while self.running:
            try:
                time.sleep(self.poll_interval)
                if not self.running:
                    break

                current_state = self._get_snapshot()

                # Check for created or modified files
                for rel_path, current_meta in current_state.items():
                    prev_meta = self.file_state_map.get(rel_path)
                    abs_path = self.target_dir / rel_path

                    if prev_meta is None:
                        # File Created
                        logger.info(f"[DYNAMIC EVENT] File Created: {rel_path}")
                        self.file_state_map[rel_path] = current_meta
                        self.on_file_changed(abs_path, "CREATED")

                    elif prev_meta != current_meta:
                        # File Modified or Permissions Changed
                        logger.info(f"[DYNAMIC EVENT] File Modified/Perms Changed: {rel_path} (mode: {oct(current_meta[2])})")
                        self.file_state_map[rel_path] = current_meta
                        self.on_file_changed(abs_path, "MODIFIED")

                # Check for deleted files
                deleted_paths = set(self.file_state_map.keys()) - set(current_state.keys())
                for rel_path in deleted_paths:
                    abs_path = self.target_dir / rel_path
                    logger.info(f"[DYNAMIC EVENT] File Deleted: {rel_path}")
                    del self.file_state_map[rel_path]
                    self.on_file_deleted(abs_path, "DELETED")

            except Exception as e:
                logger.error(f"Error in dynamic watcher loop: {e}")
