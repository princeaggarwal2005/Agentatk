import os
import json
import shutil
import uuid
from pathlib import Path
from typing import Any


class OverlayFS:
    """
    Ephemeral workspace overlay and virtual filesystem.
    Ensures safe path normalization on Windows/Linux and isolated execution.
    """

    def __init__(self, base_dir: str | None = None, copy_from_dir: str | None = None):
        if base_dir:
            self.root = Path(base_dir).resolve()
        else:
            # Store inside local workspace runs/.temp_overlays to prevent Windows %TEMP% permission restrictions
            workspace_overlay_dir = Path("runs/.temp_overlays").resolve()
            workspace_overlay_dir.mkdir(parents=True, exist_ok=True)
            self.root = workspace_overlay_dir / f"overlay_{uuid.uuid4().hex[:10]}"
        
        self.root.mkdir(parents=True, exist_ok=True)

        if copy_from_dir and os.path.exists(copy_from_dir):
            self.copy_from(copy_from_dir)

    def normalize_relpath(self, raw_path: str | Path) -> Path:
        """
        Safely strips root slashes, drive letters, and parent traversals.
        Returns a clean path relative to self.root.
        """
        text = str(raw_path).replace("\\", "/")
        parts = []
        for part in text.split("/"):
            if part in ("", ".", ".."):
                continue
            # Strip Windows drive letter like 'C:'
            if len(part) == 2 and part[1] == ":":
                continue
            parts.append(part)
        return self.root.joinpath(*parts) if parts else self.root

    def seed(self, path: str | Path, content: Any) -> Path:
        """Seed a file with specific content in the overlay."""
        target = self.normalize_relpath(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, (dict, list)):
            safe_content = json.dumps(content, indent=2)
        elif content is None:
            safe_content = ""
        else:
            safe_content = str(content)
        target.write_text(safe_content, encoding="utf-8")
        return target

    def write(self, path: str | Path, content: Any) -> Path:
        return self.seed(path, content)

    def read(self, path: str | Path) -> str:
        """Read content from the overlay filesystem."""
        target = self.normalize_relpath(path)
        if target.is_file():
            return target.read_text(encoding="utf-8", errors="replace")
        return f"FILE NOT FOUND: {path}"

    def exists(self, path: str | Path) -> bool:
        target = self.normalize_relpath(path)
        return target.exists()

    def list_files(self, rel_dir: str = ".") -> list[str]:
        target_dir = self.normalize_relpath(rel_dir)
        if not target_dir.is_dir():
            return []
        results = []
        for p in target_dir.rglob("*"):
            if p.is_file():
                results.append(str(p.relative_to(self.root)).replace("\\", "/"))
        return results

    def copy_from(self, source_dir: str | Path):
        """Copies an existing repository/directory into this ephemeral overlay."""
        src = Path(source_dir).resolve()
        if not src.exists():
            return
        for root, dirs, files in os.walk(src):
            # Skip VCS and caches
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".pytest_cache", "node_modules", "runs")]
            rel_root = Path(root).relative_to(src)
            dest_dir = self.root / rel_root
            dest_dir.mkdir(parents=True, exist_ok=True)
            for f in files:
                src_file = Path(root) / f
                dest_file = dest_dir / f
                try:
                    shutil.copy2(src_file, dest_file)
                except Exception:
                    pass

    def reset(self):
        """Wipes the ephemeral overlay directory cleanly."""
        if self.root.exists():
            try:
                shutil.rmtree(self.root, ignore_errors=True)
            except Exception:
                pass
