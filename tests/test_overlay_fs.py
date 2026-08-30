import os
from pathlib import Path
from agentatk.sandbox.overlay_fs import OverlayFS


def test_overlay_fs_path_normalization():
    fs = OverlayFS()
    try:
        # Test leading slash stripping (e.g. /secrets/api_key)
        seeded = fs.seed("/secrets/api_key", "secret-token-1234")
        assert seeded.exists()
        assert fs.read("/secrets/api_key") == "secret-token-1234"
        assert fs.read("secrets/api_key") == "secret-token-1234"

        # Test Windows drive letter stripping (e.g. C:\data\test.txt)
        fs.seed("C:\\data\\test.txt", "drive-letter-content")
        assert fs.read("data/test.txt") == "drive-letter-content"

        # Test relative path traversals (../)
        fs.seed("../../inbox/file.txt", "safe-nesting")
        assert fs.read("inbox/file.txt") == "safe-nesting"

        # Test non-existent file
        assert "FILE NOT FOUND" in fs.read("missing/file.txt")
    finally:
        fs.reset()
        assert not fs.root.exists()


def test_overlay_fs_copy_and_reset():
    fs = OverlayFS()
    try:
        fs.seed("doc.txt", "hello")
        files = fs.list_files()
        assert "doc.txt" in files
    finally:
        fs.reset()
