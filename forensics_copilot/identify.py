# identify.py

from __future__ import annotations
import hashlib
import os
import sys

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    """
    Running inside a PyInstaller bundle. This must before 'import magic'
    """
    _bundled_magic_db = os.path.join(sys._MEIPASS, "magic.mgc")
    if os.path.exists(_bundled_magic_db):
        os.environ["MAGIC"] = _bundled_magic_db

import magic

_CATEGORY_RULES: list[tuple[str, str]] = [
    ("application/vnd.tcpdump.pcap", "pcap"),
    ("application/x-pcapng", "pcap"),
    ("image/jpeg", "image"),
    ("image/png", "image"),
    ("image/gif", "image"),
    ("image/bmp", "image"),
    ("image/webp", "image"),
    ("image/", "image"),  # other image types
    ("application/pdf", "pdf"),
    ("application/zip", "archive"),
    ("application/x-rar", "archive"),
    ("application/x-7z-compressed", "archive"),
    ("application/x-tar", "archive"),
    ("application/gzip", "archive"),
    ("application/x-gzip", "archive"),
    ("application/x-bzip2", "archive"),
    ("application/x-xz", "archive"),
    ("text/plain", "text"),
    ("application/json", "text"),
    ("application/x-executable", "executable"),
    ("application/x-elf", "executable"),
    ("application/x-dosexec", "executable"),
    ("audio/", "audio"),
    ("video/", "video"),
]

_EXE_EXPECTED_CATEGORY: dict[str, str] = {
    ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image",
    ".pdf": "pdf",
    ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap",
    ".zip": "archive", ".rar": "archive", ".7z": "archive",
    ".tar": "archive", ".gz": "archive", ".bz2": "archive", ".xz": "archive",
    ".txt": "text", ".json": "text",
}

def categorize(mime: str) -> str:
    """
    Categorizes a MIME type into a predefined category.
    """
    for prefix, category in _CATEGORY_RULES:
        if mime.startswith(prefix):
            return category
    return "unknown"

def compute_sha256(path: str, chunk_size: int = 1024 * 1024) -> str:
    """
    Computes the SHA-256 hash of a file in chunks.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()

def identify_file(abs_path: str, rel_path: str) -> dict:
    """
    Identifies and inspects a file based on its path and properties.
    """
    size_bytes = os.path.getsize(abs_path)
    declared_ext = os.path.splitext(rel_path)[1].lower()

    mime = magic.from_file(abs_path, mime=True) # For machine / programming
    label = magic.from_file(abs_path)           # For human

    category = categorize(mime)
    expected_category = _EXE_EXPECTED_CATEGORY.get(declared_ext, category)
    extension_mismatch = bool(expected_category and category != "unknown" and expected_category != category)

    return {
        "path": rel_path,
        "abs_path": abs_path,
        "size_bytes": size_bytes,
        "declared_ext": declared_ext,
        "detected_mime": mime,
        "detected_type_label": label,
        "category": category,
        "extension_mismatch": extension_mismatch,
        "sha256": compute_sha256(abs_path),
    }
