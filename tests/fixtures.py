# fixtures.py

from __future__ import annotations
import os
import struct
import zipfile
import zlib
import subprocess
import tempfile


def chunk(tab: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tab + data + struct.pack(">I", zlib.crc32(tab + data))

def write_minimal_png(path: str, trailing_data: bytes = b"") -> None:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = chunk(b"IHDR", struct.pack(">2I5B", 1, 1, 8, 2, 0, 0, 0))
    raw = b"\x00\xff\xff\xff"
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    png = sig + ihdr + idat + iend
    with open(path, "wb") as f:
        f.write(png + trailing_data)

def write_minimal_jpeg(path: str, trailing_data: bytes = b"") -> None:
    soi = b"\xff\xd8"
    jfif_body = b"JFIF\x00" + b"\x01\x01" + b"\x00" + struct.pack(">HH", 1, 1) + b"\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(jfif_body) + 2) + jfif_body
    eoi = b"\xff\xd9"
    with open(path, "wb") as f:
        f.write(soi + app0 + eoi + trailing_data)

def write_zip_with_files(path: str, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for fname, data in files.items():
            zf.writestr(fname, data)

def write_password_protected_zip(path: str, filename: str, content: bytes, password: str) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        src_path = os.path.join(temp_dir, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        subprocess.run(
            ["zip", "-P", password, "-j", path, src_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

def write_fake_extension_file(path: str, content: bytes) -> None:
    with open(path, "wb") as f:
        f.write(content)