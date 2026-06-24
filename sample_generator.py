# sample_generator.py

from __future__ import annotations
import os
import struct
import sys
import zipfile
import zlib

MAX_RECURSION_DEPTH = 4


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", zlib.crc32(chunk_type + data))


def _build_png_bytes() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">2I5B", 4, 4, 8, 2, 0, 0, 0))
    raw = b"\x00" + b"\xff\x00\x00" * 4
    idat = _png_chunk(b"IDAT", zlib.compress(raw))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def _build_jpeg_bytes() -> bytes:
    soi = b"\xff\xd8"
    jfif_body = b"JFIF\x00" + b"\x01\x01" + b"\x00" + struct.pack(">HH", 1, 1) + b"\x00\x00"
    app0 = b"\xff\xe0" + struct.pack(">H", len(jfif_body) + 2) + jfif_body
    eoi = b"\xff\xd9"
    return soi + app0 + eoi


def make_normal_png(out_dir: str) -> None:
    with open(os.path.join(out_dir, "normal.png"), "wb") as f:
        f.write(_build_png_bytes())


def make_hidden_data_png(out_dir: str) -> None:
    payload = b"CTF{appended_after_iend_chunk}"
    with open(os.path.join(out_dir, "hidden_data.png"), "wb") as f:
        f.write(_build_png_bytes() + payload)


def make_hidden_data_jpeg(out_dir: str) -> None:
    payload = b"CTF{appended_after_eoi_marker}" * 3
    with open(os.path.join(out_dir, "hidden_photo.jpg"), "wb") as f:
        f.write(_build_jpeg_bytes() + payload)


def make_fake_extension_file(out_dir: str) -> None:

    path = os.path.join(out_dir, "flag.jpg")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("flag.txt", b"CTF{this_jpg_was_actually_a_zip}")


def make_zip_with_legit_comment(out_dir: str) -> None:
    path = os.path.join(out_dir, "with_comment.zip")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", b"Nothing hidden here, the comment is just a hint.")
        zf.comment = b"hint: There's no hidden data here :)"


def make_password_protected_zip(out_dir: str, password: str = "ctf123") -> None:
    import subprocess
    import tempfile

    path = os.path.join(out_dir, "protected.zip")
    with tempfile.TemporaryDirectory() as tmp:
        secret_path = os.path.join(tmp, "secret.txt")
        with open(secret_path, "wb") as f:
            f.write(b"CTF{you_needed_the_password}")
        subprocess.run(
            ["zip", "-P", password, "-j", path, secret_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def make_nested_zip(out_dir: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        level3 = os.path.join(tmp, "level3.zip")
        with zipfile.ZipFile(level3, "w") as zf:
            zf.writestr("flag.txt", b"CTF{three_layers_deep}")

        level2 = os.path.join(tmp, "level2.zip")
        with zipfile.ZipFile(level2, "w") as zf:
            zf.write(level3, "level3.zip")

        outer = os.path.join(out_dir, "nested.zip")
        with zipfile.ZipFile(outer, "w") as zf:
            zf.write(level2, "level2.zip")


def make_deep_nested_zip_hitting_limit(out_dir: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        innermost = os.path.join(tmp, f"layer{MAX_RECURSION_DEPTH + 1}.zip")
        with zipfile.ZipFile(innermost, "w") as zf:
            zf.writestr("flag.txt", b"CTF{you_should_never_see_this_by_default}")

        current = innermost
        for i in range(MAX_RECURSION_DEPTH, 0, -1):
            next_path = os.path.join(tmp, f"layer{i}.zip")
            with zipfile.ZipFile(next_path, "w") as zf:
                zf.write(current, os.path.basename(current))
            current = next_path

        final_path = os.path.join(out_dir, "too_deep.zip")
        with open(current, "rb") as src, open(final_path, "wb") as dst:
            dst.write(src.read())


def make_plain_text_file(out_dir: str) -> None:
    with open(os.path.join(out_dir, "notes.txt"), "w") as f:
        f.write("Just some plain notes, nothing suspicious here.\n")


SAMPLE_BUILDERS = [
    make_normal_png,
    make_hidden_data_png,
    make_hidden_data_jpeg,
    make_fake_extension_file,
    make_zip_with_legit_comment,
    make_password_protected_zip,
    make_nested_zip,
    make_deep_nested_zip_hitting_limit,
    make_plain_text_file,
]


def main() -> None:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "sample_data"
    os.makedirs(out_dir, exist_ok=True)

    for builder in SAMPLE_BUILDERS:
        builder(out_dir)
        print(f"  created: {builder.__name__}")

    print(f"\nDone — {len(SAMPLE_BUILDERS)} sample files written to {os.path.abspath(out_dir)}/")
    print("You can run it directly with:")
    print(f"  python3 -m forensics_copilot.cli {out_dir}")


if __name__ == "__main__":
    main()
