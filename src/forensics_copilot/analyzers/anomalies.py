# anomalies.py

from __future__ import annotations
import struct
from forensics_copilot.model import Anomaly

_PNG_HEADER = b"\x89PNG\r\n\x1a\n"
_PNG_IEND = b"IEND\xae\x42\x60\x82"
_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"
_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_ZIP_EOCD = b"PK\x05\x06"
_MP4_FTYP = b"ftyp"

_TRAILER_SIGNATURES: list[tuple[bytes, str]] = [
    (b"PK\x03\x04",       "a ZIP archive (PK\\x03\\x04 signature)"),
    (b"\x89PNG",          "a PNG image (\\x89PNG signature)"),
    (b"\xff\xd8",         "a JPEG image (\\xff\\xd8 signature)"),
    (b"GIF87a",           "a GIF image (GIF87a signature)"),
    (b"GIF89a",           "a GIF image (GIF89a signature)"),
    (b"%PDF",             "a PDF document (%PDF signature)"),
    (b"\x1f\x8b",         "a gzip stream (\\x1f\\x8b signature)"),
    (b"BZh",              "a bzip2 stream (BZh signature)"),
    (b"\xfd7zXZ\x00",     "an XZ stream"),
    (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (b"Rar!\x1a\x07",     "a RAR archive"),
    (b"MZ",               "a Windows PE executable (MZ signature)"),
    (b"\x7fELF",          "an ELF executable"),
    (b"OggS",             "an Ogg bitstream"),
    (b"fLaC",             "a FLAC audio file"),
    (b"ID3",              "an MP3 file (ID3 tag)"),
    (b"\xff\xfb",         "an MP3 file (sync word)"),
]


def _identify_trailer(trailer: bytes) -> str:
    for magic, label in _TRAILER_SIGNATURES:
        if trailer.startswith(magic):
            return label
    return f"unknown data (first bytes: {trailer[:4].hex()})"


def check_png_trailing_data(abs_path: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return anomalies

    if not data.startswith(_PNG_HEADER):
        return anomalies

    idx = data.find(_PNG_IEND)
    if idx == -1:
        anomalies.append(Anomaly(
            description="The PNG file could not find a standard IEND closing block; the file may be truncated or corrupted.",
            severity="suspicious",
        ))
        return anomalies

    trailing_start = idx + len(_PNG_IEND)
    trailing_len = len(data) - trailing_start
    if trailing_len > 0:
        kind = _identify_trailer(data[trailing_start:])
        anomalies.append(Anomaly(
            description=(
                f"The PNG file has {trailing_len} bytes of trailing data after the IEND "
                f"closing block (offset 0x{trailing_start:x}). Trailing data appears to be {kind}."
            ),
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies


def check_jpeg_trailing_data(abs_path: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return anomalies

    if not data.startswith(_JPEG_SOI):
        return anomalies

    idx = data.find(_JPEG_EOI)
    if idx == -1:
        anomalies.append(Anomaly(
            description="The JPEG file could not find a standard EOI marker; the file may be truncated or corrupted.",
            severity="suspicious",
        ))
        return anomalies

    trailing_start = idx + len(_JPEG_EOI)
    trailing_len = len(data) - trailing_start
    if trailing_len > 0:
        kind = _identify_trailer(data[trailing_start:])
        anomalies.append(Anomaly(
            description=(
                f"The JPEG file has {trailing_len} bytes of trailing data after the EOI "
                f"marker (offset 0x{trailing_start:x}). Trailing data appears to be {kind}."
            ),
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies


def check_zip_trailing_data(abs_path: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return anomalies

    if not data.startswith(_ZIP_LOCAL_HEADER):
        return anomalies

    idx = data.rfind(_ZIP_EOCD)
    if idx == -1:
        return anomalies

    # EOCD record is fixed at 22 bytes
    if idx + 22 > len(data):
        return anomalies
    comment_len = struct.unpack("<H", data[idx + 20: idx + 22])[0]
    trailing_start = idx + 22 + comment_len
    trailing_len = len(data) - trailing_start
    if trailing_len > 4:
        kind = _identify_trailer(data[trailing_start:])
        anomalies.append(Anomaly(
            description=(
                f"The ZIP file has {trailing_len} bytes of trailing data after the EOCD "
                f"record (offset 0x{trailing_start:x}). Trailing data appears to be {kind}."
            ),
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies


def _walk_mp4_boxes(data: bytes) -> int | None:
    offset = 0
    length = len(data)

    while offset < length:
        if offset + 8 > length:
            return offset

        size = struct.unpack(">I", data[offset: offset + 4])[0]

        if size == 1:
            if offset + 16 > length:
                return offset
            size = struct.unpack(">Q", data[offset + 8: offset + 16])[0]
            if size < 16:
                return None
        elif size == 0:
            return length
        else:
            if size < 8:
                return None

        next_offset = offset + size
        if next_offset > length:
            return offset
        offset = next_offset

    return offset

def check_mp4_trailing_data(abs_path: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return anomalies

    if len(data) < 8 or data[4:8] != _MP4_FTYP:
        return anomalies

    end_of_boxes = _walk_mp4_boxes(data)
    if end_of_boxes is None:
        return anomalies

    trailing_len = len(data) - end_of_boxes
    if trailing_len > 0:
        kind = _identify_trailer(data[end_of_boxes:])
        anomalies.append(Anomaly(
            description=(
                f"The MP4/MOV file has {trailing_len} bytes of trailing data after the last "
                f"ISOBMFF box (offset 0x{end_of_boxes:x}). Trailing data appears to be {kind}. "
                f"This is a common CTF technique: a second file is concatenated after the video "
                f"container and ignored by media players."
            ),
            severity="suspicious",
            details={"offset": end_of_boxes, "trailing_bytes": trailing_len},
        ))
    return anomalies

_RULES_BY_CATEGORY: dict[str, list] = {
    "image": [check_png_trailing_data, check_jpeg_trailing_data],
    "archive": [check_zip_trailing_data],
    "video": [check_mp4_trailing_data],
}

def run_anomaly_checks(abs_path: str, category: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for rule in _RULES_BY_CATEGORY.get(category, []):
        anomalies.extend(rule(abs_path))
    return anomalies