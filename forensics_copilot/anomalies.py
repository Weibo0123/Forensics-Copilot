# anomalies.py

from __future__ import annotations
from forensics_copilot.model import Anomaly

_PNG_HEADER = b"\x89PNG\r\n\x1a\n"
_PNG_IEND = b"IEND\xae\x42\x60\x82"

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
        anomalies.append(Anomaly(
            description=f"The PNG file has trailing data after the IEND closing block ({trailing_len} bytes).",
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies

_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"
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
        anomalies.append(Anomaly(
            description=f"The JPEG file has trailing data after the EOI marker ({trailing_len} bytes).",
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies

_ZIP_LOCAL_HEADER = b"PK\x03\x04"
_ZIP_EOCD = b"PK\x05\x06"

def check_zip_trailing_data(abs_path: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return anomalies

    if not data.startswith(_ZIP_LOCAL_HEADER):
        return anomalies

    idx = data.find(_ZIP_EOCD)
    if idx == -1:
        return anomalies

    # EOCD record is fixed at 22 bytes
    eocd_fix_len = 22
    trailing_start = idx + eocd_fix_len
    trailing_len = len(data) - trailing_start
    if trailing_len > 4:
        anomalies.append(Anomaly(
            description=f"The ZIP file contains approximately {trailing_len} bytes of additional data after the EOCD record. May attached other files after it",
            severity="suspicious",
            details={"offset": trailing_start, "trailing_bytes": trailing_len},
        ))
    return anomalies

_RULES_BY_CATEGORY: dict[str, list] = {
    "image": [check_png_trailing_data, check_jpeg_trailing_data],
    "archive": [check_zip_trailing_data],
}

def run_anomaly_checks(abs_path: str, category: str) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for rule in _RULES_BY_CATEGORY.get(category, []):
        anomalies.extend(rule(abs_path))
    return anomalies