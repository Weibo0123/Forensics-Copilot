# anomalies.py

from __future__ import annotations
from numpy.ma.core import anomalies
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

