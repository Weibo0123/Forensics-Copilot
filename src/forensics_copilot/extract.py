# extract.py

from __future__ import annotations
import zipfile
import tarfile
import shutil
import os
import gzip
import bz2
import lzma

MAX_RECURSION_DEPTH = 4

class ExtractionResult:
    def __init__(self):
        self.extracted_to: str | None = None
        self.success: bool = False
        self.note:str | None = None

def _try_extract(abs_path: str, dest_dir: str) -> ExtractionResult:
    result = ExtractionResult()
    try :
        with zipfile.ZipFile(abs_path) as zf:
            needs_password = any(info.flag_bits & 0x1 for info in zf.infolist())
            if needs_password:
                result.note = "The ZIP file is password protected, can't unzip automatically."
                return result
            zf.extractall(dest_dir)
        result.success = True
        result.extracted_to = dest_dir
    except zipfile.BadZipFile:
        result.note = "The ZIP file may have a corrupted structure or be a non-standard ZIP (it could be a fake/assembled file)."
    except RuntimeError:
        result.note = "Unzip failed, might require a password."
    except Exception as e:
        result.note = f"Failed to unzip: {e}"
    return result

def _try_extract_tar(abs_path: str, dest_dir: str) -> ExtractionResult:
    result = ExtractionResult()
    try:
        with tarfile.open(abs_path) as tf:
            tf.extractall(dest_dir, filter="data")
        result.success = True
        result.extracted_to = dest_dir
    except Exception as e:
        result.note = f"Failed to extract the archive: {e}."
    return result

def _try_extract_single_compressed(abs_path: str, dest_dir: str, opener) -> ExtractionResult:
    result = ExtractionResult()
    base_name = os.path.basename(abs_path)
    for suffix in (".gz", ".bz2", ".xz"):
        if base_name.endswith(suffix):
            base_name = base_name[:-len(suffix)]
            break
    out_path = os.path.join(dest_dir, base_name or "decompressed_data")
    try:
        os.makedirs(dest_dir, exist_ok=True)
        with opener(abs_path, "rb") as f_in, open(out_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        result.success = True
        result.extracted_to = dest_dir
    except Exception as e:
        result.note = f"Failed to decompress {abs_path}: {e}."
    return result

def extract_file(abs_path: str, dest_dir: str, mime: str) -> ExtractionResult:
    os.makedirs(dest_dir, exist_ok=True)

    if mime == "application/zip" or abs_path.lower().endswith(".zip"):
        return _try_extract(abs_path, dest_dir)

    if "tar" in mime or abs_path.lower().endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        return _try_extract_tar(abs_path, dest_dir)

    if mime in ("application/gzip", "application/x-gzip") or abs_path.lower().endswith(".gz"):
        return _try_extract_single_compressed(abs_path, dest_dir, gzip.open)

    if mime in ("application/x-bzip2", "application/x-bz2") or abs_path.lower().endswith(".bz2"):
        return _try_extract_single_compressed(abs_path, dest_dir, bz2.open)

    if mime in ("application/x-xz",) or abs_path.lower().endswith(".xz"):
        return _try_extract_single_compressed(abs_path, dest_dir, lzma.open)

    result = ExtractionResult()
    result.note = "Unsupported file format."
    return result
