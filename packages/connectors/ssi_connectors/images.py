"""Safe image intake (blueprint 4.1): detect by content, cap size and dimensions, strip metadata, fingerprint."""
from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass

from PIL import Image, ImageOps

MAX_BYTES = 5 * 1024 * 1024
MAX_PIXELS = 24_000_000
MAX_EDGE = 2400
Image.MAX_IMAGE_PIXELS = MAX_PIXELS


class ImageRejected(ValueError):
    pass


@dataclass
class CleanImage:
    png: bytes
    sha256_original: str
    sha256_clean: str
    width: int
    height: int
    detected: str
    dhash: str


def sniff(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def dhash(img: Image.Image) -> str:
    g = img.convert("L").resize((9, 8), Image.LANCZOS)
    px = list(g.get_flattened_data()) if hasattr(g, "get_flattened_data") else list(g.getdata())
    bits = 0
    for row in range(8):
        for col in range(8):
            bits = (bits << 1) | (px[row * 9 + col] > px[row * 9 + col + 1])
    return f"{bits:016x}"


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def sanitize(data: bytes) -> CleanImage:
    if len(data) > MAX_BYTES:
        raise ImageRejected("file too large")
    kind = sniff(data)
    if not kind:
        raise ImageRejected("unsupported file type (PNG, JPEG or WebP only)")
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        raise ImageRejected("image could not be read")
    if img.width * img.height > MAX_PIXELS:
        raise ImageRejected("image dimensions too large")
    img = ImageOps.exif_transpose(img)
    if max(img.size) > MAX_EDGE:
        img.thumbnail((MAX_EDGE, MAX_EDGE))
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    out = io.BytesIO()
    img.save(out, "PNG")              # re-encoding drops EXIF/ICC and any appended data
    clean = out.getvalue()
    return CleanImage(clean, hashlib.sha256(data).hexdigest(), hashlib.sha256(clean).hexdigest(), img.width, img.height, kind, dhash(img))
