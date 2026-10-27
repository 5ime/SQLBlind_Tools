# -*- coding: utf-8 -*-
"""Common file-magic detection and hex/binary helpers for recovered blind payloads."""
from __future__ import annotations

import re
from dataclasses import dataclass

FLAG_RE = re.compile(r"(?:flag|ctf|dasctf)(\[[^\]]+\]|\{[^}]+\})", re.IGNORECASE)

# Ordered longest-prefix first where it matters.
_MAGIC_RULES: tuple[tuple[bytes, str, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "png", ".png"),
    (b"Rar!\x1a\x07\x01\x00", "rar5", ".rar"),
    (b"Rar!\x1a\x07\x00", "rar", ".rar"),
    (b"7z\xbc\xaf'\x1c", "7z", ".7z"),
    (b"PK\x03\x04", "zip", ".zip"),
    (b"PK\x05\x06", "zip", ".zip"),
    (b"PK\x07\x08", "zip", ".zip"),
    (b"%PDF-", "pdf", ".pdf"),
    (b"\xff\xd8\xff", "jpeg", ".jpg"),
    (b"GIF87a", "gif", ".gif"),
    (b"GIF89a", "gif", ".gif"),
    (b"\x1f\x8b\x08", "gzip", ".gz"),
    (b"BM", "bmp", ".bmp"),
    (b"\x00\x00\x01\x00", "ico", ".ico"),
    (b"\x7fELF", "elf", ".elf"),
    (b"MZ", "pe", ".exe"),
    (b"\xca\xfe\xba\xbe", "mach-o/class", ".bin"),
    (b"SQLite format 3\x00", "sqlite", ".db"),
    (b"fLaC", "flac", ".flac"),
    (b"OggS", "ogg", ".ogg"),
    (b"ID3", "mp3", ".mp3"),
    (b"\xff\xfb", "mp3", ".mp3"),
    (b"\xff\xf3", "mp3", ".mp3"),
    (b"\xff\xf2", "mp3", ".mp3"),
)

_RIFF_RE = re.compile(rb"^RIFF....(WEBP|WAVE|AVI )", re.DOTALL)
_HEX_CHARS = re.compile(r"[^0-9a-fA-F]")


@dataclass(frozen=True)
class FileMagic:
    name: str
    ext: str


@dataclass
class BinaryPayload:
    data: bytes
    magic: FileMagic | None
    embedded_flags: list[str]


def _ascii_from_bytes(data: bytes) -> str:
    return data.decode("latin-1", errors="ignore")


def extract_flags_from_bytes(data: bytes) -> list[str]:
    text = _ascii_from_bytes(data)
    found: list[str] = []
    seen: set[str] = set()
    for match in FLAG_RE.finditer(text):
        value = match.group(0)
        if "?" in value or value in seen:
            continue
        seen.add(value)
        found.append(value)
    return found


def detect_magic(data: bytes) -> FileMagic | None:
    if not data:
        return None
    if data.startswith(b"RIFF") and len(data) >= 12:
        m = _RIFF_RE.match(data)
        if m:
            kind = m.group(1).decode("ascii", errors="ignore").strip().lower()
            ext = {"": ".bin", "webp": ".webp", "wave": ".wav", "avi": ".avi"}.get(kind, f".{kind or 'bin'}")
            return FileMagic(kind or "riff", ext)
    for prefix, name, ext in _MAGIC_RULES:
        if data.startswith(prefix):
            # BMP "BM" is weak — require plausible header size.
            if name == "bmp" and len(data) >= 6:
                size = int.from_bytes(data[2:6], "little")
                if size < 14 or size > len(data) + 1024 * 1024:
                    continue
            if name == "pe" and len(data) < 64:
                continue
            return FileMagic(name, ext)
    return None


def _is_mostly_hex(text: str) -> bool:
    compact = "".join(ch for ch in text if not ch.isspace())
    if len(compact) < 8:
        return False
    hex_only = _HEX_CHARS.sub("", compact)
    return len(hex_only) >= 8 and len(hex_only) % 2 == 0 and len(hex_only) >= int(len(compact) * 0.9)


def recovered_text_to_bytes(text: str) -> bytes | None:
    """Best-effort convert recovered blind text into raw bytes."""
    if not text:
        return None
    stripped = text.strip().replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")

    # Pure / near-pure hex dumps (common for hex(load_file(...)) blinds).
    if _is_mostly_hex(stripped):
        hex_only = _HEX_CHARS.sub("", stripped)
        try:
            return bytes.fromhex(hex_only)
        except ValueError:
            pass

    # \\xHH sequences (non-ASCII ordinals) — only when escapes dominate or magic hits.
    escape_count = stripped.count("\\x")
    if escape_count:
        rebuilt = bytearray()
        i = 0
        while i < len(stripped):
            if stripped.startswith("\\x", i) and i + 4 <= len(stripped):
                try:
                    rebuilt.append(int(stripped[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            rebuilt.append(ord(stripped[i]) & 0xFF)
            i += 1
        data = bytes(rebuilt)
        if detect_magic(data) or escape_count >= max(4, len(stripped) // 8):
            return data

    # Already looks like binary-ish latin-1 text with a magic header.
    raw = text.encode("latin-1", errors="replace")
    if detect_magic(raw):
        return raw
    return None


def analyze_binary_payload(text: str) -> BinaryPayload | None:
    data = recovered_text_to_bytes(text)
    if data is None or len(data) < 4:
        return None
    magic = detect_magic(data)
    flags = extract_flags_from_bytes(data)
    if magic is None and not flags:
        # Anonymous hex blob only when the surface text itself is hex.
        if _is_mostly_hex(text) and len(data) >= 32:
            return BinaryPayload(data=data, magic=FileMagic("bin", ".bin"), embedded_flags=flags)
        return None
    return BinaryPayload(data=data, magic=magic, embedded_flags=flags)
