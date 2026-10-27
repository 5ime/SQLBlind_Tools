from __future__ import annotations

import gzip
import re
import zlib
from urllib.parse import unquote, unquote_plus


def recursive_unquote(value: str, plus_as_space: bool = False, rounds: int = 8) -> str:
    decoded = value
    for _ in range(rounds):
        next_value = unquote_plus(decoded) if plus_as_space else unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


_NON_HEX = str.maketrans("", "", "0123456789abcdefABCDEF")


def is_hex_string(value: str) -> bool:
    stripped = value.strip()
    n = len(stripped)
    if n < 2 or n % 2:
        return False
    # translate-away hex digits; empty remainder ⇒ pure hex (faster than fullmatch on MB bodies)
    return not stripped.translate(_NON_HEX)


def decode_hex_payload(value: str) -> str:
    raw = value.strip()
    if not raw or not is_hex_string(raw):
        return raw
    data = bytes.fromhex(raw)
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def decode_possibly_hex_body(value: str) -> bytes:
    """Return raw body bytes; tshark http.file_data is often hex-encoded."""
    raw = value.strip()
    if not raw:
        return b""
    if is_hex_string(raw):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    return raw.encode("latin-1", errors="replace")


def decompress_body(data: bytes, content_encoding: str) -> bytes:
    encoding = (content_encoding or "").lower()
    if not data:
        return data
    if "gzip" in encoding or data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except Exception:
            try:
                return zlib.decompress(data, 16 + zlib.MAX_WBITS)
            except Exception:
                return data
    if "deflate" in encoding:
        try:
            return zlib.decompress(data)
        except Exception:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except Exception:
                return data
    return data


def bytes_to_text(data: bytes) -> str:
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def extract_gopher_candidate(uri_text: str) -> str | None:
    match = re.search(r"gopher://.+", uri_text, re.IGNORECASE | re.DOTALL)
    return match.group(0) if match else None


def parse_gopher_wrapped_request(uri_text: str) -> tuple[str, str, str] | None:
    """
    Manually unpack gopher://host/_HTTP... payloads.

    Do NOT use urllib.urlparse for the payload: real newlines inside the gopher
    path (from %0d%0a decoding) cause urlparse to truncate the request body.
    """
    match = re.search(r"gopher://[^/]+/(.*)", uri_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None

    payload = match.group(1)
    if payload.startswith("_"):
        payload = payload[1:]
    payload = recursive_unquote(payload)
    payload = payload.replace("\r\n", "\n").replace("\r", "\n")

    request_line, separator, remainder = payload.partition("\n")
    request_parts = request_line.strip().split()
    if len(request_parts) < 2:
        return None

    method = request_parts[0].upper()
    path = recursive_unquote(request_parts[1])
    body = ""
    if separator:
        if "\n\n" in remainder:
            _, _, body_part = remainder.partition("\n\n")
        else:
            # headers may be missing blank line; take last non-empty line as body
            lines = [ln for ln in remainder.split("\n") if ln.strip()]
            body_part = lines[-1] if lines else ""
        body = recursive_unquote(body_part, plus_as_space=True)
    return method, path, body.strip()


def expand_form_fields(body: str) -> str:
    """Append decoded key=value pairs so probes in form fields are easy to match."""
    if not body or "=" not in body:
        return body
    parts: list[str] = []
    for chunk in re.split(r"[&;]", body):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        key = recursive_unquote(key, plus_as_space=True)
        value = recursive_unquote(value, plus_as_space=True)
        parts.append(f"{key}={value}")
    if not parts:
        return body
    return body + "\n" + "\n".join(parts)
