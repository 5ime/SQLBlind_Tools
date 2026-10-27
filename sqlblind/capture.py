from __future__ import annotations

import csv
import hashlib
import io
import re
import subprocess
from pathlib import Path

from .decode import (
    bytes_to_text,
    decode_hex_payload,
    decode_possibly_hex_body,
    decompress_body,
    expand_form_fields,
    extract_gopher_candidate,
    parse_gopher_wrapped_request,
    recursive_unquote,
)
from .models import Config, HTTPRequestRecord, RawRequest, RawResponse, ToolError

NOISE_METHODS = {"M-SEARCH", "NOTIFY", "SUBSCRIBE"}
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
LOG_SUFFIXES = {".log", ".txt"}
# Apache/Nginx common+combined style: ... "METHOD path PROTO" status size
ACCESS_LOG_RE = re.compile(
    r'"([A-Z]+) ((?:[^"\\]|\\.)*) HTTP/[0-9.]+"\s+(\d{3})\s+(\d+|-)'
)


def parse_tshark_int(value: str) -> int | None:
    value = value.strip()
    return int(value) if value.isdigit() else None


def parse_tshark_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def run_tshark_capture(pcap_file: Path) -> tuple[list[RawRequest], dict[int, RawResponse]]:
    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-Y",
        "http && !(http.request.method == \"M-SEARCH\")",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "tcp.stream",
        "-e",
        "http.request.method",
        "-e",
        "http.host",
        "-e",
        "http.request.uri",
        "-e",
        "http.file_data",
        "-e",
        "http.response.code",
        "-e",
        "http.content_length",
        "-e",
        "http.response_in",
        "-e",
        "http.request_in",
        "-e",
        "http.time",
        "-e",
        "http.content_encoding",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolError("未找到 tshark，请先安装 Wireshark/tshark 并确保其在 PATH 中。") from exc

    stderr = (result.stderr or "").strip()
    # Truncated captures often exit 14 while still emitting usable rows.
    truncated = "cut short" in stderr.lower() or "appears to have been cut short" in stderr.lower()
    if result.returncode not in (0, None) and not (truncated and result.stdout):
        raise ToolError(f"tshark 执行失败: {stderr or f'exit {result.returncode}'}")

    reader = csv.reader(io.StringIO(result.stdout or ""), delimiter="\t", quotechar='"')
    request_rows: list[RawRequest] = []
    response_rows: dict[int, RawResponse] = {}

    for row in reader:
        padded = list(row) + [""] * (12 - len(row))
        frame_number = parse_tshark_int(padded[0])
        stream_id = parse_tshark_int(padded[1])
        if frame_number is None or stream_id is None:
            continue

        method = padded[2].strip().upper()
        host = padded[3].strip()
        uri = padded[4].strip()
        file_data = padded[5].strip()
        status_code = parse_tshark_int(padded[6])
        content_length = parse_tshark_int(padded[7])
        response_in = parse_tshark_int(padded[8])
        request_in = parse_tshark_int(padded[9])
        response_time = parse_tshark_float(padded[10])
        content_encoding = padded[11].strip()

        if method and method not in NOISE_METHODS:
            request_rows.append(
                RawRequest(
                    frame_number=frame_number,
                    stream_id=stream_id,
                    method=method,
                    host=host,
                    uri=uri,
                    body=file_data,
                    response_in=response_in,
                )
            )

        if status_code is not None or request_in is not None:
            response_rows[frame_number] = RawResponse(
                frame_number=frame_number,
                request_in=request_in,
                status_code=status_code,
                content_length=content_length,
                content_encoding=content_encoding,
                body=file_data,
                response_time=response_time,
            )

    return request_rows, response_rows


def run_pyshark_capture(pcap_file: Path) -> tuple[list[RawRequest], dict[int, RawResponse]]:
    try:
        import pyshark  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise ToolError("未安装 pyshark：请先 `pip install pyshark`，或改用默认 `--engine tshark`。") from exc

    request_rows: list[RawRequest] = []
    response_rows: dict[int, RawResponse] = {}
    capture = None
    try:
        capture = pyshark.FileCapture(
            str(pcap_file),
            display_filter='http && !(http.request.method == "M-SEARCH")',
            keep_packets=False,
        )
        for pkt in capture:
            try:
                frame_number = int(getattr(pkt.frame_info, "number", "0") or "0")
            except Exception:
                continue
            try:
                stream_id = int(getattr(pkt.tcp, "stream", "0") or "0") if hasattr(pkt, "tcp") else 0
            except Exception:
                stream_id = 0
            if not hasattr(pkt, "http"):
                continue
            http = pkt.http
            method = str(getattr(http, "request_method", "") or "").strip().upper()
            host = str(getattr(http, "host", "") or "").strip()
            uri = str(getattr(http, "request_uri", "") or "").strip()
            file_data = str(getattr(http, "file_data", "") or "").strip()
            status_code = parse_tshark_int(str(getattr(http, "response_code", "") or ""))
            content_length = parse_tshark_int(str(getattr(http, "content_length", "") or ""))
            response_in = parse_tshark_int(str(getattr(http, "response_in", "") or ""))
            request_in = parse_tshark_int(str(getattr(http, "request_in", "") or ""))
            response_time = parse_tshark_float(str(getattr(http, "time", "") or ""))
            content_encoding = str(getattr(http, "content_encoding", "") or "").strip()

            if method and method not in NOISE_METHODS:
                request_rows.append(
                    RawRequest(
                        frame_number=frame_number,
                        stream_id=stream_id,
                        method=method,
                        host=host,
                        uri=uri,
                        body=file_data,
                        response_in=response_in,
                    )
                )
            if status_code is not None or request_in is not None:
                response_rows[frame_number] = RawResponse(
                    frame_number=frame_number,
                    request_in=request_in,
                    status_code=status_code,
                    content_length=content_length,
                    content_encoding=content_encoding,
                    body=file_data,
                    response_time=response_time,
                )
    finally:
        try:
            if capture is not None:
                capture.close()
        except Exception:
            pass
    return request_rows, response_rows


def extract_http_from_access_log(log_file: Path) -> tuple[list[RawRequest], dict[int, RawResponse]]:
    """Parse Apache/Nginx access logs into request/response pairs.

    Access logs lack response bodies, so truth classification falls back to
    status code / content-length clusters (common for boolean blinds logged there).
    """
    request_rows: list[RawRequest] = []
    response_rows: dict[int, RawResponse] = {}
    try:
        text = log_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ToolError(f"无法读取日志: {log_file}") from exc

    frame = 1
    for line in text.splitlines():
        match = ACCESS_LOG_RE.search(line)
        if match is None:
            continue
        method, path, status_raw, size_raw = match.groups()
        if method.upper() in NOISE_METHODS:
            continue
        path = path.replace('\\"', '"')
        status_code = int(status_raw)
        content_length = None if size_raw == "-" else int(size_raw)
        req_frame = frame
        resp_frame = frame + 1
        request_rows.append(
            RawRequest(
                frame_number=req_frame,
                stream_id=req_frame,
                method=method.upper(),
                host="",
                uri=path,
                body="",
                response_in=resp_frame,
            )
        )
        response_rows[resp_frame] = RawResponse(
            frame_number=resp_frame,
            request_in=req_frame,
            status_code=status_code,
            content_length=content_length,
            content_encoding="",
            body="",
            response_time=None,
        )
        frame += 2
    return request_rows, response_rows


def extract_http_from_pcap(config: Config) -> tuple[list[RawRequest], dict[int, RawResponse]]:
    suffix = config.file.suffix.lower()
    if suffix in LOG_SUFFIXES or suffix == "":
        # Bare name like "sql" may still be an access log.
        if suffix in LOG_SUFFIXES or _looks_like_access_log(config.file):
            return extract_http_from_access_log(config.file)
    if suffix not in PCAP_SUFFIXES and _looks_like_access_log(config.file):
        return extract_http_from_access_log(config.file)
    if config.engine == "tshark":
        return run_tshark_capture(config.file)
    if config.engine == "pyshark":
        return run_pyshark_capture(config.file)
    raise ToolError(f"未知 engine: {config.engine}")


def _looks_like_access_log(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:4096].decode("utf-8", errors="replace")
    except OSError:
        return False
    return ACCESS_LOG_RE.search(sample) is not None


def _fingerprint_body(data: bytes) -> str:
    """Stable fingerprint; avoid hashing multi-MB bodies byte-for-byte twice."""
    n = len(data)
    if n <= 8192:
        return hashlib.sha1(data).hexdigest()
    # length + head + mid + tail — enough to separate true/false response templates
    mid = n // 2
    digest = hashlib.sha1()
    digest.update(n.to_bytes(8, "little"))
    digest.update(data[:2048])
    digest.update(data[mid : mid + 1024])
    digest.update(data[-1024:])
    return digest.hexdigest()


def normalize_request(
    row: RawRequest,
    response_rows: dict[int, RawResponse],
    response_by_request: dict[int, RawResponse] | None = None,
) -> HTTPRequestRecord:
    decoded_uri = recursive_unquote(row.uri)
    raw_body_bytes = decode_possibly_hex_body(row.body)
    decoded_body = recursive_unquote(bytes_to_text(raw_body_bytes), plus_as_space=True)
    source = "http"
    method = row.method
    path = decoded_uri
    body = decoded_body.strip()

    gopher_candidate = extract_gopher_candidate(decoded_uri)
    if gopher_candidate is None and body:
        gopher_candidate = extract_gopher_candidate(body)
    gopher_wrapped = parse_gopher_wrapped_request(gopher_candidate) if gopher_candidate else None
    if gopher_wrapped is not None:
        method, path, body = gopher_wrapped
        source = "gopher-http"

    body = expand_form_fields(body)

    response = None
    if row.response_in is not None:
        response = response_rows.get(row.response_in)
    if response is None and response_by_request is not None:
        response = response_by_request.get(row.frame_number)
    elif response is None:
        response = next((item for item in response_rows.values() if item.request_in == row.frame_number), None)

    response_body_length = None
    response_fingerprint = None
    response_preview = ""
    if response and response.body:
        resp_bytes = decode_possibly_hex_body(response.body)
        resp_bytes = decompress_body(resp_bytes, response.content_encoding)
        response_body_length = len(resp_bytes)
        response_fingerprint = _fingerprint_body(resp_bytes)
        response_preview = bytes_to_text(resp_bytes[:200])
    elif response and response.content_length is not None:
        # Access-log path: no body, length/status still usable for boolean clustering.
        response_body_length = response.content_length
        response_fingerprint = f"len:{response.content_length}|code:{response.status_code}"

    return HTTPRequestRecord(
        frame_number=row.frame_number,
        stream_id=row.stream_id,
        method=method,
        host=row.host,
        path=path,
        body=body,
        source=source,
        response_code=response.status_code if response else None,
        response_length=response.content_length if response else None,
        response_time=response.response_time if response else None,
        response_body_length=response_body_length,
        response_fingerprint=response_fingerprint,
        response_body_preview=response_preview,
    )


def build_records(request_rows: list[RawRequest], response_rows: dict[int, RawResponse]) -> list[HTTPRequestRecord]:
    response_by_request = {
        item.request_in: item for item in response_rows.values() if item.request_in is not None
    }
    return [normalize_request(row, response_rows, response_by_request) for row in request_rows]
