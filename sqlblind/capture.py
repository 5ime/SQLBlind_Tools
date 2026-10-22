from __future__ import annotations

import csv
import hashlib
import io
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
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolError("未找到 tshark，请先安装 Wireshark/tshark 并确保其在 PATH 中。") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise ToolError(f"tshark 执行失败: {stderr or exc}") from exc

    reader = csv.reader(io.StringIO(result.stdout), delimiter="\t", quotechar='"')
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


def extract_http_from_pcap(config: Config) -> tuple[list[RawRequest], dict[int, RawResponse]]:
    if config.engine == "tshark":
        return run_tshark_capture(config.file)
    if config.engine == "pyshark":
        return run_pyshark_capture(config.file)
    raise ToolError(f"未知 engine: {config.engine}")


def normalize_request(row: RawRequest, response_rows: dict[int, RawResponse]) -> HTTPRequestRecord:
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
    if response is None:
        response = next((item for item in response_rows.values() if item.request_in == row.frame_number), None)

    response_body_length = None
    response_fingerprint = None
    response_preview = ""
    if response and response.body:
        resp_bytes = decode_possibly_hex_body(response.body)
        resp_bytes = decompress_body(resp_bytes, response.content_encoding)
        decoded_response_body = bytes_to_text(resp_bytes)
        response_body_length = len(decoded_response_body)
        response_fingerprint = hashlib.sha1(
            decoded_response_body.encode("utf-8", errors="replace")
        ).hexdigest()
        response_preview = decoded_response_body[:200]

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
    return [normalize_request(row, response_rows) for row in request_rows]
