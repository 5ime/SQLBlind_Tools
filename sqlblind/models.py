from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Config:
    file: Path
    sample_limit: int = 12
    output_requests: Path | None = None
    regexp: str | None = None
    json_output: Path | None = None
    export_bin: Path | None = None
    top: int = 5
    max_records: int | None = None
    engine: str = "tshark"


@dataclass
class RawRequest:
    frame_number: int
    stream_id: int
    method: str
    host: str
    uri: str
    body: str
    response_in: int | None


@dataclass
class RawResponse:
    frame_number: int
    request_in: int | None
    status_code: int | None
    content_length: int | None
    content_encoding: str
    body: str
    response_time: float | None


@dataclass
class HTTPRequestRecord:
    frame_number: int
    stream_id: int
    method: str
    host: str
    path: str
    body: str
    source: str
    response_code: int | None = None
    response_length: int | None = None
    response_time: float | None = None
    response_body_length: int | None = None
    response_fingerprint: str | None = None
    response_body_preview: str = ""

    @property
    def rendered(self) -> str:
        prefix = f"{self.method} {self.path}".strip()
        return prefix if not self.body else f"{prefix}\n\n{self.body}"

    @property
    def haystack(self) -> str:
        """Path + body + form-expanded text for probe scanning."""
        return self.rendered


@dataclass
class ProbeObservation:
    kind: str  # ordinal / char / length
    operator: str
    position: int | None
    candidate_raw: str
    candidate_int: int | None
    candidate_text: str | None
    target_key: str
    request: HTTPRequestRecord
    time_based: bool = False


@dataclass
class AnalysisResult:
    recovered_text: str = ""
    inferred_length: int | None = None
    truth_source: str = "未知"
    polarity_confidence: float = 0.0
    target_key: str = ""
    observation_count: int = 0
    notes: list[str] = field(default_factory=list)
    shape_hint: str = ""
    file_type: str = ""
    file_ext: str = ""
    file_size: int | None = None
    file_bytes: bytes | None = field(default=None, repr=False)
    embedded_flags: list[str] = field(default_factory=list)
    exported_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # Keep JSON serializable / compact.
        payload.pop("file_bytes", None)
        if self.file_size is not None:
            payload["file_size"] = self.file_size
        return payload


class ToolError(RuntimeError):
    pass
