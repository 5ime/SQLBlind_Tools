from __future__ import annotations

import re

from .decode import decode_hex_payload
from .models import HTTPRequestRecord, ProbeObservation

SUBSTRING_FUNCTIONS = r"(?:substr|substring|mid)"
ORDINAL_FUNCTIONS = r"(?:ascii|ord|unicode)"
LENGTH_FUNCTIONS = r"(?:length|char_length|len|octet_length)"
TIME_KEYWORDS = ("sleep(", "benchmark(", "pg_sleep(", "waitfor delay", "dbms_lock.sleep", "heavyquery")

# ordinal(substr(expr, pos, 1)) op val   OR  ordinal(substr(expr from pos for 1))
ORDINAL_RE = re.compile(
    rf"(?P<full>{ORDINAL_FUNCTIONS}\s*\(\s*{SUBSTRING_FUNCTIONS}\s*\(\s*(?P<expr>.*?)\s*"
    rf"(?:,\s*(?P<pos>\d+)\s*,\s*(?P<len>\d+)|from\s*(?P<pos2>\d+)\s*for\s*(?P<len2>\d+))\s*\)\s*\)\s*\)*"
    rf"\s*(?P<op>[<>]=?|=)\s*(?P<val>0x[0-9a-fA-F]+|\d+|'[^']*'|\"[^\"]*\"))",
    re.IGNORECASE | re.DOTALL,
)

# substr(expr, pos, 1) op val
CHAR_COMPARE_RE = re.compile(
    rf"(?P<full>{SUBSTRING_FUNCTIONS}\s*\(\s*(?P<expr>.*?)\s*"
    rf"(?:,\s*(?P<pos>\d+)\s*,\s*(?P<len>\d+)|from\s*(?P<pos2>\d+)\s*for\s*(?P<len2>\d+))\s*\)\s*\)*"
    rf"\s*(?P<op>[<>]=?|=)\s*(?P<val>0x[0-9a-fA-F]+|\d+|'[^']*'|\"[^\"]*\"))",
    re.IGNORECASE | re.DOTALL,
)

LENGTH_RE = re.compile(
    rf"(?P<full>{LENGTH_FUNCTIONS}\s*\((?P<expr>.*?)\)\s*(?P<op>[<>]=?|=)\s*(?P<val>\d+))",
    re.IGNORECASE | re.DOTALL,
)

# ord(substr(...)) in (N)
ORDINAL_IN_RE = re.compile(
    rf"(?P<full>{ORDINAL_FUNCTIONS}\s*\(\s*{SUBSTRING_FUNCTIONS}\s*\(\s*(?P<expr>.*?)\s*"
    rf"(?:,\s*(?P<pos>\d+)\s*,\s*(?P<len>\d+)|from\s*(?P<pos2>\d+)\s*for\s*(?P<len2>\d+))\s*\)\s*\)\s*\)*"
    rf"\s*in\s*\(\s*(?P<val>\d+|0x[0-9a-fA-F]+|'[^']*'|\"[^\"]*\")\s*\))",
    re.IGNORECASE | re.DOTALL,
)

# least(ord(substr(...)), N) in (N)  =>  ord >= N
LEAST_ORDINAL_IN_RE = re.compile(
    rf"(?P<full>(?:least|greatest)\s*\(\s*{ORDINAL_FUNCTIONS}\s*\(\s*{SUBSTRING_FUNCTIONS}\s*\(\s*(?P<expr>.*?)\s*"
    rf"(?:,\s*(?P<pos>\d+)\s*,\s*(?P<len>\d+)|from\s*(?P<pos2>\d+)\s*for\s*(?P<len2>\d+))\s*\)\s*\)\s*\)*"
    rf"\s*,\s*(?P<bound>\d+)\s*\)\s*in\s*\(\s*(?P<val>\d+)\s*\))",
    re.IGNORECASE | re.DOTALL,
)


def canonicalize_sql_snippet(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"/\*.*?\*/", " ", lowered)
    lowered = lowered.replace("+", " ")
    lowered = re.sub(r"\s+", " ", lowered).strip()
    lowered = re.sub(r"\bsubstring\b", "substr", lowered)
    lowered = re.sub(r"\bmid\b", "substr", lowered)
    lowered = re.sub(r"\bascii\b", "ord", lowered)
    lowered = re.sub(r"\bunicode\b", "ord", lowered)
    lowered = re.sub(r"\bchar_length\b", "length", lowered)
    lowered = re.sub(r"\boctet_length\b", "length", lowered)
    lowered = re.sub(r"\blen\b", "length", lowered)
    lowered = re.sub(r"\s*,\s*", ",", lowered)
    lowered = re.sub(r"\(\s+", "(", lowered)
    lowered = re.sub(r"\s+\)", ")", lowered)
    # random salt / noise
    lowered = re.sub(r"\bchar\(\d+\)", "char(?)", lowered)
    lowered = re.sub(r"\brand\(\)", "rand()", lowered)
    return lowered


def parse_literal(raw_value: str) -> tuple[int | None, str | None]:
    literal = raw_value.strip()
    if literal.startswith(("'", '"')) and literal.endswith(("'", '"')) and len(literal) >= 2:
        literal = literal[1:-1]
    elif literal.lower().startswith("0x"):
        literal = decode_hex_payload(literal[2:])

    if literal.isdigit() or (literal.startswith("-") and literal[1:].isdigit()):
        return int(literal), literal
    if len(literal) == 1:
        return ord(literal), literal
    return None, literal or None


def normalize_target_key(matched_text: str, position: int | None, candidate_raw: str) -> str:
    normalized = canonicalize_sql_snippet(matched_text)
    # peel wrappers that shouldn't split targets
    normalized = re.sub(r"\bleast\(", "(", normalized)
    normalized = re.sub(r"\bgreatest\(", "(", normalized)
    if position is not None:
        normalized = re.sub(rf",{position},\d+", ",{pos},1", normalized, count=1)
        normalized = re.sub(rf"from\s*{position}\s*for\s*\d+", "from {pos} for 1", normalized, count=1)
    esc = re.escape(candidate_raw.lower())
    normalized = re.sub(rf"([<>]=?|=)\s*{esc}", r"\1{value}", normalized, count=1)
    normalized = re.sub(rf"\bin\s*\(\s*{esc}\s*\)", r"in({value})", normalized, count=1)
    # collapse bound duplicates from least(...,N) in (N)
    normalized = re.sub(r",\d+\)\s*in\(\{value\}\)", ")in({value})", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _pos_and_len(match: re.Match[str]) -> tuple[int, int] | None:
    pos_text = match.groupdict().get("pos") or match.groupdict().get("pos2")
    len_text = match.groupdict().get("len") or match.groupdict().get("len2") or "1"
    if not pos_text:
        return None
    return int(pos_text), int(len_text)


def _looks_time_based(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in TIME_KEYWORDS)


def extract_observations_from_text(text: str, record: HTTPRequestRecord) -> list[ProbeObservation]:
    observations: list[ProbeObservation] = []
    seen_spans: set[tuple[int, int]] = set()
    time_based = _looks_time_based(text)

    def add(obs: ProbeObservation, span: tuple[int, int]) -> None:
        if span in seen_spans:
            return
        # avoid nested duplicate of same span range
        for existing in seen_spans:
            if existing[0] <= span[0] and span[1] <= existing[1]:
                return
        seen_spans.add(span)
        observations.append(obs)

    for match in LEAST_ORDINAL_IN_RE.finditer(text):
        pos_len = _pos_and_len(match)
        if not pos_len:
            continue
        pos, length = pos_len
        if length != 1:
            continue
        bound = int(match.group("bound"))
        val = int(match.group("val"))
        # least(x, N) in (N)  <=>  x >= N when bound == val
        # greatest(x, N) in (N) <=> x <= N
        func = match.group(0).lower()
        operator = ">=" if func.lstrip().startswith("least") or "least(" in canonicalize_sql_snippet(match.group(0)[:20]) else "<="
        head = canonicalize_sql_snippet(match.group(0)[:30])
        operator = ">=" if head.startswith("least") else "<="
        candidate_raw = match.group("val")
        add(
            ProbeObservation(
                kind="ordinal",
                operator=operator,
                position=pos,
                candidate_raw=candidate_raw,
                candidate_int=bound if bound == val else val,
                candidate_text=candidate_raw,
                target_key=normalize_target_key(match.group("full"), pos, candidate_raw),
                request=record,
                time_based=time_based,
            ),
            match.span("full"),
        )

    for match in ORDINAL_IN_RE.finditer(text):
        pos_len = _pos_and_len(match)
        if not pos_len:
            continue
        pos, length = pos_len
        if length != 1:
            continue
        # skip if already covered by least pattern
        span = match.span("full")
        if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
            continue
        candidate_raw = match.group("val")
        candidate_int, candidate_text = parse_literal(candidate_raw)
        add(
            ProbeObservation(
                kind="ordinal",
                operator="=",
                position=pos,
                candidate_raw=candidate_raw,
                candidate_int=candidate_int,
                candidate_text=candidate_text,
                target_key=normalize_target_key(match.group("full"), pos, candidate_raw),
                request=record,
                time_based=time_based,
            ),
            span,
        )

    for match in ORDINAL_RE.finditer(text):
        pos_len = _pos_and_len(match)
        if not pos_len:
            continue
        pos, length = pos_len
        if length != 1:
            continue
        span = match.span("full")
        if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
            continue
        candidate_raw = match.group("val")
        candidate_int, candidate_text = parse_literal(candidate_raw)
        add(
            ProbeObservation(
                kind="ordinal",
                operator=match.group("op"),
                position=pos,
                candidate_raw=candidate_raw,
                candidate_int=candidate_int,
                candidate_text=candidate_text,
                target_key=normalize_target_key(match.group("full"), pos, candidate_raw),
                request=record,
                time_based=time_based,
            ),
            span,
        )

    for match in CHAR_COMPARE_RE.finditer(text):
        pos_len = _pos_and_len(match)
        if not pos_len:
            continue
        pos, length = pos_len
        if length != 1:
            continue
        span = match.span("full")
        # skip if this is inside an ordinal(substr(...)) already matched
        if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
            continue
        # skip substr that is nested inside ordinal(...)
        prefix = text[max(0, span[0] - 20) : span[0]].lower()
        if re.search(r"(?:ascii|ord|unicode)\s*\(\s*$", prefix):
            continue
        candidate_raw = match.group("val")
        candidate_int, candidate_text = parse_literal(candidate_raw)
        add(
            ProbeObservation(
                kind="char",
                operator=match.group("op"),
                position=pos,
                candidate_raw=candidate_raw,
                candidate_int=candidate_int,
                candidate_text=candidate_text,
                target_key=normalize_target_key(match.group("full"), pos, candidate_raw),
                request=record,
                time_based=time_based,
            ),
            span,
        )

    for match in LENGTH_RE.finditer(text):
        span = match.span("full")
        if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
            continue
        value = int(match.group("val"))
        candidate_raw = match.group("val")
        add(
            ProbeObservation(
                kind="length",
                operator=match.group("op"),
                position=None,
                candidate_raw=candidate_raw,
                candidate_int=value,
                candidate_text=candidate_raw,
                target_key=normalize_target_key(match.group("full"), None, candidate_raw),
                request=record,
                time_based=time_based,
            ),
            span,
        )

    return observations


def extract_observations(records: list[HTTPRequestRecord]) -> list[ProbeObservation]:
    observations: list[ProbeObservation] = []
    for record in records:
        observations.extend(extract_observations_from_text(record.haystack, record))
    return observations
