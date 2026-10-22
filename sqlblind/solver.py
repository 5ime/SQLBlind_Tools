from __future__ import annotations

import re
from collections import defaultdict

from .models import AnalysisResult, ProbeObservation
from .signal import TruthClassifier, build_truth_classifier, group_by_target, response_body_metric

FLAG_RE = re.compile(r"(?:flag|ctf|dasctf)(\[[^\]]+\]|\{[^}]+\})", re.IGNORECASE)
PNG_HEX_RE = re.compile(r"^89504e47", re.IGNORECASE)
HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def apply_numeric_constraint(
    lower_bound: int | None,
    upper_bound: int | None,
    operator: str,
    value: int,
    is_true: bool,
) -> tuple[int | None, int | None]:
    if operator == ">":
        lower_candidate = value + 1 if is_true else None
        upper_candidate = None if is_true else value
    elif operator == ">=":
        lower_candidate = value if is_true else None
        upper_candidate = None if is_true else value - 1
    elif operator == "<":
        lower_candidate = None if is_true else value
        upper_candidate = value - 1 if is_true else None
    elif operator == "<=":
        lower_candidate = None if is_true else value + 1
        upper_candidate = value if is_true else None
    elif operator == "=":
        if is_true:
            lower_candidate = value
            upper_candidate = value
        else:
            # inequality: cannot tighten to a point; leave bounds
            return lower_bound, upper_bound
    else:
        return lower_bound, upper_bound

    if lower_candidate is not None:
        lower_bound = lower_candidate if lower_bound is None else max(lower_bound, lower_candidate)
    if upper_candidate is not None:
        upper_bound = upper_candidate if upper_bound is None else min(upper_bound, upper_candidate)
    return lower_bound, upper_bound


def infer_trend_truth(current: ProbeObservation, next_probe: ProbeObservation) -> bool | None:
    if current.candidate_int is None or next_probe.candidate_int is None:
        return None
    if next_probe.candidate_int == current.candidate_int:
        return None
    moved_higher = next_probe.candidate_int > current.candidate_int
    if current.operator in {">", ">="}:
        return moved_higher
    if current.operator in {"<", "<="}:
        return not moved_higher
    return None


def choose_numeric_value(
    lower_bound: int | None,
    upper_bound: int | None,
    probes: list[ProbeObservation],
) -> int | None:
    if lower_bound is not None and upper_bound is not None:
        if lower_bound > upper_bound:
            return None
        if lower_bound == upper_bound:
            return lower_bound
        if upper_bound - lower_bound <= 1:
            if any(probe.operator in {">", ">="} for probe in probes):
                return upper_bound
            return lower_bound
        return None
    return None


def infer_equality_by_classifier(
    probes: list[ProbeObservation],
    truth_classifier: TruthClassifier | None,
) -> str | int | None:
    if truth_classifier is None:
        return None
    for probe in probes:
        if probe.operator != "=":
            continue
        truth = truth_classifier(probe)
        if truth:
            if probe.kind == "char" and probe.candidate_text is not None:
                return probe.candidate_text
            if probe.candidate_int is not None:
                return probe.candidate_int
            return probe.candidate_text
    return None


def infer_equality_by_time(probes: list[ProbeObservation]) -> str | int | None:
    timed = [p for p in probes if p.operator == "=" and p.request.response_time is not None]
    if len(timed) < 2:
        return None
    ranked = sorted(timed, key=lambda p: p.request.response_time or 0.0, reverse=True)
    top, second = ranked[0], ranked[1]
    if (top.request.response_time or 0) - (second.request.response_time or 0) < 0.8:
        return None
    if top.kind == "char" and top.candidate_text is not None:
        return top.candidate_text
    if top.candidate_int is not None:
        return top.candidate_int
    return top.candidate_text


def position_all_false(
    probes: list[ProbeObservation],
    truth_classifier: TruthClassifier | None,
) -> bool:
    """True when every probe at this position is classified false (string ended / no match)."""
    if truth_classifier is None or not probes:
        return False
    judged = 0
    for probe in probes:
        value = truth_classifier(probe)
        if value is None:
            continue
        judged += 1
        if value:
            return False
    return judged >= max(3, len(probes) // 4)


def numeric_to_display(value: int) -> tuple[str, str | None]:
    """Return (display_char, note). Non-ASCII ord results are marked."""
    if 32 <= value <= 126:
        return chr(value), None
    if value < 0 or value > 255:
        return "?", f"异常码点 {value}"
    # likely UTF-8 lead / non-printable
    return f"\\x{value:02x}", f"非 ASCII 字节 0x{value:02x}（可能是多字节字符首字节）"


def infer_group_value(
    probes: list[ProbeObservation],
    truth_classifier: TruthClassifier | None,
) -> tuple[str | int | None, bool]:
    """
    Returns (value, all_false).
    all_false means this position has only false probes → string likely ended.
    """
    if position_all_false(probes, truth_classifier):
        return None, True

    time_result = infer_equality_by_time(probes)
    if time_result is not None:
        return time_result, False

    eq_result = infer_equality_by_classifier(probes, truth_classifier)
    if eq_result is not None:
        return eq_result, False

    lower_bound: int | None = None
    upper_bound: int | None = None
    any_truth = False

    for index, probe in enumerate(probes):
        if probe.candidate_int is None:
            continue
        truth_value = truth_classifier(probe) if truth_classifier is not None else None
        if truth_value is None and index + 1 < len(probes):
            truth_value = infer_trend_truth(probe, probes[index + 1])
        if truth_value is None:
            continue
        any_truth = any_truth or truth_value
        lower_bound, upper_bound = apply_numeric_constraint(
            lower_bound, upper_bound, probe.operator, probe.candidate_int, truth_value
        )

    resolved = choose_numeric_value(lower_bound, upper_bound, probes)
    if resolved is not None:
        return resolved, False

    return None, False


def detect_shape(text: str) -> str:
    # Strip \\xHH markers before hex-shape detection so ciphertext with a few
    # non-ASCII bytes is not mislabeled as a hex blob.
    without_escapes = re.sub(r"\\x[0-9a-fA-F]{2}", "?", text)
    hex_only = re.sub(r"[^0-9a-fA-F]", "", without_escapes)
    if PNG_HEX_RE.match(hex_only) or without_escapes.lower().lstrip("?").startswith("89504e47"):
        return "疑似 PNG 十六进制（可用 xxd/unhex 还原图片）"
    if len(hex_only) >= 64 and len(hex_only) >= int(len(without_escapes) * 0.9) and HEX_BLOB_RE.match(hex_only):
        return "疑似长十六进制串"
    if FLAG_RE.search(text):
        return "含 flag 形态"
    letters = sum(1 for ch in without_escapes if ch.isalpha())
    if len(without_escapes) >= 40 and letters / max(len(without_escapes), 1) > 0.55 and not FLAG_RE.search(text):
        return "疑似密文/自然语言文本（盲注已还原原始串，未做二次解密）"
    return ""


def _logical_length(text: str) -> int:
    """Count characters treating \\xHH as one byte."""
    return len(re.sub(r"\\x[0-9a-fA-F]{2}", ".", text))


def score_recovered_text(text: str) -> tuple[int, int, int, int, int]:
    """Higher is better. Used to choose polarity without hardcoding answers."""
    flag_match = FLAG_RE.search(text)
    flag_hit = 1 if flag_match and "?" not in flag_match.group(0) and "\\x" not in flag_match.group(0) else 0
    question = text.count("?")
    logical = _logical_length(text)
    resolved = max(0, logical - question)
    # diversity: punish runs of a single char (wrong polarity often yields !!!! or aaaa)
    compact = re.sub(r"\\x[0-9a-fA-F]{2}", ".", text)
    unique = len(set(compact.replace("?", "")))
    diversity = unique if resolved else 0
    printable = sum(1 for ch in compact if 32 <= ord(ch) <= 126)
    quality = printable - question * 3 + diversity * 2
    return (flag_hit, diversity, resolved, quality, -question)


def invert_classifier(classifier: TruthClassifier) -> TruthClassifier:
    def inverted(observation: ProbeObservation) -> bool | None:
        value = classifier(observation)
        return None if value is None else not value

    return inverted


def recover_characters(
    position_groups: dict[int, list[ProbeObservation]],
    truth_classifier: TruthClassifier | None,
) -> tuple[str, list[str], bool]:
    """Return (text, notes, ended_by_all_false)."""
    notes: list[str] = []
    recovered_characters: list[str] = []
    ended = False
    multibyte_notes = 0

    for position in sorted(position_groups):
        if ended:
            break
        probes = position_groups[position]
        recovered, all_false = infer_group_value(probes, truth_classifier)
        if all_false:
            if recovered_characters:
                ended = True
                notes.append(f"位置 {position} 起探针全假，截断字符串")
                break
            recovered_characters.append("?")
            continue
        if recovered is None:
            recovered_characters.append("?")
        elif isinstance(recovered, int):
            ch, note = numeric_to_display(recovered)
            recovered_characters.append(ch)
            if note:
                multibyte_notes += 1
                if multibyte_notes <= 5:
                    notes.append(f"位置 {position}: {note}")
        else:
            recovered_characters.append(recovered)

    text = "".join(recovered_characters)
    if ended:
        text = text.rstrip("?")
    return text, notes, ended


def analyze_target(observations: list[ProbeObservation]) -> AnalysisResult:
    result = AnalysisResult()
    truth_classifier, truth_source, confidence = build_truth_classifier(observations)
    result.truth_source = truth_source
    result.polarity_confidence = confidence
    result.target_key = observations[0].target_key if observations else ""
    result.observation_count = len(observations)

    position_groups: dict[int, list[ProbeObservation]] = defaultdict(list)
    length_group: list[ProbeObservation] = []
    for observation in observations:
        if observation.kind == "length":
            length_group.append(observation)
        elif observation.position is not None:
            position_groups[observation.position].append(observation)

    # Dual-polarity for length/fingerprint/status (NOT time-based: slow=true is fixed).
    candidates: list[tuple[TruthClassifier | None, str, float]] = [
        (truth_classifier, truth_source, confidence),
    ]
    allow_invert = truth_classifier is not None and not truth_source.startswith("响应时延")
    if allow_invert:
        candidates.append(
            (invert_classifier(truth_classifier), truth_source + " [极性取反]", max(0.35, confidence - 0.1))
        )

    best_payload: tuple[tuple[int, int, int, int, int], str, list[str], int | None, str, float] | None = None

    for clf, src, conf in candidates:
        notes: list[str] = []
        inferred_length: int | None = None
        if length_group:
            inferred, _ = infer_group_value(length_group, clf)
            if isinstance(inferred, int) and inferred > 0:
                inferred_length = inferred
                notes.append(f"推断结果长度: {inferred}")

        text, char_notes, _ended = recover_characters(position_groups, clf)
        notes.extend(char_notes)

        if inferred_length is not None and inferred_length > 0 and len(text) > inferred_length:
            text = text[:inferred_length]
            notes.append(f"按推断长度对齐至 {inferred_length}")

        flag_match = FLAG_RE.search(text)
        if flag_match and "?" not in flag_match.group(0) and "\\x" not in flag_match.group(0):
            if len(text) <= len(flag_match.group(0)) + 8:
                text = flag_match.group(0)

        score = score_recovered_text(text)
        payload = (score, text, notes, inferred_length, src, conf)
        if best_payload is None or payload[0] > best_payload[0]:
            best_payload = payload

    assert best_payload is not None
    _score, text, notes, inferred_length, src, conf = best_payload
    if src != truth_source:
        notes.insert(0, "已按还原质量切换真值极性")
        result.polarity_confidence = conf
    else:
        result.polarity_confidence = confidence

    result.truth_source = src.replace(" [极性取反]", "")
    if "已按还原质量切换真值极性" in notes:
        result.truth_source = result.truth_source + "(已校正极性)"
    result.inferred_length = inferred_length
    result.notes = notes
    result.recovered_text = text
    result.shape_hint = detect_shape(text)
    if result.shape_hint and result.shape_hint not in result.notes:
        result.notes.append(result.shape_hint)
    return result


def rank_analysis_result(result: AnalysisResult) -> tuple[int, int, int, int, int]:
    highlighted = 1 if FLAG_RE.search(result.recovered_text) else 0
    resolved = len(result.recovered_text) - result.recovered_text.count("?") - result.recovered_text.count("\\x")
    unresolved = result.recovered_text.count("?")
    return (highlighted, resolved, -unresolved, result.observation_count, int(result.polarity_confidence * 100))


def _apply_cross_length_hints(results: list[AnalysisResult]) -> None:
    """Use standalone length-probe results to trim sibling string recoveries.

    Only the longest length-only hint is considered, and only when the recovered
    string is slightly longer — avoids short count(*) lengths chopping flags.
    """
    length_only = sorted(
        (r.inferred_length for r in results if r.inferred_length and not r.recovered_text),
        reverse=True,
    )
    if not length_only:
        return
    length = length_only[0]
    if length is None or length < 8:
        return

    for result in results:
        if not result.recovered_text:
            continue
        logical = _logical_length(result.recovered_text)
        delta = logical - length
        # Only trim when recovered is *longer* than the length hint (delta>0).
        # Exact matches are ignored to avoid attaching unrelated length probes.
        if delta <= 0 or delta > max(16, int(length * 0.05)):
            continue
        kept: list[str] = []
        count = 0
        i = 0
        text = result.recovered_text
        while i < len(text) and count < length:
            if text.startswith("\\x", i) and i + 4 <= len(text) and re.match(r"\\x[0-9a-fA-F]{2}", text[i : i + 4]):
                kept.append(text[i : i + 4])
                i += 4
            else:
                kept.append(text[i])
                i += 1
            count += 1
        result.recovered_text = "".join(kept)
        result.inferred_length = length
        note = f"按交叉长度探针对齐至 {length}"
        if note not in result.notes:
            result.notes.append(note)


def analyze_builtin_groups(observations: list[ProbeObservation]) -> list[AnalysisResult]:
    grouped = group_by_target(observations)
    results = [analyze_target(group) for group in grouped.values()]
    results = [r for r in results if r.recovered_text or r.inferred_length is not None]
    _apply_cross_length_hints(results)
    return sorted(results, key=rank_analysis_result, reverse=True)


def analyze_custom_regex(records: list, pattern: str) -> list[str]:
    matches: list[str] = []
    compiled = re.compile(pattern, re.IGNORECASE)
    for record in records:
        for match in compiled.finditer(record.rendered):
            groups = [g for g in match.groups() if g is not None]
            if not groups:
                matches.append(match.group(0))
            elif len(groups) == 1:
                matches.append(groups[0])
            else:
                matches.append(" | ".join(groups))
    return matches
