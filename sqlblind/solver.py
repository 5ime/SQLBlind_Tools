from __future__ import annotations

import re
from collections import defaultdict

from .magic import FLAG_RE, analyze_binary_payload
from .models import AnalysisResult, ProbeObservation
from .signal import TruthClassifier, build_truth_classifier, group_by_target, response_body_metric

# Re-export for callers that historically imported FLAG_RE from solver.
__all__ = ["FLAG_RE", "analyze_builtin_groups", "analyze_custom_regex", "analyze_target"]


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


def numeric_to_display(value: int) -> str:
    """Return display form for an ordinal probe result."""
    if 32 <= value <= 126:
        return chr(value)
    if value < 0 or value > 255:
        return "?"
    return f"\\x{value:02x}"


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
    """Classify recovered blob shape for structured output."""
    payload = analyze_binary_payload(text)
    if payload and payload.magic:
        return payload.magic.name
    without_escapes = re.sub(r"\\x[0-9a-fA-F]{2}", "?", text)
    if FLAG_RE.search(text):
        return "flag"
    letters = sum(1 for ch in without_escapes if ch.isalpha())
    if len(without_escapes) >= 40 and letters / max(len(without_escapes), 1) > 0.55:
        return "text"
    return ""


def enrich_recovered_result(result: AnalysisResult) -> None:
    """Detect file magic, pull embedded flags out of hex/binary recoveries."""
    text = result.recovered_text
    if not text:
        return
    payload = analyze_binary_payload(text)
    if payload is None:
        if not result.shape_hint:
            result.shape_hint = detect_shape(text)
        return

    if payload.magic:
        result.shape_hint = payload.magic.name
        result.file_type = payload.magic.name
        result.file_ext = payload.magic.ext
        result.file_size = len(payload.data)
        result.file_bytes = payload.data
    if payload.embedded_flags:
        result.embedded_flags = payload.embedded_flags
        # Promote embedded flag when the surface text is opaque hex/binary.
        if not FLAG_RE.search(text):
            result.recovered_text = payload.embedded_flags[0]
    elif not result.shape_hint:
        result.shape_hint = payload.magic.name if payload.magic else detect_shape(text)


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
) -> tuple[str, bool]:
    """Return (text, ended_by_all_false)."""
    recovered_characters: list[str] = []
    ended = False

    for position in sorted(position_groups):
        if ended:
            break
        probes = position_groups[position]
        recovered, all_false = infer_group_value(probes, truth_classifier)
        if all_false:
            if recovered_characters:
                ended = True
                break
            recovered_characters.append("?")
            continue
        if recovered is None:
            recovered_characters.append("?")
        elif isinstance(recovered, int):
            recovered_characters.append(numeric_to_display(recovered))
        else:
            recovered_characters.append(recovered)

    text = "".join(recovered_characters)
    if ended:
        text = text.rstrip("?")
    return text, ended


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
    # Run primary first; only invert when recovery looks weak (big win on long hex dumps).
    primary = (truth_classifier, truth_source, confidence)
    allow_invert = truth_classifier is not None and not truth_source.startswith("响应时延")

    def _recover(clf: TruthClassifier | None, src: str, conf: float) -> tuple[tuple[int, int, int, int, int], str, int | None, str, float]:
        inferred_length: int | None = None
        if length_group:
            inferred, _ = infer_group_value(length_group, clf)
            if isinstance(inferred, int) and inferred > 0:
                inferred_length = inferred
        text, _ended = recover_characters(position_groups, clf)
        if inferred_length is not None and inferred_length > 0 and len(text) > inferred_length:
            text = text[:inferred_length]
        flag_match = FLAG_RE.search(text)
        if flag_match and "?" not in flag_match.group(0) and "\\x" not in flag_match.group(0):
            if len(text) <= len(flag_match.group(0)) + 8:
                text = flag_match.group(0)
        return (score_recovered_text(text), text, inferred_length, src, conf)

    best_payload = _recover(*primary)
    if allow_invert:
        score = best_payload[0]
        # Clean flag / high-diversity printable → skip expensive invert pass.
        needs_invert = score[0] == 0 and (score[4] < -2 or score[2] < 8 or score[1] <= 2)
        if needs_invert:
            inverted = _recover(
                invert_classifier(truth_classifier),
                truth_source + " [极性取反]",
                max(0.35, confidence - 0.1),
            )
            if inverted[0] > best_payload[0]:
                best_payload = inverted

    _score, text, inferred_length, src, conf = best_payload
    polarity_flipped = src != truth_source
    result.polarity_confidence = conf if polarity_flipped else confidence

    result.truth_source = src.replace(" [极性取反]", "")
    if polarity_flipped:
        result.truth_source = result.truth_source + "(已校正极性)"
    result.inferred_length = inferred_length
    result.recovered_text = text
    enrich_recovered_result(result)
    return result


def rank_analysis_result(result: AnalysisResult) -> tuple[int, int, int, int, int]:
    highlighted = 1 if (result.embedded_flags or FLAG_RE.search(result.recovered_text or "")) else 0
    text = result.recovered_text or ""
    resolved = len(text) - text.count("?") - text.count("\\x")
    if result.file_size:
        resolved = max(resolved, result.file_size)
    unresolved = text.count("?")
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


def analyze_builtin_groups(observations: list[ProbeObservation]) -> list[AnalysisResult]:
    grouped = group_by_target(observations)
    results = [analyze_target(group) for group in grouped.values()]
    results = [r for r in results if r.recovered_text or r.inferred_length is not None]
    _apply_cross_length_hints(results)
    for result in results:
        enrich_recovered_result(result)
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
