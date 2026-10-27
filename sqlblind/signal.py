from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median
from typing import Callable, Optional

from .models import ProbeObservation
from .probe import TIME_KEYWORDS

TruthClassifier = Callable[[ProbeObservation], Optional[bool]]

TRUTH_TIME_MIN_DELTA = 0.8
TRUTH_TIME_MULTIPLIER = 2.0
MIN_CLUSTER_SHARE = 0.05


def response_body_metric(obs: ProbeObservation) -> int | None:
    req = obs.request
    if req.response_body_length is not None:
        return req.response_body_length
    return req.response_length


def _stable_clusters(counter: Counter, min_count: int = 2) -> list[tuple[object, int]]:
    items = [(k, v) for k, v in counter.items() if v >= min_count]
    items.sort(key=lambda kv: kv[1], reverse=True)
    return items


def _equality_ratio(observations: list[ProbeObservation]) -> float:
    if not observations:
        return 0.0
    eq = sum(1 for o in observations if o.operator == "=")
    return eq / len(observations)


def _pick_truth_key(
    key_a: object,
    count_a: int,
    key_b: object,
    count_b: int,
    observations: list[ProbeObservation],
    key_of,
) -> tuple[object, float, str]:
    """
    Choose which of two response clusters is TRUE.

    Strong prior for equality-dominated traffic: true hits are rare
    (≈ one true probe per character position).
    """
    eq_ratio = _equality_ratio(observations)
    # rarer = true when equality heavy
    rarer = key_a if count_a <= count_b else key_b
    common = key_b if rarer == key_a else key_a

    if eq_ratio >= 0.5:
        # equality: rarer cluster is almost always true
        conf = 0.55 + min(0.35, abs(count_a - count_b) / max(count_a + count_b, 1))
        return rarer, conf, "等值探针稀有簇"

    # mixed / range probes: recover soft score via body preview keywords + rarity
    success_kw = ("success", "you are in", "hello", "flag", "welcome", "correct", "登录", "成功", "存在")
    fail_kw = ("error", "not exist", "incorrect", "no data", "hacker", "失败", "错误", "不存在")

    def preview_score(key: object) -> float:
        score = 0.0
        n = 0
        for o in observations:
            if key_of(o) != key:
                continue
            preview = (o.request.response_body_preview or "").lower()
            n += 1
            if any(k in preview for k in success_kw):
                score += 1.0
            if any(k in preview for k in fail_kw):
                score -= 1.0
        return score / n if n else 0.0

    sa = preview_score(key_a)
    sb = preview_score(key_b)
    if abs(sa - sb) >= 0.15:
        truth = key_a if sa > sb else key_b
        return truth, 0.7, "响应正文语义"

    # fallback: rarer
    return rarer, 0.5, "稀有响应簇"


def build_fingerprint_classifier(
    observations: list[ProbeObservation],
) -> tuple[TruthClassifier | None, str, float]:
    fps = [o.request.response_fingerprint for o in observations if o.request.response_fingerprint]
    if len(fps) < 4:
        return None, "", 0.0
    counts = Counter(fps)
    stable = _stable_clusters(counts, min_count=2)
    if len(stable) < 2:
        return None, "", 0.0

    cluster_a, count_a = stable[0]
    cluster_b, count_b = stable[1]
    if count_b / (count_a + count_b) < MIN_CLUSTER_SHARE:
        return None, "", 0.0

    truth_fp, confidence, reason = _pick_truth_key(
        cluster_a,
        count_a,
        cluster_b,
        count_b,
        observations,
        key_of=lambda o: o.request.response_fingerprint,
    )

    def classifier(observation: ProbeObservation) -> bool | None:
        fp = observation.request.response_fingerprint
        if not fp or fp not in {cluster_a, cluster_b}:
            return None
        return fp == truth_fp

    false_fp = cluster_b if truth_fp == cluster_a else cluster_a
    label = f"响应指纹二元聚类({reason}; 真={counts[truth_fp]}, 假={counts[false_fp]})"
    return classifier, label, confidence


def build_length_classifier(
    observations: list[ProbeObservation],
) -> tuple[TruthClassifier | None, str, float]:
    metrics = [response_body_metric(o) for o in observations if response_body_metric(o) is not None]
    if len(set(metrics)) < 2:
        return None, "", 0.0
    counts = Counter(metrics)
    stable = [(m, c) for m, c in counts.most_common() if c >= 2]
    if len(stable) < 2:
        return None, "", 0.0
    len_a, count_a = stable[0]
    len_b, count_b = stable[1]

    truth_len, confidence, reason = _pick_truth_key(
        len_a,
        count_a,
        len_b,
        count_b,
        observations,
        key_of=response_body_metric,
    )

    def classifier(observation: ProbeObservation) -> bool | None:
        metric = response_body_metric(observation)
        if metric is None or metric not in {len_a, len_b}:
            return None
        return metric == truth_len

    return classifier, f"响应体长度二元聚类({reason}; 真值长度={truth_len})", confidence


def build_time_classifier(
    observations: list[ProbeObservation],
) -> tuple[TruthClassifier | None, str, float]:
    allow = any(o.time_based for o in observations)
    if not allow:
        # Avoid joining full haystacks — scan a small sample of path prefixes only.
        for o in observations[:40]:
            path = o.request.path[:240].lower()
            if any(k in path for k in TIME_KEYWORDS):
                allow = True
                break
    if not allow:
        return None, "", 0.0

    times = [o.request.response_time for o in observations if o.request.response_time is not None]
    if len(times) < 2:
        return None, "", 0.0
    baseline = median(times)
    peak = max(times)
    if not (peak - baseline >= TRUTH_TIME_MIN_DELTA or peak >= max(baseline * TRUTH_TIME_MULTIPLIER, baseline + 0.5)):
        return None, "", 0.0
    threshold = baseline + max(TRUTH_TIME_MIN_DELTA * 0.5, (peak - baseline) / 2.0)

    def classifier(observation: ProbeObservation) -> bool | None:
        value = observation.request.response_time
        return None if value is None else value >= threshold

    return classifier, f"响应时延判定(阈值={threshold:.3f}s)", 0.9


def build_status_classifier(
    observations: list[ProbeObservation],
) -> tuple[TruthClassifier | None, str, float]:
    codes = [o.request.response_code for o in observations if o.request.response_code is not None]
    if len(set(codes)) < 2:
        return None, "", 0.0
    counts = Counter(codes)
    stable = [(c, n) for c, n in counts.most_common() if n >= 2]
    if len(stable) < 2:
        return None, "", 0.0
    rare_code, rare_cnt = min(stable, key=lambda kv: kv[1])
    common_code, common_cnt = max(stable, key=lambda kv: kv[1])
    if rare_cnt / common_cnt > 0.7:
        return None, "", 0.0

    def classifier(observation: ProbeObservation) -> bool | None:
        code = observation.request.response_code
        return None if code is None else code == rare_code

    return classifier, f"状态码判定(稀有码={rare_code})", 0.55


def build_truth_classifier(observations: list[ProbeObservation]) -> tuple[TruthClassifier | None, str, float]:
    """
    Ordering:
    1) time-based when sleep/benchmark present
    2) fingerprint binary clustering
    3) body-length binary clustering
    4) status code
    """
    time_clf, time_label, time_conf = build_time_classifier(observations)
    if time_clf is not None and (
        any(o.time_based for o in observations)
        or sum(1 for o in observations if (o.request.response_time or 0) >= TRUTH_TIME_MIN_DELTA) >= 3
    ):
        return time_clf, time_label, time_conf

    fp_clf, fp_label, fp_conf = build_fingerprint_classifier(observations)
    if fp_clf is not None and fp_conf >= 0.5:
        return fp_clf, fp_label, fp_conf

    len_clf, len_label, len_conf = build_length_classifier(observations)
    if len_clf is not None:
        return len_clf, len_label, len_conf

    if fp_clf is not None:
        return fp_clf, fp_label, fp_conf

    if time_clf is not None:
        return time_clf, time_label, time_conf

    st_clf, st_label, st_conf = build_status_classifier(observations)
    if st_clf is not None:
        return st_clf, st_label, st_conf

    return None, "顺序/趋势回退", 0.2


def group_by_target(observations: list[ProbeObservation]) -> dict[str, list[ProbeObservation]]:
    grouped: dict[str, list[ProbeObservation]] = defaultdict(list)
    for obs in observations:
        grouped[obs.target_key].append(obs)
    return grouped
