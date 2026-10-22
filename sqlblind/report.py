from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Iterable

from .models import AnalysisResult, Config, HTTPRequestRecord
from .solver import FLAG_RE

ANSI_RESET = "\033[0m"
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[96m"
ANSI_MAGENTA = "\033[35m"


def configure_stdio_utf8() -> None:
    def _reconfigure(stream: object) -> None:
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    _reconfigure(sys.stdout)
    _reconfigure(sys.stderr)


def supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return True


def colorize(text: str, color: str) -> str:
    if not supports_ansi():
        return text
    return f"{color}{text}{ANSI_RESET}"


def print_banner() -> None:
    print(
        """  _________      .__ __________.__  .__            .___  ___________           .__          
 /   _____/ _____|  |\\______   \\  | |__| ____    __| _/  \\__    ___/___   ____ |  |   ______
 \\_____  \\\\ / ____/  | |    |  _/  | |  |/    \\  / __ |     |    | /  _ \\ /  _ \\|  |  /  ___/
 /        < <_|  |  |_|    |   \\  |_|  |   |  \\/ /_/ |     |    |(  <_> |  <_> )  |__\\___ \\ 
/_______  /\\__   |____/______  /____/__|___|  /\\____ |_____|____| \\____/ \\____/|____/____  >
        \\/    |__|           \\/             \\/      \\/_____/                             \\/  
                                                                            author: iami233
                                                                            version: 2.0.0"""
    )


def export_requests(records: Iterable[HTTPRequestRecord], output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", errors="replace") as handle:
        for record in records:
            handle.write(record.rendered)
            handle.write("\n" + ("-" * 80) + "\n")


def deduplicate_preserve_order(records: list[HTTPRequestRecord]) -> list[HTTPRequestRecord]:
    seen: set[str] = set()
    unique: list[HTTPRequestRecord] = []
    for record in records:
        signature = record.rendered
        if signature in seen:
            continue
        seen.add(signature)
        unique.append(record)
    return unique


def summarize_capture(records: list[HTTPRequestRecord]) -> str:
    total = len(records)
    post_count = sum(1 for item in records if item.method == "POST")
    gopher_count = sum(1 for item in records if item.source == "gopher-http")
    return f"总请求数: {total} | POST: {post_count} | gopher 封装内层请求: {gopher_count}"


def print_request_samples(records: list[HTTPRequestRecord], sample_limit: int) -> None:
    unique_records = deduplicate_preserve_order(records)
    print(colorize("[-] HTTP 请求取样...", ANSI_BLUE))
    for record in unique_records[:sample_limit]:
        print(record.rendered)
        print("-" * 80)


def highlight_flag(value: str) -> str:
    if not supports_ansi():
        return value
    return FLAG_RE.sub(lambda match: f"{ANSI_RED}{match.group(0)}{ANSI_RESET}", value)


def print_builtin_analysis(result: AnalysisResult, index: int | None = None) -> None:
    if index is not None:
        print(colorize(f"[*] 目标 {index}:", ANSI_MAGENTA), result.target_key)
    print(colorize("[*] 判定方式:", ANSI_MAGENTA), result.truth_source)
    print(colorize("[*] 极性置信度:", ANSI_MAGENTA), f"{result.polarity_confidence:.2f}")
    for note in result.notes:
        print(colorize("[*] " + note, ANSI_MAGENTA))

    if result.recovered_text:
        print(colorize("[+] 提取到的数据:", ANSI_GREEN))
        display = result.recovered_text
        if len(display) > 500:
            print(highlight_flag(display[:500]) + f"... ({len(display)} chars)")
        else:
            print(highlight_flag(display))
    elif result.inferred_length is not None:
        print(colorize("[!] 仅推断出长度，未能还原字符内容。", ANSI_YELLOW))
    else:
        print(colorize("[!] 未能从内置规则中恢复结果，请尝试自定义正则。", ANSI_RED))


def print_custom_analysis(matches: list[str]) -> None:
    if not matches:
        print(colorize("[!] 自定义正则未匹配到数据。", ANSI_RED))
        return
    print(colorize("[+] 自定义正则匹配结果:", ANSI_GREEN))
    for value in matches:
        print(highlight_flag(value))


def write_json_report(config: Config, records: list[HTTPRequestRecord], results: list[AnalysisResult]) -> None:
    if config.json_output is None:
        return
    config.json_output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "file": str(config.file),
        "summary": summarize_capture(records),
        "results": [item.to_dict() for item in results],
    }
    with config.json_output.open("w", encoding="utf-8", errors="replace") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
