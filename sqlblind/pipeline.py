from __future__ import annotations

from pathlib import Path

from .capture import build_records, extract_http_from_pcap
from .models import AnalysisResult, Config, HTTPRequestRecord, ToolError
from .probe import extract_observations
from .report import (
    colorize,
    export_binary_payloads,
    export_requests,
    print_builtin_analysis,
    print_custom_analysis,
    print_request_samples,
    summarize_capture,
    write_json_report,
    ANSI_BLUE,
    ANSI_GREEN,
    ANSI_MAGENTA,
    ANSI_RED,
)
from .solver import analyze_builtin_groups, analyze_custom_regex


def validate_input_file(file_path: Path) -> None:
    if not file_path.exists():
        raise ToolError(f"文件不存在: {file_path}")
    if not file_path.is_file():
        raise ToolError(f"不是有效文件: {file_path}")


def run_analysis(config: Config) -> tuple[list[HTTPRequestRecord], list[AnalysisResult]]:
    validate_input_file(config.file)
    request_rows, response_rows = extract_http_from_pcap(config)
    records = build_records(request_rows, response_rows)
    if config.max_records is not None:
        records = records[: max(0, config.max_records)]
    if not records:
        return [], []
    observations = extract_observations(records)
    results = analyze_builtin_groups(observations) if observations else []
    return records, results


def run_cli(config: Config) -> int:
    try:
        validate_input_file(config.file)
        request_rows, response_rows = extract_http_from_pcap(config)
        records = build_records(request_rows, response_rows)
        if config.max_records is not None:
            records = records[: max(0, config.max_records)]
    except ToolError as exc:
        print(colorize(f"[!] {exc}", ANSI_RED))
        return 1

    if not records:
        print(colorize("[!] 未在流量中解析到 HTTP 请求。", ANSI_RED))
        return 1

    print(colorize("[-] 流量概览:", ANSI_BLUE), summarize_capture(records))
    print_request_samples(records, max(1, config.sample_limit))

    if config.output_requests:
        export_requests(records, config.output_requests)
        print(colorize("[+] 归一化请求已输出到:", ANSI_GREEN), str(config.output_requests))

    if config.regexp:
        print(colorize("[*] 自定义正则:", ANSI_MAGENTA), config.regexp)
        print_custom_analysis(analyze_custom_regex(records, config.regexp))
        return 0

    observations = extract_observations(records)
    if not observations:
        print(colorize("[!] 未识别到内置支持的 SQL 注入探针。", ANSI_RED))
        return 1

    print(colorize("[*] 识别到探针数量:", ANSI_MAGENTA), str(len(observations)))
    analysis_results = analyze_builtin_groups(observations)
    if not analysis_results:
        print(colorize("[!] 已识别探针，但未能恢复有效结果。", ANSI_RED))
        return 1

    print(colorize("[*] 识别到目标数量:", ANSI_MAGENTA), str(len(analysis_results)))
    top_results = analysis_results[: config.top]
    if config.export_bin is not None:
        n = export_binary_payloads(top_results, config.export_bin)
        if n:
            print(colorize("[+] 二进制已导出:", ANSI_GREEN), str(config.export_bin), f"({n} files)")
    for index, result in enumerate(top_results, start=1):
        print_builtin_analysis(result, index=index)

    write_json_report(config, records, top_results)
    return 0
