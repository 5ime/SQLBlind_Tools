#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sqlblind.models import Config
from sqlblind.pipeline import run_cli
from sqlblind.report import configure_stdio_utf8, print_banner


DEFAULT_SAMPLE_LIMIT = 12


def parse_arguments() -> Config:
    parser = argparse.ArgumentParser(description="从 PCAP/PCAPNG 或 access 日志中提取 SQL 注入流量，并自动分析/还原盲注结果。")
    parser.add_argument("-f", "--file", required=True, help="PCAP/PCAPNG 或 access 日志文件路径")
    parser.add_argument("-r", "--regexp", help="使用自定义正则表达式从归一化请求中提取数据")
    parser.add_argument("-o", "--output", dest="output_requests", help="将归一化后的 HTTP 请求输出到指定文件")
    parser.add_argument("--json", dest="json_output", help="将分析结果输出为 JSON 文件")
    parser.add_argument(
        "--export-bin",
        dest="export_bin",
        help="将识别到的文件头载荷导出为二进制（png/zip/rar/...）到指定目录",
    )
    parser.add_argument("--top", type=int, default=5, help="终端展示的结果条数，默认 5")
    parser.add_argument("--max-records", type=int, help="最多处理的请求条数（调试用）")
    parser.add_argument(
        "--engine",
        choices=("tshark", "pyshark"),
        default="tshark",
        help="PCAP 解析引擎：tshark(默认，依赖系统 tshark) / pyshark(可选库，同样依赖 tshark)。",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=DEFAULT_SAMPLE_LIMIT,
        help=f"终端中展示的去重请求样本数量，默认 {DEFAULT_SAMPLE_LIMIT}",
    )
    args = parser.parse_args()
    return Config(
        file=Path(args.file),
        regexp=args.regexp,
        output_requests=Path(args.output_requests) if args.output_requests else None,
        json_output=Path(args.json_output) if args.json_output else None,
        export_bin=Path(args.export_bin) if args.export_bin else None,
        sample_limit=args.sample_limit,
        top=max(1, args.top),
        max_records=args.max_records,
        engine=args.engine,
    )


def main() -> int:
    configure_stdio_utf8()
    print_banner()
    config = parse_arguments()
    return run_cli(config)


if __name__ == "__main__":
    raise SystemExit(main())
