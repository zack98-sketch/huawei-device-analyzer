"""CLI entry point for the Huawei device analyzer.

Usage examples:

    # Analyze a single file
    python -m huawei_analyzer.main -i firewall.cfg -o ./reports

    # Batch-analyze a directory
    python -m huawei_analyzer.main -i ./configs -o ./reports

    # Analyze a log with a time-window filter
    python -m huawei_analyzer.main -i device.log \\
        --log-start "2024-01-15 00:00:00" --log-end "2024-01-15 23:59:59"

Reports are written under <output-dir>/ as .txt and .html, plus a batch
summary when a directory is processed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .checker import ComplianceChecker
from .detector import detect_file_type
from .parsers import FirewallParser, LogParser, SwitchParser, TrafficLogParser
from .reporter import ReportGenerator
from .traffic_analyzer import TrafficAnalyzer

# File extensions considered as input candidates when scanning a directory.
INPUT_EXTS = (".cfg", ".conf", ".txt", ".log", ".csv")


def analyze_file(
    path: Path,
    log_start: str | None = None,
    log_end: str | None = None,
    internal_prefixes: tuple[str, ...] | None = None,
    office_prefixes: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Analyze a single file and return a unified result dict."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "source": str(path),
            "device_type": "error",
            "hostname": "-",
            "config": None,
            "log": None,
            "traffic": None,
            "compliance": None,
            "error": str(exc),
        }

    file_type = detect_file_type(content)
    result: dict[str, Any] = {
        "source": str(path),
        "device_type": file_type,
        "hostname": "-",
        "config": None,
        "log": None,
        "traffic": None,
        "compliance": None,
    }

    if file_type == "firewall":
        cfg = FirewallParser().parse(content)
        result["config"] = cfg
        result["hostname"] = cfg.get("hostname", "-")
        result["compliance"] = ComplianceChecker().check(cfg)
    elif file_type == "switch":
        cfg = SwitchParser().parse(content)
        result["config"] = cfg
        result["hostname"] = cfg.get("hostname", "-")
        result["compliance"] = ComplianceChecker().check(cfg)
    elif file_type == "log":
        log = LogParser().parse(content, start_time=log_start, end_time=log_end)
        result["log"] = log
        for ev in log.get("events", []):
            if ev.get("host"):
                result["hostname"] = ev["host"]
                break
    elif file_type == "traffic_log":
        traffic_raw = TrafficLogParser().parse(
            content, start_time=log_start, end_time=log_end
        )
        analyzer = TrafficAnalyzer(
            internal_prefixes=internal_prefixes or ("10.64",),
            office_prefixes=office_prefixes or ("10.185", "10.186"),
        )
        result["traffic"] = analyzer.analyze(traffic_raw)
        result["hostname"] = Path(result["source"]).stem
    else:
        result["device_type"] = "unknown"
        result["error"] = (
            "无法识别文件类型 (非华为防火墙/交换机配置、VRP 日志或会话表 CSV)。"
            "如为交换机配置，建议提供 .txt 纯文本格式。"
        )

    return result


def write_reports(
    result: dict[str, Any],
    out_dir: Path,
    fmt: str,
    reporter: ReportGenerator,
    idx: int = 0,
) -> list[Path]:
    """Write per-device report(s). Returns list of written file paths."""
    stem = Path(result["source"]).stem or f"device_{idx}"
    safe_stem = f"{idx:03d}_{sanitize(stem)}"
    written: list[Path] = []

    if fmt in ("txt", "both"):
        p = out_dir / f"{safe_stem}.txt"
        p.write_text(reporter.render_device_text(result), encoding="utf-8")
        written.append(p)
    if fmt in ("html", "both"):
        p = out_dir / f"{safe_stem}.html"
        p.write_text(reporter.render_device_html(result), encoding="utf-8")
        written.append(p)
    return written


def sanitize(name: str) -> str:
    keep = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)[:80] or "device"


def collect_inputs(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    files: list[Path] = []
    for entry in sorted(input_path.rglob("*")):
        if entry.is_file() and entry.suffix.lower() in INPUT_EXTS:
            files.append(entry)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="huawei-analyzer",
        description="华为防火墙/交换机配置与日志自动化分析工具",
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="输入文件或目录 (目录将递归扫描 .cfg/.conf/.txt/.log/.csv)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="./reports",
        help="报告输出目录 (默认 ./reports)",
    )
    parser.add_argument(
        "-f", "--format", choices=("txt", "html", "both"), default="both",
        help="报告格式 (默认 both)",
    )
    parser.add_argument(
        "--log-start", default=None,
        help='日志过滤起始时间, 格式 "YYYY-MM-DD HH:MM:SS"',
    )
    parser.add_argument(
        "--log-end", default=None,
        help='日志过滤结束时间, 格式 "YYYY-MM-DD HH:MM:SS"',
    )
    parser.add_argument(
        "--internal-prefixes", default=None,
        help="内网IP前缀列表 (逗号分隔, 默认 10.64), 用于流量日志分类",
    )
    parser.add_argument(
        "--office-prefixes", default=None,
        help="业主办公网IP前缀 (逗号分隔, 默认 10.185,10.186), 视为外部",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="在终端打印每个文件的处理结果摘要",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"错误: 输入路径不存在: {input_path}", file=sys.stderr)
        return 2

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = collect_inputs(input_path)
    if not files:
        print(f"警告: 未在 {input_path} 找到可分析的输入文件 "
              f"(支持的扩展名: {', '.join(INPUT_EXTS)})", file=sys.stderr)
        return 1

    internal_prefixes = None
    if args.internal_prefixes:
        internal_prefixes = tuple(
            p.strip() for p in args.internal_prefixes.split(",") if p.strip()
        )
    office_prefixes = None
    if args.office_prefixes:
        office_prefixes = tuple(
            p.strip() for p in args.office_prefixes.split(",") if p.strip()
        )

    reporter = ReportGenerator()
    results: list[dict[str, Any]] = []
    for idx, f in enumerate(files):
        res = analyze_file(
            f, args.log_start, args.log_end,
            internal_prefixes=internal_prefixes,
            office_prefixes=office_prefixes,
        )
        results.append(res)
        write_reports(res, out_dir, args.format, reporter, idx)
        if args.verbose:
            _print_summary(res)

    # Batch summary when more than one file processed
    if len(results) > 1:
        if args.format in ("txt", "both"):
            p = out_dir / "batch_summary.txt"
            p.write_text(reporter.render_batch_text(results), encoding="utf-8")
            print(f"批量汇总报告: {p}")
        if args.format in ("html", "both"):
            p = out_dir / "batch_summary.html"
            p.write_text(reporter.render_batch_html(results), encoding="utf-8")
            print(f"批量汇总报告: {p}")

    print(f"完成: 共处理 {len(results)} 个文件, 报告输出至 {out_dir}")
    return 0


def _print_summary(res: dict[str, Any]) -> None:
    src = res["source"]
    dt = res["device_type"]
    host = res.get("hostname", "-")
    if dt in ("firewall", "switch"):
        comp = res.get("compliance", {})
        s = comp.get("summary", {})
        print(
            f"  [{dt:12}] {host:16} score={comp.get('compliance_score',0):>3} "
            f"H/M/L={s.get('high',0)}/{s.get('medium',0)}/{s.get('low',0)} "
            f"miss={s.get('missing',0)}  <- {src}"
        )
    elif dt == "log":
        log = res.get("log", {})
        print(
            f"  [{'log':12}] {host:16} events={log.get('total_events',0)} "
            f"critical={len(log.get('critical_events',[]))}  <- {src}"
        )
    elif dt == "traffic_log":
        tr = res.get("traffic", {})
        ob = tr.get("outbound", {})
        ib = tr.get("inbound", {})
        print(
            f"  [{'traffic':12}] {host:16} sessions={tr.get('total_sessions',0):,} "
            f"out={ob.get('total',0):,} in={ib.get('total',0):,}  <- {src}"
        )
    else:
        print(f"  [{dt:12}] {host:16}  <- {src}  ({res.get('error','')})")


if __name__ == "__main__":
    raise SystemExit(main())
