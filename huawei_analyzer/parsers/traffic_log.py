"""Huawei firewall session/traffic table CSV parser.

Parses session-table exports (``display session table`` / eSight traffic
exports) with columns such as 虚拟系统, 协议, 安全策略, 入接口, 出接口,
源安全区域, 源地址, 源端口, 目的安全区域, 目的地址, 目的端口,
开始时间, 结束时间.

Auto-detects comma/tab delimiters and common Chinese/English column headers.
The parsed result is consumed by :class:`~huawei_analyzer.traffic_analyzer.
TrafficAnalyzer` for security-oriented aggregation.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any


# For each logical field, list known header column-name tokens. Comparison is
# case-insensitive substring match against the lowercased cell value.
_COLUMN_CANDIDATES: dict[str, tuple[str, ...]] = {
    "vsys": ("虚拟系统", "vsys", "vrf"),
    "protocol": ("协议", "protocol", "proto"),
    "policy": ("安全策略", "policy", "security-policy"),
    "in_interface": ("入接口", "input-interface", "in-interface", "inputif"),
    "out_interface": ("出接口", "output-interface", "out-interface", "outputif"),
    "src_zone": ("源安全区域", "source-zone", "src-zone", "源安全域"),
    "src_ip": ("源地址", "source-address", "src-ip", "source-ip", "源ip"),
    "src_port": ("源端口", "source-port", "src-port"),
    "dst_zone": ("目的安全区域", "destination-zone", "dst-zone", "目的安全域"),
    "dst_ip": ("目的地址", "destination-address", "dst-ip", "dest-ip", "目的ip"),
    "dst_port": ("目的端口", "destination-port", "dst-port"),
    "start_time": ("开始时间", "start-time", "start", "起始时间"),
    "end_time": ("结束时间", "end-time", "end", "终止时间"),
}

# Minimum required columns to classify a CSV as a traffic/session log.
_REQUIRED_FIELDS = ("src_ip", "dst_ip", "protocol")

# Combined timestamp regex (YYYY-MM-DD or YYYY/MM/DD + HH:MM:SS).
_TS_RE = re.compile(r"(\d{4}[-/]\d{2}[-/]\d{2})[\sT](\d{2}:\d{2}:\d{2})")


class TrafficLogParser:
    """Parse Huawei firewall session/traffic table CSV exports."""

    device_type = "traffic_log"

    def parse(
        self,
        content: str,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        rows = self._csv_rows(content)
        if rows is None or len(rows) < 2:
            return self._empty_result("无法识别为流量/会话日志 CSV")

        columns = self._detect_columns(rows[0])
        missing = [f for f in _REQUIRED_FIELDS if f not in columns]
        if missing:
            return self._empty_result(
                f"缺少必要列: {missing} (已识别: {list(columns.keys())})"
            )

        st = _to_dt(start_time)
        et = _to_dt(end_time)

        sessions: list[dict[str, Any]] = []
        for row in rows[1:]:
            if not row or not any(c.strip() for c in row):
                continue
            sess = self._parse_row(row, columns)
            if sess is None:
                continue
            if st and sess["datetime"] and sess["datetime"] < st:
                continue
            if et and sess["datetime"] and sess["datetime"] > et:
                continue
            sessions.append(sess)

        timestamps = sorted(
            s["datetime"] for s in sessions if s["datetime"]
        )
        return {
            "device_type": self.device_type,
            "total_sessions": len(sessions),
            "columns": list(columns.keys()),
            "time_range": {
                "start": timestamps[0].isoformat(sep=" ") if timestamps else None,
                "end": timestamps[-1].isoformat(sep=" ") if timestamps else None,
                "filter_start": start_time,
                "filter_end": end_time,
            },
            "sessions": sessions,
            "error": None,
        }

    # ------------------------------------------------------------------
    # CSV helpers
    # ------------------------------------------------------------------
    def _csv_rows(self, content: str) -> list[list[str]] | None:
        """Parse CSV/TSV content. Returns rows or None."""
        if content.startswith("\ufeff"):
            content = content[1:]
        lines = [ln for ln in content.splitlines() if ln.strip()]
        if len(lines) < 2:
            return None
        first = lines[0]
        tab_count = first.count("\t")
        comma_count = first.count(",")
        delimiter = "\t" if tab_count > comma_count else ","
        try:
            reader = csv.reader(io.StringIO(content), delimiter=delimiter)
            return [r for r in reader if r and any(c.strip() for c in r)]
        except csv.Error:
            return None

    def _detect_columns(self, header_row: list[str]) -> dict[str, int]:
        """Map logical field names -> column indexes."""
        lower = [c.strip().lower() for c in header_row]
        mapping: dict[str, int] = {}
        for logical, tokens in _COLUMN_CANDIDATES.items():
            for tok in tokens:
                t = tok.lower()
                for idx, col in enumerate(lower):
                    if col and (t == col or t in col):
                        mapping.setdefault(logical, idx)
                        break
                if logical in mapping:
                    break
        return mapping

    def _parse_row(
        self, row: list[str], columns: dict[str, int]
    ) -> dict[str, Any] | None:
        def get(field: str, default: str = "") -> str:
            idx = columns.get(field)
            if idx is None or idx >= len(row):
                return default
            return (row[idx] or "").strip()

        src_ip = get("src_ip")
        dst_ip = get("dst_ip")
        protocol = get("protocol")
        if not src_ip or not dst_ip:
            return None

        start_raw = get("start_time")
        end_raw = get("end_time")
        dt = _parse_ts_cell(start_raw) or _parse_ts_cell(end_raw)

        # Normalize protocol: "UDP(53)" / "UDP/53" / "UDP 53" -> "UDP/53"
        proto = protocol
        m = re.match(r"(\w+)\s*[\(\(]?(\d+)[\)\)]?", protocol)
        if m:
            proto = f"{m.group(1)}/{m.group(2)}"

        return {
            "vsys": get("vsys"),
            "protocol": proto,
            "raw_protocol": protocol,
            "policy": get("policy"),
            "in_interface": get("in_interface"),
            "out_interface": get("out_interface"),
            "src_zone": get("src_zone"),
            "src_ip": src_ip,
            "src_port": get("src_port"),
            "dst_zone": get("dst_zone"),
            "dst_ip": dst_ip,
            "dst_port": get("dst_port"),
            "start_time": start_raw,
            "end_time": end_raw,
            "datetime": dt,
        }

    @staticmethod
    def _empty_result(error: str) -> dict[str, Any]:
        return {
            "device_type": "traffic_log",
            "total_sessions": 0,
            "columns": [],
            "time_range": {"start": None, "end": None},
            "sessions": [],
            "error": error,
        }


def _parse_ts_cell(cell: str) -> datetime | None:
    """Parse a timestamp cell (YYYY-MM-DD HH:MM:SS or YYYY/MM/DD ...)."""
    if not cell:
        return None
    cell = cell.strip()
    m = _TS_RE.search(cell)
    if m:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(f"{m.group(1)} {m.group(2)}", fmt)
            except ValueError:
                continue
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(cell, fmt)
        except ValueError:
            continue
    return None


def _to_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M",
        "%Y-%m-%d", "%Y/%m/%d",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None
