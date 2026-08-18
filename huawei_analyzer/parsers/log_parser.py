"""Huawei device log parser.

Parses VRP log lines of the form:

    2024-01-15 10:23:45 HOSTNAME %%01MODULE/SEVERITY/MNEMONIC:detail-string

Also parses structured CSV/TSV log exports (e.g. from Web UI / eSight),
auto-detecting comma or tab delimiters and common Chinese/English column
headers.

Classifies events into six categories (login_fail, perm_change, config_change,
port_status, security_alert, admin_op), supports time-range filtering and
severity-based statistics. Severity follows the VRP standard:

    0 emergencies, 1 alerts, 2 critical, 3 errors,
    4 warnings, 5 notifications, 6 informational, 7 debugging
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any

LOG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"%%\d*(?P<module>[A-Za-z_]+)/"
    r"(?P<severity>[0-7])/"
    r"(?P<mnemonic>[^:\s]+)\s*:\s*"
    r"(?P<detail>.*)$"
)

# Fallback: timestamped line without the %% module marker (common in some
# log export formats). The detail string is matched against keyword patterns.
LOOSE_LOG_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[\sT](?P<time>\d{2}:\d{2}:\d{2})\s+(?P<detail>.*)$"
)

SEVERITY_NAMES = {
    0: "Emergency",
    1: "Alert",
    2: "Critical",
    3: "Error",
    4: "Warning",
    5: "Notification",
    6: "Informational",
    7: "Debug",
}

# Category -> list of (module substring, mnemonic substring, detail keyword)
# First match wins; order matters (more specific first).
CATEGORY_RULES: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        "login_fail",
        [
            ("SEC", "LOGINFAIL", ""),
            ("AAA", "LOGINFAIL", ""),
            ("AAA", "", "login fail"),
            ("AAA", "", "authentication fail"),
            ("DEV", "LOGIN", "fail"),
            ("SEC", "", "login fail"),
            ("SSH", "", "fail"),
            ("TELNET", "", "fail"),
            ("FTP", "", "fail"),
        ],
    ),
    (
        "perm_change",
        [
            ("AAA", "PRIVILEGE", ""),
            ("AAA", "", "privilege"),
            ("CMD", "PRIVILEGE", ""),
            ("SEC", "", "user role"),
            ("SEC", "", "permission"),
        ],
    ),
    (
        "config_change",
        [
            ("CFG", "CONFIG", ""),
            ("CONFIG", "", "configure"),
            ("CMD", "", "system-view"),
            ("VTY", "", "configure"),
            ("CONFIG", "", "commit"),
            ("CFG", "", "save"),
        ],
    ),
    (
        "port_status",
        [
            ("IFNET", "STATE", ""),
            ("LINE", "STATE", ""),
            ("IFPDT", "", "state to"),
            ("IFNET", "", "physical state"),
            ("IFNET", "", "up"),
            ("IFNET", "", "down"),
            ("LINE", "", "change state"),
        ],
    ),
    (
        "security_alert",
        [
            ("SEC", "ATK", ""),
            ("SEC", "ATTACK", ""),
            ("SEC", "", "attack"),
            ("SEC", "", "intrusion"),
            ("SEC", "", "ddos"),
            ("SEC", "", "flood"),
            ("IDS", "", ""),
            ("IPS", "", ""),
            ("SEC", "SCAN", ""),
        ],
    ),
]

# Optional keyword that further narrows a category match (kept for future
# extension / tuning without touching the rule table structure).
# Order matters: first match wins. More specific categories (login_fail,
# security_alert, perm_change) are checked before broader ones (config_change,
# port_status, admin_op) to avoid false positives.
_EXTRA_KEYWORDS: dict[str, list[str]] = {
    "login_fail": ["login failed", "authentication failed", "password error", "login fail"],
    "perm_change": ["privilege", "user role", "permission"],
    "security_alert": ["attack", "intrusion", "ddos", "flood", "scan", "downloaded the file"],
    "config_change": ["configure", "system-view", "commit", "configuration saved", "command=", "recorded command"],
    "port_status": ["state to up", "state to down", "physical state", "link up", "link down", "changed to down", "changed to up"],
    "admin_op": [
        "logged in to web", "logged out of web", "logging in to", "logging out of",
        "comm successfully", "login to web", "logout of web",
    ],
}


def _classify(module: str, mnemonic: str, detail: str) -> str:
    """Return the event category, or 'other' if no rule matches."""
    m_low = module.upper()
    mn_low = mnemonic.upper()
    d_low = detail.lower()
    for category, rules in CATEGORY_RULES:
        for mod_sub, mnem_sub, kw in rules:
            if mod_sub and mod_sub not in m_low:
                continue
            if mnem_sub and mnem_sub not in mn_low:
                continue
            if kw and kw not in d_low:
                continue
            return category
    return "other"


def _parse_ts(date: str, time: str) -> datetime | None:
    """Parse date+time strings, supporting both ``-`` and ``/`` date separators."""
    date = date.strip()
    time = time.strip()
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M",
    ):
        try:
            return datetime.strptime(f"{date} {time}", fmt)
        except ValueError:
            continue
    return None


class LogParser:
    """Parse a Huawei device log file into categorized events."""

    def parse(
        self,
        content: str,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> dict[str, Any]:
        st = self._to_dt(start_time)
        et = self._to_dt(end_time)

        events: list[dict[str, Any]] = []
        csv_rows = self._csv_rows(content)
        if csv_rows is not None:
            columns = self._detect_csv_columns(csv_rows[0])
            # If header didn't reveal a date/timestamp field, skip CSV parsing
            # and fall through to the plain-text path below.
            if any(k in columns for k in ("timestamp", "date", "time")):
                for row in csv_rows[1:]:
                    ev = self._parse_csv_row(row, columns)
                    if ev is None:
                        continue
                    if st and ev["datetime"] and ev["datetime"] < st:
                        continue
                    if et and ev["datetime"] and ev["datetime"] > et:
                        continue
                    events.append(ev)
        else:
            for raw in content.splitlines():
                if not raw.strip():
                    continue
                ev = self._parse_line(raw)
                if ev is None:
                    continue
                if st and ev["datetime"] and ev["datetime"] < st:
                    continue
                if et and ev["datetime"] and ev["datetime"] > et:
                    continue
                events.append(ev)

        # Statistics
        by_category: dict[str, int] = {}
        by_severity: dict[int, int] = {}
        by_severity_name: dict[str, int] = {}
        for ev in events:
            by_category[ev["category"]] = by_category.get(ev["category"], 0) + 1
            sev = ev["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_severity_name[ev["severity_name"]] = (
                by_severity_name.get(ev["severity_name"], 0) + 1
            )

        # Critical events: severity <= 2 (emergency/alert/critical) plus
        # any matched security_alert regardless of numeric severity.
        critical = [
            ev for ev in events if ev["severity"] <= 2 or ev["category"] == "security_alert"
        ]

        ts_sorted = sorted(e["datetime"] for e in events if e["datetime"])
        return {
            "device_type": "log",
            "total_events": len(events),
            "time_range": {
                "start": ts_sorted[0].isoformat(sep=" ") if ts_sorted else None,
                "end": ts_sorted[-1].isoformat(sep=" ") if ts_sorted else None,
                "filter_start": start_time,
                "filter_end": end_time,
            },
            "by_category": by_category,
            "by_severity": by_severity,
            "by_severity_name": by_severity_name,
            "critical_events": critical,
            "events": events,
        }

    def _parse_line(self, raw: str) -> dict[str, Any] | None:
        m = LOG_RE.match(raw)
        if m:
            module = m.group("module")
            sev = int(m.group("severity"))
            mnemonic = m.group("mnemonic")
            detail = m.group("detail")
            category = _classify(module, mnemonic, detail)
            return {
                "raw": raw,
                "datetime": _parse_ts(m.group("date"), m.group("time")),
                "date": m.group("date"),
                "time": m.group("time"),
                "host": m.group("host"),
                "module": module,
                "severity": sev,
                "severity_name": SEVERITY_NAMES.get(sev, "Unknown"),
                "mnemonic": mnemonic,
                "detail": detail,
                "category": category,
            }
        # Loose fallback
        m = LOOSE_LOG_RE.match(raw)
        if m:
            detail = m.group("detail")
            d_low = detail.lower()
            # naive category guess via keywords
            category = "other"
            for cat, kws in _EXTRA_KEYWORDS.items():
                if any(k in d_low for k in kws):
                    category = cat
                    break
            # guess severity from keywords
            sev = self._guess_severity(category, d_low)
            return {
                "raw": raw,
                "datetime": _parse_ts(m.group("date"), m.group("time")),
                "date": m.group("date"),
                "time": m.group("time"),
                "host": "",
                "module": "",
                "severity": sev,
                "severity_name": SEVERITY_NAMES.get(sev, "Unknown"),
                "mnemonic": "",
                "detail": detail,
                "category": category,
            }
        return None

    @staticmethod
    def _guess_severity(category: str, detail_lower: str) -> int:
        if any(k in detail_lower for k in ("attack", "intrusion", "ddos")):
            return 2
        if "downloaded the file" in detail_lower:
            return 3
        if category == "login_fail":
            return 4
        if category == "perm_change":
            return 5
        if category == "config_change":
            return 6
        if category == "port_status":
            return 5
        if category == "admin_op":
            return 6
        if "fail" in detail_lower or "error" in detail_lower:
            return 3
        if "down" in detail_lower and "download" not in detail_lower:
            return 4
        return 6

    @staticmethod
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

    # ====================================================================
    # CSV (structured export) parsing helpers
    # ====================================================================

    # For each logical field, list known header column-name tokens. All strings
    # are compared case-insensitively against lowercase cell values.
    _CSV_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
        "date": ("date", "日期", "记录日期", "发生日期"),
        "time": ("time", "时间", "发生时间", "记录时间"),
        "timestamp": ("timestamp", "时间戳", "datetime", "日期时间"),
        "host": ("host", "hostname", "主机", "主机名", "设备名", "device", "虚拟系统", "vsys", "vrf"),
        "user": ("user", "admin", "administrator", "管理员", "用户名", "用户", "操作用户"),
        "src_ip": ("src_ip", "source_ip", "login_ip", "登录ip", "登录地址", "源ip", "远程ip", "remoteip", "ip"),
        "module": ("module", "模块", "模块名"),
        "severity": ("severity", "level", "级别", "严重级别", "等级"),
        "mnemonic": ("mnemonic", "助记符", "事件名", "event name", "event"),
        "message": (
            "message", "detail", "description", "info", "log",
            "消息", "描述", "详情", "信息", "日志内容", "内容",
        ),
    }

    # Known severity-name -> numeric code (handles both English and Chinese
    # names that appear in InfoCenter / eSight CSV exports).
    _SEV_NAME_TO_NUM: dict[str, int] = {
        # English VRP standard
        "emergencies": 0, "emergency": 0,
        "alerts": 1, "alert": 1,
        "critical": 2, "criticals": 2,
        "errors": 3, "error": 3, "err": 3,
        "warnings": 4, "warning": 4, "warn": 4,
        "notifications": 5, "notification": 5, "notice": 5,
        "informational": 6, "information": 6, "info": 6,
        "debugging": 7, "debug": 7,
        # Chinese aliases
        "紧急": 0, "严重": 1, "紧要": 1, "关键": 2, "致命": 2,
        "错误": 3, "故障": 3,
        "警告": 4, "告警": 4,
        "提示": 5, "通知": 5, "注意": 5,
        "信息": 6, "一般信息": 6,
        "调试": 7,
    }

    def _detect_csv_columns(self, header_row: list[str]) -> dict[str, int]:
        """Map logical field names -> column indexes in a CSV header row.

        Unknowns are simply omitted; the caller should provide graceful
        fallbacks (e.g. guess severity from detail keywords).
        """
        lower = [c.strip().lower() for c in header_row]
        mapping: dict[str, int] = {}
        for logical, tokens in self._CSV_FIELD_CANDIDATES.items():
            for tok in tokens:
                t = tok.lower()
                for idx, col in enumerate(lower):
                    if col and (t == col or t in col):
                        mapping.setdefault(logical, idx)
                        break
                if logical in mapping:
                    break
        return mapping

    def _split_timestamp(self, cell: str) -> tuple[str, str]:
        """Try to split a timestamp cell into (date, time).

        Supports both ``YYYY-MM-DD`` and ``YYYY/MM/DD`` date separators,
        with ``T`` or space between date and time.

        Returns ('', '') on failure so the caller can try separate columns.
        """
        if not cell:
            return "", ""
        cell = cell.strip().strip('"').strip("'")
        # YYYY-MM-DD or YYYY/MM/DD followed by T/space and HH:MM:SS
        m = re.match(r"^(\d{4}[-/]\d{2}[-/]\d{2})[\sT](\d{2}:\d{2}:\d{2})", cell)
        if m:
            return m.group(1), m.group(2)
        # Only date, no time
        m = re.match(r"^(\d{4}[-/]\d{2}[-/]\d{2})", cell)
        if m:
            return m.group(1), "00:00:00"
        return "", ""

    def _severity_to_num(self, cell: str) -> int | None:
        """Convert a CSV severity cell (numeric OR name) to a VRP level."""
        if cell is None:
            return None
        s = str(cell).strip().lower()
        if not s:
            return None
        if s.isdigit():
            v = int(s)
            return v if 0 <= v <= 7 else None
        # fuzzy match against known names (shortest first to prefer "error" over "warning" prefix)
        candidates = sorted(self._SEV_NAME_TO_NUM.keys(), key=len)
        for name in candidates:
            if name in s:
                return self._SEV_NAME_TO_NUM[name]
        return None

    def _csv_rows(self, content: str) -> list[list[str]] | None:
        """Parse CSV/TSV content and return rows, or None if not valid.

        Auto-detects the delimiter (comma or tab) by comparing counts in
        the first non-empty line. Handles UTF-8 BOM.
        """
        if content.startswith("\ufeff"):
            content = content[1:]
        lines = content.splitlines()
        non_empty = [ln for ln in lines if ln.strip()]
        if len(non_empty) < 2:
            return None
        # Auto-detect delimiter: tab vs comma
        first = non_empty[0]
        tab_count = first.count("\t")
        comma_count = first.count(",")
        delimiter = "\t" if tab_count > comma_count else ","
        try:
            reader = csv.reader(io.StringIO(content), delimiter=delimiter)
            rows = [r for r in reader if r and any(c.strip() for c in r)]
        except csv.Error:
            return None
        if len(rows) < 2:
            return None
        # Confirm header has enough fields
        if len(rows[0]) < 3:
            return None
        return rows

    def _parse_csv_row(
        self, row: list[str], columns: dict[str, int]
    ) -> dict[str, Any] | None:
        """Convert a single CSV/TSV row into an event dict compatible with the
        plain-text log format so downstream classification and statistics
        code doesn't have to special-case CSV.
        """
        def get(field: str, default: str = "") -> str:
            idx = columns.get(field)
            if idx is None or idx >= len(row):
                return default
            return (row[idx] or "").strip()

        # timestamp resolution: dedicated timestamp col > date+time cols
        date_s, time_s = "", ""
        if "timestamp" in columns:
            date_s, time_s = self._split_timestamp(get("timestamp"))
        if not date_s and "date" in columns:
            date_s = get("date")
        if not time_s and "time" in columns:
            time_s = get("time")

        # Some exports put a combined `Date/Time` in whichever column
        if not date_s:
            for idx, cell in enumerate(row):
                if cell:
                    d, t = self._split_timestamp(str(cell))
                    if d:
                        date_s, time_s = d, t
                        break
        if not date_s:
            return None

        host = get("host")
        module = get("module")
        mnemonic = get("mnemonic")
        detail = get("message")
        user = get("user")
        src_ip = get("src_ip")
        sev_num = self._severity_to_num(get("severity"))

        category = _classify(module, mnemonic, detail)
        if category == "other":
            # Fall back to keyword classification (same as loose fallback)
            d_low = detail.lower()
            for cat, kws in _EXTRA_KEYWORDS.items():
                if any(k in d_low for k in kws):
                    category = cat
                    break
        if sev_num is None:
            sev_num = self._guess_severity(category, detail.lower())

        sev_name = SEVERITY_NAMES.get(sev_num, "Unknown")
        return {
            "raw": ", ".join(str(c) for c in row if c is not None),
            "datetime": _parse_ts(date_s, time_s),
            "date": date_s,
            "time": time_s,
            "host": host,
            "module": module,
            "severity": sev_num,
            "severity_name": sev_name,
            "mnemonic": mnemonic,
            "detail": detail,
            "category": category,
            "user": user,
            "src_ip": src_ip,
        }
