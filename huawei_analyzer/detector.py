"""Device type auto-detection based on configuration features.

Identifies whether a file is a Huawei firewall config, switch config,
or device log file by scanning for characteristic keywords.
"""

from __future__ import annotations

import csv
import io
import re

# Configuration keywords that strongly indicate a firewall config (USG/NGFW).
FIREWALL_KEYWORDS = (
    "firewall zone",
    "security-policy",
    "nat-policy",
    "nat address-group",
    "ip service set",
    "firewall interzone",
    "detect",
)

# Configuration keywords that strongly indicate a switch config (S-series/CE).
SWITCH_KEYWORDS = (
    "vlan batch",
    "interface Vlanif",
    "port link-type",
    "port trunk allow-pass",
    "port access vlan",
    "stp mode",
    "stp bpdu-protection",
    "traffic-filter",
)

# Huawei VRP log line pattern:
#   2024-01-15 10:23:45 HOSTNAME %%01MODULE/SEVERITY/MNEMONIC:message
LOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*%%\d{2}\w+/[0-7]/\w+",
    re.IGNORECASE,
)

# Loose date-prefixed line (used as secondary signal for log files).
DATE_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}")

# CSV column-name tokens that, when appearing on the header line, suggest a
# structured Huawei log export (e.g. InfoCenter CSV export, exported from
# eSight / web-based log viewer / admin operation log).
CSV_LOG_COLUMNS = (
    # English
    "date", "time", "timestamp", "host", "hostname", "module",
    "severity", "level", "mnemonic", "message", "log", "detail",
    "user", "admin", "src_ip", "login_ip", "vsys", "vrf",
    # Chinese
    "日期", "时间", "时间戳", "主机", "主机名", "模块",
    "级别", "严重级别", "助记符", "消息", "描述", "信息", "日志", "内容",
    "管理员", "用户", "登录ip", "登录地址", "虚拟系统",
)


def _csv_looks_like_log(content: str) -> bool:
    """Return True if the content looks like a CSV/TSV log export.

    Heuristics applied in order (cheap ones first):
      1. First non-empty line has >= 2 field separators (commas or tabs).
      2. Header (first row) contains >= 2 known log column tokens (counts
         distinct logical tokens so duplicate hits collapse).
      3. >= 20% of subsequent rows contain timestamp evidence. Timestamp
         evidence is either:
         a) a single cell containing a combined YYYY-MM-DD HH:MM:SS value
            (with ``-`` or ``/`` date separators),
         b) a dedicated date col combined with a time col.
    """
    lines = content.splitlines()
    non_empty = [ln for ln in lines if ln.strip()]
    if len(non_empty) < 2:
        return False
    header = non_empty[0]
    tab_count = header.count("\t")
    comma_count = header.count(",")
    if tab_count < 2 and comma_count < 2:
        return False
    # Auto-detect delimiter
    delimiter = "\t" if tab_count > comma_count else ","
    try:
        reader = csv.reader(io.StringIO(content), delimiter=delimiter)
        rows = [r for r in reader if r and any(c.strip() for c in r)]
    except csv.Error:
        return False
    if len(rows) < 2:
        return False
    header_cols = [c.strip().lower() for c in rows[0]]
    header_hits = 0
    seen_tok: set[str] = set()
    for tok in CSV_LOG_COLUMNS:
        for h in header_cols:
            if tok in h and tok not in seen_tok:
                seen_tok.add(tok)
                header_hits += 1
                break
    if header_hits < 2:
        return False
    # Locate date/time column indexes by header token matching
    date_idx: int | None = None
    time_idx: int | None = None
    for idx, col in enumerate(header_cols):
        if date_idx is None and any(
            t in col for t in ("date", "timestamp", "datetime", "日期", "时间戳", "日期时间")
        ):
            date_idx = idx
        if time_idx is None and any(t in col for t in ("time", "时间")):
            time_idx = idx
    # When a single column holds both date and time, "时间" matches both
    # date_idx and time_idx — that's fine; the combined-ts regex below
    # handles it.
    combined_ts_re = re.compile(r"\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2}")
    date_only_re = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
    time_only_re = re.compile(r"^\d{2}:\d{2}(:\d{2})?$")
    data_rows = rows[1:]

    def _has_ts(row: list[str]) -> bool:
        if any(combined_ts_re.search(c or "") for c in row):
            return True
        if date_idx is not None and date_idx < len(row):
            d = (row[date_idx] or "").strip()
            if date_only_re.match(d):
                if time_idx is not None and time_idx != date_idx and time_idx < len(row):
                    t = (row[time_idx] or "").strip()
                    if time_only_re.match(t):
                        return True
                # A date-only cell still counts as timestamp evidence for
                # detection (time defaulted to 00:00:00 during parse).
                return True
        return False

    ts_count = sum(1 for r in data_rows if _has_ts(r))
    return ts_count > 0 and ts_count / max(1, len(data_rows)) >= 0.2


def detect_file_type(content: str) -> str:
    """Return one of: 'firewall', 'switch', 'log', 'unknown'.

    The detection scans the entire file content for characteristic tokens.
    A file is classified as a log when a meaningful fraction of lines match
    the VRP log header pattern; otherwise configuration keyword counts win.
    Comma-separated CSV log exports are handled via a dedicated heuristic.
    """
    if not content:
        return "unknown"

    # CSV log detection: run first because CSV exports (especially with
    # Chinese column headers) rarely match the plain-text line regexes.
    if _csv_looks_like_log(content):
        return "log"

    lines = content.splitlines()
    total_lines = len(lines) or 1

    # Count VRP log-style lines.
    log_hits = sum(1 for ln in lines if LOG_LINE_RE.match(ln))
    # A more lenient timestamped-line count, in case the %% module marker is
    # missing (some export formats strip it).
    ts_hits = sum(1 for ln in lines if DATE_PREFIX_RE.match(ln))

    if log_hits >= 3 or (log_hits >= 1 and log_hits / total_lines >= 0.3):
        return "log"
    if ts_hits and ts_hits / total_lines >= 0.5 and log_hits == 0:
        # Timestamped lines but no module markers -> still treat as log.
        return "log"

    # Configuration keyword counting.
    fw_hits = sum(content.count(kw) for kw in FIREWALL_KEYWORDS)
    sw_hits = sum(content.count(kw) for kw in SWITCH_KEYWORDS)

    if fw_hits > sw_hits and fw_hits > 0:
        return "firewall"
    if sw_hits > fw_hits and sw_hits > 0:
        return "switch"
    if fw_hits == sw_hits and fw_hits > 0:
        # Ambiguous: default to firewall (firewall configs also frequently
        # contain vlan/interface stanzas, but security-policy wins).
        return "firewall"
    return "unknown"
