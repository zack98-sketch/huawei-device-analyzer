"""Flask web application for the Huawei device analyzer.

Reuses the existing `huawei_analyzer` package (parsers, checker, reporter)
and exposes a small REST + HTML surface:

    GET  /                      main UI (upload + results)
    POST /api/analyze           accept multipart uploads, run analysis,
                                return JSON with per-file results + summary
    GET  /api/report/<job>/<f>  download a single .txt or .html report
    GET  /api/batch/<job>       download the batch summary (.txt or .html)

The web app is stateless: uploaded files are written to a temp job directory,
analyzed, and the generated reports are served back. Old jobs are cleaned up
on a best-effort basis when a new analysis is submitted.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory,
)

# Make the sibling `huawei_analyzer` package importable when this file is run
# directly (e.g. `python web/app.py`) without installing the package.
_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
import sys

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from huawei_analyzer.checker import ComplianceChecker  # noqa: E402
from huawei_analyzer.detector import detect_file_type  # noqa: E402
from huawei_analyzer.parsers import (  # noqa: E402
    FirewallParser,
    LogParser,
    SwitchParser,
    TrafficLogParser,
)
from huawei_analyzer.reporter import ReportGenerator  # noqa: E402
from huawei_analyzer.traffic_analyzer import TrafficAnalyzer  # noqa: E402

# Where uploaded files and generated reports for a job are stored.
JOBS_DIR = Path(
    os.environ.get("HUAWEI_ANALYZER_JOBS_DIR", _PROJECT_ROOT / "web_jobs")
)
JOBS_DIR.mkdir(parents=True, exist_ok=True)

# Keep at most this many old job directories to bound disk usage.
MAX_KEPT_JOBS = 20
# Accepted upload extensions (case-insensitive).
ALLOWED_EXTS = {".cfg", ".conf", ".txt", ".log", ".csv"}
# Max single upload size: 32 MB. Most Huawei config exports fit comfortably.
MAX_CONTENT_LENGTH = 32 * 1024 * 1024

app = Flask(__name__, template_folder=str(_HERE / "templates"), static_folder=str(_HERE / "static"))
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

_reporter = ReportGenerator()
_checker = ComplianceChecker()
_traffic_analyzer = TrafficAnalyzer()


# ---------------------------------------------------------------------------
# Routes: pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes: API
# ---------------------------------------------------------------------------
@app.post("/api/analyze")
def api_analyze():
    """Analyze uploaded files and return a JSON summary.

    Form fields:
      files      : one or more uploaded files (multipart)
      log_start  : optional "YYYY-MM-DD HH:MM:SS"
      log_end    : optional "YYYY-MM-DD HH:MM:SS"

    Returns: {
        job: <id>,
        summary: {...aggregate stats...},
        results: [ {name, device_type, hostname, score, summary, has_txt, has_html} ... ]
    }
    """
    files = request.files.getlist("files")
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "未选择文件"}), 400

    log_start = (request.form.get("log_start") or "").strip() or None
    log_end = (request.form.get("log_end") or "").strip() or None

    job_id = uuid.uuid4().hex[:12]
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    _cleanup_old_jobs()

    results: list[dict[str, Any]] = []
    idx = 0
    for f in files:
        if not f.filename:
            continue
        name = Path(f.filename).name
        ext = Path(name).suffix.lower()
        if ext not in ALLOWED_EXTS:
            results.append(
                {
                    "name": name,
                    "device_type": "skipped",
                    "hostname": "-",
                    "score": None,
                    "summary": None,
                    "has_txt": False,
                    "has_html": False,
                }
            )
            continue
        saved = job_dir / _safe_name(name)
        f.save(saved)
        res = _analyze_one(saved, log_start, log_end, idx)
        results.append(res)
        idx += 1

    # Generate per-file reports.
    for i, res in enumerate(results):
        if res["device_type"] in ("firewall", "switch", "log", "traffic_log"):
            stem = f"{i:03d}_{_safe_name(Path(res['name']).stem)}"
            txt_path = job_dir / f"{stem}.txt"
            html_path = job_dir / f"{stem}.html"
            txt_path.write_text(
                _reporter.render_device_text(_to_report_input(res)),
                encoding="utf-8",
            )
            html_path.write_text(
                _reporter.render_device_html(_to_report_input(res)),
                encoding="utf-8",
            )
            res["has_txt"] = True
            res["has_html"] = True
            res["report_stem"] = stem

    # Batch summary (when more than one analyzable file).
    batch_stem = None
    analyzable = [
        r for r in results
        if r["device_type"] in ("firewall", "switch", "log", "traffic_log")
    ]
    if len(analyzable) > 1:
        batch_stem = "batch_summary"
        (job_dir / f"{batch_stem}.txt").write_text(
            _reporter.render_batch_text([_to_report_input(r) for r in analyzable]),
            encoding="utf-8",
        )
        (job_dir / f"{batch_stem}.html").write_text(
            _reporter.render_batch_html([_to_report_input(r) for r in analyzable]),
            encoding="utf-8",
        )

    summary = _aggregate(results)

    return jsonify(
        {
            "job": job_id,
            "summary": summary,
            "results": results,
            "batch_stem": batch_stem,
            "log_start": log_start,
            "log_end": log_end,
        }
    )


@app.get("/api/report/<job>/<stem>.<fmt>")
def api_report(job, stem, fmt):
    """Download or inline-view a single generated report file.

    fmt is 'txt' or 'html'. HTML is served inline (Content-Type text/html) so
    that the browser can render it directly; txt is sent as an attachment.
    """
    if not _is_safe_token(job) or not _is_safe_token(stem):
        return ("Invalid request", 400)
    if fmt not in ("txt", "html"):
        return ("Unsupported format", 400)
    path = JOBS_DIR / job / f"{stem}.{fmt}"
    if not path.is_file():
        return ("Not found", 404)
    if fmt == "html":
        return send_from_directory(path.parent, path.name, mimetype="text/html")
    return send_file(path, as_attachment=True, download_name=f"{stem}.{fmt}")


@app.get("/api/batch/<job>/<stem>.<fmt>")
def api_batch(job, stem, fmt):
    """Alias endpoint kept for explicitness; same behavior as /api/report."""
    return api_report(job, stem, fmt)


# ---------------------------------------------------------------------------
# Routes: product documentation (decompiled CHM)
# ---------------------------------------------------------------------------
# Drop the decompiled .chm output (HTML + assets) into this directory, or point
# HUAWEI_ANALYZER_DOCS_DIR at it. The .chm is a compiled HTML Help binary; it
# must be decompiled once (see /docs placeholder for the command).
DOCS_DIR = Path(
    os.environ.get("HUAWEI_ANALYZER_DOCS_DIR", _HERE / "docs_site")
)
_DOCS_INDEX_FILES = ("index.html", "index.htm", "default.html", "default.htm")


@app.get("/docs")
def docs_index():
    """Serve the decompiled Huawei product documentation.

    Returns the CHM entry page if found, otherwise a directory listing. When
    the docs directory is absent, returns instructions for decompiling the
    .chm so the page is self-explanatory.
    """
    if not DOCS_DIR.is_dir():
        msg = (
            "<!doctype html><meta charset='utf-8'>"
            "<h2>产品文档未就绪</h2>"
            "<p>请将 <code>.chm</code> 反编译后的 HTML 目录放入 "
            "<code>web/docs_site/</code>（或设置环境变量 "
            "<code>HUAWEI_ANALYZER_DOCS_DIR</code>）。</p>"
            "<p>本机反编译示例（任选其一）：</p>"
            "<pre>"
            "# 7-Zip\n"
            "7z x \"HiSecEngine USG6000F, USG6000G V600R025C10 产品文档.chm\" -oweb/docs_site\n\n"
            "# Windows 自带 hh.exe\n"
            "hh -decompile web/docs_site \"HiSecEngine USG6000F, USG6000G V600R025C10 产品文档.chm\"\n\n"
            "# Linux/Mac (chmlib)\n"
            "extract_chmlib \"HiSecEngine USG6000F, USG6000G V600R025C10 产品文档.chm\" web/docs_site\n"
            "</pre>"
        )
        return msg, 200, {"Content-Type": "text/html; charset=utf-8"}

    for cand in _DOCS_INDEX_FILES:
        if (DOCS_DIR / cand).is_file():
            return send_from_directory(DOCS_DIR, cand, mimetype="text/html")

    # No index page -> render a directory listing so the user can navigate.
    items = sorted(p.name for p in DOCS_DIR.iterdir())
    rows = "".join(
        f'<li><a href="/docs/{name}">{name}</a></li>' for name in items
    )
    return (
        f"<!doctype html><meta charset='utf-8'>"
        f"<h2>产品文档</h2><ul>{rows}</ul>",
        200,
        {"Content-Type": "text/html; charset=utf-8"},
    )


@app.get("/docs/<path:filename>")
def docs_file(filename):
    """Serve a single file (incl. subfolders) from the decompiled docs."""
    if not DOCS_DIR.is_dir():
        return ("文档目录不存在", 404)
    # send_from_directory rejects ".." traversal and serves subpaths.
    return send_from_directory(DOCS_DIR, filename)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _analyze_one(path: Path, log_start, log_end, idx: int) -> dict[str, Any]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _err_result(path.name, f"读取文件失败: {exc}")
    file_type = detect_file_type(content)
    res: dict[str, Any] = {
        "name": path.name,
        "device_type": file_type,
        "hostname": "-",
        "score": None,
        "summary": None,
        "has_txt": False,
        "has_html": False,
        "report_stem": None,
    }
    if file_type == "firewall":
        cfg = FirewallParser().parse(content)
        comp = _checker.check(cfg)
        res["hostname"] = cfg.get("hostname", "-")
        res["score"] = comp.get("compliance_score")
        res["summary"] = comp.get("summary")
        res["_config"] = cfg
        res["_compliance"] = comp
        res["_log"] = None
        res["_traffic"] = None
    elif file_type == "switch":
        cfg = SwitchParser().parse(content)
        comp = _checker.check(cfg)
        res["hostname"] = cfg.get("hostname", "-")
        res["score"] = comp.get("compliance_score")
        res["summary"] = comp.get("summary")
        res["_config"] = cfg
        res["_compliance"] = comp
        res["_log"] = None
        res["_traffic"] = None
    elif file_type == "log":
        log = LogParser().parse(content, start_time=log_start, end_time=log_end)
        res["hostname"] = next(
            (ev["host"] for ev in log.get("events", []) if ev.get("host")), "-"
        )
        res["summary"] = {
            "total_events": log.get("total_events", 0),
            "critical": len(log.get("critical_events", [])),
            "by_category": log.get("by_category", {}),
            "time_range": log.get("time_range", {}),
        }
        res["_config"] = None
        res["_compliance"] = None
        res["_log"] = log
        res["_traffic"] = None
    elif file_type == "traffic_log":
        traffic_raw = TrafficLogParser().parse(
            content, start_time=log_start, end_time=log_end
        )
        traffic = _traffic_analyzer.analyze(traffic_raw)
        res["hostname"] = Path(res["name"]).stem
        ob = traffic.get("outbound", {})
        ib = traffic.get("inbound", {})
        res["summary"] = {
            "total_sessions": traffic.get("total_sessions", 0),
            "outbound": ob.get("total", 0),
            "inbound": ib.get("total", 0),
            "time_range": traffic.get("time_range", {}),
        }
        res["_config"] = None
        res["_compliance"] = None
        res["_log"] = None
        res["_traffic"] = traffic
    else:
        res["device_type"] = "unknown"
        res["error"] = (
            "无法识别文件类型 (非华为防火墙/交换机配置、VRP 日志或会话表 CSV)。"
            "如为交换机配置，建议提供 .txt 纯文本格式。"
        )
        res["_config"] = None
        res["_compliance"] = None
        res["_log"] = None
        res["_traffic"] = None
    return res


def _to_report_input(res: dict[str, Any]) -> dict[str, Any]:
    """Convert an internal result record into the shape expected by reporter."""
    return {
        "source": res["name"],
        "device_type": res["device_type"],
        "hostname": res.get("hostname", "-"),
        "config": res.get("_config"),
        "log": res.get("_log"),
        "traffic": res.get("_traffic"),
        "compliance": res.get("_compliance"),
    }


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    total_risks = 0
    total_missing = 0
    scored = 0
    score_sum = 0
    total_events = 0
    total_critical = 0
    total_sessions = 0
    total_outbound = 0
    total_inbound = 0
    for r in results:
        by_type[r["device_type"]] = by_type.get(r["device_type"], 0) + 1
        s = r.get("summary") or {}
        if r["device_type"] in ("firewall", "switch"):
            total_risks += (
                s.get("high", 0) + s.get("medium", 0) + s.get("low", 0)
            )
            total_missing += s.get("missing", 0)
            if r.get("score") is not None:
                score_sum += r["score"]
                scored += 1
        elif r["device_type"] == "log":
            total_events += s.get("total_events", 0)
            total_critical += s.get("critical", 0)
        elif r["device_type"] == "traffic_log":
            total_sessions += s.get("total_sessions", 0)
            total_outbound += s.get("outbound", 0)
            total_inbound += s.get("inbound", 0)
    return {
        "file_count": len(results),
        "by_type": by_type,
        "avg_score": round(score_sum / scored, 1) if scored else None,
        "total_risks": total_risks,
        "total_missing": total_missing,
        "total_log_events": total_events,
        "total_critical_events": total_critical,
        "total_traffic_sessions": total_sessions,
        "total_outbound": total_outbound,
        "total_inbound": total_inbound,
    }


def _err_result(name: str, error: str) -> dict[str, Any]:
    return {
        "name": name,
        "device_type": "error",
        "hostname": "-",
        "score": None,
        "summary": None,
        "has_txt": False,
        "has_html": False,
        "report_stem": None,
        "error": error,
        "_config": None,
        "_compliance": None,
        "_log": None,
        "_traffic": None,
    }


def _safe_name(name: str) -> str:
    keep = [c if (c.isalnum() or c in "-_.") else "_" for c in name]
    return "".join(keep)[:120] or "file"


def _is_safe_token(tok: str) -> bool:
    return bool(tok) and all(c.isalnum() or c == "_" for c in tok)


def _cleanup_old_jobs() -> None:
    """Remove oldest job dirs beyond MAX_KEPT_JOBS (best-effort)."""
    try:
        entries = [p for p in JOBS_DIR.iterdir() if p.is_dir()]
        entries.sort(key=lambda p: p.stat().st_mtime)
        for p in entries[:-MAX_KEPT_JOBS]:
            if _is_safe_token(p.name):
                shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


# Auto-cleanup of jobs older than 1 hour on each request (background best-effort).
@app.before_request
def _gc_old_jobs():
    try:
        cutoff = time.time() - 3600
        for p in JOBS_DIR.iterdir():
            if p.is_dir() and _is_safe_token(p.name) and p.stat().st_mtime < cutoff:
                shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)
