"""Report generator for Huawei device analysis results.

Produces two formats:
- Plain-text (.txt) for terminal / pipeline consumption.
- Self-contained HTML (.html) with inline CSS and severity color coding.

A *device result* is expected to be a dict shaped as::

    {
        "source": <file path>,
        "device_type": "firewall" | "switch" | "log",
        "hostname": <str>,
        "config": <parsed config dict or None>,
        "log": <parsed log dict or None>,
        "compliance": <checker result dict or None>,
    }
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

SCORE_BANDS = [
    (90, "良好 (Low Risk)"),
    (75, "需关注 (Moderate Risk)"),
    (50, "风险较高 (High Risk)"),
    (0, "高风险 (Critical Risk)"),
]

SEVERITY_COLOR = {
    "high": "#d32f2f",
    "medium": "#f57c00",
    "low": "#fbc02d",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _score_band(score: int) -> str:
    for threshold, label in SCORE_BANDS:
        if score >= threshold:
            return label
    return SCORE_BANDS[-1][1]


def _sort_risks(risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        risks,
        key=lambda r: (SEVERITY_ORDER.get(r["severity"], 3), r.get("category", "")),
    )


class ReportGenerator:
    """Render device and batch analysis reports."""

    # ==================================================================
    # Text reports
    # ==================================================================
    def render_device_text(self, result: dict[str, Any]) -> str:
        out: list[str] = []
        out.append("=" * 78)
        out.append("华为设备配置/日志分析报告")
        out.append("=" * 78)
        out.append(f"源文件      : {result.get('source', '-')}")
        out.append(f"设备类型    : {result.get('device_type', '-')}")
        out.append(f"主机名      : {result.get('hostname', '-')}")
        out.append(f"生成时间    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.append("")

        cfg = result.get("config")
        log = result.get("log")
        comp = result.get("compliance")

        if cfg is not None:
            out.append("-" * 78)
            out.append("一、配置概览")
            out.append("-" * 78)
            out.append(self._config_overview_text(cfg))

        if comp is not None:
            out.append("-" * 78)
            out.append("二、安全合规性评估")
            out.append("-" * 78)
            out.append(self._compliance_text(comp))

        if log is not None:
            out.append("-" * 78)
            out.append("三、日志事件统计")
            out.append("-" * 78)
            out.append(self._log_text(log))

        out.append("=" * 78)
        out.append("报告结束")
        out.append("=" * 78)
        return "\n".join(out)

    def _config_overview_text(self, cfg: dict[str, Any]) -> str:
        dt = cfg.get("device_type")
        lines: list[str] = []
        if dt == "firewall":
            lines.append(f"  安全域数量        : {len(cfg.get('zones', []))}")
            lines.append(f"  安全策略数量      : {len(cfg.get('security_policies', []))}")
            lines.append(
                f"  NAT 地址组/策略   : "
                f"{len(cfg.get('nat', {}).get('address_groups', []))} / "
                f"{len(cfg.get('nat', {}).get('policies', []))}"
            )
            lines.append(f"  ACL 数量          : {len(cfg.get('acls', []))}")
            lines.append(f"  接口数量          : {len(cfg.get('interfaces', []))}")
            lines.append(f"  静态路由数量      : {len(cfg.get('routes', []))}")
            lines.append(f"  AAA 本地用户      : {len(cfg.get('aaa_users', []))}")
            g = cfg.get("global", {})
            lines.append(
                f"  全局: telnet={g.get('telnet_enabled')} "
                f"ssh={g.get('ssh_enabled')} "
                f"log_audit={g.get('log_audit_enabled')}"
            )
            # list interfaces briefly
            lines.append("")
            lines.append("  接口列表:")
            for iface in cfg.get("interfaces", []):
                lines.append(
                    f"    - {iface['name']:30} ip={iface.get('ip') or '-':16} "
                    f"zone={iface.get('zone') or '-'}"
                )
        elif dt == "switch":
            lines.append(f"  VLAN 数量         : {len(cfg.get('vlans', []))}")
            lines.append(f"  VLANIF 接口       : {len(cfg.get('vlanifs', []))}")
            lines.append(f"  物理端口          : {len(cfg.get('interfaces', []))}")
            stp = cfg.get("stp", {})
            lines.append(
                f"  STP: mode={stp.get('mode')} enabled={stp.get('enabled')} "
                f"bpdu_protection={stp.get('bpdu_protection')} "
                f"root={stp.get('root_primary')}"
            )
            lines.append(f"  ACL 数量          : {len(cfg.get('acls', []))}")
            lines.append(f"  traffic-filter    : {len(cfg.get('traffic_filters', []))}")
            lines.append(f"  静态路由数量      : {len(cfg.get('routes', []))}")
            lines.append(f"  安全域            : {len(cfg.get('security_domains', []))}")
            lines.append(f"  AAA 本地用户      : {len(cfg.get('aaa_users', []))}")
            g = cfg.get("global", {})
            lines.append(
                f"  全局: telnet={g.get('telnet_enabled')} "
                f"ssh={g.get('ssh_enabled')} "
                f"log_audit={g.get('log_audit_enabled')}"
            )
            lines.append("")
            lines.append("  VLAN 列表:")
            for v in cfg.get("vlans", [])[:20]:
                lines.append(
                    f"    - VLAN {v['id']:6} desc={v.get('description') or '-'}"
                )
            lines.append("  端口列表:")
            for iface in cfg.get("interfaces", [])[:20]:
                tv = ",".join(iface.get("trunk_vlans", []) or []) or "-"
                lines.append(
                    f"    - {iface['name']:24} link={iface.get('link_type') or '-':8} "
                    f"access_vlan={iface.get('access_vlan') or '-':5} trunk={tv}"
                )
        return "\n".join(lines)

    def _compliance_text(self, comp: dict[str, Any]) -> str:
        lines: list[str] = []
        score = comp.get("compliance_score", 0)
        lines.append(f"  合规评分          : {score}/100  ({_score_band(score)})")
        s = comp.get("summary", {})
        lines.append(
            f"  风险汇总          : 高={s.get('high',0)} 中={s.get('medium',0)} "
            f"低={s.get('low',0)} 缺失项={s.get('missing',0)}"
        )
        lines.append("")
        risks = _sort_risks(comp.get("risks", []))
        if risks:
            lines.append("  [安全风险清单]")
            for r in risks:
                lines.append(
                    f"    [{r['severity'].upper():6}] ({r['category']}) {r['title']}"
                )
                lines.append(f"             详情  : {r['detail']}")
                lines.append(f"             建议  : {r['recommendation']}")
        else:
            lines.append("  [安全风险清单] 未发现风险项")
        lines.append("")
        missing = comp.get("missing_configs", [])
        if missing:
            lines.append("  [缺失关键安全配置]")
            for m in missing:
                lines.append(
                    f"    [{m['severity'].upper():6}] {m['item']}"
                )
                lines.append(f"             详情  : {m['detail']}")
                lines.append(f"             建议  : {m['recommendation']}")
        else:
            lines.append("  [缺失关键安全配置] 无")
        return "\n".join(lines)

    def _log_text(self, log: dict[str, Any]) -> str:
        lines: list[str] = []
        tr = log.get("time_range", {})
        lines.append(f"  事件总数          : {log.get('total_events', 0)}")
        lines.append(
            f"  时间范围          : {tr.get('start', '-')} ~ {tr.get('end', '-')}"
        )
        if tr.get("filter_start") or tr.get("filter_end"):
            lines.append(
                f"  过滤范围          : {tr.get('filter_start', '-')} ~ "
                f"{tr.get('filter_end', '-')}"
            )
        lines.append("")
        bc = log.get("by_category", {})
        lines.append("  [按事件类别统计]")
        for cat, n in sorted(bc.items(), key=lambda x: -x[1]):
            lines.append(f"    {cat:18}: {n}")
        lines.append("")
        bs = log.get("by_severity_name", {})
        lines.append("  [按严重等级统计]")
        for sev in ("Emergency", "Alert", "Critical", "Error", "Warning",
                    "Notification", "Informational", "Debug"):
            if sev in bs:
                lines.append(f"    {sev:18}: {bs[sev]}")
        lines.append("")
        crit = log.get("critical_events", [])
        if crit:
            lines.append(f"  [严重事件 (Critical+ 安全告警) 共 {len(crit)} 条]")
            for ev in crit[:20]:
                lines.append(
                    f"    {ev.get('date','')} {ev.get('time','')} "
                    f"[{ev.get('severity_name','')}] {ev.get('category')}: "
                    f"{ev.get('detail','')[:80]}"
                )
            if len(crit) > 20:
                lines.append(f"    ... 其余 {len(crit)-20} 条已省略")
        return "\n".join(lines)

    def render_batch_text(self, results: list[dict[str, Any]]) -> str:
        out: list[str] = []
        out.append("=" * 78)
        out.append("华为设备批量分析汇总报告")
        out.append("=" * 78)
        out.append(f"生成时间        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.append(f"处理文件总数    : {len(results)}")
        # aggregate
        by_type: dict[str, int] = {}
        total_risks = 0
        total_missing = 0
        score_sum = 0
        scored = 0
        for r in results:
            by_type[r["device_type"]] = by_type.get(r["device_type"], 0) + 1
            comp = r.get("compliance")
            if comp:
                s = comp.get("summary", {})
                total_risks += s.get("high", 0) + s.get("medium", 0) + s.get("low", 0)
                total_missing += s.get("missing", 0)
                score_sum += comp.get("compliance_score", 0)
                scored += 1
        out.append("设备类型分布    : " + ", ".join(f"{k}={v}" for k, v in by_type.items()))
        if scored:
            out.append(f"平均合规评分    : {score_sum/scored:.1f}/100")
        out.append(f"风险项总数      : {total_risks}")
        out.append(f"缺失配置项数    : {total_missing}")
        out.append("")
        out.append("-" * 78)
        out.append("各设备概要")
        out.append("-" * 78)
        for r in results:
            comp = r.get("compliance")
            if comp:
                s = comp.get("summary", {})
                out.append(
                    f"  [{r['device_type']:8}] {r.get('hostname','-'):16} "
                    f"score={comp.get('compliance_score',0):>3} "
                    f"H/M/L={s.get('high',0)}/{s.get('medium',0)}/{s.get('low',0)} "
                    f"miss={s.get('missing',0)}  <- {r.get('source','-')}"
                )
            elif r.get("device_type") == "log":
                log = r.get("log", {})
                out.append(
                    f"  [{'log':8}] {r.get('hostname','-'):16} "
                    f"events={log.get('total_events',0)} "
                    f"critical={len(log.get('critical_events',[]))}  <- {r.get('source','-')}"
                )
            else:
                out.append(
                    f"  [{r['device_type']:8}] {r.get('hostname','-'):16}  <- {r.get('source','-')}"
                )
        out.append("")
        out.append("详见各设备单独报告文件。")
        return "\n".join(out)

    # ==================================================================
    # HTML reports
    # ==================================================================
    def render_device_html(self, result: dict[str, Any]) -> str:
        body = self._device_html_body(result)
        return self._html_wrap(
            f"设备分析报告 - {html.escape(str(result.get('hostname','-')))}",
            body,
        )

    def render_batch_html(self, results: list[dict[str, Any]]) -> str:
        parts: list[str] = []
        parts.append('<div class="card">')
        parts.append('<h2>批量分析汇总</h2>')
        parts.append(f"<p>处理文件总数: <b>{len(results)}</b></p>")
        by_type: dict[str, int] = {}
        scored = 0
        score_sum = 0
        for r in results:
            by_type[r["device_type"]] = by_type.get(r["device_type"], 0) + 1
            if r.get("compliance"):
                score_sum += r["compliance"].get("compliance_score", 0)
                scored += 1
        parts.append(
            "<p>设备类型分布: "
            + ", ".join(
                f"{html.escape(k)}={v}" for k, v in by_type.items()
            )
            + "</p>"
        )
        if scored:
            parts.append(f"<p>平均合规评分: <b>{score_sum/scored:.1f}/100</b></p>")
        parts.append('<table class="summary">')
        parts.append("<tr><th>类型</th><th>主机名</th><th>评分</th>"
                     "<th>高/中/低</th><th>缺失</th><th>源文件</th></tr>")
        for r in results:
            comp = r.get("compliance")
            if comp:
                s = comp.get("summary", {})
                parts.append(
                    f"<tr><td>{html.escape(r['device_type'])}</td>"
                    f"<td>{html.escape(str(r.get('hostname','-')))}</td>"
                    f"<td>{comp.get('compliance_score',0)}</td>"
                    f"<td>{s.get('high',0)}/{s.get('medium',0)}/{s.get('low',0)}</td>"
                    f"<td>{s.get('missing',0)}</td>"
                    f"<td>{html.escape(r.get('source','-'))}</td></tr>"
                )
            elif r.get("device_type") == "log":
                log = r.get("log", {})
                parts.append(
                    f"<tr><td>log</td>"
                    f"<td>{html.escape(str(r.get('hostname','-')))}</td>"
                    f"<td>-</td>"
                    f"<td>events={log.get('total_events',0)}</td>"
                    f"<td>critical={len(log.get('critical_events',[]))}</td>"
                    f"<td>{html.escape(r.get('source','-'))}</td></tr>"
                )
            else:
                parts.append(
                    f"<tr><td>{html.escape(r['device_type'])}</td>"
                    f"<td>{html.escape(str(r.get('hostname','-')))}</td>"
                    f"<td colspan='3'>-</td>"
                    f"<td>{html.escape(r.get('source','-'))}</td></tr>"
                )
        parts.append("</table>")
        parts.append("</div>")
        for r in results:
            parts.append(self._device_html_body(r))
        return self._html_wrap("批量分析报告", "\n".join(parts))

    def _device_html_body(self, result: dict[str, Any]) -> str:
        parts: list[str] = []
        parts.append('<div class="card">')
        parts.append(
            f'<h2>{html.escape(str(result.get("hostname","-")))} '
            f'<span class="badge">{html.escape(str(result.get("device_type","-")))}</span></h2>'
        )
        parts.append(
            f'<p class="meta">源文件: <code>{html.escape(result.get("source","-"))}</code> '
            f'| 生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>'
        )

        cfg = result.get("config")
        comp = result.get("compliance")
        log = result.get("log")

        if cfg is not None:
            parts.append('<h3>一、配置概览</h3>')
            parts.append(self._config_overview_html(cfg))
        if comp is not None:
            parts.append('<h3>二、安全合规性评估</h3>')
            parts.append(self._compliance_html(comp))
        if log is not None:
            parts.append('<h3>三、日志事件统计</h3>')
            parts.append(self._log_html(log))
        parts.append("</div>")
        return "\n".join(parts)

    def _config_overview_html(self, cfg: dict[str, Any]) -> str:
        dt = cfg.get("device_type")
        rows: list[tuple[str, str]] = []
        if dt == "firewall":
            rows.append(("安全域数量", str(len(cfg.get("zones", [])))))
            rows.append(("安全策略数量", str(len(cfg.get("security_policies", [])))))
            rows.append((
                "NAT 地址组/策略",
                f"{len(cfg.get('nat',{}).get('address_groups',[]))} / "
                f"{len(cfg.get('nat',{}).get('policies',[]))}",
            ))
            rows.append(("ACL 数量", str(len(cfg.get("acls", [])))))
            rows.append(("接口数量", str(len(cfg.get("interfaces", [])))))
            rows.append(("静态路由数量", str(len(cfg.get("routes", [])))))
            rows.append(("AAA 本地用户", str(len(cfg.get("aaa_users", [])))))
        elif dt == "switch":
            rows.append(("VLAN 数量", str(len(cfg.get("vlans", [])))))
            rows.append(("VLANIF 接口", str(len(cfg.get("vlanifs", [])))))
            rows.append(("物理端口", str(len(cfg.get("interfaces", [])))))
            stp = cfg.get("stp", {})
            rows.append((
                "STP",
                f"mode={stp.get('mode')} enabled={stp.get('enabled')} "
                f"bpdu={stp.get('bpdu_protection')} root={stp.get('root_primary')}",
            ))
            rows.append(("ACL 数量", str(len(cfg.get("acls", [])))))
            rows.append(("traffic-filter", str(len(cfg.get("traffic_filters", [])))))
            rows.append(("静态路由", str(len(cfg.get("routes", [])))))
            rows.append(("安全域", str(len(cfg.get("security_domains", [])))))
            rows.append(("AAA 本地用户", str(len(cfg.get("aaa_users", [])))))
        g = cfg.get("global", {})
        rows.append((
            "全局服务",
            f"telnet={g.get('telnet_enabled')} ssh={g.get('ssh_enabled')} "
            f"log_audit={g.get('log_audit_enabled')}",
        ))
        out = ['<table class="kv">']
        for k, v in rows:
            out.append(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>")
        out.append("</table>")
        return "\n".join(out)

    def _compliance_html(self, comp: dict[str, Any]) -> str:
        score = comp.get("compliance_score", 0)
        band = _score_band(score)
        color = "#2e7d32" if score >= 90 else "#f57c00" if score >= 50 else "#d32f2f"
        s = comp.get("summary", {})
        out: list[str] = []
        out.append(
            f'<div class="score" style="border-color:{color};color:{color}">'
            f'<span class="score-num">{score}</span><span class="score-band">'
            f'{html.escape(band)}</span></div>'
        )
        out.append(
            f'<p>风险汇总: 高=<b style="color:#d32f2f">{s.get("high",0)}</b> '
            f'中=<b style="color:#f57c00">{s.get("medium",0)}</b> '
            f'低=<b style="color:#fbc02d">{s.get("low",0)}</b> '
            f'缺失项=<b>{s.get("missing",0)}</b></p>'
        )
        risks = _sort_risks(comp.get("risks", []))
        out.append("<h4>安全风险清单</h4>")
        if not risks:
            out.append('<p class="ok">未发现风险项</p>')
        else:
            out.append('<table class="risk"><tr><th>级别</th><th>类别</th>'
                        '<th>标题</th><th>详情</th><th>建议</th></tr>')
            for r in risks:
                c = SEVERITY_COLOR.get(r["severity"], "#888")
                out.append(
                    f'<tr><td><span class="sev" style="background:{c}">'
                    f'{html.escape(r["severity"].upper())}</span></td>'
                    f'<td>{html.escape(r["category"])}</td>'
                    f'<td>{html.escape(r["title"])}</td>'
                    f'<td>{html.escape(r["detail"])}</td>'
                    f'<td>{html.escape(r["recommendation"])}</td></tr>'
                )
            out.append("</table>")
        missing = comp.get("missing_configs", [])
        out.append("<h4>缺失关键安全配置</h4>")
        if not missing:
            out.append('<p class="ok">无</p>')
        else:
            out.append('<table class="risk"><tr><th>级别</th><th>项目</th>'
                        '<th>详情</th><th>建议</th></tr>')
            for m in missing:
                c = SEVERITY_COLOR.get(m["severity"], "#888")
                out.append(
                    f'<tr><td><span class="sev" style="background:{c}">'
                    f'{html.escape(m["severity"].upper())}</span></td>'
                    f'<td>{html.escape(m["item"])}</td>'
                    f'<td>{html.escape(m["detail"])}</td>'
                    f'<td>{html.escape(m["recommendation"])}</td></tr>'
                )
            out.append("</table>")
        return "\n".join(out)

    def _log_html(self, log: dict[str, Any]) -> str:
        tr = log.get("time_range", {})
        out: list[str] = []
        out.append(
            f'<p>事件总数: <b>{log.get("total_events",0)}</b> '
            f'| 时间范围: {html.escape(str(tr.get("start","-")))} ~ '
            f'{html.escape(str(tr.get("end","-")))}</p>'
        )
        bc = log.get("by_category", {})
        bs = log.get("by_severity_name", {})
        out.append('<div class="grid2">')
        out.append('<div><h4>按事件类别</h4><table class="kv">')
        for cat, n in sorted(bc.items(), key=lambda x: -x[1]):
            out.append(
                f'<tr><th>{html.escape(cat)}</th><td>{n}</td></tr>'
            )
        out.append("</table></div>")
        out.append('<div><h4>按严重等级</h4><table class="kv">')
        for sev in ("Emergency", "Alert", "Critical", "Error", "Warning",
                    "Notification", "Informational", "Debug"):
            if sev in bs:
                out.append(f'<tr><th>{sev}</th><td>{bs[sev]}</td></tr>')
        out.append("</table></div></div>")
        crit = log.get("critical_events", [])
        out.append(f"<h4>严重事件 ({len(crit)})</h4>")
        if not crit:
            out.append('<p class="ok">无严重事件</p>')
        else:
            out.append('<table class="risk"><tr><th>时间</th><th>级别</th>'
                        '<th>类别</th><th>详情</th></tr>')
            for ev in crit[:50]:
                out.append(
                    f'<tr><td>{html.escape(ev.get("date",""))} '
                    f'{html.escape(ev.get("time",""))}</td>'
                    f'<td><span class="sev" style="background:#d32f2f">'
                    f'{html.escape(ev.get("severity_name",""))}</span></td>'
                    f'<td>{html.escape(ev.get("category",""))}</td>'
                    f'<td>{html.escape(ev.get("detail",""))[:120]}</td></tr>'
                )
            out.append("</table>")
            if len(crit) > 50:
                out.append(f'<p>仅展示前 50 条，共 {len(crit)} 条。</p>')
        return "\n".join(out)

    @staticmethod
    def _html_wrap(title: str, body: str) -> str:
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; margin: 24px; background: #f5f5f5; color: #222; }}
  h1 {{ color: #1565c0; border-bottom: 2px solid #1565c0; padding-bottom: 8px; }}
  h2 {{ color: #0d47a1; margin-top: 0; }}
  h3 {{ color: #1565c0; border-left: 4px solid #1565c0; padding-left: 8px; margin-top: 24px; }}
  h4 {{ color: #37474f; margin-bottom: 6px; }}
  .card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 18px 22px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .meta {{ color: #666; font-size: 13px; }}
  .badge {{ background: #1565c0; color: #fff; font-size: 12px; padding: 2px 8px; border-radius: 10px; vertical-align: middle; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }}
  table.kv th {{ text-align: left; background: #eceff1; width: 30%; padding: 6px 10px; border: 1px solid #cfd8dc; }}
  table.kv td {{ padding: 6px 10px; border: 1px solid #cfd8dc; }}
  table.risk th {{ background: #37474f; color: #fff; text-align: left; padding: 6px 8px; border: 1px solid #263238; }}
  table.risk td {{ padding: 6px 8px; border: 1px solid #cfd8dc; vertical-align: top; }}
  table.summary th {{ background: #1565c0; color: #fff; text-align: left; padding: 6px 8px; }}
  table.summary td {{ padding: 6px 8px; border: 1px solid #cfd8dc; }}
  .sev {{ color: #fff; font-size: 11px; padding: 2px 6px; border-radius: 3px; font-weight: bold; }}
  .score {{ display: inline-block; border: 3px solid; padding: 10px 18px; border-radius: 6px; margin: 8px 0; }}
  .score-num {{ font-size: 28px; font-weight: bold; margin-right: 8px; }}
  .score-band {{ font-size: 14px; }}
  .ok {{ color: #2e7d32; font-style: italic; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 12px; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
{body}
</body>
</html>
"""
