"""Security compliance checker for parsed Huawei device configurations.

Performs four classes of checks:

1. Weak password / authentication policy
   - plaintext (`simple`) passwords, telnet enabled for mgmt, excessive privilege.
2. High-risk open ports/services
   - telnet (23), ftp (21), http (80), smb (445), rdp (3389) exposed.
3. Overly permissive ACLs / security policies
   - `permit ip` with no source/destination restriction, `permit any` rules,
     firewall security-policy `permit` without address constraints.
4. Missing critical security configuration
   - no ACL configured, ACL not applied, STP disabled / bpdu-protection off,
     no log auditing, no default route, no security-policy / zones on firewall.
"""

from __future__ import annotations

import re
from typing import Any

# Service -> risk weight mapping. Telnet/ftp/http/smb/rdp are cleartext or
# historically高危 when exposed on a device's management plane.
HIGH_RISK_SERVICES = {
    "telnet": {"port": 23, "severity": "high"},
    "ftp": {"port": 21, "severity": "high"},
    "tftp": {"port": 69, "severity": "high"},
    "http": {"port": 80, "severity": "medium"},
    "smb": {"port": 445, "severity": "high"},
    "rdp": {"port": 3389, "severity": "medium"},
    "snmp": {"port": 161, "severity": "medium"},
}

# Common default / weak password strings used by Huawei devices historically.
WEAK_PASSWORD_TOKENS = (
    "admin@123",
    "admin123",
    "huawei@123",
    "huawei123",
    "admin",
    "huawei",
    "Admin@123",
    "Admin123",
    "Admin@huawei",
    "Password@123",
)

# An ACL rule body that, after the protocol token, has no source/destination
# restriction at all (matches everything).
PERMISSIVE_ACL_RE = re.compile(
    r"^(?:ip)?\s*(?:source\s+any\s+)?(?:destination\s+any\s?)?$"
)


class ComplianceChecker:
    """Run compliance checks against a parsed device config."""

    def check(self, config: dict[str, Any]) -> dict[str, Any]:
        device_type = config.get("device_type")
        if device_type == "firewall":
            return self._check_firewall(config)
        if device_type == "switch":
            return self._check_switch(config)
        return {
            "risks": [],
            "missing_configs": [],
            "compliance_score": 0,
            "summary": {"high": 0, "medium": 0, "low": 0, "missing": 0},
            "note": f"unsupported device_type: {device_type}",
        }

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------
    def _check_firewall(self, config: dict[str, Any]) -> dict[str, Any]:
        risks: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []

        full = config.get("full_text", "")
        global_cfg = config.get("global", {})
        aaa_users = config.get("aaa_users", [])
        acls = config.get("acls", [])
        policies = config.get("security_policies", [])
        zones = config.get("zones", [])
        routes = config.get("routes", [])
        interfaces = config.get("interfaces", [])

        # 1. weak password / authentication
        if global_cfg.get("telnet_enabled"):
            risks.append(self._risk(
                "high", "auth",
                "Telnet 服务已启用",
                "Telnet 以明文传输凭据，易被中间人嗅探。",
                "禁用 Telnet，改用 SSH 管理设备并限制管理源地址。",
            ))
        for u in aaa_users:
            if u.get("password_type") == "simple":
                risks.append(self._risk(
                    "high", "auth",
                    f"用户 {u.get('name')} 使用明文(simple)口令",
                    "simple 类型口令在配置中以明文存储，存在泄露风险。",
                    "改用 cipher 或 irreversible-cipher 类型存储口令。",
                ))
            if u.get("password_cipher") and any(
                tok in (u.get("password_cipher") or "") for tok in WEAK_PASSWORD_TOKENS
            ):
                risks.append(self._risk(
                    "high", "auth",
                    f"用户 {u.get('name')} 使用弱口令/默认口令",
                    f"检测到常见弱口令特征: {u.get('password_cipher')[:24]}",
                    "立即更换为高复杂度口令，并启用口令复杂度策略。",
                ))
            if u.get("privilege") == "15" and u.get("services") and any(
                s in ("telnet", "ftp", "http") for s in u["services"]
            ):
                risks.append(self._risk(
                    "medium", "auth",
                    f"用户 {u.get('name')} 拥有最高权限且启用了不安全服务",
                    f"特权级别 15，服务: {', '.join(u['services'])}",
                    "降低最小必要权限，仅保留 SSH 服务。",
                ))

        # 2. high-risk open services on interfaces
        for iface in interfaces:
            for sm in iface.get("service_manage", []):
                svc = sm.get("service", "").lower()
                if sm.get("action") == "permit" and svc in HIGH_RISK_SERVICES:
                    info = HIGH_RISK_SERVICES[svc]
                    risks.append(self._risk(
                        info["severity"], "open_port",
                        f"接口 {iface['name']} 开放高危服务 {svc} (端口 {info['port']})",
                        f"service-manage permit {svc} 直接放行该服务流量。",
                        f"关闭 {svc} 服务或限制到受信任管理网段。",
                    ))

        # 3. permissive ACLs
        for acl in acls:
            for rule in acl.get("rules", []):
                rest = (rule.get("rest") or "").strip().lower()
                action = rule.get("action")
                if action == "permit" and self._is_permissive_acl(rest):
                    risks.append(self._risk(
                        "high", "acl",
                        f"ACL {acl['id']} 规则 {rule['num']} 过于宽松",
                        f"rule {rule['num']} permit {rest or '(无限制)'} -> 等价于放行所有流量",
                        "收紧规则，明确指定源/目的地址段与服务端口。",
                    ))

        # 3b. permissive security-policy
        for p in policies:
            if p.get("action") == "permit":
                if not p.get("source_address") and not p.get("dest_address") and not p.get("service"):
                    risks.append(self._risk(
                        "high", "policy",
                        f"安全策略 {p['name']} 放行未限制地址/服务",
                        f"src={p.get('source_zone')} dst={p.get('dest_zone')} action=permit (无地址/服务约束)",
                        "在放行策略中限定源/目的地址范围与服务，遵循最小授权原则。",
                    ))

        # 4. missing critical configs
        if not acls:
            missing.append(self._missing(
                "high", "未配置任何 ACL",
                "设备未定义 ACL，无法在接口/业务层面进行访问控制。",
                "至少配置入向 ACL 并应用到关键接口。",
            ))
        if not policies:
            missing.append(self._missing(
                "high", "未配置安全策略(security-policy)",
                "防火墙无安全策略，等价于放行所有跨域流量。",
                "按业务需要定义安全策略，并启用默认 deny。",
            ))
        if not zones:
            missing.append(self._missing(
                "high", "未配置安全域(firewall zone)",
                "未划分安全域，无法实现基于域的策略匹配。",
                "划分 trust/untrust/dmz 等安全域并绑定接口。",
            ))
        if not global_cfg.get("log_audit_enabled"):
            missing.append(self._missing(
                "medium", "未启用日志审计(info-center)",
                "缺少日志缓冲与审计，安全事件无法追溯。",
                "启用 info-center logbuffer 并将日志发送到日志服务器。",
            ))
        if not routes:
            missing.append(self._missing(
                "low", "未配置静态路由",
                "设备未配置任何静态路由，可能影响跨网段转发。",
                "根据网络拓扑配置必要的静态/默认路由。",
            ))

        return self._finalize(risks, missing)

    # ------------------------------------------------------------------
    # Switch
    # ------------------------------------------------------------------
    def _check_switch(self, config: dict[str, Any]) -> dict[str, Any]:
        risks: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []

        global_cfg = config.get("global", {})
        aaa_users = config.get("aaa_users", [])
        acls = config.get("acls", [])
        traffic_filters = config.get("traffic_filters", [])
        stp = config.get("stp", {})
        routes = config.get("routes", [])
        vlans = config.get("vlans", [])
        interfaces = config.get("interfaces", [])

        # 1. weak password / auth
        if global_cfg.get("telnet_enabled"):
            risks.append(self._risk(
                "high", "auth",
                "Telnet 服务已启用",
                "Telnet 明文传输，易被嗅探。",
                "禁用 Telnet，改用 SSH。",
            ))
        for u in aaa_users:
            if u.get("password_type") == "simple":
                risks.append(self._risk(
                    "high", "auth",
                    f"用户 {u.get('name')} 使用明文(simple)口令",
                    "simple 口令以明文存储在配置中。",
                    "改用 cipher/irreversible-cipher。",
                ))
            if u.get("password_cipher") and any(
                tok in (u.get("password_cipher") or "") for tok in WEAK_PASSWORD_TOKENS
            ):
                risks.append(self._risk(
                    "high", "auth",
                    f"用户 {u.get('name')} 使用弱口令/默认口令",
                    f"特征: {u.get('password_cipher')[:24]}",
                    "更换为高复杂度口令。",
                ))

        # 2. high-risk open services (global)
        for svc, info in HIGH_RISK_SERVICES.items():
            if global_cfg.get(f"{svc}_enabled") or (
                svc == "telnet" and global_cfg.get("telnet_enabled")
            ):
                risks.append(self._risk(
                    info["severity"], "open_port",
                    f"高危服务 {svc} (端口 {info['port']}) 已启用",
                    f"{svc} 服务在交换机上启用存在被利用风险。",
                    f"如非必要关闭 {svc}，或限制管理源。",
                ))

        # 3. permissive ACLs
        applied_acl_ids = {tf["acl"] for tf in traffic_filters}
        for acl in acls:
            for rule in acl.get("rules", []):
                rest = (rule.get("rest") or "").strip().lower()
                if rule.get("action") == "permit" and self._is_permissive_acl(rest):
                    risks.append(self._risk(
                        "high", "acl",
                        f"ACL {acl['id']} 规则 {rule['num']} 过于宽松",
                        f"rule {rule['num']} permit {rest or '(无限制)'} -> 等价放行所有流量",
                        "收紧规则，明确源/目的地址。",
                    ))
        # ACL configured but not applied
        for acl in acls:
            if acl["id"] not in applied_acl_ids:
                risks.append(self._risk(
                    "medium", "acl",
                    f"ACL {acl['id']} 已定义但未应用",
                    "未通过 traffic-filter 应用到任何接口/VLAN。",
                    f"将 ACL {acl['id']} 应用到关键接口入方向。",
                ))

        # 4. missing critical configs
        if not acls:
            missing.append(self._missing(
                "high", "未配置任何 ACL",
                "交换机未定义 ACL，缺少业务层访问控制。",
                "为关键 VLAN/接口配置入向 ACL。",
            ))
        if not stp.get("enabled"):
            missing.append(self._missing(
                "medium", "未启用 STP",
                "STP 未启用，存在二层环路风险。",
                "在接入/汇聚层启用 RSTP/MSTP。",
            ))
        if stp.get("enabled") and not stp.get("bpdu_protection"):
            missing.append(self._missing(
                "medium", "未启用 STP BPDU 保护",
                "接入端口缺少 BPDU 保护，易受伪造 BPDU 攻击。",
                "在接入侧启用 stp bpdu-protection。",
            ))
        if not global_cfg.get("log_audit_enabled"):
            missing.append(self._missing(
                "medium", "未启用日志审计(info-center)",
                "缺少日志审计，无法追溯安全事件。",
                "启用 info-center 并外发到日志服务器。",
            ))
        if not routes:
            missing.append(self._missing(
                "low", "未配置静态路由",
                "未配置静态路由，跨网段通信可能中断。",
                "按拓扑配置必要的静态/默认路由。",
            ))
        if not vlans:
            missing.append(self._missing(
                "low", "未配置 VLAN",
                "未划分 VLAN，所有端口处于同一广播域。",
                "按业务划分 VLAN 并启用端口隔离。",
            ))

        # port security: access ports without edge-port / bpdu guard hint
        access_without_edge = [
            iface["name"]
            for iface in interfaces
            if iface.get("link_type") == "access" and not iface.get("stp_edged")
        ]
        if access_without_edge:
            missing.append(self._missing(
                "low",
                f"{len(access_without_edge)} 个 access 端口未配置边缘端口(edged-port)",
                f"示例: {', '.join(access_without_edge[:5])}",
                "对接入端口配置 stp edged-port enable。",
            ))

        return self._finalize(risks, missing)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_permissive_acl(rest: str) -> bool:
        """True when an ACL rule body matches everything (no real constraint).

        Handles: '', 'source any', 'destination any', 'source any destination any',
        and combinations where the only restriction is `any`.
        """
        if not rest:
            return True
        # strip protocol token
        body = re.sub(r"^(ip|tcp|udp|icmp|gre|ospf)\s*", "", rest).strip()
        if not body:
            return True
        # any-only source/dest => permissive
        body_norm = re.sub(r"\s+", " ", body)
        if body_norm in (
            "source any",
            "destination any",
            "source any destination any",
            "destination any source any",
        ):
            return True
        return False

    @staticmethod
    def _risk(severity, category, title, detail, recommendation) -> dict[str, Any]:
        return {
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
        }

    @staticmethod
    def _missing(severity, item, detail, recommendation) -> dict[str, Any]:
        return {
            "severity": severity,
            "item": item,
            "detail": detail,
            "recommendation": recommendation,
        }

    @staticmethod
    def _finalize(risks, missing) -> dict[str, Any]:
        weight = {"high": 3, "medium": 2, "low": 1}
        penalty = sum(weight[r["severity"]] for r in risks) + sum(
            weight[m["severity"]] for m in missing
        )
        score = max(0, 100 - penalty)
        summary = {
            "high": sum(1 for r in risks if r["severity"] == "high"),
            "medium": sum(1 for r in risks if r["severity"] == "medium"),
            "low": sum(1 for r in risks if r["severity"] == "low"),
            "missing": len(missing),
        }
        return {
            "risks": risks,
            "missing_configs": missing,
            "compliance_score": score,
            "summary": summary,
        }
