"""Huawei switch (S-series / CE) configuration parser.

Extracts: security domains/zones (when present), VLANs, VLANIF interfaces,
physical port config, STP settings, ACLs, static routes, AAA users and a few
global flags used by the compliance checker.

Accepts both legacy (`port access vlan`) and current (`port default vlan`)
VRP port-command syntax.
"""

from __future__ import annotations

import re
from typing import Any

from ._common import extract_aaa_users

_HOSTNAME_RE = re.compile(r"^\s*sysname\s+(\S+)", re.MULTILINE)

_VLAN_BATCH_RE = re.compile(r"^\s*vlan\s+batch\s+(.+?)\s*$")
_VLAN_DEF_RE = re.compile(r"^\s*vlan\s+(\d+)\s*$")
_VLAN_DESC_RE = re.compile(r"^\s+description\s+(.+?)\s*$")

_VLANIF_RE = re.compile(r"^\s*interface\s+Vlanif(\d+)\s*$")
_IFACE_RE = re.compile(r"^\s*interface\s+(\S+)\s*$")
_IP_ADDR_RE = re.compile(
    r"^\s+ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
_LINK_TYPE_RE = re.compile(r"^\s+port\s+link-type\s+(\S+)\s*$")
_PORT_ACCESS_RE = re.compile(r"^\s+port\s+(?:access|default)\s+vlan\s+(\d+)\s*$")
_PORT_TRUNK_RE = re.compile(
    r"^\s+port\s+trunk\s+allow-pass\s+vlan\s+(.+?)\s*$"
)
_STP_EDGE_RE = re.compile(r"^\s+stp\s+edged-port\s+enable\s*$")
_STP_BPDU_RE = re.compile(r"^\s+stp\s+bpdu-protection\s*$")

_STP_HDR_RE = re.compile(r"^\s*stp\s+mode\s+(\S+)\s*$")
_STP_ENABLE_RE = re.compile(r"^\s*stp\s+enable\s*$")
_STP_ROOT_RE = re.compile(r"^\s*stp\s+root\s+primary\s*$")

_ACL_HDR_RE = re.compile(r"^\s*acl\s+(?:number\s+)?(\d+)\s*$")
_ACL_RULE_RE = re.compile(
    r"^\s+rule\s+(\d+)\s+(permit|deny)\s*" r"(?:ip|tcp|udp|icmp|gre|ospf)?\s*(.*)$"
)
_TRAFFIC_FILTER_RE = re.compile(
    r"^\s*traffic-filter\s+(?:(vlan)\s+(\d+)\s+)?(inbound|outbound)\s+acl\s+(\d+)\s*$"
)

_ROUTE_RE = re.compile(
    r"^\s*ip\s+route-static\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d+)"
    r"(?:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?"
)

# AAA local-user parsing is delegated to the shared _common.extract_aaa_users
# helper (handles both inline and block syntax); no local regexes needed here.

_TELNET_RE = re.compile(r"^\s*telnet\s+(?:server\s+)?enable", re.MULTILINE)
_SSH_RE = re.compile(r"^\s*ssh\s+(?:server\s+)?(?:enable|user)", re.MULTILINE)
_LOG_AUDIT_RE = re.compile(
    r"^\s*info-center\s+(?:logbuffer|channel|source)\s+enable", re.MULTILINE | re.IGNORECASE
)

# Security domain / zone commands present on some L3 switches and CE series.
_SEC_DOMAIN_RE = re.compile(r"^\s*security\s+domain\s+(\S+)\s*$")
_SEC_IFACE_BIND_RE = re.compile(r"^\s+bind\s+interface\s+(\S+)\s*$")


class SwitchParser:
    """Parse Huawei switch VRP configuration text."""

    device_type = "switch"

    def parse(self, content: str) -> dict[str, Any]:
        lines = content.splitlines()
        result: dict[str, Any] = {
            "device_type": self.device_type,
            "hostname": self._extract_hostname(content),
            "security_domains": [],
            "vlans": [],
            "vlanifs": [],
            "interfaces": [],
            "stp": {
                "mode": None,
                "enabled": False,
                "bpdu_protection": False,
                "root_primary": False,
                "edged_ports": [],
            },
            "acls": [],
            "traffic_filters": [],
            "routes": [],
            "aaa_users": [],
            "global": {
                "telnet_enabled": bool(_TELNET_RE.search(content)),
                "ssh_enabled": bool(_SSH_RE.search(content)),
                "log_audit_enabled": bool(_LOG_AUDIT_RE.search(content)),
            },
            "full_text": content,
        }

        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]

            # vlan batch <list>
            m = _VLAN_BATCH_RE.match(line)
            if m:
                for tok in re.split(r"[\s,]+", m.group(1).strip()):
                    if tok:
                        result["vlans"].append(
                            {"id": tok, "description": None, "batch": True}
                        )
                i += 1
                continue

            # vlan <id>  (with description block)
            m = _VLAN_DEF_RE.match(line)
            if m:
                vid = m.group(1)
                desc = None
                indent = len(line) - len(line.lstrip(" "))
                j = i + 1
                while j < n:
                    sub = lines[j]
                    if not sub.strip():
                        j += 1
                        continue
                    sub_indent = len(sub) - len(sub.lstrip(" "))
                    if sub_indent <= indent:
                        break
                    dm = _VLAN_DESC_RE.match(sub)
                    if dm:
                        desc = dm.group(1)
                    j += 1
                result["vlans"].append({"id": vid, "description": desc, "batch": False})
                i = j
                continue

            # security domain <name>
            m = _SEC_DOMAIN_RE.match(line)
            if m:
                dom = {"name": m.group(1), "interfaces": []}
                indent = len(line) - len(line.lstrip(" "))
                j = i + 1
                while j < n:
                    sub = lines[j]
                    if not sub.strip():
                        j += 1
                        continue
                    sub_indent = len(sub) - len(sub.lstrip(" "))
                    if sub_indent <= indent:
                        break
                    bm = _SEC_IFACE_BIND_RE.match(sub)
                    if bm:
                        dom["interfaces"].append(bm.group(1))
                    j += 1
                result["security_domains"].append(dom)
                i = j
                continue

            # interface Vlanif<id>
            if m := _VLANIF_RE.match(line):
                vif = {"id": m.group(1), "ip": None, "mask": None}
                j = self._consume_interface_block(lines, i, n, _consume_vif_attr, vif)
                result["vlanifs"].append(vif)
                i = j
                continue

            # interface <name> (physical)
            if m := _IFACE_RE.match(line):
                # Skip Vlanif - already handled above
                if m.group(1).lower().startswith("vlanif"):
                    i += 1
                    continue
                iface: dict[str, Any] = {
                    "name": m.group(1),
                    "ip": None,
                    "mask": None,
                    "link_type": None,
                    "access_vlan": None,
                    "trunk_vlans": [],
                    "stp_edged": False,
                }
                j = self._consume_interface_block(
                    lines, i, n, _consume_iface_attr, iface
                )
                result["interfaces"].append(iface)
                if iface["stp_edged"]:
                    result["stp"]["edged_ports"].append(iface["name"])
                i = j
                continue

            # stp mode / stp enable / stp root (top-level stp config)
            if m := _STP_HDR_RE.match(line):
                result["stp"]["mode"] = m.group(1)
                # consume sub-block looking for bpdu-protection
                indent = len(line) - len(line.lstrip(" "))
                j = i + 1
                while j < n:
                    sub = lines[j]
                    if not sub.strip():
                        j += 1
                        continue
                    sub_indent = len(sub) - len(sub.lstrip(" "))
                    # `<=` (not `<`) so a header at column 0 still breaks when
                    # the next column-0 command appears; otherwise the loop
                    # would swallow the rest of the file.
                    if sub_indent <= indent:
                        break
                    if _STP_BPDU_RE.match(sub):
                        result["stp"]["bpdu_protection"] = True
                    if _STP_ROOT_RE.match(sub):
                        result["stp"]["root_primary"] = True
                    if _STP_ENABLE_RE.match(sub):
                        result["stp"]["enabled"] = True
                    j += 1
                i = j
                continue
            if _STP_ENABLE_RE.match(line):
                result["stp"]["enabled"] = True
            if _STP_BPDU_RE.match(line):
                result["stp"]["bpdu_protection"] = True
            if _STP_ROOT_RE.match(line):
                result["stp"]["root_primary"] = True

            # acl number <id>
            if m := _ACL_HDR_RE.match(line):
                acl = {"id": m.group(1), "rules": []}
                indent = len(line) - len(line.lstrip(" "))
                j = i + 1
                while j < n:
                    sub = lines[j]
                    if not sub.strip():
                        j += 1
                        continue
                    sub_indent = len(sub) - len(sub.lstrip(" "))
                    if sub_indent <= indent:
                        break
                    rm = _ACL_RULE_RE.match(sub)
                    if rm:
                        acl["rules"].append(
                            {
                                "num": rm.group(1),
                                "action": rm.group(2),
                                "rest": (rm.group(3) or "").strip(),
                            }
                        )
                    j += 1
                result["acls"].append(acl)
                i = j
                continue

            # traffic-filter
            if m := _TRAFFIC_FILTER_RE.match(line):
                vlan_kw = m.group(1)
                vid = m.group(2)
                target = f"vlan {vid}" if vlan_kw else "global"
                result["traffic_filters"].append(
                    {
                        "target": target,
                        "direction": m.group(3),
                        "acl": m.group(4),
                    }
                )

            # static route (single-line command)
            if m := _ROUTE_RE.match(line):
                result["routes"].append(
                    {
                        "dest": m.group(1),
                        "mask": m.group(2),
                        "next_hop": m.group(3),
                    }
                )

            i += 1

        # AAA users: extracted from the full text via the shared helper so that
        # both inline and block syntax work (the previous in-loop aaa scanner
        # could over-consume lines following the aaa block).
        result["aaa_users"] = extract_aaa_users(content)

        # Deduplicate VLANs: `vlan batch 10 20` and a later `vlan 10` with a
        # description refer to the same VLAN. Merge by id, preserving order.
        result["vlans"] = _merge_vlans(result["vlans"])

        return result

    @staticmethod
    def _extract_hostname(content: str) -> str:
        m = _HOSTNAME_RE.search(content)
        return m.group(1) if m else "unknown"

    @staticmethod
    def _consume_interface_block(lines, start, end, attr_fn, record):
        """Consume an indented interface sub-block, populating `record`.

        Returns the index of the next top-level command.
        """
        header_indent = len(lines[start]) - len(lines[start].lstrip(" "))
        j = start + 1
        while j < end:
            sub = lines[j]
            if not sub.strip():
                j += 1
                continue
            sub_indent = len(sub) - len(sub.lstrip(" "))
            if sub_indent <= header_indent:
                break
            attr_fn(sub, record)
            j += 1
        return j


def _merge_vlans(vlans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge VLAN records by id.

    `vlan batch 10 20` and a later `vlan 10` (with description) refer to the
    same VLAN. First-seen wins for id ordering; description from the explicit
    `vlan X` block overrides the empty batch entry.
    """
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for v in vlans:
        vid = str(v.get("id"))
        if vid not in merged:
            merged[vid] = {"id": vid, "description": None, "batch": v.get("batch", False)}
            order.append(vid)
        rec = merged[vid]
        if v.get("description"):
            rec["description"] = v["description"]
        if v.get("batch"):
            rec["batch"] = True
    return [merged[vid] for vid in order]


def _consume_vif_attr(sub: str, record: dict[str, Any]) -> None:
    if m := _IP_ADDR_RE.match(sub):
        record["ip"] = m.group(1)
        record["mask"] = m.group(2)


def _consume_iface_attr(sub: str, record: dict[str, Any]) -> None:
    if m := _IP_ADDR_RE.match(sub):
        record["ip"] = m.group(1)
        record["mask"] = m.group(2)
    elif m := _LINK_TYPE_RE.match(sub):
        record["link_type"] = m.group(1)
    elif m := _PORT_ACCESS_RE.match(sub):
        record["access_vlan"] = m.group(1)
    elif m := _PORT_TRUNK_RE.match(sub):
        record["trunk_vlans"] = re.split(r"[\s,]+", m.group(1).strip())
    elif _STP_EDGE_RE.match(sub):
        record["stp_edged"] = True
