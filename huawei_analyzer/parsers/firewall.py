"""Huawei firewall (USG / NGFW) configuration parser.

Extracts: security zones, security policies, NAT policies & address groups,
ACLs, interfaces, static routes, AAA users and a few global settings used by
the compliance checker.
"""

from __future__ import annotations

import re
from typing import Any

from ._common import extract_aaa_users

_HOSTNAME_RE = re.compile(r"^\s*sysname\s+(\S+)", re.MULTILINE)

_ZONE_RE = re.compile(r"^\s*firewall\s+zone\s+(\S+)\s*$")
_ADD_IFACE_RE = re.compile(r"^\s*add\s+interface\s+(\S+)\s*$")

_SEC_POLICY_HDR_RE = re.compile(r"^\s*security-policy\s*$")
_NAT_POLICY_HDR_RE = re.compile(r"^\s*nat-policy\s*$")
_RULE_NAME_RE = re.compile(r"^\s+rule\s+name\s+(\S+)\s*$")
_SRC_ZONE_RE = re.compile(r"^\s+source-zone\s+(\S+)\s*$")
_DST_ZONE_RE = re.compile(r"^\s+destination-zone\s+(\S+)\s*$")
_SRC_ADDR_RE = re.compile(r"^\s+source-address\s+(.+?)\s*$")
_DST_ADDR_RE = re.compile(r"^\s+destination-address\s+(.+?)\s*$")
_SERVICE_RE = re.compile(r"^\s+service\s+(.+?)\s*$")
_ACTION_RE = re.compile(
    r"^\s+action\s+(permit|deny|source-nat|destination-nat|nopat|nat-policy)"
)

_NAT_ADDR_GRP_RE = re.compile(r"^\s*nat\s+address-group\s+(\S+)\s+(\d+)\s*$")
_NAT_SECTION_RE = re.compile(r"^\s+section\s+(\d+)\s+(\S+)\s+(\S+)\s*$")

_ACL_HDR_RE = re.compile(r"^\s*acl\s+(?:number\s+)?(\d+)\s*$")
_ACL_RULE_RE = re.compile(
    r"^\s+rule\s+(\d+)\s+(permit|deny)\s*"
    r"(?:ip|tcp|udp|icmp|gre|ospf)?\s*(.*)$"
)

_INTERFACE_RE = re.compile(r"^\s*interface\s+(\S+)\s*$")
_IP_ADDR_RE = re.compile(
    r"^\s+ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
_SERVICE_MANAGE_RE = re.compile(r"^\s+service-manage\s+(\S+)\s+(permit|deny)\s*$")

_ROUTE_RE = re.compile(
    r"^\s*ip\s+route-static\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d+)"
    r"(?:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?"
)

# AAA local-user parsing is delegated to the shared _common.extract_aaa_users
# helper (handles both inline and block forms); no local regexes needed here.

_TELNET_RE = re.compile(r"^\s*telnet\s+(?:server\s+)?enable", re.MULTILINE)
_SSH_RE = re.compile(r"^\s*ssh\s+(?:server\s+)?(?:enable|user)", re.MULTILINE)
_LOG_AUDIT_RE = re.compile(r"^\s*info-center\s+logbuffer\s+enable", re.MULTILINE | re.IGNORECASE)


class FirewallParser:
    """Parse Huawei firewall VRP configuration text."""

    device_type = "firewall"

    def parse(self, content: str) -> dict[str, Any]:
        lines = content.splitlines()
        result: dict[str, Any] = {
            "device_type": self.device_type,
            "hostname": self._extract_hostname(content),
            "zones": [],
            "security_policies": [],
            "nat": {"address_groups": [], "policies": []},
            "acls": [],
            "interfaces": [],
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
            stripped = line.strip()

            # firewall zone <name>
            m = _ZONE_RE.match(line)
            if m:
                zone_name = m.group(1)
                ifs: list[str] = []
                i += 1
                while i < n and lines[i].startswith(" "):
                    am = _ADD_IFACE_RE.match(lines[i])
                    if am:
                        ifs.append(am.group(1))
                    i += 1
                result["zones"].append({"name": zone_name, "interfaces": ifs})
                continue

            # security-policy / nat-policy blocks
            if _SEC_POLICY_HDR_RE.match(line) or _NAT_POLICY_HDR_RE.match(line):
                ptype = "security" if _SEC_POLICY_HDR_RE.match(line) else "nat"
                i += 1
                while i < n and lines[i].startswith(" "):
                    rm = _RULE_NAME_RE.match(lines[i])
                    if rm:
                        rule, end_i = self._parse_rule(
                            rm.group(1), ptype, lines, i, n
                        )
                        i = end_i
                        if ptype == "security":
                            result["security_policies"].append(rule)
                        else:
                            result["nat"]["policies"].append(rule)
                        continue
                    i += 1
                continue

            # nat address-group <name> <id>
            m = _NAT_ADDR_GRP_RE.match(line)
            if m:
                grp = {"name": m.group(1), "id": m.group(2), "sections": []}
                i += 1
                while i < n and lines[i].startswith(" "):
                    sm = _NAT_SECTION_RE.match(lines[i])
                    if sm:
                        grp["sections"].append(
                            {
                                "index": sm.group(1),
                                "start": sm.group(2),
                                "end": sm.group(3),
                            }
                        )
                    i += 1
                result["nat"]["address_groups"].append(grp)
                continue

            # acl number <id>
            m = _ACL_HDR_RE.match(line)
            if m:
                acl = {"id": m.group(1), "rules": []}
                i += 1
                while i < n and lines[i].startswith(" "):
                    rrm = _ACL_RULE_RE.match(lines[i])
                    if rrm:
                        acl["rules"].append(
                            {
                                "num": rrm.group(1),
                                "action": rrm.group(2),
                                "rest": (rrm.group(3) or "").strip(),
                            }
                        )
                    i += 1
                result["acls"].append(acl)
                continue

            # interface <name>
            m = _INTERFACE_RE.match(line)
            if m:
                name = m.group(1)
                iface: dict[str, Any] = {
                    "name": name,
                    "ip": None,
                    "mask": None,
                    "zone": None,
                    "service_manage": [],
                }
                i += 1
                while i < n and lines[i].startswith(" "):
                    im = _IP_ADDR_RE.match(lines[i])
                    if im:
                        iface["ip"] = im.group(1)
                        iface["mask"] = im.group(2)
                    smm = _SERVICE_MANAGE_RE.match(lines[i])
                    if smm:
                        iface["service_manage"].append(
                            {"service": smm.group(1), "action": smm.group(2)}
                        )
                    i += 1
                result["interfaces"].append(iface)
                continue

            # static route (single-line command)
            m = _ROUTE_RE.match(line)
            if m:
                result["routes"].append(
                    {
                        "dest": m.group(1),
                        "mask": m.group(2),
                        "next_hop": m.group(3),
                    }
                )

            i += 1

        # AAA users: extracted from the full text via the shared helper so that
        # both inline (`local-user X password cipher Y`) and block syntax work.
        result["aaa_users"] = extract_aaa_users(content)

        # Backfill interface -> zone mapping. The `firewall zone` blocks are
        # typically declared before the interfaces, so the in-loop tag in the
        # zone handler missed interfaces not yet seen. Fix it here.
        zone_of: dict[str, str] = {}
        for z in result["zones"]:
            for ifname in z.get("interfaces", []):
                zone_of[ifname] = z["name"]
        for iface in result["interfaces"]:
            if not iface.get("zone") and iface["name"] in zone_of:
                iface["zone"] = zone_of[iface["name"]]

        return result

    @staticmethod
    def _extract_hostname(content: str) -> str:
        m = _HOSTNAME_RE.search(content)
        return m.group(1) if m else "unknown"

    @staticmethod
    def _parse_rule(
        name: str, ptype: str, lines: list[str], rule_idx: int, end: int
    ) -> tuple[dict[str, Any], int]:
        rule: dict[str, Any] = {
            "name": name,
            "type": ptype,
            "source_zone": None,
            "dest_zone": None,
            "source_address": None,
            "dest_address": None,
            "service": None,
            "action": None,
        }
        # Indentation of the `rule name` line; attributes live at strictly
        # greater indent. Using the measured indent makes the parser tolerant
        # to 1-space vs 2-space VRP style differences.
        rule_indent = len(lines[rule_idx]) - len(lines[rule_idx].lstrip(" "))
        i = rule_idx + 1
        while i < end:
            ln = lines[i]
            if not ln.strip():
                i += 1
                continue
            indent = len(ln) - len(ln.lstrip(" "))
            if indent <= rule_indent:
                # de-indented to sibling rule or block header -> stop
                break
            if _RULE_NAME_RE.match(ln):
                break
            if m := _SRC_ZONE_RE.match(ln):
                rule["source_zone"] = m.group(1)
            elif m := _DST_ZONE_RE.match(ln):
                rule["dest_zone"] = m.group(1)
            elif m := _SRC_ADDR_RE.match(ln):
                rule["source_address"] = m.group(1).strip()
            elif m := _DST_ADDR_RE.match(ln):
                rule["dest_address"] = m.group(1).strip()
            elif m := _SERVICE_RE.match(ln):
                rule["service"] = m.group(1).strip()
            elif m := _ACTION_RE.match(ln):
                rule["action"] = m.group(1)
            i += 1
        return rule, i
