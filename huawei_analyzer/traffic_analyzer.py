"""Traffic/session log security analyzer.

Consumes parsed session records from :class:`~huawei_analyzer.parsers.
traffic_log.TrafficLogParser` and performs security-oriented aggregation:

- IP classification: internal / office (external private) / public /
  other_private / special, using the :mod:`ipaddress` stdlib.
- Outbound analysis: internal -> public sessions, top sources/destinations.
- Inbound analysis: public -> internal sessions, top sources/destinations.
- Protocol distribution, zone-pair distribution, per-interface counts.
- Cross-zone internal traffic (lateral-movement indicator).
- Dual-interface detection (same IP on multiple interfaces).

The internal/office network prefix lists are configurable via the
``internal_prefixes`` and ``office_prefixes`` constructor arguments so the
analyzer adapts to different network environments.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from typing import Any


class TrafficAnalyzer:
    """Analyze parsed traffic/session logs for security insights."""

    def __init__(
        self,
        internal_prefixes: tuple[str, ...] = ("10.64",),
        office_prefixes: tuple[str, ...] = ("10.185", "10.186"),
    ) -> None:
        self.internal_prefixes = internal_prefixes
        self.office_prefixes = office_prefixes

    # ------------------------------------------------------------------
    # IP classification
    # ------------------------------------------------------------------
    def classify_ip(self, ip: str) -> str:
        """Classify an IP address.

        Returns one of: ``internal``, ``office``, ``public``,
        ``other_private``, ``special``, ``invalid``.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return "invalid"
        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return "special"
        if addr.is_private:
            s = str(addr)
            if any(s.startswith(p) for p in self.office_prefixes):
                return "office"
            if any(s.startswith(p) for p in self.internal_prefixes):
                return "internal"
            return "other_private"
        return "public"

    # ------------------------------------------------------------------
    # Main analysis entry point
    # ------------------------------------------------------------------
    def analyze(self, traffic_result: dict[str, Any]) -> dict[str, Any]:
        """Analyze a TrafficLogParser result dict.

        Returns a new dict with aggregated security metrics. The original
        ``traffic_result`` is not mutated.
        """
        sessions = traffic_result.get("sessions", [])
        total = len(sessions)
        if total == 0:
            return {
                "device_type": "traffic_log",
                "total_sessions": 0,
                "error": traffic_result.get("error", "无会话记录"),
                "time_range": traffic_result.get("time_range", {}),
            }

        # Aggregation containers
        by_protocol: Counter = Counter()
        by_policy: Counter = Counter()
        by_vsys: Counter = Counter()
        by_zone_pair: Counter = Counter()
        by_in_interface: Counter = Counter()
        by_out_interface: Counter = Counter()

        # IP classification counters
        src_classes: Counter = Counter()
        dst_classes: Counter = Counter()

        # Outbound: internal -> public
        outbound: dict[str, Any] = {
            "total": 0,
            "top_sources": Counter(),
            "top_destinations": Counter(),
            "top_protocols": Counter(),
            "top_policies": Counter(),
        }
        # Inbound: public -> internal
        inbound: dict[str, Any] = {
            "total": 0,
            "top_sources": Counter(),
            "top_destinations": Counter(),
            "top_protocols": Counter(),
        }
        # Internal cross-zone (lateral movement indicator)
        internal_crosszone: Counter = Counter()
        # Dual-interface tracking
        ip_interfaces: dict[str, set] = defaultdict(set)

        for s in sessions:
            proto = s.get("protocol", "")
            policy = s.get("policy", "")
            vsys = s.get("vsys", "")
            src_ip = s.get("src_ip", "")
            dst_ip = s.get("dst_ip", "")
            src_zone = s.get("src_zone", "")
            dst_zone = s.get("dst_zone", "")
            in_if = s.get("in_interface", "")
            out_if = s.get("out_interface", "")

            by_protocol[proto] += 1
            by_policy[policy] += 1
            by_vsys[vsys] += 1
            by_zone_pair[f"{src_zone}->{dst_zone}"] += 1
            if in_if:
                by_in_interface[in_if] += 1
            if out_if:
                by_out_interface[out_if] += 1

            src_cls = self.classify_ip(src_ip)
            dst_cls = self.classify_ip(dst_ip)
            src_classes[src_cls] += 1
            dst_classes[dst_cls] += 1

            # Outbound: internal -> public
            if src_cls == "internal" and dst_cls == "public":
                outbound["total"] += 1
                outbound["top_sources"][src_ip] += 1
                outbound["top_destinations"][dst_ip] += 1
                outbound["top_protocols"][proto] += 1
                if policy:
                    outbound["top_policies"][policy] += 1

            # Inbound: public -> internal
            if src_cls == "public" and dst_cls == "internal":
                inbound["total"] += 1
                inbound["top_sources"][src_ip] += 1
                inbound["top_destinations"][dst_ip] += 1
                inbound["top_protocols"][proto] += 1

            # Internal cross-zone (lateral movement)
            if src_cls == "internal" and dst_cls == "internal":
                if src_zone != dst_zone and src_zone and dst_zone:
                    internal_crosszone[
                        f"{src_ip} -> {dst_ip} ({src_zone}->{dst_zone})"
                    ] += 1

            # Dual-interface: track which interfaces each IP appears on
            if in_if and src_ip:
                ip_interfaces[src_ip].add(in_if)
            if out_if and dst_ip:
                ip_interfaces[dst_ip].add(out_if)

        # Find dual-interface IPs (appear on >1 interface)
        dual_iface = {
            ip: sorted(ifaces)
            for ip, ifaces in ip_interfaces.items()
            if len(ifaces) > 1
        }

        return {
            "device_type": "traffic_log",
            "total_sessions": total,
            "error": None,
            "time_range": traffic_result.get("time_range", {}),
            "by_protocol": dict(by_protocol.most_common(20)),
            "by_policy": dict(by_policy.most_common(20)),
            "by_vsys": dict(by_vsys.most_common()),
            "by_zone_pair": dict(by_zone_pair.most_common(20)),
            "by_in_interface": dict(by_in_interface.most_common(20)),
            "by_out_interface": dict(by_out_interface.most_common(20)),
            "src_ip_classes": dict(src_classes),
            "dst_ip_classes": dict(dst_classes),
            "outbound": {
                "total": outbound["total"],
                "top_sources": dict(outbound["top_sources"].most_common(15)),
                "top_destinations": dict(
                    outbound["top_destinations"].most_common(15)
                ),
                "top_protocols": dict(outbound["top_protocols"].most_common(10)),
                "top_policies": dict(outbound["top_policies"].most_common(10)),
            },
            "inbound": {
                "total": inbound["total"],
                "top_sources": dict(inbound["top_sources"].most_common(15)),
                "top_destinations": dict(
                    inbound["top_destinations"].most_common(15)
                ),
                "top_protocols": dict(inbound["top_protocols"].most_common(10)),
            },
            "internal_crosszone": dict(internal_crosszone.most_common(15)),
            "dual_interface_ips": dict(
                sorted(dual_iface.items(), key=lambda x: -len(x[1]))[:20]
            ),
        }
