"""Shared helpers used by both the firewall and switch parsers.

Currently provides AAA local-user extraction that supports both the legacy
inline form::

    local-user admin password cipher P@ss
    local-user admin privilege level 15
    local-user admin service-type telnet ssh

and the newer block form::

    aaa
     local-user admin
      password cipher P@ss
      privilege level 15
      service-type telnet ssh
"""

from __future__ import annotations

import re
from typing import Any

_USER_DECL_RE = re.compile(r"^\s*local-user\s+(\S+)\s*(.*)$")
_PW_RE = re.compile(r"password\s+(cipher|simple|irreversible-cipher)\s+(\S+)")
_PRIV_RE = re.compile(r"privilege\s+level\s+(\d+)")
_SVC_RE = re.compile(r"service-type\s+(.+?)\s*$")


def extract_aaa_users(content: str) -> list[dict[str, Any]]:
    """Return a list of AAA local-user records, deduplicated by name.

    Both inline attributes and indented block attributes are merged into a
    single record per user, preserving first-seen order.
    """
    lines = content.splitlines()
    users: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        m = _USER_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        if name not in users:
            users[name] = {
                "name": name,
                "password_cipher": None,
                "password_type": None,
                "privilege": None,
                "services": [],
            }
            order.append(name)
        user = users[name]
        # apply attributes declared inline on the `local-user` line itself
        _apply_attrs(m.group(2), user)
        # then apply any deeper-indented continuation lines (block form)
        base_indent = len(lines[i]) - len(lines[i].lstrip(" "))
        j = i + 1
        while j < n:
            sub = lines[j]
            if not sub.strip():
                j += 1
                continue
            if _USER_DECL_RE.match(sub):
                break
            sub_indent = len(sub) - len(sub.lstrip(" "))
            if sub.strip() and sub_indent <= base_indent:
                break
            _apply_attrs(sub.strip(), user)
            j += 1
        i = j
    return [users[name] for name in order]


def _apply_attrs(text: str, user: dict[str, Any]) -> None:
    if not text:
        return
    if m := _PW_RE.search(text):
        user["password_type"] = m.group(1)
        user["password_cipher"] = m.group(2)
    if m := _PRIV_RE.search(text):
        user["privilege"] = m.group(1)
    if m := _SVC_RE.search(text):
        user["services"] = [s.strip() for s in m.group(1).split() if s.strip()]
