"""Discover applications installed on this device (Windows registry; read-only).

Sources: App Paths and Uninstall keys (HKLM/HKCU, incl. WOW6432Node) plus a few built-in
tools found on PATH. Only entries whose executable file exists are returned. Nothing is
executed during discovery.
"""
from __future__ import annotations

import ntpath
import os
import re
import shutil
import sys
from typing import Callable, Iterable

from app.security.workspace_apps import WorkspaceApp

_SKIP = re.compile(r"(unins|uninstall|setup|install|update|helper|crash|redist|vc_redist)", re.I)
_BUILTIN = {"Notepad": "notepad.exe", "Calculator": "calc.exe", "Paint": "mspaint.exe",
            "Command-line tools disabled": ""}  # placeholder removed below
_BUILTIN.pop("Command-line tools disabled")


def _base(path: str) -> str:
    return ntpath.basename(path.replace("/", "\\"))


def _clean_path(value: str) -> str:
    value = os.path.expandvars(value.strip().strip('"'))
    value = re.sub(r",\s*-?\d+$", "", value)  # DisplayIcon "C:\x.exe,0"
    return value.strip().strip('"')


def registry_entries() -> list[tuple[str, str]]:
    """Raw (name, path) pairs from the Windows registry; empty on other platforms."""
    if sys.platform != "win32":
        return []
    import winreg
    out: list[tuple[str, str]] = []
    app_paths = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, 0), (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    for hive, wow in roots:
        for base, kind in ((app_paths, "path"), (uninstall, "uninstall")):
            try:
                with winreg.OpenKey(hive, base, 0, winreg.KEY_READ | wow) as key:
                    count = winreg.QueryInfoKey(key)[0]
                    for i in range(count):
                        try:
                            sub = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, sub) as sk:
                                if kind == "path":
                                    path, _ = winreg.QueryValueEx(sk, "")
                                    out.append((ntpath.splitext(sub)[0], path))
                                else:
                                    name, _ = winreg.QueryValueEx(sk, "DisplayName")
                                    icon, _ = winreg.QueryValueEx(sk, "DisplayIcon")
                                    out.append((name, icon))
                        except OSError:
                            continue
            except OSError:
                continue
    return out


def discover_installed_apps(raw: Iterable[tuple[str, str]] | None = None,
                            exists: Callable[[str], bool] = os.path.isfile) -> list[WorkspaceApp]:
    pairs = list(registry_entries() if raw is None else raw)
    pairs += [(name, shutil.which(exe) or "") for name, exe in _BUILTIN.items()]
    seen: set[str] = set()
    apps: list[WorkspaceApp] = []
    for name, path in pairs:
        path = _clean_path(path or "")
        if not path or not path.lower().endswith(".exe") or _SKIP.search(_base(path)):
            continue
        key = path.lower()
        if key in seen or not exists(path):
            continue
        seen.add(key)
        label = (name or ntpath.splitext(_base(path))[0]).strip()
        apps.append(WorkspaceApp(label[:80], path))
    return sorted(apps, key=lambda a: a.name.lower())
