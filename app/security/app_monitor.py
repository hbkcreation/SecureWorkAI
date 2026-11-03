"""Optional running-app monitor.

Compares running programs with the apps found on this device. A program that is installed
but NOT switched on in the Apps tab raises an alert. Background/system processes and
apps SecureWork AI cannot identify are ignored on purpose, so this does not flood the user.
"""
from __future__ import annotations

import csv
import io
import ntpath
import subprocess
import sys

from app.security.remediation import AlertInfo
from app.security.workspace_apps import WorkspaceApp


def running_exe_names() -> set[str]:
    """Lower-case names of running executables (read-only; no elevation needed)."""
    try:
        import psutil  # optional
        return {(p.info["name"] or "").lower() for p in psutil.process_iter(["name"])} - {""}
    except ImportError:
        pass
    if sys.platform != "win32":
        return set()
    try:
        out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True,
                             timeout=15, shell=False).stdout
        return {row[0].lower() for row in csv.reader(io.StringIO(out)) if row}
    except (OSError, subprocess.SubprocessError):
        return set()


def check_running(all_apps: list[WorkspaceApp], allowed: list[WorkspaceApp], running: set[str]) -> list[AlertInfo]:
    allowed_exes = {ntpath.basename(a.command.replace("/", "\\")).lower() for a in allowed}
    seen, alerts = set(), []
    for app in all_apps:
        exe = ntpath.basename(app.command.replace("/", "\\")).lower()
        if not exe or exe in allowed_exes or exe in seen or exe not in running:
            continue
        seen.add(exe)
        alerts.append(AlertInfo("UNAUTHORIZED_APP", "medium", f"App not allowed for work is running: {app.name}",
                                f"{app.name} ({app.command}) is running but is switched off in the Apps tab.",
                                source=exe))
    return alerts
