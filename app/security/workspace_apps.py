"""Company-approved application launcher for the secure workspace window.

Only entries listed in config/workspace_apps.json can be launched. The window never
accepts a free-form command. This is an application-level convenience control: it does
not stop a user from starting other programs outside SecureWork AI.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG = Path("config/workspace_apps.json")


@dataclass(frozen=True)
class WorkspaceApp:
    name: str
    command: str  # executable path or a name resolvable on PATH


def load_workspace_apps(path: Path | str = DEFAULT_CONFIG) -> list[WorkspaceApp]:
    """Return approved apps; a missing/malformed config yields an empty list (fail closed)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        apps = []
        for item in data.get("approved_apps", []):
            name, command = str(item.get("name", "")).strip(), str(item.get("command", "")).strip()
            if name and command:
                apps.append(WorkspaceApp(name, command))
        return apps
    except (OSError, ValueError, AttributeError):
        return []


def resolve(app: WorkspaceApp) -> str | None:
    """Absolute path of the executable if it exists, else None."""
    if os.path.isabs(app.command):
        return app.command if os.path.isfile(app.command) else None
    return shutil.which(app.command)


def launch(app: WorkspaceApp, approved: list[WorkspaceApp]) -> subprocess.Popen:
    if app not in approved:
        raise PermissionError(f"'{app.name}' is not an approved workspace application")
    exe = resolve(app)
    if exe is None:
        raise FileNotFoundError(f"'{app.name}' is not installed or the path is invalid")
    return subprocess.Popen([exe], shell=False)


def save_workspace_apps(apps: list[WorkspaceApp], path: Path | str = DEFAULT_CONFIG) -> None:
    """Atomically write the approved list (temp file + replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"approved_apps": [{"name": a.name, "command": a.command} for a in apps]},
                              indent=2), encoding="utf-8")
    os.replace(tmp, path)
