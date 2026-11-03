"""Full-verification checklist for the SecureWork AI workspace.

'Fully verified' means every check below passes right now. It describes the state of this
workspace's protections; it is not a guarantee that the device is secure.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationState:
    usb_adapter_approved: bool
    capture_active: bool
    rule_ids_active: bool
    ml_active: bool
    allowed_apps: int
    app_monitor_on: bool


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    fix: str


def run_checks(s: VerificationState) -> list[Check]:
    return [
        Check("Approved USB Wi-Fi adapter detected", s.usb_adapter_approved,
              "Plug in the approved adapter and press Refresh in System."),
        Check("Network monitoring running", s.capture_active, "Go to Network and press Start Monitoring."),
        Check("Rule-based IDS active", s.rule_ids_active, "It starts with monitoring; resume it in Detection if paused."),
        Check("ML analysis running", s.ml_active, "Go to Detection and press Start ML analysis."),
        Check("At least one work app allowed", s.allowed_apps > 0, "Go to Apps and switch on your approved apps."),
        Check("Running-app monitoring on", s.app_monitor_on, "Go to Apps and turn on Monitor running apps."),
    ]


def is_fully_verified(checks: list[Check]) -> bool:
    return all(c.ok for c in checks)
