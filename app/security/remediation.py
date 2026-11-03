"""Plain-language 'what to do next' guidance for each kind of alert.

Important limit: SecureWork AI sees packet metadata and running programs, not message
content, so it CANNOT detect phishing emails or malicious links itself. Phishing guidance
is included because it is the most common way a device ends up attacked, and is shown
as general advice with every alert.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AlertInfo:
    kind: str            # PORT_SCAN, SYN_FLOOD, HIGH_RATE, DOS_FLOOD, DATA_EXFILTRATION, UNAUTHORIZED_APP, TEST
    severity: str        # low | medium | high | critical
    title: str
    detail: str
    source: str = ""
    target: str = ""
    timestamp: float = field(default_factory=time.time)
    origin: str = "rule"  # "rule" (rule-based IDS / app monitor) or "ml" (experimental model)


@dataclass(frozen=True)
class Advice:
    summary: str
    steps: tuple[str, ...]


PHISHING_TIPS = (
    "Do not click links or open attachments in unexpected emails, texts or chats, even if they look like they come from your company.",
    "If you already clicked or typed a password: change that password now from a different device, sign out of other sessions, and tell your IT/security team.",
    "Report the message to your IT/security team instead of forwarding it, and delete it.",
    "Turn on multi-factor authentication for your work accounts.",
)

_COMMON_END = (
    "Tell your IT/security team what you saw and when (this alert's time is shown above).",
    "Keep this device off public Wi-Fi until it has been checked.",
)

_ADVICE: dict[str, Advice] = {
    "PORT_SCAN": Advice(
        "Another device is probing many network ports on this device or network, which is a common first step before an attack.",
        ("Check whether the source address is a device you recognise (your own scanner or IT tools can look like this).",
         "If you do not recognise it, disconnect from that network or switch to your approved USB Wi-Fi adapter on a trusted network.",
         "Make sure the Windows firewall is on and that Windows and your apps are fully updated.",
         "Close any remote-access or file-sharing features you are not using.") + _COMMON_END),
    "SYN_FLOOD": Advice(
        "A very large number of half-open connection requests were seen. This is the pattern of a denial-of-service attempt.",
        ("Disconnect from the network for a minute and reconnect; a flood often stops when the connection resets.",
         "Do not run work on this network until the source is identified; use a trusted network.",
         "If the source is inside your office network, tell IT so they can block it at the router or firewall.") + _COMMON_END),
    "DOS_FLOOD": Advice(
        "The Random Forest model flagged a traffic burst that looks like a flood (experimental model trained on synthetic data).",
        ("Treat this as a hint: check whether you are running a large download, backup or sync that explains it.",
         "If not, disconnect and reconnect to the network, and tell IT if it repeats.") + _COMMON_END),
    "HIGH_RATE": Advice(
        "One device sent an unusually high number of packets in a short time.",
        ("Check for large uploads/downloads, backups or video calls that explain the traffic.",
         "If nothing explains it, disconnect from the network and tell IT.") + _COMMON_END),
    "DATA_EXFILTRATION": Advice(
        "The model flagged a large outgoing transfer. This could be a normal upload, or data leaving the device without your knowledge (experimental model trained on synthetic data).",
        ("Think about whether you started a large upload or sync (cloud storage, backups, video uploads).",
         "If not: disconnect from the network right away, and do not enter passwords until it is checked.",
         "Run a full Windows Security (Defender) scan and check recently installed programs.",
         "Tell your IT/security team immediately, since company data may be involved.") + _COMMON_END),
    "UNAUTHORIZED_APP": Advice(
        "A program that is not allowed for work is running on this device.",
        ("If you started it on purpose, close it while working, or ask IT to approve it and then switch it on in the Apps tab.",
         "If you do not recognise it, close it, run a full Windows Security (Defender) scan, and uninstall it if it is not needed.",
         "Only install software from sources your company approves.") + _COMMON_END[:1]),
    "TEST": Advice(
        "This is a test alert to show how alerts look. Nothing was detected.",
        ("No action needed.",)),
}
_DEFAULT = Advice("Suspicious activity was detected.", _COMMON_END)


def advice_for(kind: str) -> Advice:
    return _ADVICE.get(kind, _DEFAULT)
