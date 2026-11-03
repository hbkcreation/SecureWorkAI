"""Rule-based live intrusion detection over payload-free packet metadata.

This is NOT the machine-learning model (which stays gated, see README). It applies
three transparent heuristics to live PacketRecord metadata:

* PORT_SCAN   - one source touches >= scan_ports distinct destination ports of a host within the window
* SYN_FLOOD   - >= syn_threshold bare SYN packets (no ACK) from one source to one host within the window
* HIGH_RATE   - >= rate_threshold packets from one source within the window

Alerts are signals, not proof of compromise. Thresholds are conservative defaults
and should be tuned per network. Repeat alerts for the same rule/source/target are
suppressed for `cooldown` seconds.
"""
from __future__ import annotations

import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from app.security.network_monitor import PacketRecord


@dataclass(frozen=True)
class RuleAlert:
    timestamp: float
    rule: str
    severity: str
    source_ip: str
    target_ip: str
    detail: str


class ProtocolCounter:
    """Thread-safe packet counts by protocol for the dashboard pie chart."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: Counter[str] = Counter()

    def add(self, packet: PacketRecord) -> None:
        with self._lock:
            self._counts[(packet.protocol or "OTHER").upper()] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


class RuleBasedIDS:
    def __init__(self, window: float = 10.0, scan_ports: int = 20, syn_threshold: int = 100,
                 rate_threshold: int = 2000, cooldown: float = 30.0, max_alerts: int = 500) -> None:
        self.window, self.scan_ports = window, scan_ports
        self.syn_threshold, self.rate_threshold, self.cooldown = syn_threshold, rate_threshold, cooldown
        self._lock = threading.Lock()
        self._ports: dict[tuple[str, str], deque] = defaultdict(deque)   # (src,dst) -> (t, port)
        self._syns: dict[tuple[str, str], deque] = defaultdict(deque)    # (src,dst) -> t
        self._rate: dict[str, deque] = defaultdict(deque)                # src -> t
        self._last_alert: dict[tuple[str, str, str], float] = {}
        self._alerts: deque[RuleAlert] = deque(maxlen=max_alerts)
        self.active = False
        self.packets_checked = 0

    def start(self) -> None:
        with self._lock:
            self.active = True

    def stop(self) -> None:
        with self._lock:
            self.active = False

    @property
    def alerts(self) -> tuple[RuleAlert, ...]:
        with self._lock:
            return tuple(self._alerts)

    def process_packet(self, p: PacketRecord) -> None:
        """Packet-monitor callback; a no-op while stopped."""
        with self._lock:
            if not self.active:
                return
            self.packets_checked += 1
            now, cutoff = p.timestamp, p.timestamp - self.window
            src, dst = p.source_ip, p.destination_ip

            r = self._rate[src]
            r.append(now)
            self._trim(r, cutoff)
            if len(r) >= self.rate_threshold:
                self._emit(now, "HIGH_RATE", "medium", src, dst, f"{len(r)} packets in {self.window:.0f}s")

            flags = (p.tcp_flags or "").upper()
            if p.protocol and p.protocol.upper() == "TCP":
                if p.destination_port is not None:
                    pq = self._ports[(src, dst)]
                    pq.append((now, p.destination_port))
                    while pq and pq[0][0] < cutoff:
                        pq.popleft()
                    ports = {port for _, port in pq}
                    if len(ports) >= self.scan_ports:
                        self._emit(now, "PORT_SCAN", "high", src, dst, f"{len(ports)} distinct ports in {self.window:.0f}s")
                if "S" in flags and "A" not in flags:
                    sq = self._syns[(src, dst)]
                    sq.append(now)
                    self._trim(sq, cutoff)
                    if len(sq) >= self.syn_threshold:
                        self._emit(now, "SYN_FLOOD", "critical", src, dst, f"{len(sq)} SYN packets without ACK in {self.window:.0f}s")

    @staticmethod
    def _trim(q: deque, cutoff: float) -> None:
        while q and q[0] < cutoff:
            q.popleft()

    def _emit(self, now, rule, severity, src, dst, detail) -> None:
        key = (rule, src, dst)
        if now - self._last_alert.get(key, -1e18) < self.cooldown:
            return
        self._last_alert[key] = now
        self._alerts.append(RuleAlert(now, rule, severity, src, dst, detail))
