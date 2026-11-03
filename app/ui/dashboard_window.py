"""SecureWork AI dashboard: sidebar navigation, live KPIs, charts and detection panels."""
import logging

import time

from PySide6.QtCore import QObject, QPropertyAnimation, QRunnable, Qt, Signal, Slot, QThreadPool, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QMainWindow, QPushButton,
    QListWidget, QListWidgetItem, QScrollArea, QStackedWidget, QVBoxLayout, QWidget,
)
from app.ml.predict import DEFAULT_MODEL_PATH
from app.security.flow_aggregator import LiveFlowAggregator
from app.security.ids_service import FeatureCompatibilityError, IDSService
from app.security.network_monitor import NetworkInterface, NetworkMonitor
from app.security.rule_ids import ProtocolCounter, RuleBasedIDS
from app.ml.live_synthetic import LiveMLAnalyzer
from app.ui import theme
from app.ui.protocol_chart import ProtocolPieChart
from app.ui.widgets import Avatar, KpiCard, Sparkline, card, make_chip, set_chip
from app.security.usb_checker import USBAdapterChecker, USBAdapterStatus, STATUS_APPROVED

logger = logging.getLogger(__name__)


class _USBCheckSignals(QObject):
    finished = Signal(object)


class _USBCheckWorker(QRunnable):
    def __init__(self, checker: USBAdapterChecker) -> None:
        super().__init__()
        self.checker = checker
        self.signals = _USBCheckSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self.checker.check()
        except Exception as exc:
            logger.exception("Unexpected USB adapter status check failure")
            result = USBAdapterStatus(
                status="unknown",
                detected=False,
                approved=False,
                reason=f"Unable to check the USB Wi-Fi adapter: {exc}",
                error=str(exc),
            )
        self._emit_finished(result)

    def _emit_finished(self, result: USBAdapterStatus) -> None:
        try:
            self.signals.finished.emit(result)
        except RuntimeError:
            # The dashboard may close while this best-effort status check runs.
            logger.debug("Discarding USB status result after dashboard teardown")


class _ActionSignals(QObject):
    finished = Signal(object, object)


class _ActionWorker(QRunnable):
    def __init__(self, action) -> None:
        super().__init__()
        self.action = action
        self.signals = _ActionSignals()

    @Slot()
    def run(self) -> None:
        try:
            self._emit_finished(self.action(), None)
        except Exception as exc:
            self._emit_finished(None, exc)

    def _emit_finished(self, result, error) -> None:
        try:
            self.signals.finished.emit(result, error)
        except RuntimeError:
            # The dashboard may close while a non-destructive worker completes.
            logger.debug("Discarding background action result after dashboard teardown")


class DashboardWindow(QMainWindow):
    def __init__(
        self,
        on_logout,
        usb_checker: USBAdapterChecker | None = None,
        network_monitor: NetworkMonitor | None = None,
        username: str = "",
    ) -> None:
        super().__init__()
        self._on_logout = on_logout
        self._usb_checker = usb_checker or USBAdapterChecker()
        self.network_monitor = network_monitor or NetworkMonitor(usb_checker=self._usb_checker)
        self.ids_service = IDSService(DEFAULT_MODEL_PATH)
        self.ml_analyzer = LiveMLAnalyzer()
        self.flow_aggregator = LiveFlowAggregator(on_flow_completed=self._on_flow_completed)
        self._packet_callback = self.flow_aggregator.process_packet
        self.network_monitor.add_packet_callback(self._packet_callback)
        self.rule_ids = RuleBasedIDS()
        self.protocol_counter = ProtocolCounter()
        self.network_monitor.add_packet_callback(self.rule_ids.process_packet)
        self.network_monitor.add_packet_callback(self.protocol_counter.add)
        self._logged_rule_alerts = 0
        self._usb_worker: _USBCheckWorker | None = None
        self._ids_model_worker: _ActionWorker | None = None
        self._action_workers: set[_ActionWorker] = set()
        self._event_history_worker: _ActionWorker | None = None
        self._persisted_events = ()
        self._latest_usb_status: USBAdapterStatus | None = None
        self._active_action_worker: _ActionWorker | None = None
        self._active_action_success = None
        self._network_action_busy = False
        self._logout_pending = False
        self._close_pending = False
        self._thread_pool = QThreadPool.globalInstance()
        self.setWindowTitle("SecureWork AI | Dashboard")
        self.setMinimumSize(1100, 720)
        self._build_ui(username)

        self._network_timer = QTimer(self)
        self._network_timer.timeout.connect(self._refresh_network_snapshot)
        self._network_timer.start(400)
        self._load_ids_model()
        self._load_recent_events()
        self._refresh_system_status()
        self.refresh_usb_status()
        self.refresh_network_interfaces()

    # ------------------------------------------------------------------ UI
    def _build_ui(self, username: str) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ---- sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(232)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(16, 22, 16, 18)
        sb.setSpacing(6)
        brand = QLabel("◈  SecureWork AI")
        brand.setObjectName("brand")
        tag = QLabel("BYOD security workspace")
        tag.setObjectName("muted")
        sb.addWidget(brand)
        sb.addWidget(tag)
        sb.addSpacing(22)
        self._nav_buttons: list[QPushButton] = []
        for index, (icon, label) in enumerate(
            [("▦", "Overview"), ("◉", "Network"), ("⛨", "Detection"), ("⚙", "System")]
        ):
            btn = QPushButton(f"{icon}   {label}")
            btn.setObjectName("navButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _=False, i=index: self._show_page(i))
            sb.addWidget(btn)
            self._nav_buttons.append(btn)
        sb.addStretch(1)
        footer = QLabel("Signals are indicators, not proof of compromise.")
        footer.setObjectName("muted")
        footer.setWordWrap(True)
        sb.addWidget(footer)
        logout = QPushButton("Sign out")
        logout.setObjectName("secondaryButton")
        logout.setCursor(Qt.PointingHandCursor)
        logout.clicked.connect(self._request_logout)
        sb.addWidget(logout)
        outer.addWidget(sidebar)

        # ---- main column: top bar + pages
        main = QVBoxLayout()
        main.setContentsMargins(26, 20, 26, 20)
        main.setSpacing(16)
        top = QHBoxLayout()
        self.page_title = QLabel("Overview")
        self.page_title.setObjectName("pageTitle")
        top.addWidget(self.page_title)
        top.addStretch(1)
        self.chip_capture = make_chip("Capture: stopped")
        self.chip_rules = make_chip("Rule IDS: idle")
        self.chip_ml = make_chip("ML: off")
        for chip in (self.chip_capture, self.chip_rules, self.chip_ml):
            top.addWidget(chip)
        top.addSpacing(10)
        who = QVBoxLayout()
        who.setSpacing(0)
        name_label = QLabel(username or "Signed in")
        name_label.setStyleSheet("font-weight:700;")
        role_label = QLabel("Secure session")
        role_label.setObjectName("muted")
        who.addWidget(name_label, alignment=Qt.AlignRight)
        who.addWidget(role_label, alignment=Qt.AlignRight)
        top.addLayout(who)
        top.addWidget(Avatar(username))
        main.addLayout(top)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._scroll(self._page_overview()))
        self.pages.addWidget(self._scroll(self._page_network()))
        self.pages.addWidget(self._scroll(self._page_detection()))
        self.pages.addWidget(self._scroll(self._page_system()))
        main.addWidget(self.pages, 1)
        outer.addLayout(main, 1)
        self.setCentralWidget(root)
        self._show_page(0)

    @staticmethod
    def _scroll(content: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setWidget(content)
        return area

    def _show_page(self, index: int) -> None:
        names = ["Overview", "Network", "Detection", "System"]
        self.pages.setCurrentIndex(index)
        self.page_title.setText(names[index])
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        page = self.pages.currentWidget()
        effect = QGraphicsOpacityEffect(page)
        page.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", self)
        anim.setDuration(260)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.finished.connect(lambda: page.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def _page_overview(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(16)
        row = QHBoxLayout()
        row.setSpacing(14)
        self.kpi_packets = KpiCard("Packets captured", theme.CYAN)
        self.kpi_flows = KpiCard("Flows completed", theme.VIOLET)
        self.kpi_rules = KpiCard("Rule alerts", theme.WARN)
        self.kpi_ml = KpiCard("ML flagged flows", theme.BAD)
        for k in (self.kpi_packets, self.kpi_flows, self.kpi_rules, self.kpi_ml):
            row.addWidget(k)
        lay.addLayout(row)

        mid = QHBoxLayout()
        mid.setSpacing(14)
        c1, l1 = card("Live packets by protocol")
        self.protocol_chart = ProtocolPieChart()
        l1.addWidget(self.protocol_chart, 1)
        c2, l2 = card("Traffic rate")
        self.rate_chart = Sparkline()
        l2.addWidget(self.rate_chart, 1)
        mid.addWidget(c1, 1)
        mid.addWidget(c2, 1)
        lay.addLayout(mid)

        c3, l3 = card("Latest security signals")
        self.signal_feed = QListWidget()
        self.signal_feed.setMinimumHeight(190)
        self.signal_feed.addItem("No signals yet. Start monitoring to see live detections.")
        l3.addWidget(self.signal_feed)
        lay.addWidget(c3)
        lay.addStretch(1)
        return page

    def _page_network(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(16)
        network_card, nl = card("Network monitoring")
        self.network_status_label = QLabel("Status: STOPPED")
        self.network_status_label.setObjectName("statusValue")
        self.network_interface_combo = QComboBox()
        self.network_interface_combo.setMinimumContentsLength(32)
        self.network_interface_label = QLabel("Interface: None selected")
        self.network_interface_label.setObjectName("muted")
        self.network_packet_count_label = QLabel("Packets: 0")
        self.network_flow_count_label = QLabel("Flows: 0")
        self.network_error_label = QLabel(" ")
        self.network_error_label.setObjectName("message")
        self.network_error_label.setWordWrap(True)
        buttons = QHBoxLayout()
        self.start_monitoring_button = QPushButton("Start Monitoring")
        self.stop_monitoring_button = QPushButton("Stop Monitoring")
        self.refresh_interfaces_button = QPushButton("Refresh Interface")
        self.refresh_interfaces_button.setObjectName("secondaryButton")
        self.start_monitoring_button.clicked.connect(self.start_network_monitoring)
        self.stop_monitoring_button.clicked.connect(self.stop_network_monitoring)
        self.refresh_interfaces_button.clicked.connect(self.refresh_network_interfaces)
        for b in (self.start_monitoring_button, self.stop_monitoring_button, self.refresh_interfaces_button):
            buttons.addWidget(b)
        for w in (self.network_status_label, self.network_interface_combo, self.network_interface_label,
                  self.network_packet_count_label, self.network_flow_count_label, self.network_error_label):
            nl.addWidget(w)
        nl.addLayout(buttons)
        lay.addWidget(network_card)
        lay.addStretch(1)
        return page

    def _page_detection(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(16)

        # Rule-based IDS
        rule_card, rl = card("Rule-based live IDS")
        self.rule_ids_status_label = QLabel("Rule-based IDS: waiting for monitoring to start")
        self.rule_ids_status_label.setObjectName("statusValue")
        note = QLabel("Detects port scans, SYN floods and abnormal packet rates from live packet metadata.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        self.rule_ids_log = QListWidget()
        self.rule_ids_log.setMaximumHeight(130)
        self.rule_ids_log.addItem("No rule-based alerts.")
        self.rule_ids_pause_button = QPushButton("Pause rule-based IDS")
        self.rule_ids_pause_button.setCheckable(True)
        self.rule_ids_pause_button.setObjectName("secondaryButton")
        self.rule_ids_pause_button.toggled.connect(self._toggle_rule_ids_pause)
        for w in (self.rule_ids_status_label, note, self.rule_ids_log, self.rule_ids_pause_button):
            rl.addWidget(w)
        lay.addWidget(rule_card)

        # ML (Random Forest, synthetic-trained)
        ml_card, ml = card("ML analysis · Random Forest (synthetic-trained)")
        self.ml_status_label = QLabel("ML analysis: OFF")
        self.ml_status_label.setObjectName("statusValue")
        self.ml_counts_label = QLabel("Flows scored: 0 | flagged: 0")
        caveat = QLabel(
            "Trained on synthetic traffic profiles, not real attacks: treat results as an experimental "
            "signal. It scores completed live flows (needs capture running)."
        )
        caveat.setObjectName("muted")
        caveat.setWordWrap(True)
        self.ml_log = QListWidget()
        self.ml_log.setMaximumHeight(130)
        self.ml_log.addItem("No ML events yet.")
        mlb = QHBoxLayout()
        self.ml_start_button = QPushButton("Start ML analysis")
        self.ml_stop_button = QPushButton("Stop ML analysis")
        self.ml_stop_button.setObjectName("secondaryButton")
        self.ml_stop_button.setEnabled(False)
        self.ml_start_button.clicked.connect(self.start_ml_analysis)
        self.ml_stop_button.clicked.connect(self.stop_ml_analysis)
        mlb.addWidget(self.ml_start_button)
        mlb.addWidget(self.ml_stop_button)
        for w in (self.ml_status_label, self.ml_counts_label, caveat, self.ml_log):
            ml.addWidget(w)
        ml.addLayout(mlb)
        lay.addWidget(ml_card)

        # Legacy UNSW-NB15 model (gated)
        ids_card, il = card("UNSW-NB15 model (gated)")
        self.ids_model_status_label = QLabel("Model: Checking saved artifact...")
        self.ids_model_status_label.setObjectName("statusValue")
        self.ids_inference_status_label = QLabel("Live IDS inference unavailable: feature compatibility incomplete.")
        self.ids_inference_status_label.setObjectName("muted")
        self.ids_inference_status_label.setWordWrap(True)
        self.ids_monitoring_status_label = QLabel("Monitoring: STOPPED")
        self.ids_flow_count_label = QLabel("Completed flows checked: 0")
        self.ids_detection_count_label = QLabel("Attack signals: unavailable (inference disabled)")
        self.ids_latest_event_label = QLabel("Latest event: none; no compatible live predictions")
        self.ids_latest_event_label.setWordWrap(True)
        self.ids_event_log = QListWidget()
        self.ids_event_log.setMaximumHeight(110)
        self.ids_event_log.addItem("No prediction events; live inference is unavailable.")
        ib = QHBoxLayout()
        self.start_ids_button = QPushButton("Start UNSW analysis")
        self.stop_ids_button = QPushButton("Stop UNSW analysis")
        self.stop_ids_button.setObjectName("secondaryButton")
        self.start_ids_button.setEnabled(False)
        self.stop_ids_button.setEnabled(False)
        self.start_ids_button.setToolTip("Disabled until all UNSW-NB15 model features have verified live semantics. "
                                         "Use the Random Forest analysis above instead.")
        self.start_ids_button.clicked.connect(self.start_ids_analysis)
        self.stop_ids_button.clicked.connect(self.stop_ids_analysis)
        ib.addWidget(self.start_ids_button)
        ib.addWidget(self.stop_ids_button)
        for w in (self.ids_model_status_label, self.ids_inference_status_label, self.ids_monitoring_status_label,
                  self.ids_flow_count_label, self.ids_detection_count_label, self.ids_latest_event_label,
                  self.ids_event_log):
            il.addWidget(w)
        il.addLayout(ib)
        lay.addWidget(ids_card)
        lay.addStretch(1)
        return page

    def _page_system(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(16)
        system_card, sl = card("System status")
        self.system_status_label = QLabel("Not verified")
        self.system_status_label.setObjectName("statusValue")
        self.system_status_details_label = QLabel()
        self.system_status_details_label.setObjectName("muted")
        self.system_status_details_label.setWordWrap(True)
        sl.addWidget(self.system_status_label)
        sl.addWidget(self.system_status_details_label)
        lay.addWidget(system_card)

        usb_card, ul = card("USB Wi-Fi adapter")
        self.usb_status_label = QLabel("Status: CHECKING")
        self.usb_status_label.setObjectName("statusValue")
        self.usb_details_label = QLabel("Windows adapter information is being checked.")
        self.usb_details_label.setObjectName("muted")
        self.usb_details_label.setWordWrap(True)
        self.usb_refresh_button = QPushButton("Refresh")
        self.usb_refresh_button.setObjectName("secondaryButton")
        self.usb_refresh_button.clicked.connect(self.refresh_usb_status)
        for w in (self.usb_status_label, self.usb_details_label):
            ul.addWidget(w)
        ul.addWidget(self.usb_refresh_button, alignment=Qt.AlignLeft)
        lay.addWidget(usb_card)
        lay.addStretch(1)
        return page

    # ------------------------------------------------------------- ML control
    def start_ml_analysis(self) -> None:
        if self.ml_analyzer.active:
            return
        self.ml_start_button.setEnabled(False)
        self.ml_status_label.setText("ML analysis: preparing model (first run trains it, a few seconds)...")
        worker = _ActionWorker(self.ml_analyzer.load_or_train)
        self._action_workers.add(worker)
        worker.signals.finished.connect(lambda result, error, w=worker: self._ml_ready(w, result, error))
        self._thread_pool.start(worker)

    def _ml_ready(self, worker, result, error) -> None:
        self._action_workers.discard(worker)
        if error is not None:
            logger.error("ML model unavailable: %s", error)
            self.ml_status_label.setText(f"ML analysis: unavailable ({error})")
            self.ml_start_button.setEnabled(True)
            return
        self.ml_analyzer.start()
        self.ml_stop_button.setEnabled(True)
        self._refresh_ml()

    def stop_ml_analysis(self) -> None:
        self.ml_analyzer.stop()
        self.ml_stop_button.setEnabled(False)
        self.ml_start_button.setEnabled(True)
        self._refresh_ml()

    def _refresh_ml(self) -> None:
        a = self.ml_analyzer
        if a.active:
            self.ml_status_label.setText("ML analysis: ACTIVE (Random Forest, synthetic-trained)")
        elif a.loaded:
            self.ml_status_label.setText("ML analysis: STOPPED (model loaded)")
        elif "preparing" not in self.ml_status_label.text() and "unavailable" not in self.ml_status_label.text():
            self.ml_status_label.setText("ML analysis: OFF")
        self.ml_counts_label.setText(f"Flows scored: {a.flows_scored} | flagged: {a.attack_flows}")
        rendered = [
            f"{e.timestamp[11:19]} | {e.label} ({e.probability:.0%}) | {e.source_ip} → {e.destination_ip}:{e.destination_port}"
            for e in a.events[-6:] if e.label != "normal"
        ] or ["No ML events yet."]
        existing = [self.ml_log.item(i).text() for i in range(self.ml_log.count())]
        if rendered != existing:
            self.ml_log.clear()
            self.ml_log.addItems(rendered)

    # --------------------------------------------------------- overview feed
    def _refresh_overview(self) -> None:
        packets, flows = self.network_monitor.packet_count, self.network_monitor.flow_count
        now = time.monotonic()
        last_t, last_p = getattr(self, "_rate_last", (now, packets))
        if now - last_t >= 1.0:
            self.rate_chart.push(max(0, packets - last_p) / (now - last_t))
            self._rate_last = (now, packets)
        elif not hasattr(self, "_rate_last"):
            self._rate_last = (now, packets)
        rule_alerts = self.rule_ids.alerts
        self.kpi_packets.set(packets, "since monitoring started")
        self.kpi_flows.set(flows, f"{self.ids_service.flows_checked} checked by UNSW gate")
        self.kpi_rules.set(len(rule_alerts), "port scan · SYN flood · rate")
        self.kpi_ml.set(self.ml_analyzer.attack_flows, f"of {self.ml_analyzer.flows_scored} scored")
        signals = [(a.timestamp, a.severity.upper(), f"{a.rule}  {a.source_ip} → {a.target_ip}  {a.detail}") for a in rule_alerts]
        signals += [(0.0, "ML", f"{e.label} ({e.probability:.0%})  {e.source_ip} → {e.destination_ip}:{e.destination_port}")
                    for e in self.ml_analyzer.events if e.label != "normal"]
        signals.sort(key=lambda s: s[0])
        rendered = [f"{sev:<9} {text}" for _t, sev, text in signals[-8:]][::-1] or [
            "No signals yet. Start monitoring to see live detections."]
        existing = [self.signal_feed.item(i).text() for i in range(self.signal_feed.count())]
        if rendered != existing:
            self.signal_feed.clear()
            for line in rendered:
                item = QListWidgetItem(line)
                color = {"CRITICAL": theme.BAD, "HIGH": theme.BAD, "MEDIUM": theme.WARN, "ML": theme.VIOLET}.get(
                    line.split()[0] if line.split() else "", theme.MUTED)
                item.setForeground(QColor(color))
                self.signal_feed.addItem(item)
        set_chip(self.chip_capture, "Capture: running" if self.network_monitor.is_active() else "Capture: stopped",
                 "ok" if self.network_monitor.is_active() else "")
        set_chip(self.chip_rules, "Rule IDS: active" if self.rule_ids.active else "Rule IDS: idle",
                 "ok" if self.rule_ids.active else "")
        set_chip(self.chip_ml, "ML: active" if self.ml_analyzer.active else "ML: off",
                 "ok" if self.ml_analyzer.active else "")

    def _on_flow_completed(self, flow) -> None:
        self.ml_analyzer.inspect_completed_flow(flow)
        return self.ids_service.inspect_completed_flow(flow)

    def _load_ids_model(self) -> None:
        self._ids_model_worker = _ActionWorker(self.ids_service.load_model)
        self._ids_model_worker.signals.finished.connect(self._ids_model_loaded)
        self._thread_pool.start(self._ids_model_worker)

    @Slot(object, object)
    def _ids_model_loaded(self, result, error) -> None:
        self._ids_model_worker = None
        if error is not None:
            logger.error("IDS model status check failed: %s", error)
        self._refresh_ids_snapshot()
    def _load_recent_events(self) -> None:
        """Load persisted event history without blocking the UI."""
        self._event_history_worker = _ActionWorker(
            lambda: self.ids_service.load_recent_events(limit=100)
        )
        self._event_history_worker.signals.finished.connect(
            self._recent_events_loaded
        )
        self._thread_pool.start(self._event_history_worker)

    @Slot(object, object)
    def _recent_events_loaded(self, result, error) -> None:
        self._event_history_worker = None

        if error is not None:
            logger.error("Failed to load dashboard event history: %s", error)
            self._persisted_events = ()
        else:
            self._persisted_events = tuple(result or ())

        self._refresh_ids_snapshot()
    def refresh_usb_status(self) -> None:
        """Refresh once on demand without blocking the dashboard event loop."""
        self._latest_usb_status = None
        self.usb_refresh_button.setEnabled(False)
        self.usb_status_label.setText("Status: CHECKING")
        self.usb_details_label.setText("Windows adapter information is being checked.")
        self._refresh_system_status()
        worker = _USBCheckWorker(self._usb_checker)
        worker.signals.finished.connect(self._display_usb_status)
        self._usb_worker = worker
        self._thread_pool.start(worker)

    @Slot(object)
    def _display_usb_status(self, result: USBAdapterStatus) -> None:
        self._latest_usb_status = result
        self.usb_refresh_button.setEnabled(True)
        self.usb_status_label.setText(f"Status: {result.status.replace('_', ' ').upper()}")

        details = []
        if result.adapter_name:
            details.append(f"Adapter: {result.adapter_name}")
        if result.interface_name:
            details.append(f"Interface: {result.interface_name}")
        if result.reason:
            details.append(result.reason)
        self.usb_details_label.setText("\n".join(details) or "No adapter details available.")
        if result.status == STATUS_APPROVED:
            self.usb_status_label.setStyleSheet("color: #16794b;")
        elif result.status == "unknown":
            self.usb_status_label.setStyleSheet("color: #9a6700;")
        else:
            self.usb_status_label.setStyleSheet("color: #b42318;")
        self._refresh_system_status()

    def _refresh_system_status(self) -> None:
        """Render the limited checks currently available without overstating assurance."""
        usb_status = self._latest_usb_status
        if usb_status is None:
            status = "Not verified"
            details = "USB adapter verification is pending; overall system verification is not implemented."
        elif usb_status.status != STATUS_APPROVED or not usb_status.approved:
            status = "Not verified"
            details = "USB adapter verification did not succeed; overall system verification is not implemented."
            if usb_status.reason:
                details = f"{details} {usb_status.reason}"
        elif self.network_monitor.is_active():
            status = "Partially verified"
            details = (
                "The approved USB adapter and network monitoring are active; "
                "overall system verification is not implemented."
            )
        else:
            status = "Partially verified"
            details = "The USB adapter is approved; overall system verification is not implemented."

        self.system_status_label.setText(status)
        self.system_status_label.setStyleSheet("color: #9a6700;")
        self.system_status_details_label.setText(details)

    def refresh_network_interfaces(self) -> None:
        self.refresh_interfaces_button.setEnabled(False)
        self._run_network_action(self.network_monitor.discover_interfaces, self._interfaces_loaded)

    def _interfaces_loaded(self, interfaces: list[NetworkInterface]) -> None:
        self.network_interface_combo.clear()
        approved_index: int | None = None
        if not interfaces:
            self.network_interface_combo.addItem("No network interfaces discovered", None)
        else:
            for index, interface in enumerate(interfaces):
                approval = "APPROVED" if interface.approved else "not approved"
                description = f" | {interface.description}" if interface.description else ""
                self.network_interface_combo.addItem(
                    f"{interface.display_name}{description} [{approval}]",
                    interface,
                )
                if interface.approved and approved_index is None:
                    approved_index = index
        if approved_index is not None:
            # Scapy may list WAN Miniports before the approved USB adapter.
            # This is only a UI default; start_capture verifies approval again.
            self.network_interface_combo.setCurrentIndex(approved_index)
            self.network_error_label.setText(self.network_monitor.selection_error or " ")
        else:
            # Do not leave QComboBox's implicit first-item selection pointing at
            # an unapproved interface when the USB adapter has no safe match.
            self.network_interface_combo.insertItem(
                0,
                "No approved USB Wi-Fi interface available",
                None,
            )
            self.network_interface_combo.setCurrentIndex(0)
            self.network_error_label.setText(
                self.network_monitor.selection_error
                or "No approved USB Wi-Fi interface could be matched for monitoring."
            )
        self.start_monitoring_button.setEnabled(approved_index is not None)
        self.refresh_interfaces_button.setEnabled(True)

    def start_network_monitoring(self) -> None:
        selected = self.network_interface_combo.currentData()
        if not isinstance(selected, NetworkInterface) or not selected.approved:
            self.network_error_label.setText(
                "Select an approved USB Wi-Fi interface before starting monitoring."
            )
            self.start_monitoring_button.setEnabled(False)
            return
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(False)
        self._run_network_action(
            lambda: self._start_capture(selected if isinstance(selected, NetworkInterface) else ""),
            self._capture_started,
        )

    def _start_capture(self, selected: NetworkInterface | str) -> NetworkInterface:
        self.flow_aggregator.reset()
        self.ids_service.reset_session()
        return self.network_monitor.start_capture(selected)

    def _capture_started(self, _interface: NetworkInterface) -> None:
        self.network_error_label.setText(" ")

    def stop_network_monitoring(self) -> None:
        if self._network_action_busy:
            return
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(False)
        self._run_network_action(self._stop_capture_and_finalize)

    def _stop_capture_and_finalize(self) -> tuple:
        self.ids_service.stop_analysis()
        self.network_monitor.stop_capture()
        return self.flow_aggregator.finalize_all("monitor_stopped")

    def start_ids_analysis(self) -> None:
        if not self.network_monitor.is_active():
            self.network_error_label.setText("Start network monitoring before IDS analysis.")
            return
        try:
            self.ids_service.start_analysis()
        except FeatureCompatibilityError as exc:
            self.ids_inference_status_label.setText(str(exc))
        self._refresh_ids_snapshot()

    def stop_ids_analysis(self) -> None:
        self.ids_service.stop_analysis()
        self._refresh_ids_snapshot()

    def _run_network_action(self, action, on_success=None) -> None:
        if self._network_action_busy:
            return
        self._network_action_busy = True
        worker = _ActionWorker(action)
        self._action_workers.add(worker)
        self._active_action_worker = worker
        self._active_action_success = on_success
        worker.signals.finished.connect(self._network_action_finished)
        self._thread_pool.start(worker)

    @Slot(object, object)
    def _network_action_finished(self, result, error) -> None:
        worker = self._active_action_worker
        self._action_workers.discard(worker)
        self._active_action_worker = None
        self._network_action_busy = False
        if error is not None:
            logger.error("Network monitoring action failed: %s", error)
            self.network_error_label.setText(str(error))
        elif self._active_action_success is not None:
            self._active_action_success(result)
        self._active_action_success = None

        self._refresh_network_snapshot()
        if self._logout_pending:
            self._continue_logout()
        elif self._close_pending:
            self._continue_close()

    def _refresh_network_snapshot(self) -> None:
        status = self.network_monitor.status
        self.network_status_label.setText(f"Status: {status}")
        self.network_packet_count_label.setText(f"Packets: {self.network_monitor.packet_count}")
        self.network_flow_count_label.setText(f"Flows: {self.network_monitor.flow_count}")
        selected = self.network_monitor.selected_interface
        if selected is not None:
            self.network_interface_label.setText(f"Interface: {selected.display_name}")
        elif self.network_interface_combo.currentData() is not None:
            selected_item = self.network_interface_combo.currentData()
            if isinstance(selected_item, NetworkInterface):
                self.network_interface_label.setText(f"Interface: {selected_item.display_name}")
        if status == "ERROR" and self.network_monitor.last_error:
            self.network_error_label.setText(self.network_monitor.last_error)
        active = self.network_monitor.is_active()
        selected_item = self.network_interface_combo.currentData()
        can_start = isinstance(selected_item, NetworkInterface) and selected_item.approved
        if status != "ERROR" and not active and not can_start and not self._network_action_busy:
            self.network_error_label.setText(
                self.network_monitor.selection_error
                or "Start Monitoring is disabled: select a network interface that matches the approved USB "
                   "Wi-Fi adapter in config/device_policy.json."
            )
        if not self._network_action_busy:
            self.start_monitoring_button.setEnabled(not active and can_start)
            self.stop_monitoring_button.setEnabled(active)
            self.refresh_interfaces_button.setEnabled(not active)
        self._refresh_system_status()
        self._refresh_ids_snapshot()
        self._refresh_rule_ids(active)
        self._refresh_ml()
        self._refresh_overview()

    def _toggle_rule_ids_pause(self, paused: bool) -> None:
        self._rule_ids_paused = paused
        self.rule_ids_pause_button.setText("Resume rule-based IDS" if paused else "Pause rule-based IDS")

    def _refresh_rule_ids(self, capture_active: bool) -> None:
        paused = getattr(self, "_rule_ids_paused", False)
        if paused:
            capture_active = False
        if capture_active and not self.rule_ids.active:
            self.protocol_counter.reset()
            self.rule_ids.start()
        elif not capture_active and self.rule_ids.active:
            self.rule_ids.stop()
        alerts = self.rule_ids.alerts
        state = "ACTIVE" if self.rule_ids.active else "STOPPED"
        self.rule_ids_status_label.setText(
            f"Rule-based IDS: {state} | packets checked: {self.rule_ids.packets_checked} | alerts: {len(alerts)}"
        )
        for alert in alerts[self._logged_rule_alerts:]:
            logging.getLogger(__name__).warning(
                "Rule IDS %s (%s) %s -> %s: %s", alert.rule, alert.severity, alert.source_ip, alert.target_ip, alert.detail
            )
        self._logged_rule_alerts = len(alerts)
        rendered = [
            f"{a.severity.upper()} | {a.rule} | {a.source_ip} -> {a.target_ip} | {a.detail}" for a in alerts[-5:]
        ] or ["No rule-based alerts."]
        existing = [self.rule_ids_log.item(i).text() for i in range(self.rule_ids_log.count())]
        if rendered != existing:
            self.rule_ids_log.clear()
            self.rule_ids_log.addItems(rendered)
        self.protocol_chart.set_counts(self.protocol_counter.snapshot())

    def _refresh_ids_snapshot(self) -> None:
        status = self.ids_service.model_status

        if status == "LOADED":
            model_text = "Model: loaded (live inference gated)"
        elif status == "MISSING":
            model_text = "Model: unavailable (artifact missing)"
        elif status == "ERROR":
            model_text = "Model: unavailable (load or schema error)"
        else:
            model_text = f"Model: {status.lower()}"

        self.ids_model_status_label.setText(model_text)

        if not self.ids_service.inference_enabled:
            if status == "LOADED":
                self.ids_inference_status_label.setText(
                    "Live IDS inference unavailable: feature compatibility incomplete."
                )
            else:
                self.ids_inference_status_label.setText(
                    self.ids_service.status_message
                )
        else:
            self.ids_inference_status_label.setText(
                "Live IDS inference ready; start it while monitoring is active."
            )

        self.ids_monitoring_status_label.setText(
            f"Monitoring: {'RUNNING' if self.network_monitor.is_active() else 'STOPPED'}"
        )
        self.ids_flow_count_label.setText(
            f"Completed flows checked: {self.ids_service.flows_checked}"
        )

        if self.ids_service.inference_enabled:
            self.ids_detection_count_label.setText(
                f"Suspicious prediction signals: {self.ids_service.detections}"
            )
        else:
            self.ids_detection_count_label.setText(
                "Attack signals: unavailable (inference disabled)"
            )

        # Merge persisted history with current-session events.
        # The same event may exist in both sources.
        persisted = getattr(self, "_persisted_events", ())
        current = self.ids_service.events
        combined = {}

        for item in tuple(persisted) + tuple(current):
            key = (item.timestamp, item.flow_id)
            combined[key] = item

        events = sorted(
            combined.values(),
            key=lambda item: item.timestamp,
        )
        event = events[-1] if events else None

        if event is None:
            self.ids_latest_event_label.setText(
                "Latest event: none; no saved prediction events."
            )
            rendered = ["No saved prediction events yet."]
        else:
            probability = (
                f" | attack probability {event.attack_probability:.3f}"
                if event.attack_probability is not None
                else ""
            )
            self.ids_latest_event_label.setText(
                f"Latest event: {event.severity} / {event.prediction}"
                f"{probability} - "
                f"{event.source_ip}:{event.source_port} to "
                f"{event.destination_ip}:{event.destination_port}"
            )

            rendered = [
                f"{item.timestamp} | {item.severity} | "
                f"{item.prediction} | "
                f"{item.source_ip}:{item.source_port} to "
                f"{item.destination_ip}:{item.destination_port}"
                for item in events[-5:]
            ]

        existing = [
            self.ids_event_log.item(index).text()
            for index in range(self.ids_event_log.count())
        ]

        if rendered != existing:
            self.ids_event_log.clear()
            self.ids_event_log.addItems(rendered)

        capture_active = self.network_monitor.is_active()
        self.start_ids_button.setEnabled(
            self.ids_service.inference_enabled and capture_active
        )
        self.stop_ids_button.setEnabled(
            self.ids_service.analysis_active
        )
    def _request_logout(self) -> None:
        self._logout_pending = True
        self._continue_logout()

    def _continue_logout(self) -> None:
        if self._network_action_busy:
            return
        if self.network_monitor.is_active():
            self.stop_network_monitoring()
            return
        self._logout_pending = False
        self._on_logout()

    def _continue_close(self) -> None:
        if self._network_action_busy:
            return
        if self.network_monitor.is_active():
            self.stop_network_monitoring()
            return
        self._close_pending = False
        self.close()

    def closeEvent(self, event) -> None:
        if self._network_action_busy or self.network_monitor.is_active():
            event.ignore()
            self._close_pending = True
            if not self._network_action_busy:
                self._continue_close()
            return
        self.ids_service.stop_analysis()
        self.flow_aggregator.finalize_all("dashboard_closed")
        self.network_monitor.remove_packet_callback(self._packet_callback)
        event.accept()
