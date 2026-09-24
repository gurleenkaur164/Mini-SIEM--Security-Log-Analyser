"""
Mini SIEM — Core Security Analysis Engine
==========================================

Implements brute-force detection using a sliding-window algorithm against
parsed authentication logs. Generates severity-classified security alerts
with MITRE ATT&CK technique mapping and SOC response recommendations.

Detection Coverage (MITRE ATT&CK):
  • T1110.001 — Brute Force: Password Guessing
  • T1110.003 — Brute Force: Password Spraying
  • T1110.004 — Brute Force: Credential Stuffing

Severity Classification:
  ┌──────────┬────────────────────────────────────┐
  │ Severity │ Criteria                           │
  ├──────────┼────────────────────────────────────┤
  │ LOW      │ 5 – 9  failures in 5-min window    │
  │ MEDIUM   │ 10 – 19 failures in 5-min window   │
  │ HIGH     │ 20+    failures in 5-min window     │
  └──────────┴────────────────────────────────────┘
"""

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional


# ══════════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════════

@dataclass
class AuthEvent:
    """A single parsed authentication log entry (one row of the CSV)."""
    timestamp: datetime
    source_ip: str
    username: str
    auth_method: str
    service: str
    status: str          # "SUCCESS" or "FAILURE"
    message: str


@dataclass
class SecurityAlert:
    """
    A generated security alert for a detected brute-force incident.

    Each alert maps to exactly one source IP and represents the worst
    (highest-count) sliding-window hit observed for that IP.
    """
    alert_id: str
    source_ip: str
    severity: str                    # LOW / MEDIUM / HIGH
    detection_rule: str
    mitre_technique: str
    failed_attempts: int
    window_start: datetime
    window_end: datetime
    targeted_users: List[str]
    targeted_services: List[str]
    description: str
    recommendation: str


@dataclass
class ThreatIntel:
    """Enrichment data for a flagged source IP (IOC context)."""
    ip: str
    total_failures: int
    total_successes: int
    first_seen: datetime
    last_seen: datetime
    targeted_users: List[str]
    targeted_services: List[str]
    is_internal: bool


@dataclass
class AnalysisResult:
    """Complete output from the SIEM analysis pipeline."""
    total_events: int
    total_failures: int
    total_successes: int
    unique_source_ips: int
    unique_usernames: int
    analysis_window_start: Optional[datetime]
    analysis_window_end: Optional[datetime]
    alerts: List[SecurityAlert]
    threat_intel: List[ThreatIntel]
    events: List[AuthEvent]
    ip_failure_counts: Dict[str, int]
    user_failure_counts: Dict[str, int]
    hourly_failures: Dict[str, int]
    service_failure_counts: Dict[str, int]
    severity_counts: Dict[str, int]


# ══════════════════════════════════════════════════════════
#  LOG PARSER
# ══════════════════════════════════════════════════════════

class LogParser:
    """
    Parses and validates authentication log CSV files into structured events.

    Handles:
      • Missing or malformed timestamp fields
      • Unknown/extra columns (ignored gracefully)
      • Tracks and reports per-line parse errors
    """

    REQUIRED_FIELDS = {"timestamp", "source_ip", "username", "status"}
    TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

    def __init__(self):
        self.parse_errors: List[str] = []
        self.events: List[AuthEvent] = []

    def parse(self, filepath: str) -> List[AuthEvent]:
        """
        Parse a CSV log file into a sorted list of AuthEvent objects.

        Args:
            filepath: Path to the authentication log CSV.

        Returns:
            Chronologically sorted list of AuthEvent objects.

        Raises:
            FileNotFoundError: If the log file does not exist.
            ValueError: If required CSV columns are missing.
        """
        self.events = []
        self.parse_errors = []

        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            # Validate column headers
            if reader.fieldnames:
                missing = self.REQUIRED_FIELDS - set(reader.fieldnames)
                if missing:
                    raise ValueError(
                        f"Log file missing required columns: {missing}"
                    )

            for line_num, row in enumerate(reader, start=2):
                try:
                    event = AuthEvent(
                        timestamp=datetime.strptime(
                            row["timestamp"], self.TIMESTAMP_FMT
                        ),
                        source_ip=row.get("source_ip", "0.0.0.0"),
                        username=row.get("username", "UNKNOWN"),
                        auth_method=row.get("auth_method", "unknown"),
                        service=row.get("service", "unknown"),
                        status=row.get("status", "UNKNOWN").upper(),
                        message=row.get("message", ""),
                    )
                    self.events.append(event)
                except (ValueError, KeyError) as exc:
                    self.parse_errors.append(f"Line {line_num}: {exc}")

        # Chronological sort
        self.events.sort(key=lambda e: e.timestamp)
        return self.events


# ══════════════════════════════════════════════════════════
#  BRUTE-FORCE DETECTOR  (Sliding Window)
# ══════════════════════════════════════════════════════════

class BruteForceDetector:
    """
    Detects brute-force login attempts using a sliding time-window algorithm.

    Algorithm:
        1. Group all FAILURE events by source_ip.
        2. For each IP with ≥ threshold failures total, sort events by time.
        3. Slide a window of `window_minutes` across the sorted events.
        4. Track the window with the *maximum* failure count (worst burst).
        5. If that max count ≥ threshold, emit a detection hit.

    This produces at most one detection per source IP (the worst window),
    which avoids duplicate alerts for sustained attacks.

    Defaults:  window = 5 minutes,  threshold = 5 failures.
    """

    def __init__(self, window_minutes: int = 5, threshold: int = 5):
        self.window = timedelta(minutes=window_minutes)
        self.threshold = threshold
        self.window_minutes = window_minutes

    def detect(self, events: List[AuthEvent]) -> List[dict]:
        """
        Run sliding-window brute-force detection.

        Args:
            events: Full list of parsed AuthEvent objects.

        Returns:
            List of raw detection dicts, each containing:
              source_ip, count, window_start, window_end,
              targeted_users, targeted_services
        """
        # Group failures by source IP
        ip_failures: Dict[str, List[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.status == "FAILURE":
                ip_failures[event.source_ip].append(event)

        detections: List[dict] = []

        for ip, failures in ip_failures.items():
            if len(failures) < self.threshold:
                continue  # Not enough failures total — skip early

            failures.sort(key=lambda e: e.timestamp)

            # Find the worst sliding-window burst for this IP
            best: Optional[dict] = None

            for i in range(len(failures)):
                window_end_time = failures[i].timestamp + self.window

                # Collect all events within the window starting at failures[i]
                window_events: List[AuthEvent] = []
                for j in range(i, len(failures)):
                    if failures[j].timestamp <= window_end_time:
                        window_events.append(failures[j])
                    else:
                        break

                count = len(window_events)

                if count >= self.threshold:
                    if best is None or count > best["count"]:
                        best = {
                            "source_ip": ip,
                            "count": count,
                            "window_start": failures[i].timestamp,
                            "window_end": window_events[-1].timestamp,
                            "targeted_users": list(set(
                                e.username for e in window_events
                            )),
                            "targeted_services": list(set(
                                e.service for e in window_events
                            )),
                        }

            if best is not None:
                detections.append(best)

        return detections


# ══════════════════════════════════════════════════════════
#  RISK CLASSIFIER
# ══════════════════════════════════════════════════════════

class RiskClassifier:
    """
    Classifies brute-force detections into severity tiers and enriches
    alerts with MITRE ATT&CK technique IDs and SOC recommendations.

    Severity Tiers:
      HIGH   — 20+ failures in window  → Immediate blocking required
      MEDIUM — 10–19 failures          → Rate-limit and investigate
      LOW    — 5–9 failures            → Watchlist and monitor
    """

    SEVERITY_TIERS = [
        (20, "HIGH"),
        (10, "MEDIUM"),
        (5,  "LOW"),
    ]

    @classmethod
    def classify(cls, failed_count: int) -> str:
        """Return the severity label for a given failure count."""
        for threshold, severity in cls.SEVERITY_TIERS:
            if failed_count >= threshold:
                return severity
        return "INFO"

    @classmethod
    def get_mitre_technique(cls, targeted_users: List[str]) -> str:
        """
        Infer the most likely MITRE ATT&CK sub-technique from the attack
        pattern based on the number of distinct targeted usernames.
        """
        num_users = len(targeted_users)
        if num_users >= 4:
            return "T1110.004 — Credential Stuffing"
        elif num_users == 1:
            return "T1110.001 — Password Guessing"
        else:
            return "T1110.003 — Password Spraying"

    @classmethod
    def get_recommendation(cls, severity: str) -> str:
        """Return a SOC-grade response recommendation for the severity."""
        return {
            "HIGH": (
                "IMMEDIATE ACTION REQUIRED: Block source IP at perimeter "
                "firewall. Investigate targeted accounts for compromise. "
                "Force credential rotation. Escalate to SOC Tier-2."
            ),
            "MEDIUM": (
                "PRIORITY: Implement rate-limiting for source IP. Force "
                "password reset on targeted accounts. Monitor for lateral "
                "movement and privilege escalation."
            ),
            "LOW": (
                "MONITOR: Add source IP to threat watchlist. Review "
                "account lockout policies. Verify targeted accounts are "
                "not compromised. No immediate action required."
            ),
        }.get(severity, "Log event and continue monitoring.")


# ══════════════════════════════════════════════════════════
#  ALERT MANAGER
# ══════════════════════════════════════════════════════════

class AlertManager:
    """
    Converts raw detection hits into structured SecurityAlert objects,
    enriched with MITRE mapping, severity classification, and
    response recommendations.
    """

    def __init__(self):
        self.alerts: List[SecurityAlert] = []
        self._counter = 0

    def create_alert(self, detection: dict) -> SecurityAlert:
        """Build a SecurityAlert from a raw detection dict."""
        self._counter += 1

        severity = RiskClassifier.classify(detection["count"])
        mitre = RiskClassifier.get_mitre_technique(detection["targeted_users"])
        recommendation = RiskClassifier.get_recommendation(severity)

        users_display = ", ".join(sorted(detection["targeted_users"])[:6])

        alert = SecurityAlert(
            alert_id=f"SIEM-BF-{self._counter:04d}",
            source_ip=detection["source_ip"],
            severity=severity,
            detection_rule="Brute-Force Login Detection (Sliding Window)",
            mitre_technique=mitre,
            failed_attempts=detection["count"],
            window_start=detection["window_start"],
            window_end=detection["window_end"],
            targeted_users=detection["targeted_users"],
            targeted_services=detection["targeted_services"],
            description=(
                f"Detected {detection['count']} failed authentication "
                f"attempts from {detection['source_ip']} within a "
                f"{(detection['window_end'] - detection['window_start']).total_seconds():.0f}s "
                f"window. Targeted accounts: [{users_display}]."
            ),
            recommendation=recommendation,
        )

        self.alerts.append(alert)
        return alert

    def process_detections(self, detections: List[dict]) -> List[SecurityAlert]:
        """Process all raw detection hits and return sorted alerts."""
        for det in detections:
            self.create_alert(det)

        # Sort: HIGH → MEDIUM → LOW, then by attempt count descending
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
        self.alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 99),
                           -a.failed_attempts)
        )
        return self.alerts


# ══════════════════════════════════════════════════════════
#  THREAT INTEL ENRICHMENT
# ══════════════════════════════════════════════════════════

class ThreatIntelEnricher:
    """
    Builds IOC (Indicator of Compromise) context for every flagged IP
    by aggregating all associated events — both successes and failures.
    """

    INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.")

    @classmethod
    def enrich(cls, flagged_ips: List[str],
               events: List[AuthEvent]) -> List[ThreatIntel]:
        """
        Build ThreatIntel records for each flagged IP.

        Args:
            flagged_ips: IPs identified by the brute-force detector.
            events:      Full event list for context aggregation.

        Returns:
            List of ThreatIntel objects sorted by total_failures descending.
        """
        ip_events: Dict[str, List[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.source_ip in flagged_ips:
                ip_events[event.source_ip].append(event)

        intel_list: List[ThreatIntel] = []

        for ip in flagged_ips:
            evts = ip_events.get(ip, [])
            if not evts:
                continue

            failures = [e for e in evts if e.status == "FAILURE"]
            successes = [e for e in evts if e.status == "SUCCESS"]
            timestamps = [e.timestamp for e in evts]

            intel_list.append(ThreatIntel(
                ip=ip,
                total_failures=len(failures),
                total_successes=len(successes),
                first_seen=min(timestamps),
                last_seen=max(timestamps),
                targeted_users=list(set(e.username for e in failures)),
                targeted_services=list(set(e.service for e in failures)),
                is_internal=any(ip.startswith(p) for p in cls.INTERNAL_PREFIXES),
            ))

        intel_list.sort(key=lambda t: t.total_failures, reverse=True)
        return intel_list


# ══════════════════════════════════════════════════════════
#  SIEM ANALYZER  (Orchestrator)
# ══════════════════════════════════════════════════════════

class SIEMAnalyzer:
    """
    Main orchestrator for the Mini SIEM analysis pipeline.

    Pipeline Stages:
      1. INGEST   — Parse and validate authentication log CSV
      2. DETECT   — Run sliding-window brute-force detection
      3. CLASSIFY — Assign severity and MITRE ATT&CK technique
      4. ENRICH   — Build threat-intelligence context for flagged IPs
      5. REPORT   — Compile statistics and alert summaries
    """

    def __init__(self, window_minutes: int = 5, threshold: int = 5):
        self.parser = LogParser()
        self.detector = BruteForceDetector(window_minutes, threshold)
        self.alert_manager = AlertManager()

    def analyze(self, log_filepath: str) -> AnalysisResult:
        """
        Execute the full SIEM analysis pipeline.

        Args:
            log_filepath: Path to the authentication log CSV file.

        Returns:
            AnalysisResult containing all findings, alerts, and statistics.
        """
        # ── Stage 1: INGEST ──
        events = self.parser.parse(log_filepath)

        if self.parser.parse_errors:
            print(f"  [!] Warning: {len(self.parser.parse_errors)} "
                  f"malformed log entries skipped")

        # ── Stage 2: DETECT ──
        detections = self.detector.detect(events)

        # ── Stage 3: CLASSIFY & ALERT ──
        alerts = self.alert_manager.process_detections(detections)

        # ── Stage 4: ENRICH ──
        flagged_ips = [d["source_ip"] for d in detections]
        threat_intel = ThreatIntelEnricher.enrich(flagged_ips, events)

        # ── Stage 5: STATISTICS ──
        total_failures = sum(1 for e in events if e.status == "FAILURE")
        total_successes = sum(1 for e in events if e.status == "SUCCESS")
        unique_ips = len(set(e.source_ip for e in events))
        unique_users = len(set(e.username for e in events))

        timestamps = [e.timestamp for e in events]
        analysis_start = min(timestamps) if timestamps else None
        analysis_end = max(timestamps) if timestamps else None

        # Per-IP failure counts
        ip_failure_counts: Dict[str, int] = defaultdict(int)
        for e in events:
            if e.status == "FAILURE":
                ip_failure_counts[e.source_ip] += 1

        # Per-user failure counts
        user_failure_counts: Dict[str, int] = defaultdict(int)
        for e in events:
            if e.status == "FAILURE":
                user_failure_counts[e.username] += 1

        # Hourly failure timeline
        hourly_failures: Dict[str, int] = defaultdict(int)
        for e in events:
            if e.status == "FAILURE":
                hour_key = e.timestamp.strftime("%Y-%m-%d %H:00")
                hourly_failures[hour_key] += 1

        # Per-service failure counts
        service_failure_counts: Dict[str, int] = defaultdict(int)
        for e in events:
            if e.status == "FAILURE":
                service_failure_counts[e.service] += 1

        # Severity distribution
        severity_counts: Dict[str, int] = defaultdict(int)
        for alert in alerts:
            severity_counts[alert.severity] += 1

        return AnalysisResult(
            total_events=len(events),
            total_failures=total_failures,
            total_successes=total_successes,
            unique_source_ips=unique_ips,
            unique_usernames=unique_users,
            analysis_window_start=analysis_start,
            analysis_window_end=analysis_end,
            alerts=alerts,
            threat_intel=threat_intel,
            events=events,
            ip_failure_counts=dict(ip_failure_counts),
            user_failure_counts=dict(user_failure_counts),
            hourly_failures=dict(hourly_failures),
            service_failure_counts=dict(service_failure_counts),
            severity_counts=dict(severity_counts),
        )
