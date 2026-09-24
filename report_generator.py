"""
Mini SIEM — Security Report Generator
======================================

Produces a structured plaintext security report from SIEM analysis results,
formatted for SOC documentation, incident response handoffs, and audit trails.

Report Sections:
  1. Executive Summary
  2. Alert Detail Table
  3. Threat Intelligence (IOC Profiles)
  4. Top Targeted Accounts
  5. Top Targeted Services
  6. Recommendations
"""

import os
from datetime import datetime


# Box-drawing characters for report formatting
BOX_H = "═"
BOX_V = "║"
BOX_TL = "╔"
BOX_TR = "╗"
BOX_BL = "╚"
BOX_BR = "╝"
THIN_H = "─"
THIN_V = "│"
THIN_TL = "┌"
THIN_TR = "┐"
THIN_BL = "└"
THIN_BR = "┘"
THIN_ML = "├"
THIN_MR = "┤"


def _header_box(title: str, width: int = 72) -> str:
    """Render a double-bordered header box."""
    inner = width - 2
    lines = [
        BOX_TL + BOX_H * inner + BOX_TR,
        BOX_V + title.center(inner) + BOX_V,
        BOX_BL + BOX_H * inner + BOX_BR,
    ]
    return "\n".join(lines)


def _section_header(title: str) -> str:
    """Render a section header with underline."""
    return f"\n{'=' * 72}\n  {title}\n{'=' * 72}"


def _severity_indicator(severity: str) -> str:
    """Return a text-based severity indicator."""
    indicators = {
        "HIGH":   "[!!!] CRITICAL",
        "MEDIUM": "[!!]  WARNING ",
        "LOW":    "[!]   NOTICE  ",
    }
    return indicators.get(severity, "[?]   UNKNOWN ")


def generate_report(result, output_path: str = "reports/summary_report.txt") -> str:
    """
    Generate a comprehensive security analysis report.

    Args:
        result:      An AnalysisResult object from SIEMAnalyzer.
        output_path: Destination path for the text report.

    Returns:
        Absolute path to the saved report file.
    """
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []

    # ── Report Header ──
    lines.append("")
    lines.append(_header_box("MINI SIEM — SECURITY ANALYSIS REPORT"))
    lines.append(f"  Generated: {report_time}")
    if result.analysis_window_start and result.analysis_window_end:
        lines.append(
            f"  Analysis Window: "
            f"{result.analysis_window_start.strftime('%Y-%m-%d %H:%M:%S')} → "
            f"{result.analysis_window_end.strftime('%Y-%m-%d %H:%M:%S')}"
        )
    lines.append(f"  Detection Rule: Brute-Force (Sliding Window, 5-min, threshold=5)")
    lines.append("")

    # ── Section 1: Executive Summary ──
    lines.append(_section_header("1. EXECUTIVE SUMMARY"))
    lines.append("")

    failure_rate = (result.total_failures / result.total_events * 100
                    if result.total_events > 0 else 0)

    lines.append(f"  Total Authentication Events Analyzed .. {result.total_events:>8,}")
    lines.append(f"  Successful Authentications ............ {result.total_successes:>8,}")
    lines.append(f"  Failed Authentications ................ {result.total_failures:>8,}")
    lines.append(f"  Failure Rate .......................... {failure_rate:>7.1f}%")
    lines.append(f"  Unique Source IPs ..................... {result.unique_source_ips:>8,}")
    lines.append(f"  Unique Usernames ...................... {result.unique_usernames:>8,}")
    lines.append("")
    lines.append(f"  ┌─────────────────────────────────────────┐")
    lines.append(f"  │  SECURITY ALERTS GENERATED: {len(result.alerts):>3}           │")
    lines.append(f"  │                                         │")

    high_count = result.severity_counts.get("HIGH", 0)
    med_count = result.severity_counts.get("MEDIUM", 0)
    low_count = result.severity_counts.get("LOW", 0)

    lines.append(f"  │    [!!!] HIGH   : {high_count:>3}                     │")
    lines.append(f"  │    [!!]  MEDIUM : {med_count:>3}                     │")
    lines.append(f"  │    [!]   LOW    : {low_count:>3}                     │")
    lines.append(f"  └─────────────────────────────────────────┘")
    lines.append("")

    # ── Section 2: Alert Details ──
    lines.append(_section_header("2. ALERT DETAILS"))

    if not result.alerts:
        lines.append("\n  No brute-force alerts detected. All clear.")
    else:
        for i, alert in enumerate(result.alerts, 1):
            lines.append("")
            lines.append(f"  {THIN_TL}{THIN_H * 68}{THIN_TR}")
            lines.append(f"  {THIN_V}  Alert #{i}: {alert.alert_id:<20}  "
                         f"Severity: {_severity_indicator(alert.severity)}   {THIN_V}")
            lines.append(f"  {THIN_ML}{THIN_H * 68}{THIN_MR}")
            lines.append(f"  {THIN_V}  Source IP       : {alert.source_ip:<47}{THIN_V}")
            lines.append(f"  {THIN_V}  Failed Attempts : {alert.failed_attempts:<47}{THIN_V}")
            lines.append(f"  {THIN_V}  Window Start    : "
                         f"{alert.window_start.strftime('%Y-%m-%d %H:%M:%S'):<47}{THIN_V}")
            lines.append(f"  {THIN_V}  Window End      : "
                         f"{alert.window_end.strftime('%Y-%m-%d %H:%M:%S'):<47}{THIN_V}")
            lines.append(f"  {THIN_V}  MITRE ATT&CK   : {alert.mitre_technique:<47}{THIN_V}")

            users_str = ", ".join(sorted(alert.targeted_users)[:5])
            lines.append(f"  {THIN_V}  Targeted Users  : {users_str:<47}{THIN_V}")

            services_str = ", ".join(sorted(alert.targeted_services))
            lines.append(f"  {THIN_V}  Services Hit    : {services_str:<47}{THIN_V}")

            lines.append(f"  {THIN_ML}{THIN_H * 68}{THIN_MR}")

            # Wrap recommendation text
            rec = alert.recommendation
            rec_lines = [rec[j:j+46] for j in range(0, len(rec), 46)]
            lines.append(f"  {THIN_V}  Recommendation  : {rec_lines[0]:<47}{THIN_V}")
            for rl in rec_lines[1:]:
                lines.append(f"  {THIN_V}                   {rl:<47}{THIN_V}")

            lines.append(f"  {THIN_BL}{THIN_H * 68}{THIN_BR}")

    # ── Section 3: Threat Intelligence (IOC Profiles) ──
    lines.append(_section_header("3. THREAT INTELLIGENCE — IOC PROFILES"))
    lines.append("")

    if not result.threat_intel:
        lines.append("  No IOCs identified.")
    else:
        for ioc in result.threat_intel:
            origin = "INTERNAL" if ioc.is_internal else "EXTERNAL"
            lines.append(f"  IP: {ioc.ip}  ({origin})")
            lines.append(f"    Total Failures  : {ioc.total_failures}")
            lines.append(f"    Total Successes : {ioc.total_successes}")
            lines.append(f"    First Seen      : {ioc.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"    Last Seen       : {ioc.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"    Targeted Users  : {', '.join(sorted(ioc.targeted_users)[:6])}")
            lines.append(f"    Targeted Svc    : {', '.join(sorted(ioc.targeted_services))}")

            if ioc.total_successes > 0:
                lines.append(f"    ⚠  WARNING: This IP also had {ioc.total_successes} "
                             f"successful login(s) — possible compromise!")
            lines.append("")

    # ── Section 4: Top Targeted Accounts ──
    lines.append(_section_header("4. TOP TARGETED ACCOUNTS"))
    lines.append("")
    lines.append(f"  {'Rank':<6}{'Username':<20}{'Failed Attempts':<18}")
    lines.append(f"  {THIN_H * 6}{THIN_H * 20}{THIN_H * 18}")

    sorted_users = sorted(result.user_failure_counts.items(),
                          key=lambda x: x[1], reverse=True)[:15]
    for rank, (user, count) in enumerate(sorted_users, 1):
        lines.append(f"  {rank:<6}{user:<20}{count:<18}")

    # ── Section 5: Top Targeted Services ──
    lines.append("")
    lines.append(_section_header("5. TOP TARGETED SERVICES"))
    lines.append("")
    lines.append(f"  {'Service':<20}{'Failed Attempts':<18}{'% of Total Failures':<20}")
    lines.append(f"  {THIN_H * 20}{THIN_H * 18}{THIN_H * 20}")

    sorted_services = sorted(result.service_failure_counts.items(),
                             key=lambda x: x[1], reverse=True)
    for service, count in sorted_services:
        pct = (count / result.total_failures * 100) if result.total_failures > 0 else 0
        lines.append(f"  {service:<20}{count:<18}{pct:<19.1f}%")

    # ── Section 6: Recommendations ──
    lines.append("")
    lines.append(_section_header("6. SECURITY RECOMMENDATIONS"))
    lines.append("")

    if high_count > 0:
        lines.append("  [CRITICAL] Immediate Actions Required:")
        lines.append("    • Block all HIGH-severity source IPs at the perimeter firewall")
        lines.append("    • Initiate incident response for targeted accounts")
        lines.append("    • Force credential rotation for compromised/targeted users")
        lines.append("    • Escalate to SOC Tier-2 / Incident Commander")
        lines.append("")

    if med_count > 0:
        lines.append("  [WARNING] Priority Actions:")
        lines.append("    • Implement rate-limiting rules for MEDIUM-severity IPs")
        lines.append("    • Enable account lockout after 5 consecutive failures")
        lines.append("    • Review VPN and SSH access policies")
        lines.append("    • Monitor flagged IPs for lateral movement")
        lines.append("")

    if low_count > 0:
        lines.append("  [INFO] Monitoring Actions:")
        lines.append("    • Add LOW-severity IPs to the threat watchlist")
        lines.append("    • Review failed-login trends for anomalies")
        lines.append("    • Verify account lockout thresholds are properly configured")
        lines.append("")

    lines.append("  General Hardening:")
    lines.append("    • Enforce MFA (Multi-Factor Authentication) for all remote access")
    lines.append("    • Disable password-based SSH — use key-based authentication only")
    lines.append("    • Implement geo-blocking for unexpected source regions")
    lines.append("    • Deploy fail2ban or equivalent IPS for automated blocking")
    lines.append("    • Review and tighten service-account permissions")

    # ── Footer ──
    lines.append("")
    lines.append(THIN_H * 72)
    lines.append(f"  END OF REPORT — Generated by Mini SIEM v1.0")
    lines.append(f"  {report_time}")
    lines.append(THIN_H * 72)
    lines.append("")

    # Write report
    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return os.path.abspath(output_path)


# ══════════════════════════════════════════════════════════
#  Standalone execution
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    from siem_analyzer import SIEMAnalyzer

    analyzer = SIEMAnalyzer()
    result = analyzer.analyze("data/auth_logs.csv")
    path = generate_report(result)
    print(f"[+] Report saved → {path}")
