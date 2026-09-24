"""
Mini SIEM - Main Entry Point
=============================

Command-line interface for the Mini SIEM security log analysis pipeline.

Usage:
    python main.py                    # Full pipeline (generate + analyze)
    python main.py --analyze-only     # Skip log generation, analyze existing logs
    python main.py --generate-only    # Generate logs only, skip analysis

Pipeline Stages:
  1. GENERATE  - Create synthetic authentication logs (1500+ events)
  2. INGEST    - Parse and validate log file
  3. DETECT    - Sliding-window brute-force detection
  4. CLASSIFY  - Severity assignment (LOW / MEDIUM / HIGH)
  5. ENRICH    - Threat intelligence / IOC profiling
  6. REPORT    - Dashboard (PNG) + text report generation
"""

import argparse
import io
import os
import sys
import time

# Force UTF-8 output on Windows to handle special characters
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ══════════════════════════════════════════════════════════
#  ANSI Color Codes for Terminal Output
# ══════════════════════════════════════════════════════════

class Colors:
    """ANSI escape codes for colored terminal output."""
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"

    RED      = "\033[91m"
    GREEN    = "\033[92m"
    YELLOW   = "\033[93m"
    BLUE     = "\033[94m"
    MAGENTA  = "\033[95m"
    CYAN     = "\033[96m"
    WHITE    = "\033[97m"

    BG_RED   = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN = "\033[42m"

    @classmethod
    def severity(cls, sev: str) -> str:
        """Return colored severity tag."""
        if sev == "HIGH":
            return f"{cls.BG_RED}{cls.WHITE}{cls.BOLD} ✖ HIGH   {cls.RESET}"
        elif sev == "MEDIUM":
            return f"{cls.BG_YELLOW}{cls.BOLD} ⚠ MEDIUM {cls.RESET}"
        elif sev == "LOW":
            return f"{cls.BG_GREEN}{cls.BOLD} ● LOW    {cls.RESET}"
        return f"{cls.DIM} ? INFO   {cls.RESET}"


# ══════════════════════════════════════════════════════════
#  Console Output Helpers
# ══════════════════════════════════════════════════════════

def banner():
    """Print the Mini SIEM ASCII banner."""
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ███╗   ███╗██╗███╗   ██╗██╗    ███████╗██╗███████╗ ║
    ║   ████╗ ████║██║████╗  ██║██║    ██╔════╝██║██╔════╝ ║
    ║   ██╔████╔██║██║██╔██╗ ██║██║    ███████╗██║█████╗   ║
    ║   ██║╚██╔╝██║██║██║╚██╗██║██║    ╚════██║██║██╔══╝   ║
    ║   ██║ ╚═╝ ██║██║██║ ╚████║██║    ███████║██║███████╗ ║
    ║   ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝    ╚══════╝╚═╝╚══════╝║
    ║                                                      ║
    ║         Security Log Analyser v1.0                   ║
    ║         Brute-Force Detection Engine                 ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
{Colors.RESET}""")


def print_stage(stage_num: int, title: str):
    """Print a pipeline stage header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}  [{stage_num}/6] {title}{Colors.RESET}")
    print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}")


def print_success(msg: str):
    """Print a success message."""
    print(f"  {Colors.GREEN}[✓]{Colors.RESET} {msg}")


def print_info(msg: str):
    """Print an info message."""
    print(f"  {Colors.CYAN}[i]{Colors.RESET} {msg}")


def print_warning(msg: str):
    """Print a warning message."""
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {msg}")


def print_alert_summary(alerts):
    """Print a colored summary of all security alerts."""
    if not alerts:
        print(f"\n  {Colors.GREEN}{Colors.BOLD}  ✓ No security alerts — all clear!{Colors.RESET}\n")
        return

    print(f"\n  {Colors.RED}{Colors.BOLD}  ╔══════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"  {Colors.RED}{Colors.BOLD}  ║          SECURITY ALERTS DETECTED: {len(alerts):<4}                  ║{Colors.RESET}")
    print(f"  {Colors.RED}{Colors.BOLD}  ╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
    print()

    for alert in alerts:
        sev_tag = Colors.severity(alert.severity)
        users = ", ".join(sorted(alert.targeted_users)[:4])

        print(f"  {sev_tag}  {Colors.BOLD}{alert.alert_id}{Colors.RESET}")
        print(f"              Source IP      : {Colors.RED}{alert.source_ip}{Colors.RESET}")
        print(f"              Failed Attempts: {Colors.YELLOW}{alert.failed_attempts}{Colors.RESET}")
        print(f"              Window         : {alert.window_start.strftime('%H:%M:%S')} → {alert.window_end.strftime('%H:%M:%S')}")
        print(f"              MITRE ATT&CK   : {Colors.MAGENTA}{alert.mitre_technique}{Colors.RESET}")
        print(f"              Targeted Users : {users}")
        print(f"              {Colors.DIM}{alert.recommendation[:80]}...{Colors.RESET}")
        print()


# ══════════════════════════════════════════════════════════
#  Main Pipeline
# ══════════════════════════════════════════════════════════

def main():
    """Execute the Mini SIEM analysis pipeline."""
    parser = argparse.ArgumentParser(
        description="Mini SIEM — Security Log Analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--analyze-only", action="store_true",
        help="Skip log generation; analyze existing data/auth_logs.csv",
    )
    parser.add_argument(
        "--generate-only", action="store_true",
        help="Generate logs only; skip analysis",
    )
    parser.add_argument(
        "--log-file", default="data/auth_logs.csv",
        help="Path to authentication log CSV (default: data/auth_logs.csv)",
    )
    parser.add_argument(
        "--events", type=int, default=1500,
        help="Number of legitimate events to generate (default: 1500)",
    )
    parser.add_argument(
        "--window", type=int, default=5,
        help="Detection window in minutes (default: 5)",
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Minimum failed attempts to trigger alert (default: 5)",
    )

    args = parser.parse_args()

    banner()

    start_time = time.time()
    log_file = args.log_file

    # ── Stage 1: GENERATE ──
    if not args.analyze_only:
        print_stage(1, "LOG GENERATION")

        from generate_logs import generate_logs

        print_info(f"Generating {args.events}+ synthetic authentication events...")
        total_events = generate_logs(output_path=log_file, num_events=args.events)
        print_success(f"Generated {total_events:,} events → {log_file}")
    else:
        print_stage(1, "LOG GENERATION — SKIPPED")
        print_info(f"Using existing log file: {log_file}")

    if args.generate_only:
        print(f"\n{Colors.GREEN}{Colors.BOLD}  Log generation complete. Exiting.{Colors.RESET}\n")
        return

    # Verify log file exists
    if not os.path.exists(log_file):
        print(f"\n  {Colors.RED}[✖] Error: Log file not found: {log_file}{Colors.RESET}")
        print(f"      Run without --analyze-only to generate logs first.\n")
        sys.exit(1)

    # ── Stage 2: INGEST ──
    print_stage(2, "LOG INGESTION & PARSING")

    from siem_analyzer import SIEMAnalyzer

    analyzer = SIEMAnalyzer(
        window_minutes=args.window,
        threshold=args.threshold,
    )

    print_info(f"Parsing {log_file}...")
    result = analyzer.analyze(log_file)

    print_success(f"Parsed {result.total_events:,} events "
                  f"({result.total_successes:,} success, "
                  f"{result.total_failures:,} failures)")
    print_success(f"Unique source IPs: {result.unique_source_ips:,}")
    print_success(f"Unique usernames: {result.unique_usernames:,}")

    if result.analysis_window_start and result.analysis_window_end:
        print_info(
            f"Analysis window: "
            f"{result.analysis_window_start.strftime('%Y-%m-%d %H:%M')} → "
            f"{result.analysis_window_end.strftime('%Y-%m-%d %H:%M')}"
        )

    # ── Stage 3: DETECT ──
    print_stage(3, "BRUTE-FORCE DETECTION")
    print_info(f"Detection rule: ≥{args.threshold} failures within "
               f"{args.window}-minute sliding window")
    print_success(f"Detection complete — {len(result.alerts)} alert(s) generated")

    # ── Stage 4: CLASSIFY ──
    print_stage(4, "RISK CLASSIFICATION")

    high = result.severity_counts.get("HIGH", 0)
    med = result.severity_counts.get("MEDIUM", 0)
    low = result.severity_counts.get("LOW", 0)

    if high:
        print(f"  {Colors.RED}{Colors.BOLD}  [!!!] HIGH   : {high}{Colors.RESET}")
    if med:
        print(f"  {Colors.YELLOW}{Colors.BOLD}  [!!]  MEDIUM : {med}{Colors.RESET}")
    if low:
        print(f"  {Colors.GREEN}{Colors.BOLD}  [!]   LOW    : {low}{Colors.RESET}")

    if not result.alerts:
        print_success("No threats detected — environment is clean")

    # ── Stage 5: ENRICH ──
    print_stage(5, "THREAT INTELLIGENCE ENRICHMENT")

    if result.threat_intel:
        for ioc in result.threat_intel:
            origin = f"{Colors.YELLOW}INTERNAL{Colors.RESET}" if ioc.is_internal else f"{Colors.RED}EXTERNAL{Colors.RESET}"
            print(f"    IOC: {Colors.BOLD}{ioc.ip}{Colors.RESET} ({origin}) — "
                  f"{ioc.total_failures} failures, "
                  f"first seen {ioc.first_seen.strftime('%Y-%m-%d %H:%M')}")
    else:
        print_info("No IOCs identified")

    # ── Stage 6: REPORTING ──
    print_stage(6, "REPORT GENERATION")

    # Dashboard
    from dashboard import generate_dashboard
    dashboard_path = generate_dashboard(result)
    print_success(f"Dashboard saved → {dashboard_path}")

    # Text report
    from report_generator import generate_report
    report_path = generate_report(result)
    print_success(f"Report saved   → {report_path}")

    # ── Alert Summary ──
    print_alert_summary(result.alerts)

    # ── Pipeline Complete ──
    elapsed = time.time() - start_time
    print(f"  {Colors.CYAN}{'─' * 50}{Colors.RESET}")
    print(f"  {Colors.GREEN}{Colors.BOLD}  ✓ Pipeline complete in {elapsed:.2f}s{Colors.RESET}")
    print(f"  {Colors.DIM}    Logs     : {log_file}")
    print(f"    Dashboard : reports/dashboard.png")
    print(f"    Report    : reports/summary_report.txt{Colors.RESET}")
    print()


if __name__ == "__main__":
    main()
