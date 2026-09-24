"""
Mini SIEM — Synthetic Authentication Log Generator
===================================================

Generates 1500+ realistic authentication events with embedded attack patterns
for brute-force detection testing and SIEM validation.

Embedded Attack Scenarios:
  • SSH brute-force bursts    — rapid failed logins from a single IP
  • Credential stuffing       — many usernames tried from one source
  • Insider threat simulation — internal IP targeting service accounts
  • Distributed probing       — lower-rate attempts spread over time

The generator creates a reproducible dataset (seeded RNG) with realistic
temporal patterns: higher volume during business hours, quieter nights/weekends.

Output: data/auth_logs.csv
"""

import csv
import os
import random
from datetime import datetime, timedelta


# ═══════════════════════════════════════════════
#  THREAT ACTOR PROFILES
# ═══════════════════════════════════════════════
# Each profile simulates a distinct attacker with unique TTPs.

THREAT_ACTORS = [
    {
        "ip": "203.0.113.45",
        "label": "APT-BruteForce-01",
        "ttp": "T1110.001 — Password Guessing",
        "target_users": ["root", "admin", "ubuntu"],
        "burst_size": (20, 35),       # → HIGH severity
        "burst_window_minutes": 3,
        "num_bursts": (2, 4),
    },
    {
        "ip": "198.51.100.22",
        "label": "APT-BruteForce-02",
        "ttp": "T1110.001 — Password Guessing",
        "target_users": ["admin", "administrator", "test"],
        "burst_size": (10, 18),       # → MEDIUM severity
        "burst_window_minutes": 4,
        "num_bursts": (2, 3),
    },
    {
        "ip": "192.0.2.100",
        "label": "CredStuffer-01",
        "ttp": "T1110.004 — Credential Stuffing",
        "target_users": ["john", "jane", "admin", "root", "user1", "guest", "support"],
        "burst_size": (22, 40),       # → HIGH severity
        "burst_window_minutes": 5,
        "num_bursts": (3, 5),
    },
    {
        "ip": "10.0.0.254",
        "label": "InsiderThreat-01",
        "ttp": "T1110.001 — Password Guessing",
        "target_users": ["svc_account", "backup_admin"],
        "burst_size": (5, 9),         # → LOW severity
        "burst_window_minutes": 5,
        "num_bursts": (2, 3),
    },
    {
        "ip": "172.16.0.88",
        "label": "APT-BruteForce-03",
        "ttp": "T1110.003 — Password Spraying",
        "target_users": ["root", "deploy", "ci_user", "jenkins", "gitlab"],
        "burst_size": (7, 14),        # → LOW–MEDIUM severity
        "burst_window_minutes": 4,
        "num_bursts": (2, 4),
    },
    {
        "ip": "45.33.32.156",
        "label": "Scanner-01",
        "ttp": "T1110.001 — Password Guessing",
        "target_users": ["admin", "root", "test", "oracle", "postgres"],
        "burst_size": (12, 20),       # → MEDIUM–HIGH severity
        "burst_window_minutes": 5,
        "num_bursts": (1, 3),
    },
]


# ═══════════════════════════════════════════════
#  LEGITIMATE USER SIMULATION
# ═══════════════════════════════════════════════

LEGIT_USERS = [
    "alice", "bob", "charlie", "diana", "eve", "frank", "grace", "henry",
    "iris", "jack", "karen", "leo", "maria", "nathan", "olivia", "peter",
    "quinn", "rachel", "steve", "tina", "uma", "victor", "wendy", "xander",
    "yuki", "zara", "arun", "bhaskar", "chitra", "dev",
]

AUTH_METHODS = ["password", "ssh_key", "2fa", "kerberos", "certificate"]
AUTH_METHOD_WEIGHTS = [40, 25, 20, 10, 5]

SERVICES = ["sshd", "web_portal", "vpn_gateway", "rdp", "api_server"]
SERVICE_WEIGHTS = [35, 25, 20, 10, 10]

SUCCESS_MESSAGES = [
    "Authentication successful",
    "Session opened for user",
    "Login accepted via PAM",
    "Access granted — session initiated",
    "User authenticated successfully",
    "Accepted publickey for user",
    "Kerberos TGT validated",
]

FAILURE_MESSAGES = [
    "Authentication failure; logname= uid=0 euid=0",
    "Failed password for invalid user",
    "pam_unix(sshd:auth): authentication failure",
    "error: maximum authentication attempts exceeded",
    "Connection closed by authenticating user [preauth]",
    "Permission denied (publickey,password)",
    "Failed keyboard-interactive/pam for user",
    "Invalid credentials — access denied",
]

# Business-hour distribution weights (index = hour of day)
HOURLY_WEIGHTS = [
    1, 1, 1, 1, 1, 2,       # 00–05
    5, 8, 10, 12, 12, 11,   # 06–11
    10, 12, 12, 11, 10, 8,  # 12–17
    6, 4, 3, 2, 1, 1,       # 18–23
]


def _build_legit_ip_pool(seed: int) -> list:
    """Generate a pool of ~120 unique legitimate source IPs."""
    rng = random.Random(seed)
    ips = set()
    for _ in range(80):
        ips.add(f"10.0.{rng.randint(1, 50)}.{rng.randint(1, 254)}")
    for _ in range(30):
        ips.add(f"192.168.1.{rng.randint(1, 254)}")
    for _ in range(15):
        ips.add(f"172.16.{rng.randint(1, 10)}.{rng.randint(1, 254)}")
    return list(ips)


def _generate_legitimate_event(timestamp: datetime, legit_ips: list) -> dict:
    """Generate a single legitimate authentication log entry."""
    user = random.choice(LEGIT_USERS)
    ip = random.choice(legit_ips)
    method = random.choices(AUTH_METHODS, weights=AUTH_METHOD_WEIGHTS)[0]
    service = random.choices(SERVICES, weights=SERVICE_WEIGHTS)[0]

    # Legitimate users succeed ~90% of the time
    if random.random() < 0.90:
        status = "SUCCESS"
        message = random.choice(SUCCESS_MESSAGES)
    else:
        status = "FAILURE"
        message = random.choice(FAILURE_MESSAGES)

    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": ip,
        "username": user,
        "auth_method": method,
        "service": service,
        "status": status,
        "message": message,
    }


def _generate_attack_burst(actor: dict, base_timestamp: datetime) -> list:
    """Generate a concentrated burst of failed login attempts from a threat actor."""
    events = []
    burst_count = random.randint(*actor["burst_size"])
    window_seconds = actor["burst_window_minutes"] * 60

    for _ in range(burst_count):
        offset_seconds = random.uniform(0, window_seconds)
        ts = base_timestamp + timedelta(seconds=offset_seconds)
        user = random.choice(actor["target_users"])

        # Attackers overwhelmingly use password-based auth
        method = random.choices(["password", "ssh_key"], weights=[92, 8])[0]
        service = random.choices(["sshd", "web_portal", "rdp", "vpn_gateway"],
                                 weights=[45, 25, 20, 10])[0]

        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": actor["ip"],
            "username": user,
            "auth_method": method,
            "service": service,
            "status": "FAILURE",
            "message": random.choice(FAILURE_MESSAGES),
        })

    return events


def generate_logs(output_path: str = "data/auth_logs.csv",
                  num_events: int = 1500,
                  seed: int = 42) -> int:
    """
    Generate synthetic authentication logs with embedded attack patterns.

    Args:
        output_path: Destination CSV path (directories created automatically).
        num_events:  Minimum number of legitimate background events.
        seed:        Random seed for reproducibility.

    Returns:
        Total number of events written (legitimate + attack).
    """
    random.seed(seed)
    legit_ips = _build_legit_ip_pool(seed)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    all_events = []

    # ── Legitimate traffic over a 7-day window ──
    base_date = datetime(2026, 9, 18, 0, 0, 0)

    for _ in range(num_events):
        day_offset = random.randint(0, 6)
        hour = random.choices(range(24), weights=HOURLY_WEIGHTS)[0]
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        ts = base_date + timedelta(days=day_offset, hours=hour,
                                   minutes=minute, seconds=second)
        all_events.append(_generate_legitimate_event(ts, legit_ips))

    # ── Inject threat-actor attack bursts ──
    for actor in THREAT_ACTORS:
        num_bursts = random.randint(*actor["num_bursts"])
        for _ in range(num_bursts):
            day_offset = random.randint(0, 6)
            hour = random.randint(0, 23)
            burst_start = base_date + timedelta(
                days=day_offset,
                hours=hour,
                minutes=random.randint(0, 54),
            )
            all_events.extend(_generate_attack_burst(actor, burst_start))

    # Sort chronologically
    all_events.sort(key=lambda e: e["timestamp"])

    # Write CSV
    fieldnames = [
        "timestamp", "source_ip", "username",
        "auth_method", "service", "status", "message",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_events)

    return len(all_events)


# ═══════════════════════════════════════════════
#  Standalone execution
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    total = generate_logs()
    print(f"[+] Generated {total} authentication events → data/auth_logs.csv")
