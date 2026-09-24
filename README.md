# 🛡️ Mini SIEM — Security Log Analyser

A lightweight **SIEM-style security monitoring system** built in Python that parses and analyzes **1500+ authentication events** for suspicious login activity, implements **time-window based brute-force detection**, and generates professional security reports with actionable intelligence.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110-orange)

---

## 🔍 Features

### Core Detection Engine
- **Sliding-window brute-force detection** — flags any IP with **5+ failed login attempts within a 5-minute window**
- **Risk severity classification** — `LOW` (5–9), `MEDIUM` (10–19), `HIGH` (20+) based on attempt count
- **MITRE ATT&CK mapping** — auto-classifies attacks as T1110.001 (Password Guessing), T1110.003 (Password Spraying), or T1110.004 (Credential Stuffing)

### Threat Intelligence
- **IOC (Indicator of Compromise) profiling** for every flagged IP
- **Internal vs. external threat** classification based on RFC 1918 ranges
- **Targeted account analysis** — identifies most-attacked usernames and services

### Reporting & Visualization
- **Dark-themed security dashboard** (4-panel matplotlib visualization)
- **SOC-grade text report** with box-drawn alert cards, IOC profiles, and response recommendations
- **Color-coded terminal output** with severity indicators and ASCII banner

### Realistic Log Generation
- **1500+ synthetic authentication events** with realistic temporal patterns
- **6 embedded threat actor profiles** simulating brute-force, credential stuffing, and insider threats
- **Reproducible dataset** via seeded RNG for consistent testing

---

## 📁 Project Structure

```
Mini-SIEM/
├── main.py                  # CLI entry point — runs full pipeline
├── generate_logs.py         # Synthetic auth log generator (1500+ events)
├── siem_analyzer.py         # Core detection engine (5 components)
├── dashboard.py             # Matplotlib security dashboard
├── report_generator.py      # Structured text report generator
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation
├── data/
│   └── auth_logs.csv        # Generated authentication logs
└── reports/
    ├── dashboard.png         # Visual security dashboard
    └── summary_report.txt    # Detailed analysis report
```

---

## 🚀 Setup & Usage

### Prerequisites
- Python 3.8+

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Mini-SIEM.git
cd Mini-SIEM

# Install dependencies
pip install -r requirements.txt
```

### Run the Full Pipeline

```bash
python main.py
```

This will:
1. Generate 1500+ synthetic authentication logs → `data/auth_logs.csv`
2. Parse and validate all log entries
3. Run sliding-window brute-force detection
4. Classify alerts by severity (LOW / MEDIUM / HIGH)
5. Enrich alerts with MITRE ATT&CK techniques and IOC context
6. Generate dashboard (`reports/dashboard.png`) and report (`reports/summary_report.txt`)

### CLI Options

```bash
python main.py --analyze-only        # Skip log generation, use existing CSV
python main.py --generate-only       # Generate logs only
python main.py --events 3000         # Generate 3000+ events
python main.py --window 10           # Use 10-minute detection window
python main.py --threshold 3         # Lower detection threshold to 3
python main.py --log-file custom.csv # Use custom log file path
```

---

## 🔧 Architecture

### Detection Algorithm

```
For each unique source IP:
    1. Collect all FAILURE events
    2. Sort chronologically
    3. Slide a 5-minute window across the timeline
    4. Track the window with maximum failure count
    5. If max_count ≥ 5 → generate SecurityAlert

Severity Classification:
    5–9 failures   → LOW    (Monitor & watchlist)
    10–19 failures → MEDIUM (Rate-limit & investigate)
    20+ failures   → HIGH   (Block immediately & escalate)
```

### Pipeline Components

| Component | Class | Responsibility |
|---|---|---|
| Log Parser | `LogParser` | CSV ingestion, validation, structured parsing |
| Detector | `BruteForceDetector` | Sliding-window brute-force detection |
| Classifier | `RiskClassifier` | Severity assignment + MITRE ATT&CK mapping |
| Alert Manager | `AlertManager` | Alert creation, enrichment, deduplication |
| Threat Intel | `ThreatIntelEnricher` | IOC profiling for flagged IPs |
| Orchestrator | `SIEMAnalyzer` | End-to-end pipeline coordination |

### MITRE ATT&CK Coverage

| Technique ID | Name | Detection Criteria |
|---|---|---|
| T1110.001 | Password Guessing | Single target user, rapid failures |
| T1110.003 | Password Spraying | 2–3 target users from same IP |
| T1110.004 | Credential Stuffing | 4+ distinct usernames targeted |

---

## 📊 Sample Output

### Console Output
```
  [!!!] HIGH    SIEM-BF-0001
              Source IP      : 192.0.2.100
              Failed Attempts: 35
              Window         : 14:22:08 → 14:27:01
              MITRE ATT&CK   : T1110.004 — Credential Stuffing
              Targeted Users : admin, guest, jane, john

  [!!]  MEDIUM  SIEM-BF-0002
              Source IP      : 198.51.100.22
              Failed Attempts: 15
              Window         : 09:11:33 → 09:15:19
              MITRE ATT&CK   : T1110.001 — Password Guessing
              Targeted Users : admin, administrator, test
```

### Dashboard
A 4-panel dark-themed dashboard with:
- Top 10 threat sources (color-coded by severity)
- Alert severity distribution (pie chart)
- Attack timeline (hourly failure volume)
- Targeted services breakdown

---

## 🛠️ Technologies

- **Python 3.8+** — Core language
- **pandas** — Data manipulation
- **matplotlib** — Security dashboard visualization
- **csv / dataclasses** — Log parsing and data models

---

## 📝 License

This project is for educational and portfolio purposes.
