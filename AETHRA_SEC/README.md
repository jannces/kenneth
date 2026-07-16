# AETHRA-SEC

**A Unified System for Automated Penetration Testing with Real-Time Network
Traffic Analysis and Immediate Threat Mitigation Recommender**

AETHRA-SEC combines three standalone cybersecurity tools — **Nmap**
(vulnerability assessment), **PyShark/Wireshark** (live traffic monitoring), and
**Snort** (intrusion detection) — into a single Windows desktop application with
one unified dashboard. Instead of switching between separate tools, an analyst
opens AETHRA-SEC and sees correlated results in one place, together with
plain-language, education-focused threat-mitigation guidance.

It is designed for **controlled educational laboratory networks** only. It is a
**defensive** monitoring platform: it detects, classifies, logs, and
**recommends** mitigation — it never blocks traffic, changes firewall rules, or
performs offensive exploitation.

---

## Key Features

| Area | Capability |
|------|-----------|
| Authentication | Login with bcrypt-hashed passwords, session management, account lockout after repeated failures |
| RBAC | Two roles — Administrator (full control) and Standard User (operational, read-mostly) |
| Vulnerability Assessment | Nmap scans (host discovery, quick, normal, intense, service/version/OS detection, TCP/UDP), risk classification, scan history |
| Live Monitoring | Continuous PyShark capture, protocol/application detection, per-connection tracking, device discovery, bandwidth and statistics |
| Intrusion Detection | Snort integration over an **Alert Socket (IPC)** — not file polling — with parsing, threat classification, severity scoring, and deduplication |
| Threat Correlation | Links Snort alerts to Nmap findings (e.g. "SSH exposed" + "SSH brute force" → high-risk) |
| Mitigation Engine | Structured, beginner-friendly recommendations (problem, why, risk, verify, immediate actions, long-term prevention, references) |
| Dashboard | Live cards and Matplotlib charts that update automatically — no manual refresh |
| Reports | PDF (with charts), CSV, and Excel export |
| Auditing | Comprehensive system, activity, scan, monitoring, alert, and authentication logs (read-only in the GUI) |

---

## Technology Stack

- **Python 3.12+**
- **Tkinter + ttkbootstrap** (GUI — no Electron/React/PyQt/Kivy)
- **MySQL** (all persistent storage)
- **python-nmap**, **PyShark**, **Snort** (integrations)
- **bcrypt** (password hashing), **Matplotlib**, **ReportLab**, **openpyxl**

---

## Architecture

A layered architecture keeps concerns separated:

```
Presentation Layer (Tkinter GUI)          gui/, dashboard/, authentication/login.py
        │
Application Layer (Controllers)           gui/app_context.py, scan_controller, main_window
        │
Business Logic Layer (Core Services)      auth_service, mitigation, alert_processor, report_generator
        │
Integration Layer (Nmap, PyShark, Snort)  scanner/, monitoring/, ids/
        │
Database Layer (MySQL)                     database/
```

### Project structure

```
AETHRA_SEC/
├── main.py                  # Entry point (boot → login → dashboard)
├── config.py                # Central configuration (reads .env)
├── requirements.txt
├── .env.example             # Copy to .env and fill in credentials
│
├── database/                # Connection pool, schema.sql, seed data
├── authentication/          # login, auth_service, password, session, permissions
├── scanner/                 # nmap_engine, scan_parser, vulnerability_mapper, scan_controller
├── monitoring/              # pyshark_capture, packet_parser, statistics, bandwidth, trackers
├── ids/                     # snort_listener, alert_parser, threat_classifier, alert_processor
├── mitigation/              # recommender, recommendation_db, knowledge base
├── reports/                 # report_generator, pdf/csv/excel exporters
├── settings/                # settings service, network + user preferences
├── logs/                    # logging engine, activity + error logging
├── dashboard/               # charts, widgets, dashboard statistics
├── gui/                     # app shell, router, data table, notifications, pages/
├── utils/                   # constants, validators, helpers, threading
└── tests/                   # unit + integration tests
```

---

## Prerequisites (Windows 10 / 11)

1. **Python 3.12+** — <https://www.python.org/downloads/>
2. **MySQL Server 8.x** — <https://dev.mysql.com/downloads/mysql/>
3. **Nmap** (includes the `nmap` binary) — <https://nmap.org/download.html>
4. **Wireshark** (provides `tshark`, required by PyShark) — <https://www.wireshark.org/>
5. **Snort** (IDS engine) — <https://www.snort.org/>

Run the application with Administrator privileges so packet capture works.

---

## Installation

```bat
:: 1. Clone / copy the project, then create a virtual environment
python -m venv .venv
.venv\Scripts\activate

:: 2. Install Python dependencies
pip install -r requirements.txt

:: 3. Configure credentials
copy .env.example .env
:: Edit .env: set AETHRA_DB_USER / AETHRA_DB_PASSWORD and tool paths
```

### Database

You do **not** need to create the schema manually — on first launch AETHRA-SEC
creates the `aethra_sec` database, applies `database/schema.sql`, and seeds
default data (using the credentials in `.env`). The MySQL user must have
privileges to create databases, or you can pre-create the database and grant the
user access to it.

### Default accounts (change immediately after first login)

| Username | Password | Role |
|----------|-----------|------|
| `admin` | `Admin@123` | Administrator |
| `analyst` | `Analyst@123` | Standard User |

---

## Snort Alert Socket (IPC)

AETHRA-SEC **listens** for alerts on a TCP loopback socket (default
`127.0.0.1:9000`) rather than repeatedly reading alert files. Snort's alert
output is streamed to that socket, one message per line, in either:

- **JSON** — Snort 3 `alert_json` output, or
- **Fast text** — the classic `alert_fast` single-line format.

Configure the host/port under **Settings → Snort IDS**. A thin forwarder that
pipes Snort's alert output to the socket can be used where a direct socket
output plugin is not available. The listener auto-reconnects if Snort restarts.

---

## Running

```bat
.venv\Scripts\activate
python main.py
```

The login window appears first. After authentication the dashboard loads and
background services (monitoring + Snort listener) start automatically.

---

## Testing

The algorithmic core (validators, risk assessment, threat classification, alert
parsing/deduplication/correlation, statistics) is covered by a standard-library
`unittest` suite that needs **no** external services:

```bat
python -m unittest discover -s tests -v
```

---

## Security & Ethics

- Scan and monitor **only** authorized systems on an **isolated laboratory
  network**.
- AETHRA-SEC performs authorized vulnerability assessment and passive monitoring
  only. It never exploits, blocks, or automatically contains attacks.
- Passwords are bcrypt-hashed; database credentials live in `.env` (git-ignored)
  and are never committed.
- Historical security records (logs, alerts, scan history) cannot be edited
  through the GUI, preserving audit integrity.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| "Database connection failed" | Ensure MySQL is running and `.env` credentials are correct |
| Scanning disabled | Install Nmap + `python-nmap`; set `AETHRA_NMAP_PATH` if `nmap` is not on PATH |
| Monitoring won't start | Install Wireshark (`tshark`) + `pyshark`; run as Administrator |
| No Snort alerts | Verify Snort streams alerts to the configured Alert Socket host/port |

All errors are written to `logs/files/errors.log`.

---

*AETHRA-SEC — built for cybersecurity education in controlled laboratory
environments.*
