# 🛡️ SentinelAI: Autonomous Threat Detection & Incident Response Platform

> **4-Year Flagship Engineering Project (B.Tech CSE - AI/ML)**  
> *A modular, evolving cybersecurity intelligence system scaling from low-level network packet analysis to distributed multi-agent autonomous security operations.*

---

## 📌 Executive Summary

Modern cybersecurity threats (zero-days, automated port reconnaissance, DDoS, and credential stuffing) operate at machine speed. **SentinelAI** is designed as a multi-tier Security Information and Event Management (SIEM) and Intrusion Detection System (IDS).

It is structured to evolve across all 4 years of an undergraduate engineering degree, incrementally integrating:
- **Computer Networking & Systems** (Year 1)
- **High-Throughput Full-Stack & Distributed Databases** (Year 2)
- **Machine Learning & Deep Learning Anomaly Detectors** (Year 3)
- **Agentic AI Incident Response & Cloud Production MLOps** (Year 4)

---

## 🗺️ 4-Year Architectural Evolution Roadmap

```
[Year 1: Foundations]
   └─ Packet Sniffer & Log Parser CLI (Scapy / Sockets / Heuristic Correlator)
         │
[Year 2: High-Performance Systems & Web UI]
   └─ FastAPI Ingestion Engine + Time-Series DB (Timescale/ClickHouse) + Live Attack Map
         │
[Year 3: Machine Learning & Behavioral AI]
   └─ PyTorch Autoencoders, Isolation Forests, NSL-KDD Benchmarks, MITRE ATT&CK Mapping
         │
[Year 4: Autonomous SecOps & Cloud Scale]
   └─ Multi-Agent LLM Incident Triage, Kafka Event Streaming, Docker/K8s, Edge Probes
```

| Phase | Academic Stage | Focus Area | Technical Capabilities Added |
| :--- | :--- | :--- | :--- |
| **Phase 1** | **Year 1** *(Foundations)* | Networking & Systems | • Real-time TCP/UDP/ICMP packet dissection.<br>• Sliding-window heuristic detectors (Port scan, SYN flood).<br>• Linux/Syslog auth log parser for brute force attacks.<br>• Structured CLI with Rich colorized telemetry. |
| **Phase 2** | **Year 2** *(Full-Stack)* | Backends & Databases | • High-throughput REST API with **FastAPI**.<br>• Storage engine using **PostgreSQL + TimescaleDB** / ClickHouse.<br>• Interactive web dashboard (Next.js / React) with live WebSockets.<br>• Real-time GeoIP global attack vector mapping. |
| **Phase 3** | **Year 3** *(AI & ML Core)* | Machine Learning | • Unsupervised anomaly detection with **Isolation Forests** & **Autoencoders**.<br>• Supervised classification for DDoS/Malware using CIC-IDS2017.<br>• Automated tagging with standard **MITRE ATT&CK** techniques.<br>• Experiment tracking via **MLflow** / **Weights & Biases**. |
| **Phase 4** | **Year 4** *(Production)* | Distributed Systems & Agents | • **Autonomous LLM Agents** that draft incident reports and generate firewall rules (`iptables` / `ufw`).<br>• Distributed sensor network via **Apache Kafka**.<br>• Microservices deployment with **Docker Compose & Kubernetes**.<br>• Automated CI/CD and vulnerability regression tests. |

---

## 📂 Repository Structure

```text
Project-1/
├── sentinel/                       # Core Python Engine
│   ├── __init__.py
│   ├── cli.py                      # Interactive Command Line Interface
│   ├── sniffer/
│   │   ├── __init__.py
│   │   ├── capture.py              # Live capture & synthetic traffic generator
│   │   └── protocol.py             # PacketEvent and SecurityAlert data models
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── auth_log.py             # Syslog/SSH authentication brute force parser
│   ├── rules/
│   │   ├── __init__.py
│   │   └── signatures.py           # Stateful sliding-window threat detector
│   └── storage/
│       ├── __init__.py
│       └── reporter.py             # Terminal formatter & JSON alert exporter
├── data/
│   └── sample_logs/
│       └── auth_sample.log         # Sample authentication log with brute-force attack
├── tests/
│   ├── __init__.py
│   └── test_signatures.py          # Pytest unit tests for detection engine
├── pyproject.toml                  # Packaging and entrypoint config
├── requirements.txt                # Dependencies (scapy, rich, click, pytest)
└── README.md                       # Documentation & Roadmap
```

---

## 🚀 Quickstart Guide (Year 1)

### 1. Prerequisites
- Python 3.10+ installed
- Git installed

### 2. Environment Setup
```powershell
# Clone or navigate to the directory
cd Project-1

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package dependencies
pip install -r requirements.txt
```

### 3. Verify Version & Diagnostics
```powershell
python -m sentinel.cli version
```

### 4. Run Threat Simulation (No Admin/Root Needed)
Test real-time packet inspection and sliding-window heuristic detection:

* **Simulate a Port Scan Attack:**
  ```powershell
  python -m sentinel.cli simulate-attack --type port_scan --count 30
  ```

* **Simulate a SYN Flood (DoS) Attack:**
  ```powershell
  python -m sentinel.cli simulate-attack --type syn_flood --count 40
  ```

* **Export Alerts to JSON:**
  ```powershell
  python -m sentinel.cli simulate-attack --type port_scan --export alerts.json
  ```

### 5. Parse Authentication Logs for Brute Force
Analyze system logs for password-guessing attacks:
```powershell
python -m sentinel.cli parse-logs data/sample_logs/auth_sample.log --export alerts.json
```

### 6. Run Unit Tests
```powershell
pytest
```

---

## 📈 Next Milestones for Semester 2 / Year 2
- [ ] Add PCAP file reader (`.pcap` / `.pcapng`) to replay recorded Wireshark dumps.
- [ ] Add DNS tunneling and ARP spoofing heuristic detectors.
- [ ] Implement a SQLite / DuckDB local storage layer for indexing packet metrics.
- [ ] Wrap the engine in a **FastAPI** asynchronous server.

---

## 📜 License
MIT License - Open for educational and research use.
