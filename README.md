# 🛡️ CyberShield — Cybersecurity Log Threat Detector

A Python-based cybersecurity log analysis tool that detects brute-force attacks, suspicious requests, and unauthorized access patterns from server log files. Built with **Streamlit** for an interactive web dashboard, **Pandas** for data analysis, **Matplotlib** for visualization, and **MySQL** for persistent threat storage.

---

## 📁 Project Structure

```
CyberShield/
│
├── app.py                    # Streamlit web interface
│
├── analyzer/
│   ├── __init__.py
│   ├── log_parser.py         # Reads log and extracts IP, time, event, etc.
│   ├── threat_detector.py    # Detects suspicious patterns
│   └── risk_analyzer.py      # Assigns LOW / MEDIUM / HIGH risk
│
├── database/
│   ├── __init__.py
│   └── db_manager.py         # Stores detected threats in MySQL
│
├── utils/
│   ├── __init__.py
│   └── logger.py             # Records application errors/events
│
├── data/
│   └── sample_server.log     # Sample input data
│
├── reports/
│   └── reports.csv           # Generated analysis report
│
├── requirements.txt          # Required Python libraries
└── README.md                 # Project documentation
```

---

## ✨ Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **📂 Log File Upload & Parsing** | Upload `.log` files; regex extracts timestamp, IP, event, and status code |
| 2 | **🔐 Brute-Force Detection** | Flags IPs with ≥ 5 consecutive `LOGIN_FAILED` events |
| 3 | **🚨 Suspicious Request Detection** | Identifies repeated `403`/`404` status codes and suspicious event types |
| 4 | **📊 Threat Dashboard** | Interactive charts — threat distribution, risk pie chart, event frequency |
| 5 | **⚠️ Risk Classification** | Assigns `LOW`, `MEDIUM`, or `HIGH` risk based on occurrence thresholds |
| 6 | **🗄️ Threat History + Report** | Saves threats to MySQL; download analysis as CSV |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.8+**
- **MySQL Server** (optional — only needed for Feature 6)

### Installation

```bash
# 1. Clone or navigate to the project directory
cd CyberShield

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Create the MySQL database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS cybershield;"

# 4. Run the app
streamlit run app.py
```

The dashboard will open at **http://localhost:8501**.

---

## 📋 Log File Format

Each line must follow this pipe-separated format:

```
TIMESTAMP | IP_ADDRESS | EVENT | STATUS_CODE
```

**Example:**

```
2026-10-02 10:15:22 | 192.168.1.20 | LOGIN_FAILED | 401
2026-10-02 10:16:00 | 10.0.0.45 | UNAUTHORIZED_ACCESS | 403
```

A sample file is provided at `data/sample_server.log`.

---

## ⚠️ Risk Classification Rules

| Failed Attempts | Risk Level |
|-----------------|------------|
| < 3             | 🟢 LOW    |
| 3 – 4           | 🟡 MEDIUM |
| ≥ 5             | 🔴 HIGH   |

> **Note:** These thresholds are predefined detection rules for the project, not indicators of confirmed real-world attacks.

---

## 🗄️ MySQL Setup

1. Start your MySQL server.
2. Create the database:
   ```sql
   CREATE DATABASE IF NOT EXISTS cybershield;
   ```
3. In the Streamlit sidebar, enter your MySQL credentials and enable **"Save threats to MySQL"**.
4. The `threats` table is created automatically on first run.

**Table Schema:**

| Column       | Type         |
|-------------|--------------|
| id          | INT (PK, AI) |
| timestamp   | VARCHAR(50)  |
| ip_address  | VARCHAR(45)  |
| threat_type | VARCHAR(100) |
| occurrences | INT          |
| risk_level  | VARCHAR(10)  |
| detected_at | DATETIME     |

---

## 🔄 Application Flow

```
USER
  │
  ↓
Upload server.log
  │
  ↓
Read log file
  │
  ↓
Regex parses each line
  │
  ↓
Store structured data
  │
  ├──────────────────┐
  ↓                  ↓
Failed Login     Suspicious
Detection        Request Detection
  │                  │
  └────────┬─────────┘
           ↓
    Threat Detection
           ↓
      Risk Analysis
           │
  ┌────────┴────────┐
  ↓                 ↓
Dashboard         MySQL
  │                 │
  ↓                 ↓
Charts         Threat History
```

---

## 🛠️ Technologies Used

- **Python 3** — Core programming language
- **Streamlit** — Web interface and dashboard
- **Pandas** — Data manipulation and analysis
- **Matplotlib** — Chart generation
- **MySQL** — Persistent threat storage
- **Regular Expressions** — Log line parsing
- **Logging** — Application event recording

---

## 📄 License

This project is developed for educational purposes as a college mini-project.
