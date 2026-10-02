# 🛡️ CyberShield — Cybersecurity Log Threat Detector

A Python-based cybersecurity log analysis tool that detects brute-force attacks, suspicious requests, and unauthorized access patterns from server log files. Built with **Streamlit** for an interactive web dashboard, **Pandas** for data analysis, **Matplotlib** for visualization, and **MySQL** for persistent threat storage.

---

## 📁 Project Structure

```
CyberShield/
│
├── app.py                    # Web server & Vercel entrypoint (Flask)
├── streamlit_app.py          # Streamlit dashboard interface
├── vercel.json               # Vercel serverless routing configuration
│
├── public/
│   └── index.html            # CyberShield Web UI Dashboard
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

# 4. Run the Web Dashboard (Flask / Vercel entrypoint)
python app.py
# Accessible at http://127.0.0.1:5000

# OR run with Streamlit:
python -X utf8 -m streamlit run streamlit_app.py
# Accessible at http://localhost:8501
```

---

## 🌐 Cloud Deployment

### 1. Vercel (Web Serverless Deployment)
CyberShield is configured for instant deployment on **Vercel**:
- Root [app.py](file:///d:/R09/My%20Project/CyberShield/app.py) exports the top-level `app` WSGI instance.
- Static dashboard assets are served from `public/`.
- Routes and rewrites are managed by `vercel.json`.

### 2. Streamlit Community Cloud
To host the Streamlit dashboard on [share.streamlit.io](https://share.streamlit.io/):
- **Repository:** `raj-aparnathi/CyberShield-Cybersecurity-Log-Threat-Detector`
- **Main file path:** `streamlit_app.py`

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
