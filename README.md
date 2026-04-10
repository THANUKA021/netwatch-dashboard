# 🌐 NetWatch — Network Traffic Monitoring Dashboard

A free, open-source, real-time network traffic monitoring and analysis
dashboard built with Python, Flask, Plotly and Bootstrap.

---

## 📸 Features

| Feature | Details |
|---|---|
| Live Packet Capture | Scapy (preferred) → PyShark → Demo fallback |
| Protocols Detected | TCP, UDP, DNS, HTTP, HTTPS, SSH, FTP |
| Storage | SQLite + CSV (all packets saved automatically) |
| Charts | Bandwidth line, Protocol bar, Device pie |
| Anomaly Detection | Z-score based — flags high-traffic devices in red |
| Filters | Protocol, Device IP, Time window, Row limit |
| Reports | Download CSV or PDF at any time |
| Auto-refresh | Every 5 seconds (no page reload needed) |
| Theme | Dark industrial / terminal aesthetic |

---

## 🗂 Project Structure

```
netwatch/
│
├── app.py            # Flask application + API routes
├── capture.py        # Packet capture (Scapy / PyShark / Demo)
├── db.py             # SQLite & CSV read/write helpers
├── requirements.txt  # Python dependencies
│
├── templates/
│   └── index.html    # Main dashboard HTML
│
├── static/
│   ├── css/style.css # Dark-theme stylesheet
│   └── js/dashboard.js  # Plotly charts + auto-refresh logic
│
├── netwatch.db       # Created automatically on first run
└── packets.csv       # Appended automatically on first run
```

---

## 🚀 Quick Start

### 1 — Clone / download the project

```bash
# If you have git:
git clone https://github.com/yourname/netwatch
cd netwatch

# Or just unzip the downloaded folder and cd into it
```

### 2 — Create a virtual environment (recommended)

```bash
python -m venv venv

# Linux / macOS:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

**Optional extras:**
```bash
# For PDF reports:
pip install reportlab

# For live capture on Linux/macOS (needs root):
pip install scapy

# Alternative: PyShark (needs Wireshark/tshark installed):
pip install pyshark
```

### 4 — Run the dashboard

```bash
# Linux / macOS — needs sudo for raw packet capture:
sudo python app.py

# Windows — run as Administrator, then:
python app.py

# No root / no Scapy?  It runs in DEMO mode automatically.
```

### 5 — Open in your browser

```
http://localhost:5000
```

---

## 🐧 Linux / macOS Notes

Raw packet capture requires elevated privileges:

```bash
# Option A — run with sudo (simplest):
sudo python app.py

# Option B — give Python the capability without sudo:
sudo setcap cap_net_raw+ep $(which python3)
python app.py
```

---

## 🪟 Windows Notes

1. Install [Npcap](https://npcap.com/) (required by Scapy).
2. Run **Command Prompt as Administrator**.
3. `python app.py`

---

## 🎭 Demo Mode

If neither Scapy nor PyShark is installed, or if you run without root,
the app automatically falls back to **Demo Mode** which generates
realistic simulated traffic — including one "heavy" device that will
trigger the anomaly detection banner.

This is great for testing the dashboard without any setup!

---

## 📊 API Endpoints

All endpoints accept the filters `?hours=N&protocol=X&device=Y`.

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Summary card values |
| `GET /api/protocols` | Per-protocol totals |
| `GET /api/devices` | Per-device totals + anomaly flag |
| `GET /api/bandwidth` | Bandwidth over time (bucketed) |
| `GET /api/packets` | Raw packet list |
| `GET /download/csv` | Download CSV report |
| `GET /download/pdf` | Download PDF report |

---

## 🔧 Configuration

Open `app.py` and adjust at the top:

| Variable | Default | Description |
|---|---|---|
| `ANOMALY_SIGMA` | `2.0` | Z-score threshold for anomaly flag |
| `BUFFER_SIZE` in `capture.py` | `1000` | In-memory packet ring buffer size |
| `REFRESH_INTERVAL` in `dashboard.js` | `5000` | Auto-refresh ms |

---

## 📦 Dependencies

| Package | Purpose | License |
|---|---|---|
| Flask | Web server | BSD |
| Scapy | Packet capture | GPL-2 |
| PyShark | Alt. packet capture | MIT |
| pandas | Data manipulation | BSD |
| Plotly.js | Interactive charts | MIT (CDN) |
| Bootstrap 5 | UI layout | MIT (CDN) |
| ReportLab | PDF generation | BSD |

Everything is **free and open-source**. Zero paid services.

---

## 💡 Portfolio Tips

- **Show Demo Mode** to interviewers if you can't run with root.
- The anomaly banner makes a great visual talking point.
- Mention the architecture: **capture thread → SQLite → REST API → Plotly**.
- Explain the z-score anomaly detection for data-science brownie points.

---

## 📄 License

MIT — do whatever you like with it.
