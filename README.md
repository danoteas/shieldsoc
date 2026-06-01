# ShieldSOC — DDoS Detection Platform

A full-stack real-time DDoS attack detection and mitigation platform built with machine learning, SHAP explainability, and MITRE ATT&CK framework mapping.

**Developed by:** Otegen Danial | Astana IT University | 2026

---

## Features

- Real-time packet capture via pyshark on eth0
- XGBoost ML classification with SHAP explainability per decision
- 7 Snort-style rule-based detection rules
- Automated iptables IP blocking with dynamic block duration
- MITRE ATT&CK technique mapping for all detected attack types
- Three-tier event storage (hot/warm/cold)
- JWT authentication with httpOnly cookies
- nginx reverse proxy with SSL/TLS
- Telegram alerting (6 trigger types)
- CEF export for Splunk/IBM QRadar compatibility
- Geographic attack map via Leaflet.js
- AI Assistant powered by DeepSeek API
- Real-time WebSocket dashboard

## Tech Stack

| Component | Technology |
|---|---|
| Backend | FastAPI, Python 3.10 |
| Packet Capture | pyshark (Wireshark/tshark) |
| ML Model | XGBoost + SHAP TreeExplainer |
| Database | SQLite (WAL mode) |
| Reverse Proxy | nginx |
| Frontend | Jinja2, Bootstrap 5, Chart.js, Leaflet.js |
| Auth | JWT + httpOnly cookies |
| Mitigation | iptables |
| Alerting | Telegram Bot API |

## Requirements

```bash
pip install -r requirements.txt
```

Also required on system:
```bash
sudo apt install tshark nginx
```

## Setup

**1. Clone the repository**
```bash
git clone https://github.com/danoteas/shieldsoc.git
cd shieldsoc
```

**2. Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Create .env file**
```bash
SHIELDSOC_USERNAME=admin
SHIELDSOC_PASSWORD=yourpassword
SHIELDSOC_SECRET=your_jwt_secret_key
TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DEEPSEEK_API_KEY=your_deepseek_api_key
```
**4. Configure nginx**
```bash
sudo cp shieldsoc.nginx /etc/nginx/sites-available/shieldsoc
sudo ln -s /etc/nginx/sites-available/shieldsoc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

**5. Allow iptables without password**
```bash
sudo visudo
# Add: yourusername ALL=(ALL) NOPASSWD: /sbin/iptables
```

**6. Run the platform**
```bash
sudo python3 main.py
```

## Detection Rules

| Rule | Condition | Attack Type |
|---|---|---|
| SYN_FLOOD_HIGH_PPS | PPS > 8000 AND entropy < 1.0 | SYN Flood |
| UDP_FLOOD_HIGH_BPS | BPS > 1,000,000 AND unique < 5 | UDP Flood |
| DISTRIBUTED_AMPLIFICATION | unique > 50 AND entropy > 4.0 | Amplification |
| SINGLE_SOURCE_FLOOD | dominant_ratio > 0.80 | Volumetric |
| PORT_SCAN_PROBE | unique > 20 AND packets < 200 | Port Scan |
| BURST_SPIKE | burst_index > 6.0 | Volumetric |
| SLOWLORIS | PPS < 150 AND packets > 150 | Slowloris |

## ML Evaluation Results

Evaluated on NSL-KDD KDDTest+ benchmark (22,544 records):

| Model | Accuracy | ROC AUC | Log Loss |
|---|---|---|---|
| XGBoost | 0.7574 | **0.9596** | **2.022** |
| Random Forest | 0.7517 | 0.9326 | 3.145 |
| Decision Tree | 0.7615 | 0.8027 | 8.597 |
| KNN | 0.7568 | 0.8200 | 7.883 |

XGBoost selected as the platform engine due to highest ROC AUC and lowest Log Loss.

## Lab Setup

Tested in a two-machine controlled environment:
- Victim machine: 192.168.20.8 (running ShieldSOC)
- Attacker machine: 192.168.20.7 (hping3, nmap, custom scripts)

## License

MIT License — free to use for academic and research purposes.

## Related

- NSL-KDD evaluation notebook: [ml-for-network-security](https://github.com/danoteas/ml-for-network-security)
- Diploma thesis: Astana IT University, 2026
