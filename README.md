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
## Troubleshooting

**pyshark not capturing packets**
```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which tshark)
```

**iptables permission denied**
```bash
sudo visudo
# Add: danoteas ALL=(ALL) NOPASSWD: /sbin/iptables
```

**Port 443 already in use**
```bash
sudo systemctl stop apache2
sudo systemctl restart nginx
```

**WebSocket connection failed**
- Check nginx config has WebSocket proxy headers
- Make sure you access via https:// not http://

---

## Recommendations for Production

- Replace self-signed SSL certificate with Let's Encrypt:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

- Change default credentials in .env before deployment
- Set strong JWT secret (minimum 32 characters)
- Configure Telegram alerts for 24/7 monitoring
- Set ML threshold between 0.65-0.75 for balanced detection
- Add your gateway and trusted IPs to whitelist before starting

---

## Attack Testing (Lab Only)

To simulate attacks in controlled environment:
```bash
# SYN Flood
sudo hping3 -S --flood -V -p 80 192.168.20.8

# UDP Flood  
sudo hping3 --udp --flood -p 80 192.168.20.8

# Port Scan
nmap -sS -p 1-65535 192.168.20.8

# Slowloris
python3 simulate_traffic.py
```

**Warning:** Only use on your own machines in isolated lab environment.

---

## Project Structure

```
shieldsoc/
├── main.py                 # FastAPI app, all API endpoints
├── auth.py                 # JWT authentication
├── config.py               # Configuration
├── shared_state.py         # Shared detection state
├── detector/
│   └── detector_engine.py  # Packet capture, ML inference, rules
├── services/
│   ├── event_store.py      # Three-tier storage
│   ├── mitigation.py       # iptables blocking
│   ├── session_engine.py   # Attack session tracking
│   └── telegram_alerts.py  # Telegram notifications
├── ml_pipeline/
│   ├── generate_dataset_v3.py
│   ├── build_features_v2.py
│   └── train_model_v2.py
├── templates/              # Jinja2 HTML templates
├── static/                 # JS, CSS assets
├── model/                  # Trained XGBoost model
└── shieldsoc.nginx         # nginx configuration
```

## License

MIT License — free to use for academic and research purposes.

## Related

- NSL-KDD evaluation notebook: [ml-for-network-security](https://github.com/danoteas/ml-for-network-security)
- Diploma thesis: Astana IT University, 2026
