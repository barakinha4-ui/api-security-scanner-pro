# 🔐 API Security Scanner Pro — Enterprise Edition

Welcome to the **Premium** version of your API Security Scanner. This project has been reorganized for professional use and includes advanced features like **OAST Integration**, **Hot-Reload Plugins**, and **Multi-User IDOR Confirmation**.

---

## 🔥 Enterprise Features

### 📡 OAST (Out-of-Band) Integration
Detect blind vulnerabilities (SSRF, RCE, Blind SQLi) that traditional scanners miss.
- **Provider**: Default integration with `interact.sh` protocol.
- **Unique Domains**: Generates isolated subdomains for every scan to eliminate collisions.
- **Auto-Verification**: Polls external servers to confirm callbacks in real-time.

### 🔄 Plugin Hot-Reload
Develop and debug security modules without stopping your scans.
- **Watchdog Support**: Automatically reloads `.py` files in the `modules/` directory upon change.
- **Live Testing**: Update your payloads and see the results instantly on the next scan phase.

### 🧠 Advanced Confidence Scoring
No more drowning in false positives. Every finding includes a **Confidence Score (0.0 - 1.0)** based on:
- HTTP Status Code variance
- Response body pattern matching
- Time-based differential analysis
- **OAST Callback** (instantly promotes to 100% confidence)

### 📊 Professional Analytics
- **Dynamic Charts**: HTML reports now include Chart.js visualizations (Severity distribution, OWASP coverage, Confidence ratio).
- **CVSS v3.1 Integration**: Standalone calculator providing full vector strings for every vulnerability.
- **Pydantic Config**: manageable via `.env` files or environment variables.

---

## 📁 Project Structure

```text
api-security-scanner-pro/
├── dashboard/              # 🌐 Web-based Analysis Dashboard (Tailwind CSS)
└── src/
    └── apiscanner/         # 🐍 Core Scanner Engine
        ├── core/           # OAST, CVSS, Engine, and Plugin Registry
        ├── modules/        # Advanced Plugins (SQLi, BOLA, JWT, SSRF)
        ├── payloads/       # Attack Payloads Database
        ├── reports/        # HTML/JSON/Markdown/SARIF Generators
        ├── tests/          # Unit tests for core logic
        ├── config.py       # Pydantic-Settings & .env management
        ├── cli.py          # Unified CLI Entrypoint
        └── scanner.py      # Async Scan Orchestrator
```

---

## 🚀 Usage

### Full Enterprise Scan with OAST:
```bash
python src/apiscanner/cli.py \
  --target https://api.yourtarget.com \
  --scan full \
  --output report.html
```

### Enable Hot-Reload for Plugin Development:
Configure in `.env`:
```env
ENABLE_HOT_RELOAD=true
MAX_CONCURRENCY=50
OAST_PROVIDER=interact.sh
```

---

## ☁️ Deploying the Dashboard

Your **Enterprise Dashboard** can be hosted on **Cloudflare Pages** in seconds.
1. Drag the `dashboard/` folder into [Cloudflare Pages](https://dash.cloudflare.com/).
2. Upload your `report.json` to the deployed URL for a professional analytical view.

---

*This tool is for authorized security testing only. Happy hunting!*
