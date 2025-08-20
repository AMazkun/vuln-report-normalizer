# 🛡️ Vulnerability Report Normalizer

A universal parser and normalizer for security scanner reports (GVM, Nessus, Nikto, ZAP, Burp, Nmap) into a **unified MongoDB schema**.  
This project helps security teams and researchers **store, query, and analyze** heterogeneous scan results in a consistent format.

---

## ✨ Features
- 📂 Parse multiple security scanner formats:
  - GVM (OpenVAS)
  - Nessus
  - Nikto
  - OWASP ZAP
  - Burp Suite
  - Nmap
- 📊 Normalize fields into a **MongoDB collection schema** (hosts, ports, vulnerabilities, CVEs, CVSS, risk, etc.)
- 🤖 Auto-detect scanner type from report file
- 📦 Automatically archive processed reports → `/archive/{date}/{scanner}/`
- 🔄 Ready to integrate with ELK, Grafana, or other SIEM solutions

---

## 🗂 MongoDB Schema

Each normalized vulnerability document follows this schema:

```json
{
  "_id": "ObjectId",
  "Host": "192.168.1.10",
  "Protocol": "tcp",
  "Port": "80",
  "Hostname": "example.local",
  "Service": "http",

  "Plugin ID": "12345",
  "Plugin Ver": "1.0",
  "Plugin Name": "Apache HTTP Server < 2.4.50 Multiple Vulnerabilities",
  "Plugin Output": "Apache outdated",

  "CVE": ["CVE-2021-41773", "CVE-2021-42013"],
  "Risk": "Medium",
  "Synopsis": "Outdated Apache version",
  "Description": "...",
  "Solution": "Update to 2.4.50 or later",
  "See Also": ["https://httpd.apache.org/security/vulnerabilities_24.html"],

  "CVSS Base Type": "CVSS2",
  "CVSS Base Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
  "CVSS Base Score": 7.5,

  "STIG Severity": null,
  "VPR Score": null,
  "EPSS Score": null,
  "Risk Factor": "Medium",

  "BID": null,
  "XREF": null,
  "MSKB": null,
  "Metasploit": null,
  "Core Impact": null,
  "CANVAS": null,

  "scan_type": "full",
  "scan_tool": "nessus",
  "scan_begin": "2025-08-16 10:05:12",
  "scan_end": "2025-08-16 10:15:48",
  "scan_document_id": "report_123"
}
```

---

## 🚀 Usage

### 1. Clone the repo
```bash
git clone https://github.com/yourname/vuln-report-normalizer.git
cd vuln-report-normalizer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Parse a report
```bash
python parse_report.py reports/scan.xml
```

This will:
- Auto-detect scanner type
- Parse report into MongoDB schema
- Save documents into MongoDB
- Move the raw file into `/archive/{date}/{scanner}/`

---

## 🧩 Supported Scanners
- ✅ GVM (XML)
- ✅ Nessus (XML)
- ✅ Nikto (XML/JSON)
- ✅ OWASP ZAP (JSON/XML)
- ✅ Burp Suite (XML/JSON)
- ✅ Nmap (XML)

---

## 📦 Roadmap
- [ ] Add support for more scanners (Acunetix, Qualys, OpenSCAP)
- [ ] REST API with FastAPI
- [ ] Web dashboard with filtering and statistics
- [ ] Docker Compose integration with MongoDB + Grafana

---

## 🤝 Contributing
PRs and issues are welcome!  
If you have a scanner not yet supported, feel free to open a feature request.

---

## 📜 License
MIT License – free to use, modify, and distribute.
