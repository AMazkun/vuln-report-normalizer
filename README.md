# 🛡️ Vulnerability Report Normalizer

A universal parser and normalizer for security scanner reports (GVM, Nessus, Nikto, ZAP, Burp, Nmap) into a **unified MongoDB schema**.  
This project helps security teams and researchers **store, query, and analyze** heterogeneous scan results in a consistent format.

Comparing reports across different security scanners is often a real headache. Each tool (Nmap, Nessus, GVM, Nikto, ZAP, Burp, etc.) uses its own structure, naming conventions, and levels of detail when describing vulnerabilities. What’s called a “Risk” in one scanner might be “Threat” or “Severity” in another, CVSS vectors may appear in completely different formats, and even common identifiers like CVE numbers may be buried in tags or presented as free text. This inconsistency makes it challenging not only to normalize findings into a single schema but also to verify which vulnerabilities are genuine and which are false positives. Building a unified view requires careful parsing, mapping, and often manual validation to ensure accurate results.

All mapping details into **FieldsMapping.numbers** file.

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

### 1. Clone and install

```bash
git clone https://github.com/yourname/vuln-report-normalizer.git
cd vuln-report-normalizer
```

Install python packadges dependencies

```bash
pip install -r requirements.txt
```

### 2. Parse all reports

 Copy xml format reports to **/import** or place a links to directories with exported reports there
 All vaild xml reports in **/import** wil be autodetected and parsed

```bash
python PARCERS/PARSER.py
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
- ✅ Nikto (XML)
- ✅ OWASP ZAP (XML)
- ✅ Burp Suite (XML)
- ✅ Nmap (XML)

---

## 📦 Roadmap

- [ ] Add support for more scanners (Acunetix, Qualys, OpenSCAP)
- [ ] Complete NMAP and BURP reports
- [ ] NMAP based scaner with infrastructure verification
- [ ] Web dashboard with filtering and statistics
- [ ] Docker Compose integration with MongoDB + Grafana

---

## 🤝 Contributing

PRs and issues are welcome!  
If you have a scanner not yet supported, feel free to open a feature request.

---

## 📜 License

MIT License – free to use, modify, and distribute.
