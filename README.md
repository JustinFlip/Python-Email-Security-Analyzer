# Python-Email-Security-Analyzer
# 🔒 Email Security Analyzer

A powerful Python-based email analysis tool that scans emails for malicious URLs, suspicious attachments, and security threats using VirusTotal integration.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## 🌟 Features

- **📧 Email Parsing**: Analyzes .eml files with full header inspection
- **🔗 URL Extraction**: Automatically extracts and scans all URLs from email body
- **📎 Attachment Analysis**: Scans attachments for malware using SHA256 hashing
- **🦠 VirusTotal Integration**: Real-time threat detection via VirusTotal API
- **📄 Multi-Format Support**: Extracts URLs from PDF, DOCX, TXT, HTML, and more
- **🎯 Clear Verdicts**: Easy-to-understand MALICIOUS/SUSPICIOUS/CLEAN ratings
- **⚡ Batch Processing**: Analyze multiple emails at once

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- VirusTotal API key (free at [virustotal.com](https://www.virustotal.com/gui/join-us))

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/email-security-analyzer.git
cd email-security-analyzer
```

2. Install required dependencies:
```bash
pip install -r requirements.txt --break-system-packages
```

3. Set up your VirusTotal API key:
```bash
export VT_API_KEY="your_api_key_here"
```

For permanent setup, add to your `~/.bashrc`:
```bash
echo 'export VT_API_KEY="your_api_key_here"' >> ~/.bashrc
source ~/.bashrc
```

### Usage

1. Place your `.eml` files in the `emails/` directory

2. Run the analyzer:
```bash
python3 email_analyzer.py
```

3. View results in the terminal and check saved attachments in `attachments/` directory

## 📋 Example Output

```
============================================================
=== Analyzing: emails/suspicious_email.eml ===
============================================================

[*] Email Headers:
From: suspicious@example.com
To: victim@company.com
Subject: Urgent: Update Your Account
Date: Mon, 30 Jan 2026 10:30:00 +0000

[+] Found 3 URL(s) in email body:
  - http://phishing-site.com/login
    ⚠️  MALICIOUS: 45/89 engines flagged this URL
  - http://legitimate-site.com
    ✓ CLEAN: No threats detected

[!] Attachment found: invoice.pdf
[*] SHA256: a1b2c3d4e5f6...
[VT] VirusTotal Results:
  - Malicious: 12
  - Suspicious: 3
  - Total scans: 70
  ⚠️  VERDICT: MALICIOUS (12/70 engines detected threats)
```

## 🛠️ Configuration

Edit these variables in `email_analyzer.py`:

```python
EMAIL_DIR = "emails"           # Directory for input .eml files
ATTACHMENTS_DIR = "attachments" # Directory for saved attachments
```

## 📦 Dependencies

- `beautifulsoup4` - HTML parsing
- `requests` - API communication
- `PyPDF2` - PDF text extraction (optional)
- `python-docx` - Word document parsing (optional)

Install optional dependencies for full functionality:
```bash
pip install PyPDF2 python-docx --break-system-packages
```

## 🔐 Security Features

### URL Analysis
- Extracts all HTTP/HTTPS links from email body
- Scans each URL against VirusTotal database
- Displays threat level with detection ratios

### Attachment Scanning
- Calculates SHA256 hash for each file
- Checks hash against VirusTotal's malware database
- Extracts URLs from common file formats (PDF, DOCX, TXT)

### Header Inspection
- Displays sender, recipient, and subject information
- Shows Return-Path for spoofing detection

## 📊 VirusTotal Integration

This tool uses the VirusTotal API v3 for threat detection:
- **Free tier**: 4 requests/minute, 500/day
- **Coverage**: 70+ antivirus engines
- **Detection types**: Malware, phishing, suspicious URLs

Get your free API key: https://www.virustotal.com/gui/join-us

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Always ensure you have permission to analyze emails and attachments. The author is not responsible for misuse of this tool.

## 👤 Author

**Justin Flip**

- GitHub: https://github.com/JustinFlip

## 📮 Support

If you found this project helpful, please give it a ⭐️!

For issues or questions, please open an issue on GitHub.

---

Made with ❤️ by Justin Flip
