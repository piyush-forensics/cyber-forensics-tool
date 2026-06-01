# 🔍 Cyber Forensics Investigation Tool v6.0

A Python-based digital forensics tool built for Cyber Cell internship.

---

## 📋 What It Does

- Scans any folder or device image for suspicious files
- Extracts complete file metadata (name, size, created, modified, accessed, permissions)
- Generates SHA256 hash for every file (used for evidence integrity)
- Detects real file type using Magic Bytes (catches disguised malware)
- Flags suspicious files by extension (.exe, .bat, .sh, .php, .js, .vbs and 15+ more)
- Detects camouflaged files — virus.exe renamed as image.jpg
- Entropy analysis to find encrypted or obfuscated files
- Scans file content for suspicious strings (ASCII + UTF-16LE)
- Checks known malicious hash blacklist
- Read-only evidence mode — warns if evidence folder is writable
- Generates professional investigation report (TXT + CSV + JSON)

---

## 🧪 Real Case Demo

**Case CC-2026-001:**
Scanned 53,278 files — found 273 suspicious files

**Case CC-2026-002: UPI Phishing Fraud Simulation**
Caught: `cleanup.bat`, `payload.exe`, `suspicious_script.sh`
Also detected: `invoice.jpg` (disguised EXE), encrypted payload with entropy 7.8

---

## 🚀 How To Run

```bash
python3 forensics_tool_final.py
```

```
Investigator Name : Piyush
Case Number       : CC-2026-001
Case Description  : UPI Phishing Fraud Investigation
Folder to Scan    : /home/victim/downloads
```

Three reports are auto-generated:
```
report_CC2026001_20260530.txt   ← Human readable
report_CC2026001_20260530.csv   ← Excel compatible
report_CC2026001_20260530.json  ← Machine readable
```

---

## 🔬 Detection Methods

| Method | What It Catches |
|---|---|
| Extension Check | .exe, .bat, .sh, .php, .js, .vbs and 15+ more |
| Magic Bytes | Real file type from binary signature |
| Extension Mismatch | virus.exe disguised as image.jpg |
| Entropy Analysis | Encrypted or obfuscated malware |
| String Analysis | cmd.exe, powershell, wget, base64, reverse_shell (ASCII + UTF-16LE) |
| Hash Blacklist | Known malicious file database |
| Location Check | Files in Downloads, Temp, AppData, Startup etc. |
| SHA256 Hash | Evidence integrity / chain of custody |

---

## 🛠️ Tools Used

- Python 3.13
- Kali Linux
- Built-in libraries: `os`, `hashlib`, `datetime`, `stat`, `math`, `json`, `csv`, `sys`

---

## 💡 Skills Demonstrated

- Digital forensics methodology
- File metadata analysis
- Magic byte and file signature analysis
- SHA256 hash verification (chain of custody)
- Entropy-based malware detection
- Suspicious string hunting (ASCII + UTF-16LE)
- Extension mismatch / camouflage detection
- Read-only evidence handling
- Professional report generation (TXT, CSV, JSON)

---

## 🌐 Relevance to Cyber Cell

India recorded **28.15 lakh cybercrime cases in 2025**. Cyber cells face a major backlog in analyzing seized digital devices. This tool automates the first step of any device investigation — rapid triage of suspicious files with SHA256-verified evidence integrity.

---

## ⚠️ Forensic Note

This tool is designed for initial evidence triage and screening. Always work on a forensic copy — never the original evidence. SHA256 hashes serve as proof of evidence integrity in court.

---

## 👩‍💻 Built By

**Piyush** | Cyber Security Student | 2026  
Cyber Cell Internship Project
## Screenshots

### Tool Running
![Tool Running](screenshots/tool_running.png)

### Report Generated
![Report Generated](screenshots/report_generated.png)
