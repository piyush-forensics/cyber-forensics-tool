# Cyber Forensics Investigation Tool

A Python-based digital forensics tool built for Cyber Cell internship.

## What It Does
- Scans any folder or device image for suspicious files
- Extracts complete file metadata (name, size, created, modified, accessed, permissions)
- Generates SHA256 hash for every file (used for evidence integrity)
- Flags suspicious files by extension (.exe, .bat, .sh, .php, .js, .vbs)
- Generates a professional investigation report with case number and investigator name

## Real Case Demo
- Case CC-2026-001: Scanned 53,278 files, found 273 suspicious files
- Case CC-2026-002: UPI Phishing Fraud simulation - caught cleanup.bat, payload.exe, suspicious_script.sh

## Tools Used
- Python 3.13
- Kali Linux
- Built-in libraries: os, hashlib, datetime, stat

## Skills Demonstrated
- Digital forensics methodology
- File metadata analysis
- SHA256 hash verification (chain of custody)
- Suspicious file detection
- Professional report generation

## How To Run
```bash
python3 forensics_tool.py
```

## Relevance to Cyber Cell
India recorded 28.15 lakh cybercrime cases in 2025.
Cyber cells face a major backlog in analyzing seized digital devices.
This tool automates the first step of any device investigation.

## Built By
Kajal | Cyber Security Student | 2026
