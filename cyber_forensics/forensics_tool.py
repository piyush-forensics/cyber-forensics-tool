import os
import hashlib
import datetime
import stat
import math
import json
import csv
import sys

# ============================================================
#   CYBER FORENSICS INVESTIGATION TOOL v6.0 - FINAL
#   SHA256 | Magic Bytes | Entropy | Strings | Location
#   CSV/JSON Export | Read-Only Mode | Hash Blacklist
#   Built for Cyber Cell Internship
# ============================================================

# --- Known malicious hashes (SHA256 blacklist) ---
# Add real hashes here from threat intelligence feeds
KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty file / possible placeholder",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test file",
    # Add more known malicious hashes here
}

SUSPICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.sh', '.php', '.js', '.vbs',
    '.ps1', '.jar', '.dll', '.msi', '.cmd',
    '.scr', '.hta', '.wsf', '.reg', '.pif', '.com',
    '.vbe', '.jse', '.wsh', '.cpl', '.inf'
]

MAGIC_BYTES = [
    (b'SQLite format 3\x00',       'SQLite Database'),
    (b'\x37\x7A\xBC\xAF\x27\x1C', '7-Zip Archive'),
    (b'\x4D\x5A\x90\x00',         'PE Executable'),
    (b'\x7F\x45\x4C\x46',         'Linux ELF Executable'),
    (b'\xCA\xFE\xBA\xBE',         'Java Class File'),
    (b'\x50\x4B\x03\x04',         'ZIP Archive'),
    (b'\x52\x61\x72\x21',         'RAR Archive'),
    (b'\x25\x50\x44\x46',         'PDF File'),
    (b'\x89\x50\x4E\x47',         'PNG Image'),
    (b'\xFF\xD8\xFF',              'JPEG Image'),
    (b'\x47\x49\x46\x38',         'GIF Image'),
    (b'\xD0\xCF\x11\xE0',         'MS Office Document'),
    (b'\x7B\x5C\x72\x74\x66',    'RTF Document'),
    (b'\x1F\x8B',                 'GZIP Archive'),
    (b'\x4D\x5A',                 'Windows EXE/DLL'),
    (b'\x23\x21',                 'Script (Shebang)'),
]

COMPRESSED_TYPES = {'ZIP Archive', 'RAR Archive', '7-Zip Archive', 'GZIP Archive'}

EXPECTED_EXTENSIONS = {
    'PE Executable'        : ['.exe', '.dll', '.sys', '.scr', '.com', '.ocx'],
    'Windows EXE/DLL'      : ['.exe', '.dll', '.sys', '.scr', '.com', '.ocx'],
    'Linux ELF Executable' : ['.elf', '.so', '.out', ''],
    'Java Class File'      : ['.class', '.jar'],
    'ZIP Archive'          : ['.zip', '.jar', '.apk', '.docx', '.docm',
                              '.xlsx', '.xlsm', '.pptx', '.pptm',
                              '.odt', '.ods', '.odp', '.epub', '.xpi'],
    'RAR Archive'          : ['.rar', '.r00'],
    '7-Zip Archive'        : ['.7z'],
    'GZIP Archive'         : ['.gz', '.tgz'],
    'PDF File'             : ['.pdf'],
    'PNG Image'            : ['.png'],
    'JPEG Image'           : ['.jpg', '.jpeg'],
    'GIF Image'            : ['.gif'],
    'MS Office Document'   : ['.doc', '.xls', '.ppt', '.msg'],
    'RTF Document'         : ['.rtf'],
    'SQLite Database'      : ['.db', '.sqlite', '.sqlite3'],
    'Script (Shebang)'     : ['.sh', '.py', '.pl', '.rb', '.php', '.bash', ''],
}

SUSPICIOUS_STRINGS = [
    b'cmd.exe', b'powershell', b'/bin/sh', b'/bin/bash',
    b'wget ', b'curl ', b'nc ', b'netcat',
    b'base64', b'base64_decode', b'eval(',
    b'exec(', b'system(', b'shell_exec(',
    b'http://', b'https://', b'ftp://',
    b'socket', b'connect(', b'bind(',
    b'HKEY_', b'regedit', b'reg add',
    b'schtasks', b'crontab', b'at.exe',
    b'keylog', b'ransomware', b'encrypt',
    b'payload', b'reverse_shell', b'backdoor',
    b'rootkit', b'botnet', b'exploit',
    b'DROP TABLE', b'DELETE FROM',
    b'UNION SELECT', b"' OR '",
]

UTF16_SUSPICIOUS = [
    'powershell', 'cmd.exe', 'wget', 'curl',
    'reverse_shell', 'backdoor', 'exploit',
    'keylog', 'payload', 'base64',
]

SUSPICIOUS_LOCATIONS = [
    'downloads', 'temp', 'tmp', 'appdata',
    'desktop', 'recycle', 'recycler', '$recycle.bin',
    'public', 'startup', 'roaming'
]


# ============================================================
#   READ-ONLY EVIDENCE MODE
# ============================================================
def verify_readonly_mode(path):
    """Warn if path is writable — evidence should be read-only."""
    if os.access(path, os.W_OK):
        print("\n[!] WARNING: Evidence folder is WRITABLE!")
        print("[!] In real investigations, mount evidence as READ-ONLY.")
        print("[!] Changes to evidence can invalidate it in court.")
        print("[!] Continue anyway? (yes/no): ", end="")
        ans = input().strip().lower()
        if ans != 'yes':
            print("[-] Scan aborted. Mount evidence read-only and retry.")
            sys.exit(0)
    else:
        print("[✓] Evidence folder is READ-ONLY — safe to proceed.")


# ============================================================
#   KNOWN HASH BLACKLIST CHECK
# ============================================================
def check_hash_blacklist(file_hash):
    """Check if hash matches known malicious file database."""
    return KNOWN_MALICIOUS_HASHES.get(file_hash, None)


# ============================================================
#   SINGLE-PASS FILE READ
# ============================================================
def analyze_file_content(filepath, max_string_bytes=524288):
    sha256      = hashlib.sha256()
    byte_counts = [0] * 256
    total_bytes = 0
    header      = b''
    content_for_strings = b''

    try:
        with open(filepath, 'rb') as f:
            first_chunk    = True
            bytes_for_str  = 0
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                if first_chunk:
                    header      = chunk[:32]
                    first_chunk = False
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
                if bytes_for_str < max_string_bytes:
                    take = min(len(chunk), max_string_bytes - bytes_for_str)
                    content_for_strings += chunk[:take]
                    bytes_for_str       += take

        file_hash = sha256.hexdigest()
    except (IOError, PermissionError) as e:
        return {'hash': 'N/A', 'header': b'', 'entropy': -1.0,
                'data_len': 0, 'content': b'', 'error': str(e)}

    entropy = 0.0
    if total_bytes > 0:
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)

    return {
        'hash'    : file_hash,
        'header'  : header,
        'entropy' : round(entropy, 4),
        'data_len': total_bytes,
        'content' : content_for_strings,
        'error'   : None,
    }


def detect_file_type(header):
    for magic, filetype in MAGIC_BYTES:
        if header.startswith(magic):
            return filetype
    return "Unknown"


def is_extension_mismatch(filepath, detected_type):
    ext = os.path.splitext(filepath)[1].lower()
    if detected_type == 'Linux ELF Executable':
        if ext.lstrip('.').isdigit():
            return False
    if detected_type in EXPECTED_EXTENSIONS:
        return ext not in EXPECTED_EXTENSIONS[detected_type]
    return False


def entropy_level(entropy):
    if entropy < 0:     return "Cannot read"
    elif entropy < 3.5: return "LOW (Normal text/data)"
    elif entropy < 6.0: return "MEDIUM (Compressed or mixed)"
    elif entropy < 7.5: return "HIGH (Possibly encrypted/packed)"
    else:               return "VERY HIGH (Likely encrypted/obfuscated)"


def find_suspicious_strings(content):
    found         = []
    content_lower = content.lower()
    for sus_str in SUSPICIOUS_STRINGS:
        if sus_str.lower() in content_lower:
            found.append(sus_str.decode('utf-8', errors='ignore'))
    try:
        utf16_text = content.decode('utf-16-le', errors='ignore').lower()
        for word in UTF16_SUSPICIOUS:
            if word in utf16_text:
                tag = f"{word} [UTF-16LE]"
                if tag not in found:
                    found.append(tag)
    except Exception:
        pass
    return found


def check_suspicious_location(filepath):
    parts = os.path.normpath(filepath).lower().split(os.sep)
    for loc in SUSPICIOUS_LOCATIONS:
        if loc in parts:
            return f"YES — found in '{loc}' folder"
    return "NO"


def get_metadata(filepath):
    try:
        info       = os.stat(filepath)
        time_label = "Created" if os.name == 'nt' else "Metadata Changed"
        return {
            "File Name"    : os.path.basename(filepath),
            "Full Path"    : filepath,
            "Size (bytes)" : info.st_size,
            time_label     : str(datetime.datetime.fromtimestamp(info.st_ctime)),
            "Modified"     : str(datetime.datetime.fromtimestamp(info.st_mtime)),
            "Accessed"     : str(datetime.datetime.fromtimestamp(info.st_atime)),
            "Permissions"  : oct(stat.S_IMODE(info.st_mode)),
        }
    except (OSError, ValueError) as e:
        return {
            "File Name"    : os.path.basename(filepath),
            "Full Path"    : filepath,
            "Size (bytes)" : "N/A",
            "Modified"     : "N/A",
            "Accessed"     : "N/A",
            "Permissions"  : "N/A",
            "Error"        : str(e),
        }


def walk_error_handler(err):
    print(f"\n[!] Access denied — skipping: {err.filename}")


def sanitize_filename(name):
    return "".join(c for c in name if c.isalnum() or c in "-_")


# ============================================================
#   SCAN
# ============================================================
def scan_directory(path):
    findings = []
    for root, dirs, files in os.walk(path, followlinks=False, onerror=walk_error_handler):
        for file in files:
            filepath = os.path.join(root, file)
            print(f"[*] Scanning: {filepath[:70]:<70}", end='\r')

            meta     = get_metadata(filepath)
            analysis = analyze_file_content(filepath)

            meta["SHA256 Hash"] = analysis['hash']

            # Hash blacklist check
            blacklist_hit = check_hash_blacklist(analysis['hash'])

            ext            = os.path.splitext(file)[1].lower()
            ext_suspicious = ext in SUSPICIOUS_EXTENSIONS
            detected_type  = detect_file_type(analysis['header'])
            mismatch       = is_extension_mismatch(filepath, detected_type)
            entropy        = analysis['entropy']
            data_len       = analysis['data_len']
            entropy_lbl    = entropy_level(entropy)
            high_entropy   = (entropy >= 7.5 and data_len >= 4096
                              and detected_type not in COMPRESSED_TYPES)
            sus_strings     = find_suspicious_strings(analysis['content'])
            has_sus_strings = len(sus_strings) > 0
            sus_location    = check_suspicious_location(filepath)
            is_sus_location = sus_location != "NO"

            reasons = []
            if blacklist_hit:
                reasons.append(f"KNOWN MALICIOUS HASH: {blacklist_hit}")
            if ext_suspicious:
                reasons.append(f"Suspicious extension ({ext})")
            if mismatch:
                reasons.append(f"Extension mismatch — file is actually {detected_type}")
            if high_entropy:
                reasons.append("Very high entropy — possibly encrypted/obfuscated")
            if has_sus_strings:
                reasons.append(f"Suspicious strings: {', '.join(sus_strings[:5])}")
            if is_sus_location and len(reasons) > 0:
                reasons.append(f"Suspicious location: {sus_location}")

            is_suspicious = len(reasons) > 0

            meta["Detected File Type"]  = detected_type
            meta["Extension Mismatch"]  = "YES" if mismatch else "NO"
            meta["Entropy Score"]       = f"{entropy} — {entropy_lbl}"
            meta["Data Size Checked"]   = f"{data_len} bytes"
            meta["Suspicious Strings"]  = ', '.join(sus_strings) if sus_strings else "None"
            meta["Suspicious Location"] = sus_location
            meta["Blacklist Match"]     = blacklist_hit if blacklist_hit else "None"
            meta["Suspicious"]          = "YES" if is_suspicious else "NO"
            meta["Reason"]              = " | ".join(reasons) if reasons else "Clean"

            meta["_flag_mismatch"]   = mismatch
            meta["_flag_entropy"]    = high_entropy
            meta["_flag_strings"]    = has_sus_strings
            meta["_flag_location"]   = is_sus_location and is_suspicious
            meta["_flag_blacklist"]  = bool(blacklist_hit)

            findings.append(meta)

    print(" " * 80, end='\r')
    return findings


# ============================================================
#   EXPORT — CSV
# ============================================================
def export_csv(findings, case_number, timestamp):
    safe_case   = sanitize_filename(case_number) or "CASE"
    output_path = f"report_{safe_case}_{timestamp}.csv"
    if not findings:
        return output_path

    # Only export visible keys
    keys = [k for k in findings[0].keys() if not k.startswith("_flag")]

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
        writer.writeheader()
        for row in findings:
            writer.writerow({k: row.get(k, '') for k in keys})

    print(f"[+] CSV report saved   : {output_path}")
    return output_path


# ============================================================
#   EXPORT — JSON
# ============================================================
def export_json(findings, case_number, timestamp, investigator, case_description):
    safe_case   = sanitize_filename(case_number) or "CASE"
    output_path = f"report_{safe_case}_{timestamp}.json"
    suspicious  = [x for x in findings if x["Suspicious"] == "YES"]

    export_data = {
        "metadata": {
            "tool"           : "Cyber Forensics Investigation Tool v6.0",
            "case_number"    : case_number,
            "investigator"   : investigator,
            "case_description": case_description,
            "scan_time"      : str(datetime.datetime.now()),
            "total_files"    : len(findings),
            "suspicious_files": len(suspicious),
            "clean_files"    : len(findings) - len(suspicious),
        },
        "suspicious_files": [
            {k: v for k, v in f.items() if not k.startswith("_flag")}
            for f in suspicious
        ],
        "all_files": [
            {k: v for k, v in f.items() if not k.startswith("_flag")}
            for f in findings
        ],
    }

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, default=str)

    print(f"[+] JSON report saved  : {output_path}")
    return output_path


# ============================================================
#   TEXT REPORT
# ============================================================
def generate_text_report(findings, investigator, case_number, case_description, timestamp):
    suspicious         = [x for x in findings if x["Suspicious"] == "YES"]
    safe_case          = sanitize_filename(case_number) or "CASE"
    output_path        = f"report_{safe_case}_{timestamp}.txt"

    ext_mismatch_count = sum(1 for x in suspicious if x.get("_flag_mismatch"))
    high_ent_count     = sum(1 for x in suspicious if x.get("_flag_entropy"))
    sus_str_count      = sum(1 for x in suspicious if x.get("_flag_strings"))
    sus_loc_count      = sum(1 for x in suspicious if x.get("_flag_location"))
    blacklist_count    = sum(1 for x in suspicious if x.get("_flag_blacklist"))

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("   CYBER FORENSICS INVESTIGATION REPORT v6.0\n")
        f.write("   Cyber Cell - Digital Evidence Analysis\n")
        f.write("=" * 60 + "\n")
        f.write(f"Case Number     : {case_number}\n")
        f.write(f"Investigator    : {investigator}\n")
        f.write(f"Date & Time     : {datetime.datetime.now()}\n")
        f.write(f"Case Description: {case_description}\n")
        f.write("=" * 60 + "\n\n")

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total Files Scanned  : {len(findings)}\n")
        f.write(f"Suspicious Files     : {len(suspicious)}\n")
        f.write(f"Clean Files          : {len(findings) - len(suspicious)}\n\n")

        f.write("DETECTION BREAKDOWN\n")
        f.write("-" * 40 + "\n")
        f.write(f"  Known Malicious Hash : {blacklist_count} files\n")
        f.write(f"  Extension Mismatch   : {ext_mismatch_count} files\n")
        f.write(f"  High Entropy         : {high_ent_count} files\n")
        f.write(f"  Suspicious Strings   : {sus_str_count} files\n")
        f.write(f"  Suspicious Location  : {sus_loc_count} files\n")
        f.write("  (One file can trigger multiple detections)\n\n")

        f.write("SUSPICIOUS FILES\n")
        f.write("-" * 40 + "\n")
        if suspicious:
            for i, file in enumerate(suspicious, 1):
                f.write(f"\nSUSPICIOUS FILE #{i}\n")
                for key, value in file.items():
                    if not key.startswith("_flag"):
                        f.write(f"  {key}: {value}\n")
                f.write("-" * 40 + "\n")
        else:
            f.write("  No suspicious files found.\n\n")

        f.write("\n\nFULL FILE LISTING\n")
        f.write("-" * 40 + "\n")
        for i, file in enumerate(findings, 1):
            f.write(f"\nFILE #{i}\n")
            for key, value in file.items():
                if not key.startswith("_flag"):
                    f.write(f"  {key}: {value}\n")
            f.write("-" * 40 + "\n")

    print(f"[+] TXT report saved   : {output_path}")
    return output_path


# ============================================================
#   MAIN
# ============================================================
def main():
    print("=" * 60)
    print("   CYBER FORENSICS INVESTIGATION TOOL v6.0")
    print("   SHA256 | Magic Bytes | Entropy | UTF-16LE Strings")
    print("   Hash Blacklist | Read-Only Mode | CSV/JSON Export")
    print("   Built for Cyber Cell Internship")
    print("=" * 60)

    investigator     = input("\nInvestigator Name : ").strip()
    case_number      = input("Case Number       : ").strip()
    case_description = input("Case Description  : ").strip()
    path             = input("Folder to Scan    : ").strip()

    if not os.path.exists(path):
        print("[-] Path does not exist.")
        return
    if not os.path.isdir(path):
        print("[-] Not a directory.")
        return

    # Read-only evidence check
    verify_readonly_mode(path)

    print(f"\n[*] Starting scan on : {path}")
    print(f"[*] Checks: Extension | Magic Bytes | Entropy | Strings | Location | Blacklist")
    print("-" * 60)

    findings  = scan_directory(path)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    print("\n[*] Generating reports...")
    generate_text_report(findings, investigator, case_number, case_description, timestamp)
    export_csv(findings, case_number, timestamp)
    export_json(findings, case_number, timestamp, investigator, case_description)

    suspicious = [x for x in findings if x["Suspicious"] == "YES"]
    print(f"\n{'=' * 60}")
    print(f"[✓] Scan complete!")
    print(f"[✓] Total files  : {len(findings)}")
    print(f"[✓] Suspicious   : {len(suspicious)}")
    print(f"[✓] Reports      : TXT + CSV + JSON generated")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
