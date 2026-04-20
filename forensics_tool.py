import os
import hashlib
import datetime
import stat

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return "Unable to read file"

def get_metadata(filepath):
    try:
        info = os.stat(filepath)
        return {
            "File Name": os.path.basename(filepath),
            "Full Path": filepath,
            "Size (bytes)": info.st_size,
            "Created": datetime.datetime.fromtimestamp(info.st_ctime),
            "Modified": datetime.datetime.fromtimestamp(info.st_mtime),
            "Accessed": datetime.datetime.fromtimestamp(info.st_atime),
            "Permissions": oct(stat.S_IMODE(info.st_mode)),
            "SHA256 Hash": get_file_hash(filepath),
            "Suspicious": "NO"
        }
    except Exception as e:
        return {
            "File Name": os.path.basename(filepath),
            "Full Path": filepath,
            "Size (bytes)": "N/A",
            "Created": "N/A", "Modified": "N/A",
            "Accessed": "N/A", "Permissions": "N/A",
            "SHA256 Hash": "N/A", "Suspicious": "NO",
            "Error": str(e)
        }

def scan_directory(path):
    findings = []
    suspicious_extensions = ['.exe', '.bat', '.sh', '.php', '.js', '.vbs']
    for root, dirs, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            meta = get_metadata(filepath)
            ext = os.path.splitext(file)[1].lower()
            meta["Suspicious"] = "YES" if ext in suspicious_extensions else "NO"
            findings.append(meta)
    return findings

def generate_report(findings, investigator, case_number, case_description, output_path="investigation_report.txt"):
    suspicious = [x for x in findings if x["Suspicious"] == "YES"]
    with open(output_path, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("   CYBER FORENSICS INVESTIGATION REPORT\n")
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
        f.write("SUSPICIOUS FILES (REQUIRE FURTHER ANALYSIS)\n")
        f.write("-" * 40 + "\n")
        for i, file in enumerate(suspicious, 1):
            f.write(f"\nSUSPICIOUS FILE #{i}\n")
            for key, value in file.items():
                f.write(f"  {key}: {value}\n")
            f.write("-" * 40 + "\n")
        f.write("\n\nFULL FILE LISTING\n")
        f.write("-" * 40 + "\n")
        for i, file in enumerate(findings, 1):
            f.write(f"\nFILE #{i}\n")
            for key, value in file.items():
                f.write(f"  {key}: {value}\n")
            f.write("-" * 40 + "\n")
    print(f"\n[+] Report saved to   : {output_path}")
    print(f"[+] Total files scanned: {len(findings)}")
    print(f"[+] Suspicious files   : {len(suspicious)}")
    print(f"[+] Case Number        : {case_number}")

def main():
    print("=" * 60)
    print("   CYBER FORENSICS INVESTIGATION TOOL")
    print("   Built for Cyber Cell Internship Project")
    print("=" * 60)
    investigator = input("\nInvestigator Name : ")
    case_number = input("Case Number       : ")
    case_description = input("Case Description  : ")
    path = input("Folder to Scan    : ")
    if not os.path.exists(path):
        print("[-] Path does not exist.")
        return
    print(f"\n[*] Scanning: {path}")
    findings = scan_directory(path)
    generate_report(findings, investigator, case_number, case_description)

if __name__ == "__main__":
    main()
