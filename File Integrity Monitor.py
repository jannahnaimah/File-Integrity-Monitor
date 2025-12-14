import os
import hashlib
import json
from colorama import init, Fore, Style

init(autoreset=True)

BASELINE_FILE = 'baseline_fim.json'
REPORT_FILE = 'fim_report.txt'

def sha256_of_file(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return None

def walk_directory_and_hash(base_path):
    hashes = {}
    for root, _, files in os.walk(base_path):
        for name in files:
            full_path = os.path.join(root, name)
            # Skip baseline and report files for self-integrity
            if os.path.abspath(full_path) in map(os.path.abspath, [BASELINE_FILE, REPORT_FILE]):
                continue
            file_hash = sha256_of_file(full_path)
            if file_hash is not None:
                hashes[full_path] = file_hash
    return hashes

def save_baseline(baseline):
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=2)

def load_baseline():
    if not os.path.isfile(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, 'r') as f:
        return json.load(f)

def color_print(msg, color):
    print(color + msg + Style.RESET_ALL)

def write_report(report_lines):
    with open(REPORT_FILE, 'w') as f:
        for line in report_lines:
            f.write(line + '\n')

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Python-Based File Integrity Monitor (FIM)")
    parser.add_argument("path", help="Directory to monitor")
    parser.add_argument("--baseline", action="store_true", help="Create (or overwrite) integrity baseline")
    parser.add_argument("--report", action="store_true", help="Save change report to file")
    args = parser.parse_args()
    path = os.path.abspath(args.path)

    if args.baseline or not os.path.exists(BASELINE_FILE):
        print(Fore.CYAN + f"[+] Creating baseline for '{path}'..." + Style.RESET_ALL)
        baseline = walk_directory_and_hash(path)
        save_baseline(baseline)
        print(Fore.GREEN + "[+] Baseline created and saved." + Style.RESET_ALL)
        return

    print(Fore.CYAN + "[*] Loading baseline and checking for integrity..." + Style.RESET_ALL)
    old_baseline = load_baseline()
    new_baseline = walk_directory_and_hash(path)

    modified = []
    deleted = []
    new = []

    old_files = set(old_baseline.keys())
    new_files = set(new_baseline.keys())

    # Detect deleted
    for filename in old_files - new_files:
        deleted.append(filename)

    # Detect new
    for filename in new_files - old_files:
        new.append(filename)

    # Detect modified
    for filename in old_files & new_files:
        if old_baseline[filename] != new_baseline[filename]:
            modified.append(filename)

    report_lines = []

    if modified:
        color_print("\n[!] Modified files:", Fore.YELLOW)
        report_lines.append("Modified files:")
        for mf in modified:
            color_print(f"    M {mf}", Fore.YELLOW)
            report_lines.append(f"    M {mf}")

    if deleted:
        color_print("\n[-] Deleted files:", Fore.RED)
        report_lines.append("Deleted files:")
        for df in deleted:
            color_print(f"    D {df}", Fore.RED)
            report_lines.append(f"    D {df}")

    if new:
        color_print("\n[+] New files:", Fore.GREEN)
        report_lines.append("New files:")
        for nf in new:
            color_print(f"    N {nf}", Fore.GREEN)
            report_lines.append(f"    N {nf}")

    if not (modified or deleted or new):
        color_print("\n[+] No changes detected. Integrity OK.", Fore.GREEN)
        report_lines.append("No changes detected. Integrity OK.")

    if args.report:
        write_report(report_lines)
        print(Fore.BLUE + f"\n[+] Report saved to '{REPORT_FILE}'" + Style.RESET_ALL)

if __name__ == "__main__":
    main()

