#!/usr/bin/env bash
# ==============================================================================
#  autoclean.sh — Web Malware Injection Scanner & Safe Cleaner CLI
# ==============================================================================
#  Author  : Percio Castelo <percio@perciocastelo.com.br>
#  Website : https://perciocastelo.com.br
#  Project : https://perciocastelo.com.br/projetos/en/autoclean.html
#  Repo    : https://github.com/sr00t3d/autoclean
#  License : Apache-2.0
#  Version : 2.0.0
#  Notes   : Clean-room Bash + Python3-stdlib reimplementation inspired by
#            `autoclean 1.2` (2011, Patrick Harrison / HostGator Security).
#            Removes defunct Python 2.6/XML-RPC/telemetry dependencies and adds
#            offline high-precision signatures, dry-run default, chmod 600
#            tar.gz backups, custom rules, and table/json/csv outputs.
# ==============================================================================

set -uo pipefail
export LC_ALL=C

readonly SCRIPT_NAME="autoclean.sh"
readonly SCRIPT_VERSION="2.0.0"

# Defaults
TARGET_DIR="."
RESELLER=""
CLEAN_MODE=0
SKIP_BACKUP=0
BACKUP_DIR=""
RULES_FILE=""
MAX_SIZE_KB=512
MAX_DEPTH=0
EXIT_CODE_MODE=0
FORMAT="table"
QUIET=0
NO_COLOR=0
VERBOSE=0

TIMESTAMP_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

show_help() {
  cat <<'USAGE'
autoclean.sh v2.0.0 — Web Malware Injection Scanner & Safe Cleaner CLI

Usage:
  autoclean.sh [options] [directory]

Options:
  -d, --directory <path>     Target directory to scan (default: current directory)
  -r, --reseller <user>      cPanel mode: scan /home/<user>/public_html for all accounts owned by reseller
  -c, --clean                Actually remove matched injections (default: DRY-RUN scan only)
  -B, --skip-backup          Skip creating chmod 600 .tar.gz backup before cleaning (use with caution)
  --backup-dir <path>        Custom directory to store autoclean-<timestamp>.tar.gz backups
  --rules-file <path>        Load custom regex rules from JSON file (list of {name, extensions, pattern})
  --max-size <KB>            Maximum file size to scan in KB (default: 512)
  --max-depth <n>            Maximum directory recursion depth (0 = unlimited)
  --exit-code                Exit with code 2 if any infection is detected (ideal for Cron/SOC/CI)
  -o, --output <fmt>         Output format: table (default), json, csv
  -v, --verbose              Show matched snippet previews in table output
  -q, --quiet                Suppress banner header
  --no-color                 Disable ANSI colors
  -V, --version              Show version and exit
  -h, --help                 Show this help and exit

Examples:
  # Safe dry-run scan of a web root
  autoclean.sh -d /home/user/public_html

  # Clean matched injections with automatic chmod 600 tar.gz backup
  autoclean.sh -d /home/user/public_html --clean

  # Audit in JSON and exit 2 if infected
  autoclean.sh -d /var/www/html -o json --exit-code

  # Scan all cPanel accounts owned by a reseller
  autoclean.sh -r myreseller --exit-code
USAGE
}

need_cmd() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      printf '[ERR] Required command not found: %s\n' "$cmd" >&2
      exit 1
    fi
  done
}

main() {
  need_cmd python3

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -h|--help)        show_help; exit 0 ;;
      -V|--version)     printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
      -d|--directory)   TARGET_DIR="${2:-.}"; shift 2 ;;
      -r|--reseller)    RESELLER="${2:-}"; shift 2 ;;
      -c|--clean|--clean-files) CLEAN_MODE=1; shift ;;
      -B|--skip-backup) SKIP_BACKUP=1; shift ;;
      --backup-dir)     BACKUP_DIR="${2:-}"; shift 2 ;;
      --rules-file)     RULES_FILE="${2:-}"; shift 2 ;;
      --max-size)       MAX_SIZE_KB="${2:-512}"; shift 2 ;;
      --max-depth)      MAX_DEPTH="${2:-0}"; shift 2 ;;
      --exit-code)      EXIT_CODE_MODE=1; shift ;;
      -o|--output)      FORMAT="${2:-table}"; shift 2 ;;
      --output=*)       FORMAT="${1#*=}"; shift ;;
      -v|--verbose)     VERBOSE=1; shift ;;
      -q|--quiet)       QUIET=1; shift ;;
      --no-color)       NO_COLOR=1; shift ;;
      -*)               printf '[ERR] Unknown option: %s (use -h for help)\n' "$1" >&2; exit 1 ;;
      *)                TARGET_DIR="$1"; shift ;;
    esac
  done

  case "$FORMAT" in
    table|json|csv) ;;
    *) printf '[ERR] Invalid output format: %s (expected table, json, or csv)\n' "$FORMAT" >&2; exit 1 ;;
  esac

  if [[ ! "$MAX_SIZE_KB" =~ ^[0-9]+$ || ! "$MAX_DEPTH" =~ ^[0-9]+$ ]]; then
    printf '[ERR] --max-size and --max-depth must be non-negative integers.\n' >&2
    exit 1
  fi

  local use_color=0
  if [[ "$NO_COLOR" -eq 0 && -t 1 && -z "${NO_COLOR:-}" && "$FORMAT" == "table" ]]; then
    use_color=1
  fi

  python3 - "$SCRIPT_NAME" "$SCRIPT_VERSION" "$TIMESTAMP_UTC" \
    "$TARGET_DIR" "$RESELLER" "$CLEAN_MODE" "$SKIP_BACKUP" "$BACKUP_DIR" \
    "$RULES_FILE" "$MAX_SIZE_KB" "$MAX_DEPTH" "$EXIT_CODE_MODE" \
    "$FORMAT" "$QUIET" "$use_color" "$VERBOSE" <<'PYEOF'
import csv
import io
import json
import os
import re
import stat
import sys
import tarfile
import time

(
    script_name,
    script_version,
    timestamp_utc,
    target_dir,
    reseller,
    clean_mode_s,
    skip_backup_s,
    backup_dir,
    rules_file,
    max_size_kb_s,
    max_depth_s,
    exit_code_mode_s,
    fmt,
    quiet_s,
    use_color_s,
    verbose_s,
) = sys.argv[1:17]

clean_mode = clean_mode_s == "1"
skip_backup = skip_backup_s == "1"
max_size_bytes = int(max_size_kb_s) * 1024
max_depth = int(max_depth_s)
exit_code_mode = exit_code_mode_s == "1"
quiet = quiet_s == "1"
use_color = use_color_s == "1"
verbose = verbose_s == "1"

C_RED = "\033[0;31m" if use_color else ""
C_GRN = "\033[0;32m" if use_color else ""
C_YEL = "\033[0;33m" if use_color else ""
C_CYN = "\033[0;36m" if use_color else ""
C_BLD = "\033[1m" if use_color else ""
C_RST = "\033[0m" if use_color else ""

OMIT_DIR_NAMES = {".git", ".cpanel", ".security", "node_modules", "virtfs", "mail", ".cagefs"}

DEFAULT_RULES = [
    {
        "name": "php_eval_base64_injection",
        "extensions": [".php", ".phtml", ".php5", ".inc"],
        "pattern": r"<\?php\s+/\*[a-z0-9]{4,12}\*/\s*@?(?:eval|assert)\s*\(\s*(?:gzinflate\s*\(\s*)?(?:str_rot13\s*\(\s*)?base64_decode\s*\([^)]+\)\s*\)+\s*;\s*\?>",
    },
    {
        "name": "php_eval_base64_inline",
        "extensions": [".php", ".phtml", ".php5", ".inc"],
        "pattern": r"@?(?:eval|assert)\s*\(\s*(?:gzinflate\s*\(\s*)?(?:str_rot13\s*\(\s*)?base64_decode\s*\(\s*['\"][A-Za-z0-9+/=]{40,}['\"]\s*\)\s*\)+\s*;?",
    },
    {
        "name": "php_globals_obfuscated_header",
        "extensions": [".php", ".phtml", ".php5"],
        "pattern": r"<\?php\s+\$GLOBALS\['_[A-Za-z0-9]{4,24}'\]\s*=\s*Array\([^;]{20,}\);[^?]{10,400}\?>",
    },
    {
        "name": "php_request_backdoor_eval",
        "extensions": [".php", ".phtml", ".php5"],
        "pattern": r"@?(?:eval|assert)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:POST|GET|COOKIE|REQUEST)\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\)?\s*\)\s*;?",
    },
    {
        "name": "php_preg_replace_e_rce",
        "extensions": [".php", ".phtml", ".php5"],
        "pattern": r"preg_replace\s*\(\s*['\"][^'\"]*/e['\"]\s*,\s*(?:@?eval|base64_decode|\$_(?:POST|GET|COOKIE|REQUEST))[^;]+;",
    },
    {
        "name": "js_obfuscated_fromcharcode_eval",
        "extensions": [".js", ".html", ".htm", ".php"],
        "pattern": r"(?:<script[^>]*>\s*)?eval\s*\(\s*String\.fromCharCode\s*\([0-9,\s]{30,}\)\s*\)\s*;?(?:\s*</script>)?",
    },
    {
        "name": "html_hidden_external_iframe",
        "extensions": [".html", ".htm", ".php", ".phtml"],
        "pattern": r"<iframe[^>]+src\s*=\s*['\"]https?://[^'\"]+['\"][^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*['\"]?0['\"]?|height\s*=\s*['\"]?0['\"]?)[^>]*>\s*</iframe>",
    },
    {
        "name": "htaccess_malicious_search_redirect",
        "extensions": [".htaccess"],
        "pattern": r"(?:RewriteCond\s+%\{HTTP_REFERER\}[^\n]*(?:google|bing|yahoo)[^\n]*\n){1,4}\s*RewriteRule\s+\.\*\s+https?://[^\s\n]+\s+\[[^\]]*R=30[12][^\]]*\]",
    },
]

if rules_file:
    if not os.path.isfile(rules_file):
        sys.stderr.write("[ERR] Rules file not found: %s\n" % rules_file)
        sys.exit(1)
    with open(rules_file, "r", encoding="utf-8") as fh:
        raw_rules = json.load(fh)
else:
    raw_rules = DEFAULT_RULES

compiled_rules = []
allowed_exts = set()
for r in raw_rules:
    exts = [e.lower() for e in r.get("extensions", [])]
    allowed_exts.update(exts)
    compiled_rules.append({
        "name": r["name"],
        "extensions": set(exts),
        "regex": re.compile(r["pattern"], re.IGNORECASE | re.DOTALL),
    })

def get_reseller_dirs(reseller_name):
    tuo = "/etc/trueuserowners"
    if not os.path.isfile(tuo):
        sys.stderr.write("[ERR] /etc/trueuserowners not found (cPanel reseller mode unavailable).\n")
        sys.exit(1)
    dirs = []
    with open(tuo, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or ": " not in line:
                continue
            u, owner = line.split(": ", 1)
            if owner.strip() == reseller_name:
                pub = os.path.join("/home", u.strip(), "public_html")
                if os.path.isdir(pub):
                    dirs.append(pub)
    return dirs

if reseller:
    scan_roots = get_reseller_dirs(reseller)
    if not scan_roots:
        sys.stderr.write("[ERR] No public_html directories found for reseller: %s\n" % reseller)
        sys.exit(1)
else:
    abs_target = os.path.abspath(target_dir)
    if not os.path.exists(abs_target):
        sys.stderr.write("[ERR] Target path not found: %s\n" % target_dir)
        sys.exit(1)
    scan_roots = [abs_target]

def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    base_depth = root.rstrip(os.sep).count(os.sep)
    for cur_root, dirs, files in os.walk(root, followlinks=False):
        cur_depth = cur_root.rstrip(os.sep).count(os.sep) - base_depth
        dirs[:] = [
            d for d in dirs
            if d not in OMIT_DIR_NAMES
            and not os.path.islink(os.path.join(cur_root, d))
            and (max_depth == 0 or cur_depth < max_depth)
        ]
        for fn in files:
            full = os.path.join(cur_root, fn)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                continue
            if max_size_bytes > 0 and st.st_size > max_size_bytes:
                continue
            lower_fn = fn.lower()
            _, ext = os.path.splitext(lower_fn)
            if lower_fn == ".htaccess":
                ext = ".htaccess"
            if ext in allowed_exts:
                yield full

files_scanned = 0
findings = []
cleaned_files = []
backup_path = ""
tar_handle = None

def ensure_backup_handle(first_root):
    global tar_handle, backup_path
    if tar_handle is not None or skip_backup or not clean_mode:
        return
    bdir = backup_dir
    if not bdir:
        parts = first_root.split(os.sep)
        if len(parts) >= 3 and parts[1] == "home" and os.path.isdir(os.path.join("/home", parts[2])):
            bdir = os.path.join("/home", parts[2], ".security")
        else:
            bdir = os.path.join(os.getcwd(), ".autoclean-backups")
    os.makedirs(bdir, exist_ok=True)
    ts_slug = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    backup_path = os.path.join(bdir, "autoclean-%s.tar.gz" % ts_slug)
    tar_handle = tarfile.open(backup_path, "w:gz")
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass

for root in scan_roots:
    for fpath in iter_files(root):
        files_scanned += 1
        lower_fn = os.path.basename(fpath).lower()
        _, ext = os.path.splitext(lower_fn)
        if lower_fn == ".htaccess":
            ext = ".htaccess"

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue

        spans = []
        for rule in compiled_rules:
            if ext not in rule["extensions"]:
                continue
            for m in rule["regex"].finditer(content):
                snippet = m.group(0).replace("\n", " ").replace("\r", "")[:120]
                spans.append((m.start(), m.end(), rule["name"], snippet))

        if not spans:
            continue

        # Sort & remove overlapping spans safely
        spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        merged = []
        for s in spans:
            if not merged or s[0] >= merged[-1][1]:
                merged.append(s)

        action_taken = "detected"
        if clean_mode:
            ensure_backup_handle(root)
            if tar_handle is not None:
                try:
                    tar_handle.add(fpath, arcname=fpath.lstrip(os.sep))
                except OSError:
                    pass
            chars = list(content)
            for start, end, _, _ in reversed(merged):
                chars[start:end] = []
            new_content = "".join(chars)
            try:
                with open(fpath, "w", encoding="utf-8") as fh:
                    fh.write(new_content)
                action_taken = "cleaned"
                cleaned_files.append(fpath)
            except OSError:
                action_taken = "clean_failed"

        for start, end, rname, snippet in merged:
            findings.append({
                "file": fpath,
                "rule": rname,
                "start": start,
                "end": end,
                "action": action_taken,
                "snippet": snippet,
            })

if tar_handle is not None:
    tar_handle.close()
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass

infected_files = sorted(set(f["file"] for f in findings))
report = {
    "tool": script_name,
    "version": script_version,
    "timestamp": timestamp_utc,
    "mode": "clean" if clean_mode else "dry-run",
    "rules_loaded": len(compiled_rules),
    "files_scanned": files_scanned,
    "infected_files": len(infected_files),
    "matches_total": len(findings),
    "cleaned_files": len(cleaned_files),
    "backup_archive": backup_path,
    "findings": findings,
}

if fmt == "json":
    print(json.dumps(report, indent=2))
elif fmt == "csv":
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["file", "rule", "start", "end", "action"])
    for f in findings:
        w.writerow([f["file"], f["rule"], f["start"], f["end"], f["action"]])
    sys.stdout.write(buf.getvalue())
else:
    if not quiet:
        print("%s%s%s" % (C_CYN, "=" * 80, C_RST))
        print(" %s%s v%s%s | Mode: %s | Rules: %d | %s" % (
            C_BLD, script_name, script_version, C_RST,
            "CLEAN" if clean_mode else "DRY-RUN",
            len(compiled_rules), timestamp_utc
        ))
        print("%s%s%s" % (C_CYN, "=" * 80, C_RST))
    if not findings:
        print("%s[OK]%s No malware injections detected (%d files scanned)." % (C_GRN, C_RST, files_scanned))
    else:
        for f in findings:
            col = C_GRN if f["action"] == "cleaned" else C_RED
            tag = "[CLEANED]" if f["action"] == "cleaned" else "[INFECTED]"
            print("%s%-10s%s %-36s %s (%d..%d)" % (col, tag, C_RST, f["rule"], f["file"], f["start"], f["end"]))
            if verbose:
                print("           snippet: %s" % f["snippet"])
    if not quiet:
        print("")
        print("Summary: %d scanned | %d infected file(s) | %d match(es) | %d cleaned" % (
            files_scanned, len(infected_files), len(findings), len(cleaned_files)
        ))
        if backup_path:
            print("Backup : %s (chmod 600)" % backup_path)

if exit_code_mode and len(findings) > 0:
    sys.exit(2)
sys.exit(0)
PYEOF
}

main "$@"
