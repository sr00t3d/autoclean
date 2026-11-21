🇺🇸 **English** | [🇧🇷 Português (BR)](README-ptbr.md) | [🇪🇸 Español](README-es.md)

# autoclean — Web Malware Injection Scanner & Safe Cleaner CLI

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)](https://github.com/sr00t3d/autoclean/releases)
[![Bash](https://img.shields.io/badge/Linux%20%2F%20macOS-Bash%204.0%2B-4EAA25?logo=gnu-bash&logoColor=white)](autoclean.sh)

**`autoclean.sh`** is a lightweight, offline-first Bash CLI for detecting and surgically removing common web malware injections from PHP, HTML, JavaScript, and `.htaccess` files — with **dry-run mode by default**, automatic **`chmod 600` `.tar.gz` backups** before any modification, optional cPanel reseller scanning, custom JSON regex rules, and structured `table`, `json`, and `csv` outputs.

> **Historical Inspiration:** Clean-room Bash + Python 3 stdlib reimplementation inspired by `autoclean 1.2` (2011, **Patrick Harrison** / HostGator Security). Removes all defunct Python 2.6/RPM installers, XML-RPC servers, and internal telemetry endpoints while preserving the safe surgical backup-and-clean workflow.

---

## Features

- **Safe by Default (Dry-Run):** Never modifies files unless `-c` / `--clean` is explicitly passed.
- **Automatic `chmod 600` `.tar.gz` Backup:** Archives original infected files before removing matched spans (`~/.security/autoclean-<timestamp>.tar.gz` on cPanel accounts or `--backup-dir <path>`).
- **8 High-Precision Built-in Offline Signatures:**
  - `php_eval_base64_injection` & `php_eval_base64_inline` (`eval`/`assert` + `base64_decode`/`gzinflate`/`str_rot13`)
  - `php_globals_obfuscated_header` (single-line `$GLOBALS['_...'] = Array(...)` header injections)
  - `php_request_backdoor_eval` (`@eval($_POST|$_GET|$_COOKIE|$_REQUEST[...])`)
  - `php_preg_replace_e_rce` (`preg_replace('/.../e', ...)`)
  - `js_obfuscated_fromcharcode_eval` (`eval(String.fromCharCode(...))`)
  - `html_hidden_external_iframe` (hidden external `<iframe>` injections)
  - `htaccess_malicious_search_redirect` (search-engine referer hijacking rules)
- **Custom Rules (`--rules-file`):** Load your own JSON signature packs (see `rules.example.json`).
- **Symlink & System Directory Guard:** Never follows symlinks; skips `.git`, `.cpanel`, `.security`, `virtfs`, `mail`, `node_modules`, and `.cagefs`.
- **cPanel Reseller Support (`-r <reseller>`):** Scans `/home/<user>/public_html` across all accounts listed in `/etc/trueuserowners`.
- **NOC / CI Automation:** `--exit-code` (exits `2` when infections are found) and `-o table|json|csv`.

---

## Direct Execution (Linux / macOS)

```bash
# Dry-run scan of a directory (no clone required)
bash <(curl -fsSL https://raw.githubusercontent.com/sr00t3d/autoclean/main/autoclean.sh) -d /var/www/html --exit-code
```

---

## Installation & Usage

```bash
git clone https://github.com/sr00t3d/autoclean.git
cd autoclean
chmod +x autoclean.sh

# Dry-run scan (read-only)
./autoclean.sh -d /home/user/public_html

# Clean matched injections with automatic chmod 600 tar.gz backup
./autoclean.sh -d /home/user/public_html --clean

# JSON report + exit code 2 if infected
./autoclean.sh -d /var/www/html -o json --exit-code

# Scan all cPanel accounts owned by a reseller
./autoclean.sh -r myreseller --exit-code

# Use custom regex rules
./autoclean.sh -d /var/www/html --rules-file ./rules.example.json
```

---

## Real Output Example

### Dry-Run Scan (`./autoclean.sh -d /tmp/site --exit-code`)

```text
================================================================================
 autoclean.sh v2.0.0 | Mode: DRY-RUN | Rules: 8 | 2026-11-21T06:24:35Z
================================================================================
[INFECTED] html_hidden_external_iframe          /tmp/site/footer.html (21..86)
[INFECTED] php_eval_base64_injection            /tmp/site/index.php (0..105)

Summary: 3 scanned | 2 infected file(s) | 2 match(es) | 0 cleaned
# Exit code: 2
```

### Safe Surgical Clean (`./autoclean.sh -d /tmp/site --clean --backup-dir /tmp/backups`)

```text
================================================================================
 autoclean.sh v2.0.0 | Mode: CLEAN | Rules: 8 | 2026-11-21T06:24:35Z
================================================================================
[CLEANED]  html_hidden_external_iframe          /tmp/site/footer.html (21..86)
[CLEANED]  php_eval_base64_injection            /tmp/site/index.php (0..105)

Summary: 3 scanned | 2 infected file(s) | 2 match(es) | 2 cleaned
Backup : /tmp/backups/autoclean-20261121_062436.tar.gz (chmod 600)
```

---

## Author & License

Developed by **Percio Castelo** ([perciocastelo.com.br](https://perciocastelo.com.br)).
Inspired by `autoclean 1.2` (2011, **Patrick Harrison** / HostGator Security).

Licensed under the [Apache License 2.0](LICENSE).
