[🇺🇸 English](README.md) | 🇧🇷 **Português (BR)** | [🇪🇸 Español](README-es.md)

# autoclean — Scanner e Limpador Seguro de Injeções de Malware Web

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)](https://github.com/sr00t3d/autoclean/releases)
[![Bash](https://img.shields.io/badge/Linux%20%2F%20macOS-Bash%204.0%2B-4EAA25?logo=gnu-bash&logoColor=white)](autoclean.sh)

O **`autoclean.sh`** é uma CLI leve e offline em Bash para detectar e remover cirurgicamente injeções clássicas de malware em arquivos PHP, HTML, JavaScript e `.htaccess` — com **modo dry-run por padrão**, **backup automático `.tar.gz` (`chmod 600`)** antes de qualquer alteração, suporte opcional a revendas cPanel, regras regex customizadas em JSON e saídas `table`, `json` e `csv`.

> **Inspiração Histórica:** Reimplementação limpa em Bash + Python 3 stdlib inspirada no `autoclean 1.2` (2011, **Patrick Harrison** / HostGator Security). Remove instaladores obsoletos de Python 2.6/RPM, XML-RPC e telemetria interna extinta, preservando o fluxo seguro de backup e limpeza cirúrgica.

---

## Funcionalidades

- **Seguro por Padrão (Dry-Run):** Nunca modifica arquivos sem a flag explícita `-c` / `--clean`.
- **Backup Automático `chmod 600` (`.tar.gz`):** Arquiva os arquivos originais antes de remover os trechos maliciosos (`~/.security/autoclean-<timestamp>.tar.gz` em contas cPanel ou `--backup-dir <caminho>`).
- **8 Assinaturas Offline de Alta Precisão:** PHP `eval`/`assert` + `base64_decode`/`gzinflate`/`str_rot13`, injeções de cabeçalho `$GLOBALS`, backdoors `$_POST`/`$_COOKIE`/`$_REQUEST`, `preg_replace('/.../e')`, JS `String.fromCharCode`, `<iframe>` oculto externo e redirecionamentos maliciosos em `.htaccess`.
- **Regras Customizadas (`--rules-file`):** Carregue suas próprias assinaturas regex em JSON (veja `rules.example.json`).
- **Proteção contra Symlinks e Diretórios de Sistema:** Nunca segue symlinks e ignora `.git`, `.cpanel`, `.security`, `virtfs`, `mail`, `node_modules` e `.cagefs`.
- **Modo Revenda cPanel (`-r <reseller>`):** Varre `/home/<user>/public_html` de todas as contas em `/etc/trueuserowners`.
- **Pronto para SOC / Cron:** `--exit-code` (retorna código `2` quando encontra infecções) e `-o table|json|csv`.

---

## Execução Direta (Linux / macOS)

```bash
# Varredura dry-run sem clonar o repositório
bash <(curl -fsSL https://raw.githubusercontent.com/sr00t3d/autoclean/main/autoclean.sh) -d /var/www/html --exit-code
```

---

## Instalação e Uso

```bash
git clone https://github.com/sr00t3d/autoclean.git
cd autoclean
chmod +x autoclean.sh

# Varredura segura (dry-run)
./autoclean.sh -d /home/usuario/public_html

# Limpeza cirúrgica com backup automático .tar.gz chmod 600
./autoclean.sh -d /home/usuario/public_html --clean

# Relatório JSON + exit code 2 se infectado
./autoclean.sh -d /var/www/html -o json --exit-code

# Varrer todas as contas de uma revenda cPanel
./autoclean.sh -r minharevenda --exit-code
```

---

## Exemplo Real de Saída

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

## Autor & Licença

Desenvolvido por **Percio Castelo** ([perciocastelo.com.br](https://perciocastelo.com.br)).
Inspirado no `autoclean 1.2` (2011, **Patrick Harrison** / HostGator Security).

Licenciado sob a [Apache License 2.0](LICENSE).
