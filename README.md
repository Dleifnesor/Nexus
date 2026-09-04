# Nexus

AI-assisted autonomous vulnerability and remediation scanner for Kali/Parrot Linux.

Install Nexus on a Kali box inside a company network. It autonomously performs reconnaissance,
enumeration, vulnerability discovery, validation, and OSINT (including breach-data lookups and
browser-driven collection), then produces a CVE-enriched report with AI-generated remediations.
It self-heals on errors, can install any tool it needs (isolated in Docker), and stops when it
converges or hits a budget.

## Legal / safety notice

Only run Nexus against systems you are explicitly authorized to test.

- `--scope` mode enforces boundaries: it refuses to act against out-of-scope targets, and
  breach/credential validation is limited to in-scope assets. All security-relevant actions are
  written to an append-only audit log (`nexus-out/logs/audit.log.jsonl`).
- `--sandbox` mode disables scope enforcement and is intended for **isolated, monitored lab
  environments only**. It prints a warning and requires explicit confirmation.

## Architecture

- **Modes** (`--scope` / `--sandbox`) — `nexus/config.py`, `nexus/scope/scope.py`
- **AI brain** — local Ollama by default, optional OpenAI/Anthropic — `nexus/llm/`
- **Phased engine** (state machine + LLM planner) — `nexus/engine/`
- **Tools** — built-in tools run on host; discovered/non-built-in tools run in ephemeral
  Docker containers; tool discovery via web search — `nexus/tools/`
- **OSINT** — Playwright browser + breach APIs (mode-gated) — `nexus/osint/`
- **Resilience** — timeouts/retries/backoff, SQLite checkpoints (`--resume`), LLM-driven
  recovery, coverage-gap logging — `nexus/engine/`, `nexus/storage/db.py`
- **Reporting** — NVD (CPE + keyword) + OSV + CISA KEV + EPSS + Exploit-DB + GitHub PoC +
  Vulners + GreyNoise/Shodan exposure enrichment, LLM remediations, risk scoring, MITRE
  ATT&CK mapping, attack-path graphs, and delta/diff reports — HTML/PDF/JSON/SARIF —
  `nexus/report/`, `nexus/enrich/`
- **UX** — live TUI dashboard, optional local web dashboard — `nexus/ui/`

## Install

```bash
git clone https://github.com/Dleifnesor/Nexus && cd Nexus
./scripts/install.sh
```

Or manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[pdf,web]"
python -m playwright install chromium
```

## Usage

```bash
# Prerequisite check
nexus --scope --check

# Authorized engagement (interactive scope prompt)
nexus --scope

# Non-interactive scope
nexus --scope --scope-entry 10.0.0.0/24 --scope-entry example.com

# Isolated lab, unrestricted
nexus --sandbox --scope-entry 10.0.0.0/24 --yes

# Resume an interrupted run
nexus --scope --resume <run_id>

# Enable local web dashboard
nexus --scope --web
```

### Key flags

| Flag | Purpose |
|------|---------|
| `--scope` / `--sandbox` | Operation mode (one required) |
| `--scope-entry` / `--scope-file` | Provide scope non-interactively |
| `--scope-exclude` | Exclude an IP/CIDR/domain from scope (repeatable) |
| `--docker-network` | Docker network for containerized tools |
| `--no-docker` | Run all tools natively on the host (auto-install missing built-in tools) |
| `--no-tool-search` | Disable automatic discovery/installation of new tools via web search (on by default) |
| `--rate-limit-ms` | Minimum ms between tool actions (pacing) |
| `--max-concurrent` | Parallel tool actions per iteration (default 1) |
| `--diff <id>` | Render a finding diff against a previous run |
| `--llm-provider` / `--model` / `--llm-base-url` | LLM backend |
| `--max-time` / `--max-tokens` / `--max-actions` | Budgets (stop criteria) |
| `--convergence-iters` | Idle iterations before a phase converges |
| `--resume <id>` | Resume from last checkpoint (budget is restored) |
| `--web` / `--no-tui` | Interface options |
| `--check` | Run prerequisite checks and exit |

### Environment variables

- `NEXUS_LLM_API_KEY`, `NEXUS_LLM_BASE_URL` — cloud LLM credentials/endpoint
- `NEXUS_NVD_API_KEY` — higher NVD rate limits
- `NEXUS_HIBP_API_KEY` — enable HaveIBeenPwned breach lookups
- `NEXUS_SLACK_WEBHOOK` — post a scan summary to Slack on completion
- `NEXUS_WEBHOOK_URL` — POST the summary JSON to any HTTP receiver (Jira/ServiceNow)

### Worked example: assessing an internal subnet + domain

This walks through a full authorized engagement against `10.10.0.0/24` and `acme-corp.local`,
using a local Ollama model and enabling breach lookups.

```bash
# 1. Verify the box is ready (Docker, LLM, tools).
$ nexus --scope --check
Nexus prerequisite checks:
  [OK ] docker: daemon reachable
  [OK ] llm(ollama): reachable; models=['llama3.1:8b']
  [OK ] playwright: installed
  [OK ] tool:nmap: found
  [.. ] tool:theHarvester: missing (will containerize)
  ...

# 2. Enable breach lookups (optional) and set higher NVD rate limits.
$ export NEXUS_HIBP_API_KEY="your-hibp-key"
$ export NEXUS_NVD_API_KEY="your-nvd-key"

# 3. Launch the engagement. Scope is enforced; out-of-scope targets are refused.
#    Bound the run to 2 hours / 300 actions so it stops even if it keeps finding assets.
$ nexus --scope \
    --scope-entry 10.10.0.0/24 \
    --scope-entry acme-corp.local \
    --model llama3.1:8b \
    --max-time 7200 \
    --max-actions 300 \
    --web
```

While it runs, the live TUI shows the current phase and counts:

```
+-- Status ---------------------------+
|   Phase   active_recon              |
|   Assets  42                        |
|   Findings 9                        |
|   Actions 27                        |
|   Budget  318.4s / 27 actions / ... |
+-------------------------------------+
+-- Activity --------------------------------------+
| [active_recon] nmap -> 10.10.0.15                |
| [passive_recon] subfinder -> acme-corp.local     |
| [passive_recon] Discovering tool: web dir brute  |
+--------------------------------------------------+
```

The web dashboard (from `--web`) is available at `http://127.0.0.1:8787`.

On completion Nexus prints the run ID and report paths:

```
Run 3f9a2c1b... finished with status: completed
  JSON: /path/to/nexus-out/reports/report-3f9a2c1b....json
  HTML: /path/to/nexus-out/reports/report-3f9a2c1b....html
  SARIF: /path/to/nexus-out/reports/report-3f9a2c1b....sarif
  PDF:  /path/to/nexus-out/reports/report-3f9a2c1b....pdf
  Stats: {'assets': 61, 'findings': 18, 'actions': 143}
```

If the run is interrupted (Ctrl-C, reboot, budget hit mid-phase), resume it from the last
checkpoint using the printed run ID — completed actions are not repeated:

```bash
$ nexus --scope --resume 3f9a2c1b...
```

For a quick isolated-lab smoke test against a deliberately vulnerable VM (no scope
enforcement), use sandbox mode:

```bash
$ nexus --sandbox --scope-entry 10.10.0.50 --yes --max-actions 50
```

## Output

Reports are written to `nexus-out/reports/` as HTML, PDF (if WeasyPrint is installed), JSON,
and SARIF (for DefectDojo/CI/Jira ingestion). Findings include CVE/CVSS, EPSS, CISA KEV
"known exploited" flags, a normalized risk score, and MITRE ATT&CK technique mapping.
Runtime state, findings, and checkpoints live in `nexus-out/data/nexus.db` (SQLite).

## Bundled tools

Nexus ships with parsers and command templates for a broad set of detection tools, run on
host when available or in ephemeral containers otherwise: `nmap`, `nuclei`, `sqlmap`, `ffuf`,
`wpscan`, `nikto`, `whatweb`, `subfinder`, `theHarvester`, `gau`, `crt.sh`, `gitleaks`,
`testssl.sh`, `netexec`, `dalfox`, `trivy`, `grype`, `lynis`, `naabu`, `httpx`, `wafw00f`,
`gowitness`, `puredns`, `dnsx`, `ssh-audit`, `kerbrute`, `hydra`, and `bloodhound-python`.
Missing tools are auto-discovered via web search or containerized with a Kali base image.
Discovered credentials are stored in a per-run credential store and reused by credential-aware
tools in later phases.

### Automatic tool discovery

When the planner needs a capability no registered tool provides, Nexus finds and adds a new
tool on its own:

1. It runs a **browser-driven web search** (headless Chromium via Playwright), extracts the
   top results, and fetches the most relevant pages — preferring GitHub, PyPI, pkg.go.dev,
   and the Kali package site, which usually document the install command.
   (If a browser isn't available it falls back to an HTTP search endpoint.)
2. The LLM reads those results and synthesizes a registry entry — install command, run
   command template, and output parser.
3. The new tool is registered and used in the current and later phases.

Discovery and installation are **enabled by default**; pass `--no-tool-search` to turn the
whole feature off (no web searches, no new tools). Discovered tools run wherever your Docker
setting dictates — in an ephemeral container by default, or natively on the host under
`--no-docker`. Because the install command and invocation are derived from untrusted web
content, the install command is validated against a package-manager allowlist
(`apt`/`pip`/`pipx`/`go`/`cargo`/`gem`/`npm` installs only; anything with shell operators is
rejected), so only a single package install can ever run — never an arbitrary shell command.

### Native (host) execution

By default, missing tools run in ephemeral Docker containers. To run everything directly on the
host with no containerization, pass `--no-docker`; Nexus then installs any missing **built-in**
tool on demand via its hardcoded `install` command (audit-logged) and executes it natively. Tools
that must run on the host (e.g. `gvm`) are always native regardless of this flag.

**Dynamically discovered tools** have their install command synthesized by the LLM from
web-search results, so it is validated against a package-manager allowlist (a single
`apt`/`pip`/`pipx`/`go`/`cargo`/`gem`/`npm` install; no shell operators) before it runs. Under
`--no-docker` they install and run natively like any other tool; otherwise they run in an
ephemeral container. Disable discovery entirely with `--no-tool-search`.

### Greenbone / OpenVAS (GVM)

Nexus can drive Greenbone Vulnerability Manager for authenticated network vulnerability scanning:

```bash
# One-time install + feed setup (idempotent; first run downloads feeds, can take 30+ min)
sudo bash scripts/install_gvm.sh

# Run a scan against a target via gvm-cli (requires a configured GVM)
bash scripts/gvm_scan.sh 10.10.0.10
```

The `gvm` tool (registered natively, `host_only`) launches `gvm-cli` against the local
`/run/gvmd/gvmd.sock` socket; if the `gvm` package is missing, Nexus installs and starts it
automatically.

## Development

```bash
pip install -e ".[dev]"
pytest
```
