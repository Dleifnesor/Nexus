# Nexus

AI-assisted autonomous vulnerability scanning and remediation tool for Enterprise environments.

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
- **Reporting** — NVD + OSV enrichment, LLM remediations, HTML/PDF/JSON — `nexus/report/`,
  `nexus/enrich/`
- **UX** — live TUI dashboard, optional local web dashboard — `nexus/ui/`

## Install

```bash
git clone <repo> && cd nexus
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
| `--llm-provider` / `--model` / `--llm-base-url` | LLM backend |
| `--max-time` / `--max-tokens` / `--max-actions` | Budgets (stop criteria) |
| `--convergence-iters` | Idle iterations before a phase converges |
| `--resume <id>` | Resume from last checkpoint |
| `--web` / `--no-tui` | Interface options |
| `--check` | Run prerequisite checks and exit |

### Environment variables

- `NEXUS_LLM_API_KEY`, `NEXUS_LLM_BASE_URL` — cloud LLM credentials/endpoint
- `NEXUS_NVD_API_KEY` — higher NVD rate limits
- `NEXUS_HIBP_API_KEY` — enable HaveIBeenPwned breach lookups

## Output

Reports are written to `nexus-out/reports/` as HTML, PDF (if WeasyPrint is installed), and JSON.
Runtime state, findings, and checkpoints live in `nexus-out/data/nexus.db` (SQLite).

## Development

```bash
pip install -e ".[dev]"
pytest
```
