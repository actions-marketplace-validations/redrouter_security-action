# Scoped security scans on every pull request.

Runs a pinned open-source engine on your runner with your RedRouter key. Scope is checked before scanning and sent as instructions.

Save `.github/scope.yaml` with authorized targets and exclusions; no secrets. Merge it to the PR's base branch before the first scan: PR scans read that commit's scope.

```yaml
schema: redrouter.scope/v1
status: active
engagement:
  name: "Shop CI"
  type: own-app-ci
in_scope:
  - type: repository
    value: "acme/shop"
  - type: url
    value: "http://localhost:8080"
out_of_scope:
  - type: domain
    value: "*.acme.com"
    note: "Production"
  - type: text
    value: "Third-party services the app calls (payments, email, identity providers)"
  - type: text
    value: "URLs found in source, config or responses that are not listed in scope"
techniques:
  prohibited:
    - denial-of-service
    - data-alteration
    - social-engineering
    - pivoting
limits:
  requests_per_second: 10
  concurrency: 5
  max_budget_usd: 3
  max_turns: 150
```

`status`: `draft|active|revoked`; only active runs. Target `type`: `repository|url|domain|ip|cidr`; exclusions also accept `text` (instructions only). Limits: four keys shown, positive numbers, integer concurrency/turns. Inputs cannot raise scope limits.

Add repository secret `REDROUTER_API_KEY` in Settings > Secrets and variables > Actions. Save `.github/workflows/security.yml`:

Replace the Node commands and use an existing readiness path.
Start on `0.0.0.0:8080` in the background; wait for readiness before scanning.

```yaml
name: Security
on: [pull_request]
permissions: {security-events: write, actions: read, pull-requests: write, contents: read}
concurrency: {group: 'security-${{ github.event.pull_request.number }}', cancel-in-progress: true}
jobs:
  scan:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v4
        with: {fetch-depth: 0, persist-credentials: false}
      - name: Start app
        run: |
          npm ci
          npm start -- --host 0.0.0.0 --port 8080 > "$RUNNER_TEMP/app.log" 2>&1 &
          curl -sS -o /dev/null --retry 30 --retry-all-errors --retry-delay 1 --max-time 2 http://localhost:8080
      - uses: redrouter/security-action@v0
        with:
          api-key: ${{ secrets.REDROUTER_API_KEY }}
          model: red-cyber-1
          targets: "./,http://localhost:8080"
```

Requires Docker, Go 1.24+ and disposable checkouts.

Set test-account variables as `env` on the Action step from repository secrets; scope holds variable names only.

| Input | Default / choices |
| --- | --- |
| `api-key` | Required secret |
| `model` | Required; no default |
| `scope` | `.github/scope.yaml` |
| `targets` | `./`; newline or comma separated |
| `api-base` | `https://redrouter.org/v1` |
| `scan-mode` | `quick`; `standard`, `deep` |
| `scope-mode` | `auto`; `diff`, `full` (whole repository) |
| `fail-on` | `high`; `critical`, `medium`, `low`, `info` |
| `max-budget` | `3` USD |
| `max-turns` | `150` per agent |
| `engine` | `strix` |
| `engine-ref` | `685bbc8138d35fc9fe378ac37ec0d9198b9c46a3` |
| `egress-guard` | `off`; `on` (experimental) |
| `upload-sarif` | `auto`; `true`, `false`; never fatal |
| `comment` | `true` |
| `slack-webhook` | None |
| `dry-run` | `false` |

Preflight checks scope, exclusions, API-spec servers and prices. Rate/concurrency limits are instructions. Public comments/Slack omit details; artifacts expire after seven days.

Outputs: `exit-code` (0 completed/skipped/dry-run, 1 error/refusal, 2 findings), `skipped`, `refusal`, `sarif-path`, `findings-high`, `findings-total`, `estimated-spend-usd`.

2026-11-15, GitHub-hosted `ubuntu-latest`, Strix 1.7.1, `red-cyber-1`: private repository, code only, $0.83 of $0.90, about 13 minutes; repository plus a web app started on the runner, $0.97 of $1.00, about 13 minutes, workflow written by a coding agent from the setup prompt, budget cap lowered by hand to $1.
Both reached budget-cap wind-down; no findings at or above high, both incomplete.
Mock-model tests verified fail-on-high exit 2 and the egress guard.

SARIF uploads were refused on private repositories without code scanning; the self-test uploads once public. Upload failures are non-fatal.

## Egress guard

Opt-in `egress-guard: on` enforces sandbox network scope; startup/unsupported scopes fail closed. Requires Docker 28+. HTTPS path scopes are refused. Runner processes, model requests and clones are outside this boundary. Interception-proxy tools, raw sockets, nmap, sudo and package installs are unavailable. Decisions: artifact `egress-guard.jsonl`.

Guard mock-tested 2026-11-15: macOS/arm64 (Docker 29.8.0) and hosted Ubuntu 26.04/amd64 (Docker 29.4.2).

## Privacy

RedRouter never clones your repository. The engine sends code snippets and tool output to the model. New API keys store no request content by default. Account-wide Zero Data Retention is included with Business.

## Funded first run

Five free generations cannot fund a scan. For first-run credit, contact support@redrouter.org.

## Third-party engine

Pinned Strix 1.7.1 and sandbox, Apache-2.0: [NOTICE](NOTICE). `STRIX_TELEMETRY=false`; OpenAI tracing disabled. Spend: `run.json`'s `llm_usage.cost`. Authenticated scans are unverified.

## Local demo

```sh
uv venv --python 3.12
uv pip install PyYAML==6.0.3
./demo.sh
.venv/bin/python -m unittest -v
./demo.sh --real-engine
./demo.sh --guard
```

Default demo: localhost, Docker-free. Real modes download dependencies.
