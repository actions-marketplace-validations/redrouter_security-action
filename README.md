# Scoped security scans on every pull request.

Runs a pinned open-source scanning engine on your runner with your RedRouter key. Scope is checked before the run and sent to the agent as instructions.

Save `.github/scope.yaml`, replacing `acme/shop` and exclusions with your authorized targets. No secrets or account details. Merge scope to the PR's base branch before the first scan: PR scans read that commit's scope.

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

`status`: `draft|active|revoked`; only active runs. Target `type`: `repository|url|domain|ip|cidr`; exclusions also accept `text` (instructions only). Limits accept only the four keys shown: positive numbers, with integer concurrency and turns. Budget/turn inputs cannot raise scope limits.

Add repository secret `REDROUTER_API_KEY` in Settings > Secrets and variables > Actions. Save `.github/workflows/security.yml`:

Replace the example Node install/start commands below with your app's commands.
Start in the background on `0.0.0.0:8080`, then wait for readiness before the Action.

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
          curl --fail --retry 30 --retry-all-errors --retry-delay 1 --max-time 2 http://localhost:8080
      - uses: redrouter/security-action@v0
        with:
          api-key: ${{ secrets.REDROUTER_API_KEY }}
          model: red-cyber-1
          targets: "./,http://localhost:8080"
```

Requires Docker and Go 1.24+; use disposable checkouts.

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

Preflight checks scope, status, window, targets, exclusions, API-spec servers and catalog prices. Rate/concurrency limits are instructions. Budget wind-down at 90% is marked incomplete. Public comments/Slack omit details; see SARIF and seven-day artifacts. SARIF requires code scanning; upload failures are non-fatal.

Outputs: `exit-code` (0 completed/skipped/dry-run, 1 error/refusal, 2 findings), `skipped`, `refusal`, `sarif-path`, `findings-high`, `findings-total`, `estimated-spend-usd`.

Dry runs redact secrets. Dependencies: `uv==0.12.18`, `PyYAML==6.0.3`.

Tested 2026-11-15 on GitHub-hosted `ubuntu-latest`: Strix 1.7.1, `red-cyber-1`; comment, summary and artifact delivered; private-repository SARIF refused without code security.

## Egress guard

Opt-in `egress-guard: on` enforces sandbox network scope; startup/unsupported scopes fail closed. Requires Docker 28+. HTTPS path scopes are refused. Runner processes, model requests and clones are outside this boundary. Interception-proxy tools, raw sockets, nmap, sudo and package installs are unavailable. Decisions: artifact `egress-guard.jsonl`.

Guard tested 2026-11-15 with local mocks: Docker Desktop/macOS (4.92.0, Engine 29.8.0, arm64) and GitHub-hosted Ubuntu 26.04/Docker 29.4.2 (amd64).

## Privacy

RedRouter never clones your repository. The engine sends code snippets and tool output to the model. New API keys store no request content by default. Account-wide Zero Data Retention is included with Business.

## Funded first run

The free trial is five generations, which is not enough for a scan. Early users can get credit for a first run: contact support@redrouter.org.

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

Default: localhost, Docker-free; run on 2026-11-15. Real modes may download dependencies.
