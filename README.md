# Scoped security scans on every pull request.

Runs a pinned open-source scanning engine on your runner with your RedRouter key. Scope is checked before the run and sent to the agent as instructions.

Build `.github/scope.yaml` at [redrouter.org/scope](https://redrouter.org/scope), merge it to the base branch, add the `REDROUTER_API_KEY` repository secret, and save this workflow as `.github/workflows/security.yml` with your catalog model. Open a PR; read its comment.

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
      - uses: redrouter/security-action@main
        with:
          api-key: ${{ secrets.REDROUTER_API_KEY }}
          model: YOUR_CATALOG_MODEL_ID
```

Use `@main` for private testing; `@v0` is reserved for release. Use `pull_request`, never `pull_request_target`. Requires Docker and Go 1.24+. Use disposable checkouts.

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

Preflight checks committed scope, schema, status, window, targets, exclusions, API-spec servers and catalog prices before inference. Budget and turns use the lower scope/input limit. Budget is estimated; rate/concurrency limits are instructions.

PR scans read scope from the exact base commit; other events use the checked-out commit.

Public comments and Slack omit finding details. Details: SARIF and seven-day artifacts. Budget wind-down at 90% is marked incomplete without changing the engine exit code. Missing/error reports exit 1. SARIF needs `security-events: write` and code scanning enabled; upload failures are non-fatal.

Outputs: `exit-code` (0 completed/skipped/dry-run, 1 error/refusal, 2 findings), `skipped`, `refusal`, `sarif-path`, `findings-high`, `findings-total`, `estimated-spend-usd`. Check status before counts.

Dry runs print commands with secrets redacted. A temporary venv supplies `uv==0.12.18` and `PyYAML==6.0.3`.

Tested 2026-11-15 on GitHub-hosted `ubuntu-latest`: Strix 1.7.1, `red-cyber-1`; comment, summary and artifact delivered; private-repository SARIF refused without code security.

## Egress guard

Opt-in `egress-guard: on` enforces sandbox network scope through an HTTP/HTTPS/DNS proxy; startup or unsupported scopes fail closed. Requires Docker Engine 28+. HTTPS path scopes are refused. The runner process, model requests and clones are outside this boundary. Interception-proxy tools, raw sockets, nmap, sudo and package installs are unavailable. Linux targets need a `0.0.0.0` bind or published port; the sandbox uses `host.docker.internal`. Decisions: artifact `egress-guard.jsonl`.

Guard tested 2026-11-15 with local mocks: Docker Desktop/macOS (4.92.0, Engine 29.8.0, arm64) and GitHub-hosted Ubuntu 26.04/Docker 29.4.2 (amd64).

## Privacy

RedRouter never clones your repository. The engine sends code snippets and tool output to the model. New API keys store no request content by default. Account-wide Zero Data Retention is included with Business.

## Funded first run

The free trial is five generations, which is not enough for a scan. Early users can get credit for a first run: contact support@redrouter.org.

## Third-party engine

Pinned Strix 1.7.1 and sandbox, Apache-2.0: [NOTICE](NOTICE). `STRIX_TELEMETRY=false`; OpenAI tracing disabled. Spend: `run.json`'s `llm_usage.cost` ([source](https://github.com/usestrix/strix/blob/685bbc8138d35fc9fe378ac37ec0d9198b9c46a3/strix/report/state.py#L947-L951)). Test-account variables reach only the engine process; authenticated scans are unverified.

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
