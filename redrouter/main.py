"""Composite Action entry point: preflight, engine, summary, deliveries, exit."""
from __future__ import annotations

import argparse
import base64
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid
from types import SimpleNamespace

from . import catalog, egress, github, results
from .http import request
from .scope import Refusal, check_targets, parse_scope
from .strix import PIN, Strix


def input_value(name, default=""):
    return os.environ.get("INPUT_" + name.upper().replace("-", "_"), default).strip()


def boolean(name, default):
    value = input_value(name, default)
    if value not in ("true", "false"):
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def configuration(repository):
    guard = input_value("egress-guard", "off")
    if guard not in ("on", "off"):
        raise ValueError("egress-guard must be on or off")
    budget = float(input_value("max-budget", "3"))
    turns = int(input_value("max-turns", "150"))
    if not math.isfinite(budget) or budget <= 0 or turns <= 0:
        raise ValueError("Budget and turns must be positive and finite")
    c = SimpleNamespace(
        api_key=input_value("api-key"), model=input_value("model"),
        scope=input_value("scope", ".github/scope.yaml"),
        targets=[t.strip() for t in re.split(r"[,\n]", input_value("targets", "./")) if t.strip()],
        api_base=input_value("api-base", "https://redrouter.org/v1"),
        scan_mode=input_value("scan-mode", "quick"), scope_mode=input_value("scope-mode", "auto"), fail_on=input_value("fail-on", "high"),
        budget=budget, turns=turns, engine=input_value("engine", "strix"),
        engine_ref=input_value("engine-ref", PIN), upload_sarif=input_value("upload-sarif", "auto"),
        comment=boolean("comment", "true"), dry_run=boolean("dry-run", "false"),
        egress_guard=guard == "on",
        slack=os.environ.get("REDROUTER_SLACK_WEBHOOK_URL", input_value("slack-webhook")),
        workspace=Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve(),
        repository=repository or os.environ.get("GITHUB_REPOSITORY", os.environ.get("REDROUTER_REPOSITORY", "")),
    )
    if not c.api_key or not c.model:
        raise ValueError("api-key and model are required")
    if c.scan_mode not in ("quick", "standard", "deep") or c.fail_on not in ("critical", "high", "medium", "low", "info"):
        raise ValueError("Invalid scan-mode or fail-on")
    if c.scope_mode not in ("auto", "diff", "full"):
        raise ValueError("scope-mode must be auto, diff or full")
    if c.engine != "strix" or c.upload_sarif not in ("auto", "true", "false"):
        raise ValueError("Unsupported engine or upload-sarif value")
    return c


def committed_scope(config, event):
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        # Resolve against the Git tree, never the head's files or symlinks.
        try:
            relative = (config.workspace / config.scope).relative_to(config.workspace)
            if not relative.parts or ".." in relative.parts:
                raise ValueError("Scope must be inside the workspace")
            sha = event["pull_request"]["base"]["sha"]
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                raise ValueError("Invalid base commit")
            git = {"cwd": config.workspace, "capture_output": True, "check": True, "timeout": 120}
            try:
                subprocess.run(["git", "cat-file", "-e", sha + "^{commit}"], **git)
            except subprocess.CalledProcessError:
                shallow = subprocess.run(["git", "rev-parse", "--is-shallow-repository"], **git).stdout.strip()
                if shallow != b"true":
                    raise
                env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
                token = os.environ.get("GITHUB_TOKEN")
                if token:
                    # checkout may disable persisted credentials; keep the token out of argv.
                    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
                    auth = base64.b64encode(("x-access-token:" + token).encode()).decode()
                    env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0=f"http.{server}/.extraheader",
                               GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + auth)
                subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", sha], env=env, **git)
            return subprocess.run(["git", "show", sha + ":" + relative.as_posix()], **git).stdout
        except (KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
            raise Refusal("scope-missing", "The scope file must be merged to the base branch first.") from exc
    path = (config.workspace / config.scope).resolve()
    try:
        relative = path.relative_to(config.workspace)
        committed = subprocess.run(["git", "show", "HEAD:" + relative.as_posix()], cwd=config.workspace, capture_output=True, check=True).stdout
        if path.read_bytes() != committed:
            raise ValueError("Scope differs from HEAD")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise Refusal("scope-missing", "Commit the scope file inside this workspace; its contents must match HEAD.") from exc
    return committed


def notice(message):
    print("::notice::" + message.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D"), flush=True)


def best_effort(label, operation):
    try:
        return operation()
    except Exception:
        # HTTP error bodies and URLs can contain secrets.
        notice(f"{label} unavailable; check service access and permissions. Engine exit code is unchanged.")


def main(argv=None):
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    result = results.Result()
    config = engine = work = None
    event = {}
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default="")
    args = parser.parse_args(argv)
    try:
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        event = json.loads(Path(event_path).read_text()) if event_path else {}
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        if event_name == "pull_request_target":
            raise ValueError("Use the pull_request event")
        if event_name == "pull_request":
            pr = event["pull_request"]
            head_repo = pr.get("head", {}).get("repo") or {}
            base_repo = pr.get("base", {}).get("repo") or {}
            identity = os.environ.get("GITHUB_REPOSITORY", "")
            if not head_repo.get("full_name") or head_repo["full_name"].lower() != identity.lower() or (os.environ.get("GITHUB_ACTOR") == "dependabot[bot]" and not input_value("api-key")):
                result.exit_code, result.skipped = 0, True
                notice(result.status())
                return finish(result, None, event, None)
            if base_repo.get("full_name", identity).lower() != identity.lower():
                raise ValueError("Pull request repository identity mismatch")
        try:
            config = configuration(args.repository)
        except ValueError as exc:
            result.input_error = True
            result.message = str(exc)
            notice(result.message)
            return finish(result, None, event, None)
        result.fail_on, result.budget, result.dry_run = config.fail_on, config.budget, config.dry_run
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        if config.repository and os.environ.get("GITHUB_RUN_ID"):
            result.run_url = f"{server}/{config.repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        scope = parse_scope(committed_scope(config, event))
        result.scope_name = scope.name
        check_targets(scope, config.targets, config.workspace, config.repository)
        if config.egress_guard:
            egress.check_supported(scope)
            if config.engine_ref != PIN:
                raise egress.GuardError("Egress guard supports only the pinned engine.")
        result.targets = config.targets
        config.budget = min(config.budget, scope.limits["max_budget_usd"])
        config.turns = min(config.turns, scope.limits["max_turns"])
        result.budget = config.budget
        prices = catalog.prices(config.api_base, config.model)
        default_root = Path(os.environ["RUNNER_TEMP"]) / "redrouter-results" if os.environ.get("RUNNER_TEMP") else config.workspace / ".redrouter-results"
        if config.egress_guard and not os.environ.get("RUNNER_TEMP"):
            default_root = Path(tempfile.gettempdir()) / "redrouter-results"
        root = Path(os.environ.get("REDROUTER_RESULTS_DIR", str(default_root))).resolve()
        if config.egress_guard and root.is_relative_to(config.workspace):
            raise egress.GuardError("Egress guard state must be outside the workspace; set REDROUTER_RESULTS_DIR accordingly.")
        work = root / ("run-" + uuid.uuid4().hex) / "artifact"
        work.mkdir(parents=True)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                stream.write(f"artifact-path={work}\n")
        instructions = work / "scope-instructions.txt"
        instructions.write_text(scope.instructions() + (egress.INSTRUCTIONS if config.egress_guard else ""))
        engine = Strix(config, scope, prices, work, instructions)
        if config.egress_guard:
            if engine.stub:
                raise egress.GuardError("Egress guard requires the real engine; use the guarded demo.")
            engine.guard = work.parent / "guard/connection.json"
        command, env = engine.build()
        if config.dry_run:
            if config.egress_guard:
                print("Egress guard not started; the command's manifest will be created before a real run.")
            secret_names = {"LLM_API_KEY"} | {a[k] for a in scope.data.get("test_accounts", []) for k in ("username_env", "password_env")}
            print("Engine working directory: " + str(work))
            print("Engine environment (all entries; secret values redacted):")
            for key, value in sorted(env.items()):
                print(key + "=" + shlex.quote("[REDACTED]" if key in secret_names else value))
            print("Engine command: " + shlex.join(command))
            result.exit_code = 0
        else:
            try:
                engine.install()
                if config.egress_guard:
                    engine.guard = egress.up(scope, work)
                    result.guard = "on"
                result.exit_code = engine.run()
            finally:
                if config.egress_guard and engine.guard.parent.exists():
                    egress.down(engine.guard, work.parent.name, work, result)
                shutil.rmtree(work.parent / "engine-home", ignore_errors=True)
            try:
                result.findings = engine.normalize(engine.locate_results())
                result.complete = result.findings.sarif is not None
            except Exception:
                result.exit_code = 1
                result.message = "Engine results could not be read; counts are unavailable. See the run artifact."
                notice(result.message)
            if not result.complete:
                result.incomplete = result.exit_code == 0
                result.exit_code = 1
                if not result.message:
                    result.message = "Engine returned no SARIF; counts are unavailable. See the run artifact."
            elif result.exit_code in (0, 2) and (result.findings.partial or result.budget_reached()):
                # Wind-down or hard stop at the cap: counts stay visible, but a clean exit must not read as a pass.
                result.early_stop = True
                result.exit_code = max(result.exit_code, 1)
            elif result.exit_code in (0, 2) and not result.findings.finished:
                result.incomplete = True
                result.exit_code = 1
            if result.guard_ended:
                result.incomplete, result.exit_code = True, 1
    except Refusal as exc:
        result.refusal, result.message, result.exit_code = exc.code, str(exc), 1
        notice(f"{exc.code}: {exc}")
    except egress.GuardError as exc:
        result.exit_code, result.not_started = 1, True
        result.message = str(exc) + " No model request was made."
        notice(result.message)
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        result.exit_code, result.incomplete = 1, True
        result.message = "Scan interrupted or timed out."
        notice(result.message)
    except Exception:
        result.exit_code = 1
        result.message = "Check inputs and the engine log."
        notice(result.message)
    return finish(result, config, event, work)


def finish(result, config, event, work):
    # Summary precedes all network deliveries, even if the engine failed.
    summary = results.summary(result)
    if work:
        (work / "summary.md").write_text(summary)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as stream:
            stream.write(summary)
    else:
        print(summary)
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a") as stream:
            for key, value in result.outputs().items():
                stream.write(f"{key}={value}\n")
            # Internal output for the composite's artifact step.
            stream.write(f"artifact-path={work or ''}\n")
    if config and not result.skipped and not config.dry_run:
        if config.comment and event.get("pull_request") and os.environ.get("GITHUB_TOKEN"):
            best_effort("PR comment", lambda: github.sticky_comment(event.get("number", event["pull_request"].get("number")), results.comment(result)))
        if config.upload_sarif != "false" and result.findings.sarif and os.environ.get("GITHUB_TOKEN"):
            upload_notice = best_effort("SARIF upload", lambda: github.upload_sarif(result.findings.sarif))
            if upload_notice:
                notice(upload_notice)
                for path in ([work / "summary.md"] if work else []) + ([Path(summary_path)] if summary_path else []):
                    with path.open("a") as stream:
                        stream.write("\n" + upload_notice + "\n")
        if config.slack:
            best_effort("Slack delivery", lambda: request(config.slack, "POST", results.slack(result)))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
