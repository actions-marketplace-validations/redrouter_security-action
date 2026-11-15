"""Run the complete local demo; default mode makes only localhost requests."""
import argparse
from pathlib import Path
import shutil
import sys

from redrouter.scope import CODES
from redrouter.results import MARKER
from .cases import ROOT, invoke, prepare
from .mock import server


def run_case(destination, case, real=False):
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    with server(destination) as mock:
        if case == "valid-own-app" and not real:
            mock.comments.append({"id": 1, "body": MARKER + "\nPrevious local run.", "user": {"type": "Bot"}})
        env = prepare(destination, mock.origin, case, real=real)
        result, outputs = invoke(env, destination, timeout=600 if real else 60)
        calls = sum(r["path"] == "/v1/chat/completions" for r in mock.requests)
        if case in CODES:
            assert result.returncode == 1, result.stdout + result.stderr
            assert outputs["refusal"] == case, outputs
            assert calls == 0, "A refusal made a model request"
        else:
            assert result.returncode == (0 if real else 2), result.stdout + result.stderr
            assert calls > 0, "Engine did not reach the local mock"
            assert len(mock.comments) == 1, "Expected one sticky PR comment"
            assert (destination / "findings.sarif").is_file(), "Engine returned no SARIF"
        (destination / "proof.json").write_text(__import__("json").dumps({"exit_code": result.returncode, "refusal": outputs["refusal"], "model_requests": calls, "engine": "pinned-real" if real else "scripted"}, indent=2) + "\n")
    return calls


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--real-engine", action="store_true", help="Run pinned engine and Docker against localhost; may fetch pinned dependencies")
    modes.add_argument("--guard", action="store_true", help="Run pinned engine through the guard against isolated local stand-ins")
    args = parser.parse_args()
    base = ROOT / "demo-out"
    if args.guard:
        from .guarded import run
        return run(base / "guard")
    if args.real_engine:
        calls = run_case(base / "real-engine", "valid-own-app", real=True)
        print(f"demo-out/real-engine/: real pinned engine, {calls} local model requests; scripted final report, no autonomous assessment.")
        return 0
    run_case(base / "happy", "valid-own-app")
    for code in CODES:
        run_case(base / "refusals" / code, code)
    print("demo-out/happy/: summary.md, pr-comment.md, findings.sarif, slack.json, outputs.txt")
    print("demo-out/refusals/<code>/: 8 summaries, outputs, requests.jsonl and proof.json (zero model requests each)")
    print("Scripted demo only; no paid API requests. All local servers stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
