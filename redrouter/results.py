"""Render counts only on public surfaces. Detailed findings stay in artifacts."""
from dataclasses import dataclass, field
from decimal import Decimal
import html

from .engine import Findings

MARKER = "<!-- redrouter-security-action -->"


@dataclass
class Result:
    exit_code: int = 1
    skipped: bool = False
    refusal: str = ""
    message: str = ""
    dry_run: bool = False
    input_error: bool = False
    not_started: bool = False
    incomplete: bool = False
    early_stop: bool = False
    scope_name: str = "Not checked"
    targets: list = field(default_factory=list)
    budget: float = 3
    fail_on: str = "high"
    run_url: str = ""
    findings: Findings = field(default_factory=Findings)
    complete: bool = False
    guard: str = "off"
    guard_blocked: int | None = None
    guard_ended: str = ""

    def status(self):
        if self.skipped:
            return "Skipped: pull request secrets are unavailable."
        if self.refusal:
            return f"Refused: {self.refusal}."
        if self.input_error:
            return "Input error: scan did not start."
        if self.not_started:
            return "Error: scan did not start."
        if self.dry_run and self.exit_code == 0:
            return "Dry run: preflight passed; engine not run."
        if self.incomplete:
            return "Incomplete: scan stopped before finishing; results are partial."
        if self.stopped_early():
            reason = "budget cap reached before the scan finished" if self.budget_reached() else "the engine reported partial coverage"
            so_far = (f"Findings so far meet or exceed {self.fail_on}." if self.exit_code == 2
                      else f"No findings at or above {self.fail_on} so far.")
            return f"Incomplete: {reason}. {so_far}"
        if self.exit_code == 1:
            return "Error: scan did not complete."
        if self.exit_code == 2:
            return f"Fail: findings meet or exceed {self.fail_on}."
        return f"Pass: no findings at or above {self.fail_on}."

    def budget_reached(self):
        # The engine winds down at 90% of the cap.
        return (self.findings.estimated_spend != "" and
                Decimal(self.findings.estimated_spend) >= Decimal(str(self.budget)) * Decimal("0.9"))

    def stopped_early(self):
        """The engine exited normally but did not finish the assessment."""
        return report_counts(self) and not self.incomplete and (self.findings.partial or self.budget_reached())

    def outputs(self):
        return {"exit-code": str(self.exit_code), "skipped": str(self.skipped).lower(),
                "refusal": self.refusal, "sarif-path": str(self.findings.sarif or ""),
                "findings-high": str(self.findings.counts["high"]),
                "findings-total": str(sum(self.findings.counts.values())),
                "estimated-spend-usd": self.findings.estimated_spend}


def safe(text):
    return html.escape(str(text)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ").replace("`", "&#96;").replace("[", "&#91;")


def table(result):
    labels = ("critical", "high", "medium", "low", "info", "unknown")
    counts = [str(result.findings.counts[k]) for k in labels]
    return "| " + " | ".join(k.title() for k in labels) + " |\n| " + " | ".join("---:" for _ in labels) + " |\n| " + " | ".join(counts) + " |"


def report_counts(result):
    return result.complete and (result.early_stop or (result.findings.finished and result.exit_code in (0, 2)))


def budget_line(result):
    if result.findings.estimated_spend != "":
        return f"Spent ${Decimal(result.findings.estimated_spend):.2f} of ${result.budget:.2f}."
    return f"Budget cap: ${result.budget:.2f}."


def summary(result):
    if result.refusal:
        return f"**{safe(result.status())}**\n\n{safe(result.message)} No model request was made.\n"
    lines = [f"**{safe(result.status())}**", ""]
    if result.message:
        lines += [safe(result.message), ""]
    if report_counts(result):
        lines += [table(result), "", f"Scope: {safe(result.scope_name)}; targets checked: {safe(', '.join(result.targets))}.",
                  budget_line(result), ""]
    if result.guard == "on":
        line = "Egress guard: on. "
        if result.guard_blocked is None:
            line += "Its log could not be read."
        else:
            n = result.guard_blocked
            line += (f"Blocked {n} out-of-scope request{'' if n == 1 else 's'} or DNS lookup{'' if n == 1 else 's'}, including background tool requests. "
                     "Log: egress-guard.jsonl in the run artifact.")
        if result.guard_ended:
            line += f" Scope ended during the run ({result.guard_ended}); later traffic was blocked."
        lines += [line, ""]
    if result.run_url:
        lines.append(f"[Run and SARIF artifact]({result.run_url}#artifacts)" if report_counts(result) else f"[View run]({result.run_url})")
    return "\n".join(lines).rstrip() + "\n"


def comment(result):
    # Never include engagement names, targets, errors, finding titles or details.
    lines = [MARKER, f"**RedRouter Security Action: {safe(result.status())}**", ""]
    if result.refusal or result.not_started:
        lines += ["No model request was made.", ""]
    elif report_counts(result):
        lines += [table(result), "", budget_line(result), ""]
    if result.run_url:
        lines.append(f"[View run]({result.run_url})")
    return "\n".join(lines).rstrip() + "\n"


def slack(result):
    text = f"RedRouter Security Action: {result.status()}"
    if result.refusal or result.not_started:
        text += " No model request was made."
    elif report_counts(result):
        text += " " + ", ".join(f"{k}: {v}" for k, v in result.findings.counts.items()) + "."
        text += " " + budget_line(result)
    if result.run_url:
        text += " " + result.run_url
    return {"text": text, "unfurl_links": False, "unfurl_media": False}
