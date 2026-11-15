"""Only the engine operations used by the Action; no plugin registry."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


@dataclass
class Findings:
    counts: dict = field(default_factory=lambda: dict.fromkeys(SEVERITIES, 0))
    sarif: Path | None = None
    estimated_spend: str = ""
    finished: bool = False


class Engine(Protocol):
    def install(self) -> None: ...
    def build(self) -> tuple[list[str], dict[str, str]]: ...
    def run(self) -> int: ...
    def locate_results(self) -> Path | None: ...
    def normalize(self, path: Path | None) -> Findings: ...
