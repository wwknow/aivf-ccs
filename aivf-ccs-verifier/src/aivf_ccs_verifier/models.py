from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional
import time, secrets

DIMENSIONS = ("structure","schema","latency","cost","identity","integrity","security")

@dataclass(frozen=True)
class Command:
    agent_id: str
    tool: str
    params: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    trace_id: str = field(default_factory=lambda: secrets.token_hex(8))
    context: Dict[str, Any] = field(default_factory=dict)
    cost: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RuleResult:
    name: str
    dimension: str
    status: str  # pass | fail | unknown
    reason: str = ""
    latency_us: float = 0.0

@dataclass
class VerificationResult:
    verdict: str  # allow | deny | escalate
    dimensions: Dict[str, str]
    rule_results: list[RuleResult]
    block_reason: Optional[str]
    receipt: Dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    @property
    def retryable(self) -> bool:
        return self.verdict == "escalate"

    @property
    def error_code(self) -> int | None:
        if self.verdict == "allow":
            return None
        # Stable dimension-level mapping
        failed = next((d for d,s in self.dimensions.items() if s == "fail"), "security")
        return {
            "structure": -32001, "schema": -32002, "latency": -32003,
            "cost": -32004, "identity": -32005, "integrity": -32006,
            "security": -32000,
        }.get(failed, -32000)
