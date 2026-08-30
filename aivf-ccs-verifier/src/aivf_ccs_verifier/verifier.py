from __future__ import annotations
from collections import defaultdict
from .models import Command, VerificationResult, DIMENSIONS
from .rules import (
    StructureRule, SchemaRule, LatencyRule, CostRule, IdentityRule, IntegrityRule,
    SSRFRule, RCERule, CredentialLeakRule
)

class Verifier:
    def __init__(self, rules=None, *, receipt_manager=None, config=None):
        self.config=config or {}
        self.rules=rules or [
            StructureRule(),
            SchemaRule(self.config.get("schemas")),
            LatencyRule(self.config.get("max_age_seconds",30.0)),
            CostRule(self.config.get("max_cost")),
            IdentityRule(self.config.get("allowed_agents")),
            IntegrityRule(),
            SSRFRule(), RCERule(), CredentialLeakRule(),
        ]
        if receipt_manager is None:
            raise ValueError("Verifier requires an explicit ReceiptManager")
        self.receipts=receipt_manager
        self.mode="in-process"

    def verify(self, command: Command) -> VerificationResult:
        results=[]
        try:
            for rule in self.rules:
                results.append(rule.evaluate(command))
        except Exception as e:
            dims={d:"unknown" for d in DIMENSIONS}
            dims["security"]="fail"
            receipt=self.receipts.create_admission(
                command,"deny",dims,"verifier_exception=fail",
                f"verifier exception: {e}",self.config
            )
            return VerificationResult("deny",dims,results,f"verifier exception: {e}",receipt)

        bydim=defaultdict(list)
        for r in results:
            bydim[r.dimension].append(r.status)

        dimensions={}
        for d in DIMENSIONS:
            vals=bydim.get(d,[])
            if "fail" in vals:
                dimensions[d]="fail"
            elif "unknown" in vals or not vals:
                dimensions[d]="unknown"
            else:
                dimensions[d]="pass"

        verdict="deny" if "fail" in dimensions.values() else (
            "escalate" if "unknown" in dimensions.values() else "allow"
        )
        reason=next((r.reason for r in results if r.status=="fail" and r.reason),None)
        if not reason and verdict=="escalate":
            reason="one or more dimensions are unknown"
        summary="|".join(f"{r.name}={r.status}" for r in results)
        receipt=self.receipts.create_admission(command,verdict,dimensions,summary,reason,self.config)
        return VerificationResult(verdict,dimensions,results,reason,receipt)
