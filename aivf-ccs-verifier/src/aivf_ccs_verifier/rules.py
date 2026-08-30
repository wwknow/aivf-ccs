from __future__ import annotations
import ipaddress, json, re, time
from typing import Any, Iterable
from .models import Command, RuleResult

class Rule:
    name = "rule"
    dimension = "security"
    def evaluate(self, command: Command) -> RuleResult:
        raise NotImplementedError

def _result(rule, status, reason="", started=None):
    us = (time.perf_counter_ns() - started)/1000 if started else 0.0
    return RuleResult(rule.name, rule.dimension, status, reason, us)

class StructureRule(Rule):
    name="structure"; dimension="structure"
    def evaluate(self, command):
        t=time.perf_counter_ns()
        if not command.agent_id or not command.tool or not isinstance(command.params, dict):
            return _result(self,"fail","missing/invalid command structure",t)
        return _result(self,"pass","",t)

class SchemaRule(Rule):
    name="schema"; dimension="schema"
    def __init__(self, schemas=None):
        self.schemas=schemas or {}
    def evaluate(self, command):
        t=time.perf_counter_ns()
        spec=self.schemas.get(command.tool)
        if spec is None:
            return _result(self,"pass","no restrictive schema configured",t)
        required=spec.get("required",[])
        missing=[k for k in required if k not in command.params]
        if missing:
            return _result(self,"fail","missing required params: "+",".join(missing),t)
        types=spec.get("types",{})
        for k,typ in types.items():
            if k in command.params:
                expected={"string":str,"number":(int,float),"object":dict,"array":list,"boolean":bool}.get(typ)
                if expected and not isinstance(command.params[k], expected):
                    return _result(self,"fail",f"param {k} type mismatch",t)
        return _result(self,"pass","",t)

class LatencyRule(Rule):
    name="latency"; dimension="latency"
    def __init__(self, max_age_seconds=30.0):
        self.max_age_seconds=max_age_seconds
    def evaluate(self, command):
        t=time.perf_counter_ns()
        age=max(0.0,time.time()-command.timestamp)
        if age > self.max_age_seconds:
            return _result(self,"fail",f"command age {age:.3f}s exceeds limit",t)
        return _result(self,"pass","",t)

class CostRule(Rule):
    name="cost"; dimension="cost"
    def __init__(self, max_cost=None):
        self.max_cost=max_cost
    def evaluate(self, command):
        t=time.perf_counter_ns()
        if self.max_cost is None or command.cost is None:
            return _result(self,"pass","",t)
        if command.cost > self.max_cost:
            return _result(self,"fail",f"cost {command.cost} exceeds {self.max_cost}",t)
        return _result(self,"pass","",t)

class IdentityRule(Rule):
    name="identity"; dimension="identity"
    def __init__(self, allowed_agents=None):
        self.allowed=set(allowed_agents or [])
    def evaluate(self, command):
        t=time.perf_counter_ns()
        if self.allowed and command.agent_id not in self.allowed:
            return _result(self,"fail","agent identity not allowed",t)
        return _result(self,"pass","",t)

class IntegrityRule(Rule):
    name="integrity"; dimension="integrity"
    def evaluate(self, command):
        t=time.perf_counter_ns()
        try:
            json.dumps(command.params, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False)
        except Exception as e:
            return _result(self,"fail",f"params are not canonicalizable: {e}",t)
        return _result(self,"pass","",t)

def _flatten(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()
    except Exception:
        return str(value).lower()

class SSRFRule(Rule):
    name="ssrf_protection"; dimension="security"
    _url_re=re.compile(r"(?:https?|file|gopher|ftp)://[^\s\"']+", re.I)
    def evaluate(self, command):
        t=time.perf_counter_ns()
        blob=_flatten(command.params)
        if "file://" in blob or "gopher://" in blob:
            return _result(self,"fail","dangerous URL scheme",t)
        if "169.254.169.254" in blob or "metadata.google.internal" in blob:
            return _result(self,"fail","cloud metadata endpoint",t)
        for m in self._url_re.findall(blob):
            host=re.sub(r"^[a-z]+://","",m).split("/")[0].split("@")[-1].split(":")[0].strip("[]")
            if host in {"localhost","0.0.0.0"}:
                return _result(self,"fail","loopback/local target",t)
            try:
                ip=ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return _result(self,"fail","non-public IP target",t)
            except ValueError:
                pass
        return _result(self,"pass","",t)

class RCERule(Rule):
    name="rce_protection"; dimension="security"
    patterns=[
        re.compile(r"\bcurl\b.{0,200}\|\s*(?:ba)?sh\b",re.I|re.S),
        re.compile(r"\bwget\b.{0,200}\|\s*(?:ba)?sh\b",re.I|re.S),
        re.compile(r"\brm\s+-rf\s+/(?:\s|$)",re.I),
        re.compile(r"\b(?:eval|exec)\s*\(",re.I),
        re.compile(r"\b(?:nc|netcat)\b.{0,100}\s-e\s",re.I|re.S),
    ]
    def evaluate(self, command):
        t=time.perf_counter_ns()
        blob=_flatten(command.params)
        if any(p.search(blob) for p in self.patterns):
            return _result(self,"fail","RCE pattern detected",t)
        return _result(self,"pass","",t)

class CredentialLeakRule(Rule):
    name="credential_leak"; dimension="security"
    sensitive=re.compile(r"(api[_-]?key|secret|password|passwd|authorization|bearer|private[_-]?key)",re.I)
    exfil_tools=re.compile(r"(http|fetch|request|send|upload|webhook|curl)",re.I)
    def evaluate(self, command):
        t=time.perf_counter_ns()
        blob=_flatten(command.params)
        if self.sensitive.search(blob) and self.exfil_tools.search(command.tool+" "+blob):
            return _result(self,"fail","possible credential exfiltration",t)
        return _result(self,"pass","",t)
