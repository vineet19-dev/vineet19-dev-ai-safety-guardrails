"""
Audit Logger
============
Complete decision trail with reasoning, stakeholder impact documentation,
regulatory compliance records, and transparency reporting.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, TextIO

from .ethical_framework import Action, EthicsVerdict
from .prevention import PreventionOutcome


@dataclass
class AuditEntry:
    entry_id: str
    timestamp: float
    actor_id: str
    action_type: str
    domain: str
    verdict: str
    severity: str
    violations: list[str]
    stakeholder_impacts: list[str]
    reasoning: str
    allowed: bool
    friction_applied: bool
    escalated: bool
    enforcement_notes: list[str]
    suggested_alternatives: list[str]
    anomaly_score: float
    behavior_flags: list[str]
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """
    Structured audit logger that stores every guardrails decision for
    compliance review and transparency reporting.

    By default records are kept in memory.  Pass a ``sink`` (any
    file-like object that accepts str writes) to also stream JSON-Lines
    output to disk or a remote endpoint.
    """

    def __init__(self, sink: TextIO | None = None) -> None:
        self._entries: list[AuditEntry] = []
        self._sink = sink
        self._entry_counter = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(
        self,
        action: Action,
        verdict: EthicsVerdict,
        outcome: PreventionOutcome,
        anomaly_score: float = 0.0,
        behavior_flags: list[str] | None = None,
    ) -> AuditEntry:
        """Create and store an AuditEntry for a guardrails decision."""
        self._entry_counter += 1
        entry = AuditEntry(
            entry_id=f"audit-{self._entry_counter:06d}",
            timestamp=time.time(),
            actor_id=action.actor_id,
            action_type=action.action_type,
            domain=action.domain.value,
            verdict=verdict.verdict.value,
            severity=verdict.severity.value,
            violations=list(verdict.violations),
            stakeholder_impacts=list(verdict.stakeholder_impacts),
            reasoning=verdict.reasoning,
            allowed=outcome.allowed,
            friction_applied=outcome.friction_applied,
            escalated=outcome.escalated,
            enforcement_notes=list(outcome.enforcement_notes),
            suggested_alternatives=list(outcome.alternatives),
            anomaly_score=anomaly_score,
            behavior_flags=list(behavior_flags or []),
            confidence=verdict.confidence,
            metadata=dict(action.metadata),
        )
        self._entries.append(entry)

        if self._sink is not None:
            self._sink.write(json.dumps(asdict(entry)) + "\n")

        return entry

    def get_all_entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def get_entries_for_actor(self, actor_id: str) -> list[AuditEntry]:
        return [e for e in self._entries if e.actor_id == actor_id]

    def get_blocked_entries(self) -> list[AuditEntry]:
        return [e for e in self._entries if not e.allowed]

    def get_escalated_entries(self) -> list[AuditEntry]:
        return [e for e in self._entries if e.escalated]

    def compliance_report(self) -> dict[str, Any]:
        """Return a high-level compliance summary suitable for regulators."""
        total = len(self._entries)
        blocked = sum(1 for e in self._entries if not e.allowed)
        escalated = sum(1 for e in self._entries if e.escalated)
        friction = sum(1 for e in self._entries if e.friction_applied)

        violation_counts: dict[str, int] = {}
        for entry in self._entries:
            for v in entry.violations:
                violation_counts[v] = violation_counts.get(v, 0) + 1

        domain_counts: dict[str, int] = {}
        for entry in self._entries:
            domain_counts[entry.domain] = domain_counts.get(entry.domain, 0) + 1

        false_positive_rate = (
            round(
                sum(1 for e in self._entries if e.allowed and e.friction_applied) / total,
                4,
            )
            if total
            else 0.0
        )

        return {
            "total_evaluations": total,
            "blocked": blocked,
            "escalated": escalated,
            "friction_applied": friction,
            "detection_rate": round(blocked / total, 4) if total else 0.0,
            "estimated_false_positive_rate": false_positive_rate,
            "top_violations": sorted(
                violation_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "evaluations_by_domain": domain_counts,
        }

    def transparency_report(self) -> str:
        """Return a human-readable transparency report."""
        report = self.compliance_report()
        lines = [
            "=== AI Safety Guardrails – Transparency Report ===",
            f"Total evaluations : {report['total_evaluations']}",
            f"Actions blocked   : {report['blocked']}",
            f"Actions escalated : {report['escalated']}",
            f"Friction injected : {report['friction_applied']}",
            f"Detection rate    : {report['detection_rate']:.1%}",
            f"Est. FP rate      : {report['estimated_false_positive_rate']:.1%}",
            "",
            "Top violations:",
        ]
        for name, count in report["top_violations"]:
            lines.append(f"  {name:<35} {count}")
        lines.append("")
        lines.append("Evaluations by domain:")
        for domain, count in sorted(report["evaluations_by_domain"].items()):
            lines.append(f"  {domain:<35} {count}")
        return "\n".join(lines)
