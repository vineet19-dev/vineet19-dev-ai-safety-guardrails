"""Audit logging for AI safety guardrails."""

from datetime import datetime
from typing import List, Dict, Any, Optional


class AuditLogger:
    """Complete audit trail for AI safety decisions."""

    def __init__(self):
        self._audit_trail: List[Dict] = []

    def log_decision(self, decision: dict) -> None:
        """Log a decision with timestamp."""
        entry = {
            **decision,
            '_logged_at': datetime.now().isoformat(),
            '_entry_id': len(self._audit_trail)
        }
        self._audit_trail.append(entry)

    def get_audit_trail(self, filter: dict = None) -> List[Dict]:
        """Get audit trail, optionally filtered."""
        if not filter:
            return list(self._audit_trail)

        filtered = []
        for entry in self._audit_trail:
            match = all(
                entry.get(k) == v
                for k, v in filter.items()
                if not k.startswith('_')
            )
            if match:
                filtered.append(entry)

        return filtered

    def export_compliance_report(self) -> dict:
        """Export a compliance summary report."""
        total = len(self._audit_trail)
        blocked = sum(1 for e in self._audit_trail if e.get('blocked') is True)

        domains: Dict[str, int] = {}
        severities: Dict[str, int] = {}

        for entry in self._audit_trail:
            domain = entry.get('domain', 'UNKNOWN')
            severity = entry.get('severity', 'UNKNOWN')
            domains[domain] = domains.get(domain, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1

        return {
            'total_decisions': total,
            'total_blocked': blocked,
            'block_rate': blocked / total if total > 0 else 0.0,
            'decisions_by_domain': domains,
            'decisions_by_severity': severities,
            'report_generated_at': datetime.now().isoformat()
        }
