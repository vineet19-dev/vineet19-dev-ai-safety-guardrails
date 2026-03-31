from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import statistics

from ai_safety_guardrails.core.threat_level import ThreatLevel


@dataclass
class ValidationResult:
    is_valid: bool
    violations: List[str]
    severity: str
    confidence: float
    reasoning: str
    recommended_action: str


@dataclass
class AuditResult:
    has_anomalies: bool
    anomalies: List[Dict]
    severity: str
    confidence: float
    summary: str


class BusinessEthicsValidator:
    """Validator for detecting business ethics violations."""

    def validate_business_action(self, action: dict) -> ValidationResult:
        """Validate a business action for ethical violations."""
        violations = []

        # Check fraud: misrepresentation
        if action.get('contains_misrepresentation') or action.get('false_statements'):
            violations.append('fraud: misrepresentation detected')

        # Check bribery: suspicious payment patterns
        payment = action.get('payment_amount', 0)
        payment_purpose = action.get('payment_purpose', '').lower()
        if payment > 0 and payment_purpose in ('gift', 'facilitation', 'favor', 'unofficial'):
            violations.append('bribery: suspicious payment pattern')

        # Check anti-competitive behavior
        if action.get('price_coordination') or action.get('market_allocation'):
            violations.append('anti_competitive: price fixing or market allocation')

        # Check labor exploitation
        if action.get('wage_below_minimum') or action.get('hours_violation'):
            violations.append('labor_exploitation: wage or hours violation')

        if not violations:
            return ValidationResult(
                is_valid=True,
                violations=[],
                severity='LOW',
                confidence=0.95,
                reasoning='No violations detected',
                recommended_action='allow'
            )

        severity = 'HIGH' if len(violations) > 1 else 'MEDIUM'
        return ValidationResult(
            is_valid=False,
            violations=violations,
            severity=severity,
            confidence=0.85,
            reasoning=f'Detected {len(violations)} violation(s)',
            recommended_action='block_and_report'
        )

    def audit_financial_records(self, records: list) -> AuditResult:
        """Audit financial records for anomalies."""
        anomalies = []

        if not records:
            return AuditResult(
                has_anomalies=False,
                anomalies=[],
                severity='LOW',
                confidence=0.95,
                summary='No records to audit'
            )

        amounts = [r.get('amount', 0) for r in records]

        if len(amounts) >= 3:
            avg = sum(amounts) / len(amounts)
            try:
                std = statistics.stdev(amounts)
                for i, record in enumerate(records):
                    amount = record.get('amount', 0)
                    if std > 0 and abs(amount - avg) > 3 * std:
                        anomalies.append({
                            'record_index': i,
                            'type': 'statistical_outlier',
                            'amount': amount,
                            'deviation': abs(amount - avg) / std
                        })
            except statistics.StatisticsError:
                pass

            # IQR-based outlier detection (robust against extreme outliers)
            sorted_amounts = sorted(amounts)
            n = len(sorted_amounts)
            q1 = sorted_amounts[n // 4]
            q3 = sorted_amounts[(3 * n) // 4]
            iqr = q3 - q1
            if iqr > 0:
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                for i, record in enumerate(records):
                    amount = record.get('amount', 0)
                    if amount < lower_bound or amount > upper_bound:
                        # Only add if not already detected
                        already_detected = any(a.get('record_index') == i for a in anomalies)
                        if not already_detected:
                            anomalies.append({
                                'record_index': i,
                                'type': 'iqr_outlier',
                                'amount': amount,
                                'deviation': (amount - q3) / iqr if amount > q3 else (q1 - amount) / iqr
                            })

        # Check for round number transactions (potential structuring)
        round_transactions = [r for r in records if r.get('amount', 0) % 1000 == 0 and r.get('amount', 0) > 0]
        if len(round_transactions) > len(records) * 0.7:
            anomalies.append({'type': 'structuring', 'description': 'High proportion of round-number transactions'})

        return AuditResult(
            has_anomalies=len(anomalies) > 0,
            anomalies=anomalies,
            severity='HIGH' if len(anomalies) > 2 else ('MEDIUM' if anomalies else 'LOW'),
            confidence=0.80,
            summary=f'Found {len(anomalies)} anomalies in {len(records)} records'
        )
