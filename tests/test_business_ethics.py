import pytest
from ai_safety_guardrails.domains.business_ethics import BusinessEthicsValidator, ValidationResult, AuditResult


def test_legitimate_business_action():
    validator = BusinessEthicsValidator()
    action = {
        'action_type': 'contract_signing',
        'transparent': True,
        'contains_misrepresentation': False
    }
    result = validator.validate_business_action(action)
    assert isinstance(result, ValidationResult)
    assert result.is_valid == True
    assert len(result.violations) == 0


def test_fraud_detection():
    validator = BusinessEthicsValidator()
    action = {
        'action_type': 'contract',
        'contains_misrepresentation': True,
        'false_statements': True
    }
    result = validator.validate_business_action(action)
    assert result.is_valid == False
    assert len(result.violations) > 0
    assert any('fraud' in v.lower() for v in result.violations)


def test_bribery_detection():
    validator = BusinessEthicsValidator()
    action = {
        'action_type': 'payment',
        'payment_amount': 5000,
        'payment_purpose': 'gift'
    }
    result = validator.validate_business_action(action)
    assert result.is_valid == False
    assert any('bribery' in v.lower() for v in result.violations)


def test_anti_competitive_detection():
    validator = BusinessEthicsValidator()
    action = {
        'action_type': 'pricing_meeting',
        'price_coordination': True
    }
    result = validator.validate_business_action(action)
    assert result.is_valid == False
    assert any('anti_competitive' in v.lower() or 'competitive' in v.lower() for v in result.violations)


def test_labor_exploitation_detection():
    validator = BusinessEthicsValidator()
    action = {
        'action_type': 'payroll',
        'wage_below_minimum': True
    }
    result = validator.validate_business_action(action)
    assert result.is_valid == False
    assert any('labor' in v.lower() or 'exploitation' in v.lower() for v in result.violations)


def test_financial_audit_clean_records():
    validator = BusinessEthicsValidator()
    records = [
        {'record_id': 'r1', 'amount': 1000},
        {'record_id': 'r2', 'amount': 1200},
        {'record_id': 'r3', 'amount': 900},
        {'record_id': 'r4', 'amount': 1100},
    ]
    result = validator.audit_financial_records(records)
    assert isinstance(result, AuditResult)


def test_financial_audit_with_anomalies():
    validator = BusinessEthicsValidator()
    # Normal records with one massive outlier
    records = [
        {'amount': 1000}, {'amount': 1100}, {'amount': 900}, {'amount': 1050},
        {'amount': 1000}, {'amount': 950}, {'amount': 1000}, {'amount': 100000}  # Outlier
    ]
    result = validator.audit_financial_records(records)
    assert result.has_anomalies == True
    assert len(result.anomalies) > 0
