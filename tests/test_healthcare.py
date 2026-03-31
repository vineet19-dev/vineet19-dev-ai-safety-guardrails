import pytest
from ai_safety_guardrails.domains.healthcare import HealthcareIntegrityMonitor, ClaimAssessment, PatternAssessment, ThreatLevel


def test_legitimate_claim():
    monitor = HealthcareIntegrityMonitor()
    claim = {
        'claim_id': 'C001',
        'patient_id': 'P001',
        'billed_procedure_code': 'CPT99213',
        'actual_procedure_code': 'CPT99213',
        'amount': 150
    }
    result = monitor.analyze_claim(claim)
    assert isinstance(result, ClaimAssessment)
    assert result.is_suspicious == False
    assert result.threat_level == ThreatLevel.LOW


def test_upcoding_detection():
    monitor = HealthcareIntegrityMonitor()
    claim = {
        'claim_id': 'C002',
        'patient_id': 'P002',
        'billed_procedure_code': 'CPT99215',  # Level 5 (expensive)
        'actual_procedure_code': 'CPT99212',  # Level 2 (cheap)
        'amount': 300
    }
    result = monitor.analyze_claim(claim)
    assert result.is_suspicious == True
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
    assert any('upcode' in i.lower() or 'upcod' in i.lower() for i in result.fraud_indicators)


def test_ghost_service_detection():
    monitor = HealthcareIntegrityMonitor()
    claim = {
        'claim_id': 'C003',
        'patient_id': 'P003',
        'service_not_rendered': True,
        'amount': 500
    }
    result = monitor.analyze_claim(claim)
    assert result.is_suspicious == True
    assert any('ghost' in i.lower() for i in result.fraud_indicators)


def test_duplicate_billing_detection():
    monitor = HealthcareIntegrityMonitor()
    claim = {
        'claim_id': 'C004',
        'patient_id': 'P004',
        'is_duplicate': True,
        'amount': 200
    }
    result = monitor.analyze_claim(claim)
    assert result.is_suspicious == True


def test_normal_treatment_pattern():
    monitor = HealthcareIntegrityMonitor()
    treatments = [
        {'procedure': 'checkup', 'date': '2024-01-01'},
        {'procedure': 'blood_test', 'date': '2024-01-15'},
        {'procedure': 'followup', 'date': '2024-02-01'},
    ]
    result = monitor.analyze_treatment_pattern('patient_normal', treatments)
    assert isinstance(result, PatternAssessment)
    assert result.is_suspicious == False


def test_unnecessary_treatment_detection():
    monitor = HealthcareIntegrityMonitor()
    # Same procedure repeated > 10 times
    treatments = [{'procedure': 'mri_scan', 'date': f'2024-{i:02d}-01'} for i in range(1, 13)]
    result = monitor.analyze_treatment_pattern('patient_exploit', treatments)
    assert result.is_suspicious == True
    assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)


def test_data_breach_detection():
    monitor = HealthcareIntegrityMonitor()
    # Many data accesses
    treatments = [{'procedure': 'checkup', 'type': 'data_access'} for _ in range(25)]
    result = monitor.analyze_treatment_pattern('suspicious_access', treatments)
    assert result.is_suspicious == True
    assert 'data' in result.pattern_type.lower() or 'breach' in result.pattern_type.lower()
