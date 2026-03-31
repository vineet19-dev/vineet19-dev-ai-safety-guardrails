# AI Safety Guardrails

> **Quick Start:** See [QUICKSTART.md](QUICKSTART.md) for a step-by-step guide to getting started.

An enhanced AI safety guardrails system that detects and prevents unethical AI behaviors across multiple critical domains: **financial trading**, **gaming/esports**, **business operations**, **healthcare**, and **social platforms**.

## Overview

Real-world AI systems can engage in deeply unethical behaviors when optimizing for rewards without proper constraints. This system provides a multi-layered defense against such behaviors through:

- **Unified Ethical Framework** – regex-based rule engine with domain-specific classifiers, intent vs. outcome analysis, and stakeholder impact assessment
- **Behavior Monitoring** – real-time anomaly scoring, frequency analysis, and network-based collusion detection
- **Domain-Specific Detectors** – deep rule engines for each domain with regulatory references
- **Prevention Engine** – action blocking, friction injection, and escalation triggers
- **Audit Logger** – complete decision trail for regulatory compliance and transparency reporting

## Supported Domains & Detected Violations

| Domain | Violations Detected |
|---|---|
| **Financial Trading** | Front-running, market manipulation, spoofing, layering, pump-and-dump, quote stuffing, wash trading, insider trading, price fixing |
| **Gaming / Esports** | Account farming, collusion, glitch exploitation, smurf accounts, botting, match fixing |
| **Business / Corporate** | Fraud, bribery, kickbacks, anti-competitive behavior, labor exploitation, environmental violations, money laundering |
| **Healthcare** | Insurance fraud (upcoding/phantom billing), unnecessary treatments, patient coercion, PHI breaches, healthcare kickbacks, Stark Law violations |
| **Social Platforms** | Misinformation, harassment, deepfakes, vote manipulation, CSAM, coordinated inauthentic behavior, incitement to violence |

## Architecture

```
Action (input)
    │
    ▼
BehaviorMonitor          ← real-time anomaly scoring & collusion detection
    │
    ▼
Domain Detector          ← FinancialTradingMonitor | GamingBehaviorAnalyzer |
    │                       BusinessEthicsValidator | HealthcareIntegrityMonitor |
    │                       PlatformSafetyGuard
    ▼
EthicsClassifier         ← unified multi-dimensional classifier + intent analysis
    │
    ▼
PreventionEngine         ← ALLOW / WARN (friction) / BLOCK / ESCALATE
    │
    ▼
AuditLogger              ← full decision trail, compliance & transparency reports
    │
    ▼
PipelineResult (output)
```

## Installation

```bash
pip install -e ".[dev]"
```

Python ≥ 3.10 is required (uses `match` statements). No third-party runtime dependencies.

## Quick Start

```python
from guardrails import SafetyPipeline
from guardrails.ethical_framework import Action, Domain

pipeline = SafetyPipeline()

# Evaluate a suspicious trading action
action = Action(
    action_id="order-001",
    domain=Domain.FINANCIAL_TRADING,
    action_type="place_order",
    parameters={"front_run": True},
    actor_id="trader-99",
)

result = pipeline.evaluate(action)
print(result.allowed)              # False
print(result.verdict.violations)   # ['front_running']
print(result.prevention.blocked_reason)
# "Action blocked due to policy violation(s): front_running."
```

### Checking for Collusion

```python
# Record interactions and detect coordinated actors
for _ in range(6):
    pipeline.collusion_check("actor-A", "actor-B")

print(pipeline.collusion_check("actor-A", "actor-B"))  # True
```

### Compliance & Transparency Reporting

```python
report = pipeline.compliance_report()
print(report["detection_rate"])   # e.g. 0.92

print(pipeline.transparency_report())
# === AI Safety Guardrails – Transparency Report ===
# Total evaluations : 42
# Actions blocked   : 38
# ...
```

## Web Dashboard (FastAPI + Modern UI)

### Quick Start - Run the Dashboard

The easiest way to run the full-featured dashboard:

```bash
python run_dashboard.py
```

Or using the module directly:

```bash
python -m guardrails.api
```

Then open **http://localhost:8000** in your browser.

### Features

The modern web dashboard includes:

- **🎨 Dark Theme UI** - Professional dark mode interface
- **🔍 Safety Check** - Evaluate AI actions in real-time
- **🎯 Pre-built Test Cases** - Quick buttons for common attack scenarios:
  - 💰 Financial Fraud (Pump & Dump)
  - 🎮 Game Exploit (Botting)
  - 🎭 Deepfake Attack
  - 🏥 Healthcare Fraud
  - 📊 Insider Trading
  - ✅ Clean Action (baseline)
- **📊 Live Logs Panel** - Real-time action evaluation history
- **🎬 Demo Mode** - Simulate multiple AI actions automatically
- **📈 Statistics** - Decision and domain distribution (via API)

### API Endpoints

The FastAPI backend provides the following REST endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard (HTML) |
| `/evaluate` | POST | Evaluate an AI action, returns structured JSON |
| `/logs` | GET | Retrieve recent audit logs |
| `/api/domains` | GET | List supported domains |
| `/api/stats` | GET | Get decision/domain statistics |
| `/api/demo-actions` | GET | Get pre-built test actions |
| `/api/demo-mode` | POST | Run all demo actions automatically |
| `/docs` | GET | Interactive API documentation (Swagger UI) |

### API Response Format

The `/evaluate` endpoint returns structured JSON:

```json
{
  "decision": "BLOCK",
  "domain": "financial_trading",
  "confidence": 0.92,
  "reason": "Front-running detected: placing orders ahead of known client orders.",
  "law": "SEC Rule 10b-5 (Market Manipulation)",
  "action_id": "order-001",
  "violations": ["front_running"],
  "severity": "critical",
  "stakeholder_impacts": ["market_integrity", "client_interests"],
  "suggested_alternatives": [],
  "allowed": false,
  "anomaly_score": 0.15
}
```

### Example API Usage

```python
import requests

# Evaluate an action
response = requests.post("http://localhost:8000/evaluate", json={
    "action_id": "test-001",
    "domain": "financial_trading",
    "action_type": "place_order",
    "parameters": {"front_run": True},
    "actor_id": "trader-99"
})

result = response.json()
print(f"Decision: {result['decision']}")
print(f"Reason: {result['reason']}")
print(f"Law: {result['law']}")

# Get logs
logs_response = requests.get("http://localhost:8000/logs?limit=10")
logs = logs_response.json()
print(f"Total actions evaluated: {logs['total']}")
```

### Legacy Web Interface

For a simpler HTTP server-based interface (no FastAPI required):

```bash
python -m guardrails.web
```

Then open `http://127.0.0.1:8000` to use the basic frontend form.

## Running Tests

```bash
python -m pytest tests/ -v
```

The test suite covers:

- **111 unit and integration tests** across all domains
- **Detection rate validation** – asserts ≥85% of known attack patterns are blocked
- **False positive validation** – asserts <5% of clean actions are incorrectly blocked

## Success Criteria

| Criterion | Target | Status |
|---|---|---|
| Detection rate for known attacks | ≥ 85% | ✅ verified in tests |
| Prevention of attempted violations | ≥ 90% | ✅ all attack scenarios blocked |
| False positive rate | < 5% | ✅ verified in tests |
| Full audit trail | Required | ✅ `AuditLogger` captures every decision |
| Explainability | Required | ✅ `reasoning` field on every verdict |
| Regulatory references | Required | ✅ each rule includes applicable law/regulation |

## Project Structure

```
src/guardrails/
├── __init__.py                    # Public API
├── ethical_framework.py           # Multi-dimensional ethics classifier
├── behavior_monitor.py            # Real-time behavior surveillance
├── prevention.py                  # Prevention & enforcement engine
├── audit_logger.py                # Audit trail & compliance reporting
├── pipeline.py                    # Unified SafetyPipeline orchestrator
├── api.py                         # FastAPI backend with REST endpoints
├── web.py                         # Legacy HTTP server frontend
└── detectors/
    ├── financial_trading.py       # SEC/FINRA rule engine
    ├── gaming.py                  # Fair-play rule engine
    ├── business_ethics.py         # Corporate ethics rule engine
    ├── healthcare.py              # HIPAA/AKS/Stark Law rule engine
    └── platform_safety.py        # Platform community standards engine

tests/
├── test_ethical_framework.py
├── test_financial_trading.py
├── test_gaming.py
├── test_business_ethics.py
├── test_healthcare.py
├── test_platform_safety.py
├── test_prevention.py
├── test_web.py
└── test_integration.py            # End-to-end pipeline + detection rate tests

run_dashboard.py                   # Dashboard launcher script
```

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
