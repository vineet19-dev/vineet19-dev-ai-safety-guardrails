# AI Safety Guardrails - Quick Start Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/vineet19-dev/vineet19-dev-ai-safety-guardrails.git
cd vineet19-dev-ai-safety-guardrails
```

2. Install dependencies (Python ≥ 3.10 required):
```bash
pip install -e .
```

## Running the Dashboard

### Option 1: Using the launcher script (Recommended)
```bash
python run_dashboard.py
```

### Option 2: Using the module directly
```bash
python -m guardrails.api
```

Then open your browser to **http://localhost:8000**

## Running the Demo

See the system in action with pre-built test scenarios:
```bash
python demo.py
```

This will demonstrate:
- Financial fraud detection (pump & dump, insider trading, front-running)
- Gaming exploits (botting, match fixing, glitch abuse)
- Healthcare fraud (insurance fraud, phantom billing)
- Platform safety (deepfakes, misinformation)

## Running Tests

```bash
python -m pytest tests/ -v
```

All 124 tests should pass, validating:
- ≥85% detection rate for known attacks
- <5% false positive rate
- Full audit trail and compliance reporting

## Using the API

### Python Example

```python
from guardrails import SafetyPipeline
from guardrails.ethical_framework import Action, Domain

pipeline = SafetyPipeline()

# Evaluate a suspicious action
action = Action(
    action_id="test-001",
    domain=Domain.FINANCIAL_TRADING,
    action_type="place_order",
    parameters={"front_run": True},
    actor_id="trader-99"
)

result = pipeline.evaluate(action)
print(f"Decision: {result.verdict.verdict.value}")  # ESCALATE
print(f"Allowed: {result.allowed}")                 # False
print(f"Violations: {result.verdict.violations}")    # ['front_running']
```

### REST API Example

```bash
# Evaluate an action
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "test-001",
    "domain": "financial_trading",
    "action_type": "place_order",
    "parameters": {"front_run": true},
    "actor_id": "trader-99"
  }'

# Get logs
curl http://localhost:8000/logs?limit=10

# Get statistics
curl http://localhost:8000/api/stats

# Get demo actions
curl http://localhost:8000/api/demo-actions
```

## Dashboard Features

The web dashboard includes:

1. **Input Section**
   - Text area for action description
   - Domain selector
   - "Run Safety Check" button
   - "Run Demo Mode" button

2. **Pre-built Test Buttons**
   - 💰 Financial Fraud (Pump & Dump)
   - 🎮 Game Exploit (Botting)
   - 🎭 Deepfake Attack
   - 🏥 Healthcare Fraud
   - 📊 Insider Trading
   - ✅ Clean Action (baseline)

3. **Results Display**
   - Color-coded decision (ALLOW/WARN/BLOCK/ESCALATE)
   - Domain and confidence score
   - Severity level
   - Detailed reason
   - Applicable law/regulation
   - List of violations

4. **Live Logs Panel**
   - Real-time action evaluation history
   - Auto-refreshes every 5 seconds
   - Timestamp, decision, domain, and violations

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard (HTML) |
| `/evaluate` | POST | Evaluate an AI action |
| `/logs` | GET | Get recent audit logs |
| `/api/domains` | GET | List supported domains |
| `/api/stats` | GET | Get statistics |
| `/api/demo-actions` | GET | Get pre-built test actions |
| `/api/demo-mode` | POST | Run all demos automatically |
| `/docs` | GET | Interactive API docs (Swagger) |

## Project Structure

```
src/guardrails/
├── api.py                    # FastAPI backend + dashboard
├── pipeline.py               # Main SafetyPipeline orchestrator
├── ethical_framework.py      # Ethics classifier
├── behavior_monitor.py       # Anomaly detection
├── prevention.py             # Action blocking engine
├── audit_logger.py           # Compliance logging
└── detectors/                # Domain-specific detectors
    ├── financial_trading.py
    ├── gaming.py
    ├── healthcare.py
    ├── business_ethics.py
    └── platform_safety.py
```

## Supported Domains & Violations

### Financial Trading
- Front-running, market manipulation, spoofing, layering
- Pump-and-dump, quote stuffing, wash trading
- Insider trading, price fixing

### Gaming
- Botting, account farming, collusion
- Glitch exploitation, smurf accounts
- Match fixing

### Healthcare
- Insurance fraud (upcoding, phantom billing)
- Unnecessary treatments, patient coercion
- PHI breaches, kickbacks, Stark Law violations

### Social Platforms
- Misinformation, harassment, deepfakes
- Vote manipulation, CSAM
- Coordinated inauthentic behavior, incitement to violence

### Business
- Fraud, bribery, kickbacks
- Anti-competitive behavior, labor exploitation
- Environmental violations, money laundering

## Need Help?

- View API documentation: http://localhost:8000/docs
- Run the demo: `python demo.py`
- Check the README: [README.md](README.md)

## License

MIT License - see LICENSE file for details
