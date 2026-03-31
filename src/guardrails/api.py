"""FastAPI backend for AI Safety Guardrails System."""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import os

from .ethical_framework import Action, Domain
from .pipeline import SafetyPipeline

# Initialize FastAPI app
app = FastAPI(
    title="AI Safety Guardrails API",
    description="API for detecting and preventing unethical AI behaviors",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global pipeline instance
pipeline = SafetyPipeline()


# Request/Response Models
class ActionRequest(BaseModel):
    """Request model for action evaluation."""
    action_id: str = Field(..., description="Unique action identifier")
    domain: str = Field(..., description="Domain of the action")
    action_type: str = Field(..., description="Type of action being performed")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    actor_id: str = Field(default="anonymous", description="ID of the actor performing the action")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class EvaluationResponse(BaseModel):
    """Response model for action evaluation."""
    decision: str = Field(..., description="ALLOW, WARN, BLOCK, or ESCALATE")
    domain: str = Field(..., description="Domain of the action")
    confidence: float = Field(..., description="Confidence score (0-1)")
    reason: str = Field(..., description="Explanation for the decision")
    law: str = Field(default="", description="Applicable law or regulation")
    action_id: str = Field(..., description="Action ID")
    violations: List[str] = Field(default_factory=list, description="List of violations detected")
    severity: str = Field(..., description="Severity of violations")
    stakeholder_impacts: List[str] = Field(default_factory=list, description="Impacted stakeholders")
    suggested_alternatives: List[str] = Field(default_factory=list, description="Alternative actions")
    allowed: bool = Field(..., description="Whether action is allowed")
    anomaly_score: float = Field(default=0.0, description="Behavioral anomaly score")


class LogEntry(BaseModel):
    """Model for audit log entries."""
    timestamp: str
    action_id: str
    actor_id: str
    domain: str
    decision: str
    violations: List[str]
    severity: str


class DemoAction(BaseModel):
    """Pre-defined demo action."""
    name: str
    description: str
    action: ActionRequest


# Helper function to convert domain string to Domain enum
def parse_domain(domain_str: str) -> Domain:
    """Convert domain string to Domain enum."""
    try:
        return Domain(domain_str)
    except ValueError:
        valid_domains = [d.value for d in Domain]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain '{domain_str}'. Valid domains: {', '.join(valid_domains)}"
        )


# Helper function to extract law/regulation from violations
def extract_law(domain_analysis: Any) -> str:
    """Extract regulatory reference from domain analysis."""
    if domain_analysis is None:
        return ""

    violations = getattr(domain_analysis, "violations", [])
    if violations:
        # Get the regulatory reference from the first violation
        return getattr(violations[0], "regulatory_reference", "")
    return ""


@app.get("/")
async def root():
    """Serve the frontend HTML."""
    html_content = get_frontend_html()
    return HTMLResponse(content=html_content)


@app.post("/evaluate", response_model=EvaluationResponse)
async def evaluate_action(request: ActionRequest):
    """
    Evaluate an AI action for ethical compliance.

    Returns structured JSON with decision, domain, confidence, reason, and applicable law.
    """
    try:
        # Parse domain
        domain = parse_domain(request.domain)

        # Create Action object
        action = Action(
            action_id=request.action_id,
            domain=domain,
            action_type=request.action_type,
            parameters=request.parameters,
            actor_id=request.actor_id,
            context=request.context,
            metadata=request.metadata,
        )

        # Evaluate action
        result = pipeline.evaluate(action)

        # Extract law/regulation from domain analysis
        law = extract_law(result.domain_analysis)

        # Build explanation
        reason = result.verdict.reasoning if result.verdict.reasoning else (
            f"Action evaluated with {len(result.verdict.violations)} violation(s) detected."
        )

        # Create response
        response = EvaluationResponse(
            decision=result.verdict.verdict.value.upper(),
            domain=request.domain,
            confidence=result.verdict.confidence,
            reason=reason,
            law=law,
            action_id=result.action_id,
            violations=result.verdict.violations,
            severity=result.verdict.severity.value,
            stakeholder_impacts=result.verdict.stakeholder_impacts,
            suggested_alternatives=result.verdict.suggested_alternatives,
            allowed=result.allowed,
            anomaly_score=result.behavior.anomaly_score,
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error evaluating action: {str(e)}")


@app.get("/logs")
async def get_logs(limit: int = 50):
    """
    Get recent audit logs.

    Returns list of recent action evaluations with their decisions.
    """
    try:
        entries = pipeline.audit_entries()

        # Convert to log entries (most recent first)
        logs = []
        for entry in reversed(entries[-limit:]):
            logs.append({
                "timestamp": entry.timestamp,
                "action_id": entry.action_id,
                "actor_id": entry.actor_id,
                "domain": entry.action_domain,
                "decision": entry.verdict_type.upper(),
                "violations": entry.violations,
                "severity": entry.severity,
            })

        return {"logs": logs, "total": len(entries)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving logs: {str(e)}")


@app.get("/api/domains")
async def get_domains():
    """Get list of supported domains."""
    return {"domains": [d.value for d in Domain]}


@app.get("/api/stats")
async def get_stats():
    """Get statistics for charts."""
    try:
        entries = pipeline.audit_entries()

        if not entries:
            return {
                "decision_distribution": {},
                "domain_distribution": {},
                "total_evaluations": 0,
            }

        # Calculate decision distribution
        decision_dist = {}
        domain_dist = {}

        for entry in entries:
            # Decision distribution
            decision = entry.verdict_type.upper()
            decision_dist[decision] = decision_dist.get(decision, 0) + 1

            # Domain distribution
            domain = entry.action_domain
            domain_dist[domain] = domain_dist.get(domain, 0) + 1

        return {
            "decision_distribution": decision_dist,
            "domain_distribution": domain_dist,
            "total_evaluations": len(entries),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving stats: {str(e)}")


@app.get("/api/demo-actions")
async def get_demo_actions():
    """Get pre-built demo actions for testing."""
    demos = [
        {
            "name": "Financial Fraud (Pump & Dump)",
            "description": "Detect pump and dump market manipulation",
            "action": {
                "action_id": "demo-financial-001",
                "domain": "financial_trading",
                "action_type": "place_order",
                "parameters": {
                    "pump_and_dump": True,
                    "coordinated_buying": True,
                    "artificial_hype": True
                },
                "actor_id": "demo-trader",
            }
        },
        {
            "name": "Game Exploit",
            "description": "Detect game botting and exploitation",
            "action": {
                "action_id": "demo-gaming-001",
                "domain": "gaming",
                "action_type": "execute_action",
                "parameters": {
                    "bot_detected": True,
                    "automated_farming": True,
                    "exploit_glitch": True
                },
                "actor_id": "demo-player",
            }
        },
        {
            "name": "Deepfake Attack",
            "description": "Detect deepfake and misinformation",
            "action": {
                "action_id": "demo-platform-001",
                "domain": "social_platform",
                "action_type": "post_content",
                "parameters": {
                    "deepfake": True,
                    "synthetic_media": True,
                    "impersonation": True
                },
                "actor_id": "demo-user",
            }
        },
        {
            "name": "Healthcare Fraud",
            "description": "Detect healthcare insurance fraud",
            "action": {
                "action_id": "demo-healthcare-001",
                "domain": "healthcare",
                "action_type": "submit_claim",
                "parameters": {
                    "upcoding": True,
                    "phantom_billing": True,
                    "inflate_charges": True
                },
                "actor_id": "demo-provider",
            }
        },
        {
            "name": "Insider Trading",
            "description": "Detect insider trading with non-public information",
            "action": {
                "action_id": "demo-financial-002",
                "domain": "financial_trading",
                "action_type": "place_order",
                "parameters": {
                    "uses_non_public_info": True,
                    "insider_trading": True
                },
                "actor_id": "demo-insider",
            }
        },
        {
            "name": "Legitimate Trading",
            "description": "A clean, legitimate trading action",
            "action": {
                "action_id": "demo-clean-001",
                "domain": "financial_trading",
                "action_type": "place_order",
                "parameters": {
                    "order_type": "market",
                    "side": "buy",
                    "quantity": 100
                },
                "actor_id": "demo-clean-trader",
            }
        },
    ]

    return {"demo_actions": demos}


@app.post("/api/demo-mode")
async def run_demo_mode():
    """Run demo mode - simulate multiple AI actions."""
    try:
        demo_actions = await get_demo_actions()
        results = []

        for demo in demo_actions["demo_actions"]:
            action_req = ActionRequest(**demo["action"])
            result = await evaluate_action(action_req)
            results.append({
                "name": demo["name"],
                "description": demo["description"],
                "result": result.dict()
            })

        return {"results": results, "total": len(results)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running demo mode: {str(e)}")


def get_frontend_html() -> str:
    """Get the frontend HTML with dark theme and modern UI."""
    # Read from static file if exists, otherwise return embedded HTML
    static_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    if os.path.exists(static_path):
        with open(static_path, "r") as f:
            return f.read()

    # Return embedded HTML (will be created separately)
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AI Safety Guardrails Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }

            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }

            @keyframes slideIn {
                from { opacity: 0; transform: translateX(-20px); }
                to { opacity: 1; transform: translateX(0); }
            }

            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }

            @keyframes shimmer {
                0% { background-position: -1000px 0; }
                100% { background-position: 1000px 0; }
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
                color: #e0e0e0;
                line-height: 1.6;
                min-height: 100vh;
            }

            .container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 2rem;
                animation: fadeIn 0.6s ease-out;
            }

            header {
                text-align: center;
                margin-bottom: 3rem;
                animation: fadeIn 0.8s ease-out;
            }

            h1 {
                background: linear-gradient(135deg, #60a5fa 0%, #a855f7 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                font-size: 2.8rem;
                margin-bottom: 0.5rem;
                font-weight: 800;
                letter-spacing: -0.5px;
            }

            .subtitle {
                color: #9ca3af;
                font-size: 1.1rem;
                font-weight: 300;
            }

            .dashboard {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 2rem;
            }

            @media (max-width: 1024px) {
                .dashboard { grid-template-columns: 1fr; }
            }

            .card {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border-radius: 16px;
                padding: 1.5rem;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(96, 165, 250, 0.1);
                transition: all 0.3s ease;
                animation: slideIn 0.6s ease-out;
                position: relative;
                overflow: hidden;
            }

            .card::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(96, 165, 250, 0.1), transparent);
                transition: left 0.5s;
            }

            .card:hover {
                transform: translateY(-4px);
                box-shadow: 0 12px 48px rgba(96, 165, 250, 0.2);
                border-color: rgba(96, 165, 250, 0.3);
            }

            .card:hover::before {
                left: 100%;
            }

            .card h2 {
                color: #60a5fa;
                margin-bottom: 1rem;
                font-size: 1.5rem;
                font-weight: 700;
            }

            .input-group { margin-bottom: 1rem; }

            label {
                display: block;
                color: #9ca3af;
                margin-bottom: 0.5rem;
                font-size: 0.9rem;
                font-weight: 500;
            }

            input, select, textarea {
                width: 100%;
                padding: 0.75rem;
                background: rgba(15, 15, 35, 0.8);
                border: 1px solid #2d2d44;
                border-radius: 8px;
                color: #e0e0e0;
                font-size: 1rem;
                transition: all 0.3s ease;
            }

            input:focus, select:focus, textarea:focus {
                outline: none;
                border-color: #60a5fa;
                box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.1);
            }

            textarea {
                min-height: 100px;
                font-family: 'Courier New', monospace;
                resize: vertical;
            }

            button {
                background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                color: white;
                border: none;
                padding: 0.75rem 1.5rem;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1rem;
                font-weight: 600;
                transition: all 0.3s ease;
                margin-right: 0.5rem;
                margin-top: 0.5rem;
                position: relative;
                overflow: hidden;
            }

            button::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                width: 0;
                height: 0;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.3);
                transform: translate(-50%, -50%);
                transition: width 0.6s, height 0.6s;
            }

            button:hover::after {
                width: 300px;
                height: 300px;
            }

            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4);
            }

            button:active {
                transform: translateY(0);
            }

            .demo-buttons {
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-top: 1rem;
            }

            .demo-btn {
                background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
                font-size: 0.9rem;
                padding: 0.6rem 1rem;
            }

            .result-card {
                margin-top: 1rem;
                padding: 1.5rem;
                border-radius: 12px;
                border-left: 4px solid;
                animation: fadeIn 0.5s ease-out;
                backdrop-filter: blur(10px);
            }

            .result-ALLOW {
                background: linear-gradient(135deg, rgba(6, 78, 59, 0.6) 0%, rgba(4, 120, 87, 0.4) 100%);
                border-color: #10b981;
            }

            .result-WARN {
                background: linear-gradient(135deg, rgba(120, 53, 15, 0.6) 0%, rgba(217, 119, 6, 0.4) 100%);
                border-color: #f59e0b;
            }

            .result-BLOCK {
                background: linear-gradient(135deg, rgba(127, 29, 29, 0.6) 0%, rgba(185, 28, 28, 0.4) 100%);
                border-color: #ef4444;
            }

            .result-ESCALATE {
                background: linear-gradient(135deg, rgba(88, 28, 135, 0.6) 0%, rgba(126, 34, 206, 0.4) 100%);
                border-color: #a855f7;
            }

            .result-label {
                font-weight: 700;
                font-size: 1.3rem;
                margin-bottom: 0.5rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .result-row { margin: 0.5rem 0; }
            .result-row strong { color: #9ca3af; }

            .logs-panel {
                max-height: 400px;
                overflow-y: auto;
                scrollbar-width: thin;
                scrollbar-color: #60a5fa #1a1a2e;
            }

            .logs-panel::-webkit-scrollbar {
                width: 8px;
            }

            .logs-panel::-webkit-scrollbar-track {
                background: #1a1a2e;
                border-radius: 4px;
            }

            .logs-panel::-webkit-scrollbar-thumb {
                background: #60a5fa;
                border-radius: 4px;
            }

            .log-entry {
                padding: 0.75rem;
                border-bottom: 1px solid rgba(45, 45, 68, 0.5);
                font-size: 0.9rem;
                animation: slideIn 0.3s ease-out;
                transition: background 0.2s ease;
            }

            .log-entry:hover {
                background: rgba(96, 165, 250, 0.05);
            }

            .log-entry:last-child { border-bottom: none; }

            .chart-container {
                height: 300px;
                margin-top: 1rem;
                position: relative;
            }

            .loading {
                text-align: center;
                color: #60a5fa;
                padding: 2rem;
                animation: pulse 2s infinite;
            }

            .spinner {
                display: inline-block;
                width: 40px;
                height: 40px;
                border: 4px solid rgba(96, 165, 250, 0.2);
                border-top-color: #60a5fa;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .full-width { grid-column: 1 / -1; }

            .live-indicator {
                display: inline-block;
                width: 8px;
                height: 8px;
                background: #10b981;
                border-radius: 50%;
                margin-right: 0.5rem;
                animation: pulse 2s infinite;
            }

            .stat-card {
                background: rgba(96, 165, 250, 0.1);
                padding: 1rem;
                border-radius: 8px;
                margin-bottom: 1rem;
                border: 1px solid rgba(96, 165, 250, 0.2);
            }

            .stat-number {
                font-size: 2rem;
                font-weight: 700;
                color: #60a5fa;
                margin-bottom: 0.25rem;
            }

            .stat-label {
                color: #9ca3af;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🛡️ AI Safety Guardrails Dashboard</h1>
                <p class="subtitle">Real-time detection and prevention of unethical AI behaviors</p>
            </header>

            <div class="dashboard">
                <!-- Input Section -->
                <div class="card">
                    <h2>Run Safety Check</h2>
                    <div class="input-group">
                        <label>Action Description</label>
                        <textarea id="actionDesc" placeholder='Enter AI action or use demo buttons below...'></textarea>
                    </div>
                    <div class="input-group">
                        <label>Domain</label>
                        <select id="domain">
                            <option value="financial_trading">Financial Trading</option>
                            <option value="gaming">Gaming</option>
                            <option value="healthcare">Healthcare</option>
                            <option value="social_platform">Social Platform</option>
                            <option value="business">Business</option>
                            <option value="general">General</option>
                        </select>
                    </div>
                    <button onclick="runCheck()">🔍 Run Safety Check</button>
                    <button onclick="runDemoMode()" style="background: #8b5cf6;">🎬 Run Demo Mode</button>

                    <div class="demo-buttons">
                        <button class="demo-btn" onclick="loadDemo(0)">💰 Financial Fraud</button>
                        <button class="demo-btn" onclick="loadDemo(1)">🎮 Game Exploit</button>
                        <button class="demo-btn" onclick="loadDemo(2)">🎭 Deepfake Attack</button>
                        <button class="demo-btn" onclick="loadDemo(3)">🏥 Healthcare Fraud</button>
                        <button class="demo-btn" onclick="loadDemo(4)">📊 Insider Trading</button>
                        <button class="demo-btn" onclick="loadDemo(5)">✅ Clean Action</button>
                    </div>
                </div>

                <!-- Results Section -->
                <div class="card">
                    <h2>Evaluation Result</h2>
                    <div id="result">
                        <p style="color: #9ca3af; text-align: center; padding: 2rem;">
                            Run a safety check to see results
                        </p>
                    </div>
                </div>

                <!-- Live Logs Section -->
                <div class="card full-width">
                    <h2><span class="live-indicator"></span>Live Action Logs</h2>
                    <div class="logs-panel" id="logs">
                        <p class="loading"><div class="spinner"></div></p>
                    </div>
                </div>

                <!-- Statistics Section -->
                <div class="card full-width">
                    <h2>📊 Statistics Dashboard</h2>
                    <div id="stats-summary" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
                        <div class="stat-card">
                            <div class="stat-number" id="stat-total">0</div>
                            <div class="stat-label">Total Evaluations</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number" id="stat-blocked" style="color: #ef4444;">0</div>
                            <div class="stat-label">Blocked Actions</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number" id="stat-allowed" style="color: #10b981;">0</div>
                            <div class="stat-label">Allowed Actions</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number" id="stat-warn" style="color: #f59e0b;">0</div>
                            <div class="stat-label">Warnings</div>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
                        <div class="chart-container">
                            <canvas id="decisionChart"></canvas>
                        </div>
                        <div class="chart-container">
                            <canvas id="domainChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let demoActions = [];
            let decisionChart = null;
            let domainChart = null;

            // Load demo actions on page load
            async function loadDemoActions() {
                try {
                    const response = await fetch('/api/demo-actions');
                    const data = await response.json();
                    demoActions = data.demo_actions;
                } catch (error) {
                    console.error('Error loading demo actions:', error);
                }
            }

            // Load a specific demo
            function loadDemo(index) {
                const demo = demoActions[index];
                if (!demo) return;

                document.getElementById('actionDesc').value = demo.description;
                document.getElementById('domain').value = demo.action.domain;
            }

            // Run safety check
            async function runCheck() {
                const actionDesc = document.getElementById('actionDesc').value.trim();
                const domain = document.getElementById('domain').value;

                if (!actionDesc) {
                    alert('Please enter an action description');
                    return;
                }

                document.getElementById('result').innerHTML = '<p class="loading">Evaluating...</p>';

                try {
                    const response = await fetch('/evaluate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            action_id: 'web-' + Date.now(),
                            domain: domain,
                            action_type: 'custom_action',
                            parameters: { description: actionDesc },
                            actor_id: 'web-user'
                        })
                    });

                    const result = await response.json();
                    displayResult(result);
                    await loadLogs();
                } catch (error) {
                    document.getElementById('result').innerHTML =
                        '<p style="color: #ef4444;">Error: ' + error.message + '</p>';
                }
            }

            // Display evaluation result
            function displayResult(result) {
                const html = `
                    <div class="result-card result-${result.decision}">
                        <div class="result-label">Decision: ${result.decision}</div>
                        <div class="result-row"><strong>Domain:</strong> ${result.domain}</div>
                        <div class="result-row"><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</div>
                        <div class="result-row"><strong>Severity:</strong> ${result.severity}</div>
                        <div class="result-row"><strong>Reason:</strong> ${result.reason}</div>
                        ${result.law ? '<div class="result-row"><strong>Law:</strong> ' + result.law + '</div>' : ''}
                        ${result.violations.length > 0 ? '<div class="result-row"><strong>Violations:</strong> ' + result.violations.join(', ') + '</div>' : ''}
                    </div>
                `;
                document.getElementById('result').innerHTML = html;
            }

            // Load logs
            async function loadLogs() {
                try {
                    const response = await fetch('/logs?limit=20');
                    const data = await response.json();

                    if (data.logs.length === 0) {
                        document.getElementById('logs').innerHTML =
                            '<p style="color: #9ca3af; text-align: center; padding: 1rem;">No logs yet</p>';
                        return;
                    }

                    const html = data.logs.map(log => {
                        const time = new Date(log.timestamp).toLocaleTimeString();
                        const decision = log.decision;
                        const color = decision === 'ALLOW' ? '#10b981' :
                                     decision === 'WARN' ? '#f59e0b' :
                                     decision === 'BLOCK' ? '#ef4444' : '#a855f7';

                        return `
                            <div class="log-entry">
                                <span style="color: #6b7280;">[${time}]</span>
                                <span style="color: ${color}; font-weight: 600;">${decision}</span>
                                <span style="color: #9ca3af;">→ ${log.domain}</span>
                                ${log.violations.length > 0 ?
                                    '<span style="color: #ef4444; font-size: 0.85rem;"> (' + log.violations.join(', ') + ')</span>' : ''}
                            </div>
                        `;
                    }).join('');

                    document.getElementById('logs').innerHTML = html;
                } catch (error) {
                    console.error('Error loading logs:', error);
                }
            }

            // Run demo mode
            async function runDemoMode() {
                document.getElementById('result').innerHTML = '<p class="loading">Running demo mode...</p>';

                try {
                    const response = await fetch('/api/demo-mode', { method: 'POST' });
                    const data = await response.json();

                    let html = '<div><h3 style="color: #60a5fa; margin-bottom: 1rem;">Demo Mode Results</h3>';
                    data.results.forEach(r => {
                        html += `
                            <div class="result-card result-${r.result.decision}" style="margin-bottom: 1rem;">
                                <div style="font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem;">${r.name}</div>
                                <div style="color: #9ca3af; font-size: 0.9rem;">${r.result.decision} - ${r.result.reason}</div>
                            </div>
                        `;
                    });
                    html += '</div>';

                    document.getElementById('result').innerHTML = html;
                    await loadLogs();
                } catch (error) {
                    document.getElementById('result').innerHTML =
                        '<p style="color: #ef4444;">Error: ' + error.message + '</p>';
                }
            }

            // Load and update statistics
            async function loadStats() {
                try {
                    const response = await fetch('/api/stats');
                    const data = await response.json();

                    // Update stat cards
                    document.getElementById('stat-total').textContent = data.total_evaluations;

                    const decisions = data.decision_distribution || {};
                    const blocked = (decisions.BLOCK || 0) + (decisions.ESCALATE || 0);
                    const allowed = decisions.ALLOW || 0;
                    const warned = decisions.WARN || 0;

                    document.getElementById('stat-blocked').textContent = blocked;
                    document.getElementById('stat-allowed').textContent = allowed;
                    document.getElementById('stat-warn').textContent = warned;

                    // Update decision chart
                    const decisionLabels = Object.keys(decisions);
                    const decisionData = Object.values(decisions);
                    const decisionColors = decisionLabels.map(label => {
                        switch(label) {
                            case 'ALLOW': return '#10b981';
                            case 'WARN': return '#f59e0b';
                            case 'BLOCK': return '#ef4444';
                            case 'ESCALATE': return '#a855f7';
                            default: return '#60a5fa';
                        }
                    });

                    if (decisionChart) {
                        decisionChart.data.labels = decisionLabels;
                        decisionChart.data.datasets[0].data = decisionData;
                        decisionChart.data.datasets[0].backgroundColor = decisionColors;
                        decisionChart.update();
                    } else {
                        const ctx1 = document.getElementById('decisionChart').getContext('2d');
                        decisionChart = new Chart(ctx1, {
                            type: 'doughnut',
                            data: {
                                labels: decisionLabels,
                                datasets: [{
                                    data: decisionData,
                                    backgroundColor: decisionColors,
                                    borderColor: '#1a1a2e',
                                    borderWidth: 2
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    legend: {
                                        position: 'bottom',
                                        labels: { color: '#9ca3af', padding: 15, font: { size: 12 } }
                                    },
                                    title: {
                                        display: true,
                                        text: 'Decision Distribution',
                                        color: '#60a5fa',
                                        font: { size: 16, weight: 'bold' }
                                    }
                                }
                            }
                        });
                    }

                    // Update domain chart
                    const domains = data.domain_distribution || {};
                    const domainLabels = Object.keys(domains);
                    const domainData = Object.values(domains);

                    if (domainChart) {
                        domainChart.data.labels = domainLabels;
                        domainChart.data.datasets[0].data = domainData;
                        domainChart.update();
                    } else {
                        const ctx2 = document.getElementById('domainChart').getContext('2d');
                        domainChart = new Chart(ctx2, {
                            type: 'bar',
                            data: {
                                labels: domainLabels,
                                datasets: [{
                                    label: 'Evaluations',
                                    data: domainData,
                                    backgroundColor: 'rgba(96, 165, 250, 0.6)',
                                    borderColor: '#60a5fa',
                                    borderWidth: 2
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    legend: {
                                        display: false
                                    },
                                    title: {
                                        display: true,
                                        text: 'Domain Distribution',
                                        color: '#60a5fa',
                                        font: { size: 16, weight: 'bold' }
                                    }
                                },
                                scales: {
                                    y: {
                                        beginAtZero: true,
                                        ticks: { color: '#9ca3af' },
                                        grid: { color: 'rgba(96, 165, 250, 0.1)' }
                                    },
                                    x: {
                                        ticks: { color: '#9ca3af' },
                                        grid: { display: false }
                                    }
                                }
                            }
                        });
                    }
                } catch (error) {
                    console.error('Error loading stats:', error);
                }
            }

            // Initialize
            loadDemoActions();
            loadLogs();
            loadStats();
            setInterval(() => {
                loadLogs();
                loadStats();
            }, 5000); // Refresh every 5 seconds
        </script>
    </body>
    </html>
    """


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
