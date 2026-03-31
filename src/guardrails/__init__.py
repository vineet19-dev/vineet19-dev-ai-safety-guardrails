"""AI Safety Guardrails – top-level package."""

from .pipeline import SafetyPipeline
from .ethical_framework import EthicsClassifier, EthicsVerdict
from .audit_logger import AuditLogger
from .web import run_server


def run_fastapi_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the FastAPI server with enhanced dashboard."""
    import uvicorn
    from .api import app
    uvicorn.run(app, host=host, port=port)


__all__ = ["SafetyPipeline", "EthicsClassifier", "EthicsVerdict", "AuditLogger", "run_server", "run_fastapi_server"]
