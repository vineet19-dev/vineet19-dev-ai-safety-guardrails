#!/usr/bin/env python3
"""
AI Safety Guardrails Dashboard Runner

Run this script to start the FastAPI-based dashboard with modern UI.
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("🛡️  Starting AI Safety Guardrails Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:8000")
    print("🔍 API documentation: http://localhost:8000/docs")
    print("⚡ Press CTRL+C to stop\n")

    try:
        uvicorn.run(
            "guardrails.api:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
        sys.exit(0)
