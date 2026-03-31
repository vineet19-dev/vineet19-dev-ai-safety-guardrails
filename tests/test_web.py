"""Tests for minimal web frontend/backend helpers."""

from __future__ import annotations

import pytest

from guardrails.ethical_framework import Domain
from guardrails.pipeline import SafetyPipeline
from guardrails.web import build_action_from_payload, evaluate_payload


def test_build_action_from_payload_parses_domain_and_fields():
    action = build_action_from_payload(
        {
            "action_id": "web-001",
            "actor_id": "user-1",
            "domain": "gaming",
            "action_type": "play",
            "parameters": {"actions_per_minute": 100},
        }
    )
    assert action.action_id == "web-001"
    assert action.actor_id == "user-1"
    assert action.domain == Domain.GAMING
    assert action.parameters["actions_per_minute"] == 100


def test_build_action_from_payload_rejects_invalid_domain():
    with pytest.raises(ValueError, match="Invalid domain"):
        build_action_from_payload(
            {
                "action_id": "web-002",
                "actor_id": "user-2",
                "domain": "not-a-domain",
                "action_type": "do_thing",
            }
        )


def test_evaluate_payload_returns_json_safe_result():
    pipeline = SafetyPipeline()
    response = evaluate_payload(
        {
            "action_id": "web-003",
            "actor_id": "user-3",
            "domain": "financial_trading",
            "action_type": "place_order",
            "parameters": {"front_run": True},
        },
        pipeline,
    )
    assert response["allowed"] is False
    assert response["verdict"]["verdict"] in {"block", "escalate"}
    assert response["prevention"]["blocked_reason"]


def test_evaluate_payload_allows_clean_action():
    pipeline = SafetyPipeline()
    response = evaluate_payload(
        {
            "action_id": "web-004",
            "actor_id": "user-4",
            "domain": "gaming",
            "action_type": "game_action",
            "parameters": {"actions_per_minute": 120, "win_rate": 0.55},
        },
        pipeline,
    )
    assert response["allowed"] is True
    assert response["verdict"]["verdict"] == "allow"
    assert response["prevention"]["blocked_reason"] == ""
    assert response["prevention"]["escalated"] is False
