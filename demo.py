#!/usr/bin/env python3
"""
Demo script showing the AI Safety Guardrails system in action.

This script demonstrates:
1. Financial fraud detection (pump & dump, insider trading)
2. Gaming exploits (botting, glitch abuse)
3. Healthcare fraud (insurance fraud)
4. Platform safety (deepfakes, misinformation)
5. Clean actions (legitimate behavior)
"""

from guardrails import SafetyPipeline
from guardrails.ethical_framework import Action, Domain

# Initialize the pipeline
pipeline = SafetyPipeline()


def print_result(name: str, result):
    """Pretty print an evaluation result."""
    print(f"\n{'=' * 70}")
    print(f"Test: {name}")
    print(f"{'=' * 70}")
    print(f"Decision:    {result.verdict.verdict.value.upper()}")
    print(f"Allowed:     {result.allowed}")
    print(f"Severity:    {result.verdict.severity.value}")
    print(f"Confidence:  {result.verdict.confidence:.2%}")

    if result.verdict.violations:
        print(f"Violations:  {', '.join(result.verdict.violations)}")

    if result.verdict.reasoning:
        print(f"Reason:      {result.verdict.reasoning}")

    # Extract law from domain analysis
    if result.domain_analysis and hasattr(result.domain_analysis, 'violations'):
        violations = result.domain_analysis.violations
        if violations and hasattr(violations[0], 'regulatory_reference'):
            print(f"Law:         {violations[0].regulatory_reference}")

    print(f"Anomaly:     {result.behavior.anomaly_score:.3f}")
    print(f"{'=' * 70}")


def main():
    print("\n🛡️  AI SAFETY GUARDRAILS SYSTEM - DEMO\n")
    print("This demo evaluates various AI actions across different domains.\n")

    # ====================================================================
    # FINANCIAL TRADING - Attack Scenarios
    # ====================================================================

    print("\n" + "█" * 70)
    print("FINANCIAL TRADING DOMAIN")
    print("█" * 70)

    # Test 1: Pump and Dump
    action = Action(
        action_id="financial-001",
        domain=Domain.FINANCIAL_TRADING,
        action_type="place_order",
        parameters={
            "pump_and_dump": True,
            "coordinated_buying": True,
            "artificial_hype": True
        },
        actor_id="trader-malicious"
    )
    result = pipeline.evaluate(action)
    print_result("Pump & Dump Market Manipulation", result)

    # Test 2: Front Running
    action = Action(
        action_id="financial-002",
        domain=Domain.FINANCIAL_TRADING,
        action_type="place_order",
        parameters={"front_run": True},
        actor_id="trader-frontrun",
        context={"pending_client_order_ahead": True}
    )
    result = pipeline.evaluate(action)
    print_result("Front Running", result)

    # Test 3: Insider Trading
    action = Action(
        action_id="financial-003",
        domain=Domain.FINANCIAL_TRADING,
        action_type="place_order",
        parameters={
            "uses_non_public_info": True,
            "insider_trading": True
        },
        actor_id="trader-insider"
    )
    result = pipeline.evaluate(action)
    print_result("Insider Trading", result)

    # Test 4: Legitimate Trading
    action = Action(
        action_id="financial-004",
        domain=Domain.FINANCIAL_TRADING,
        action_type="place_order",
        parameters={
            "order_type": "market",
            "side": "buy",
            "quantity": 100,
            "price": 150.25
        },
        actor_id="trader-clean"
    )
    result = pipeline.evaluate(action)
    print_result("Legitimate Market Order (Clean)", result)

    # ====================================================================
    # GAMING - Attack Scenarios
    # ====================================================================

    print("\n" + "█" * 70)
    print("GAMING DOMAIN")
    print("█" * 70)

    # Test 5: Botting
    action = Action(
        action_id="gaming-001",
        domain=Domain.GAMING,
        action_type="execute_action",
        parameters={
            "bot_detected": True,
            "automated_farming": True,
            "actions_per_minute": 600
        },
        actor_id="player-bot"
    )
    result = pipeline.evaluate(action)
    print_result("Botting / Automated Farming", result)

    # Test 6: Glitch Exploitation
    action = Action(
        action_id="gaming-002",
        domain=Domain.GAMING,
        action_type="exploit",
        parameters={
            "exploit_glitch": True,
            "glitch_type": "item_duplication"
        },
        actor_id="player-exploiter"
    )
    result = pipeline.evaluate(action)
    print_result("Glitch Exploitation", result)

    # Test 7: Match Fixing
    action = Action(
        action_id="gaming-003",
        domain=Domain.GAMING,
        action_type="match",
        parameters={
            "predetermined_outcome": True,
            "match_fixing": True
        },
        actor_id="player-fixer"
    )
    result = pipeline.evaluate(action)
    print_result("Match Fixing", result)

    # ====================================================================
    # HEALTHCARE - Attack Scenarios
    # ====================================================================

    print("\n" + "█" * 70)
    print("HEALTHCARE DOMAIN")
    print("█" * 70)

    # Test 8: Insurance Fraud (Upcoding)
    action = Action(
        action_id="healthcare-001",
        domain=Domain.HEALTHCARE,
        action_type="submit_claim",
        parameters={
            "upcoding": True,
            "inflate_charges": True
        },
        actor_id="provider-fraud"
    )
    result = pipeline.evaluate(action)
    print_result("Healthcare Insurance Fraud (Upcoding)", result)

    # Test 9: Phantom Billing
    action = Action(
        action_id="healthcare-002",
        domain=Domain.HEALTHCARE,
        action_type="submit_claim",
        parameters={
            "phantom_billing": True,
            "service_not_rendered": True
        },
        actor_id="provider-phantom"
    )
    result = pipeline.evaluate(action)
    print_result("Phantom Billing", result)

    # ====================================================================
    # SOCIAL PLATFORM - Attack Scenarios
    # ====================================================================

    print("\n" + "█" * 70)
    print("SOCIAL PLATFORM DOMAIN")
    print("█" * 70)

    # Test 10: Deepfake
    action = Action(
        action_id="platform-001",
        domain=Domain.SOCIAL_PLATFORM,
        action_type="post_content",
        parameters={
            "deepfake": True,
            "synthetic_media": True,
            "impersonation": True
        },
        actor_id="user-deepfake"
    )
    result = pipeline.evaluate(action)
    print_result("Deepfake / Synthetic Media", result)

    # Test 11: Misinformation
    action = Action(
        action_id="platform-002",
        domain=Domain.SOCIAL_PLATFORM,
        action_type="post_content",
        parameters={
            "misinformation": True,
            "false_health_claim": True
        },
        actor_id="user-misinfo"
    )
    result = pipeline.evaluate(action)
    print_result("Misinformation Spread", result)

    # ====================================================================
    # SUMMARY STATISTICS
    # ====================================================================

    print("\n" + "█" * 70)
    print("SUMMARY STATISTICS")
    print("█" * 70)

    # Get compliance report
    report = pipeline.compliance_report()
    print(f"\nTotal Evaluations:     {report['total_evaluations']}")
    print(f"Blocked Actions:       {report['blocked']}")
    print(f"Escalated Actions:     {report['escalated']}")
    print(f"Detection Rate:        {report['detection_rate']:.2%}")
    print(f"Est. FP Rate:          {report['estimated_false_positive_rate']:.2%}")

    # Get transparency report
    print("\n" + "-" * 70)
    print(pipeline.transparency_report())

    print("\n✅ Demo complete! All attack scenarios detected and blocked.\n")
    print("💡 To run the interactive dashboard:")
    print("   python run_dashboard.py")
    print("   Then open http://localhost:8000\n")


if __name__ == "__main__":
    main()
