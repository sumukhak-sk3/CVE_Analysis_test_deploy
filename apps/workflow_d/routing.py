"""Routing decisions.

Combines verdict + confidence + verifier outcome + patch caps to produce a
single routing decision. Workflow D itself never writes code or upgrades
packages — it only emits the decision and the artifacts needed for the next
workflow (E) or human review.
"""
from __future__ import annotations

from dataclasses import dataclass

from .confidence import ConfidencePolicy, ConfidenceScores, all_above
from .schemas import (
    EvidenceBundle,
    FixProposal,
    RoutingDecision,
    RoutingResult,
    TriageResult,
    Verdict,
    VerifierResult,
    VerifierVerdict,
)
from .version_compare import already_at_or_above


@dataclass(frozen=True)
class RoutingPolicy:
    max_patch_lines: int = 500
    max_patch_files: int = 5


def decide(
    bundle: EvidenceBundle,
    triage: TriageResult,
    fix: FixProposal | None,
    verifier: VerifierResult | None,
    confidence: ConfidenceScores,
    policy: RoutingPolicy,
    confidence_policy: ConfidencePolicy,
) -> RoutingResult:
    verdict = triage.verdict

    # Suppression based on prior decisions could be added here.
    # Fix author may explicitly override to `needs_human`.
    if fix and fix.verdict_override:
        verdict = fix.verdict_override

    # Patch caps — applied regardless of confidence. The verdict stays
    # `code_change` (that IS the analyzer's classification); only the routing
    # decision flips to human_review.
    if verdict == Verdict.code_change and fix:
        total_lines = fix.lines_added + fix.lines_removed
        if total_lines > policy.max_patch_lines or len(fix.files_touched) > policy.max_patch_files:
            return RoutingResult(
                decision=RoutingDecision.human_review,
                final_verdict=verdict,
                reason=(
                    f"patch exceeds caps "
                    f"(lines={total_lines}>{policy.max_patch_lines} "
                    f"or files={len(fix.files_touched)}>{policy.max_patch_files})"
                ),
                auto_proceed=False,
            )

    # Verifier disagreement always blocks auto-proceed on code changes.
    if verdict == Verdict.code_change and verifier and verifier.verdict != VerifierVerdict.pass_:
        return RoutingResult(
            decision=RoutingDecision.human_review,
            final_verdict=verdict,
            reason=f"verifier returned '{verifier.verdict.value}'",
            auto_proceed=False,
        )

    # Confidence gate — fix_confidence only matters for code_change.
    confident = all_above(
        confidence,
        confidence_policy.auto_proceed_min,
        require_fix=(verdict == Verdict.code_change),
    )

    if verdict == Verdict.not_applicable:
        if confident:
            return RoutingResult(
                decision=RoutingDecision.suppress,
                final_verdict=verdict,
                reason="not_applicable with high confidence; suppressing",
                auto_proceed=True,
            )
        return RoutingResult(
            decision=RoutingDecision.human_review,
            final_verdict=verdict,
            reason="not_applicable but confidence below threshold",
            auto_proceed=False,
        )

    if verdict == Verdict.package_upgrade:
        # Ubuntu Security API is the authoritative source for OS-package fixes.
        # When it confirms a fixed version, the upgrade target does not depend
        # on the model's self-confidence — defer to the authority.
        ubuntu = bundle.ubuntu_security or {}
        ubuntu_authoritative = bool(
            ubuntu.get("ok") and ubuntu.get("fixed_version")
        )

        # Version sanity: if installed version already >= Ubuntu fixed,
        # the upgrade is a no-op — flip to not_applicable + suppress.
        current_version = (
            bundle.cve_event.component.current_version
            if bundle.cve_event and bundle.cve_event.component
            else None
        )
        if ubuntu_authoritative:
            at_or_above = already_at_or_above(current_version, ubuntu.get("fixed_version"))
            if at_or_above is True:
                return RoutingResult(
                    decision=RoutingDecision.suppress,
                    final_verdict=Verdict.not_applicable,
                    reason=(
                        f"installed {current_version} >= Ubuntu fixed "
                        f"{ubuntu.get('fixed_version')}; already patched"
                    ),
                    auto_proceed=True,
                )

        if confident or ubuntu_authoritative:
            return RoutingResult(
                decision=RoutingDecision.handoff_workflow_e,
                final_verdict=verdict,
                reason=(
                    "package_upgrade confirmed by Ubuntu Security authority"
                    if ubuntu_authoritative and not confident
                    else "package_upgrade ready for Workflow E"
                ),
                auto_proceed=True,
            )
        return RoutingResult(
            decision=RoutingDecision.human_review,
            final_verdict=verdict,
            reason="package_upgrade but confidence below threshold",
            auto_proceed=False,
        )

    if verdict == Verdict.code_change:
        if confident and verifier and verifier.verdict == VerifierVerdict.pass_:
            return RoutingResult(
                decision=RoutingDecision.handoff_workflow_e,
                final_verdict=verdict,
                reason="code_change verified and confident",
                auto_proceed=True,
            )
        return RoutingResult(
            decision=RoutingDecision.human_review,
            final_verdict=verdict,
            reason="code_change not eligible for auto-proceed",
            auto_proceed=False,
        )

    # needs_human and anything else
    return RoutingResult(
        decision=RoutingDecision.human_review,
        final_verdict=Verdict.needs_human,
        reason=triage.rationale or "explicit needs_human",
        auto_proceed=False,
    )
