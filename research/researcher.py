"""
Research orchestrator for Phase 2 Live Evidence-Based Claim Verification.
Coordinates claim extraction, targeted queries, Tavily search, source prioritization,
and deterministic evidence evaluation without altering the Phase 1 risk score.
"""

from typing import List, Optional, Set
import logging

from research.models import (
    ResearchReport,
    ClaimVerificationResult,
    SourceRecord,
    ExtractedUrlInfo,
    VerificationStatus,
)
from research.claim_extractor import extract_claims, extract_urls
from research.source_filter import prioritize_sources
from research.evidence import EvidenceEvaluator
from research.providers.tavily_provider import TavilyProvider

logger = logging.getLogger(__name__)


class MessageResearcher:
    """
    Orchestrates live internet research on factual claims using Tavily.
    """

    def __init__(self, provider: Optional[TavilyProvider] = None):
        self.provider = provider if provider is not None else TavilyProvider()

    def research_message(self, text: str) -> ResearchReport:
        """
        Execute full Phase 2 research pipeline on a user message.

        Steps:
        1. Extract URLs and analyze structure
        2. Extract factual claims and entities
        3. Check Tavily configuration (Live vs Offline)
        4. Execute targeted searches (if live)
        5. Prioritize official regulator & government domains
        6. Deterministically evaluate evidence per claim
        7. Compile traceable ResearchReport
        """
        cleaned_text = text.strip() if text else ""
        if not cleaned_text:
            return ResearchReport(
                is_live=False,
                mode_label="OFFLINE MODE — LIVE WEB VERIFICATION NOT CONFIGURED",
                claims=[],
                sources=[],
                extracted_urls=[],
                steps_performed=["No text provided for external research."],
                error_message=None,
                summary="No text provided to research.",
            )

        steps_performed: List[str] = []

        # Step 1: Extract URLs
        extracted_urls = extract_urls(cleaned_text)
        if extracted_urls:
            steps_performed.append(f"Extracted and inspected {len(extracted_urls)} URL(s) from message.")

        # Step 2: Extract factual claims
        claims = extract_claims(cleaned_text)
        if claims:
            steps_performed.append(f"Extracted {len(claims)} verifiable factual claim(s) and relevant entities.")

        # Step 3: Check Tavily configuration
        if not self.provider.is_configured():
            steps_performed.append("Live web verification is not configured (TAVILY_API_KEY missing).")
            # Generate offline / not-configured results for extracted claims
            unverified_claims: List[ClaimVerificationResult] = []
            for c in claims:
                unverified_claims.append(
                    ClaimVerificationResult(
                        claim_id=c.claim_id,
                        original_claim=c.original_text,
                        claim_type=c.claim_type,
                        status=VerificationStatus.UNABLE_TO_VERIFY,
                        source_title=None,
                        source_url=None,
                        source_domain=None,
                        source_type=None,
                        relevant_text=None,
                        what_source_establishes="Live verification could not be completed (offline mode).",
                        what_source_does_not_establish="Tavily API key is not configured. External internet sources were not queried.",
                        retrieved_at=None,
                    )
                )

            return ResearchReport(
                is_live=False,
                mode_label="OFFLINE MODE — LIVE WEB VERIFICATION NOT CONFIGURED",
                claims=unverified_claims,
                sources=[],
                extracted_urls=extracted_urls,
                steps_performed=steps_performed,
                error_message="TAVILY_API_KEY not configured. Running in offline evaluation mode.",
                summary="External research was skipped because Tavily API key is not configured.",
            )

        # Step 4: Execute Live Research
        steps_performed.append("Generated targeted search queries without sensitive credentials.")
        steps_performed.append("Executed real web searches using Tavily Search API.")

        all_retrieved_sources: List[SourceRecord] = []
        verified_claims: List[ClaimVerificationResult] = []
        seen_urls: Set[str] = set()
        search_error: Optional[str] = None

        for claim in claims:
            claim_sources: List[SourceRecord] = []
            for query in claim.search_queries[:2]:  # Limit to top 2 targeted queries per claim to conserve requests
                sources, err = self.provider.search(query=query)
                if err:
                    search_error = err
                for src in sources:
                    if src.url not in seen_urls:
                        seen_urls.add(src.url)
                        all_retrieved_sources.append(src)
                    claim_sources.append(src)

            # Step 5: Prioritize sources
            prioritized_claim_sources = prioritize_sources(claim_sources)

            # Step 6: Evaluate claim
            is_successful = (search_error is None) or bool(prioritized_claim_sources)
            eval_result = EvidenceEvaluator.evaluate_claim(
                claim=claim,
                sources=prioritized_claim_sources,
                is_search_successful=is_successful,
                search_error=search_error,
            )
            verified_claims.append(eval_result)

        # Prioritize full sources list for reporting
        final_prioritized_sources = prioritize_sources(all_retrieved_sources)

        if final_prioritized_sources:
            steps_performed.append(f"Retrieved {len(final_prioritized_sources)} authentic source records.")
            steps_performed.append("Classified domains and prioritized official regulatory & government sources.")
            steps_performed.append("Compared retrieved official source content against extracted claims.")
            steps_performed.append("Assigned deterministic claim verification statuses.")
        elif search_error:
            steps_performed.append(f"External search encountered an issue: {search_error}")
        else:
            steps_performed.append("External search completed but returned zero matching source records.")

        summary_text = (
            f"Evaluated {len(verified_claims)} claim(s) across {len(final_prioritized_sources)} external source(s)."
            if verified_claims else "No verifiable factual claims detected in message."
        )

        return ResearchReport(
            is_live=True,
            mode_label="LIVE WEB VERIFICATION",
            claims=verified_claims,
            sources=final_prioritized_sources,
            extracted_urls=extracted_urls,
            steps_performed=steps_performed,
            error_message=search_error,
            summary=summary_text,
        )
