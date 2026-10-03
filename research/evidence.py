"""
Evidence evaluation and claim-to-evidence comparison module for SachCheck.
Determines verification statuses deterministically based strictly on retrieved sources.
Enforces the mandatory rule: REGISTRATION ≠ ENDORSEMENT.
"""

from typing import List, Optional
import re

from research.models import (
    ExtractedClaim,
    SourceRecord,
    SourceType,
    VerificationStatus,
    ClaimVerificationResult,
)


class EvidenceEvaluator:
    """
    Evaluates extracted claims against real retrieved sources.
    No LLM is permitted to invent or alter verification statuses.
    """

    @classmethod
    def evaluate_claim(
        cls,
        claim: ExtractedClaim,
        sources: List[SourceRecord],
        is_search_successful: bool = True,
        search_error: Optional[str] = None,
    ) -> ClaimVerificationResult:
        """
        Evaluate a single claim against prioritized sources.
        """
        if not is_search_successful:
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.UNABLE_TO_VERIFY,
                source_title=None,
                source_url=None,
                source_domain=None,
                source_type=None,
                relevant_text=None,
                what_source_establishes="Live verification could not be completed.",
                what_source_does_not_establish="No external search evidence could be retrieved or evaluated.",
                retrieved_at=None,
            )

        if not sources:
            # NO SEARCH RESULT != FALSE, NO SEARCH RESULT != SCAM, NO SEARCH RESULT != CONTRADICTED
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.NOT_VERIFIED,
                source_title=None,
                source_url=None,
                source_domain=None,
                source_type=None,
                relevant_text=None,
                what_source_establishes="No external search results were retrieved for this targeted query.",
                what_source_does_not_establish="Does not disprove the claim; available public evidence was insufficient to verify.",
                retrieved_at=None,
            )

        # Route by claim type
        if claim.claim_type == "REGULATORY_REGISTRATION":
            return cls._evaluate_regulatory_claim(claim, sources)
        elif claim.claim_type == "GUARANTEED_RETURN":
            return cls._evaluate_guaranteed_return_claim(claim, sources)
        elif claim.claim_type == "GOVERNMENT_APPROVAL":
            return cls._evaluate_government_claim(claim, sources)
        elif claim.claim_type == "WITHDRAWAL_FEE":
            return cls._evaluate_withdrawal_fee_claim(claim, sources)
        elif claim.claim_type == "REMOTE_ACCESS_CLAIM":
            return cls._evaluate_remote_access_claim(claim, sources)
        else:
            return cls._evaluate_general_claim(claim, sources)

    @classmethod
    def _evaluate_regulatory_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        entity = claim.extracted_entity

        # Look for official regulator sources first (sebi.gov.in, rbi.org.in)
        regulator_sources = [s for s in sources if s.source_type == SourceType.OFFICIAL_REGULATOR]
        primary_source = regulator_sources[0] if regulator_sources else sources[0]

        # Case 1: Anonymous claim ("SEBI approved investment / scheme") without a specific entity
        if not entity:
            # Check if regulator source states that SEBI does not approve schemes/returns
            combined_content = " ".join([s.content for s in sources]).lower()
            if any(term in combined_content for term in ["does not approve", "prohibited", "illegal", "caution", "beware"]):
                return ClaimVerificationResult(
                    claim_id=claim.claim_id,
                    original_claim=claim.original_text,
                    claim_type=claim.claim_type,
                    status=VerificationStatus.CONTRADICTED,
                    source_title=primary_source.title,
                    source_url=primary_source.url,
                    source_domain=primary_source.domain,
                    source_type=primary_source.source_type,
                    relevant_text=cls._extract_snippet(primary_source.content, ["approve", "prohibit", "scheme", "guarantee"]),
                    what_source_establishes="Official regulatory guidance establishes that SEBI registers intermediaries but does NOT approve, endorse, or guarantee specific investment schemes or commercial returns.",
                    what_source_does_not_establish="Does not identify the anonymous sender, but confirms that claims of SEBI-approved schemes contradict regulatory rules.",
                    retrieved_at=primary_source.retrieved_at,
                )
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.NOT_VERIFIED,
                source_title=primary_source.title,
                source_url=primary_source.url,
                source_domain=primary_source.domain,
                source_type=primary_source.source_type,
                relevant_text=cls._extract_snippet(primary_source.content, ["sebi", "intermediary", "register"]),
                what_source_establishes="Generic regulatory references retrieved, but no specific registered entity was named in the message.",
                what_source_does_not_establish="Cannot verify registration without a specific legal entity name or SEBI registration number.",
                retrieved_at=primary_source.retrieved_at,
            )

        # Case 2: Named entity provided
        entity_lower = entity.lower()

        # Check if regulator source confirms registration
        for s in regulator_sources:
            content_lower = s.content.lower()
            title_lower = s.title.lower()
            # Strict entity match: entity name must appear in source content or title
            if entity_lower in content_lower or entity_lower in title_lower:
                # Check for negative/caution/debarment mentions
                if any(w in content_lower for w in ["debarred", "unregistered", "fake", "caution list", "prohibited", "scam"]):
                    return ClaimVerificationResult(
                        claim_id=claim.claim_id,
                        original_claim=claim.original_text,
                        claim_type=claim.claim_type,
                        status=VerificationStatus.CONTRADICTED,
                        source_title=s.title,
                        source_url=s.url,
                        source_domain=s.domain,
                        source_type=s.source_type,
                        relevant_text=cls._extract_snippet(s.content, ["debarred", "unregistered", "caution", entity_lower]),
                        what_source_establishes=f"Official regulatory source flags '{entity}' under cautionary, unauthorized, or debarment lists.",
                        what_source_does_not_establish="Does not represent a final criminal court verdict, but verifies official regulatory warning status.",
                        retrieved_at=s.retrieved_at,
                    )

                # Positive registration evidence
                if any(w in content_lower for w in ["registration no", "registered", "stock broker", "investment adviser", "research analyst", "recognized"]):
                    # MANDATORY RULE: REGISTRATION != ENDORSEMENT
                    return ClaimVerificationResult(
                        claim_id=claim.claim_id,
                        original_claim=claim.original_text,
                        claim_type=claim.claim_type,
                        status=VerificationStatus.VERIFIED,
                        source_title=s.title,
                        source_url=s.url,
                        source_domain=s.domain,
                        source_type=s.source_type,
                        relevant_text=cls._extract_snippet(s.content, [entity_lower, "registered", "registration"]),
                        what_source_establishes=f"The entity '{entity}' appears in the official regulator directory as a registered intermediary.",
                        what_source_does_not_establish="CRITICAL: SEBI registration does NOT constitute an endorsement, recommendation, or guarantee of returns for any investment or unsolicited WhatsApp/Telegram message.",
                        retrieved_at=s.retrieved_at,
                    )

        # If regulator sources didn't have positive or negative confirmation
        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, [entity_lower, "sebi", "register"]),
            what_source_establishes=f"Retrieved sources did not contain explicit official registration records for '{entity}'.",
            what_source_does_not_establish=f"Does not prove '{entity}' is fraudulent or non-existent, but official registration could not be verified from available records. Verify directly on sebi.gov.in.",
            retrieved_at=primary_source.retrieved_at,
        )

    @classmethod
    def _evaluate_guaranteed_return_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        """
        Evaluate guaranteed return claim against official market regulations.
        """
        primary_source = sources[0]
        combined = " ".join([s.content for s in sources]).lower()

        # Check if regulator explicitly states guaranteed returns are prohibited
        if any(w in combined for w in ["prohibited", "illegal", "cannot guarantee", "no guaranteed", "caution"]):
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.CONTRADICTED,
                source_title=primary_source.title,
                source_url=primary_source.url,
                source_domain=primary_source.domain,
                source_type=primary_source.source_type,
                relevant_text=cls._extract_snippet(primary_source.content, ["guarantee", "prohibit", "return", "risk"]),
                what_source_establishes="Official regulatory guidance establishes that promising fixed or guaranteed returns in securities markets is strictly prohibited.",
                what_source_does_not_establish="Does not trace the individual identity of the message sender, but verifies that the claim itself contradicts market regulations.",
                retrieved_at=primary_source.retrieved_at,
            )

        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, ["guaranteed", "return"]),
            what_source_establishes="Retrieved source content was insufficient to formally establish regulatory status.",
            what_source_does_not_establish="Does not establish legitimacy of the return claim.",
            retrieved_at=primary_source.retrieved_at,
        )

    @classmethod
    def _evaluate_government_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        primary_source = sources[0]
        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, ["government", "scheme", "approved"]),
            what_source_establishes="Public government sources did not confirm approval for this private investment opportunity.",
            what_source_does_not_establish="Does not prove whether the claim refers to an existing unrelated public scheme.",
            retrieved_at=primary_source.retrieved_at,
        )

    @classmethod
    def _evaluate_withdrawal_fee_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        primary_source = sources[0]
        combined = " ".join([s.content for s in sources]).lower()
        if any(w in combined for w in ["scam", "fraud", "caution", "advisory", "warning", "prohibited"]):
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.CONTRADICTED,
                source_title=primary_source.title,
                source_url=primary_source.url,
                source_domain=primary_source.domain,
                source_type=primary_source.source_type,
                relevant_text=cls._extract_snippet(primary_source.content, ["fee", "withdrawal", "scam", "caution"]),
                what_source_establishes="Official cybercrime and regulatory advisories confirm that requiring upfront fees, processing charges, or tax deposits to release profits contradicts legitimate financial market rules and represents a documented extortion pattern.",
                what_source_does_not_establish="Does not identify the individual behind the message, but confirms that the fee requirement contradicts legitimate broker operations.",
                retrieved_at=primary_source.retrieved_at,
            )
        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, ["withdrawal", "fee"]),
            what_source_establishes="Retrieved sources did not contain explicit official confirmation regarding this fee demand.",
            what_source_does_not_establish="Does not establish the legitimacy of the demanded processing fee.",
            retrieved_at=primary_source.retrieved_at,
        )

    @classmethod
    def _evaluate_remote_access_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        primary_source = sources[0]
        combined = " ".join([s.content for s in sources]).lower()
        if any(w in combined for w in ["scam", "fraud", "caution", "advisory", "warning", "never share", "prohibited", "illegal"]):
            return ClaimVerificationResult(
                claim_id=claim.claim_id,
                original_claim=claim.original_text,
                claim_type=claim.claim_type,
                status=VerificationStatus.CONTRADICTED,
                source_title=primary_source.title,
                source_url=primary_source.url,
                source_domain=primary_source.domain,
                source_type=primary_source.source_type,
                relevant_text=cls._extract_snippet(primary_source.content, ["remote access", "anydesk", "caution", "advisory"]),
                what_source_establishes="Official regulatory and cybercrime advisories establish that SEBI, RBI, and genuine banking intermediaries NEVER ask customers to install remote-access software (such as AnyDesk or TeamViewer) or share session codes to resolve account or KYC issues.",
                what_source_does_not_establish="Does not trace the caller's individual identity, but verifies that the demand for remote device control directly contradicts official regulatory security protocols.",
                retrieved_at=primary_source.retrieved_at,
            )
        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, ["remote", "support"]),
            what_source_establishes="Retrieved source content did not contain explicit official endorsement for remote-access support for this entity.",
            what_source_does_not_establish="Does not verify that remote access is authorized. Treat unsolicited remote-support requests with high caution.",
            retrieved_at=primary_source.retrieved_at,
        )

    @classmethod
    def _evaluate_general_claim(
        cls, claim: ExtractedClaim, sources: List[SourceRecord]
    ) -> ClaimVerificationResult:
        primary_source = sources[0]
        return ClaimVerificationResult(
            claim_id=claim.claim_id,
            original_claim=claim.original_text,
            claim_type=claim.claim_type,
            status=VerificationStatus.NOT_VERIFIED,
            source_title=primary_source.title,
            source_url=primary_source.url,
            source_domain=primary_source.domain,
            source_type=primary_source.source_type,
            relevant_text=cls._extract_snippet(primary_source.content, []),
            what_source_establishes="Source content was insufficient to verify or contradict this claim.",
            what_source_does_not_establish="Verification inconclusive based on available sources.",
            retrieved_at=primary_source.retrieved_at,
        )

    @staticmethod
    def _extract_snippet(content: str, keywords: List[str], max_len: int = 240) -> str:
        """
        Extracts an authentic substring snippet from real retrieved source content
        centered around keywords. Never generates artificial content.
        """
        if not content:
            return "No content snippet available in source."

        content_clean = " ".join(content.split())
        if not keywords:
            return content_clean[:max_len] + ("..." if len(content_clean) > max_len else "")

        for kw in keywords:
            idx = content_clean.lower().find(kw.lower())
            if idx != -1:
                start = max(0, idx - 60)
                end = min(len(content_clean), idx + max_len - 60)
                prefix = "..." if start > 0 else ""
                suffix = "..." if end < len(content_clean) else ""
                return f"{prefix}{content_clean[start:end]}{suffix}"

        return content_clean[:max_len] + ("..." if len(content_clean) > max_len else "")
