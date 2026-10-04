"""
Tavily Search Provider.
Encapsulates real web search queries using the official Tavily Python SDK.
Preserves authentic URLs, snippets, and domains without fabrication.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging

from config import Config
from research.models import SourceRecord, SourceType

logger = logging.getLogger(__name__)


class TavilyProvider:
    """
    Client wrapper for Tavily Search API.
    Handles network errors, rate limits, timeouts, and result normalization.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = (api_key if api_key is not None else Config.TAVILY_API_KEY).strip()
        self._client = None
        self._cache: Dict[str, List[SourceRecord]] = {}
        self._last_error: Optional[str] = None

        if self.is_configured():
            try:
                from tavily import TavilyClient
                self._client = TavilyClient(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize TavilyClient: {e}")
                self._last_error = f"Initialization error: {str(e)}"

    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is present."""
        return bool(self.api_key and len(self.api_key) > 5)

    def get_last_error(self) -> Optional[str]:
        return self._last_error

    def search(
        self,
        query: str,
        max_results: int = Config.TAVILY_MAX_RESULTS,
        search_depth: str = Config.TAVILY_SEARCH_DEPTH,
    ) -> Tuple[List[SourceRecord], Optional[str]]:
        """
        Execute real internet search via Tavily for the specified query.

        Args:
            query: The targeted search query string.
            max_results: Maximum number of search results to return.
            search_depth: 'advanced' or 'basic'.

        Returns:
            Tuple of (List of authentic SourceRecords, error message if any).
        """
        self._last_error = None
        cleaned_query = query.strip()
        if not cleaned_query:
            return [], None

        # Check in-memory session cache to conserve API credits
        cache_key = f"{cleaned_query}::{max_results}::{search_depth}"
        if cache_key in self._cache:
            logger.info(f"Returning cached Tavily results for query: {cleaned_query}")
            return self._cache[cache_key], None

        if not self.is_configured():
            self._last_error = "Tavily API key is not configured. Running in offline mode."
            return [], self._last_error

        if self._client is None:
            self._last_error = "Tavily client is not initialized."
            return [], self._last_error

        try:
            # Perform real web search with underlying source content
            response = self._client.search(
                query=cleaned_query,
                search_depth=search_depth,
                topic="general",
                max_results=max_results,
                include_answer=False,
                timeout=Config.TAVILY_TIMEOUT_SECONDS,
            )

            raw_results = response.get("results", []) if isinstance(response, dict) else []
            source_records: List[SourceRecord] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for item in raw_results:
                url = item.get("url", "").strip()
                title = item.get("title", "").strip() or "Untitled Source"
                content = item.get("content", "").strip()
                score = item.get("score")

                if not url:
                    continue

                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                if domain.startswith("www."):
                    domain = domain[4:]

                record = SourceRecord(
                    title=title,
                    url=url,
                    domain=domain,
                    content=content,
                    source_type=SourceType.UNVERIFIED_SOURCE,  # Classified downstream
                    retrieved_at=now_iso,
                    relevance_score=float(score) if score is not None else None,
                )
                source_records.append(record)

            # Store in cache
            self._cache[cache_key] = source_records
            return source_records, None

        except Exception as e:
            err_msg = str(e)
            logger.warning(f"Tavily search failed for '{cleaned_query}': {err_msg}")
            # Identify known error types safely
            err_lower = err_msg.lower()
            if "unauthorized" in err_lower or "invalid api key" in err_lower or "401" in err_lower:
                self._last_error = "Invalid Tavily API key provided."
            elif "rate limit" in err_lower or "429" in err_lower:
                self._last_error = "Tavily API rate limit reached. Please retry later."
            elif "timeout" in err_lower or "timed out" in err_lower:
                self._last_error = "Tavily search request timed out."
            else:
                self._last_error = f"Tavily search error: {err_msg}"

            return [], self._last_error
