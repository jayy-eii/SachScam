"""
Text highlighting utilities for displaying exact matched evidence.
Safely escapes all user input HTML and visually wraps matched risk patterns.
"""

import html
from typing import List, Tuple


def highlight_risk_evidence(
    text: str,
    spans: List[Tuple[int, int, str]],
) -> str:
    """
    Safely highlights matched phrases in the original message.

    Args:
        text: The original user-submitted message string.
        spans: List of tuples (start_idx, end_idx, category_name).

    Returns:
        HTML string with escaped text and highlighted <mark> tags.
    """
    if not text:
        return ""

    if not spans:
        return html.escape(text).replace("\n", "<br>")

    # Clean and filter invalid spans
    valid_spans = []
    text_len = len(text)
    for start, end, label in spans:
        if 0 <= start < end <= text_len:
            # Trim trailing whitespace from span if any
            matched_segment = text[start:end]
            trailing_ws = len(matched_segment) - len(matched_segment.rstrip())
            actual_end = end - trailing_ws
            if start < actual_end:
                valid_spans.append((start, actual_end, label))

    if not valid_spans:
        return html.escape(text).replace("\n", "<br>")

    # Sort spans by start asc, end desc
    sorted_spans = sorted(valid_spans, key=lambda s: (s[0], -s[1]))

    # Merge overlapping or contiguous spans
    merged_spans: List[Tuple[int, int, str]] = []
    for s_start, s_end, label in sorted_spans:
        if not merged_spans:
            merged_spans.append((s_start, s_end, label))
        else:
            prev_start, prev_end, prev_label = merged_spans[-1]
            if s_start <= prev_end:
                # Overlap: merge and combine labels if different
                combined_label = prev_label if prev_label == label else f"{prev_label}, {label}"
                merged_spans[-1] = (prev_start, max(prev_end, s_end), combined_label)
            else:
                merged_spans.append((s_start, s_end, label))

    # Construct HTML with safe escaping
    html_parts: List[str] = []
    curr_pos = 0

    for s_start, s_end, label in merged_spans:
        if s_start > curr_pos:
            unmatched = html.escape(text[curr_pos:s_start]).replace("\n", "<br>")
            html_parts.append(unmatched)

        matched_content = html.escape(text[s_start:s_end]).replace("\n", "<br>")
        safe_label = html.escape(label)
        html_parts.append(
            f'<mark class="risk-highlight" data-category="{safe_label}" '
            f'title="{safe_label}">{matched_content}</mark>'
        )
        curr_pos = s_end

    if curr_pos < len(text):
        remaining = html.escape(text[curr_pos:]).replace("\n", "<br>")
        html_parts.append(remaining)

    return "".join(html_parts)
