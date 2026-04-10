"""Response analysis to detect successful path traversal."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Signatures that indicate a successful file read per common target files
SIGNATURES: dict[str, list[str]] = {
    "/etc/passwd": ["root:x:0:0:", "root:*:0:0:", "daemon:", "nobody:"],
    "/etc/shadow": ["root:$", "root:!", "root:*:"],
    "/etc/hosts": ["127.0.0.1", "localhost"],
    "/etc/hostname": [],  # any non-error content
    "/proc/self/environ": ["PATH=", "HOME=", "USER="],
    "/proc/version": ["Linux version"],
    "/proc/self/cmdline": [],
    "win.ini": ["[fonts]", "[extensions]", "[files]"],
    "boot.ini": ["[boot loader]", "[operating systems]", "WINDOWS"],
    "C:\\Windows\\System32\\drivers\\etc\\hosts": ["127.0.0.1", "localhost"],
    "web.xml": ["<web-app", "<servlet"],
    ".env": ["APP_KEY=", "DB_PASSWORD=", "DB_HOST="],
}

# Generic error patterns that indicate the traversal did NOT work
ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(404|not\s*found)", re.IGNORECASE),
    re.compile(r"(403|forbidden|access\s*denied)", re.IGNORECASE),
    re.compile(r"(400|bad\s*request)", re.IGNORECASE),
    re.compile(r"(500|internal\s*server\s*error)", re.IGNORECASE),
    re.compile(r"<html[^>]*>.*<title>.*error.*</title>", re.IGNORECASE | re.DOTALL),
]


@dataclass
class Detection:
    """Result of analyzing a response for traversal success."""

    hit: bool
    confidence: str  # "high", "medium", "low"
    reason: str
    matched_signature: str = ""


def analyze_response(
    status_code: int,
    body: str,
    target_file: str,
    baseline_length: int | None = None,
) -> Detection:
    """Analyze an HTTP response to determine if traversal succeeded.

    Args:
        status_code: HTTP response status code.
        body: Response body text.
        target_file: The file being targeted (e.g. /etc/passwd).
        baseline_length: Length of a known-bad response for comparison.
    """
    # Non-200 is almost certainly not a hit
    if status_code >= 400:
        return Detection(hit=False, confidence="high", reason=f"HTTP {status_code}")

    # Check for known error patterns in body
    for pat in ERROR_PATTERNS:
        if pat.search(body[:2000]):
            return Detection(hit=False, confidence="medium", reason=f"Error pattern: {pat.pattern[:40]}")

    # Check for file-specific signatures
    normalized = target_file.replace("\\", "/").strip("/").split("/")[-1]
    for sig_file, sigs in SIGNATURES.items():
        sig_normalized = sig_file.replace("\\", "/").strip("/").split("/")[-1]
        if normalized == sig_normalized or target_file.endswith(sig_normalized):
            for sig in sigs:
                if sig in body:
                    return Detection(
                        hit=True,
                        confidence="high",
                        reason=f"Signature match for {sig_file}",
                        matched_signature=sig,
                    )
            # File matched but no signature found
            if sigs:  # has signatures but none matched
                break
            # No specific signatures (like /etc/hostname) - check body isn't empty
            if len(body.strip()) > 0 and status_code == 200:
                return Detection(
                    hit=True,
                    confidence="medium",
                    reason=f"Non-empty 200 response for {sig_file} (no specific signature)",
                )

    # Baseline length comparison - significant difference suggests different content
    if baseline_length is not None and len(body) != baseline_length:
        diff_ratio = abs(len(body) - baseline_length) / max(baseline_length, 1)
        if diff_ratio > 0.3 and len(body) > 50:
            return Detection(
                hit=True,
                confidence="low",
                reason=f"Response length differs from baseline ({len(body)} vs {baseline_length}, {diff_ratio:.0%} diff)",
            )

    # 200 with content but no signature match
    if status_code == 200 and len(body.strip()) > 100:
        return Detection(
            hit=False,
            confidence="low",
            reason="200 OK but no signature match - review manually",
        )

    return Detection(hit=False, confidence="medium", reason="No indicators of success")
