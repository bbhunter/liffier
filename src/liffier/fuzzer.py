"""Core fuzzer: dispatches requests and collects results."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from liffier.detector import Detection, analyze_response
from liffier.encodings import build_payloads


@dataclass
class FuzzResult:
    """Single fuzzing attempt result."""

    url: str
    payload: str
    encoding: str
    depth: int
    suffix: str
    status_code: int
    content_length: int
    elapsed_ms: int
    detection: Detection
    response_snippet: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "url": self.url,
            "payload": self.payload,
            "encoding": self.encoding,
            "depth": self.depth,
            "suffix": self.suffix,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "elapsed_ms": self.elapsed_ms,
            "hit": self.detection.hit,
            "confidence": self.detection.confidence,
            "reason": self.detection.reason,
            "matched_signature": self.detection.matched_signature,
            "response_snippet": self.response_snippet,
            "error": self.error,
        }
        return d


@dataclass
class FuzzConfig:
    """Fuzzer configuration."""

    url: str
    target_file: str
    max_depth: int = 10
    encodings: list[str] | None = None
    bypass_suffixes: bool = False
    workers: int = 10
    timeout: int = 10
    delay: float = 0.0
    proxy: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    follow_redirects: bool = False
    snippet_length: int = 200


class PathTraversalFuzzer:
    """Fuzz a URL parameter for path traversal vulnerabilities."""

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False
        if config.proxy:
            self.session.proxies = {
                "http": config.proxy,
                "https": config.proxy,
            }
        if config.cookies:
            self.session.cookies.update(config.cookies)
        if config.headers:
            self.session.headers.update(config.headers)
        self.baseline_length: int | None = None

    def _get_baseline(self) -> None:
        """Fetch baseline response for comparison."""
        try:
            test_url = self.config.url + "nonexistent_file_baseline_test_12345"
            resp = self.session.request(
                self.config.method,
                test_url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
            )
            self.baseline_length = len(resp.text)
        except Exception:
            self.baseline_length = None

    def _fuzz_single(self, payload_info: dict[str, str]) -> FuzzResult:
        """Send a single traversal request."""
        payload = payload_info["payload"]
        url = self.config.url + payload

        try:
            resp = self.session.request(
                self.config.method,
                url,
                timeout=self.config.timeout,
                allow_redirects=self.config.follow_redirects,
            )
            detection = analyze_response(
                status_code=resp.status_code,
                body=resp.text,
                target_file=self.config.target_file,
                baseline_length=self.baseline_length,
            )
            snippet = resp.text[:self.config.snippet_length].strip()
            return FuzzResult(
                url=url,
                payload=payload,
                encoding=payload_info["encoding"],
                depth=int(payload_info["depth"]),
                suffix=payload_info["suffix"],
                status_code=resp.status_code,
                content_length=len(resp.content),
                elapsed_ms=int(resp.elapsed.total_seconds() * 1000),
                detection=detection,
                response_snippet=snippet,
            )
        except requests.exceptions.Timeout:
            return FuzzResult(
                url=url,
                payload=payload,
                encoding=payload_info["encoding"],
                depth=int(payload_info["depth"]),
                suffix=payload_info["suffix"],
                status_code=0,
                content_length=0,
                elapsed_ms=self.config.timeout * 1000,
                detection=Detection(hit=False, confidence="high", reason="Timeout"),
                error="Request timed out",
            )
        except Exception as exc:
            return FuzzResult(
                url=url,
                payload=payload,
                encoding=payload_info["encoding"],
                depth=int(payload_info["depth"]),
                suffix=payload_info["suffix"],
                status_code=0,
                content_length=0,
                elapsed_ms=0,
                detection=Detection(hit=False, confidence="high", reason=str(exc)),
                error=str(exc),
            )

    def run(self, callback: Any = None) -> list[FuzzResult]:
        """Execute the fuzzing campaign.

        Args:
            callback: Optional callable(FuzzResult) invoked after each request.
        """
        payloads = build_payloads(
            target_file=self.config.target_file,
            max_depth=self.config.max_depth,
            encoding_names=self.config.encodings,
            use_bypass_suffixes=self.config.bypass_suffixes,
        )

        self._get_baseline()

        results: list[FuzzResult] = []

        with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
            futures = {}
            for i, payload_info in enumerate(payloads):
                if self.config.delay and i > 0:
                    time.sleep(self.config.delay)
                fut = pool.submit(self._fuzz_single, payload_info)
                futures[fut] = payload_info

            for fut in as_completed(futures):
                result = fut.result()
                results.append(result)
                if callback:
                    callback(result)

        return results


def export_results(results: list[FuzzResult], path: Path, fmt: str = "json") -> None:
    """Write results to a file."""
    records = [r.to_dict() for r in results]

    if fmt == "json":
        path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    elif fmt == "jsonl":
        with path.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
    elif fmt == "csv":
        import csv

        if not records:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
