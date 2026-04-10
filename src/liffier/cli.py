"""CLI interface for Liffier."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import requests
from rich.console import Console
from rich.live import Live
from rich.table import Table

from liffier.encodings import TRAVERSAL_SEQUENCES, build_payloads, list_encodings
from liffier.fuzzer import FuzzConfig, FuzzResult, PathTraversalFuzzer, export_results

console = Console(stderr=True)
out = Console()

# Suppress InsecureRequestWarning for proxy usage
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Common LFI target files
DEFAULT_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/version",
    "../../../../etc/passwd",
]


def _parse_cookies(cookie_str: str) -> dict[str, str]:
    """Parse 'key=val; key2=val2' cookie string."""
    cookies = {}
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _parse_headers(header_list: tuple[str, ...]) -> dict[str, str]:
    """Parse 'Key: Value' header strings."""
    headers = {}
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------
@click.group()
@click.version_option(package_name="liffier")
def main() -> None:
    """Liffier - Path traversal / LFI fuzzer with encoding bypass techniques."""


# ---------------------------------------------------------------------------
# fuzz - main fuzzing command
# ---------------------------------------------------------------------------
@main.command()
@click.argument("url")
@click.option("--file", "-f", "target_file", default="/etc/passwd", show_default=True, help="Target file to read.")
@click.option("--depth", "-d", default=10, show_default=True, help="Max traversal depth (number of ../).")
@click.option("--encoding", "-e", multiple=True, help="Specific encodings to use (can repeat). Use 'list' to see all.")
@click.option("--bypass", "-b", is_flag=True, help="Enable null-byte and extension bypass suffixes.")
@click.option("--workers", "-w", default=10, show_default=True, help="Concurrent request threads.")
@click.option("--timeout", "-t", default=10, show_default=True, help="Per-request timeout (s).")
@click.option("--delay", default=0.0, help="Delay between requests (s).")
@click.option("--proxy", "-x", help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp/Caido).")
@click.option("--cookie", "-c", help="Cookies as 'key=val; key2=val2'.")
@click.option("--header", "-H", multiple=True, help="Extra headers as 'Key: Value' (can repeat).")
@click.option("--method", "-m", default="GET", show_default=True, help="HTTP method.")
@click.option("--follow-redirects", "-L", is_flag=True, help="Follow HTTP redirects.")
@click.option("--output", "-o", type=click.Path(), help="Save results to file.")
@click.option("--format", "fmt", type=click.Choice(["json", "jsonl", "csv"]), default="json", help="Output format.")
@click.option("--hits-only", is_flag=True, help="Only display detected hits.")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output - only hits, no table.")
def fuzz(
    url: str,
    target_file: str,
    depth: int,
    encoding: tuple[str, ...],
    bypass: bool,
    workers: int,
    timeout: int,
    delay: float,
    proxy: str | None,
    cookie: str | None,
    header: tuple[str, ...],
    method: str,
    follow_redirects: bool,
    output: str | None,
    fmt: str,
    hits_only: bool,
    quiet: bool,
) -> None:
    """Fuzz URL for path traversal / LFI vulnerabilities.

    URL should end at the injection point, e.g.:

    \b
      https://target.com/page?file=
      https://target.com/download/
      https://target.com/include.php?path=

    The tool appends traversal payloads to this URL.
    """
    enc_list = list(encoding) if encoding else None

    config = FuzzConfig(
        url=url,
        target_file=target_file,
        max_depth=depth,
        encodings=enc_list,
        bypass_suffixes=bypass,
        workers=workers,
        timeout=timeout,
        delay=delay,
        proxy=proxy,
        cookies=_parse_cookies(cookie) if cookie else {},
        headers=_parse_headers(header),
        method=method,
        follow_redirects=follow_redirects,
    )

    payloads = build_payloads(
        target_file=target_file,
        max_depth=depth,
        encoding_names=enc_list,
        use_bypass_suffixes=bypass,
    )

    console.print(f"[bold]Target:[/bold] {url}")
    console.print(f"[bold]File:[/bold] {target_file}")
    console.print(f"[bold]Payloads:[/bold] {len(payloads)} ({depth} depths x {len(enc_list) if enc_list else len(TRAVERSAL_SEQUENCES)} encodings{' x bypasses' if bypass else ''})")
    console.print(f"[bold]Workers:[/bold] {workers} | [bold]Timeout:[/bold] {timeout}s")
    if proxy:
        console.print(f"[bold]Proxy:[/bold] {proxy}")
    console.print()

    fuzzer = PathTraversalFuzzer(config)

    hits: list[FuzzResult] = []
    all_results: list[FuzzResult] = []
    count = 0

    def on_result(result: FuzzResult) -> None:
        nonlocal count
        count += 1
        all_results.append(result)
        if result.detection.hit:
            hits.append(result)
            if quiet:
                click.echo(f"[HIT] [{result.detection.confidence.upper()}] {result.encoding} d={result.depth} | {result.status_code} | {result.url}")
            else:
                console.print(
                    f"  [green][HIT][/green] [{result.detection.confidence.upper()}] "
                    f"{result.encoding} depth={result.depth} | "
                    f"HTTP {result.status_code} | {result.content_length}B | "
                    f"{result.detection.reason}"
                )
                if result.response_snippet:
                    console.print(f"    [dim]{result.response_snippet[:150]}[/dim]")
        elif not hits_only and not quiet:
            if count % 50 == 0:
                console.print(f"  [dim]{count}/{len(payloads)} tested, {len(hits)} hits so far...[/dim]")

    with console.status(f"[bold]Fuzzing {len(payloads)} payloads...[/bold]"):
        fuzzer.run(callback=on_result)

    # Summary
    console.print()
    if not quiet:
        if hits:
            table = Table(title=f"Hits ({len(hits)})", show_lines=True)
            table.add_column("Confidence", width=10)
            table.add_column("Encoding")
            table.add_column("Depth", width=6)
            table.add_column("Status", width=6)
            table.add_column("Size", width=8)
            table.add_column("Reason")
            table.add_column("URL", max_width=60, style="dim")

            for r in sorted(hits, key=lambda x: {"high": 0, "medium": 1, "low": 2}[x.detection.confidence]):
                conf_style = {"high": "red bold", "medium": "yellow", "low": "dim"}[r.detection.confidence]
                table.add_row(
                    f"[{conf_style}]{r.detection.confidence.upper()}[/{conf_style}]",
                    r.encoding,
                    str(r.depth),
                    str(r.status_code),
                    f"{r.content_length}B",
                    r.detection.reason,
                    r.url,
                )
            out.print(table)
        else:
            console.print("[yellow]No hits detected.[/yellow]")

    console.print(f"\n[bold]{len(hits)}[/bold] hits / {len(all_results)} tested")

    if output:
        results_to_save = hits if hits_only else all_results
        export_results(results_to_save, Path(output), fmt=fmt)
        console.print(f"Results saved to [cyan]{output}[/cyan]")


# ---------------------------------------------------------------------------
# scan - fuzz multiple common files at once
# ---------------------------------------------------------------------------
@main.command()
@click.argument("url")
@click.option("--files", "-f", multiple=True, help="Target files to test (can repeat). Defaults to common LFI targets.")
@click.option("--depth", "-d", default=8, show_default=True, help="Max traversal depth.")
@click.option("--encoding", "-e", multiple=True, help="Specific encodings to use.")
@click.option("--bypass", "-b", is_flag=True, help="Enable bypass suffixes.")
@click.option("--workers", "-w", default=10, show_default=True, help="Concurrent threads.")
@click.option("--timeout", "-t", default=10, show_default=True, help="Per-request timeout (s).")
@click.option("--proxy", "-x", help="HTTP proxy.")
@click.option("--cookie", "-c", help="Cookies.")
@click.option("--header", "-H", multiple=True, help="Extra headers.")
@click.option("--output", "-o", type=click.Path(), help="Save results to file.")
@click.option("--format", "fmt", type=click.Choice(["json", "jsonl", "csv"]), default="json")
def scan(
    url: str,
    files: tuple[str, ...],
    depth: int,
    encoding: tuple[str, ...],
    bypass: bool,
    workers: int,
    timeout: int,
    proxy: str | None,
    cookie: str | None,
    header: tuple[str, ...],
    output: str | None,
    fmt: str,
) -> None:
    """Quick scan: fuzz multiple common files against a URL.

    Tests /etc/passwd, /etc/shadow, /etc/hosts, /proc/self/environ,
    /proc/version, and win.ini by default.
    """
    target_files = list(files) if files else [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/proc/version",
        "win.ini",
        "boot.ini",
        ".env",
    ]

    enc_list = list(encoding) if encoding else None
    all_hits: list[FuzzResult] = []

    for tf in target_files:
        console.print(f"\n[bold cyan]--- Testing: {tf} ---[/bold cyan]")
        config = FuzzConfig(
            url=url,
            target_file=tf,
            max_depth=depth,
            encodings=enc_list,
            bypass_suffixes=bypass,
            workers=workers,
            timeout=timeout,
            proxy=proxy,
            cookies=_parse_cookies(cookie) if cookie else {},
            headers=_parse_headers(header),
        )

        fuzzer = PathTraversalFuzzer(config)
        results = fuzzer.run()
        hits = [r for r in results if r.detection.hit]
        all_hits.extend(hits)

        if hits:
            for r in hits:
                console.print(
                    f"  [green][HIT][/green] [{r.detection.confidence.upper()}] "
                    f"{r.encoding} d={r.depth} | HTTP {r.status_code} | {r.detection.reason}"
                )
        else:
            console.print(f"  [dim]No hits for {tf}[/dim]")

    console.print(f"\n[bold]Total: {len(all_hits)} hits across {len(target_files)} files[/bold]")

    if output and all_hits:
        export_results(all_hits, Path(output), fmt=fmt)
        console.print(f"Results saved to [cyan]{output}[/cyan]")


# ---------------------------------------------------------------------------
# encodings - list available encodings
# ---------------------------------------------------------------------------
@main.command()
def encodings() -> None:
    """List all available traversal encoding techniques."""
    table = Table(title="Traversal Encodings")
    table.add_column("Name", style="cyan")
    table.add_column("Sequence")
    table.add_column("Example (depth=3, /etc/passwd)")

    for name, seq in list_encodings():
        example = (seq * 3) + "/etc/passwd"
        table.add_row(name, repr(seq), example[:80])
    out.print(table)


# ---------------------------------------------------------------------------
# payloads - generate payloads to stdout (for use with other tools)
# ---------------------------------------------------------------------------
@main.command()
@click.option("--file", "-f", "target_file", default="/etc/passwd", show_default=True, help="Target file.")
@click.option("--depth", "-d", default=10, show_default=True, help="Max depth.")
@click.option("--encoding", "-e", multiple=True, help="Specific encodings.")
@click.option("--bypass", "-b", is_flag=True, help="Include bypass suffixes.")
@click.option("--prefix", default="", help="Prefix prepended to each payload.")
def payloads(
    target_file: str,
    depth: int,
    encoding: tuple[str, ...],
    bypass: bool,
    prefix: str,
) -> None:
    """Generate traversal payloads to stdout (one per line, pipe-friendly).

    Useful for feeding into other tools like ffuf, Burp Intruder, etc.

    \b
      liffier payloads -f /etc/passwd | ffuf -u https://target/file=FUZZ -w -
    """
    enc_list = list(encoding) if encoding else None
    payload_list = build_payloads(
        target_file=target_file,
        max_depth=depth,
        encoding_names=enc_list,
        use_bypass_suffixes=bypass,
    )
    for p in payload_list:
        click.echo(f"{prefix}{p['payload']}")
