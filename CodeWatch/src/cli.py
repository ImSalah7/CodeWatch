"""CodeWatch CLI - Enterprise SAST Platform."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import click

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except OSError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .__init__ import __version__
from .core.config import ScanConfig
from .core.engine import ScanEngine

console = Console(force_terminal=True)


def _prepare_target(target: str, quiet: bool = False) -> tuple[str, bool]:
    """Prepare target for scanning. Returns (local_path, is_temp_dir)."""
    target = target.rstrip(".")
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and "github.com" in parsed.netloc:
        temp_dir = tempfile.mkdtemp(prefix="codewatch_")
        try:
            if not quiet:
                console.print(f"[yellow]Cloning {target}...[/yellow]")
            subprocess.run(
                ["git", "clone", "--depth", "1", target, temp_dir],
                check=True,
                capture_output=True,
                timeout=120,
            )
            return temp_dir, True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to clone {target}: {e}") from e
    return target, False


@click.group()
@click.version_option(version=__version__, prog_name="CodeWatch")
def cli():
    """CodeWatch - Enterprise AI-Powered SAST Platform"""


@cli.command()
@click.argument("target")
@click.option("-o", "--output", help="Output file path")
@click.option("-f", "--format", "fmt", default="markdown",
              type=click.Choice(["markdown", "json", "sarif", "html", "csv"]),
              help="Report format")
@click.option("-l", "--local", is_flag=True, help="Scan a local directory")
@click.option("--no-deps", is_flag=True, help="Skip dependency scanning")
@click.option("--no-quality", is_flag=True, help="Skip quality scanning")
@click.option("--include-info", is_flag=True, help="Include INFO-severity findings (default: skipped for speed)")
@click.option("--no-secrets", is_flag=True, help="Skip secrets scanning")
@click.option("--no-security", is_flag=True, help="Skip security scanning")
@click.option("--include-tests", is_flag=True, help="Include test files")
@click.option("--include-docs", is_flag=True, help="Include documentation files")
@click.option("--severity", default="info",
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Minimum severity to report")
@click.option("--threads", default=4, help="Number of threads")
@click.option("--enterprise", is_flag=True, help="Enable enterprise-grade analysis (AST, data flow, taint tracking)")
@click.option("--secret-display", default=None,
              type=click.Choice(["full", "masked", "smart"]),
              help="Secret display mode (default: smart)")
@click.option("--show-secrets", "secret_display_override", flag_value="full",
              help="Show full secrets in reports (equivalent to --secret-display=full)")
@click.option("--developer-mode", "secret_display_override", flag_value="full",
              help="Developer mode: show all secrets for easy debugging")
def scan(target, output, fmt, local, no_deps, no_quality, include_info, no_secrets, no_security,
         include_tests, include_docs, severity, threads, enterprise,
         secret_display, secret_display_override):
    """Scan a repository or directory for security vulnerabilities and code quality issues."""
    from .core.models import SecretDisplayMode
    from .core.secret_display import SecretDisplayConfig

    if secret_display_override:
        display_config = SecretDisplayConfig.from_string(secret_display_override)
    elif secret_display:
        display_config = SecretDisplayConfig.from_string(secret_display)
    else:
        display_config = SecretDisplayConfig(SecretDisplayMode.SMART)

    local_path, is_temp = _prepare_target(target)
    try:
        config = ScanConfig(
            target=local_path,
            local=local or Path(local_path).exists(),
            skip_deps=no_deps,
            skip_quality=no_quality,
            skip_info=not include_info,
            skip_secrets=no_secrets,
            skip_security=no_security,
            include_tests=include_tests,
            include_docs=include_docs,
            severity_threshold=severity,
            threads=threads,
        )

        mode_label = f"[bold cyan]CodeWatch v{__version__}[/bold cyan]" if enterprise else f"[bold cyan]CodeWatch v{__version__}[/bold cyan]"
        console.print(Panel(f"{mode_label} - Enterprise SAST Platform", style="blue"))
        console.print(f"Target: [green]{target}[/green]")
        if enterprise:
            console.print("Mode: [yellow]Enterprise (AST + Data Flow + Taint)[/yellow]")
        if display_config.is_full:
            console.print("[bold red]WARNING: Full secret display is enabled. "
                          "Reports may expose sensitive credentials.[/bold red]")
        console.print()

        engine = ScanEngine(config, enterprise_mode=enterprise)

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=None)
                result = engine.scan(local_path)
                progress.update(task, completed=True)
        except FileNotFoundError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Scan error:[/bold red] {e}")
            sys.exit(1)

        from .core.secret_display import apply_secret_display_mode
        apply_secret_display_mode(result.findings, display_config.mode)
        result._secret_display_mode = display_config.mode.value

        _print_results(result)

        if output:
            output_path = Path(output)
            _save_report(result, output_path, fmt)
        else:
            report_dir = Path("codewatch_reports")
            report_dir.mkdir(exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S")
            _save_report(result, report_dir / f"report_{ts}", fmt)
    finally:
        if is_temp:
            shutil.rmtree(local_path, ignore_errors=True)


@cli.command()
@click.argument("target")
@click.option("--no-deps", is_flag=True)
@click.option("--severity", default="high", type=click.Choice(["critical", "high", "medium", "low", "info"]))
def quick(target, no_deps, severity):
    """Quick scan - show only high/critical findings."""
    local_path, is_temp = _prepare_target(target)
    try:
        config = ScanConfig(target=local_path, local=Path(local_path).exists(), skip_deps=no_deps, severity_threshold=severity)
        engine = ScanEngine(config)
        try:
            result = engine.scan(local_path)
        except FileNotFoundError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Scan error:[/bold red] {e}")
            sys.exit(1)

        critical_high = [f for f in result.security_findings if f.severity.value in ("critical", "high")]

        console.print(f"\n[bold]Risk Score: {result.risk_score}/100 | Grade: {result.grade}[/bold]\n")

        if critical_high:
            console.print(f"[red]Found {len(critical_high)} critical/high security issue(s):[/red]\n")
            for f in critical_high:
                icon = "[bold red]CRIT[/bold red]" if f.severity.value == "critical" else "[red]HIGH[/red]"
                console.print(f"  {icon}  {f.location.file_path}:{f.location.line}  {f.title}")
                if f.cwe:
                    console.print(f"        [dim]{f.cwe}[/dim]")
        else:
            console.print("[green]No critical or high security issues found.[/green]")
    finally:
        if is_temp:
            shutil.rmtree(local_path, ignore_errors=True)


@cli.command()
def info():
    """Show scanner information."""
    from .core.rules import ALL_RULES

    console.print(Panel(f"[bold cyan]CodeWatch v{__version__}[/bold cyan]", style="blue"))

    table = Table(title="Scanner Modules")
    table.add_column("Module", style="bold")
    table.add_column("Description")
    table.add_column("Rules", justify="right")

    categories = {}
    for r in ALL_RULES:
        cat = r.category.value
        categories[cat] = categories.get(cat, 0) + 1

    table.add_row("Security Scanner", "Pattern-based vulnerability detection with CWE/OWASP/CVSS", str(categories.get("security", 0)))
    table.add_row("Quality Scanner", "Code quality, complexity, and maintainability checks", str(categories.get("quality", 0)))
    table.add_row("Secrets Scanner", "Credential and secret detection with entropy analysis", str(sum(1 for r in ALL_RULES if "secret" in r.tags)))
    console.print(table)

    console.print(f"\n[bold]Total rules: {len(ALL_RULES)}[/bold]\n")

    console.print("[bold]Supported Languages:[/bold]")
    console.print("Python, JavaScript, TypeScript, React, Node.js, Java, Go, PHP, C#, Rust, C/C++, HTML, CSS, Docker, Terraform, YAML, Shell, Kotlin, Swift, Ruby\n")

    console.print("[bold]Export Formats:[/bold]")
    console.print("SARIF, HTML, JSON, CSV, Markdown\n")

    console.print("[bold]Severity Classification:[/bold]")
    for sev, score in [("CRITICAL", 25), ("HIGH", 15), ("MEDIUM", 8), ("LOW", 3), ("INFO", 1)]:
        console.print(f"  {sev:>10}  weight={score}")


def _print_results(result):
    sc = result.severity_counts
    sec = result.security_findings
    qual = result.quality_findings
    secs = result.secret_findings

    risk_color = "green" if result.risk_score < 15 else "yellow" if result.risk_score < 30 else "red"

    console.print()
    console.rule("[bold]CodeWatch Results[/bold]")
    console.print(f"\n[{risk_color} bold]Risk Score: {result.risk_score}/100 | Grade: {result.grade}[/{risk_color} bold]\n")

    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    style_map = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
    for sev, count in sc.items():
        table.add_row(sev.upper(), str(count), style=style_map.get(sev))
    table.add_row("TOTAL", str(sum(sc.values())), style="bold")
    console.print(table)

    summary_table = Table(title="Findings by Category")
    summary_table.add_column("Category", style="bold")
    summary_table.add_column("Count", justify="right")
    summary_table.add_row("Security", str(len(sec)))
    summary_table.add_row("Quality", str(len(qual)))
    summary_table.add_row("Secrets", str(len(secs)))
    console.print(summary_table)

    if sec:
        console.print("\n[bold red]Top Security Findings:[/bold red]")
        for f in sorted(sec, key=lambda x: x.severity.numeric)[:10]:
            sev_style = style_map.get(f.severity.value, "")
            console.print(f"  [{sev_style}]{f.severity.value.upper():>8}[/{sev_style}]  {f.location.file_path}:{f.location.line}  {f.title}")
            if f.cwe:
                console.print(f"  {'':>8}  [dim]{f.cwe} ({f.cwe_name})[/dim]")
            if f.fix_suggestion:
                console.print(f"  {'':>8}  [green]Fix: {f.fix_suggestion[:80]}[/green]")

    if secs:
        secret_display = getattr(result, '_secret_display_mode', 'smart')
        console.print("\n[bold yellow]Secrets Found:[/bold yellow]")
        for f in secs[:5]:
            console.print(f"  {f.location.file_path}:{f.location.line}  {f.title}")
            snippet = f.location.code_snippet or ""
            if snippet:
                console.print(f"  {'':>8}  [dim]Value: {snippet[:60]}[/dim]")
        if secret_display == "full":
            console.print("\n  [bold red]WARNING: Full secret display is enabled.[/bold red]")

    console.print(f"\n[dim]Scanned {result.files_scanned} files, {result.lines_scanned:,} lines in {result.scan_duration:.1f}s[/dim]")
    console.print(f"[dim]Languages: {', '.join(f'{k}: {v}' for k, v in sorted(result.languages_detected.items(), key=lambda x: x[1], reverse=True))}[/dim]")
    console.print()


def _save_report(result, output_path: Path, fmt: str):
    from .reporters import REPORTERS

    reporter_cls = REPORTERS.get(fmt)
    if not reporter_cls:
        console.print(f"[red]Unknown format: {fmt}[/red]")
        return

    reporter = reporter_cls()
    content = reporter.generate(result)
    suffix = f".{fmt}" if fmt != "sarif" else ".sarif"
    if fmt == "markdown":
        suffix = ".md"
    elif fmt == "html":
        suffix = ".html"
    elif fmt == "csv":
        suffix = ".csv"
    elif fmt == "json":
        suffix = ".json"

    final_path = output_path.with_suffix(suffix) if not output_path.suffix else output_path
    final_path.parent.mkdir(parents=True, exist_ok=True)
    final_path.write_text(content, encoding="utf-8")
    console.print(f"[green]Report saved to {final_path}[/green]")


def run_scan(target: str, local: bool = False, use_ai: bool = False, skip_deps: bool = False,
             skip_security: bool = False, skip_quality: bool = False, skip_secrets: bool = False,
             include_tests: bool = False, include_docs: bool = False, severity: str = "info",
             enterprise: bool = False, include_info: bool = False,
             secret_display: str = "smart") -> list[dict]:
    """Programmatic scan function for dashboard/API use."""
    from .core.secret_display import SecretDisplayConfig, apply_secret_display_mode

    display_config = SecretDisplayConfig.from_string(secret_display)

    local_path, is_temp = _prepare_target(target, quiet=True)
    try:
        config = ScanConfig(
            target=local_path,
            local=local or Path(local_path).exists(),
            skip_deps=skip_deps,
            skip_quality=skip_quality,
            skip_info=not include_info,
            skip_secrets=skip_secrets,
            skip_security=skip_security,
            include_tests=include_tests,
            include_docs=include_docs,
            severity_threshold=severity,
            threads=4,
        )
        engine = ScanEngine(config, enterprise_mode=enterprise)
        result = engine.scan(local_path)
        apply_secret_display_mode(result.findings, display_config.mode)
        result._secret_display_mode = display_config.mode.value
        return [f.to_dict() for f in result.findings]
    finally:
        if is_temp:
            shutil.rmtree(local_path, ignore_errors=True)


@cli.command()
@click.argument("target")
@click.option("--enterprise", is_flag=True, help="Use enterprise-grade analysis")
@click.option("--tools", default="semgrep,bandit",
              help="Comma-separated list of external tools to compare")
@click.option("-o", "--output", help="Output file path for benchmark results")
def benchmark(target, enterprise, tools, output):
    """Compare CodeWatch against other SAST tools (semgrep, bandit)."""
    from .core.benchmark import run_benchmark

    tool_list = [t.strip() for t in tools.split(",") if t.strip()]

    console.print(f"[bold]Running benchmark against: {', '.join(tool_list)}[/bold]")
    console.print(f"[dim]Target: {target}[/dim]\n")

    result = run_benchmark(target, enterprise=enterprise, tools=tool_list)

    console.rule("[bold]Benchmark Results[/bold]\n")

    ms = result.myscan_result
    if ms:
        console.print(f"[bold green]CodeWatch:[/bold green] {ms.finding_count} findings in {ms.scan_duration:.1f}s ({ms.file_count} files)")
        if ms.error:
            console.print(f"  [red]Error: {ms.error}[/red]")

    for name, ext in result.external_results.items():
        color = "green" if not ext.error else "red"
        console.print(f"[bold {color}]{name}:[/bold {color}] {ext.finding_count} findings in {ext.scan_duration:.1f}s ({ext.file_count} files)")
        if ext.error:
            console.print(f"  [yellow]Note: {ext.error}[/yellow]")

    if result.metrics:
        console.print()
        metrics_table = Table(title="Comparison Metrics")
        metrics_table.add_column("Metric", style="bold")
        for tool in result.metrics:
            metrics_table.add_column(tool, justify="right")

        metric_rows = [
            ("Overlap", "overlap"),
            ("Unique to CodeWatch", "unique_to_myscan"),
            ("Unique to External", "unique_to_external"),
            ("Est. Precision", "estimated_precision"),
            ("Est. Recall", "estimated_recall"),
            ("Est. F1", "estimated_f1"),
            ("File Coverage", "file_coverage"),
        ]
        for label, key in metric_rows:
            row = [label]
            for m in result.metrics.values():
                val = m.get(key, 0)
                if isinstance(val, float) and val < 1:
                    row.append(f"{val:.1%}")
                else:
                    row.append(str(val))
            metrics_table.add_row(*row)
        console.print(metrics_table)

    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"\n[green]Benchmark results saved to {out_path}[/green]")

    console.print(f"\n[dim]Total benchmark duration: {result.duration:.1f}s[/dim]")


@cli.group()
def users():
    """Manage user accounts and API keys (multi-user auth)."""


@users.command("create")
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--role", default="viewer", type=click.Choice(["admin", "operator", "viewer"]),
              help="Role for the new account")
def users_create(username, password, role):
    """Create a user account."""
    from . import store
    from . import users as userlib

    store.init_store()
    if len(password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise click.Abort()
    if store.get_user(username):
        console.print(f"[red]User already exists: {username}[/red]")
        raise click.Abort()
    store.create_user(username, userlib.hash_password(password), role)
    console.print(f"[green]Created user '{username}' with role '{role}'.[/green]")


@users.command("list")
def users_list():
    """List user accounts."""
    from . import store

    store.init_store()
    table = Table(title="Users")
    table.add_column("Username", style="bold")
    table.add_column("Role")
    table.add_column("Active")
    table.add_column("Created")
    for u in store.list_users():
        table.add_row(u["username"], u["role"], "yes" if u["active"] else "no", u["created_at"])
    console.print(table)


@users.command("set-password")
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def users_set_password(username, password):
    """Reset a user's password."""
    from . import store
    from . import users as userlib

    store.init_store()
    if len(password) < 8:
        console.print("[red]Password must be at least 8 characters.[/red]")
        raise click.Abort()
    if not store.update_user(username, password_hash=userlib.hash_password(password)):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    console.print(f"[green]Password updated for '{username}'.[/green]")


@users.command("set-role")
@click.argument("username")
@click.argument("role", type=click.Choice(["admin", "operator", "viewer"]))
def users_set_role(username, role):
    """Change a user's role."""
    from . import store

    store.init_store()
    if not store.update_user(username, role=role):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    console.print(f"[green]Role for '{username}' set to '{role}'.[/green]")


@users.command("disable")
@click.argument("username")
def users_disable(username):
    """Deactivate a user account."""
    from . import store

    store.init_store()
    if not store.update_user(username, active=0):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    console.print(f"[green]User '{username}' disabled.[/green]")


@users.command("enable")
@click.argument("username")
def users_enable(username):
    """Reactivate a user account."""
    from . import store

    store.init_store()
    if not store.update_user(username, active=1):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    console.print(f"[green]User '{username}' enabled.[/green]")


@users.command("delete")
@click.argument("username")
@click.confirmation_option(prompt="Delete this user and all their API keys?")
def users_delete(username):
    """Delete a user account and their API keys."""
    from . import store

    store.init_store()
    if not store.delete_user(username):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    console.print(f"[green]User '{username}' deleted.[/green]")


@users.command("add-key")
@click.argument("username")
@click.option("--label", default="", help="Optional label for the key")
def users_add_key(username, label):
    """Generate a new API key for a user (shown exactly once)."""
    from . import store
    from . import users as userlib

    store.init_store()
    if not store.get_user(username):
        console.print(f"[red]User not found: {username}[/red]")
        raise click.Abort()
    raw = userlib.generate_api_key()
    key_id = store.add_api_key(username, userlib.hash_api_key(raw), label)
    console.print(f"[green]API key for '{username}' (id {key_id}):[/green]")
    console.print(f"[cyan]{raw}[/cyan]")
    console.print("[yellow]Store this key now; only a hash is kept and it cannot be shown again.[/yellow]")


@users.command("list-keys")
@click.argument("username")
def users_list_keys(username):
    """List a user's API keys."""
    from . import store

    store.init_store()
    table = Table(title=f"API Keys - {username}")
    table.add_column("ID")
    table.add_column("Label")
    table.add_column("Created")
    table.add_column("Last Used")
    table.add_column("Revoked")
    for k in store.list_api_keys(username):
        table.add_row(
            str(k["id"]), k["label"], k["created_at"], k["last_used"],
            "yes" if k["revoked"] else "no",
        )
    console.print(table)


@users.command("revoke-key")
@click.argument("username")
@click.argument("key_id", type=int)
def users_revoke_key(username, key_id):
    """Revoke a user's API key."""
    from . import store

    store.init_store()
    if not store.revoke_api_key(username, key_id):
        console.print(f"[red]Key {key_id} not found for user '{username}'.[/red]")
        raise click.Abort()
    console.print(f"[green]Key {key_id} revoked.[/green]")


if __name__ == "__main__":
    cli()