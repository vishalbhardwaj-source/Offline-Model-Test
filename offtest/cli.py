import json
import shutil
import sys
from pathlib import Path
import click

from offtest.checks.planner import get_tool_manifest
from offtest.core.evidence_store import EvidenceStore
from offtest.core.models import CheckStatus, Severity
from offtest.orchestrator import AssessmentOrchestrator
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.issue_focused import IssueFocusedReportGenerator


@click.group()
@click.version_option(version="0.2.0", prog_name="offtest")
def main():
    """Offline App and Website Testing Model CLI."""
    pass


@main.command("assess")
@click.argument("repo_path", type=click.Path(exists=True))
@click.option("--base", default="main", help="Comparison base branch name.")
@click.option("--branch", default=None, help="Specific branch to assess.")
@click.option(
    "--allow-scripts",
    is_flag=True,
    default=False,
    help="Approve running repository-provided test and build scripts in offline sandbox.",
)
@click.option(
    "--detect-flaky",
    is_flag=True,
    default=False,
    help="Perform multi-run repeat-sampling to identify and quarantine unstable/flaky tests.",
)
@click.option(
    "--quarantine-policy",
    type=click.Choice(["warn", "block", "ignore"], case_sensitive=False),
    default="warn",
    help="Handling policy for quarantined flaky tests (warn, block CI, or ignore).",
)
@click.option(
    "--generate-tests/--no-generate-tests",
    default=True,
    help="Automatically synthesize and validate targeted branch unit tests.",
)
@click.option("--out", default=".offtest_runs", help="Output directory for runs and reports.")
@click.option("--sarif-out", default=None, help="Optional output path for OASIS SARIF 2.1.0 file.")
@click.option("--json-out", is_flag=True, default=False, help="Print summary JSON to stdout.")
@click.option("--strict", is_flag=True, default=False, help="Fail with non-zero exit code on blocked checks.")
def assess(repo_path, base, branch, allow_scripts, detect_flaky, quarantine_policy, generate_tests, out, sarif_out, json_out, strict):
    """
    Run offline repository intake, inventory, app mapping, checks, and generate reports.
    """
    click.echo(f"[*] Starting offline assessment for: {repo_path}")
    if not allow_scripts:
        click.echo("[i] Repository scripts disabled by default. Pass --allow-scripts to enable test execution.")
    else:
        click.echo("[!] Script execution APPROVED by operator.")

    orchestrator = AssessmentOrchestrator(
        repo_path_or_archive=repo_path,
        base_branch=base,
        target_branch=branch,
        allow_scripts=allow_scripts,
        output_dir=out,
        detect_flaky=detect_flaky,
        quarantine_policy=quarantine_policy,
        generate_tests=generate_tests,
    )

    context, detailed_path, issue_path, sarif_path = orchestrator.run()

    if sarif_out:
        shutil.copyfile(str(sarif_path), sarif_out)
        click.echo(f"[+] SARIF 2.1.0 report saved to: {sarif_out}")

    click.echo(f"[+] Assessment completed successfully! Run ID: {context.run_id}")
    click.echo(f"[+] Files analyzed: {context.inventory_summary.analyzed_count} / {context.inventory_summary.total_files}")
    click.echo(f"[+] Discovered routes/APIs: {len(context.routes)} routes, {len(context.apis)} APIs")
    click.echo(f"[+] Offline SBOM Components: {context.sbom.total_dependencies} ({', '.join(context.sbom.ecosystems) or 'None'})")
    click.echo(f"[+] Inferred RBAC Roles: {', '.join(context.rbac_matrix.roles)}")
    click.echo(f"[+] Generated Branch Tests: {context.generated_test_suite.total_generated} (Status: synthesized, unverified)")
    click.echo(f"[+] Total findings: {len(context.findings)}")
    click.echo(f"[+] Report 1 (Detailed): {detailed_path}")
    click.echo(f"[+] Report 2 (Issue-focused): {issue_path}")
    click.echo(f"[+] SARIF Report: {sarif_path}")

    if json_out:
        summary = {
            "schema_version": context.schema_version,
            "run_id": context.run_id,
            "timestamp": context.timestamp,
            "findings_count": len(context.findings),
            "files_analyzed": context.inventory_summary.analyzed_count,
            "sbom_dependencies": context.sbom.total_dependencies,
            "rbac_endpoints": context.rbac_matrix.endpoints_count,
            "generated_tests": context.generated_test_suite.total_generated,
            "detailed_report": str(detailed_path),
            "issue_report": str(issue_path),
            "sarif_report": str(sarif_path),
        }
        click.echo(json.dumps(summary, indent=2))

    # Standard CI Exit Codes
    crit_or_high = [f for f in context.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
    blocked_checks = [c for c in context.check_results if c.status == CheckStatus.BLOCKED]

    if crit_or_high:
        click.echo(f"[!] CI Gate: {len(crit_or_high)} Critical/High findings detected.")
        sys.exit(1)
    elif strict and blocked_checks:
        click.echo(f"[!] CI Gate: {len(blocked_checks)} checks were blocked under strict mode.")
        sys.exit(3)
    else:
        sys.exit(0)


@main.command("report")
@click.argument("run_id_or_file")
@click.option("--out", default=None, help="Directory to write reproduced reports to.")
def report(run_id_or_file, out):
    """
    Reproduce Report 1 & Report 2 directly from saved evidence store without re-running tests.
    """
    store = EvidenceStore()
    context = store.load_run(run_id_or_file)

    detailed_gen = DetailedReportGenerator(context)
    issue_gen = IssueFocusedReportGenerator(context)

    target_dir = Path(out) if out else Path(".offtest_runs") / context.run_id
    target_dir.mkdir(parents=True, exist_ok=True)

    det_path = target_dir / "REPORT_1_DETAILED.md"
    iss_path = target_dir / "REPORT_2_ISSUES.md"

    det_path.write_text(detailed_gen.generate_markdown(), encoding="utf-8")
    iss_path.write_text(issue_gen.generate_markdown(), encoding="utf-8")

    click.echo(f"[+] Successfully reproduced reports from run '{context.run_id}'!")
    click.echo(f"[+] Detailed report: {det_path}")
    click.echo(f"[+] Issue-focused report: {iss_path}")


@main.command("manifest")
def manifest():
    """
    Display inventory of installed offline tools, runtimes, and analyzers.
    """
    click.echo("Offline Tool & Runtime Manifest:")
    click.echo("-" * 65)
    for tool in get_tool_manifest():
        avail = "[ONLINE/AVAILABLE]" if tool.is_available else "[UNAVAILABLE]"
        click.echo(f"{tool.name:<32} {tool.version:<15} {avail}")
        if tool.notes:
            click.echo(f"  Note: {tool.notes}")
    click.echo("-" * 65)


@main.command("verify-offline")
def verify_offline():
    """
    Verify that the environment executes analysis without network dependencies
    using raw socket, DNS, and HTTP probes executed inside the IsolatedRunner.
    """
    click.echo("[*] Executing offline network isolation probes from INSIDE child sandbox processes via IsolatedRunner...")
    click.echo("    (Probes execute in scrubbed subprocess environments with proxy sinkholes and host secrets stripped)")
    from offtest.checks.isolated_runner import IsolatedRunner
    runner = IsolatedRunner(Path("."), timeout_sec=5)

    # 1. HTTP Probe with proxy sinkhole
    http_probe = [sys.executable, "-c", "import urllib.request; urllib.request.urlopen('http://example.com', timeout=2)"]
    c1, _, _, d1 = runner.run(http_probe)

    # 2. Raw TCP Socket Probe (direct IP connection attempt, ignores proxy env vars)
    raw_socket_probe = [sys.executable, "-c", "import socket; s = socket.create_connection(('1.1.1.1', 53), timeout=2); s.close()"]
    c2, _, _, d2 = runner.run(raw_socket_probe)

    # 3. Direct DNS Lookup Probe
    dns_probe = [sys.executable, "-c", "import socket; socket.getaddrinfo('example.com', 80)"]
    c3, _, _, d3 = runner.run(dns_probe)

    # 4. Raw UDP Datagram Probe (direct IP egress attempt)
    udp_probe = [sys.executable, "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'leak', ('8.8.8.8', 53)); s.close()"]
    c4, _, _, d4 = runner.run(udp_probe)

    click.echo(f"  - HTTP Proxy Sinkhole Probe: {'BLOCKED / SAFE' if c1 != 0 else 'UNPROTECTED'} ({d1}s)")
    if c2 != 0:
        click.echo(f"  - Raw TCP Socket Probe: BLOCKED / SAFE (Offline interceptor / network boundary active) ({d2}s)")
    else:
        click.echo(f"  - Raw TCP Socket Probe: [!] WARNING: Connected to raw socket! (Host network interface is open)")

    if c3 != 0:
        click.echo(f"  - Direct DNS Resolution Probe: BLOCKED / SAFE ({d3}s)")
    else:
        click.echo(f"  - Direct DNS Resolution Probe: [!] NOTICE: DNS resolved via host resolver.")

    if c4 != 0:
        click.echo(f"  - Raw UDP Datagram Egress: BLOCKED / SAFE ({d4}s)")
    else:
        click.echo(f"  - Raw UDP Datagram Egress: [!] WARNING: UDP egress allowed.")

    if c1 != 0 and c2 != 0 and c3 != 0 and c4 != 0:
        click.echo("[+] Full air-gap verified: All HTTP, TCP, UDP, and DNS outbound attempts blocked.")
    elif c1 != 0:
        click.echo("[i] Partial isolation active. Some raw socket egress is permitted on host.")
    else:
        click.echo("[!] WARNING: Network isolation is not functioning.")


if __name__ == "__main__":
    main()
