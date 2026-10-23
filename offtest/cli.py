import json
import sys
from pathlib import Path
import click

from offtest.checks.planner import get_tool_manifest
from offtest.core.evidence_store import EvidenceStore
from offtest.orchestrator import AssessmentOrchestrator
from offtest.reports.detailed import DetailedReportGenerator
from offtest.reports.issue_focused import IssueFocusedReportGenerator


@click.group()
@click.version_option(version="0.1.0", prog_name="offtest")
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
@click.option("--out", default=".offtest_runs", help="Output directory for runs and reports.")
@click.option("--json-out", is_flag=True, default=False, help="Print summary JSON to stdout.")
def assess(repo_path, base, branch, allow_scripts, out, json_out):
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
    )

    context, detailed_path, issue_path = orchestrator.run()

    click.echo(f"[+] Assessment completed successfully! Run ID: {context.run_id}")
    click.echo(f"[+] Files analyzed: {context.inventory_summary.analyzed_count} / {context.inventory_summary.total_files}")
    click.echo(f"[+] Discovered routes/APIs: {len(context.routes)} routes, {len(context.apis)} APIs")
    click.echo(f"[+] Total findings: {len(context.findings)}")
    click.echo(f"[+] Report 1 (Detailed): {detailed_path}")
    click.echo(f"[+] Report 2 (Issue-focused): {issue_path}")

    if json_out:
        summary = {
            "run_id": context.run_id,
            "timestamp": context.timestamp,
            "findings_count": len(context.findings),
            "files_analyzed": context.inventory_summary.analyzed_count,
            "detailed_report": str(detailed_path),
            "issue_report": str(issue_path),
        }
        click.echo(json.dumps(summary, indent=2))


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
    Verify that the environment executes analysis without network dependencies.
    """
    click.echo("[*] Verifying offline execution safeguards...")
    from offtest.checks.isolated_runner import IsolatedRunner
    runner = IsolatedRunner(Path("."))
    code, stdout, stderr, dur = runner.run([sys.executable, "-c", "import urllib.request; urllib.request.urlopen('http://example.com', timeout=2)"])
    if code != 0:
        click.echo(f"[+] Network isolation confirmed: External network request blocked ({dur}s).")
    else:
        click.echo("[!] WARNING: Outbound socket connection succeeded. Ensure network adapter is disabled or isolated.")


if __name__ == "__main__":
    main()
