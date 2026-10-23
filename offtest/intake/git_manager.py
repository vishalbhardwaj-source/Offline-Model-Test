import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from offtest.core.models import BranchDiffRecord, BranchRecord


class GitManager:
    def __init__(self, repo_dir: str):
        self.repo_dir = Path(repo_dir).resolve()
        self.is_git = (self.repo_dir / ".git").exists()

    def _run_git(self, args: List[str]) -> Tuple[int, str, str]:
        if not self.is_git:
            return 1, "", "Not a git repository"
        try:
            # Harden Git against malicious .git/config commands (fsmonitor, textconv, hooks, pagers)
            hardened_flags = [
                "-c", "core.fsmonitor=false",
                "-c", "core.pager=cat",
                "-c", "core.hooksPath=",
                "-c", "diff.external=false",
                "-c", "diff.textconv=false",
                "-c", "protocol.allow=never",
            ]
            git_env = {
                k: v for k, v in os.environ.items()
                if k.upper() in ["PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP"]
            }
            git_env.update({
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_SSH_COMMAND": "false",
            })

            result = subprocess.run(
                ["git", "--no-pager"] + hardened_flags + args,
                cwd=str(self.repo_dir),
                env=git_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except Exception as e:
            return 1, "", str(e)

    def get_repo_state(self) -> Dict[str, any]:
        if not self.is_git:
            return {
                "is_git": False,
                "commit_hash": None,
                "active_branch": None,
                "working_tree_clean": True,
                "remotes": [],
            }

        # Commit hash
        code, commit, _ = self._run_git(["rev-parse", "HEAD"])
        commit_hash = commit if code == 0 else None

        # Active branch
        code, branch, _ = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        active_branch = branch if code == 0 else None

        # Working tree status
        code, status_out, _ = self._run_git(["status", "--porcelain"])
        is_clean = len(status_out.strip()) == 0

        # Remotes (read configuration only, DO NOT FETCH)
        code, remotes_out, _ = self._run_git(["remote", "-v"])
        remotes = []
        if code == 0 and remotes_out:
            for line in remotes_out.splitlines():
                if "(fetch)" in line:
                    remotes.append(line.split()[0])
            remotes = sorted(list(set(remotes)))

        return {
            "is_git": True,
            "commit_hash": commit_hash,
            "active_branch": active_branch,
            "working_tree_clean": is_clean,
            "remotes": remotes,
        }

    def list_local_branches(self, comparison_base: Optional[str] = None) -> List[BranchRecord]:
        if not self.is_git:
            return []

        # List only local branches
        code, out, _ = self._run_git(["for-each-ref", "--format=%(refname:short)|%(objectname:short)|%(subject)", "refs/heads/"])
        if code != 0 or not out:
            return []

        branches = []
        state = self.get_repo_state()
        active = state.get("active_branch")

        for line in out.splitlines():
            parts = line.split("|", 2)
            if len(parts) >= 2:
                name = parts[0].strip()
                commit = parts[1].strip()
                msg = parts[2].strip() if len(parts) > 2 else ""
                branches.append(
                    BranchRecord(
                        name=name,
                        is_current=(name == active),
                        is_base=(name == comparison_base),
                        head_commit=commit,
                        commit_message=msg,
                        status="assessed" if (name == active) else "unassessed",
                    )
                )
        return branches

    def compare_branches(self, branch: str, base: str) -> Optional[BranchDiffRecord]:
        if not self.is_git:
            return None

        # Safely compute changed files between local base and target branch
        code, diff_names, err = self._run_git(["diff", "--name-status", f"{base}...{branch}"])
        if code != 0:
            return BranchDiffRecord(
                branch_name=branch,
                base_branch=base,
                diff_summary=f"Comparison failed or branches diverge: {err}",
            )

        added, modified, deleted = [], [], []
        for line in diff_names.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                status, path = parts[0], parts[1]
                if status.startswith("A"):
                    added.append(path)
                elif status.startswith("M"):
                    modified.append(path)
                elif status.startswith("D"):
                    deleted.append(path)
                else:
                    modified.append(path)

        return BranchDiffRecord(
            branch_name=branch,
            base_branch=base,
            added_files=added,
            modified_files=modified,
            deleted_files=deleted,
            total_changed_files=len(added) + len(modified) + len(deleted),
            diff_summary=f"+{len(added)} ~{len(modified)} -{len(deleted)} files changed",
        )
