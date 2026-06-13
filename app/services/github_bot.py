"""
GitHub Pull-Request automation for ThreatWeaver remediations.

Once the autonomous pipeline has produced remediation patches for a target, this
bot opens a Pull Request on the target repository so a human can review and merge
the fixes. It uses the PyGithub library, talking to the GitHub REST API:

    1. Authenticate with a Personal Access Token (``GITHUB_PAT``).
    2. Resolve the target repository (``GITHUB_TARGET_REPO`` = "owner/repo").
    3. Create a dedicated branch ``threatweaver-patch-<id>-<timestamp>`` off the
       repository's default branch.
    4. Commit each generated patch/diff artefact onto that branch.
    5. Open a Pull Request from the branch back to the default branch.

Design notes
------------
* PyGithub is a synchronous library, so the blocking API work runs inside
  ``asyncio.to_thread`` to avoid stalling the event loop.
* The ``github`` import is guarded: if PyGithub is not installed the module
  still imports cleanly and the bot reports itself as unconfigured, so the rest
  of the pipeline keeps working.
* Every public entry point returns a structured dict (never raises) so a
  credential/network problem can never crash a scan's finalization.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Guarded PyGithub import — keeps the app importable even without the dependency.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - exercised implicitly by import
    from github import Github

    try:
        from github import Auth as _GithubAuth  # PyGithub >= 1.58
    except Exception:  # older PyGithub without the Auth helper
        _GithubAuth = None

    try:
        from github.GithubException import GithubException
    except Exception:  # pragma: no cover
        from github import GithubException  # type: ignore
except Exception:  # PyGithub not installed
    Github = None  # type: ignore
    _GithubAuth = None  # type: ignore

    class GithubException(Exception):  # type: ignore
        """Fallback so except-clauses are valid when PyGithub is absent."""


# Directory inside the target repo where generated patch artefacts are written.
PATCH_DIR = "threatweaver-patches"


def _slugify(text: Any, default: str = "patch") -> str:
    """Turn an arbitrary label into a filesystem/branch-safe slug."""
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(text or "")).strip("-._").lower()
    return slug or default


class GitHubBot:
    """Opens remediation Pull Requests on a target repository via PyGithub."""

    def __init__(
        self,
        token: Optional[str] = None,
        repo_full_name: Optional[str] = None,
        branch_prefix: str = "threatweaver-patch-",
    ):
        # The Personal Access Token the bot authenticates with.
        self.token = token if token is not None else os.getenv("GITHUB_PAT", "")
        # "owner/repo" of the repository to patch. Defaults to GITHUB_TARGET_REPO.
        self.repo_full_name = (
            repo_full_name
            if repo_full_name is not None
            else os.getenv("GITHUB_TARGET_REPO", "")
        )
        self.branch_prefix = branch_prefix

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #
    def is_configured(self) -> bool:
        """True when PyGithub is available AND a token + target repo are set."""
        return bool(Github and self.token and self.repo_full_name)

    async def create_patch_pr(
        self,
        patch_id: str,
        patches: List[Dict[str, Any]],
        *,
        target_url: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a branch, commit the supplied patches, and open a Pull Request.

        ``patches`` is a list of dicts shaped like the RemediationService output:
        {vuln_node, name, category, endpoint, risk_level, cves, description,
         recommendation, code, [target_path]}.

        Returns a structured result dict. On any failure it returns
        {"status": "failed"/"skipped", "error"/"reason": ...} rather than raising.
        """
        if Github is None:
            return {"status": "skipped", "reason": "PyGithub is not installed."}
        if not self.token:
            return {"status": "skipped", "reason": "GITHUB_PAT is not set."}
        if not self.repo_full_name:
            return {"status": "skipped", "reason": "GITHUB_TARGET_REPO is not set."}
        if not patches:
            return {"status": "skipped", "reason": "No patches to submit."}

        try:
            return await asyncio.to_thread(
                self._create_pr_sync, patch_id, patches, target_url, summary
            )
        except GithubException as exc:  # API-level failure (auth, 404, perms...)
            return {"status": "failed", "error": f"GitHub API error: {exc}"}
        except Exception as exc:  # noqa: BLE001 - never let PR automation crash a scan
            return {"status": "failed", "error": f"PR automation failed: {exc}"}

    # ------------------------------------------------------------------ #
    # Internal (synchronous PyGithub work)                                #
    # ------------------------------------------------------------------ #
    def _client(self) -> "Github":
        """Build an authenticated PyGithub client across library versions."""
        if _GithubAuth is not None:
            return Github(auth=_GithubAuth.Token(self.token))
        return Github(self.token)  # legacy positional-token constructor

    def _create_pr_sync(
        self,
        patch_id: str,
        patches: List[Dict[str, Any]],
        target_url: Optional[str],
        summary: Optional[str],
    ) -> Dict[str, Any]:
        gh = self._client()
        repo = gh.get_repo(self.repo_full_name)
        base_branch = repo.default_branch
        source = repo.get_branch(base_branch)

        # Unique branch name so re-runs of the same job never collide.
        suffix = time.strftime("%Y%m%d-%H%M%S")
        branch = f"{self.branch_prefix}{_slugify(patch_id)}-{suffix}"
        repo.create_git_ref(ref=f"refs/heads/{branch}", sha=source.commit.sha)

        written: List[str] = []
        for index, patch in enumerate(patches, 1):
            vuln = patch.get("vuln_node") or patch.get("name") or f"finding-{index}"
            path = patch.get("target_path") or f"{PATCH_DIR}/{_slugify(vuln)}.patch"
            content = self._render_patch_file(patch, target_url)
            commit_msg = f"ThreatWeaver: remediation for {vuln}"
            try:
                # Update in place if the file already exists on the branch.
                existing = repo.get_contents(path, ref=branch)
                repo.update_file(
                    path, commit_msg, content, existing.sha, branch=branch
                )
            except GithubException:
                repo.create_file(path, commit_msg, content, branch=branch)
            written.append(path)

        n = len(patches)
        title = (
            f"ThreatWeaver automated remediation "
            f"({n} patch{'es' if n != 1 else ''})"
        )
        body = self._render_pr_body(patches, target_url, summary)
        pull = repo.create_pull(
            title=title, body=body, head=branch, base=base_branch
        )

        return {
            "status": "open",
            "url": pull.html_url,
            "number": pull.number,
            "branch": branch,
            "base": base_branch,
            "repo": self.repo_full_name,
            "files": written,
        }

    # ------------------------------------------------------------------ #
    # Rendering helpers                                                   #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _render_patch_file(patch: Dict[str, Any], target_url: Optional[str]) -> str:
        """Render a single patch artefact (header metadata + remediation code)."""
        vuln = patch.get("vuln_node") or patch.get("name") or "unknown"
        lines: List[str] = [
            "# ThreatWeaver automated remediation",
            f"# Vulnerability: {vuln}",
        ]
        if patch.get("category"):
            lines.append(f"# Category: {patch['category']}")
        if patch.get("endpoint"):
            lines.append(f"# Endpoint: {patch['endpoint']}")
        if target_url:
            lines.append(f"# Target: {target_url}")
        if patch.get("risk_level"):
            lines.append(f"# Risk: {patch['risk_level']}")
        cves = patch.get("cves") or []
        if cves:
            lines.append(f"# CVEs: {', '.join(str(c) for c in cves)}")
        if patch.get("description"):
            lines.append("#")
            lines.append("# Description:")
            lines.extend(f"#   {ln}" for ln in str(patch["description"]).splitlines())
        if patch.get("recommendation"):
            lines.append("#")
            lines.append("# Recommended fix:")
            lines.extend(
                f"#   {ln}" for ln in str(patch["recommendation"]).splitlines()
            )
        code = (patch.get("code") or patch.get("patch") or "").rstrip()
        lines.append("")
        lines.append(code or "# No remediation code was generated for this finding.")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _render_pr_body(
        patches: List[Dict[str, Any]],
        target_url: Optional[str],
        summary: Optional[str],
    ) -> str:
        """Render the Pull Request description summarising every remediation."""
        out: List[str] = ["## ThreatWeaver automated remediation", ""]
        if target_url:
            out.append(f"**Target scanned:** `{target_url}`")
        if summary:
            out.extend(["", summary])
        n = len(patches)
        out.extend([
            "",
            f"This PR contains **{n}** AI-generated remediation"
            f"{'s' if n != 1 else ''} for review:",
            "",
        ])
        for index, patch in enumerate(patches, 1):
            vuln = patch.get("vuln_node") or patch.get("name") or f"finding-{index}"
            risk = patch.get("risk_level") or "Unknown"
            out.append(f"### {index}. {vuln} ({risk})")
            if patch.get("endpoint"):
                out.append(f"- **Endpoint:** `{patch['endpoint']}`")
            if patch.get("cves"):
                out.append(
                    f"- **CVEs:** {', '.join(str(c) for c in patch['cves'])}"
                )
            if patch.get("description"):
                out.append(f"- {patch['description']}")
            if patch.get("recommendation"):
                out.append(f"- **Fix:** {patch['recommendation']}")
            out.append("")
        out.extend([
            "---",
            "_Generated by the ThreatWeaver Autonomous Security Engine. "
            "Review carefully before merging._",
        ])
        return "\n".join(out)
