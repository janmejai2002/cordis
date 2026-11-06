"""Cordis Forge Self-Approval & Token Guard.
Inspects git commit author/committer metadata and CI/Forge environment variables
(GITHUB_ACTOR, GITHUB_TRIGGERING_ACTOR, GITHUB_EVENT_NAME) to prevent bot self-approval
and single-token automated merging without dual-custody verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Known bot patterns (case-insensitive)
BOT_IDENTIFIER_PATTERNS = [
    r"\[bot\]",
    r"\bbot\b",
    r"github-actions",
    r"dependabot",
    r"renovate",
    r"coderabbit",
    r"devin",
    r"cursor-agent",
    r"claude-code",
    r"antigravity-agent",
    r"copilot",
    r"sweep-ai",
]

BOT_EMAIL_DOMAINS = [
    "users.noreply.github.com",
    "actions@github.com",
    "bot@",
    "agent@",
]

BOT_RE = re.compile("|".join(BOT_IDENTIFIER_PATTERNS), re.IGNORECASE)


@dataclass
class GitActorInfo:
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    commit_message: str = ""
    is_bot: bool = False


@dataclass
class ForgeGuardReport:
    passed: bool
    is_bot_authored: bool = False
    is_self_approved: bool = False
    actor: str = ""
    triggering_actor: str = ""
    event_name: str = ""
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def is_bot_identity(name: str, email: str = "") -> bool:
    """Detects if a given name or email indicates an automated bot/agent account."""
    if not name and not email:
        return False
    if BOT_RE.search(name):
        return True
    if email:
        if BOT_RE.search(email):
            return True
        for domain in BOT_EMAIL_DOMAINS:
            if domain in email.lower():
                return True
    return False


def inspect_git_actor(repo_dir: str | Path = ".", ref: str = "HEAD") -> GitActorInfo:
    """Extracts git commit author and committer metadata for the specified ref."""
    cmd = ["git", "log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", ref]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if proc.returncode == 0:
            parts = proc.stdout.strip().split("\x00")
            if len(parts) >= 5:
                an, ae, cn, ce, msg = parts[0], parts[1], parts[2], parts[3], parts[4]
                bot = is_bot_identity(an, ae) or is_bot_identity(cn, ce)
                return GitActorInfo(
                    author_name=an,
                    author_email=ae,
                    committer_name=cn,
                    committer_email=ce,
                    commit_message=msg,
                    is_bot=bot,
                )
    except Exception:
        pass
    return GitActorInfo(
        author_name="unknown",
        author_email="unknown@unknown.com",
        committer_name="unknown",
        committer_email="unknown@unknown.com",
        is_bot=False,
    )


def audit_forge_guard(
    actor_info: Optional[GitActorInfo] = None,
    env: Optional[Dict[str, str]] = None,
    pr_author: Optional[str] = None,
    reviewer: Optional[str] = None,
    review_state: Optional[str] = None,  # e.g., "APPROVED", "COMMENTED", "CHANGES_REQUESTED"
    auto_merge_requested: bool = False,
) -> ForgeGuardReport:
    """Audits PR actor metadata and CI environment variables for bot self-approval,
    single-token auto-merge, and missing human dual-custody approval.
    """
    if env is None:
        env = dict(os.environ)

    actor = env.get("GITHUB_ACTOR", "").strip()
    triggering_actor = env.get("GITHUB_TRIGGERING_ACTOR", actor).strip()
    event_name = env.get("GITHUB_EVENT_NAME", "").strip()

    violations: List[str] = []
    warnings: List[str] = []

    # 1. Determine effective PR author
    effective_pr_author = pr_author or ""
    if not effective_pr_author and actor_info:
        effective_pr_author = actor_info.author_name

    author_is_bot = is_bot_identity(
        effective_pr_author,
        actor_info.author_email if actor_info else "",
    ) or (actor_info.is_bot if actor_info else False)

    # 2. Check reviewer identity & state
    effective_reviewer = reviewer or actor
    reviewer_is_bot = is_bot_identity(effective_reviewer)
    is_self_approved = False

    # Check for direct Self-Approval
    if effective_pr_author and effective_reviewer:
        clean_author = effective_pr_author.lower().replace("[bot]", "").strip()
        clean_reviewer = effective_reviewer.lower().replace("[bot]", "").strip()
        if clean_author and clean_author == clean_reviewer and review_state == "APPROVED":
            is_self_approved = True
            violations.append(
                f"Forge Guard Violation [SELF_APPROVAL]: PR author `{effective_pr_author}` approved their own PR. "
                "Dual-custody verification failed."
            )

    # Check for Bot-to-Bot collusion (Bot approved by another Bot without human sign-off)
    if author_is_bot and reviewer_is_bot and review_state == "APPROVED":
        violations.append(
            f"Forge Guard Violation [BOT_COLLUSION]: Bot PR authored by `{effective_pr_author}` was approved by "
            f"bot `{effective_reviewer}` without human verification."
        )

    # 3. Check for Single-Token Agent Auto-Merging
    if auto_merge_requested or "auto-merge" in env.get("GITHUB_ACTION_REPOSITORY", "").lower():
        if author_is_bot and (not reviewer or reviewer_is_bot or is_self_approved):
            violations.append(
                f"Forge Guard Violation [SINGLE_TOKEN_AUTO_MERGE]: Automated auto-merge triggered for bot-authored "
                f"PR `{effective_pr_author}` without independent human approval."
            )

    # 4. In GitHub Actions PR review events
    if event_name in ("pull_request_review", "pull_request_review_comment"):
        if review_state == "APPROVED":
            if actor and effective_pr_author and actor.lower() == effective_pr_author.lower():
                if not is_self_approved:
                    is_self_approved = True
                    violations.append(
                        f"Forge Guard Violation [GITHUB_ACTOR_SELF_APPROVAL]: GITHUB_ACTOR `{actor}` is approving "
                        f"PR authored by `{effective_pr_author}`."
                    )
            if is_bot_identity(actor):
                warnings.append(
                    f"Forge Guard Notice: Review performed by automated bot account `{actor}`."
                )

    passed = len(violations) == 0

    return ForgeGuardReport(
        passed=passed,
        is_bot_authored=author_is_bot,
        is_self_approved=is_self_approved,
        actor=actor,
        triggering_actor=triggering_actor,
        event_name=event_name,
        violations=violations,
        warnings=warnings,
        metadata={
            "effective_pr_author": effective_pr_author,
            "effective_reviewer": effective_reviewer,
            "review_state": review_state,
            "author_is_bot": author_is_bot,
            "reviewer_is_bot": reviewer_is_bot,
        },
    )


def audit_current_environment(repo_dir: str | Path = ".") -> ForgeGuardReport:
    """Audits current git repository HEAD and environment for Forge Guard compliance."""
    actor_info = inspect_git_actor(repo_dir=repo_dir, ref="HEAD")
    return audit_forge_guard(actor_info=actor_info)


def compute_diff_attestation_digest(
    modified_anchors: dict[str, str],
    gate2_kill_rate: float = 1.0,
) -> str:
    """Computes a deterministic 64-bit (16-hex character) BLAKE2b digest over
    the lexicographically sorted modified function anchors and Gate 2 kill rate.

    Args:
        modified_anchors: Mapping from function qualname to anchor tag (¶path#16hex).
        gate2_kill_rate: Mutation gate kill rate as float (e.g. 1.0).

    Returns:
        16-hex character lowercase digest string.
    """
    if not modified_anchors:
        payload = f"EMPTY_DIFF:{gate2_kill_rate:.4f}"
    else:
        payload = "\n".join(
            f"{q}:{t}:{gate2_kill_rate:.4f}"
            for q, t in sorted(modified_anchors.items())
        )
    return hashlib.blake2b(payload.encode("utf-8"), digest_size=8).hexdigest().lower()


def verify_commit_attestation_trailer(commit_message: str, expected_digest: str) -> bool:
    """Verifies that the commit message contains a Cordis-Attestation trailer
    matching expected_digest (case-insensitive).

    Format:
        Cordis-Attestation: ¶<16hex>
        or
        Cordis-Attestation: <16hex>

    Args:
        commit_message: Git commit message string.
        expected_digest: 16-hex character attestation digest.

    Returns:
        True if valid matching attestation trailer found, False otherwise.
    """
    if not commit_message or not expected_digest:
        return False
    target = expected_digest.strip().lower()
    pattern = r"Cordis-Attestation:\s*¶?([0-9a-fA-F]{16})(?![0-9a-fA-F])"
    for match in re.finditer(pattern, commit_message, re.IGNORECASE):
        if match.group(1).lower() == target:
            return True
    return False

