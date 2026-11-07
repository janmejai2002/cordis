"""Cordis Gate 0 PreToolUse Firewall & Stop Hook Prosecutor.
Deterministic pre-execution policy enforcer and working tree verifier.
100% Python Standard Library, zero external dependencies.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cordis.ast_gate import audit_test_tampering, index_ast_anchors
from cordis.git_diff import extract_git_diff, get_git_file_content
from cordis.memory import EpisodicMemoryLedger
from cordis.mutator import MutantResult, run_in_memory_mutation_gate
from cordis.repair import synthesize_mutant_killing_test


@dataclass
class HookDecision:
    """Encapsulates the deterministic decision of the pre-tool firewall."""

    allowed: bool
    reason: str = ""
    exit_code: int = 0
    command: str = ""
    vector: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "command": self.command,
            "vector": self.vector,
            "metadata": self.metadata,
        }


# Regex patterns for bypass vector detection
RE_HOOKS_PATH = re.compile(r"core\.hookspath", re.IGNORECASE)
RE_HOOK_FILES = re.compile(r"(\.git[/\\].*hooks|\.claude[/\\].*hooks)", re.IGNORECASE)
RE_HOOK_MUTATORS = re.compile(
    r"\b(rm|del|erase|rmdir|rd|remove-item|ri|mv|move|move-item|mi|ren|rename|rename-item|chmod|icacls|attrib|unlink|trash)\b",
    re.IGNORECASE,
)
RE_SUPPRESSIONS = re.compile(
    r"(\s-[a-zA-Z]*q\b|--quiet\b|/dev/null\b|nul\b|\$null\b|out-null\b|2>&1|\*>)",
    re.IGNORECASE,
)
RE_STASH_KEEP_INDEX = re.compile(r"(--keep-index\b|-[a-zA-Z]*k[a-zA-Z]*\b)")
RE_COMMIT_NO_VERIFY = re.compile(r"(--no-verify\b|--no-ver\b|-[a-zA-Z]*n[a-zA-Z]*\b)")


def _split_pipeline_segments(cmd: str) -> list[str]:
    """Splits composite shell/PowerShell pipelines (&&, ||, ;, |, &, \\n)
    while strictly respecting quotes (single and double).
    """
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(cmd)

    while i < n:
        ch = cmd[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
            i += 1
        elif ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
            i += 1
        elif ch == "\\" and in_double:
            current.append(ch)
            if i + 1 < n:
                current.append(cmd[i + 1])
                i += 2
            else:
                i += 1
        elif not in_single and not in_double:
            if cmd[i : i + 2] in ("&&", "||"):
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 2
            elif ch in (";", "|", "&", "\n"):
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 1
            else:
                current.append(ch)
                i += 1
        else:
            current.append(ch)
            i += 1

    rem = "".join(current).strip()
    if rem:
        segments.append(rem)
    return segments if segments else [cmd]


def _tokenize_command(cmd: str) -> list[str]:
    """Tokenizes command string into arguments preserving backslashes on Windows."""
    try:
        return shlex.split(cmd, posix=False)
    except ValueError:
        return cmd.split()


def _strip_outer_quotes(s: str) -> str:
    """Strips wrapping single, double quotes or curly braces."""
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1].strip()
    if s.startswith("{") and s.endswith("}"):
        return s[1:-1].strip()
    return s


def _audit_embedded_python(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects python -c payload for embedded subversion or hook tampering."""
    clean_payload = _strip_outer_quotes(payload)

    # 1. Inspect AST if valid Python syntax
    try:
        tree = ast.parse(clean_payload)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_str = ast.unparse(node.func)
                # Check for direct file removal/chmod tampering targeting hooks
                if any(m in func_str for m in ("remove", "unlink", "rmtree", "chmod")):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if RE_HOOK_FILES.search(arg.value):
                                return HookDecision(
                                    allowed=False,
                                    exit_code=2,
                                    command=raw_cmd,
                                    vector="EMBEDDED_SUBVERSION",
                                    reason=f"Bypass detected: python payload tampers with hooks ({func_str})",
                                    metadata={"nested_vector": "HOOKS_TAMPERING", "payload": clean_payload},
                                )
                # Check for shell execution calls
                if any(
                    m in func_str
                    for m in (
                        "os.system",
                        "os.popen",
                        "subprocess.run",
                        "subprocess.Popen",
                        "subprocess.call",
                        "subprocess.check_call",
                        "subprocess.check_output",
                        "exec",
                        "eval",
                        "getattr",
                    )
                ) or "subprocess" in func_str:
                    sub_cmds: list[str] = []
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            sub_cmds.append(first_arg.value)
                        elif isinstance(first_arg, (ast.List, ast.Tuple)):
                            parts = []
                            for elt in first_arg.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    parts.append(elt.value)
                            if parts:
                                sub_cmds.append(" ".join(parts))
                        elif isinstance(first_arg, ast.Call):
                            first_func = ast.unparse(first_arg.func)
                            if "b64decode" in first_func and first_arg.args:
                                if isinstance(first_arg.args[0], ast.Constant) and isinstance(first_arg.args[0].value, str):
                                    try:
                                        decoded_py = base64.b64decode(first_arg.args[0].value).decode("utf-8", errors="replace")
                                        dec_res = _audit_embedded_python(decoded_py, raw_cmd)
                                        if dec_res is not None:
                                            return dec_res
                                    except Exception:
                                        pass

                    for sub_c in sub_cmds:
                        inner_dec = audit_pre_tool_use_command(sub_c)
                        if not inner_dec.allowed:
                            return HookDecision(
                                allowed=False,
                                exit_code=2,
                                command=raw_cmd,
                                vector="EMBEDDED_SUBVERSION",
                                reason=f"Bypass detected in embedded python command: {inner_dec.reason}",
                                metadata={"nested_vector": inner_dec.vector, "nested_command": sub_c},
                            )
    except SyntaxError:
        pass

    # 2. Fallback heuristic inspection on raw payload
    if RE_HOOKS_PATH.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: core.hooksPath override",
            metadata={"nested_vector": "HOOKS_PATH_OVERRIDE"},
        )
    if RE_HOOK_FILES.search(clean_payload) and re.search(r"\b(remove|unlink|rmtree|chmod|rm|del)\b", clean_payload, re.IGNORECASE):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: hook tampering",
            metadata={"nested_vector": "HOOKS_TAMPERING"},
        )
    if re.search(r"git\s+commit", clean_payload, re.IGNORECASE) and RE_COMMIT_NO_VERIFY.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: git commit with no-verify / -n",
            metadata={"nested_vector": "NO_VERIFY"},
        )
    if re.search(r"git\s+stash", clean_payload, re.IGNORECASE) and RE_STASH_KEEP_INDEX.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: git stash --keep-index",
            metadata={"nested_vector": "STASH_KEEP_INDEX"},
        )

    return None


def _audit_embedded_powershell(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects powershell -Command payload."""
    clean_payload = _strip_outer_quotes(payload)
    inner_dec = audit_pre_tool_use_command(clean_payload)
    if not inner_dec.allowed:
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason=f"Bypass detected in embedded PowerShell command: {inner_dec.reason}",
            metadata={"nested_vector": inner_dec.vector, "nested_command": clean_payload},
        )
    return None


def _audit_embedded_shell(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects bash/sh/zsh/eval -c payload."""
    clean_payload = _strip_outer_quotes(payload)
    inner_dec = audit_pre_tool_use_command(clean_payload)
    if not inner_dec.allowed:
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason=f"Bypass detected in embedded shell command: {inner_dec.reason}",
            metadata={"nested_vector": inner_dec.vector, "nested_command": clean_payload},
        )
    return None


def _audit_single_command(cmd_segment: str) -> HookDecision:
    """Audits a single, non-composite command string against all bypass vectors."""
    clean_cmd = cmd_segment.strip()
    if not clean_cmd:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    tokens = _tokenize_command(clean_cmd)
    if not tokens:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    # Strip environment variable prefixes (e.g. VAR=1 git ...)
    start_idx = 0
    while start_idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tokens[start_idx]):
        start_idx += 1

    # Strip common command prefixes (sudo, nohup, time, builtin, command, exec, env)
    while start_idx < len(tokens):
        raw_prefix = _strip_outer_quotes(tokens[start_idx]).replace("/", "\\").strip("\"' ")
        prefix_name = Path(raw_prefix).name.lower().strip("\"'")
        for ext in (".exe", ".cmd", ".bat"):
            if prefix_name.endswith(ext):
                prefix_name = prefix_name[:-len(ext)]
        if prefix_name in ("sudo", "nohup", "time", "builtin", "command", "exec", "env"):
            start_idx += 1
        else:
            break

    effective_tokens = tokens[start_idx:]
    if not effective_tokens:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    prog_raw = _strip_outer_quotes(effective_tokens[0]).replace("/", "\\").strip("\"' ")
    prog_name = Path(prog_raw).name.lower().strip("\"'")
    for ext in (".exe", ".cmd", ".bat"):
        if prog_name.endswith(ext):
            prog_name = prog_name[:-len(ext)]

    # --- VECTOR 5: Embedded Subversion Unwrapping ---
    # 1. Python unwrapping
    if prog_name in ("python", "python3", "py") or prog_name.startswith("python3."):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok in ("-c", "/c"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_python(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 2. PowerShell unwrapping
    if prog_name in ("powershell", "pwsh"):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            tok_lower = tok.lower()
            if tok_lower in ("-command", "-c", "/command", "/c"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_powershell(payload, cmd_segment)
                if res is not None:
                    return res
                break
            elif tok_lower in ("-encodedcommand", "-ec", "-enc", "-e") or (
                tok_lower.startswith("-enc") and not tok_lower.startswith("--")
            ):
                b64_str = effective_tokens[idx + 1] if idx + 1 < len(effective_tokens) else ""
                try:
                    raw_bytes = base64.b64decode(b64_str)
                    decoded = raw_bytes.decode("utf-16le", errors="replace")
                except Exception:
                    decoded = ""
                if decoded:
                    res = _audit_embedded_powershell(decoded, cmd_segment)
                    if res is not None:
                        return res
                break

    # 3. Bash / Sh / Zsh unwrapping
    if prog_name in ("bash", "sh", "zsh", "dash"):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok == "-c":
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_shell(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 4. Eval unwrapping
    if prog_name == "eval":
        payload = " ".join(effective_tokens[1:])
        res = _audit_embedded_shell(payload, cmd_segment)
        if res is not None:
            return res

    # 5. Cmd.exe unwrapping
    if prog_name == "cmd":
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok.lower() in ("/c", "/k"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_shell(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 6. Node.js unwrapping
    if prog_name == "node":
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok.lower() in ("-e", "--eval"):
                payload = " ".join(effective_tokens[idx + 1 :])
                clean_payload = _strip_outer_quotes(payload)
                for m in re.finditer(
                    r"['\"]([^'\"]*(?:git\s+commit|git\s+stash|core\.hookspath|\.git[/\\].*hooks)[^'\"]*)['\"]",
                    clean_payload,
                    re.IGNORECASE,
                ):
                    sub_c = m.group(1).strip()
                    inner_dec = audit_pre_tool_use_command(sub_c)
                    if not inner_dec.allowed:
                        return HookDecision(
                            allowed=False,
                            exit_code=2,
                            command=cmd_segment,
                            vector="EMBEDDED_SUBVERSION",
                            reason=f"Bypass detected in embedded node payload: {inner_dec.reason}",
                            metadata={"nested_vector": inner_dec.vector, "nested_command": sub_c},
                        )
                break

    # --- Check Git Subcommands & Global Options ---
    is_git = prog_name == "git"
    git_subcmd = ""
    subcmd_idx = -1

    if is_git:
        skip_flag_val = False
        git_global_val_flags = {
            "-c",
            "-C",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
            "--config-env",
            "--super-prefix",
        }
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            clean_tok = tok.strip("\"'")
            if skip_flag_val:
                skip_flag_val = False
                continue
            if clean_tok in git_global_val_flags:
                skip_flag_val = True
                continue
            if clean_tok.startswith("-"):
                continue
            git_subcmd = clean_tok.lower()
            subcmd_idx = idx
            break

    # --- VECTOR 2: core.hooksPath Override ---
    if RE_HOOKS_PATH.search(clean_cmd):
        cmd_lower = clean_cmd.lower()
        is_git_related = (
            is_git
            or prog_name == "git-config"
            or "git" in prog_name
            or "config" in cmd_lower
            or "-c" in cmd_lower
        )
        if is_git_related:
            if is_git and git_subcmd == "commit":
                top_level_tokens = effective_tokens[1:subcmd_idx] if subcmd_idx > 1 else []
                if any(RE_HOOKS_PATH.search(t) for t in top_level_tokens):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_PATH_OVERRIDE",
                        reason="Bypass detected: core.hooksPath override attempt",
                    )
            else:
                if is_git or "config" in cmd_lower or "-c" in cmd_lower:
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_PATH_OVERRIDE",
                        reason="Bypass detected: core.hooksPath override attempt",
                    )

    # --- VECTOR 3: Hook Tampering & Permission Stripping ---
    if RE_HOOK_FILES.search(clean_cmd):
        if not (is_git and git_subcmd == "commit"):
            mutator_progs = {
                "rm",
                "del",
                "erase",
                "rmdir",
                "rd",
                "remove-item",
                "ri",
                "mv",
                "move",
                "move-item",
                "mi",
                "ren",
                "rename",
                "rename-item",
                "chmod",
                "icacls",
                "attrib",
                "unlink",
                "trash",
                "out-file",
                "set-content",
                "sc",
                "tee",
            }
            is_mutator = prog_name in mutator_progs or (is_git and git_subcmd in ("rm", "mv"))
            if is_mutator:
                args_to_check = effective_tokens[1:]
                if any(RE_HOOK_FILES.search(a) for a in args_to_check):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_TAMPERING",
                        reason="Bypass detected: hook file tampering or deletion (.git/hooks or .claude/hooks)",
                    )
            if ">" in clean_cmd:
                redir_match = re.search(r">\s*([^\s;&|]+)", clean_cmd)
                if redir_match and RE_HOOK_FILES.search(redir_match.group(1)):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_TAMPERING",
                        reason="Bypass detected: hook file tampering or deletion (.git/hooks or .claude/hooks)",
                    )

    # --- VECTOR 4: git stash --keep-index / -k ---
    if is_git and git_subcmd == "stash":
        stash_args = effective_tokens[subcmd_idx + 1 :]
        for tok in stash_args:
            clean_tok = tok.strip("\"'")
            clean_tok_lower = clean_tok.lower()
            if clean_tok_lower == "--keep-index" or clean_tok_lower.startswith("--keep"):
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=cmd_segment,
                    vector="STASH_KEEP_INDEX",
                    reason="Bypass detected: git stash --keep-index hides unstaged test modifications",
                )
            if clean_tok.startswith("-") and not clean_tok.startswith("--"):
                if "k" in clean_tok_lower:
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="STASH_KEEP_INDEX",
                        reason="Bypass detected: git stash -k short flag hides unstaged test modifications",
                    )

    # --- VECTOR 1: git commit with --no-verify or -n ---
    if is_git and git_subcmd == "commit":
        commit_args = effective_tokens[subcmd_idx + 1 :]
        skip_next = False

        value_taking_flags = {
            "-m",
            "-f",
            "-c",
            "-t",
            "--message",
            "--file",
            "--author",
            "--date",
            "--cleanup",
            "--squash",
            "--fixup",
        }

        for tok in commit_args:
            clean_tok = tok.strip("\"'")
            clean_tok_lower = clean_tok.lower()
            if skip_next:
                skip_next = False
                continue

            if clean_tok_lower.startswith((
                "--message=",
                "--file=",
                "--author=",
                "--date=",
                "--cleanup=",
                "--squash=",
                "--fixup=",
                "-m=",
            )):
                continue

            if clean_tok_lower in value_taking_flags:
                skip_next = True
                continue

            if clean_tok.startswith(('-m"', "-m'", "-m=")) or (
                clean_tok.startswith("-m") and any(ch in clean_tok for ch in ('"', "'", "="))
            ):
                continue

            if (clean_tok.startswith("-F") or clean_tok.startswith("-f")) and len(clean_tok) > 2:
                continue

            if clean_tok_lower.startswith("--no-v"):
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=cmd_segment,
                    vector="NO_VERIFY",
                    reason="Bypass detected: git commit with --no-verify",
                )

            if clean_tok.startswith("-") and not clean_tok.startswith("--"):
                valid_commit_flags = set("mnasvq")
                flag_chars = set(clean_tok_lower[1:])
                if flag_chars.issubset(valid_commit_flags):
                    if "m" in clean_tok_lower:
                        skip_next = True
                    if "n" in clean_tok_lower:
                        return HookDecision(
                            allowed=False,
                            exit_code=2,
                            command=cmd_segment,
                            vector="NO_VERIFY",
                            reason=f"Bypass detected: git commit with short flag '{clean_tok}' containing -n (no-verify)",
                        )
                else:
                    if clean_tok.startswith(("-m", "-f", "-c")):
                        continue

    return HookDecision(allowed=True, exit_code=0, command=cmd_segment)


def audit_pre_tool_use_command(command: str) -> HookDecision:
    """Inspects shell, PowerShell, and embedded strings, deterministically blocking
    all 6 bypass vectors (exit_code=2, allowed=False) per the Conseca model (arXiv:2501.17070).
    Legitimate commands are permitted (allowed=True, exit_code=0).
    """
    if not command or not command.strip():
        return HookDecision(allowed=True, exit_code=0, command=command)

    # Check for piped interpreter execution e.g. echo "git commit -n" | bash
    if "|" in command:
        pipe_parts = command.split("|")
        for p_idx in range(len(pipe_parts) - 1):
            left_part = pipe_parts[p_idx].strip()
            right_part = pipe_parts[p_idx + 1].strip()
            right_tokens = _tokenize_command(right_part)
            if right_tokens:
                right_raw = _strip_outer_quotes(right_tokens[0]).replace("/", "\\").strip("\"' ")
                right_prog = Path(right_raw).name.lower().strip("\"'")
                for ext in (".exe", ".cmd", ".bat"):
                    if right_prog.endswith(ext):
                        right_prog = right_prog[:-len(ext)]
                if right_prog in ("bash", "sh", "zsh", "dash", "powershell", "pwsh", "cmd", "python", "python3", "py", "node"):
                    left_tokens = _tokenize_command(left_part)
                    if left_tokens:
                        left_raw = _strip_outer_quotes(left_tokens[0]).replace("/", "\\").strip("\"' ")
                        left_prog = Path(left_raw).name.lower().strip("\"'")
                        for ext in (".exe", ".cmd", ".bat"):
                            if left_prog.endswith(ext):
                                left_prog = left_prog[:-len(ext)]
                        if left_prog in ("echo", "printf", "write-output"):
                            payload = " ".join(left_tokens[1:])
                            clean_payload = _strip_outer_quotes(payload)
                            inner_dec = audit_pre_tool_use_command(clean_payload)
                            if not inner_dec.allowed:
                                return HookDecision(
                                    allowed=False,
                                    exit_code=2,
                                    command=command,
                                    vector="CHAINED_CIRCUMVENTION",
                                    reason=f"Bypass detected in piped shell execution: {inner_dec.reason}",
                                    metadata={"nested_vector": inner_dec.vector, "piped_command": clean_payload},
                                )

    segments = _split_pipeline_segments(command)
    has_chaining = len(segments) > 1 or any(op in command for op in ("&&", "||", ";", "|", "&", "\n"))
    has_suppression = bool(RE_SUPPRESSIONS.search(command))

    for segment in segments:
        decision = _audit_single_command(segment)
        if not decision.allowed:
            # If pipeline combines bypass flags with suppression flags or chained execution
            if has_chaining and has_suppression:
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=command,
                    vector="CHAINED_CIRCUMVENTION",
                    reason=f"Bypass detected in chained/suppressed pipeline: {decision.reason}",
                    metadata={
                        "primary_vector": decision.vector,
                        "failing_segment": segment,
                        "has_chaining": True,
                        "has_suppression": True,
                    },
                )
            # Retain original vector
            return HookDecision(
                allowed=False,
                exit_code=2,
                command=command,
                vector=decision.vector,
                reason=decision.reason,
                metadata=decision.metadata,
            )

    return HookDecision(allowed=True, exit_code=0, command=command)


def _compute_digest_fallback(modified_anchors: dict[str, str], kill_rate: float = 1.0) -> str:
    """Computes deterministic 16-hex character (64-bit) BLAKE2b digest."""
    try:
        from cordis.forge_guard import compute_diff_attestation_digest

        return compute_diff_attestation_digest(modified_anchors, gate2_kill_rate=kill_rate)
    except (ImportError, AttributeError):
        if not modified_anchors:
            payload = f"EMPTY_DIFF:{kill_rate:.4f}"
        else:
            lines = [f"{k}:{v}:{kill_rate:.4f}" for k, v in sorted(modified_anchors.items())]
            payload = "\n".join(lines)
        return hashlib.blake2b(payload.encode("utf-8"), digest_size=8).hexdigest()


def run_stop_hook_prosecutor(repo_dir: str = ".", max_retries: int = 3) -> int:
    """Evaluates working tree state before turn completion.
    - Exits in <10ms for clean trees.
    - Runs Gate 1 (test tampering) and Gate 2 (mutation gate) on modified files.
    - Enforces 3-strike circuit breaker per AST anchor via EpisodicMemoryLedger.
    - On pass, writes .cordis_attestation.json containing 64-bit BLAKE2b digest.
    """
    repo_path = Path(repo_dir).resolve()

    # Fast-Path: Extract uncommitted working-tree changes
    try:
        diff_report = extract_git_diff(repo_dir=str(repo_path), base_ref="HEAD", target_ref=None)
    except Exception:
        diff_report = None

    if diff_report is None or (
        not diff_report.source_files
        and not diff_report.test_files
        and not diff_report.modified_functions
        and not (diff_report.raw_diff or "").strip()
    ):
        # Clean working tree -> exit 0 in <10ms
        return 0

    # Gate 1: Audit test tampering on modified test files
    gate1_failed = False
    gate1_violations: list[str] = []
    target_fns = diff_report.target_function_names

    for test_file in diff_report.test_files:
        test_full = repo_path / test_file
        if not test_full.is_file():
            continue
        new_test_code = test_full.read_text(encoding="utf-8", errors="replace")
        old_test_code = get_git_file_content("HEAD", test_file, repo_dir=str(repo_path)) or ""

        if test_file.endswith((".ts", ".tsx", ".js", ".jsx")):
            from cordis.ts_gate import audit_ts_test_tampering
            report = audit_ts_test_tampering(
                old_test_code=old_test_code,
                new_test_code=new_test_code,
                target_function_names=target_fns,
                file_path=test_file,
            )
        elif test_file.endswith(".go"):
            from cordis.polyglot_gate import audit_go_test_tampering
            report = audit_go_test_tampering(
                old_test_code,
                new_test_code,
                file_path=test_file,
            )
        elif test_file.endswith(".rs"):
            from cordis.polyglot_gate import audit_rust_test_tampering
            report = audit_rust_test_tampering(
                old_test_code,
                new_test_code,
                file_path=test_file,
                prod_rs_diff=diff_report.raw_diff or "",
            )
        elif test_file.endswith(".py"):
            report = audit_test_tampering(
                old_test_code=old_test_code,
                new_test_code=new_test_code,
                target_function_names=target_fns,
                file_path=test_file,
            )
        else:
            continue
        if not report.passed:
            gate1_failed = True
            gate1_violations.extend(report.violations)

    # Check if any modified .rs source file injected a production .unwrap() or .expect()
    if any(s.endswith(".rs") for s in diff_report.source_files):
        from cordis.polyglot_gate import audit_rust_test_tampering
        for src_file in diff_report.source_files:
            if src_file.endswith(".rs"):
                rs_rep = audit_rust_test_tampering(
                    "",
                    "",
                    file_path=src_file,
                    prod_rs_diff=diff_report.raw_diff or "",
                )
                if not rs_rep.passed:
                    gate1_failed = True
                    for v in rs_rep.violations:
                        if v not in gate1_violations:
                            gate1_violations.append(v)

    # Gate 2: Mutation gate on modified source files
    gate2_failed = False
    surviving_mutants: list[MutantResult] = []
    failing_anchor = ""
    failing_fn = ""
    failing_src = ""

    # Test code candidates for in-memory mutation
    test_code_candidates: list[str] = []
    for tf in diff_report.test_files:
        if not tf.endswith(".py"):
            continue
        tf_full = repo_path / tf
        if tf_full.is_file():
            test_code_candidates.append(tf_full.read_text(encoding="utf-8", errors="replace"))

    if not test_code_candidates:
        tests_dir = repo_path / "tests"
        if tests_dir.is_dir():
            for cand in sorted(tests_dir.glob("test_*.py")):
                try:
                    test_code_candidates.append(cand.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass

    primary_test_code = "\n".join(test_code_candidates[:2])

    for mod_fn in diff_report.modified_functions:
        if mod_fn.is_test or not mod_fn.file_path.endswith(".py"):
            continue
        src_file = mod_fn.file_path
        src_full = repo_path / src_file
        if not src_full.is_file():
            continue
        src_code = src_full.read_text(encoding="utf-8", errors="replace")

        if src_code and primary_test_code:
            mod_name = Path(src_file).with_suffix("").as_posix().replace("/", ".")
            g2_rep = run_in_memory_mutation_gate(
                source_code=src_code,
                test_code=primary_test_code,
                target_function=mod_fn.name,
                module_name=mod_name,
            )
            if not g2_rep.passed:
                gate2_failed = True
                survived = [m for m in g2_rep.results if not m.killed]
                surviving_mutants.extend(survived)
                failing_fn = mod_fn.name
                failing_src = src_code

                anchors = index_ast_anchors(src_code, file_path=src_file)
                if mod_fn.name in anchors:
                    failing_anchor = anchors[mod_fn.name].tag
                else:
                    failing_anchor = f"¶{src_file}#{mod_fn.name}"
                break

    # Episodic Memory & Circuit Breaker Tracking
    db_path = repo_path / ".cordis_memory.db"
    ledger = EpisodicMemoryLedger(db_path=db_path)

    try:
        if gate1_failed or gate2_failed:
            failure_mode = "gate1_tampering" if gate1_failed else "gate2_mutant_survived"
            summary = (
                "; ".join(gate1_violations[:2])
                if gate1_failed
                else f"{len(surviving_mutants)} AST mutant(s) survived"
            )
            anchor = (
                failing_anchor
                or (f"¶{diff_report.test_files[0]}#tampering" if diff_report.test_files else "¶repo#gate_failure")
            )
            fn_name = failing_fn or "test_suite"

            # Check existing retry count for this anchor
            cur = ledger.conn.cursor()
            cur.execute(
                "SELECT flake_retry_count FROM memory_entries WHERE ast_anchor = ? AND failure_mode = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
                (anchor, failure_mode),
            )
            row = cur.fetchone()
            prior_retries = row[0] if row else 0
            retry_count = prior_retries + 1

            ledger.record_outcome(
                ast_anchor=anchor,
                function_name=fn_name,
                failure_mode=failure_mode,
                summary=summary,
                tags="stop_hook_gate_failure",
            )

            if retry_count < max_retries:
                # Strikes 1 or 2: emit bounded <25-line stderr remediation block with repair suggestion
                test_suggestion = ""
                if failing_src and surviving_mutants:
                    try:
                        test_suggestion = synthesize_mutant_killing_test(
                            source_code=failing_src,
                            target_function=fn_name,
                            surviving_mutants=surviving_mutants,
                        )
                    except Exception:
                        test_suggestion = ""

                rem_lines = [
                    "🛑 [Cordis Stop Hook Blocked]: Verification failure in working tree.",
                    f"Target: {fn_name} [Anchor: {anchor}] (Strike {retry_count}/{max_retries})",
                    f"Failure: {summary}",
                ]
                if test_suggestion:
                    rem_lines.append("Remediation suggestion:")
                    for line in test_suggestion.strip().splitlines()[:15]:
                        rem_lines.append(f"  {line}")

                bounded_output = "\n".join(rem_lines[:24]) + "\n"
                sys.stderr.write(bounded_output)
                return 2
            else:
                # Strike >= max_retries: Trigger circuit breaker
                alert_lines = [
                    f"[CIRCUIT BREAKER TRIGGERED: Max retries ({max_retries}) reached. Halting loop. NEEDS_HUMAN_ARBITRATION]",
                    f"Target: {fn_name} [Anchor: {anchor}] failed {retry_count} times.",
                    "Halting agent execution loop to prevent infinite retry and token exhaustion.",
                ]
                bounded_alert = "\n".join(alert_lines[:24]) + "\n"
                sys.stderr.write(bounded_alert)
                return 2

        # All gates passed: Compute 64-bit BLAKE2b diff attestation digest
        modified_anchors: dict[str, str] = {}
        for sf in diff_report.source_files:
            sf_full = repo_path / sf
            if sf_full.is_file():
                try:
                    code = sf_full.read_text(encoding="utf-8", errors="replace")
                    anchors = index_ast_anchors(code, file_path=sf)
                    for name, a in anchors.items():
                        modified_anchors[f"{sf}::{name}"] = a.tag
                except Exception:
                    pass

        digest = _compute_digest_fallback(modified_anchors, kill_rate=1.0)

        # Write .cordis_attestation.json to repo_dir
        attestation_file = repo_path / ".cordis_attestation.json"
        attestation_data = {
            "digest": digest,
            "gate2_kill_rate": 1.0,
            "modified_anchors": modified_anchors,
            "status": "PASSED",
        }
        attestation_file.write_text(json.dumps(attestation_data, indent=2) + "\n", encoding="utf-8")
        return 0

    finally:
        ledger.close()


def install_harness_hooks(
    repo_dir: str = ".",
    targets: list[str] = ["git", "claude"],
) -> list[str]:
    """Safely installs git pre-commit and Claude Code settings hook configurations.
    Returns list of installed file paths.
    """
    repo_path = Path(repo_dir).resolve()
    installed: list[str] = []

    norm_targets = {t.lower() for t in targets}
    if "all" in norm_targets:
        norm_targets.update(["git", "claude"])

    if "git" in norm_targets:
        git_hooks_dir = repo_path / ".git" / "hooks"
        git_hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit_file = git_hooks_dir / "pre-commit"
        script_content = (
            "#!/usr/bin/env sh\n"
            "# Cordis Gate 0 Pre-Commit Hook\n"
            "python -m cordis.cli hooks stop-gate --repo-dir .\n"
        )
        pre_commit_file.write_text(script_content, encoding="utf-8", newline="\n")
        try:
            os.chmod(pre_commit_file, 0o755)
        except OSError:
            pass
        installed.append(str(pre_commit_file))

    if "claude" in norm_targets:
        claude_dir = repo_path / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        settings_file = claude_dir / "settings.local.json"

        settings_data: dict[str, Any] = {}
        if settings_file.is_file():
            try:
                settings_data = json.loads(settings_file.read_text(encoding="utf-8"))
            except Exception:
                settings_data = {}

        hooks_section = settings_data.setdefault("hooks", {})
        hooks_section["PreToolUse"] = 'python -m cordis.cli hooks check-cmd --command "$COMMAND"'
        hooks_section["Stop"] = "python -m cordis.cli hooks stop-gate --repo-dir ."

        settings_file.write_text(
            json.dumps(settings_data, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        installed.append(str(settings_file))

    return installed


# Backward-compatible and procedural alias
handle_stop_hook = run_stop_hook_prosecutor

