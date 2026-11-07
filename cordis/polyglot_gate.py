"""Gate 1 & Gate 2: Zero-Dependency Polyglot AST Gate (Go & Rust).
Provides 64-bit BLAKE2b AST anchor indexing, test tampering / anti-mock auditing,
and diff-scoped mutant synthesis for Go and Rust using 100% Python 3.10+ standard library.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from cordis.ast_gate import ASTAnchor, TestTamperingReport, compute_node_hash

__all__ = [
    "AnchorDict",
    "mask_go_code",
    "index_go_ast_anchors",
    "audit_go_test_tampering",
    "generate_go_mutants",
    "mask_rust_code",
    "index_rust_ast_anchors",
    "audit_rust_test_tampering",
    "generate_rust_mutants",
]


class AnchorDict(dict):
    """Dictionary mapping qualified names, anchor tags, and hash tags to ASTAnchor."""

    def __getitem__(self, key: str) -> ASTAnchor:
        if super().__contains__(key):
            return super().__getitem__(key)
        for anchor in self.values():
            if anchor.tag == key or anchor.hash_tag == key:
                return anchor
        if "::" in key:
            alt = key.replace("::", ".")
            if super().__contains__(alt):
                return super().__getitem__(alt)
        elif "." in key:
            alt = key.replace(".", "::")
            if super().__contains__(alt):
                return super().__getitem__(alt)
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            if any(anchor.tag == key or anchor.hash_tag == key for anchor in self.values()):
                return True
            if "::" in key:
                alt = key.replace("::", ".")
                if super().__contains__(alt):
                    return True
            elif "." in key:
                alt = key.replace(".", "::")
                if super().__contains__(alt):
                    return True
        return False


def _find_matching_brace(code: str, start_idx: int) -> int:
    """Finds index of matching '}' for '{' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1


def _find_matching_paren(code: str, start_idx: int) -> int:
    """Finds index of matching ')' for '(' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


# ==============================================================================
# GO GATE: LEXICAL SCANNER, AST ANCHOR INDEXER, TAMPERING AUDITOR & MUTATOR
# ==============================================================================


def mask_go_code(code: str, mask_strings: bool = True) -> str:
    """Masks comments and optionally strings/runes in Go code with whitespace,
    preserving exact character offsets and newline positions (\\n).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # Line comment: // ...
        if c == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue

        # Block comment: /* ... */ (non-nestable in Go)
        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                else:
                    out.append("\n" if code[i] == "\n" else " ")
                    i += 1
            continue

        # Raw string literal: `...`
        if c == "`":
            out.append(" " if mask_strings else "`")
            i += 1
            while i < n:
                if code[i] == "`":
                    out.append(" " if mask_strings else "`")
                    i += 1
                    break
                else:
                    out.append("\n" if code[i] == "\n" else (" " if mask_strings else code[i]))
                    i += 1
            continue

        # Interpreted string literal: "..."
        if c == '"':
            out.append(" " if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(" " if mask_strings else '"')
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Rune literal: '...'
        if c == "'":
            out.append(" " if mask_strings else "'")
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == "'":
                    out.append(" " if mask_strings else "'")
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out)


def _extract_go_receiver_type(recv_str: str) -> str:
    """Extracts base receiver struct name from Go receiver parameter string."""
    cleaned = recv_str.strip()
    no_brackets = re.sub(r"\[.*\]", "", cleaned).strip()
    parts = no_brackets.split()
    type_part = parts[-1] if parts else no_brackets
    type_part = type_part.lstrip("*&").strip()
    return type_part


def index_go_ast_anchors(source_code: str, file_path: str = "module.go") -> Dict[str, ASTAnchor]:
    """Indexes functions and receiver methods in Go code into 64-bit BLAKE2b AST anchors."""
    clean_code = source_code.lstrip("\ufeff")
    if not clean_code.strip():
        return AnchorDict()

    masked = mask_go_code(clean_code, mask_strings=True)
    anchors = AnchorDict()

    # Match func declarations:
    # 1. func (r *Receiver) Method(args) ... {
    # 2. func FunctionName(args) ... {
    func_pattern = re.compile(
        r"(?:^|[;\n\s])func\s+(?:\((?P<recv>[^)]+)\)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    )

    for m in func_pattern.finditer(masked):
        idx = m.start()
        # Find exact start of 'func' keyword
        func_kw_idx = clean_code.find("func", idx, m.end())
        if func_kw_idx == -1:
            continue

        recv_raw = m.group("recv")
        name = m.group("name")

        if recv_raw:
            scope_path = _extract_go_receiver_type(recv_raw)
            qualname = f"{scope_path}.{name}"
            node_type = "MethodDeclaration"
        else:
            scope_path = "<module>"
            qualname = name
            node_type = "FunctionDeclaration"

        # Find opening brace '{'
        decl_end = m.end()
        brace_idx = masked.find("{", decl_end)
        if brace_idx == -1:
            continue

        # Check that there is no semicolon or other func before '{'
        intermediate = masked[decl_end:brace_idx]
        if ";" in intermediate:
            continue

        close_brace_idx = _find_matching_brace(masked, brace_idx)
        lineno = clean_code.count("\n", 0, func_kw_idx) + 1
        end_lineno = clean_code.count("\n", 0, close_brace_idx) + 1

        raw_sig = clean_code[func_kw_idx:brace_idx].strip()
        sig = re.sub(r"\s+", " ", raw_sig)

        raw_body = clean_code[brace_idx + 1 : close_brace_idx]
        norm_body = re.sub(r"\s+", "", raw_body)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            normalized_body_dump=norm_body,
        )

        anchor = ASTAnchor(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )

        anchors[qualname] = anchor

    return anchors


def _count_go_table_cases(code: str) -> int:
    """Counts test cases inside Go table-driven struct slice literals."""
    masked = mask_go_code(code, mask_strings=True)
    pattern = re.compile(r"\[\]struct\s*\{[^}]*\}\s*\{")
    total_cases = 0
    for m in pattern.finditer(masked):
        body_start = m.end() - 1
        body_end = _find_matching_brace(masked, body_start)
        slice_body = masked[body_start + 1 : body_end]
        depth = 0
        cases = 0
        for ch in slice_body:
            if ch == "{":
                if depth == 0:
                    cases += 1
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
        total_cases += cases
    return total_cases


def audit_go_test_tampering(
    old_go: str,
    new_go: str,
    file_path: str = "module_test.go",
) -> TestTamperingReport:
    """Audits Go tests for tampering, skipping (t.Skip), weakened assertions,
    blank identifier result discarding (_ = got), and table shrinking.
    """
    violations: List[str] = []
    clean_new = new_go.lstrip("\ufeff")
    masked_new = mask_go_code(clean_new, mask_strings=False)

    # 1. Test Skipping: t.Skip / t.Skipf / t.SkipNow
    skip_pattern = re.compile(r"\bt\.(?:Skip|Skipf|SkipNow)\b")
    for m in skip_pattern.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Test decorated with t.Skip / t.SkipNow.")

    # 2. Strong vs Hollow assertions
    strong_re = re.compile(
        r"\b(?:assert\.Equal|require\.Equal|assert\.True|require\.True|assert\.False|require\.False|"
        r"assert\.Contains|cmp\.Diff|cmp\.Equal|reflect\.DeepEqual|t\.Errorf|t\.Fatalf|t\.FailNow)\b"
    )
    hollow_re = re.compile(
        r"\b(?:assert\.NotNil|require\.NotNil|assert\.Nil|require\.Nil|assert\.NotZero|require\.NotZero)\b"
    )

    old_strong = list(strong_re.finditer(old_go))
    new_strong = list(strong_re.finditer(clean_new))
    new_hollow = list(hollow_re.finditer(clean_new))

    if new_hollow and (len(old_strong) > len(new_strong) or len(new_strong) == 0):
        for hm in new_hollow:
            lineno = clean_new.count("\n", 0, hm.start()) + 1
            violations.append(
                f"Line {lineno}: Strong value assertions weakened to hollow checks (assert.NotNil / hollow check without value comparison)."
            )

    # 3. Blank identifier result discarding: _ = got
    blank_re = re.compile(r"(?:^|[;{\n])\s*_\s*=\s*[^;\n]+")
    for m in blank_re.finditer(masked_new):
        u_idx = clean_new.find("_", m.start(), m.end())
        idx = u_idx if u_idx != -1 else m.start()
        lineno = clean_new.count("\n", 0, idx) + 1
        violations.append(
            f"Line {lineno}: Test discards output value via blank identifier '_ = got' without assertion."
        )

    # 4. Table-driven test shrinking
    old_table_cases = _count_go_table_cases(old_go)
    new_table_cases = _count_go_table_cases(clean_new)
    if old_table_cases > 0 and new_table_cases < old_table_cases:
        violations.append(
            f"Line 1: Table-driven test table was shrunk (deleted test cases from {old_table_cases} to {new_table_cases})."
        )

    # 5. Tautological assertions: assert.Equal(t, x, x) or assert.True(t, true)
    tautology_eq = re.compile(r"\bassert\.Equal\s*\(\s*[^,]+,\s*([A-Za-z0-9_]+)\s*,\s*\1\s*\)")
    for m in tautology_eq.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (comparing variable to itself).")

    tautology_true = re.compile(r"\bassert\.True\s*\(\s*[^,]+,\s*true\s*\)")
    for m in tautology_true.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (asserting true).")

    anchors = index_go_ast_anchors(clean_new, file_path=file_path) if clean_new.strip() else AnchorDict()

    return TestTamperingReport(
        passed=len(violations) == 0,
        old_assert_count=len(old_strong),
        new_assert_count=len(new_strong),
        violations=violations,
        anchors=anchors,
    )


def generate_go_mutants(
    go_code: str,
    max_mutants: int = 5,
    target_function: Optional[str] = None,
) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped Go mutants.
    Returns list of (description, lineno, mutated_go_code).
    """
    clean_code = go_code.lstrip("\ufeff")
    if not clean_code.strip():
        return []

    masked = mask_go_code(clean_code, mask_strings=True)
    anchors = index_go_ast_anchors(clean_code)

    start_line = 1
    end_line = clean_code.count("\n") + 1

    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
            else:
                return []

    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()

    patterns: List[Tuple[str, str, str]] = [
        (r"==", "!=", "Equality inverted (== to !=)"),
        (r"!=", "==", "Inequality inverted (!= to ==)"),
        (r"<=", "<", "Relational boundary adjusted (<= to <)"),
        (r">=", ">", "Relational boundary adjusted (>= to >)"),
        (r"(?<![<=-])<(?![<=-])", ">=", "Relational order inverted (< to >=)"),
        (r"(?<![>=-])>(?![>=-])", "<=", "Relational order inverted (> to <=)"),
        (r"&&", "||", "Logical AND inverted to OR (&& to ||)"),
        (r"\|\|", "&&", "Logical OR inverted to AND (|| to &&)"),
        (r"(?<!\+)\+(?!\+|=)", "-", "Arithmetic addition inverted to subtraction (+ to -)"),
        (r"(?<!-)-(?!-|=|>)", "+", "Arithmetic subtraction inverted to addition (- to +)"),
        (r"\btrue\b", "false", "Boolean literal inverted (true to false)"),
        (r"\bfalse\b", "true", "Boolean literal inverted (false to true)"),
    ]

    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count("\n", 0, idx) + 1
            if not (start_line <= lineno <= end_line):
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f"Line {lineno}: {desc}", lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants

    # Return nil mutation: return <expr> -> return nil
    ret_re = re.compile(r"\breturn\s+([^;\n]+)")
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count("\n", 0, idx) + 1
        if not (start_line <= lineno <= end_line):
            continue
        expr = clean_code[m.start(1) : m.end(1)].strip()
        if expr == "nil":
            continue
        mutated = clean_code[: m.start(1)] + "nil" + clean_code[m.end(1) :]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'nil'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants

    return mutants


# ==============================================================================
# RUST GATE: LEXICAL SCANNER, AST ANCHOR INDEXER, TAMPERING AUDITOR & MUTATOR
# ==============================================================================


def mask_rust_code(code: str, mask_strings: bool = True) -> str:
    """Masks comments and optionally strings/literals in Rust code with whitespace,
    supporting nested block comments (/* /* */ */), raw strings (r#\"...\"#),
    and character literals vs lifetime annotations ('a).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # Line comment: //, ///, //!
        if c == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue

        # Nested block comment: /* ... /* ... */ ... */
        if c == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if code[i] == "/" and i + 1 < n and code[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if code[i] == "\n" else " ")
                    i += 1
            continue

        # Raw string literal: r"...", r#"..."#, r##"..."##, br#"..."#
        if (c == "r" and (nxt == '"' or nxt == "#")) or (c == "b" and nxt == "r"):
            raw_match = re.match(r"^(?:b)?r(#*)\"", code[i:])
            if raw_match:
                hashes = raw_match.group(1)
                delim = f'"{hashes}'
                prefix_len = len(raw_match.group(0))
                out.append(" " * prefix_len if mask_strings else code[i : i + prefix_len])
                i += prefix_len
                end_pos = code.find(delim, i)
                if end_pos != -1:
                    inner = code[i:end_pos]
                    for ch in inner:
                        out.append("\n" if ch == "\n" else (" " if mask_strings else ch))
                    out.append(" " * len(delim) if mask_strings else delim)
                    i = end_pos + len(delim)
                    continue

        # Regular string literal: "..."
        if c == '"':
            out.append(" " if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(" " if mask_strings else '"')
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Char literal vs Lifetime: 'c' vs 'a
        if c == "'":
            char_match = re.match(r"^'(?:[^'\\]|\\(?:[nrt0\\'\"\\/]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}))'", code[i:])
            if char_match:
                c_len = len(char_match.group(0))
                out.append(" " * c_len if mask_strings else char_match.group(0))
                i += c_len
                continue

        out.append(c)
        i += 1

    return "".join(out)


def index_rust_ast_anchors(source_code: str, file_path: str = "lib.rs") -> Dict[str, ASTAnchor]:
    """Indexes functions and impl methods in Rust code into 64-bit BLAKE2b AST anchors."""
    clean_code = source_code.lstrip("\ufeff")
    if not clean_code.strip():
        return AnchorDict()

    masked = mask_rust_code(clean_code, mask_strings=True)
    anchors = AnchorDict()

    # Pass 1: Discover impl blocks to establish scopes
    # impl StructName { ... } or impl Trait for StructName { ... }
    impl_blocks: List[Tuple[int, int, str]] = []
    impl_pattern = re.compile(r"\bimpl\b(?P<hdr>[^{]+)\{")
    for m in impl_pattern.finditer(masked):
        brace_idx = m.end() - 1
        end_brace_idx = _find_matching_brace(masked, brace_idx)
        hdr = m.group("hdr").strip()
        if " for " in hdr:
            target_raw = hdr.split(" for ")[-1].strip()
        else:
            target_raw = hdr
        target_clean = re.sub(r"<[^>]*>", "", target_raw)
        target_clean = target_clean.split("where")[0].strip()
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", target_clean)
        target_type = words[-1] if words else "Unknown"
        impl_blocks.append((brace_idx, end_brace_idx, target_type))

    # Pass 2: Discover fn declarations
    fn_pattern = re.compile(
        r"(?:^|[;\n\s])(?:pub(?:\([^)]+\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    )

    for m in fn_pattern.finditer(masked):
        idx = m.start()
        fn_kw_idx = clean_code.find("fn", idx, m.end())
        if fn_kw_idx == -1:
            continue

        name = m.group("name")

        # Determine scope from enclosing impl blocks
        scope_path = "<module>"
        node_type = "FunctionDeclaration"
        for start_b, end_b, t_name in impl_blocks:
            if start_b <= fn_kw_idx <= end_b:
                scope_path = t_name
                node_type = "MethodDeclaration"
                break

        qualname = f"{scope_path}.{name}" if scope_path != "<module>" else name

        decl_end = m.end()
        brace_idx = masked.find("{", decl_end)
        if brace_idx == -1:
            continue

        intermediate = masked[decl_end:brace_idx]
        if ";" in intermediate:
            # Trait method stub without body
            continue

        close_brace_idx = _find_matching_brace(masked, brace_idx)
        lineno = clean_code.count("\n", 0, fn_kw_idx) + 1
        end_lineno = clean_code.count("\n", 0, close_brace_idx) + 1

        raw_sig = clean_code[fn_kw_idx:brace_idx].strip()
        sig = re.sub(r"\s+", " ", raw_sig)

        raw_body = clean_code[brace_idx + 1 : close_brace_idx]
        norm_body = re.sub(r"\s+", "", raw_body)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            normalized_body_dump=norm_body,
        )

        anchor = ASTAnchor(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )

        anchors[qualname] = anchor

    return anchors


def _is_rust_test_path(path_str: str) -> bool:
    name = re.split(r"[\\/]", path_str)[-1].lower()
    if (
        name.endswith("_test.rs")
        or name in ("test.rs", "tests.rs")
        or (name.startswith("test_") and name.endswith(".rs"))
    ):
        return True
    parts = [part.lower() for part in re.split(r"[\\/]", path_str)]
    if any(part in ("tests", "test", "__tests__") for part in parts):
        return True
    return False


def audit_rust_test_tampering(
    old_rs: str,
    new_rs: str,
    file_path: str = "lib.rs",
    prod_rs_diff: str = "",
) -> TestTamperingReport:
    """Audits Rust tests and production diffs for tampering:
    1. #[ignore] skip attributes on test functions.
    2. Weak assertions (assert!(x.is_ok()) / assert!(x.is_some()) without payload equality).
    3. Production code .unwrap() / .expect() panic injections (grounded in Prusti & Creusot verification).
    4. Tautological assertions.
    """
    violations: List[str] = []
    clean_new = new_rs.lstrip("\ufeff")
    masked_new = mask_rust_code(clean_new, mask_strings=False)

    # 1. #[ignore] attribute detection
    ignore_pattern = re.compile(r"#\[\s*ignore(?:\s*=\s*\"[^\"]*\")?\s*\]")
    for m in ignore_pattern.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Test decorated with #[ignore] attribute.")

    # 2. Weak assertions: assert!(x.is_ok()) / assert!(x.is_some()) without value comparison
    assert_pattern = re.compile(r"\bassert!\s*\(")
    for m in assert_pattern.finditer(masked_new):
        open_paren_idx = m.end() - 1
        close_paren_idx = _find_matching_paren(masked_new, open_paren_idx)
        if close_paren_idx != -1:
            inner = clean_new[open_paren_idx + 1 : close_paren_idx]
            if re.search(r"\.(?:is_ok|is_some|is_err|is_none)\s*\(\s*\)", inner):
                lineno = clean_new.count("\n", 0, m.start()) + 1
                violations.append(
                    f"Line {lineno}: Weak assertion 'assert!(x.is_ok())' used without value equality assertion (violates Prusti/Creusot postcondition invariant)."
                )

    # 3. Production code panic injection via .unwrap() / .expect() in prod_rs_diff
    if prod_rs_diff:
        has_unified_headers = (
            "diff --git " in prod_rs_diff
            or "\n--- " in prod_rs_diff
            or prod_rs_diff.startswith("--- ")
            or "\n+++ " in prod_rs_diff
            or prod_rs_diff.startswith("+++ ")
        )
        current_file: Optional[str] = None if has_unified_headers else file_path

        for line_idx, line in enumerate(prod_rs_diff.splitlines(), start=1):
            if line.startswith("diff --git "):
                m = re.match(r"^diff --git\s+(?:a/)?(.*?)\s+(?:b/)?(.*)$", line)
                if m:
                    current_file = m.group(2).strip()
                continue
            if line.startswith("+++ "):
                target = line[4:].strip()
                if target.startswith("b/"):
                    target = target[2:].strip()
                if target != "/dev/null":
                    current_file = target
                continue

            if line.startswith("+") and not line.startswith("+++"):
                if current_file:
                    if not current_file.endswith(".rs") or _is_rust_test_path(current_file):
                        continue
                elif has_unified_headers:
                    continue
                else:
                    if file_path and _is_rust_test_path(file_path):
                        continue

                added_code = line[1:]
                masked_added = mask_rust_code(added_code, mask_strings=True)
                if re.search(r"(?<!\bunwrap_or)(?<!\bunwrap_or_else)(?<!\bunwrap_or_default)\.unwrap\s*\(", masked_added):
                    violations.append(
                        f"Line {line_idx}: Production code injects unsafe/panic-prone .unwrap() call (violates Prusti/Creusot panic-freedom invariant)."
                    )
                elif re.search(r"\.expect\s*\(", masked_added):
                    violations.append(
                        f"Line {line_idx}: Production code injects unsafe/panic-prone .expect() call (violates Prusti/Creusot panic-freedom invariant)."
                    )

    # 4. Tautological assertions: assert_eq!(x, x) or assert!(true)
    tautology_eq = re.compile(r"\bassert_eq!\s*\(\s*([A-Za-z0-9_]+)\s*,\s*\1\s*\)")
    for m in tautology_eq.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (comparing variable to itself).")

    tautology_true = re.compile(r"\bassert!\s*\(\s*true\s*\)")
    for m in tautology_true.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (asserting true).")

    anchors = index_rust_ast_anchors(clean_new, file_path=file_path) if clean_new.strip() else AnchorDict()
    old_asserts = len(re.findall(r"\b(?:assert_eq!|assert_ne!|assert!|matches!)\b", old_rs))
    new_asserts = len(re.findall(r"\b(?:assert_eq!|assert_ne!|assert!|matches!)\b", clean_new))

    return TestTamperingReport(
        passed=len(violations) == 0,
        old_assert_count=old_asserts,
        new_assert_count=new_asserts,
        violations=violations,
        anchors=anchors,
    )


def generate_rust_mutants(
    rs_code: str,
    max_mutants: int = 5,
    target_function: Optional[str] = None,
) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped Rust mutants.
    Returns list of (description, lineno, mutated_rs_code).
    """
    clean_code = rs_code.lstrip("\ufeff")
    if not clean_code.strip():
        return []

    masked = mask_rust_code(clean_code, mask_strings=True)
    anchors = index_rust_ast_anchors(clean_code)

    start_line = 1
    end_line = clean_code.count("\n") + 1

    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
            else:
                return []

    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()

    patterns: List[Tuple[str, str, str]] = [
        (r"==", "!=", "Equality inverted (== to !=)"),
        (r"!=", "==", "Inequality inverted (!= to ==)"),
        (r"<=", "<", "Relational boundary adjusted (<= to <)"),
        (r">=", ">", "Relational boundary adjusted (>= to >)"),
        (r"(?<![<=-])<(?![<=-])", ">=", "Relational order inverted (< to >=)"),
        (r"(?<![>=-])>(?![>=-])", "<=", "Relational order inverted (> to <=)"),
        (r"&&", "||", "Logical AND inverted to OR (&& to ||)"),
        (r"\|\|", "&&", "Logical OR inverted to AND (|| to &&)"),
        (r"(?<!\+)\+(?!\+|=)", "-", "Arithmetic addition inverted to subtraction (+ to -)"),
        (r"(?<!-)-(?!-|=|>)", "+", "Arithmetic subtraction inverted to addition (- to +)"),
        (r"\btrue\b", "false", "Boolean literal inverted (true to false)"),
        (r"\bfalse\b", "true", "Boolean literal inverted (false to true)"),
    ]

    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count("\n", 0, idx) + 1
            if not (start_line <= lineno <= end_line):
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f"Line {lineno}: {desc}", lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants

    # Return Default::default() mutation: return <expr>; -> return Default::default();
    ret_re = re.compile(r"\breturn\s+([^;]+);")
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count("\n", 0, idx) + 1
        if not (start_line <= lineno <= end_line):
            continue
        expr = clean_code[m.start(1) : m.end(1)].strip()
        if expr == "Default::default()":
            continue
        mutated = clean_code[: m.start(1)] + "Default::default()" + clean_code[m.end(1) :]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'Default::default()'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants

    return mutants
