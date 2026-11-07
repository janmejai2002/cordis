"""Gate 1 & Gate 2: Zero-Dependency TypeScript / JavaScript / Jest / Vitest AST Gate.
Provides 64-bit BLAKE2b AST anchor indexing, test tampering / anti-mock auditing,
and diff-scoped mutant synthesis using 100% Python 3.10+ standard library.
"""
from __future__ import annotations
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from cordis.ast_gate import ASTAnchor, TestTamperingReport, compute_node_hash
__all__ = ['AnchorDict', 'index_ts_ast_anchors', 'audit_ts_test_tampering', 'generate_ts_mutants', 'mask_ts_code', 'strip_ts_comments', 'BOUNDARY_MOCK_TARGETS']

class AnchorDict(dict):
    """Dictionary mapping qualified names and anchor tags to ASTAnchor."""

    def __getitem__(self, key: str) -> ASTAnchor:
        if super().__contains__(key):
            return super().__getitem__(key)
        for anchor in self.values():
            if anchor.tag == key or anchor.hash_tag == key:
                return anchor
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return any((anchor.tag == key or anchor.hash_tag == key for anchor in self.values()))
        return False

def _is_regex_start(code: str, pos: int) -> bool:
    """Heuristic check whether `/` at `pos` starts a regex literal rather than division."""
    j = pos - 1
    while j >= 0 and code[j] in ' \t\r\n':
        j -= 1
    if j < 0:
        return True
    prev = code[j]
    if prev in '+-':
        if j > 0 and code[j - 1] == prev and (j < 2 or code[j - 2] != prev):
            return False
    if prev in '(=[!&|?:,;~^><+*%-{':
        return True
    if prev.isalnum() or prev in '_$':
        k = j
        while k >= 0 and (code[k].isalnum() or code[k] in '_$'):
            k -= 1
        word = code[k + 1:j + 1]
        if word in ('return', 'yield', 'case', 'default', 'typeof', 'delete', 'void', 'throw', 'await', 'in', 'of', 'instanceof', 'else', 'do'):
            return True
        return False
    return False

def mask_ts_code(code: str, mask_strings: bool=True) -> str:
    """Masks comments and optionally string/template literals with whitespace,
    preserving exact byte offsets and newline positions (\\n).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    stack: List[Any] = []
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ''
        if stack and stack[-1] == 'TEMPLATE':
            if c == '\\':
                if i + 1 < n:
                    if mask_strings:
                        out.append(' ')
                        out.append('\n' if nxt == '\n' else ' ')
                    else:
                        out.append(c)
                        out.append(nxt)
                    i += 2
                else:
                    out.append(' ' if mask_strings else c)
                    i += 1
                continue
            elif c == '`':
                stack.pop()
                out.append(' ' if mask_strings else '`')
                i += 1
                continue
            elif c == '$' and nxt == '{':
                stack.append(['EXPR', 1])
                out.append('  ' if mask_strings else '${')
                i += 2
                continue
            else:
                if mask_strings:
                    out.append('\n' if c == '\n' else ' ')
                else:
                    out.append(c)
                i += 1
                continue
        if stack and isinstance(stack[-1], list) and (stack[-1][0] == 'EXPR'):
            if c == '{':
                stack[-1][1] += 1
                out.append('{')
                i += 1
                continue
            elif c == '}':
                stack[-1][1] -= 1
                if stack[-1][1] == 0:
                    stack.pop()
                    out.append(' ' if mask_strings else '}')
                else:
                    out.append('}')
                i += 1
                continue
        if c == '/' and nxt == '/':
            out.append('  ')
            i += 2
            while i < n and code[i] != '\n':
                out.append(' ')
                i += 1
            continue
        if c == '/' and nxt == '*':
            out.append('  ')
            i += 2
            while i < n:
                if code[i] == '*' and i + 1 < n and (code[i + 1] == '/'):
                    out.append('  ')
                    i += 2
                    break
                else:
                    out.append('\n' if code[i] == '\n' else ' ')
                    i += 1
            continue
        if c == "'":
            out.append(' ' if mask_strings else "'")
            i += 1
            while i < n:
                sc = code[i]
                if sc == '\\':
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if snxt == '\n' else ' ')
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else sc)
                        i += 1
                elif sc == "'":
                    out.append(' ' if mask_strings else "'")
                    i += 1
                    break
                elif sc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else sc)
                    i += 1
            continue
        if c == '"':
            out.append(' ' if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == '\\':
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if snxt == '\n' else ' ')
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(' ' if mask_strings else '"')
                    i += 1
                    break
                elif sc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else sc)
                    i += 1
            continue
        if c == '`':
            stack.append('TEMPLATE')
            out.append(' ' if mask_strings else '`')
            i += 1
            continue
        if c == '/' and _is_regex_start(code, i):
            out.append(' ' if mask_strings else '/')
            i += 1
            in_char_class = False
            while i < n:
                rc = code[i]
                if rc == '\\':
                    if i + 1 < n:
                        rnxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if rnxt == '\n' else ' ')
                        else:
                            out.append(rc)
                            out.append(rnxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else rc)
                        i += 1
                elif rc == '[':
                    in_char_class = True
                    out.append(' ' if mask_strings else rc)
                    i += 1
                elif rc == ']' and in_char_class:
                    in_char_class = False
                    out.append(' ' if mask_strings else rc)
                    i += 1
                elif rc == '/' and (not in_char_class):
                    out.append(' ' if mask_strings else '/')
                    i += 1
                    while i < n and code[i].isalpha():
                        out.append(' ' if mask_strings else code[i])
                        i += 1
                    break
                elif rc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else rc)
                    i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)

def strip_ts_comments(code: str) -> str:
    """Masks only comments with whitespace, keeping string literals and regex intact."""
    return mask_ts_code(code, mask_strings=False)

def _find_matching_brace(code: str, start_idx: int) -> int:
    """Finds index of matching '}' for '{' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1

def _find_matching_paren(code: str, start_idx: int) -> int:
    """Finds index of matching ')' for '(' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == '(':
            depth += 1
        elif code[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    return -1

def _find_toplevel_relational_op(expr: str) -> Optional[Tuple[str, str, str]]:
    """Finds top-level relational operator in expression outside inner parens/brackets/braces.
    Returns (operator, lhs, rhs) or None.
    """
    e = expr.strip()
    while e.startswith('(') and e.endswith(')'):
        d = 0
        enclosed = True
        for idx in range(len(e) - 1):
            if e[idx] == '(':
                d += 1
            elif e[idx] == ')':
                d -= 1
                if d == 0:
                    enclosed = False
                    break
        if enclosed:
            e = e[1:-1].strip()
        else:
            break
    depth = 0
    i = 0
    n = len(e)
    while i < n:
        c = e[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif depth == 0:
            for op in ('===', '!==', '==', '!=', '<=', '>=', '<', '>'):
                if e.startswith(op, i):
                    if op in ('<', '>'):
                        if i + 1 < n and e[i + 1] in ('<', '>', '='):
                            continue
                    left = e[:i].strip()
                    right = e[i + len(op):].strip()
                    return (op, left, right)
        i += 1
    return None

def _extract_signature(params_raw: str) -> str:
    """Extracts normalized argument names from raw parameter declaration."""
    clean = params_raw.strip()
    if not clean:
        return '()'
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in clean:
        if ch in '([{<':
            depth += 1
            current.append(ch)
        elif ch in ')]}>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append(''.join(current).strip())
    arg_names: List[str] = []
    for p in parts:
        m = re.match('^([A-Za-z_$][A-Za-z0-9_$]*)', p)
        if m:
            arg_names.append(m.group(1))
        elif p:
            arg_names.append(p.split(':')[0].strip())
    return f"({', '.join(arg_names)})"

def index_ts_ast_anchors(ts_code: str, file_path: str='module.ts') -> Dict[str, ASTAnchor]:
    """Indexes all TypeScript/JavaScript functions, arrow functions, and class methods
    with 64-bit BLAKE2b AST anchors.
    """
    clean_code = ts_code.lstrip('\ufeff')
    if not clean_code.strip():
        return AnchorDict()
    masked = mask_ts_code(clean_code, mask_strings=True)
    no_comments = strip_ts_comments(clean_code)
    anchors = AnchorDict()
    class_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+(?:default\\s+)?)?(?:abstract\\s+)?class\\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)(?:<[\\s\\S]*?>)?(?:\\s+extends\\s+[A-Za-z0-9_$.<>\\s]+)?(?:\\s+implements\\s+[A-Za-z0-9_$,.<>\\s]+)?\\s*\\{', re.MULTILINE)
    class_spans: List[Tuple[str, int, int]] = []
    for m in class_re.finditer(masked):
        c_name = m.group('name')
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(masked, open_brace)
        class_spans.append((c_name, open_brace, close_brace))

    def get_enclosing_class(idx: int) -> Optional[str]:
        for c_name, ob, cb in class_spans:
            if ob < idx < cb:
                return c_name
        return None
    method_re = re.compile('(?:^|[;\\n}])\\s*(?:(?:public|private|protected|static|async|override|readonly)\\s+)*(?:\\*\\s*)?(?:(?:get|set)\\s+)?(?P<name>\\[[^\\]]+\\]|[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?:<[\\s\\S]*?>)?\\s*\\((?P<params>[^)]*)\\)\\s*(?::\\s*[^{;]+)?\\s*\\{', re.MULTILINE)
    for c_name, ob, cb in class_spans:
        class_body = masked[ob + 1:cb]
        for m in method_re.finditer(class_body):
            abs_name_start = ob + 1 + m.start('name')
            abs_name_end = ob + 1 + m.end('name')
            m_name = clean_code[abs_name_start:abs_name_end].strip()
            if m_name in ('if', 'for', 'while', 'switch', 'catch'):
                continue
            abs_start = ob + 1 + m.start()
            open_b = ob + 1 + m.end() - 1
            close_b = _find_matching_brace(masked, open_b)
            lineno = clean_code.count('\n', 0, abs_start) + 1
            end_lineno = clean_code.count('\n', 0, close_b) + 1
            sig = _extract_signature(m.group('params'))
            body_text = no_comments[open_b:close_b + 1]
            norm_body = re.sub('\\s+', '', body_text)
            qualname = f'{c_name}.{m_name}'
            hash_tag = compute_node_hash(file_path=file_path, scope_path=c_name, node_type='MethodDefinition', identifier=m_name, signature=sig, normalized_body_dump=norm_body)
            anchor = ASTAnchor(file_path=file_path, scope_path=c_name, node_type='MethodDefinition', identifier=m_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
            anchors[qualname] = anchor
    func_decl_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+(?:default\\s+)?)?(?P<async>async\\s+)?function(?:\\s*\\*\\s*|\\s+)(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?:<[\\s\\S]*?>)?\\s*\\((?P<params>[^)]*)\\)\\s*(?::\\s*[^{;]+)?\\s*\\{', re.MULTILINE)
    for m in func_decl_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group('name')
        is_async = bool(m.group('async'))
        node_type = 'AsyncFunctionDeclaration' if is_async else 'FunctionDeclaration'
        open_b = m.end() - 1
        close_b = _find_matching_brace(masked, open_b)
        lineno = clean_code.count('\n', 0, idx) + 1
        end_lineno = clean_code.count('\n', 0, close_b) + 1
        sig = _extract_signature(m.group('params'))
        body_text = no_comments[open_b:close_b + 1]
        norm_body = re.sub('\\s+', '', body_text)
        hash_tag = compute_node_hash(file_path=file_path, scope_path='<module>', node_type=node_type, identifier=f_name, signature=sig, normalized_body_dump=norm_body)
        anchor = ASTAnchor(file_path=file_path, scope_path='<module>', node_type=node_type, identifier=f_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
        anchors[f_name] = anchor
    arrow_assign_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+)?(?:const|let|var)\\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?::\\s*[^=]+)?\\s*=\\s*(?:async\\s+)?(?:<[\\s\\S]*?>\\s*)?(?:\\((?P<params>[^)]*)\\)|(?P<single_param>[A-Za-z_$][A-Za-z0-9_$]*))\\s*(?::\\s*(?:(?!=>).)*)?\\s*=>\\s*', re.MULTILINE)
    for m in arrow_assign_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group('name')
        params_raw = m.group('params') or m.group('single_param') or ''
        sig = _extract_signature(params_raw)
        arrow_end = m.end()
        body_rest = masked[arrow_end:].lstrip()
        leading_spaces = len(masked[arrow_end:]) - len(body_rest)
        body_start_idx = arrow_end + leading_spaces
        if body_start_idx < len(masked) and masked[body_start_idx] == '{':
            close_b = _find_matching_brace(masked, body_start_idx)
            end_idx = close_b
        else:
            end_idx = body_start_idx
            while end_idx < len(masked) and masked[end_idx] not in (';', '\n'):
                end_idx += 1
        lineno = clean_code.count('\n', 0, idx) + 1
        end_lineno = clean_code.count('\n', 0, end_idx) + 1
        body_text = no_comments[arrow_end:end_idx + 1]
        norm_body = re.sub('\\s+', '', body_text)
        hash_tag = compute_node_hash(file_path=file_path, scope_path='<module>', node_type='ArrowFunction', identifier=f_name, signature=sig, normalized_body_dump=norm_body)
        anchor = ASTAnchor(file_path=file_path, scope_path='<module>', node_type='ArrowFunction', identifier=f_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
        anchors[f_name] = anchor
    return anchors
BOUNDARY_MOCK_TARGETS = ('axios', 'fetch', 'http', 'https', 'node:http', 'node:https', 'fs', 'node:fs', 'path', 'node:path', 'child_process', 'node:child_process', 'redis', 'ioredis', 'pg', 'mysql', 'prisma', 'aws-sdk', '@aws-sdk', 'setTimeout', 'setInterval')

def _is_boundary_mock(target_str: str) -> bool:
    clean = target_str.strip('\'"`')
    return any((clean == b or clean.startswith(b + '/') or clean.startswith(b + '.') for b in BOUNDARY_MOCK_TARGETS))
STRONG_MATCHER_RE = re.compile('\\.(?:toBe|toEqual|toStrictEqual|toThrow|toThrowError|toMatchObject|toHaveLength|toContain|toMatch)\\s*\\(')
HOLLOW_MATCHER_RE = re.compile('\\.(?:toBeDefined\\s*\\(\\s*\\)|not\\s*\\.\\s*toBeNull\\s*\\(\\s*\\)|not\\s*\\.\\s*toBeUndefined\\s*\\(\\s*\\)|toBeTruthy\\s*\\(\\s*\\)|toBeFalsy\\s*\\(\\s*\\))')

def audit_ts_test_tampering(old_ts_code: str, new_ts_code: str, target_function_names: Optional[List[str]]=None, file_path: str='test_module.ts') -> TestTamperingReport:
    """Audits old vs new Jest/Vitest test code to catch test tampering."""
    target_set = set(target_function_names or [])
    clean_old = old_ts_code.lstrip('\ufeff')
    clean_new = new_ts_code.lstrip('\ufeff')
    old_no_comments = strip_ts_comments(clean_old)
    new_no_comments = strip_ts_comments(clean_new)
    violations: List[str] = []
    old_assert_matches = list(re.finditer('\\bexpect\\s*\\(', old_no_comments))
    new_assert_matches = list(re.finditer('\\bexpect\\s*\\(', new_no_comments))
    old_assert_count = len(old_assert_matches)
    new_assert_count = len(new_assert_matches)
    if old_assert_count > 0 and new_assert_count < old_assert_count:
        violations.append(f'Assertion count decreased from {old_assert_count} to {new_assert_count} (deleted assertions).')
    if new_assert_count == 0 and len(clean_new.strip()) > 0:
        violations.append('Test file contains zero expect assertions.')
    old_strong = len(STRONG_MATCHER_RE.findall(old_no_comments))
    new_strong = len(STRONG_MATCHER_RE.findall(new_no_comments))
    new_hollow = len(HOLLOW_MATCHER_RE.findall(new_no_comments))
    if old_strong > new_strong:
        violations.append(f'Strong value assertions weakened to hollow checks (strong asserts dropped from {old_strong} to {new_strong}).')
    if new_assert_count > 0 and new_strong == 0 and (new_hollow > 0):
        violations.append('New test is hollow (asserts only weak .toBeDefined()/.not.toBeNull() with zero strong value checks).')
    masked_new = mask_ts_code(new_no_comments, mask_strings=True)
    for m in re.finditer('\\bexpect\\s*\\(', masked_new):
        paren_start = m.end() - 1
        paren_end = _find_matching_paren(masked_new, paren_start)
        if paren_end == -1:
            continue
        actual = new_no_comments[paren_start + 1:paren_end].strip()
        after = new_no_comments[paren_end + 1:]
        m_matcher = re.match('^\\s*\\.\\s*(?P<matcher>toBeTruthy|toBeFalsy|toBe|toEqual|toStrictEqual)\\b', after)
        if not m_matcher:
            continue
        matcher = m_matcher.group('matcher')
        matcher_end_idx = paren_end + 1 + m_matcher.end()
        p_arg_start = masked_new.find('(', matcher_end_idx)
        expected = ''
        call_end = matcher_end_idx
        if p_arg_start != -1 and (not masked_new[matcher_end_idx:p_arg_start].strip()):
            p_arg_end = _find_matching_paren(masked_new, p_arg_start)
            if p_arg_end != -1:
                expected = new_no_comments[p_arg_start + 1:p_arg_end].strip()
                call_end = p_arg_end + 1
            else:
                call_end = p_arg_start + 1
        full_call = new_no_comments[m.start():call_end]
        is_taut = False
        if matcher in ('toBe', 'toEqual', 'toStrictEqual'):
            if actual == expected:
                is_taut = True
            elif actual in ('true', '1') and expected in ('true', '1'):
                is_taut = True
            elif actual in ('false', '0') and expected in ('false', '0'):
                is_taut = True
        rel = _find_toplevel_relational_op(actual)
        if rel:
            op, left, right = rel
            if left == right:
                if op in ('===', '==', '<=', '>=') and (expected in ('true', '1') or matcher == 'toBeTruthy'):
                    is_taut = True
                elif op in ('!==', '!=', '<', '>') and (expected in ('false', '0') or matcher == 'toBeFalsy'):
                    is_taut = True
        if is_taut and full_call not in old_no_comments:
            lineno = clean_new.count('\n', 0, m.start()) + 1
            violations.append(f'Line {lineno}: Tautological assertion in expect(...) ({actual} -> {matcher}({expected})).')
    skip_re = re.compile('\\b(?P<token>(?:it|test|describe)\\s*\\.\\s*(?:skip|todo|only)|(?:xit|xtest|xdescribe))\\s*\\(')
    for m in skip_re.finditer(new_no_comments):
        token = re.sub('\\s+', '', m.group('token'))
        if token not in re.sub('\\s+', '', old_no_comments):
            lineno = clean_new.count('\n', 0, m.start()) + 1
            violations.append(f'Line {lineno}: Test decorated with skip/todo ({token}).')
    mock_re = re.compile('\\b(?P<lib>vi|jest)\\s*\\.\\s*(?P<type>mock|spyOn|fn)\\s*\\(\\s*(?P<target>[^,);]*)')
    total_mocks = 0
    internal_mock_count = 0
    boundary_mock_count = 0
    mock_calls: List[Tuple[int, str, str, str]] = []
    for m in mock_re.finditer(new_no_comments):
        total_mocks += 1
        lineno = clean_new.count('\n', 0, m.start()) + 1
        lib = m.group('lib')
        m_type = m.group('type')
        target_str = m.group('target').strip()
        p_start = masked_new.find('(', m.start())
        p_end = _find_matching_paren(masked_new, p_start) if p_start != -1 else -1
        if p_end != -1:
            semi_idx = new_no_comments.find(';', p_end)
            newline_idx = new_no_comments.find('\n', p_end)
            if semi_idx != -1 and (newline_idx == -1 or semi_idx < newline_idx):
                snippet = new_no_comments[m.start():semi_idx + 1]
            else:
                snippet = new_no_comments[m.start():p_end + 1]
        else:
            newline_idx = new_no_comments.find('\n', m.start())
            snippet = new_no_comments[m.start():newline_idx if newline_idx != -1 else m.end() + 100]
        mock_calls.append((lineno, lib, m_type, snippet))
        if _is_boundary_mock(target_str):
            boundary_mock_count += 1
        else:
            internal_mock_count += 1
    for lineno, lib, m_type, snippet in mock_calls:
        for t_fn in target_set:
            if t_fn in snippet:
                violations.append(f"Line {lineno}: Test mocks out target function '{t_fn}' via {lib}.{m_type}.")
    total_asserts = max(new_assert_count, 1)
    mar = round(total_mocks / total_asserts, 4)
    weighted_mar = round((1.0 * internal_mock_count + 0.25 * boundary_mock_count) / total_asserts, 4)
    if mar < 0.1:
        risk_level = 'LOW'
    elif mar <= 0.25:
        risk_level = 'MODERATE'
    else:
        risk_level = 'HIGH_RISK'
    anchors = index_ts_ast_anchors(clean_new, file_path=file_path)
    passed = len(violations) == 0
    return TestTamperingReport(passed=passed, old_assert_count=old_assert_count, new_assert_count=new_assert_count, violations=violations, anchors=anchors, total_mocks=total_mocks, mar=mar, risk_level=risk_level, internal_mock_count=internal_mock_count, boundary_mock_count=boundary_mock_count, weighted_mar=weighted_mar)

def generate_ts_mutants(source_code: str='', target_function: Optional[str]=None, max_mutants: int=5, *, ts_code: Optional[str]=None) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped TypeScript/JS mutants.
    Returns list of (description, lineno, mutated_ts_code).
    """
    raw_code = ts_code if ts_code is not None else source_code
    clean_code = raw_code.lstrip('\ufeff')
    if not clean_code.strip():
        return None
    masked = mask_ts_code(clean_code, mask_strings=True)
    anchors = index_ts_ast_anchors(clean_code)
    start_line = 1
    end_line = clean_code.count('\n') + 1
    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()
    patterns: List[Tuple[str, str, str]] = [('===', '!==', 'Strict equality inverted (=== to !==)'), ('!==', '===', 'Strict inequality inverted (!== to ===)'), ('(?<![!=])==(?!=)', '!=', 'Equality inverted (== to !=)'), ('(?<![!=])!=(?!=)', '==', 'Inequality inverted (!= to ==)'), ('<=', '<', 'Relational boundary adjusted (<= to <)'), ('>=', '>', 'Relational boundary adjusted (>= to >)'), ('&&', '||', 'Logical AND inverted to OR (&& to ||)'), ('\\|\\|', '&&', 'Logical OR inverted to AND (|| to &&)'), ('(?<!\\+)\\+(?!\\+|=)', '-', 'Arithmetic addition inverted to subtraction (+ to -)'), ('(?<!-)-(?!-|=)', '+', 'Arithmetic subtraction inverted to addition (- to +)'), ('\\btrue\\b', 'false', 'Boolean literal inverted (true to false)'), ('\\bfalse\\b', 'true', 'Boolean literal inverted (false to true)')]
    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count('\n', 0, idx) + 1
            if not start_line <= lineno <= end_line:
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f'Line {lineno}: {desc}', lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants
    ret_re = re.compile('\\breturn\\s+([^;]+);')
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count('\n', 0, idx) + 1
        if not start_line <= lineno <= end_line:
            continue
        expr = clean_code[m.start(1):m.end(1)].strip()
        if expr == 'null':
            continue
        mutated = clean_code[:idx] + 'return null;' + clean_code[end_idx:]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'null'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants
    return mutants