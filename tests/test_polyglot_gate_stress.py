"""Empirical stress-testing and adversarial challenge suite for Go Gate, Rust Gate,
TS mutant signature parity, and Git Diff polyglot routing.

Coverage:
1. Go Gate (cordis/polyglot_gate.py):
   - mask_go_code: strings with '//' and '/* */', escaped quotes, multiline raw strings, rune literals.
   - index_go_ast_anchors: pointer and value receivers, generics, multi-returns, named returns.
   - audit_go_test_tampering: t.Skip / t.Skipf / t.SkipNow, table slice shrinking, blank identifier discards, tautologies.
   - generate_go_mutants: syntax validity, diff-scoping to target_function, return nil mutation.
2. Rust Gate (cordis/polyglot_gate.py):
   - mask_rust_code: deeply nested block comments, raw strings with multiple '#' chars, char literals vs lifetimes.
   - index_rust_ast_anchors: standalone pub/async/unsafe fn, impl struct methods, generic impl<T>, trait impls, trait stubs.
   - audit_rust_test_tampering: #[ignore], weak assert!(x.is_ok()), production .unwrap() / .expect() vs safe .unwrap_or_default().
   - generate_rust_mutants: syntax validity, diff-scoping, return Default::default() mutation.
3. Polyglot Git Diff (cordis/git_diff.py):
   - is_test_file: Go and Rust test conventions, #[cfg(test)] detection.
   - parse_git_diff_text: Go and Rust file routing, function attribution, and is_test computation.
4. TS Mutant Parity (cordis/ts_gate.py):
   - generate_ts_mutants: dual parameter signature parity (source_code and ts_code kwargs).
"""
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from typing import Dict, List, Optional, Tuple
from unittest.mock import patch

import cordis.git_diff as gd
import cordis.polyglot_gate as pg
import cordis.ts_gate as tg
from cordis.ast_gate import ASTAnchor, TestTamperingReport
from cordis.cli import run_verify_git
from cordis.hooks import handle_stop_hook, run_stop_hook_prosecutor


class TestGoGateAdversarialStress(unittest.TestCase):
    """Adversarial stress testing for Go lexical scanning, AST indexing, tampering, and mutants."""

    def test_mask_go_code_strings_containing_comment_delimiters(self):
        """Strings with embedded // and /* */ must remain masked as strings, not treated as comments."""
        code = (
            'package main\n'
            'func Example() string {\n'
            '    url := "https://example.com/api/*v1*/test";\n'
            '    escaped := "hello \\" // not a comment \\" world";\n'
            '    return url + escaped;\n'
            '}\n'
        )
        masked = pg.mask_go_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code), "Masked length must match original exactly")
        self.assertEqual(masked.count("\n"), code.count("\n"), "Newline count must match exactly")
        self.assertNotIn("example.com", masked)
        self.assertNotIn("not a comment", masked)
        self.assertIn("func Example()", masked)
        self.assertIn("return", masked)

    def test_mask_go_code_multiline_raw_backtick_strings(self):
        """Multiline raw backtick strings containing comments, braces, and quotes must be masked."""
        code = (
            'package main\n'
            'func Query() string {\n'
            '    raw := `SELECT * FROM users\n'
            '    WHERE comment = "// not a comment"\n'
            '    /* also not a comment */\n'
            '    AND id = 1`;\n'
            '    return raw;\n'
            '}\n'
        )
        masked = pg.mask_go_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code), "Raw string mask must preserve exact character count")
        self.assertEqual(masked.count("\n"), code.count("\n"), "Raw string mask must preserve exact line count")
        self.assertNotIn("SELECT", masked)
        self.assertNotIn("users", masked)
        self.assertIn("func Query()", masked)

    def test_mask_go_code_rune_literals_and_escapes(self):
        """Go rune literals like '\\'', '\\\\', '\\n', and '/' must be masked without swallowing following code."""
        code = (
            'package main\n'
            'func Runes() {\n'
            "    r1 := '\\'';\n"
            "    r2 := '\\\\';\n"
            "    r3 := '\\n';\n"
            "    r4 := '/';\n"
            "    r5 := '*';\n"
            "    r6 := '\"';\n"
            '    active := true;\n'
            '}\n'
        )
        masked = pg.mask_go_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code))
        self.assertEqual(masked.count("\n"), code.count("\n"))
        self.assertIn("active := true;", masked)

    def test_index_go_ast_anchors_pointer_and_value_receivers(self):
        """Struct receiver methods (both pointer *T and value T) must be indexed with StructName.Method."""
        code = (
            'package main\n'
            'type Database struct{}\n'
            'func (db *Database) Query(sql string) (Result, error) {\n'
            '    return nil, nil\n'
            '}\n'
            'func (db Database) Ping() bool {\n'
            '    return true\n'
            '}\n'
            'func FreeFunction(x int) int {\n'
            '    return x * 2\n'
            '}\n'
        )
        anchors = pg.index_go_ast_anchors(code, file_path="db.go")
        self.assertIn("Database.Query", anchors)
        self.assertIn("Database.Ping", anchors)
        self.assertIn("FreeFunction", anchors)

        query_anchor = anchors["Database.Query"]
        self.assertEqual(query_anchor.node_type, "MethodDeclaration")
        self.assertEqual(query_anchor.scope_path, "Database")
        self.assertEqual(query_anchor.identifier, "Query")
        self.assertEqual(query_anchor.lineno, 3)
        self.assertEqual(query_anchor.end_lineno, 5)

        ping_anchor = anchors["Database.Ping"]
        self.assertEqual(ping_anchor.node_type, "MethodDeclaration")
        self.assertEqual(ping_anchor.scope_path, "Database")

        free_anchor = anchors["FreeFunction"]
        self.assertEqual(free_anchor.node_type, "FunctionDeclaration")
        self.assertEqual(free_anchor.scope_path, "<module>")

    def test_index_go_ast_anchors_generics_and_complex_signatures(self):
        """Generic type receivers, generic functions, and complex multi/named return signatures."""
        code = (
            'package main\n'
            'type Cache[K comparable, V any] struct{}\n'
            'func (c *Cache[K, V]) Set(key K, val V) (evicted bool, err error) {\n'
            '    return false, nil\n'
            '}\n'
            'func Transform[T any, R any](items []T, fn func(T) R) ([]R, error) {\n'
            '    return nil, nil\n'
            '}\n'
        )
        anchors = pg.index_go_ast_anchors(code, file_path="cache.go")
        self.assertIn("Cache.Set", anchors)
        self.assertIn("Transform", anchors)
        self.assertEqual(anchors["Cache.Set"].scope_path, "Cache")
        self.assertEqual(anchors["Transform"].scope_path, "<module>")

    def test_anchor_dict_resolution(self):
        """AnchorDict must resolve by qualname, tag, and hash_tag, and support 'in' membership."""
        code = 'package main\nfunc Hello() { println("hi") }\n'
        anchors = pg.index_go_ast_anchors(code, file_path="main.go")
        anchor = anchors["Hello"]
        self.assertIn("Hello", anchors)
        self.assertIn(anchor.tag, anchors)
        self.assertIn(anchor.hash_tag, anchors)
        self.assertIs(anchors[anchor.tag], anchor)
        self.assertIs(anchors[anchor.hash_tag], anchor)
        with self.assertRaises(KeyError):
            _ = anchors["NonExistentFunction"]

    def test_audit_go_test_tampering_skips(self):
        """audit_go_test_tampering must detect t.Skip, t.Skipf, and t.SkipNow."""
        code_old = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestFeature(t *testing.T) {\n'
            '    assert.Equal(t, 1, 1)\n'
            '}\n'
        )
        for skip_call in ('t.Skip("skipping")', 't.Skipf("skip %d", 1)', 't.SkipNow()'):
            code_new = (
                'package main\n'
                'import "testing"\n'
                'import "github.com/stretchr/testify/assert"\n'
                'func TestFeature(t *testing.T) {\n'
                f'    {skip_call}\n'
                '    assert.Equal(t, 1, 1)\n'
                '}\n'
            )
            report = pg.audit_go_test_tampering(code_old, code_new, "feature_test.go")
            self.assertFalse(report.passed, f"Expected violation for {skip_call}")
            self.assertTrue(any("t.Skip" in v for v in report.violations))

    def test_audit_go_test_tampering_table_shrinking(self):
        """Shrinking table-driven test case slice must trigger a tampering violation."""
        code_old = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestTable(t *testing.T) {\n'
            '    tests := []struct{ in string; want int }{\n'
            '        {"a", 1},\n'
            '        {"b", 2},\n'
            '        {"c", 3},\n'
            '    }\n'
            '    for _, tt := range tests {\n'
            '        assert.Equal(t, tt.want, len(tt.in))\n'
            '    }\n'
            '}\n'
        )
        code_shrunk = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestTable(t *testing.T) {\n'
            '    tests := []struct{ in string; want int }{\n'
            '        {"a", 1},\n'
            '    }\n'
            '    for _, tt := range tests {\n'
            '        assert.Equal(t, tt.want, len(tt.in))\n'
            '    }\n'
            '}\n'
        )
        report = pg.audit_go_test_tampering(code_old, code_shrunk, "table_test.go")
        self.assertFalse(report.passed)
        self.assertTrue(any("shrunk" in v for v in report.violations))

    def test_audit_go_test_tampering_blank_identifier_discard(self):
        """Discarding test result with blank identifier '_ = got' without assertion must fail."""
        code_old = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestAdd(t *testing.T) {\n'
            '    got := Add(1, 2)\n'
            '    assert.Equal(t, 3, got)\n'
            '}\n'
        )
        code_new = (
            'package main\n'
            'import "testing"\n'
            'func TestAdd(t *testing.T) {\n'
            '    got := Add(1, 2)\n'
            '    _ = got\n'
            '}\n'
        )
        report = pg.audit_go_test_tampering(code_old, code_new, "calc_test.go")
        self.assertFalse(report.passed)
        self.assertTrue(any("blank identifier" in v for v in report.violations))

    def test_audit_go_test_tampering_tautological_and_weak_assertions(self):
        """Tautological self-comparisons and weakening value checks to hollow assert.NotNil."""
        code_old = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestVal(t *testing.T) {\n'
            '    got := Compute()\n'
            '    assert.Equal(t, 42, got)\n'
            '}\n'
        )
        # Tautology 1: assert.Equal(t, got, got)
        code_taut1 = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestVal(t *testing.T) {\n'
            '    got := Compute()\n'
            '    assert.Equal(t, got, got)\n'
            '}\n'
        )
        rep1 = pg.audit_go_test_tampering(code_old, code_taut1, "val_test.go")
        self.assertFalse(rep1.passed)
        self.assertTrue(any("Tautological" in v for v in rep1.violations))

        # Tautology 2: assert.True(t, true)
        code_taut2 = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestVal(t *testing.T) {\n'
            '    assert.True(t, true)\n'
            '}\n'
        )
        rep2 = pg.audit_go_test_tampering(code_old, code_taut2, "val_test.go")
        self.assertFalse(rep2.passed)
        self.assertTrue(any("Tautological" in v for v in rep2.violations))

        # Weakened to assert.NotNil
        code_weak = (
            'package main\n'
            'import "testing"\n'
            'import "github.com/stretchr/testify/assert"\n'
            'func TestVal(t *testing.T) {\n'
            '    got := Compute()\n'
            '    assert.NotNil(t, got)\n'
            '}\n'
        )
        rep3 = pg.audit_go_test_tampering(code_old, code_weak, "val_test.go")
        self.assertFalse(rep3.passed)
        self.assertTrue(any("weakened to hollow checks" in v for v in rep3.violations))

    def test_generate_go_mutants_diff_scoping_and_syntactic_validity(self):
        """Go mutants must be syntactically valid Go substitutions and scoped to target_function."""
        code = (
            'package main\n'
            'func Target(a int, b int) int {\n'
            '    if a == b {\n'
            '        return a + b\n'
            '    }\n'
            '    return a - b\n'
            '}\n'
            'func Untouched(x int) bool {\n'
            '    return x > 0\n'
            '}\n'
        )
        mutants = pg.generate_go_mutants(code, max_mutants=5, target_function="Target")
        self.assertGreater(len(mutants), 0)
        for desc, lineno, mutated_code in mutants:
            self.assertGreaterEqual(lineno, 2, "Mutant must be inside Target function")
            self.assertLessEqual(lineno, 7, "Mutant must be inside Target function")
            self.assertIn("Untouched(x int) bool {\n    return x > 0", mutated_code, "Untouched function must remain pristine")

    def test_generate_go_mutants_suppressed_in_comments_and_strings(self):
        """Mutations must NOT alter operators inside comments or string literals."""
        code = (
            'package main\n'
            'func Greet() string {\n'
            '    // check if a == b\n'
            '    /* or a <= b */\n'
            '    msg := "a == b and a + b"\n'
            '    return msg\n'
            '}\n'
        )
        mutants = pg.generate_go_mutants(code, max_mutants=5, target_function="Greet")
        # The only valid mutation is `return nil`
        for desc, lineno, mutated in mutants:
            self.assertIn("return nil", mutated)
            self.assertIn('// check if a == b', mutated)
    def test_generate_go_mutants_missing_target_function(self):
        """When target_function is specified but not found, mutator should return empty list (diff-scoped)."""
        code = 'package main\nfunc ExistingFunc() bool { return true }\n'
        mutants = pg.generate_go_mutants(code, max_mutants=5, target_function="NonExistent")
        self.assertEqual(len(mutants), 0, "Mutator must return 0 mutants when target_function is not found")



class TestRustGateAdversarialStress(unittest.TestCase):
    """Adversarial stress testing for Rust lexical scanning, AST indexing, tampering, and mutants."""

    def test_mask_rust_code_deeply_nested_block_comments(self):
        """Deeply nested Rust block comments /* /* /* ... */ */ */ must be fully masked."""
        code = (
            'fn compute() -> i32 {\n'
            '    /* level 1\n'
            '       /* level 2\n'
            '          /* level 3 "quotes inside" */\n'
            '          still level 2 */\n'
            '       back to level 1 */\n'
            '    let x = 42;\n'
            '    return x;\n'
            '}\n'
        )
        masked = pg.mask_rust_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code), "Masked length must match original exactly")
        self.assertEqual(masked.count("\n"), code.count("\n"), "Newline count must match exactly")
        self.assertNotIn("level 1", masked)
        self.assertNotIn("level 2", masked)
        self.assertNotIn("level 3", masked)
        self.assertIn("let x = 42;", masked)
        self.assertIn("return x;", masked)

    def test_mask_rust_code_raw_strings_multiple_hashes(self):
        """Raw strings r###"..."### with multiple # characters and embedded quotes/comments."""
        code = (
            'fn regex_pattern() -> &\'static str {\n'
            '    let s1 = r#"simple "raw" string"#;\n'
            '    let s2 = r###"multi-hash "quotes" and /* not a comment */ and r#"inner"# "###;\n'
            '    let b1 = br#"byte raw string"#;\n'
            '    return s1;\n'
            '}\n'
        )
        masked = pg.mask_rust_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code))
        self.assertEqual(masked.count("\n"), code.count("\n"))
        self.assertNotIn("not a comment", masked)
        self.assertNotIn("byte raw string", masked)
        self.assertIn("fn regex_pattern()", masked)

    def test_mask_rust_code_char_literals_vs_lifetimes(self):
        """Char literals ('c', '\\'', '\\\\') vs lifetime annotations ('a, 'static, &'a str)."""
        code = (
            'fn parse<\'a, \'b: \'a>(input: &\'a str) -> &\'b str {\n'
            '    let ch1 = \'a\';\n'
            '    let ch2 = \'\\\'\';\n'
            '    let ch3 = \'\\\\\';\n'
            '    let ch4 = \'\\n\';\n'
            '    let ch5 = \'/\';\n'
            '    let ch6 = \'*\';\n'
            '    let s: &\'static str = "ok";\n'
            '    return s;\n'
            '}\n'
        )
        masked = pg.mask_rust_code(code, mask_strings=True)
        self.assertEqual(len(masked), len(code))
        self.assertEqual(masked.count("\n"), code.count("\n"))
        self.assertIn("fn parse", masked)
        self.assertIn("return s;", masked)

    def test_index_rust_ast_anchors_functions_methods_and_generics(self):
        """Standalone pub/async/unsafe functions, impl struct methods, and generic impl<T>."""
        code = (
            'pub struct Calculator<T> {\n'
            '    pub value: T,\n'
            '}\n'
            'impl<T: std::ops::Add<Output = T>> Calculator<T> {\n'
            '    pub fn new(val: T) -> Self {\n'
            '        Self { value: val }\n'
            '    }\n'
            '    pub async fn calculate(&self, other: T) -> T {\n'
            '        return self.value + other;\n'
            '    }\n'
            '}\n'
            'pub unsafe fn raw_operation(ptr: *const u8) -> u8 {\n'
            '    *ptr\n'
            '}\n'
        )
        anchors = pg.index_rust_ast_anchors(code, file_path="calc.rs")
        self.assertIn("Calculator.new", anchors)
        self.assertIn("Calculator::new", anchors)
        self.assertIn("Calculator.calculate", anchors)
        self.assertIn("Calculator::calculate", anchors)
        self.assertIn("raw_operation", anchors)

        new_anchor = anchors["Calculator.new"]
        self.assertEqual(new_anchor.node_type, "MethodDeclaration")
        self.assertEqual(new_anchor.scope_path, "Calculator")
        self.assertEqual(new_anchor.identifier, "new")

        raw_anchor = anchors["raw_operation"]
        self.assertEqual(raw_anchor.node_type, "FunctionDeclaration")
        self.assertEqual(raw_anchor.scope_path, "<module>")

    def test_index_rust_ast_anchors_ignores_trait_method_stubs(self):
        """Trait declarations with semicolon stubs (fn stub(&self);) must not be indexed as methods."""
        code = (
            'pub trait Greeter {\n'
            '    fn greet(&self) -> String;\n'
            '    fn default_greeting(&self) -> String {\n'
            '        return "hello".to_string();\n'
            '    }\n'
            '}\n'
        )
        anchors = pg.index_rust_ast_anchors(code, file_path="trait.rs")
        self.assertNotIn("greet", anchors)
        self.assertIn("default_greeting", anchors)

    def test_audit_rust_test_tampering_ignore_attribute(self):
        """#[ignore] on test functions must trigger a tampering violation."""
        code_old = (
            '#[test]\n'
            'fn test_computation() {\n'
            '    assert_eq!(2 + 2, 4);\n'
            '}\n'
        )
        for ign in ('#[ignore]', '#[ignore = "flaky test"]', '#[  ignore  ]'):
            code_new = (
                f'{ign}\n'
                '#[test]\n'
                'fn test_computation() {\n'
                '    assert_eq!(2 + 2, 4);\n'
                '}\n'
            )
            rep = pg.audit_rust_test_tampering(code_old, code_new, "calc_test.rs")
            self.assertFalse(rep.passed, f"Expected violation for {ign}")
            self.assertTrue(any("Line 1:" in v and "#[ignore]" in v for v in rep.violations))

    def test_audit_rust_test_tampering_weak_assertions(self):
        """Weak assertions assert!(x.is_ok()) or assert!(x.is_some()) without payload equality."""
        code_old = (
            '#[test]\n'
            'fn test_result() {\n'
            '    let res = calculate();\n'
            '    assert_eq!(res.unwrap(), 42);\n'
            '}\n'
        )
        for weak in ('assert!(res.is_ok())', 'assert!(opt.is_some())', 'assert!(res.is_err())', 'assert!(opt.is_none())'):
            code_new = (
                '#[test]\n'
                'fn test_result() {\n'
                '    let res = calculate();\n'
                f'    {weak};\n'
                '}\n'
            )
            rep = pg.audit_rust_test_tampering(code_old, code_new, "calc_test.rs")
            self.assertFalse(rep.passed, f"Expected violation for {weak}")
            self.assertTrue(any("Weak assertion" in v for v in rep.violations))

    def test_audit_rust_test_tampering_production_unwrap_expect_vs_safe_unwrap_or(self):
        """Newly added .unwrap() or .expect() in prod_rs_diff must fail; safe .unwrap_or* must pass."""
        old_test = '#[test]\nfn test_a() { assert_eq!(1, 1); }\n'
        new_test = '#[test]\nfn test_a() { assert_eq!(1, 1); }\n'

        # Panic injection: .unwrap()
        diff_unwrap = (
            '--- a/src/lib.rs\n'
            '+++ b/src/lib.rs\n'
            '@@ -10,3 +10,4 @@\n'
            ' fn process(opt: Option<i32>) -> i32 {\n'
            '+    let val = opt.unwrap();\n'
            '     val * 2\n'
        )
        rep1 = pg.audit_rust_test_tampering(old_test, new_test, "lib.rs", prod_rs_diff=diff_unwrap)
        self.assertFalse(rep1.passed)
        self.assertTrue(any(".unwrap()" in v for v in rep1.violations))

        # Panic injection: .expect()
        diff_expect = (
            '--- a/src/lib.rs\n'
            '+++ b/src/lib.rs\n'
            '@@ -10,3 +10,4 @@\n'
            ' fn process(opt: Option<i32>) -> i32 {\n'
            '+    let val = opt.expect("value must exist");\n'
            '     val * 2\n'
        )
        rep2 = pg.audit_rust_test_tampering(old_test, new_test, "lib.rs", prod_rs_diff=diff_expect)
        self.assertFalse(rep2.passed)
        self.assertTrue(any(".expect()" in v for v in rep2.violations))

        # Safe alternatives: .unwrap_or_default(), .unwrap_or(0), .unwrap_or_else(...)
        old_test_safe = '#[test]\nfn test_b() { assert_eq!(calc(), 42); }\n'
        new_test_safe = '#[test]\nfn test_b() { assert_eq!(calc(), 42); }\n'
        diff_safe = (
            '--- a/src/lib.rs\n'
            '+++ b/src/lib.rs\n'
            '@@ -10,3 +10,5 @@\n'
            ' fn process(opt: Option<i32>) -> i32 {\n'
            '+    let a = opt.unwrap_or_default();\n'
            '+    let b = opt.unwrap_or(0);\n'
            '+    let c = opt.unwrap_or_else(|| 42);\n'
            '     a + b + c\n'
        )
        rep3 = pg.audit_rust_test_tampering(old_test_safe, new_test_safe, "lib.rs", prod_rs_diff=diff_safe)
        self.assertTrue(rep3.passed, f"Safe unwrap_or alternatives must pass, but got: {rep3.violations}")

    def test_audit_rust_test_tampering_tautological_assertions(self):
        """assert_eq!(x, x) or assert!(true) must trigger tautology violations."""
        code_old = '#[test]\nfn t() { assert_eq!(a, b); }\n'
        code_taut1 = '#[test]\nfn t() { assert_eq!(a, a); }\n'
        rep1 = pg.audit_rust_test_tampering(code_old, code_taut1, "test.rs")
        self.assertFalse(rep1.passed)
        self.assertTrue(any("Tautological" in v for v in rep1.violations))

        code_taut2 = '#[test]\nfn t() { assert!(true); }\n'
        rep2 = pg.audit_rust_test_tampering(code_old, code_taut2, "test.rs")
        self.assertFalse(rep2.passed)
        self.assertTrue(any("Tautological" in v for v in rep2.violations))

    def test_generate_rust_mutants_diff_scoping_and_syntactic_validity(self):
        """Rust mutants must replace operators or inject return Default::default() scoped to target."""
        code = (
            'pub fn target_calc(a: i32, b: i32) -> i32 {\n'
            '    if a == b {\n'
            '        return a + b;\n'
            '    }\n'
            '    return a - b;\n'
            '}\n'
            'pub fn untouched_fn(x: bool) -> bool {\n'
            '    return x && true;\n'
            '}\n'
        )
        mutants = pg.generate_rust_mutants(code, max_mutants=5, target_function="target_calc")
        self.assertGreater(len(mutants), 0)
        for desc, lineno, mutated in mutants:
            self.assertGreaterEqual(lineno, 1)
            self.assertLessEqual(lineno, 6)
            self.assertIn("untouched_fn(x: bool) -> bool {\n    return x && true;", mutated)

    def test_generate_rust_mutants_missing_target_function(self):
        """When target_function is specified but not found, Rust mutator should return empty list."""
        code = 'pub fn existing_fn() -> bool { true }\n'
        mutants = pg.generate_rust_mutants(code, max_mutants=5, target_function="non_existent")
        self.assertEqual(len(mutants), 0, "Rust mutator must return 0 mutants when target_function is not found")



class TestGitDiffPolyglotIntegration(unittest.TestCase):
    """Stress testing git_diff.py polyglot extensions for Go and Rust."""

    def test_is_test_file_polyglot_conventions(self):
        """Verifies test file detection across Go, Rust, and inline #[cfg(test)]."""
        # Go
        self.assertTrue(gd.is_test_file("module_test.go"))
        self.assertTrue(gd.is_test_file("pkg/sub/service_test.go"))
        self.assertFalse(gd.is_test_file("module.go"))
        self.assertFalse(gd.is_test_file("pkg/sub/service.go"))

        # Rust
        self.assertTrue(gd.is_test_file("tests.rs"))
        self.assertTrue(gd.is_test_file("test.rs"))
        self.assertTrue(gd.is_test_file("engine_test.rs"))
        self.assertTrue(gd.is_test_file("tests/common.rs"))
        self.assertTrue(gd.is_test_file("src/tests/integration.rs"))
        self.assertFalse(gd.is_test_file("src/lib.rs"))
        self.assertFalse(gd.is_test_file("src/main.rs"))

        # Rust inline #[cfg(test)]
        rust_with_cfg = "pub fn add() {}\n#[cfg(test)]\nmod tests {}\n"
        rust_without_cfg = "pub fn add() {}\n"
        self.assertTrue(gd.is_test_file("src/lib.rs", content=rust_with_cfg))
        self.assertFalse(gd.is_test_file("src/lib.rs", content=rust_without_cfg))

    def test_parse_git_diff_text_routes_go_files_and_attributes_functions(self):
        """Unified diff with Go files routes to index_go_ast_anchors and attributes functions."""
        go_source = (
            'package math\n'
            'func Add(a, b int) int {\n'
            '    return a + b\n'
            '}\n'
            'func Multiply(a, b int) int {\n'
            '    return a * b\n'
            '}\n'
        )
        diff_text = (
            'diff --git a/pkg/math.go b/pkg/math.go\n'
            '--- a/pkg/math.go\n'
            '+++ b/pkg/math.go\n'
            '@@ -2,3 +2,3 @@\n'
            ' func Add(a, b int) int {\n'
            '-    return a + b\n'
            '+    return a + b + 0\n'
            ' }\n'
        )
        report = gd.parse_git_diff_text(
            diff_text,
            file_reader=lambda p: go_source if p == "pkg/math.go" else None,
        )
        self.assertIn("pkg/math.go", report.source_files)
        self.assertNotIn("pkg/math.go", report.test_files)
        self.assertEqual(len(report.modified_functions), 1)
        mod_func = report.modified_functions[0]
        self.assertEqual(mod_func.name, "Add")
        self.assertEqual(mod_func.file_path, "pkg/math.go")
        self.assertFalse(mod_func.is_test)

    def test_parse_git_diff_text_routes_rust_files_and_attributes_methods(self):
        """Unified diff with Rust files routes to index_rust_ast_anchors and attributes methods."""
        rust_source = (
            'pub struct Engine;\n'
            'impl Engine {\n'
            '    pub fn start(&self) -> bool {\n'
            '        true\n'
            '    }\n'
            '    pub fn stop(&self) -> bool {\n'
            '        false\n'
            '    }\n'
            '}\n'
        )
        diff_text = (
            'diff --git a/src/engine.rs b/src/engine.rs\n'
            '--- a/src/engine.rs\n'
            '+++ b/src/engine.rs\n'
            '@@ -3,3 +3,3 @@\n'
            '     pub fn start(&self) -> bool {\n'
            '-        true\n'
            '+        true && true\n'
            '     }\n'
        )
        report = gd.parse_git_diff_text(
            diff_text,
            file_reader=lambda p: rust_source if p == "src/engine.rs" else None,
        )
        self.assertIn("src/engine.rs", report.source_files)
        self.assertEqual(len(report.modified_functions), 1)
        mod_func = report.modified_functions[0]
        self.assertEqual(mod_func.name, "start")
        self.assertEqual(mod_func.scope, "Engine")
        self.assertFalse(mod_func.is_test)


class TestTsGateMutantsParity(unittest.TestCase):
    """Stress testing generate_ts_mutants parameter parity and export."""

    def test_generate_ts_mutants_parameter_signatures(self):
        """generate_ts_mutants must support positional, source_code, and ts_code kwargs."""
        ts_code = "function test(x: number): boolean {\n    return x === 10;\n}\n"

        # 1. Positional argument
        m_pos = tg.generate_ts_mutants(ts_code, max_mutants=2)
        self.assertGreater(len(m_pos), 0)

        # 2. source_code keyword argument
        m_src = tg.generate_ts_mutants(source_code=ts_code, max_mutants=2)
        self.assertEqual(len(m_src), len(m_pos))

        # 3. ts_code keyword argument
        m_ts = tg.generate_ts_mutants(ts_code=ts_code, max_mutants=2)
        self.assertEqual(len(m_ts), len(m_pos))

        # 4. ts_code precedence when both are provided
        dummy_code = "function dummy() { return false; }"
        m_both = tg.generate_ts_mutants(source_code=dummy_code, ts_code=ts_code, max_mutants=2)
        # Should mutate ts_code (test), not dummy
        self.assertTrue(any("===" in d for d, _, _ in m_both))

    def test_ts_gate_module_all_exports(self):
        """__all__ in cordis/ts_gate.py must explicitly contain generate_ts_mutants."""
        self.assertIn("generate_ts_mutants", tg.__all__)
        self.assertIn("index_ts_ast_anchors", tg.__all__)
        self.assertIn("audit_ts_test_tampering", tg.__all__)
        self.assertTrue(callable(getattr(tg, "generate_ts_mutants")))


class TestPolyglotGate1RoutingIntegration(unittest.TestCase):
    """Integration verification that run_verify_git and handle_stop_hook cleanly prosecute
    Go and Rust files without invoking Python's ast.parse().
    """

    def test_run_verify_git_and_stop_hook_prosecute_go_and_rust_without_ast_parse(self):
        """Simulated .go (module_test.go with t.Skip) and .rs (lib_test.rs with #[ignore])
        git diffs must be cleanly prosecuted by run_verify_git() and handle_stop_hook()
        without calling Python's ast.parse().
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            # 1. Base commit with honest Go and Rust tests
            go_test_orig = (
                "package main\n\n"
                "import (\n"
                "\t\"testing\"\n"
                ")\n\n"
                "func TestAdd(t *testing.T) {\n"
                "\tif 1 + 1 != 2 {\n"
                "\t\tt.Errorf(\"expected 2\")\n"
                "\t}\n"
                "}\n"
            )
            rs_test_orig = (
                "#[test]\n"
                "fn test_add() {\n"
                "    assert_eq!(1 + 1, 2);\n"
                "}\n"
            )

            p_go = os.path.join(tmp_dir, "module_test.go")
            p_rs = os.path.join(tmp_dir, "lib_test.rs")

            with open(p_go, "w", encoding="utf-8", newline="\n") as f:
                f.write(go_test_orig)
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write(rs_test_orig)

            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "initial polyglot tests"], cwd=tmp_dir, check=True, capture_output=True)

            # 2. Tampered working tree: Go has t.Skip, Rust has #[ignore]
            go_test_tampered = (
                "package main\n\n"
                "import (\n"
                "\t\"testing\"\n"
                ")\n\n"
                "func TestAdd(t *testing.T) {\n"
                "\tt.Skip(\"skipping test to cheat CI\")\n"
                "}\n"
            )
            rs_test_tampered = (
                "#[test]\n"
                "#[ignore]\n"
                "fn test_add() {\n"
                "    assert_eq!(1 + 1, 2);\n"
                "}\n"
            )

            with open(p_go, "w", encoding="utf-8", newline="\n") as f:
                f.write(go_test_tampered)
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write(rs_test_tampered)

            # Strict poison spy: ast.parse MUST NOT be called for .go or .rs files
            def forbidden_ast_parse(*args, **kwargs):
                raise AssertionError(f"ast.parse() was illegally called during polyglot Gate 1 audit: {args}")

            with patch("ast.parse", side_effect=forbidden_ast_parse):
                # Verify run_verify_git catches both violations without calling ast.parse
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc_git = run_verify_git(repo_dir=tmp_dir)

                out = buf.getvalue()
                self.assertEqual(rc_git, 1, "run_verify_git must return exit code 1 for tampered Go and Rust tests")
                self.assertIn("Gate 1 Test-Tampering", out)
                self.assertIn("module_test.go: ❌ FAIL", out)
                self.assertIn("t.Skip", out)
                self.assertIn("lib_test.rs: ❌ FAIL", out)
                self.assertIn("#[ignore]", out)

                # Verify handle_stop_hook catches both violations without calling ast.parse
                err_buf = io.StringIO()
                with redirect_stderr(err_buf):
                    rc_hook = handle_stop_hook(repo_dir=tmp_dir)
                self.assertEqual(rc_hook, 2, "handle_stop_hook must return exit code 2 (blocked) for tampered Go and Rust tests")
                self.assertIn("🛑 [Cordis Stop Hook Blocked]", err_buf.getvalue())

    def test_run_verify_git_detects_rust_production_unwrap_without_test_file(self):
        """When only a .rs source file is modified with .unwrap(), run_verify_git must block it
        even without a modified test file, without calling ast.parse().
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            p_src = os.path.join(tmp_dir, "lib.rs")
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn parse_data(opt: Option<i32>) -> i32 {\n    opt.unwrap_or(0)\n}\n")

            subprocess.run(["git", "add", "lib.rs"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "safe rust code"], cwd=tmp_dir, check=True, capture_output=True)

            # Invalidate panic-freedom by injecting .unwrap() in production source file
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn parse_data(opt: Option<i32>) -> i32 {\n    opt.unwrap()\n}\n")

            def forbidden_ast_parse(*args, **kwargs):
                raise AssertionError(f"ast.parse() was illegally called during Rust source verification: {args}")

            with patch("ast.parse", side_effect=forbidden_ast_parse):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = run_verify_git(repo_dir=tmp_dir)
                out = buf.getvalue()
                self.assertEqual(rc, 1, "Must block production .unwrap() injection even without test files modified")
                self.assertIn(".unwrap()", out)

                # Also test handle_stop_hook blocks it
                err_buf = io.StringIO()
                with redirect_stderr(err_buf):
                    rc_hook = handle_stop_hook(repo_dir=tmp_dir)
                self.assertEqual(rc_hook, 2, "handle_stop_hook must return exit code 2 (blocked) for production .unwrap() injection")
                self.assertIn("🛑 [Cordis Stop Hook Blocked]", err_buf.getvalue())

    def test_run_verify_git_and_stop_hook_clean_polyglot_pass_without_ast_parse(self):
        """Clean (untampered) .go and .rs test and source modifications must pass with exit 0
        in both run_verify_git() and handle_stop_hook() without calling ast.parse().
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            p_go = os.path.join(tmp_dir, "module_test.go")
            p_rs = os.path.join(tmp_dir, "lib_test.rs")

            with open(p_go, "w", encoding="utf-8", newline="\n") as f:
                f.write("package main\nimport \"testing\"\nfunc TestAdd(t *testing.T) {\n    if 1 + 1 != 2 { t.Errorf(\"err\") }\n}\n")
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write("#[test]\nfn test_add() {\n    assert_eq!(1 + 1, 2);\n}\n")

            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Honest new test added in both
            with open(p_go, "w", encoding="utf-8", newline="\n") as f:
                f.write("package main\nimport \"testing\"\nfunc TestAdd(t *testing.T) {\n    if 1 + 1 != 2 { t.Errorf(\"err\") }\n}\nfunc TestSub(t *testing.T) {\n    if 2 - 1 != 1 { t.Errorf(\"err\") }\n}\n")
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write("#[test]\nfn test_add() {\n    assert_eq!(1 + 1, 2);\n}\n#[test]\nfn test_sub() {\n    assert_eq!(2 - 1, 1);\n}\n")

            def forbidden_ast_parse(*args, **kwargs):
                raise AssertionError(f"ast.parse() was illegally called during clean polyglot audit: {args}")

            with patch("ast.parse", side_effect=forbidden_ast_parse):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc_git = run_verify_git(repo_dir=tmp_dir)
                self.assertEqual(rc_git, 0, f"run_verify_git must pass with exit 0 for honest Go and Rust tests: {buf.getvalue()}")

                rc_hook = handle_stop_hook(repo_dir=tmp_dir)
                self.assertEqual(rc_hook, 0, "handle_stop_hook must pass with exit 0 for honest Go and Rust tests")

    def test_rust_test_with_unwrap_passes_cleanly_without_false_positive(self):
        """Rust unit tests legitimately use .unwrap() and .expect() to assert test outcomes.
        run_verify_git() and handle_stop_hook() must not falsely flag test-file unwrap calls
        as production panic injections.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            p_rs = os.path.join(tmp_dir, "lib_test.rs")
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write("#[test]\nfn test_base() {\n    assert_eq!(1, 1);\n}\n")

            subprocess.run(["git", "add", "lib_test.rs"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Legitimate unwrap inside test
            with open(p_rs, "w", encoding="utf-8", newline="\n") as f:
                f.write(
                    "#[test]\n"
                    "fn test_base() {\n"
                    "    let val = Some(42).unwrap();\n"
                    "    let text = Some(\"ok\").expect(\"expected text\");\n"
                    "    assert_eq!(val, 42);\n"
                    "    assert_eq!(text, \"ok\");\n"
                    "}\n"
                )

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_git = run_verify_git(repo_dir=tmp_dir)
            self.assertEqual(rc_git, 0, f"run_verify_git must pass for legitimate test-file unwrap: {buf.getvalue()}")

            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                rc_hook = handle_stop_hook(repo_dir=tmp_dir)
            self.assertEqual(rc_hook, 0, f"handle_stop_hook must pass for legitimate test-file unwrap: {err_buf.getvalue()}")

    def test_cross_language_unwrap_does_not_falsely_block_rust_source(self):
        """When diff contains a non-Rust file (or Python test) with .unwrap() and a clean Rust source file,
        run_verify_git() must not attribute the Python unwrap to the Rust source file.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            p_src = os.path.join(tmp_dir, "lib.rs")
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn safe_calc() -> i32 {\n    42\n}\n")

            p_py = os.path.join(tmp_dir, "test_demo.py")
            with open(p_py, "w", encoding="utf-8", newline="\n") as f:
                f.write("def test_demo():\n    assert 1 == 1\n")

            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Modify Rust cleanly, modify Python with unwrap method call
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn safe_calc() -> i32 {\n    let msg = \"do not .unwrap()\";\n    100\n}\n")
            with open(p_py, "w", encoding="utf-8", newline="\n") as f:
                f.write("def test_demo():\n    res = model.unwrap()\n    assert res == 100\n")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_git = run_verify_git(repo_dir=tmp_dir)
            self.assertEqual(rc_git, 0, f"run_verify_git must not cross-contaminate Python unwrap to Rust: {buf.getvalue()}")
            self.assertNotIn("Discovered existing test files", buf.getvalue(), "Must not auto-discover tests when test files are modified in git diff")

    def test_production_rust_unwrap_is_caught_even_with_test_file_modified(self):
        """When both a Rust test file and a Rust production source file are modified,
        production .unwrap() injection in the source file must still be blocked.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)

            p_src = os.path.join(tmp_dir, "lib.rs")
            p_test = os.path.join(tmp_dir, "lib_test.rs")
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn calc(x: Option<i32>) -> i32 {\n    x.unwrap_or(0)\n}\n")
            with open(p_test, "w", encoding="utf-8", newline="\n") as f:
                f.write("#[test]\nfn test_calc() {\n    assert_eq!(calc(Some(1)), 1);\n}\n")

            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Modify both: test is honest, src injects unwrap
            with open(p_src, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn calc(x: Option<i32>) -> i32 {\n    x.unwrap()\n}\n")
            with open(p_test, "w", encoding="utf-8", newline="\n") as f:
                f.write("#[test]\nfn test_calc() {\n    assert_eq!(calc(Some(2)), 2);\n}\n")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc_git = run_verify_git(repo_dir=tmp_dir)
            self.assertEqual(rc_git, 1, f"run_verify_git must block production unwrap when test file is also modified: {buf.getvalue()}")

            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                rc_hook = handle_stop_hook(repo_dir=tmp_dir)
            self.assertEqual(rc_hook, 2, "handle_stop_hook must return exit code 2")

    def test_handle_stop_hook_clean_tree_fast_path(self):
        """Clean working tree with zero diffs must exit 0 immediately."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_dir, check=True, capture_output=True)
            p = os.path.join(tmp_dir, "lib.rs")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write("pub fn f() -> i32 { 1 }\n")
            subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            rc = handle_stop_hook(repo_dir=tmp_dir)
            self.assertEqual(rc, 0, "Clean working tree must exit 0")

        # Non-git directory or None diff_report must also return 0 without AttributeError
        with patch("cordis.hooks.extract_git_diff", return_value=None):
            rc_none = handle_stop_hook(repo_dir=tmp_dir)
            self.assertEqual(rc_none, 0, "diff_report=None must exit 0")

        with tempfile.TemporaryDirectory() as empty_dir:
            rc_empty = handle_stop_hook(repo_dir=empty_dir)
            self.assertEqual(rc_empty, 0, "Non-git directory must exit 0")


if __name__ == "__main__":
    unittest.main()
