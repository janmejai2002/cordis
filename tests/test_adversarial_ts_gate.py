"""Empirical Adversarial Stress-Test Suite for TypeScript AST Gate (cordis/ts_gate.py).

Authored by Teamwork Challenger (challenger_1_mc) to stress-test:
1. Lexical scanner: mask_ts_code & strip_ts_comments
2. Anchor indexing: index_ts_ast_anchors
3. Mutant synthesis: generate_ts_mutants
"""
from __future__ import annotations

import re
import unittest
from typing import List, Tuple

import cordis.ts_gate as tg


class TestAdversarialLexicalScanner(unittest.TestCase):
    """Adversarial stress tests for mask_ts_code and strip_ts_comments."""

    def assertLengthAndNewlinesPreserved(self, code: str):
        masked = tg.mask_ts_code(code, mask_strings=True)
        self.assertEqual(
            len(code),
            len(masked),
            f"Length mismatch: len(code)={len(code)}, len(masked)={len(masked)} for snippet:\n{code!r}",
        )
        self.assertEqual(
            code.count("\n"),
            masked.count("\n"),
            f"Newline count mismatch: code has {code.count(chr(10))} vs masked {masked.count(chr(10))}",
        )
        for idx, ch in enumerate(code):
            if ch == "\n":
                self.assertEqual(
                    masked[idx],
                    "\n",
                    f"Newline position displaced at character index {idx}",
                )

    def test_deeply_nested_template_strings_and_object_expressions(self):
        """Tests deeply nested template strings with internal expressions and objects."""
        snippets = [
            # Nested template inside template
            "const s = `level 1 ${ `level 2 ${ `level 3 ${val}` }` }`;",
            # Object literal with nested template literal inside expression
            "const s = `outer ${ { a: `${b}` } } end`;",
            # Multiple expressions with strings containing braces
            'const s = `prefix ${ "brace { in } string" } middle ${ { x: 1 } } suffix`;',
            # Comments containing braces inside expressions
            "const s = `result: ${ /* comment with } brace */ 42 }`;",
            # Single-line comment with brace inside expression
            "const s = `result: ${\n // line comment with } brace\n 42\n }`;",
            # Regex inside expression containing braces
            "const s = `regex: ${ /a{1,3}/.test(str) }`;",
            # Escaped backticks and dollar braces
            r"const s = `escaped \` and \${not_interpolated} but ${interpolated}`;",
            # Nested arrow function with inner template string containing braces
            "const s = `nested arrow ${ ((x) => `inner ${x} with { brace }`)('val') } end`;",
            # Unclosed block comment at EOF
            "/* unclosed block comment at EOF\nwith asterisks * and / slashes",
            # Unclosed line comment at EOF
            "// unclosed line comment at EOF without newline",
        ]
        for snip in snippets:
            with self.subTest(snippet=snip):
                self.assertLengthAndNewlinesPreserved(snip)

    def test_multiline_block_comments_with_asterisks_and_slashes(self):
        """Tests block comments with pathological asterisk/slash combinations."""
        snippets = [
            "/*** / ***/",
            "/* */",
            "/**/",
            "/* * / * / */",
            "/*\n * Class header\n * /* nested lookalike */\n */",
            "// comment with /* fake block */ and / slashes",
            "/* comment ending with slash /*/",
        ]
        for snip in snippets:
            with self.subTest(snippet=snip):
                self.assertLengthAndNewlinesPreserved(snip)

    def test_ambiguous_division_vs_regex_literals(self):
        """Tests lexical disambiguation between regex literals and division operators."""
        snippets = [
            # Return regex
            "function f() { return /abc/g; }",
            # Plain division
            "const ratio = x / y / z;",
            # Regex in array literal
            "const arr = [ /abc/, /def/ ];",
            # Regex with character class containing slash
            "const r = /[/]/;",
            # Regex with escaped slash
            r"const r = /\/foo\/bar\//;",
            # Regex with escaped closing bracket in character class
            r"const r = /[\]]/;",
            # Ternary with regex
            "const r = condition ? /foo/i : /bar/g;",
            # Arrow concise returning regex
            "const getRegex = () => /pattern/;",
            # Parens division
            "const res = (a + b) / (c + d);",
        ]
        for snip in snippets:
            with self.subTest(snippet=snip):
                self.assertLengthAndNewlinesPreserved(snip)

    def test_edge_post_increment_decrement_division(self):
        """Hypothesis H2: x++ / y and x-- / y should not be masked as regex literals."""
        code_inc = "const val = x++ / y / z;"
        masked_inc = tg.mask_ts_code(code_inc)
        # In x++ / y / z;, '/ y /' should be division, not a regex literal
        # If masked as regex, 'y' would be replaced with spaces
        has_y_preserved = "y" in masked_inc
        # We record whether the scanner correctly treats this as division
        self.assertTrue(
            has_y_preserved,
            "Scanner falsely treated 'x++ / y / z' as regex literal instead of division!",
        )

    def test_trailing_backslash_at_eof(self):
        """Hypothesis H3: Trailing backslash at EOF in unclosed strings must not expand length."""
        for q in ["'", '"', "`", "/"]:
            snip = f"{q}abc\\"
            masked = tg.mask_ts_code(snip)
            self.assertEqual(
                len(masked),
                5,
                f"Length expanded from 5 to {len(masked)} on trailing backslash with delimiter {q}",
            )
            self.assertEqual(len(snip), 5)

    def test_post_increment_decrement_division_chaining(self):
        """Hypothesis: Chained post-increment/decrement division x++ / y++ / z++ and a-- / b-- / c--.
        None of the divisions should be falsely masked as regex literals.
        """
        snippets = [
            "const res = x++ / y++ / z++;",
            "const res2 = a-- / b-- / c--;",
            "const res3 = p++ / q-- / r++;",
            "const res4 = ((x++) / (y++)) / (z++);",
        ]
        for snip in snippets:
            with self.subTest(snippet=snip):
                self.assertLengthAndNewlinesPreserved(snip)
                masked = tg.mask_ts_code(snip)
                for var in ("x", "y", "z", "a", "b", "c", "p", "q", "r"):
                    if var in snip:
                        self.assertIn(
                            var,
                            masked,
                            f"Variable {var!r} in chained division was erroneously masked as regex!",
                        )

    def test_unclosed_strings_with_multiple_backslashes(self):
        """Hypothesis: Multiple backslashes at EOF or across lines in unclosed quotes must preserve exact length and newlines."""
        bs = chr(92)
        delims = ["'", '"', "`", "/"]
        for q in delims:
            for count in range(1, 6):
                snip = f"{q}literal_content{bs * count}"
                with self.subTest(delim=q, backslashes=count, snip=snip):
                    self.assertLengthAndNewlinesPreserved(snip)
                snip_nl = f"{q}line1{bs * count}\nline2{bs * count}\nline3"
                with self.subTest(delim=q, backslashes=count, snip=snip_nl):
                    self.assertLengthAndNewlinesPreserved(snip_nl)


class TestAdversarialAnchorIndexing(unittest.TestCase):
    """Adversarial stress tests for index_ts_ast_anchors."""

    def test_generic_function_declaration(self):
        """Hypothesis H5: Generic function with nested angle brackets in type parameters."""
        code = """
        export function processItems<T extends Record<string, any>>(arg: T): Promise<T[]> {
            return Promise.resolve([arg]);
        }
        """
        anchors = tg.index_ts_ast_anchors(code, "service.ts")
        self.assertIn(
            "processItems",
            anchors,
            "Failed to index function with nested generic parameters <T extends Record<string, any>>",
        )

    def test_arrow_function_with_generics(self):
        """Hypothesis H5: Arrow function with generic type parameters."""
        code = """
        export const transform = <T extends Record<string, any>>(arg: T): Promise<T[]> => {
            return Promise.resolve([arg]);
        };
        """
        anchors = tg.index_ts_ast_anchors(code, "utils.ts")
        self.assertIn(
            "transform",
            anchors,
            "Failed to index arrow function with generic type parameters <T extends ...>",
        )

    def test_simple_generic_arrow_function(self):
        """Hypothesis H5: Arrow function with simple <T> generic."""
        code = "const identity = <T>(x: T): T => x;"
        anchors = tg.index_ts_ast_anchors(code, "identity.ts")
        self.assertIn("identity", anchors, "Failed to index simple generic arrow function <T>(x: T)")

    def test_class_method_modifiers_and_generators(self):
        """Hypothesis H6: Class methods with async generator and computed symbols."""
        code = """
        class AsyncIterableQueue {
            public static async *[Symbol.iterator]() {
                yield 1;
            }
            async *generatorMethod() {
                yield 2;
            }
            public static async createInstance(config: any) {
                return new AsyncIterableQueue();
            }
        }
        """
        anchors = tg.index_ts_ast_anchors(code, "queue.ts")
        # createInstance should always be indexed
        self.assertIn("AsyncIterableQueue.createInstance", anchors)
        # Check computed symbol and generator methods
        has_symbol_iter = any("iterator" in k for k in anchors.keys())
        has_generator = "AsyncIterableQueue.generatorMethod" in anchors
        self.assertTrue(
            has_symbol_iter or has_generator,
            "Class generator and computed symbol methods were completely unindexed",
        )

    def test_abstract_class_methods(self):
        """Hypothesis: abstract class methods should be indexed."""
        code = """
        export abstract class BaseService {
            public abstract execute(req: any): Promise<any>;
            public logInfo(msg: string) {
                console.log(msg);
            }
        }
        """
        anchors = tg.index_ts_ast_anchors(code, "base.ts")
        self.assertIn("BaseService.logInfo", anchors, "Methods inside abstract class were not indexed")

    def test_tsx_component_function_and_arrow(self):
        """Hypothesis: TSX / JSX components should be indexed properly."""
        code = """
        export function MyButton(props: ButtonProps): JSX.Element {
            return <button onClick={props.onClick}>{props.label}</button>;
        }
        export const Card = (props: CardProps) => {
            return (
                <div className="card">
                    <h1>{props.title}</h1>
                    {props.children}
                </div>
            );
        };
        """
        anchors = tg.index_ts_ast_anchors(code, "Component.tsx")
        self.assertIn("MyButton", anchors)
        self.assertIn("Card", anchors)

    def test_deterministic_and_unique_blake2b_anchors(self):
        """Hypothesis: Anchors must be deterministic 16-hex BLAKE2b digests without collisions."""
        code = """
        class ControllerA {
            handle() { return 1; }
        }
        class ControllerB {
            handle() { return 1; }
        }
        function handle() { return 1; }
        """
        anchors = tg.index_ts_ast_anchors(code, "controllers.ts")
        self.assertEqual(len(anchors), 3)
        tags = [a.hash_tag for a in anchors.values()]
        # All 3 have identical body 'return 1;' but distinct scopes/names, so hashes must NOT collide
        self.assertEqual(len(set(tags)), 3, "Scope-differentiated AST anchors collided!")
        for tag in tags:
            self.assertTrue(re.match(r"^[0-9a-f]{16}$", tag), f"Invalid 16-hex digest: {tag}")

    def test_deep_nested_generics_map_set_promise(self):
        """Hypothesis: Deeply nested generics <T extends Map<string, Set<Promise<number>>>> across function and arrow definitions."""
        code = """
        export function deeplyNested<T extends Map<string, Set<Promise<number>>>>(items: T): Promise<T> {
            return Promise.resolve(items);
        }
        export const arrowNested = <T extends Map<string, Set<Promise<number>>>>(items: T): Promise<T> => {
            return Promise.resolve(items);
        };
        class GenericContainer {
            public async process<T extends Map<string, Set<Promise<number>>>>(items: T): Promise<T> {
                return Promise.resolve(items);
            }
        }
        """
        anchors = tg.index_ts_ast_anchors(code, "nested_generics.ts")
        self.assertIn("deeplyNested", anchors, "Failed to index function with 4-level nested generics")
        self.assertIn("arrowNested", anchors, "Failed to index arrow function with 4-level nested generics")
        self.assertIn("GenericContainer.process", anchors, "Failed to index class method with 4-level nested generics")

    def test_generator_methods_with_computed_symbols(self):
        """Hypothesis: Async generator and generator methods with computed Symbol properties."""
        code = """
        class StreamEngine {
            async *[Symbol.asyncIterator]() {
                yield 1;
            }
            *[Symbol.iterator]() {
                yield 'data';
            }
            public static async *[Symbol.for('customStream')]() {
                yield 42;
            }
        }
        """
        anchors = tg.index_ts_ast_anchors(code, "stream.ts")
        self.assertIn("StreamEngine.[Symbol.asyncIterator]", anchors)
        self.assertIn("StreamEngine.[Symbol.iterator]", anchors)
        self.assertIn("StreamEngine.[Symbol.for('customStream')]", anchors)


class TestAdversarialMutantSynthesis(unittest.TestCase):
    """Adversarial stress tests for generate_ts_mutants."""

    def test_mutants_suppressed_inside_comments_and_strings(self):
        """Hypothesis H7: No mutations may occur inside comments or strings."""
        code = """
        function compute(x: number): boolean {
            // Comment with fake operator: a === b && c + d
            /* Block comment with fake operator: return true; */
            const message = "String containing === and != and + and return null;";
            if (x === 42) {
                return true;
            }
            return false;
        }
        """
        mutants = tg.generate_ts_mutants(code, target_function="compute", max_mutants=10)
        self.assertTrue(len(mutants) > 0, "No mutants generated for valid code")
        for desc, lineno, mutated_code in mutants:
            # Check line numbers of mutations
            self.assertNotIn(
                lineno,
                [3, 4, 5],
                f"Mutant placed inside comment or string literal at line {lineno} ({desc})",
            )
            # The comments and string literal must be preserved intact in the mutated code
            self.assertIn("// Comment with fake operator: a === b && c + d", mutated_code)
            self.assertIn('const message = "String containing === and != and + and return null;";', mutated_code)

    def test_return_without_semicolon_mutation(self):
        """Hypothesis: TS/JS code without trailing semicolons (ASI)."""
        code = """
        function calculate(a: number, b: number) {
            return a + b
        }
        """
        mutants = tg.generate_ts_mutants(code, target_function="calculate")
        has_return_null = any("null" in desc for desc, _, _ in mutants)
        # Note if return without semicolon is supported
        # If not, we document this boundary condition


if __name__ == "__main__":
    unittest.main()
