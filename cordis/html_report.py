"""Cordis Dark-Mode Visual Prosecutor Scorecard (HTML & Markdown Exporters).
Generates publication-grade, self-contained visual prosecutor dashboards for YC demo & CI artifacts.
Adheres to ui-engineering standards: surface ladder, hairline borders, tabular numerals,
zero external CDN dependencies, and high-contrast dark mode.
"""
from __future__ import annotations

import html
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional


def _escape(text: Any) -> str:
    return html.escape(str(text) if text is not None else "")


def generate_html_report(
    pr_title: str,
    fixproof_revert_passed: bool,
    gate1_report: Any,
    gate2_report: Any,
    gate3_fuzz_report: Any,
    gate3_bench_report: Any,
    forge_report: Optional[Any] = None,
) -> str:
    """Renders a self-contained, responsive dark-mode HTML Prosecutor Scorecard."""
    g1_pass = getattr(gate1_report, "passed", False)
    g2_pass = getattr(gate2_report, "passed", False)
    g3a_pass = getattr(gate3_fuzz_report, "passed", False)
    g3b_pass = getattr(gate3_bench_report, "passed", False)
    forge_pass = getattr(forge_report, "passed", True) if forge_report else True

    overall_passed = g1_pass and g2_pass and g3a_pass and g3b_pass and forge_pass

    # Status indicators
    verdict_badge_text = "VERIFIED APPROVED TO LAND" if overall_passed else "BLOCKED — ADVERSARIAL FLAWS DETECTED"
    verdict_badge_color = "#10b981" if overall_passed else "#f43f5e"
    verdict_bg = "rgba(16, 185, 129, 0.08)" if overall_passed else "rgba(244, 63, 94, 0.08)"
    verdict_border = "rgba(16, 185, 129, 0.3)" if overall_passed else "rgba(244, 63, 94, 0.3)"

    # FixProof Comparison Note
    if fixproof_revert_passed and not overall_passed:
        fp_status_html = """
        <div class="fixproof-pill fooled">
            <span class="pill-dot red"></span>
            <strong>FixProof (git revert) FOOLED:</strong> Checked exit 0 on revert and claimed valid, but missed hollow test &amp; overfitted logic!
        </div>
        """
    elif fixproof_revert_passed:
        fp_status_html = """
        <div class="fixproof-pill ok">
            <span class="pill-dot green"></span>
            <strong>FixProof (git revert):</strong> Revert test check passed.
        </div>
        """
    else:
        fp_status_html = """
        <div class="fixproof-pill failed">
            <span class="pill-dot red"></span>
            <strong>FixProof (git revert):</strong> Failed revert check.
        </div>
        """

    # Gate 1 Violations HTML
    g1_violations = getattr(gate1_report, "violations", [])
    if g1_violations:
        g1_detail_html = '<ul class="evidence-list">' + "".join(
            f'<li class="violation-item"><code>{_escape(v)}</code></li>' for v in g1_violations
        ) + '</ul>'
    else:
        g1_detail_html = '<div class="clean-state">No assertion tampering, mock-patch injection, or skip directives detected.</div>'

    # Gate 2 Mutants HTML
    g2_results = getattr(gate2_report, "results", [])
    survived_mutants = [m for m in g2_results if not getattr(m, "killed", True)]
    kill_rate_pct = int(getattr(gate2_report, "kill_rate", 0.0) * 100)

    if survived_mutants:
        g2_detail_html = '<div class="mutant-warning">Surviving Mutants (Agent test exited 0 despite broken code):</div><ul class="evidence-list">' + "".join(
            f'<li class="mutant-item"><strong>Mutant #{m.mutant_id} (Line {m.lineno})</strong>: {_escape(m.description)} <span class="tag-hollow">HOLLOW TEST</span></li>'
            for m in survived_mutants
        ) + '</ul>'
    else:
        g2_detail_html = f'<div class="clean-state">All {getattr(gate2_report, "total_mutants", 0)} AST mutants were terminated by the test suite (100% kill rate).</div>'

    # Gate 3A Counterexamples HTML
    counterexamples = getattr(gate3_fuzz_report, "counterexamples", [])
    if counterexamples:
        rows = "".join(
            f"<tr><td><code>{_escape(cx.args)}</code></td><td><code>{_escape(cx.old_outcome)}</code></td><td><code class='text-error'>{_escape(cx.new_outcome)}</code></td><td>{_escape(cx.reason)}</td></tr>"
            for cx in counterexamples[:6]
        )
        g3a_detail_html = f"""
        <table class="data-table">
            <thead><tr><th>Input Args</th><th>Expected Spec (f_old)</th><th>Candidate PR (f_new)</th><th>Root Cause</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """
    else:
        g3a_detail_html = f'<div class="clean-state">Tested {getattr(gate3_fuzz_report, "inputs_tested", 200)} property inputs across boundary matrix (NaN, inf, floats, edge ints) with zero mismatches.</div>'

    # Gate 3B Benchmark HTML
    base_us = getattr(gate3_bench_report, "baseline_median_us", 0.0)
    cand_us = getattr(gate3_bench_report, "candidate_median_us", 0.0)
    delta_pct = getattr(gate3_bench_report, "latency_delta_pct", 0.0)
    bench_note = getattr(gate3_bench_report, "note", "")
    p_val = getattr(gate3_bench_report, "p_value", 1.0)

    # Forge Guard Section HTML
    forge_html = ""
    if forge_report:
        f_violations = getattr(forge_report, "violations", [])
        f_actor = getattr(forge_report, "actor", "") or "local"
        f_pass = getattr(forge_report, "passed", True)
        status_text = "PASSED" if f_pass else "VIOLATION DETECTED"
        status_cls = "badge-pass" if f_pass else "badge-fail"
        v_items = "".join(f'<li class="violation-item">{_escape(v)}</li>' for v in f_violations)
        forge_html = f"""
        <section class="card forge-card">
            <div class="card-header">
                <div>
                    <span class="eyebrow">SECURITY GOVERNANCE</span>
                    <h2 class="card-title">Forge Guard: Token &amp; Dual-Custody Verification</h2>
                </div>
                <span class="badge {status_cls}">{status_text}</span>
            </div>
            <div class="card-body">
                <div class="stat-strip">
                    <div class="stat-col"><span class="stat-label">GITHUB_ACTOR</span><span class="stat-value mono">{_escape(f_actor)}</span></div>
                    <div class="stat-col"><span class="stat-label">BOT AUTHORED</span><span class="stat-value">{_escape(getattr(forge_report, 'is_bot_authored', False))}</span></div>
                    <div class="stat-col"><span class="stat-label">SELF APPROVAL</span><span class="stat-value">{_escape(getattr(forge_report, 'is_self_approved', False))}</span></div>
                </div>
                {f'<ul class="evidence-list">{v_items}</ul>' if f_violations else '<div class="clean-state">Verified human approval signature or compliant dual-custody authorization.</div>'}
            </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cordis Prosecutor Scorecard: {_escape(pr_title)}</title>
<style>
:root {{
    --bg: #07090e;
    --raised: #0f131c;
    --elevated: #181d2a;
    --overlay: #202636;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --border: rgba(255, 255, 255, 0.08);
    --border-accent: rgba(255, 255, 255, 0.16);
    --green: #10b981;
    --red: #f43f5e;
    --amber: #f59e0b;
    --cyan: #06b6d4;
    --font-mono: ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono", Consolas, monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    line-height: 1.5;
    padding: 32px 24px;
    display: flex;
    justify-content: center;
}}
.container {{
    width: 100%;
    max-width: 1100px;
    display: flex;
    flex-direction: column;
    gap: 20px;
}}
header {{
    background: var(--raised);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    display: flex;
    flex-direction: column;
    gap: 16px;
}}
.header-top {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 12px;
}}
.brand {{
    font-size: 13px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--cyan);
    font-weight: 700;
}}
h1 {{
    font-size: 24px;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-top: 4px;
}}
.verdict-banner {{
    display: inline-flex;
    align-items: center;
    gap: 10px;
    padding: 8px 16px;
    border-radius: 9999px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    background: {verdict_bg};
    color: {verdict_badge_color};
    border: 1px solid {verdict_border};
}}
.fixproof-pill {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 13px;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--elevated);
}}
.fixproof-pill.fooled {{
    border-color: rgba(244, 63, 94, 0.4);
    background: rgba(244, 63, 94, 0.06);
    color: #fca5a5;
}}
.fixproof-pill.ok {{
    border-color: rgba(16, 185, 129, 0.3);
    background: rgba(16, 185, 129, 0.05);
    color: #a7f3d0;
}}
.pill-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
}}
.pill-dot.red {{ background: var(--red); box-shadow: 0 0 8px var(--red); }}
.pill-dot.green {{ background: var(--green); box-shadow: 0 0 8px var(--green); }}

.cards-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}}
@media (max-width: 800px) {{
    .cards-grid {{ grid-template-columns: 1fr; }}
}}
.card {{
    background: var(--raised);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
}}
.card-header {{
    padding: 16px 20px;
    background: var(--elevated);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.eyebrow {{
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
    font-weight: 600;
}}
.card-title {{
    font-size: 16px;
    font-weight: 700;
    margin-top: 2px;
}}
.badge {{
    font-size: 11px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}}
.badge-pass {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }}
.badge-fail {{ background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4); }}
.card-body {{
    padding: 18px 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
}}
.stat-strip {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
}}
.stat-col {{
    display: flex;
    flex-direction: column;
}}
.stat-label {{
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
.stat-value {{
    font-size: 20px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    margin-top: 2px;
}}
.stat-value.mono {{ font-family: var(--font-mono); font-size: 14px; }}
.evidence-list {{
    list-style: none;
    display: flex;
    flex-direction: column;
    gap: 8px;
}}
.violation-item, .mutant-item {{
    font-size: 13px;
    padding: 8px 12px;
    background: var(--elevated);
    border-left: 3px solid var(--red);
    border-radius: 4px;
}}
.mutant-warning {{
    font-size: 13px;
    font-weight: 600;
    color: #fb7185;
}}
.tag-hollow {{
    background: rgba(244, 63, 94, 0.2);
    color: #fda4af;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    margin-left: 6px;
}}
.clean-state {{
    font-size: 13px;
    color: #94a3b8;
    background: rgba(16, 185, 129, 0.04);
    border-left: 3px solid var(--green);
    padding: 10px 14px;
    border-radius: 4px;
}}
.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    font-family: var(--font-mono);
}}
.data-table th, .data-table td {{
    padding: 8px 10px;
    text-align: left;
    border-bottom: 1px solid var(--border);
}}
.data-table th {{
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 10px;
}}
code {{
    font-family: var(--font-mono);
    font-size: 12px;
    background: var(--elevated);
    padding: 2px 4px;
    border-radius: 4px;
}}
.text-error {{ color: #fb7185; }}
footer {{
    text-align: center;
    font-size: 12px;
    color: var(--text-muted);
    padding: 12px;
}}
</style>
</head>
<body>
<div class="container">
    <header>
        <div class="header-top">
            <div>
                <div class="brand">CORDIS ADVERSARIAL PR PROSECUTOR</div>
                <h1>{_escape(pr_title)}</h1>
            </div>
            <div class="verdict-banner">{verdict_badge_text}</div>
        </div>
        {fp_status_html}
    </header>

    <div class="cards-grid">
        <!-- GATE 1 -->
        <section class="card">
            <div class="card-header">
                <div>
                    <span class="eyebrow">GATE 1 &bull; AST INTEGRITY</span>
                    <h2 class="card-title">Test-Tampering &amp; Mock Audit</h2>
                </div>
                <span class="badge {'badge-pass' if g1_pass else 'badge-fail'}">{'PASS' if g1_pass else 'FAIL'}</span>
            </div>
            <div class="card-body">
                <div class="stat-strip">
                    <div class="stat-col"><span class="stat-label">OLD ASSERTS</span><span class="stat-value">{getattr(gate1_report, 'old_assert_count', 0)}</span></div>
                    <div class="stat-col"><span class="stat-label">NEW ASSERTS</span><span class="stat-value">{getattr(gate1_report, 'new_assert_count', 0)}</span></div>
                    <div class="stat-col"><span class="stat-label">VIOLATIONS</span><span class="stat-value" style="color: {'var(--green)' if len(g1_violations) == 0 else 'var(--red)'}">{len(g1_violations)}</span></div>
                </div>
                {g1_detail_html}
            </div>
        </section>

        <!-- GATE 2 -->
        <section class="card">
            <div class="card-header">
                <div>
                    <span class="eyebrow">GATE 2 &bull; COUNTERFEIT RED KILLER</span>
                    <h2 class="card-title">AST Mutation Kill Rate</h2>
                </div>
                <span class="badge {'badge-pass' if g2_pass else 'badge-fail'}">{'PASS' if g2_pass else 'FAIL'}</span>
            </div>
            <div class="card-body">
                <div class="stat-strip">
                    <div class="stat-col"><span class="stat-label">KILL RATE</span><span class="stat-value">{kill_rate_pct}%</span></div>
                    <div class="stat-col"><span class="stat-label">KILLED</span><span class="stat-value">{getattr(gate2_report, 'killed_mutants', 0)}</span></div>
                    <div class="stat-col"><span class="stat-label">SURVIVED</span><span class="stat-value" style="color: {'var(--green)' if getattr(gate2_report, 'survived_mutants', 0) == 0 else 'var(--red)'}">{getattr(gate2_report, 'survived_mutants', 0)}</span></div>
                </div>
                {g2_detail_html}
            </div>
        </section>

        <!-- GATE 3A -->
        <section class="card">
            <div class="card-header">
                <div>
                    <span class="eyebrow">GATE 3A &bull; PROPERTY FUZZING</span>
                    <h2 class="card-title">Differential Fuzzing (N=200)</h2>
                </div>
                <span class="badge {'badge-pass' if g3a_pass else 'badge-fail'}">{'PASS' if g3a_pass else 'FAIL'}</span>
            </div>
            <div class="card-body">
                <div class="stat-strip">
                    <div class="stat-col"><span class="stat-label">INPUTS</span><span class="stat-value">{getattr(gate3_fuzz_report, 'inputs_tested', 200)}</span></div>
                    <div class="stat-col"><span class="stat-label">COUNTEREXAMPLES</span><span class="stat-value" style="color: {'var(--green)' if len(counterexamples) == 0 else 'var(--red)'}">{len(counterexamples)}</span></div>
                </div>
                {g3a_detail_html}
            </div>
        </section>

        <!-- GATE 3B -->
        <section class="card">
            <div class="card-header">
                <div>
                    <span class="eyebrow">GATE 3B &bull; STATISTICAL BENCHMARK</span>
                    <h2 class="card-title">Mann-Whitney U Test (N=30)</h2>
                </div>
                <span class="badge {'badge-pass' if g3b_pass else 'badge-fail'}">{'PASS' if g3b_pass else 'FAIL'}</span>
            </div>
            <div class="card-body">
                <div class="stat-strip">
                    <div class="stat-col"><span class="stat-label">BASELINE</span><span class="stat-value mono">{base_us:.3f} &mu;s</span></div>
                    <div class="stat-col"><span class="stat-label">PR CANDIDATE</span><span class="stat-value mono">{cand_us:.3f} &mu;s</span></div>
                    <div class="stat-col"><span class="stat-label">DELTA</span><span class="stat-value mono" style="color: {'var(--green)' if delta_pct <= 10.0 else 'var(--red)'}">{delta_pct:+.1f}%</span></div>
                </div>
                <div class="clean-state">
                    <strong>Statistical Note:</strong> {_escape(bench_note)} (p = {p_val:.4f}, Mann-Whitney U test across 30 rounds).
                </div>
            </div>
        </section>
    </div>

    {forge_html}

    <footer>
        Cordis Independent AST Invariant Verifier &bull; 100% Python Standard Library &bull; Zero External Dependencies
    </footer>
</div>
</body>
</html>
"""


def save_html_report(
    filepath: Path | str,
    pr_title: str,
    fixproof_revert_passed: bool,
    gate1_report: Any,
    gate2_report: Any,
    gate3_fuzz_report: Any,
    gate3_bench_report: Any,
    forge_report: Optional[Any] = None,
) -> Path:
    """Renders and saves the HTML report to disk."""
    p = Path(filepath)
    content = generate_html_report(
        pr_title=pr_title,
        fixproof_revert_passed=fixproof_revert_passed,
        gate1_report=gate1_report,
        gate2_report=gate2_report,
        gate3_fuzz_report=gate3_fuzz_report,
        gate3_bench_report=gate3_bench_report,
        forge_report=forge_report,
    )
    p.write_text(content, encoding="utf-8")
    return p


def save_markdown_report(
    filepath: Path | str,
    content: str,
) -> Path:
    """Saves a markdown verdict to disk."""
    p = Path(filepath)
    p.write_text(content, encoding="utf-8")
    return p
