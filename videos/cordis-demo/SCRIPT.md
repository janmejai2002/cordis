# SCRIPT — cordis-launch

**Voice:** am_michael (Kokoro)
**Voice direction:** Authoritative, razor-sharp technical delivery, dark-engineering confidence.

---

## Line 1 — The Problem (Frame 1)

**Time:** 0.0 – 15.0s
**Delivery:** Urgent, analytical, exposing the systemic risk.

    Autonomous coding agents are generating tens of thousands of Pull Requests every day. But they grade their own homework. On SlopCodeBench, 83.7% of agent runs fail to preserve system invariants, and agent test suites miss 37% of injected bugs.

## Line 2 — The Counterfeit Red Trap (Frame 2)

**Time:** 15.0 – 35.0s
**Delivery:** Diagnostic, sharp contrast against false security.

    Traditional CI only measures if code was touched, not if logic was tested. Even SWE-bench's git revert gate is trivially fooled by single-input hardcoded overfits. When an agent crafts a plausible-looking hollow test, the entire verification stack approves it.

## Line 3 — Enter Cordis (Frame 3)

**Time:** 35.0 – 55.0s
**Delivery:** Punchy, commanding, introducing the solution.

    Meet Cordis: the independent adversarial verifier that prosecutes AI-authored code before human review. Zero dependencies. Pure Python standard library. Sub-5 millisecond AST execution.

## Line 4 — The 4 Deterministic Gates (Frame 4)

**Time:** 55.0 – 85.0s
**Delivery:** Structured, rhythmic, marching through the four unbribable gates.

    Cordis runs four unbribable gates. Gate 0 blocks bot collusion. Gate 1 inspects AST anchors to catch weakened asserts. Gate 2 injects in-place mutations—if an agent's test still passes while the function is broken, the PR is rejected. And Gate 3 fuzzes 200 adversarial edge cases outside the bug's domain.

## Line 5 — Empirical Proof (Frame 5)

**Time:** 85.0 – 110.0s
**Delivery:** Hard empirical proof, data-driven authority.

    In head-to-head testing across 22,000 AST functions in top open-source libraries, Cordis caught 100% of counterfeit agent PRs in under 70 milliseconds, with zero false positives on human maintainer commits.

## Line 6 — Drop-In CI (Frame 6)

**Time:** 110.0 – 125.0s
**Delivery:** Decisive, direct call to action.

    Add an adversarial prosecutor to your team in four lines of YAML. Protect your repository from counterfeit code before you merge. Get started with pip install cordis-verify or visit github.com/janmejai2002/cordis.
