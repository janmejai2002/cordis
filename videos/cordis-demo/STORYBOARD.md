---
format: 1920x1080
duration: 125s
message: "Cordis: Adversarial AI-PR & AST Invariant Prosecutor"
arc: Problem → Blind Spot → Solution → Architecture Gates → Empirical Proof → Drop-In CI
audience: AI engineers, open-source maintainers, and platform security teams
mode: autonomous
music: none
---

## Video direction

- **Palette system**: Authored in modern dark engineering aesthetic (`#080C14` / `#0D1117` ground, `#E6EDF3` text, `#58A6FF` cyan accent, `#3FB950` emerald verified, `#D29922` amber alert, `#F85149` crimson rejected). No pure white, no floating purple AI blobs.
- **Motion grammar + reveal model**: Pure `power3.out` curves. Revealing strictly on spoken cues—never dumping full UI upfront. Elements entrance smoothly and resolve into crystal-clear readability.
- **Rhythm / held-frame allocation**: Frame 3 and Frame 5 provide rock-solid held moments where the viewer absorbs the hero brand identity and empirical data.
- **Negative list**: No bouncy overshoots, no generic stock footage, no fake loading spinners, no unanchored floaters. Every frame is a crisp, responsive, terminal/code-native experience.

---

## Frame 1 — The Problem: Agents Grading Their Own Homework
- status: animated
- src: compositions/frames/01-problem-homework.html
- duration: 19.5s
- transition_in: cut
- scene: Autonomous agents generating PRs that pass hollow tests while grading their own homework
- voiceover: Autonomous coding agents are generating tens of thousands of Pull Requests every day. But they grade their own homework. On SlopCodeBench, 83.7% of agent runs fail to preserve system invariants, and agent test suites miss 37% of injected bugs.
- asset_candidates: capture/assets/cordis-hero-banner.svg
- blueprint: kinetic-type-beats (Adapt)
- focal: terminal PR generation stream with SlopCodeBench stat callout
- roles: terminal = hero cutout · stat card = supporting · backdrop = dark grid #080C14
- sfx: terminal-keystrokes, warning-chime

Scene 1 (0.0–4.0s): Dark terminal window opens upper-left (`#0D1117` surface, hairline border `#21262D`). Agent stream types: "Claude Code / Cursor / Devin generating PR #1042..." with synthetic green checkmarks popping up.
Scene 2 (4.0–9.0s): Red warning banner slams down: "THEY GRADE THEIR OWN HOMEWORK". The fake green checkmarks flicker amber and glitch into hollow check outlines.
Scene 3 (9.0–15.0s): Dual SlopCodeBench metric cards slide in right: "83.7% Invariant Failure Rate" in crimson `#F85149`, "37% Injected Bugs Missed", paired with "43.6% Mock Density" · "29.6% Mutant Survival Rate". The frame holds in high tension.

---

## Frame 2 — The Counterfeit Red Trap & The Industry Blind Spot
- status: animated
- src: compositions/frames/02-counterfeit-trap.html
- duration: 19.43s
- transition_in: crossfade
- scene: 3-column breakdown of industry blind spots (Pytest line coverage, SWE-bench F2P git revert, LLM review)
- voiceover: Traditional CI only measures if code was touched, not if logic was tested. Even SWE-bench's git revert gate is trivially fooled by single-input hardcoded overfits. When an agent crafts a plausible-looking hollow test, the entire verification stack approves it.
- asset_candidates: capture/assets/cordis_report.html
- blueprint: triptych-cards (Adapt)
- focal: 3 failure cards (pytest 100% line coverage fooled, SWE-bench F2P fooled, LLM PR Reviewers blind)
- roles: cards = hero triptych · failure badges = accent highlights
- sfx: error-buzz, glitch-sweep

Scene 1 (0.0–6.0s): Column 1 reveals: "Pytest & Codecov". Displays 100% Line Coverage badge in deceptive green, then peels back to reveal `assert x is not None` hollow assertion. "Fooled by touched lines".
Scene 2 (6.0–13.0s): Column 2 reveals: "SWE-bench Fail-to-Pass (`git revert HEAD~1`)". Displays 100% Pass badge, then exposes single-input overfit: `if x == 100: return 0.15`. Red FOOLED stamp strikes down across the card.
Scene 3 (13.0–20.0s): Column 3 reveals: "LLM PR Reviewers (Copilot / CodeRabbit)". Shows polite markdown commentary: "LGTM! Logic looks clean." completely blind to runtime mutant survival. All 3 cards outline in amber alert hairlines and hold.

---

## Frame 3 — Enter Cordis: Adversarial AST Invariant Prosecutor
- status: animated
- src: compositions/frames/03-enter-cordis.html
- duration: 15.13s
- transition_in: wipe
- scene: Enter Cordis hero banner reveal with core architectural badges
- voiceover: Meet Cordis: the independent adversarial verifier that prosecutes AI-authored code before human review. Zero dependencies. Pure Python standard library. Sub-5 millisecond AST execution.
- asset_candidates: capture/assets/cordis-hero-banner.svg
- blueprint: hero-banner-entrance (Reproduce)
- focal: capture/assets/cordis-hero-banner.svg
- roles: cordis-hero-banner = hero center · feature badges = lower-third triplet
- sfx: sub-bass-boom, power-hum

Scene 1 (0.0–5.0s): Dark veil parts. The official Cordis hero identity banner (`cordis-hero-banner.svg`) sweeps onto canvas at 1080p center, glowing crimson shield emblem with cyan AST nexus pulse.
Scene 2 (5.0–12.0s): Headline lockup locks: "ADVERSARIAL AI-PR & AST INVARIANT PROSECUTOR". Subtitle illuminates: "Prosecute AI-authored code before human review."
Scene 3 (12.0–20.0s): Three crystalline badge pills emerge horizontally underneath: "100% Python Standard Library" · "Zero External Dependencies" · "Sub-5ms AST Execution". Pulsing hairline border `#58A6FF` illuminates and holds with cinematic dignity.

---

## Frame 4 — The 4 Deterministic Prosecution Gates
- status: animated
- src: compositions/frames/04-prosecution-gates.html
- duration: 24.19s
- transition_in: crossfade
- scene: The 4 Deterministic Prosecution Gates architecture pipeline animation
- voiceover: Cordis runs four unbribable gates. Gate 0 blocks bot collusion. Gate 1 inspects AST anchors to catch weakened asserts. Gate 2 injects in-place mutations—if an agent's test still passes while the function is broken, the PR is rejected. And Gate 3 fuzzes 200 adversarial edge cases outside the bug's domain.
- asset_candidates: capture/assets/cordis-architecture.svg
- blueprint: stepped-process-flow (Adapt)
- focal: capture/assets/cordis-architecture.svg
- roles: cordis-architecture = hero schematic · gate highlights = stepped lighting pass
- sfx: gate-lock, scan-pulse, mutant-kill-snap

Scene 1 (0.0–6.0s): Full architecture schematic (`cordis-architecture.svg`) fills center canvas. Light beam races to **Gate 0: ForgeGuard**. Highlights bot self-approval filter, agent token provenance, multi-agent collusion block.
Scene 2 (6.0–12.0s): Signal passes to **Gate 1: AST Invariant & Anti-Tamper Auditor**. Visualizes 64-bit BLAKE2b AST structural anchors, catching deleted assertions and test mocking.
Scene 3 (12.0–20.0s): Signal ignites **Gate 2: AST Mutation Engine ('Counterfeit Red' Killer)**. In-place AST mutations fire: `==` flips to `!=`, `<` flips to `>=`. Holographic code diff shows hollow agent test failing when mutant lives: "MUTANT KILLED · PR REJECTED".
Scene 4 (20.0–30.0s): Signal powers **Gate 3: Differential Property Fuzzer & Latency Gate**. 200 adversarial inputs (`NaN`, `-0.0`, extreme ints) stream through + 30-round Mann-Whitney U test benchmark. Gate seals with green verified seal.

---

## Frame 5 — Live Execution & Empirical Proof
- status: animated
- src: compositions/frames/05-empirical-proof.html
- duration: 16.68s
- transition_in: crossfade
- scene: Live Execution blocked scorecard and benchmark across 22,595 AST functions
- voiceover: In head-to-head testing across 22,000 AST functions in top open-source libraries, Cordis caught 100% of counterfeit agent PRs in under 70 milliseconds, with zero false positives on human maintainer commits.
- asset_candidates: capture/assets/cordis-benchmark-chart.svg, capture/assets/cordis_report.html
- blueprint: split-comparison-metric (Adapt)
- focal: capture/assets/cordis-benchmark-chart.svg
- roles: benchmark-chart = left hero 60% · scorecard = right proof 40%
- sfx: telemetry-click, success-tone

Scene 1 (0.0–8.0s): Interactive live CI scorecard (`cordis_report.html`) renders right-hand side: "PR #42: Bad Agent Patch" with banner: `VERDICT: REJECTED · BLOCKED` and `SWE-bench F2P: FOOLED`.
Scene 2 (8.0–16.0s): Left-hand side reveals `cordis-benchmark-chart.svg`: 22,595 AST functions audited across `click`, `boltons`, `python-dotenv`, `fastmcp`, `smolagents`.
Scene 3 (16.0–25.0s): Three glowing telemetry callout cards count up and lock: "100% Counterfeit PRs Caught" · "< 70ms Execution" · "0.00% False Positives on Human Code". The empirical benchmark holds with overwhelming clarity.

---

## Frame 6 — Drop-In CI & Call to Action
- status: animated
- src: compositions/frames/06-drop-in-ci.html
- duration: 17.92s
- transition_in: crossfade
- scene: Drop-in GitHub Actions workflow and terminal install call to action
- voiceover: Add an adversarial prosecutor to your team in four lines of YAML. Protect your repository from counterfeit code before you merge. Get started with pip install cordis-verify or visit github.com/janmejai2002/cordis.
- asset_candidates: capture/assets/cordis-hero-banner.svg
- blueprint: action-code-banner (Adapt)
- focal: GitHub Actions YAML window + pip install terminal
- roles: yaml-window = left focal · terminal-pill = right CTA
- sfx: terminal-enter, chime-resolve

Scene 1 (0.0–5.0s): Code window floats left: 4-line GitHub Actions workflow snippet:
```yaml
- name: Cordis Invariant Prosecution
  uses: janmejai2002/cordis@v0.2.0
  with:
    fail-on-surviving-mutant: true
```
Scene 2 (5.0–10.0s): Terminal command prompt types onto right panel: `$ pip install cordis-verify` followed by `$ uvx cordis-verify demo`.
Scene 3 (10.0–15.0s): Large glowing repository link resolves center-bottom: `github.com/janmejai2002/cordis` with "STAR ON GITHUB · SECURE YOUR CI". Shield emblem glows and holds.
