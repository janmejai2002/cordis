<div align="center">

# 🤖 Cordis CI/CD & GitHub Actions Integration Guide

**Automate adversarial verification across your pull request pipeline.**

[![GitHub Actions](https://img.shields.io/badge/github--actions-supported-2088FF.svg?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/features/actions)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square)](https://docs.python.org/3/)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square)](../LICENSE)

---

</div>

## 📌 1. Complete GitHub Actions Workflow (`.github/workflows/cordis.yml`)

The canonical workflow executes the full 4-gate verification suite on every opened or updated Pull Request, posts a detailed forensic scorecard comment on the PR, renders a markdown step summary, and uploads the interactive HTML report as an artifact:

```yaml
name: Cordis Adversarial AI-PR Prosecutor

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  pull_request_review:
    types: [submitted]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  prosecute:
    name: Cordis 4-Gate Invariant Verification
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 2 # Required for diff extraction against HEAD~1

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run Test Suite
        run: |
          python -m unittest discover -s tests -v

      - name: Run Cordis Invariant Prosecutor
        run: |
          python -m cordis.cli verify-git \
            --base-ref HEAD~1 \
            --github-comment \
            --output-html cordis_report.html \
            --output-md cordis_report.md
        env:
          GITHUB_ACTOR: ${{ github.actor }}
          GITHUB_TRIGGERING_ACTOR: ${{ github.triggering_actor }}
          GITHUB_EVENT_NAME: ${{ github.event_name }}

      - name: Publish Step Summary to GitHub Job
        if: always()
        run: |
          if [ -f cordis_report.md ]; then
            cat cordis_report.md >> $GITHUB_STEP_SUMMARY
          else
            echo "### 🛡️ Cordis Prosecutor: Verification Completed" >> $GITHUB_STEP_SUMMARY
          fi

      - name: Post Cordis Verdict Comment on PR
        if: always() && github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            if (fs.existsSync('cordis_report.md')) {
              const body = fs.readFileSync('cordis_report.md', 'utf8');
              github.rest.issues.createComment({
                issue_number: context.issue.number,
                owner: context.repo.owner,
                repo: context.repo.repo,
                body: body
              });
            }

      - name: Upload Visual Scorecard Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cordis-prosecutor-scorecard
          path: cordis_report.html
```

---

## 🎯 2. How the Scorecard Looks in GitHub PRs

When Cordis runs, it posts an unambiguous, forensic verdict table directly into your pull request:

```markdown
## 🛡️ Cordis Adversarial AI-PR Prosecutor Verdict: PR #42
**Overall Verdict**: 🛑 **BLOCKED — COUNTERFEIT RED / REGRESSION DETECTED**

**SWE-bench `Fail-to-Pass` (`git revert HEAD~1`)**: ✅ PASSED (Fooled by single-input test!)

| Prosecution Gate | Status | Telemetry & Evidence |
| :--- | :---: | :--- |
| **Gate 0: ForgeGuard Bot Self-Approval** | ✅ PASS | Verified human maintainer trigger |
| **Gate 1: AST Invariant & Anti-Tamper** | ❌ FAIL | 1 tampering violation (hollow assertion) |
| **Gate 2: In-Place AST Mutator** | ❌ FAIL | 2/3 killed (1 mutant survived untouched) |
| **Gate 3A: Differential Property Fuzzing** | ❌ FAIL | 5 counterexamples found (`f_spec != f_pr`) |
| **Gate 3B: Mann-Whitney U Latency Gate** | ✅ PASS | 0.054us -> 0.041us (-25.7% delta) |
```

---

## 🔒 3. Local Git Pre-Push Hook (`.git/hooks/pre-push`)

Prevent pushing counterfeit or hollow tests before code even reaches CI. Create `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -e

echo "🛡️ Running Cordis pre-push invariant prosecution..."
python -m cordis.cli verify-git --base-ref origin/main --quiet

if [ $? -ne 0 ]; then
    echo "🛑 Cordis detected surviving mutants or test tampering! Push aborted."
    exit 1
fi

echo "✅ Cordis approved local changes."
exit 0
```

Make it executable:
```bash
chmod +x .git/hooks/pre-push
```

---

## 🛡️ 4. Recommended Branch Protection Rules

To enforce dual-custody and prevent AI agents from bypassing Cordis:

1. **Require status checks to pass before merging**:
   - Enable check: `Cordis 4-Gate Invariant Verification`.
2. **Require branches to be up to date before merging**.
3. **Require a pull request before merging**:
   - Require approvals: `1` minimum (Human Maintainer).
   - Dismiss stale pull request approvals when new commits are pushed.
4. **Do not allow bypassing the above settings**.
