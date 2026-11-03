# Contributing to Cordis

Thank you for your interest in contributing to Cordis! Cordis is designed as an independent adversarial prosecutor for AI-authored code and pull requests.

## 🏛️ Architecture & Philosophy

1. **Zero External Dependencies**: The core prosecutorial engine of Cordis runs entirely on the Python standard library (`ast`, `dis`, `sqlite3`, `unittest`, `dataclasses`, `difflib`). Do not add external runtime dependencies to `cordis/`.
2. **Sub-5ms Execution**: Every AST gate and mutant generator must remain lightweight and deterministic.
3. **Adversarial Mindset**: Assume agents will attempt to reward-hack CI by weakening assertions, over-mocking, or hardcoding return values. Gates must remain tamper-resistant.

## 🛠️ Development Setup

Cordis uses [`uv`](https://github.com/astral-sh/uv) for fast, reproducible environment management:

```powershell
# Clone the repository
git clone https://github.com/janmejai2002/cordis.git
cd cordis

# Install editable package with test tools
uv pip install -e .

# Run test suite
uv run pytest -v
```

## 🧪 Testing Guidelines

- All PRs must pass the test suite with 100% success.
- If introducing new AST mutation operators (`cordis/mutator.py`) or test tampering checks (`cordis/ast_gate.py`), include both:
  - An adversarial synthetic test case demonstrating what is caught.
  - A regression test confirming legitimate maintainer patterns are not flagged (zero false positives).

## 🚀 Running the Benchmarks

```powershell
# Run the 5-Archetype synthetic benchmark
uv run cordis benchmark

# Run the live 6-repository open-source benchmark (click, boltons, python-dotenv, fastmcp, smolagents, nao)
uv run cordis benchmark-repos
```

## 📝 Submitting a Pull Request

1. Fork the repo and create a feature branch (`git checkout -b feat/my-new-gate`).
2. Verify all tests pass (`uv run pytest`).
3. Commit your changes using clear commit messages.
4. Push and open a PR. Cordis's own CI workflow will prosecute the PR before review.
