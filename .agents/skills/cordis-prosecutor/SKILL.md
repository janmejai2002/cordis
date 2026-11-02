---
name: cordis-prosecutor
description: Run and extend the Cordis 3-Gate Adversarial AI-PR Prosecutor (AST Test-Tampering Gate, 5-Mutant AST Hollow-Test Killer, and Differential Fuzzer + Mann-Whitney Benchmark).
---
# Cordis Prosecutor Workflow

1. Always verify code changes by running:
   ```powershell
   python -m pytest -v
   python -m cordis.cli demo --github-comment
   ```
2. When adding new verification gates or AST mutators:
   - Preserve 100% Windows PowerShell compatibility (`sys.executable`, `pathlib.Path`, `subprocess.run(..., timeout=5)`).
   - Ensure every new mutator or AST rule has a corresponding unit test in `tests/test_cordis.py`.