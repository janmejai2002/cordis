# Cordis Handover & Deployment Guide

> **Project**: [Cordis (cordis-verify)](https://github.com/janmejai2002/cordis)  
> **Release**: v0.3.0  
> **Purpose**: Complete guide for sharing repository access, configuring deployment permissions (GitHub + PyPI), and instructing AI agents (Claude Code / AGY) on maintaining and deploying Cordis.

---

## 1. Quick Overview: What Has Been Built

Cordis is an independent, zero-token adversarial verification engine designed to prevent AI coding agents from cheating test suites. In this release (v0.3.0):
- **100% Mutant Kill Rate**: Across all 8 core modules (`ast_gate.py`, `mutator.py`, `fuzzer.py`, `repair.py`, `hooks.py`, `ts_gate.py`, `forge_guard.py`, `policy_guard.py`), 0 surviving non-arid mutants exist across 71 core functions.
- **324+ Unit & Stress Tests Passing**: Full suite runs deterministically in ~42s via `python -m unittest discover -s tests -v`.
- **TypeScript / JavaScript Mutation & Tampering Gate** (`cordis/ts_gate.py`): Full lexical masking, function anchor indexing (BLAKE2b 16-hex), and relational mutant synthesis.
- **Autonomous Hook Firewall** (`cordis/hooks.py`): Real-time pre-tool interception and pre-commit verification for Claude Code and git.
- **Automated Test Synthesis Engine** (`cordis/repair.py`): Generates targeted invariant assertions for surviving mutants.

---

## 2. Granting Access & Permissions to Your Friend

Follow these 3 steps to give your friend full control over the code, CI/CD, and PyPI deployments.

### Step 2.1: Grant GitHub Repository Collaborator Access

1. Open your repository on GitHub:
   👉 **`https://github.com/janmejai2002/cordis/settings/access`**
2. Click **"Add people"** (green button).
3. Enter your friend's GitHub username or email address.
4. Select their role:
   - **`Admin`** *(Recommended)*: Gives them full control to manage repository settings, configure secrets, manage branches, and dispatch workflows.
   - **`Maintain` / `Write`**: Allows them to push directly to branches, open PRs, and run Actions without changing repository admin settings.
5. Send the invitation.
6. Your friend will receive an email invitation or can accept it directly at:
   👉 **`https://github.com/janmejai2002/cordis/invitations`**

---

### Step 2.2: Configure PyPI Deployment Permissions

Cordis is published to the Python Package Index under **`cordis-verify`**.

#### Option A: Add Your Friend as a PyPI Collaborator (Direct Access)
1. Log in to [PyPI.org](https://pypi.org).
2. Go to **`https://pypi.org/manage/project/cordis-verify/collaboration/`**.
3. Under **"Invite a collaborator"**, enter your friend's PyPI username.
4. Set role to **`Maintainer`** or **`Owner`**.
5. Click **"Add"**. Your friend accepts the invitation in their PyPI dashboard.

#### Option B: Configure GitHub Actions Automated PyPI Publishing (Recommended)
Cordis already has an automated CI/CD workflow at `.github/workflows/publish-pypi.yml` that builds and deploys to PyPI whenever a tag (`v*`) is pushed.

1. Create a PyPI API Token:
   - Log in to [PyPI Account Settings](https://pypi.org/manage/account/).
   - Click **"Add API token"**.
   - Scope: Set to project **`cordis-verify`** (or entire account if first release).
   - Copy the generated token string (starts with `pypi-...`).
2. Add the token to GitHub Secrets:
   - Go to 👉 **`https://github.com/janmejai2002/cordis/settings/secrets/actions`**.
   - Click **"New repository secret"**.
   - Name: `PYPI_API_TOKEN`
   - Secret: Paste the PyPI token.
   - Click **"Add secret"**.
3. *Done!* Whenever you or your friend push a version tag (e.g., `git tag v0.3.0 && git push origin v0.3.0`), GitHub Actions will automatically build the wheel, create a GitHub Release, and publish to PyPI.

---

### Step 2.3: Verify GitHub Actions Workflow Permissions

To allow the Cordis PR Prosecutor bot to write PR comments and upload scorecards:
1. Go to 👉 **`https://github.com/janmejai2002/cordis/settings/actions`**.
2. Scroll to **"Workflow permissions"**.
3. Select **"Read and write permissions"**.
4. Check **"Allow GitHub Actions to create and approve pull requests"**.
5. Click **"Save"**.

---

## 3. Local Setup Instructions for Your Friend

Send this section directly to your friend so they can get running in under 2 minutes:

```bash
# 1. Clone the repository
git clone https://github.com/janmejai2002/cordis.git
cd cordis

# 2. Set up virtual environment using uv (recommended) or python
uv venv
source .venv/bin/activate       # On macOS/Linux
# or: .venv\Scripts\activate    # On Windows

# 3. Install in editable mode with development dependencies
uv pip install -e ".[dev]"

# 4. Verify test suite (324+ tests)
python -m unittest discover -s tests -v

# 5. Install git pre-commit hook and agent firewall
python -m cordis.cli hooks install
```

---

## 4. Instructing Claude Code (For Your Friend's Agent)

A root **`CLAUDE.md`** has been placed in the repository. Claude Code automatically reads this file whenever it opens the workspace.

### How Your Friend's Claude Uses `CLAUDE.md`:
1. **Automatic Context Orientation**: Claude immediately understands the 8-module architecture, the 3-gate verification system, and all CLI commands.
2. **Quality Invariant**: Claude is explicitly instructed to maintain a **100% mutant kill rate** on all new code and will never attempt to weaken assertions or insert hollow mocks.
3. **Execution Commands**:
   - `python -m unittest discover -s tests -v` — complete regression suite.
   - `python -m cordis.cli probe --source <src> --test <test> --func <fn> --suggest-test` — mutant killer synthesis.
   - `python -m cordis.cli check-policy --repo .` — anti-AI policy guard.

---

## 5. Deployment / Publishing Checklist

When ready to ship v0.3.0 to PyPI and GitHub Releases:

```bash
# 1. Confirm clean working tree and tests
python -m unittest discover -s tests -v

# 2. Create the release tag
git tag -a v0.3.0 -m "Cordis v0.3.0: 100% mutant kill rate, TypeScript gate, and agent firewall"

# 3. Push to GitHub
git push origin main --tags
```

GitHub Actions will automatically execute `.github/workflows/publish-pypi.yml`:
- Builds `dist/cordis_verify-0.3.0-py3-none-any.whl` and tarball.
- Creates GitHub Release `v0.3.0` with autogenerated release notes.
- Publishes the package to PyPI at `https://pypi.org/project/cordis-verify/`.
