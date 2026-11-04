<div align="center">

# 🗺️ Cordis Technical Roadmap (2026–2027)

**The Engineering Roadmap for Next-Generation Adversarial AI-PR Prosecution**

[![Status: Active Development](https://img.shields.io/badge/status-active%20development-blue.svg?style=flat-square)](../README.md)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0%20external-success.svg?style=flat-square)](https://docs.python.org/3/)
[![License: MIT](https://img.shields.io/badge/license-MIT-informational.svg?style=flat-square)](../LICENSE)

---

</div>

## 🎯 Strategic Vision

Cordis is transforming from a Python-focused AST invariant prosecutor into the **universal adversarial verification standard for the autonomous software engineering era**. As frontier coding agents scale from writing 10 lines of code to authoring entire distributed systems, Cordis provides the mathematically un-gameable boundary between AI generation and production deployment.

---

## 🚀 Wave 1: Core Engine Hardening (Q1–Q2 2026) — *Completed & Verified*

- [x] **Zero-Dependency Python Stdlib Architecture**: Pure standard library execution with sub-5ms latency and zero supply chain overhead.
- [x] **The 4-Gate Prosecution Engine**:
  - Gate 0: ForgeGuard (Dual-custody verification, commit trailer analysis).
  - Gate 1: AST Anti-Tamper & Mock-to-Assertion Ratio (MAR).
  - Gate 2: In-Place AST Mutator with `.cordis.bak` crash recovery.
  - Gate 3: 200-input differential property fuzzer & Mann-Whitney U latency gate.
- [x] **Headless Zero-Token Probe (`cordis probe`)**: Scoped test execution with `--pytest-args` and sub-second mutant validation.
- [x] **Tier-1 Wild Invariant Hunting**: Audited 16+ industry-standard repositories (`aiohttp`, `httpx`, `fastmcp`, `smolagents`, `pydantic-ai`, `instructor`, `anthropic-sdk-python`, `openai-python`, `litellm`, `sqlmodel`, `requests`, `fastapi`, `click`, `boltons`, `python-dotenv`). 401+ mutants evaluated in the wild with 138+ invariants killed with 100% precision.
- [x] **Self-Dogfooding Invariant Verification**: Cordis audited itself across 15 self-probed mutants with 100% kill rate (zero surviving mutants).

---

## ⚡ Wave 2: Frontier AST Operators & Deep Protocols (Q3 2026) — *In Progress*

### 1. Transport Stream Lifecycle & Async Resource Auditing
- **Context**: In HTTP client and streaming libraries (`httpx`, `aiohttp`, `urllib3`), agents frequently mock response bodies without verifying connection release (`stream.close()` / `stream.aclose()`).
- **Milestone**: Introduce dedicated lifecycle visitor for `SyncByteStream` and `AsyncByteStream` protocols to enforce context manager and teardown assertion verification.

### 2. Multi-Hop Buffer Boundary Probing (`CHUNK_SIZE`)
- **Context**: Implementations using internal chunking constants (e.g. `CHUNK_SIZE = 65_536`) often survive tests because tests pass trivial single-chunk inputs (e.g. 13-byte strings).
- **Milestone**: Automated heuristic synthesis in Gate 3 detecting buffer constants and exercising multi-hop chunk boundary conditions ($x > 2 \times \text{CHUNK\_SIZE}$).

### 3. Security Parameter Default Invariants
- **Context**: Mutations on security-critical constructor flags (`trust_env=True` $\rightarrow$ `False`, `verify=True` $\rightarrow$ `False`) frequently survive when tests rely on mock responses.
- **Milestone**: Automated parameter default mutation tracking for cryptographic, SSL, and network environment defaults.

---

## 🌐 Wave 3: Polyglot Multi-Language Prosecution (Q4 2026)

- [ ] **TypeScript / JavaScript AST Gate (Node & Bun)**:
  - Zero-external-dependency TypeScript AST parsing via native tree traversal.
  - Detection of Jest/Vitest hollow assertions (`expect(val).toBeDefined()`) and `@jest/mock` abuse.
- [ ] **Rust Invariant Engine (`cargo-cordis`)**:
  - Trait boundary mutation and property fuzzing integration via `cargo-fuzz`.
- [ ] **Go AST Prosecutor (`go/ast`)**:
  - In-place mutant injection for table-driven tests and goroutine concurrency leak detection.

---

## 🧠 Wave 4: Continuous Autonomous Invariant Synthesis (2027)

- [ ] **Counterexample-Driven Auto-Repair**:
  - When Cordis discovers an agent's test is hollow or overfitted, synthesize the exact missing assertion patch automatically.
- [ ] **GitHub Marketplace App (1-Click Bot)**:
  - Frictionless 1-click GitHub App installation for public and private organizations.
- [ ] **Decentralized Invariant Ledger**:
  - Global attestation of tested invariant kill rates across the open-source software supply chain.
