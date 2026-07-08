# Strix Convergence Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the current real Strix runtime monitor into a staged, strategy-aware, convergence-diagnosing black-box scan orchestrator without leaving the native frontend + minimal Python backend architecture.

**Architecture:** Keep `demo_server.py` as the API shell, move scan-stage analysis and strategy selection into small backend services, and extend the existing `/runtime` payload so the frontend can explain scan phase, attack surface, convergence, and effective outcome. Reuse the existing real scan path and `strix_runs/` artifacts instead of adding a new job system.

**Tech Stack:** Python standard library backend, native HTML/CSS/JavaScript frontend, existing `strix` CLI integration, existing backend/frontend unittest coverage.

## Global Constraints

- Preserve the native frontend + minimal Python backend architecture.
- Do not remove or regress the existing real Strix scan path (`resultSource=latest_real_run`).
- Do not remove or regress DOCX export.
- Use `apply_patch` for file edits.
- Prefer small focused services over enlarging `demo_server.py`.

---

### Task 1: Runtime Analysis Service

**Files:**
- Create: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\services\runtime_analyzer.py`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\api\demo_server.py`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\tests\backend\test_runtime_analyzer.py`

**Interfaces:**
- Consumes: `run.json`, `strix.log`, task target, task status
- Produces: `analyze_runtime(run_dir: Path | None, *, task_status: str, target: str) -> dict[str, Any]`

- [ ] Add failing backend tests for runtime phase extraction, llm usage extraction, and timeout/no-surface classification.
- [ ] Run only the new backend runtime analyzer tests and confirm they fail.
- [ ] Implement `runtime_analyzer.py`.
- [ ] Update `demo_server.py` to delegate runtime shaping to the analyzer.
- [ ] Re-run the backend runtime analyzer tests and confirm they pass.

### Task 2: Scan Strategy Service

**Files:**
- Create: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\services\scan_strategy.py`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\services\strix_runner.py`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\api\demo_server.py`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\tests\backend\test_scan_strategy.py`

**Interfaces:**
- Consumes: task target, user instruction, optional prior convergence state
- Produces:
  - `build_site_profile(target: str) -> dict[str, Any]`
  - `build_effective_instruction(...) -> str | None`

- [ ] Add failing tests for site-profile classification and instruction-template composition.
- [ ] Run the new strategy tests and confirm they fail.
- [ ] Implement `scan_strategy.py`.
- [ ] Update real-scan startup path so `instruction` sent to Strix is platform-composed.
- [ ] Re-run strategy tests and relevant existing Strix runner tests.

### Task 3: Effective Outcome Classification

**Files:**
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\api\demo_server.py`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\backend\services\runtime_analyzer.py`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\tests\backend\test_demo_server.py`

**Interfaces:**
- Consumes: analyzer output + existing task status transitions
- Produces: richer `summary` and `runtime` states distinguishing environment failure, unconverged timeout, surface found but unverified, and validated findings

- [ ] Add failing API tests for `/runtime` and `/results` for timeout/no-surface, timeout/with-surface, and validated-findings cases.
- [ ] Run targeted backend API tests and confirm they fail.
- [ ] Update summary-building branches to map runtime effectiveness into user-facing Chinese explanations.
- [ ] Re-run targeted backend tests and full backend suite.

### Task 4: Frontend Runtime Workbench Upgrade

**Files:**
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\index.html`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\styles.css`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\app.js`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\tests\frontend\rendering.test.mjs`

**Interfaces:**
- Consumes: expanded `/runtime` payload
- Produces: runtime UI showing phase, site type, attack surface, convergence state, and next-action hint

- [ ] Add failing frontend rendering tests for the new runtime cards and status copy.
- [ ] Run the frontend tests and confirm they fail.
- [ ] Extend frontend runtime state normalization and rendering.
- [ ] Add UI blocks for phase, strategy, attack surface, and convergence diagnosis.
- [ ] Re-run frontend tests and `node --check src/frontend/app.js`.

### Task 5: End-to-End Verification

**Files:**
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\progress.md`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\task_plan.md`

**Interfaces:**
- Consumes: completed backend/frontend changes
- Produces: verified runtime explanations and updated project state

- [ ] Run `python -m unittest discover -s tests/backend`.
- [ ] Run `node --check src/frontend/app.js`.
- [ ] Run `node --test tests/frontend/rendering.test.mjs tests/frontend/taskData.test.mjs`.
- [ ] Run one real scan smoke on a clean port and capture runtime explanation quality.
- [ ] Update `progress.md` and `task_plan.md` with the verified outcome.
