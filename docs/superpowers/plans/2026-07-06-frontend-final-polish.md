# Frontend Final Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将当前前端收束为深色、冷静、产品级演示界面，同时保持现有任务创建、结果读取、显式运行、来源切换与 Markdown 导出能力不回退。

**Architecture:** 继续沿用现有静态 `index.html + styles.css + app.js + rendering.mjs` 架构，不引入新框架。实现以 HTML 结构收束和 CSS 视觉重构为主，只有当 DOM 挂载点或显示文案受影响时才最小化调整 `rendering.mjs`。

**Tech Stack:** 原生 HTML、CSS、ES modules、Node 内置测试、现有 Python demo server

## Global Constraints

- 保持 `src/frontend/app.js` 现有 API 调用路径不回退
- 保持 `fixture` 与 `latest_real_run` 两条来源路径不回退
- 不新增业务功能，不修改后端接口语义
- 页面方向固定为 `A1 = 深色、冷静、产品级演示`
- 去掉假大空文案，所有标题优先说明用途
- 风险颜色仅用于严重级别，不扩散为整页氛围色

---

### Task 1: 收束页面结构与文案语气

**Files:**
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\index.html`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\tests\frontend\rendering.test.mjs`

**Interfaces:**
- Consumes: `#task-form`, `#form-feedback`, `#task-list`, `#summary-strip`, `#ai-summary`, `#findings-list`, `#report-task-name`, `#report-target`, `#report-source`, `#run-task`, `#export-report`
- Produces: 保持上述 DOM id 不变；允许 class 名与文案更新

- [ ] **Step 1: 写出会失败的结构快照测试**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("index.html uses product-focused labels for the final polish layout", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.match(html, /任务创建/);
  assert.match(html, /结果总览/);
  assert.match(html, /任务记录/);
  assert.match(html, /风险详情/);
  assert.doesNotMatch(html, /Mission|Current Result|Overview|Task List|Findings/);
});
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `node --test tests/frontend/rendering.test.mjs`

Expected: FAIL，因为当前 `index.html` 仍含 `Overview`、`Current Result`、`Task List` 或其他旧英文标签。

- [ ] **Step 3: 以最小结构调整实现产品化文案与模块标题**

```html
<header class="topbar">
  <div class="topbar__brand">
    <span class="topbar__mark">SA</span>
    <div>
      <p class="micro-label">Strix Demo</p>
      <strong>AI 辅助安全分析平台</strong>
    </div>
  </div>
  <div class="topbar__status">
    <span class="status-chip">授权目标</span>
    <span class="status-chip status-chip--muted">课程演示版</span>
  </div>
</header>

<section class="hero">
  <div class="hero__main">
    <p class="micro-label">Product Demo</p>
    <h1>安全分析演示界面</h1>
    <p>支持任务创建、结果查看、显式运行、摘要讲解和 Markdown 导出。</p>
  </div>
  <div class="hero__actions">
    <a href="#task-form">新建任务</a>
    <a href="#findings-list">查看结果</a>
  </div>
</section>

<div class="section-heading">
  <p class="micro-label">Task Setup</p>
  <h2>任务创建</h2>
</div>

<div class="section-heading section-heading--tight">
  <p class="micro-label">Result Overview</p>
  <h2>结果总览</h2>
</div>

<div class="section-heading section-heading--tight">
  <p class="micro-label">Task History</p>
  <h2>任务记录</h2>
</div>

<div class="section-heading">
  <p class="micro-label">Finding Review</p>
  <h2>风险详情</h2>
</div>
```

- [ ] **Step 4: 运行测试确认通过**

Run: `node --test tests/frontend/rendering.test.mjs`

Expected: PASS，且现有渲染类测试继续通过。

- [ ] **Step 5: Commit**

```bash
git add src/frontend/index.html tests/frontend/rendering.test.mjs
git commit -m "feat: tighten frontend product copy and structure"
```

### Task 2: 重构深色产品化视觉与交互层级

**Files:**
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\styles.css`
- Modify: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\src\frontend\src\frontend\index.html`
- Test: `C:\Users\MMK20041021\Desktop\workspace\01_新项目\scripts\browser_smoke_test.mjs`

**Interfaces:**
- Consumes: Task 1 中保留的 DOM id、更新后的 layout class
- Produces: 深色产品级视觉层；不改变按钮、表单、列表和 findings 的交互目标

- [ ] **Step 1: 写出会失败的视觉契约测试**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("styles.css uses a restrained product-dark palette instead of the old amber-teal atmosphere", () => {
  const css = readFileSync(new URL("../../src/frontend/styles.css", import.meta.url), "utf8");

  assert.match(css, /--accent:\s*#6f8cff/i);
  assert.match(css, /--bg:\s*#0b1020/i);
  assert.doesNotMatch(css, /--accent:\s*#d89a5f/i);
  assert.doesNotMatch(css, /atmosphere--amber|atmosphere--teal/);
});
```

- [ ] **Step 2: 运行测试并确认失败**

Run: `node --test tests/frontend/rendering.test.mjs`

Expected: FAIL，因为当前样式仍包含旧的橙青氛围变量和 atmosphere 层。

- [ ] **Step 3: 以产品级深色样式重写主视觉**

```css
:root {
  --bg: #0b1020;
  --bg-elevated: #121933;
  --panel: #11172b;
  --panel-soft: #161e36;
  --line: rgba(148, 163, 184, 0.18);
  --line-strong: rgba(148, 163, 184, 0.3);
  --text: #e8edf8;
  --muted: #9aa7bf;
  --accent: #6f8cff;
  --accent-strong: #8fa3ff;
  --success: #54c7a5;
  --radius-xl: 24px;
  --radius-lg: 18px;
  --radius-md: 14px;
}

body {
  background:
    radial-gradient(circle at top left, rgba(111, 140, 255, 0.14), transparent 24%),
    linear-gradient(180deg, #090e1b 0%, #0b1020 100%);
  color: var(--text);
}

.topbar,
.hero,
.workspace,
.detail-stage {
  border: 1px solid var(--line);
  background: linear-gradient(180deg, rgba(18, 25, 51, 0.96), rgba(11, 16, 32, 0.96));
  box-shadow: 0 18px 48px rgba(3, 8, 20, 0.34);
}

.summary-meter,
.task-entry,
.finding-entry,
.result-meta,
.result-summary {
  background: var(--panel-soft);
  border: 1px solid var(--line);
}

button,
.hero a {
  background: linear-gradient(135deg, var(--accent-strong), var(--accent));
  color: #f8fbff;
}
```

- [ ] **Step 4: 如挂载结构变化影响展示，则最小化调整渲染层文案**

```js
export function renderSummaryMarkup(task, severityOrder = defaultSeverityOrder) {
  const counts = summarizeFindings(task.report.findings, severityOrder);

  return {
    summaryStripMarkup: severityOrder.map((severity) => `
      <article class="summary-meter summary-meter--${escapeHTML(severity)}">
        <span class="micro-label">${escapeHTML(severityDisplayMap[severity] ?? severity)}</span>
        <strong>${escapeHTML(String(counts[severity]))}</strong>
        <p>当前结果中的${escapeHTML(severityDisplayMap[severity] ?? severity)}数量。</p>
      </article>
    `).join(""),
    aiSummaryMarkup: task.summary?.executiveSummary
      ? renderBackendSummary(task)
      : renderFallbackSummary(task, counts, task.report.findings[0]),
  };
}
```

- [ ] **Step 5: 跑语法检查与前端测试**

Run: `node --check src/frontend/app.js`

Expected: 无输出，退出码 0

Run: `node --test tests/frontend/rendering.test.mjs tests/frontend/taskData.test.mjs`

Expected: PASS，全部前端测试通过

- [ ] **Step 6: 跑浏览器 smoke 验证关键演示路径**

Run: `node scripts/browser_smoke_test.mjs http://127.0.0.1:8767`

Expected: create task / explicit run / export 路径通过；若端口脏，则改用干净本地端口再次执行

- [ ] **Step 7: Commit**

```bash
git add src/frontend/index.html src/frontend/styles.css src/frontend/rendering.mjs tests/frontend/rendering.test.mjs
git commit -m "feat: polish frontend into product-grade dark demo"
```

## Self-Review

- Spec coverage：已覆盖首屏产品化、三区产品化、风险详情产品化、深色冷静风格和动效收束
- Placeholder scan：无 TBD / TODO / “稍后实现” 类占位
- Type consistency：保留现有 DOM id 和渲染入口，不引入新的未定义接口名
