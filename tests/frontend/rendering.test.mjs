import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  escapeHTML,
  renderTaskListMarkup,
  renderSummaryMarkup,
  renderFindingsMarkup,
  renderRuntimeWorkbenchMarkup,
} from "../../src/frontend/rendering.mjs";

function assertSectionHeading(html, headingText) {
  const escapedHeading = headingText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  assert.match(
    html,
    new RegExp(`<div class="section-heading(?: section-heading--tight)?">\\s*<h2>${escapedHeading}<\\/h2>`),
  );
}

test("index.html renders each functional module with a single title", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assertSectionHeading(html, "任务创建");
  assertSectionHeading(html, "结果总览");
  assertSectionHeading(html, "任务记录");
  assertSectionHeading(html, "风险详情");
  assert.doesNotMatch(html, /<p class="micro-label">任务创建<\/p>/);
  assert.doesNotMatch(html, /<p class="micro-label">结果总览<\/p>/);
  assert.doesNotMatch(html, /<p class="micro-label">任务记录<\/p>/);
  assert.doesNotMatch(html, /<p class="micro-label">风险详情<\/p>/);
});

test("index.html uses a continuous product-stage layout instead of fact-card stacking", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.doesNotMatch(html, /<section class="hero\b/);
  assert.doesNotMatch(html, /hero__rail/);
  assert.doesNotMatch(html, /hero-signal/);
  assert.doesNotMatch(html, /fact-card/);
});

test("index.html removes explanatory copy from functional modules", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.doesNotMatch(html, /panel-intro/);
  assert.doesNotMatch(html, /panel-note/);
  assert.doesNotMatch(html, /detail-stage__intro/);
  assert.doesNotMatch(html, /result-summary__caption/);
});

test("index.html exposes markdown and docx export choices", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.match(html, /id="export-kind"/);
  assert.match(html, /Markdown 报告/);
  assert.match(html, /DOCX 报告（当前网站）/);
  assert.match(html, /DOCX 报告（全部网站合并）/);
});

test("index.html exposes scan timeout presets for real scans", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.match(html, /id="task-timeout"/);
  assert.match(html, /3 分钟/);
  assert.match(html, /5 分钟/);
  assert.match(html, /10 分钟/);
});

test("styles.css uses the restrained product-dark palette for the final polish", () => {
  const css = readFileSync(new URL("../../src/frontend/styles.css", import.meta.url), "utf8");

  assert.match(css, /--bg:\s*#0b1020/i);
  assert.match(css, /--accent:\s*#6f8cff/i);
  assert.doesNotMatch(css, /--accent:\s*#d89a5f/i);
  assert.doesNotMatch(css, /atmosphere--amber|atmosphere--teal/);
});

test("escapeHTML escapes dangerous HTML characters", () => {
  assert.equal(
    escapeHTML(`<img src="x" onerror="alert('xss')">&"'`),
    "&lt;img src=&quot;x&quot; onerror=&quot;alert(&#39;xss&#39;)&quot;&gt;&amp;&quot;&#39;",
  );
});

test("renderTaskListMarkup escapes user-controlled task fields", () => {
  const payload = `<img src=x onerror="alert('xss')">`;
  const markup = renderTaskListMarkup(
    [
      {
        taskId: "task-001",
        name: payload,
        target: payload,
        scanMode: payload,
        status: payload,
      },
    ],
    "task-001",
  );

  assert.equal(markup.includes(payload), false);
  assert.match(markup, /&lt;img src=x onerror=&quot;alert\(&#39;xss&#39;\)&quot;&gt;/);
});

test("renderTaskListMarkup shows failed status for failed tasks", () => {
  const markup = renderTaskListMarkup(
    [
      {
        taskId: "task-003",
        name: "real scan",
        target: "./src/frontend",
        scanMode: "quick",
        resultSource: "latest_real_run",
        status: "failed",
      },
    ],
    "task-003",
  );

  assert.match(markup, /执行失败/);
  assert.doesNotMatch(markup, /已完成/);
});

test("renderTaskListMarkup shows completed status for failed tasks that already retained findings", () => {
  const markup = renderTaskListMarkup(
    [
      {
        taskId: "task-004",
        name: "real scan with preserved findings",
        target: "./src/frontend",
        scanMode: "deep",
        resultSource: "latest_real_run",
        status: "failed",
        report: {
          findings: [
            {
              findingId: "finding-001",
              severity: "high",
            },
          ],
        },
      },
    ],
    "task-004",
  );

  assert.match(markup, /已完成/);
  assert.doesNotMatch(markup, /执行失败/);
});

test("renderSummaryMarkup escapes finding titles and counts", () => {
  const payload = `<svg onload="alert('xss')">`;
  const { summaryStripMarkup, aiSummaryMarkup } = renderSummaryMarkup({
    report: {
      findings: [
        { severity: "high", title: payload },
        { severity: "medium", title: "normal finding" },
      ],
    },
  });

  assert.equal(summaryStripMarkup.includes(payload), false);
  assert.equal(aiSummaryMarkup.includes(payload), false);
  assert.match(aiSummaryMarkup, /&lt;svg onload=&quot;alert\(&#39;xss&#39;\)&quot;&gt;/);
});

test("renderFindingsMarkup escapes scan findings before innerHTML sinks", () => {
  const payload = `<script>alert('xss')</script>`;
  const markup = renderFindingsMarkup({
    report: {
      findings: [
        {
          findingId: payload,
          title: payload,
          severity: payload,
          summary: payload,
          evidence: payload,
          remediation: payload,
        },
      ],
    },
  });

  assert.equal(markup.includes(payload), false);
  assert.match(markup, /&lt;script&gt;alert\(&#39;xss&#39;\)&lt;\/script&gt;/);
});

test("rendering uses Chinese severity labels in summary and findings", () => {
  const summary = renderSummaryMarkup({
    report: {
      findings: [{ severity: "high", title: "越权访问" }],
    },
  });
  const findingsMarkup = renderFindingsMarkup({
    report: {
      findings: [
        {
          findingId: "finding-001",
          title: "越权访问",
          severity: "high",
          summary: "接口返回了其他用户的数据。",
          evidence: "替换用户编号后仍可成功读取资料。",
          remediation: "对每次读取都执行服务端归属校验。",
        },
      ],
    },
  });

  assert.match(summary.summaryStripMarkup, /高危/);
  assert.doesNotMatch(summary.summaryStripMarkup, /High/);
  assert.match(findingsMarkup, /severity-pill[^>]*>高危</);
  assert.doesNotMatch(findingsMarkup, />high</);
});

test("renderSummaryMarkup handles empty findings without throwing", () => {
  const { summaryStripMarkup, aiSummaryMarkup } = renderSummaryMarkup({
    report: {
      findings: [],
    },
  });

  assert.match(summaryStripMarkup, /<strong>0<\/strong>/);
  assert.match(aiSummaryMarkup, /未发现风险项/);
});

test("renderSummaryMarkup prefers backend summary when available", () => {
  const payload = `<img src=x onerror="alert('xss')">`;
  const { aiSummaryMarkup } = renderSummaryMarkup({
    summary: {
      executiveSummary: payload,
      technicalAnalysis: "tech details",
      recommendations: "fix it",
    },
    report: {
      findings: [{ severity: "medium", title: "fallback finding" }],
    },
  });

  assert.equal(aiSummaryMarkup.includes(payload), false);
  assert.match(aiSummaryMarkup, /tech details/);
  assert.match(aiSummaryMarkup, /fix it/);
  assert.doesNotMatch(aiSummaryMarkup, /fallback finding/);
});

test("index.html exposes a runtime monitor area for transparent Strix execution", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.match(html, /id="runtime-status"/);
  assert.match(html, /id="runtime-log"/);
  assert.match(html, /id="runtime-workbench"/);
  assert.match(html, /id="runtime-empty-state"/);
});

test("app.js polls runtime data and renders it into the runtime monitor", () => {
  const appJs = readFileSync(new URL("../../src/frontend/app.js", import.meta.url), "utf8");

  assert.match(appJs, /\/tasks\/\$\{task\.taskId\}\/runtime/);
  assert.match(appJs, /runtimeStatus:\s*document\.querySelector\("#runtime-status"\)/);
  assert.match(appJs, /runtimeLog:\s*document\.querySelector\("#runtime-log"\)/);
  assert.match(appJs, /runtimeWorkbench:\s*document\.querySelector\("#runtime-workbench"\)/);
  assert.match(appJs, /runtimeEmptyState:\s*document\.querySelector\("#runtime-empty-state"\)/);
  assert.match(appJs, /setInterval\(/);
  assert.match(appJs, /phase_label/);
  assert.match(appJs, /attack_surface/);
  assert.match(appJs, /convergence/);
  assert.match(appJs, /recommended_next_action/);
  assert.match(appJs, /llm_usage/);
});

test("app.js does not let stale runtime refreshes override a newly selected task", () => {
  const appJs = readFileSync(new URL("../../src/frontend/app.js", import.meta.url), "utf8");

  assert.match(appJs, /async function refreshTaskResults\(task\) {[\s\S]*?upsertTask\(refreshedTask\);[\s\S]*?return refreshedTask;/);
  assert.match(appJs, /state\.activeTaskId !== task\.taskId/);
});

test("index.html exposes a cancel control for long-running real scans", () => {
  const html = readFileSync(new URL("../../src/frontend/index.html", import.meta.url), "utf8");

  assert.match(html, /id="cancel-task"/);
});

test("renderRuntimeWorkbenchMarkup renders runtime phase, attack surface, convergence and next action", () => {
  const markup = renderRuntimeWorkbenchMarkup({
    phaseLabel: "攻击面分析",
    failureClassificationLabel: "已识别攻击面，但尚未验证",
    attackSurface: {
      pages: 6,
      forms: 2,
      parameters: 9,
      apiEndpoints: 3,
      authPoints: 1,
      uploadPoints: 0,
    },
    llmUsage: {
      requests: 39,
      totalTokens: 1712579,
    },
    convergence: {
      statusLabel: "已发现攻击面，但尚未形成可验证漏洞",
      scoreText: "0.58",
      idleRounds: 4,
    },
    recommendedNextAction: "建议收缩到表单与查询参数验证，优先复现单个高置信问题。",
  });

  assert.match(markup, /当前阶段/);
  assert.match(markup, /攻击面分析/);
  assert.match(markup, /攻击面概览/);
  assert.match(markup, /页面/);
  assert.match(markup, />6</);
  assert.match(markup, /表单/);
  assert.match(markup, /收敛诊断/);
  assert.match(markup, /LLM 请求/);
  assert.match(markup, /1712579/);
  assert.match(markup, /下一步建议/);
  assert.match(markup, /建议收缩到表单与查询参数验证/);
});

test("renderRuntimeWorkbenchMarkup renders fixture empty-state copy without pretending to be a real scan", () => {
  const markup = renderRuntimeWorkbenchMarkup(null, {
    emptyTitle: "演示样例模式",
    emptyBody: "当前任务没有真实 Strix 运行态，执行轨迹区仅在真实扫描任务中展示阶段、攻击面和收敛诊断。",
  });

  assert.match(markup, /演示样例模式/);
  assert.match(markup, /当前任务没有真实 Strix 运行态/);
  assert.doesNotMatch(markup, /攻击面概览<\/h4>/);
});
