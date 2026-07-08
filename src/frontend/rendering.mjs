const defaultSeverityOrder = ["critical", "high", "medium", "low", "info"];

const severityDisplayMap = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

const sourceDisplayMap = {
  latest_real_run: "最新真实运行",
  fixture: "演示样例",
};

const statusDisplayMap = {
  completed: "已完成",
  demo_fixture_loaded: "演示结果",
  created: "已创建",
  running: "执行中",
  failed: "执行失败",
};

function resolveTaskStatusLabel(task) {
  if (task?.status === "failed" && (task?.report?.findings?.length ?? 0) > 0) {
    return "已完成";
  }

  return statusDisplayMap[task?.status] ?? task?.status ?? "未知状态";
}

const runtimeSurfaceMetrics = [
  { key: "pages", label: "页面" },
  { key: "forms", label: "表单" },
  { key: "parameters", label: "参数" },
  { key: "apiEndpoints", label: "接口" },
  { key: "authPoints", label: "认证点" },
  { key: "uploadPoints", label: "上传点" },
];

const htmlEscapeMap = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

export function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => htmlEscapeMap[character]);
}

export function summarizeFindings(findings, severityOrder = defaultSeverityOrder) {
  const counts = severityOrder.reduce((accumulator, severity) => {
    accumulator[severity] = 0;
    return accumulator;
  }, {});

  findings.forEach((finding) => {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  });

  return counts;
}

export function renderTaskListMarkup(tasks, activeTaskId) {
  return tasks
    .map((task) => {
      const isActive = task.taskId === activeTaskId;
      const sourceLabel = sourceDisplayMap[task.resultSource] ?? "本地任务";
      const statusLabel = resolveTaskStatusLabel(task);

      return `
        <article class="task-lane ${isActive ? "task-lane--active" : ""}" data-task-id="${escapeHTML(task.taskId)}">
          <div class="task-lane__pulse" aria-hidden="true"></div>
          <div class="task-lane__main">
            <div class="task-lane__header">
              <p class="micro-label">${escapeHTML(task.taskId)}</p>
              <span class="task-lane__source">${escapeHTML(sourceLabel)}</span>
            </div>
            <h3>${escapeHTML(task.name)}</h3>
            <p>${escapeHTML(task.target)}</p>
          </div>
          <div class="task-lane__state">
            <span>模式 ${escapeHTML(task.scanMode)}</span>
            <strong>${escapeHTML(statusLabel)}</strong>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderBackendSummary(task) {
  return `
    <p>${escapeHTML(task.summary.executiveSummary)}</p>
    <p><strong>技术分析：</strong>${escapeHTML(task.summary.technicalAnalysis ?? "")}</p>
    <p><strong>修复建议：</strong>${escapeHTML(task.summary.recommendations ?? "")}</p>
  `;
}

function renderFallbackSummary(task, counts, topFinding) {
  if (!topFinding) {
    return "<p>未发现风险项。</p>";
  }

  return `
    <p>共发现 <strong>${escapeHTML(String(task.report.findings.length))}</strong> 条风险。</p>
    <p><strong>首要问题：</strong>${escapeHTML(topFinding.title)}</p>
    <p><strong>级别分布：</strong>${escapeHTML(severityDisplayMap.critical)} ${escapeHTML(String(counts.critical))}，${escapeHTML(severityDisplayMap.high)} ${escapeHTML(String(counts.high))}，${escapeHTML(severityDisplayMap.medium)} ${escapeHTML(String(counts.medium))}</p>
  `;
}

export function renderSummaryMarkup(task, severityOrder = defaultSeverityOrder) {
  const counts = summarizeFindings(task.report.findings, severityOrder);
  const topFinding = task.report.findings[0];
  const aiSummaryMarkup = task.summary?.executiveSummary
    ? renderBackendSummary(task)
    : renderFallbackSummary(task, counts, topFinding);

  return {
    summaryStripMarkup: severityOrder
      .map(
        (severity) => `
          <article class="summary-meter summary-meter--${escapeHTML(severity)}">
            <span class="micro-label">${escapeHTML(severityDisplayMap[severity] ?? severity)}</span>
            <strong>${escapeHTML(String(counts[severity]))}</strong>
            <p>${escapeHTML(severityDisplayMap[severity] ?? severity)}</p>
          </article>
        `,
      )
      .join(""),
    aiSummaryMarkup,
  };
}

export function renderFindingsMarkup(task) {
  if (task.report.findings.length === 0) {
    return `
      <article class="finding-entry finding-entry--empty">
        未发现风险项。
      </article>
    `;
  }

  return task.report.findings
    .map(
      (finding) => `
        <article class="finding-entry">
          <header class="finding-entry__header">
            <div class="finding-entry__title">
              <p class="micro-label">${escapeHTML(finding.findingId)}</p>
              <h3>${escapeHTML(finding.title)}</h3>
            </div>
            <span class="severity-pill severity-pill--${escapeHTML(finding.severity)}">${escapeHTML(severityDisplayMap[finding.severity] ?? finding.severity)}</span>
          </header>
          <div class="finding-entry__facets">
            <div class="finding-entry__facet">
              <span>摘要</span>
              <p>${escapeHTML(finding.summary)}</p>
            </div>
            <div class="finding-entry__facet">
              <span>证据</span>
              <p>${escapeHTML(finding.evidence)}</p>
            </div>
            <div class="finding-entry__facet">
              <span>修复建议</span>
              <p>${escapeHTML(finding.remediation)}</p>
            </div>
          </div>
        </article>
      `,
    )
    .join("");
}

function renderRuntimeMetric(label, value) {
  return `
    <article class="runtime-metric">
      <span>${escapeHTML(label)}</span>
      <strong>${escapeHTML(String(value ?? 0))}</strong>
    </article>
  `;
}

export function renderRuntimeWorkbenchMarkup(runtime, options = {}) {
  if (!runtime) {
    return `
      <article class="runtime-empty-state">
        <h4>${escapeHTML(options.emptyTitle ?? "运行信息不可用")}</h4>
        <p>${escapeHTML(options.emptyBody ?? "当前没有可展示的结构化运行态信息。")}</p>
      </article>
    `;
  }

  const surface = runtime.attackSurface ?? {};
  const llmUsage = runtime.llmUsage ?? {};
  const convergence = runtime.convergence ?? {};

  return `
    <div class="runtime-workbench">
      <section class="runtime-group">
        <div class="runtime-group__header">
          <h4>当前阶段</h4>
        </div>
        <div class="runtime-phase">
          <strong>${escapeHTML(runtime.phaseLabel ?? "运行信息不可用")}</strong>
          <p>${escapeHTML(runtime.failureClassificationLabel ?? "当前未触发额外失败分类。")}</p>
        </div>
      </section>

      <section class="runtime-group">
        <div class="runtime-group__header">
          <h4>攻击面概览</h4>
        </div>
        <div class="runtime-metrics">
          ${runtimeSurfaceMetrics
            .map((metric) => renderRuntimeMetric(metric.label, surface[metric.key]))
            .join("")}
        </div>
      </section>

      <section class="runtime-group">
        <div class="runtime-group__header">
          <h4>收敛诊断</h4>
        </div>
        <div class="runtime-diagnosis">
          <div class="runtime-diagnosis__grid">
            ${renderRuntimeMetric("LLM 请求", llmUsage.requests)}
            ${renderRuntimeMetric("累计 Token", llmUsage.totalTokens)}
            ${renderRuntimeMetric("收敛评分", convergence.scoreText ?? "-")}
            ${renderRuntimeMetric("空转轮次", convergence.idleRounds ?? 0)}
          </div>
          <div class="runtime-diagnosis__summary">
            <p><strong>当前判断：</strong>${escapeHTML(convergence.statusLabel ?? "暂无收敛判断")}</p>
            <p><strong>下一步建议：</strong>${escapeHTML(runtime.recommendedNextAction ?? "建议继续观察真实扫描进展。")}</p>
          </div>
        </div>
      </section>
    </div>
  `;
}
