import test from "node:test";
import assert from "node:assert/strict";

import {
  buildExportFileName,
  buildLocalExportPayload,
  buildRunningTaskFromTask,
  buildFailedTaskFromError,
  createTaskFromApiPayload,
} from "../../src/frontend/taskData.mjs";

test("createTaskFromApiPayload keeps backend summary fields", () => {
  const task = createTaskFromApiPayload({
    task: {
      task_id: "task-001",
      name: "demo",
      target: "https://authorized-lab.example",
      scan_mode: "quick",
      instruction: "authorized only",
      status: "completed",
      result_source: "latest_real_run",
      scan_timeout_seconds: 600,
      started_at: "2026-07-16T08:00:00+00:00",
    },
    report: {
      task_id: "task-001",
      target: "https://authorized-lab.example",
      findings: [],
    },
    summary: {
      executive_summary: "summary text",
      technical_analysis: "analysis text",
      recommendations: "recommendation text",
    },
  });

  assert.deepEqual(task.summary, {
    executiveSummary: "summary text",
    technicalAnalysis: "analysis text",
    recommendations: "recommendation text",
  });
  assert.equal(task.resultSource, "latest_real_run");
  assert.equal(task.scanTimeoutSeconds, 600);
  assert.equal(task.startedAt, "2026-07-16T08:00:00+00:00");
});

test("createTaskFromApiPayload preserves candidate verification metadata and counts", () => {
  const task = createTaskFromApiPayload({
    task: {
      task_id: "task-010",
      name: "partial scan",
      target: "http://authorized-lab.example",
      scan_mode: "standard",
      result_source: "latest_real_run",
      instruction: "report first",
      status: "partial",
    },
    summary: {},
    report: {
      task_id: "task-010",
      target: "http://authorized-lab.example",
      confirmed_count: 0,
      candidate_count: 1,
      findings: [{
        finding_id: "note-1",
        title: "Candidate evidence",
        severity: "info",
        summary: "summary",
        evidence: "safe evidence",
        remediation: "verify",
        verification_status: "candidate",
        source: "strix_note",
      }],
    },
  });

  assert.equal(task.status, "partial");
  assert.equal(task.report.confirmedCount, 0);
  assert.equal(task.report.candidateCount, 1);
  assert.equal(task.report.findings[0].verificationStatus, "candidate");
  assert.equal(task.report.findings[0].source, "strix_note");
});

test("createTaskFromApiPayload localizes english finding fields from API payload", () => {
  const task = createTaskFromApiPayload({
    task: {
      task_id: "task-002",
      name: "upload scan",
      target: "http://host.docker.internal/4.8/upload2.php",
      scan_mode: "deep",
      instruction: "authorized only",
      status: "completed",
      result_source: "latest_real_run",
      scan_timeout_seconds: 600,
    },
    report: {
      task_id: "task-002",
      target: "http://host.docker.internal/4.8/upload2.php",
      findings: [
        {
          finding_id: "vuln-0001",
          title: "Unrestricted File Upload Leading to Remote Code Execution via .htaccess Bypass",
          severity: "critical",
          summary:
            "The file upload functionality in upload2.php only blocks files with the exact .php extension.",
          evidence:
            "The upload2.php script processes file uploads by extracting the file extension using PHP's pathinfo() function.",
          remediation:
            "Implement a whitelist of allowed file extensions instead of a blacklist.",
        },
      ],
    },
    summary: {
      executive_summary: "summary text",
      technical_analysis: "analysis text",
      recommendations: "recommendation text",
    },
  });

  assert.doesNotMatch(task.report.findings[0].title, /Unrestricted File Upload|Remote Code Execution|Bypass/);
  assert.match(task.report.findings[0].title, /任意文件上传|远程代码执行/);
  assert.doesNotMatch(task.report.findings[0].summary, /only blocks files|exact \.php extension/);
  assert.match(task.report.findings[0].evidence, /提取上传文件扩展名|决定是否放行/);
  assert.doesNotMatch(task.report.findings[0].remediation, /Implement a whitelist/);
});

test("buildExportFileName creates a stable markdown filename", () => {
  const fileName = buildExportFileName({
    taskId: "task-007",
    name: "Demo Scan Report",
  });

  assert.equal(fileName, "task-007-demo-scan-report.md");
});

test("buildLocalExportPayload returns markdown content for demo tasks", () => {
  const exported = buildLocalExportPayload({
    taskId: "task-001",
    name: "Local Demo",
    target: "https://authorized-lab.example",
    scanMode: "quick",
    resultSource: "fixture",
    status: "demo_fixture_loaded",
    summary: {
      executiveSummary: "summary text",
      technicalAnalysis: "analysis text",
      recommendations: "recommendation text",
    },
    report: {
      findings: [
        {
          findingId: "finding-1",
          title: "Demo Finding",
          severity: "medium",
          summary: "summary",
          evidence: "evidence",
          remediation: "remediation",
        },
      ],
    },
  });

  assert.equal(exported.format, "markdown");
  assert.match(exported.content, /# 扫描报告/);
  assert.match(exported.content, /## 任务信息/);
  assert.match(exported.content, /### 技术分析/);
  assert.match(exported.content, /### 修复建议/);
  assert.match(exported.content, /## 风险详情/);
  assert.match(exported.content, /Demo Finding/);
  assert.doesNotMatch(exported.content, /# Scan Report|Technical Analysis|Recommendations|No findings/);
});

test("buildFailedTaskFromError clears stale results and marks the task as failed", () => {
  const failedTask = buildFailedTaskFromError(
    {
      taskId: "task-003",
      name: "real scan",
      target: "./src/frontend",
      scanMode: "quick",
      resultSource: "latest_real_run",
      instruction: "demo",
      status: "completed",
      summary: {
        executiveSummary: "old summary",
        technicalAnalysis: "old analysis",
        recommendations: "old recommendations",
      },
      report: {
        taskId: "task-003",
        target: "./src/frontend",
        findings: [
          {
            findingId: "finding-001",
            title: "old finding",
            severity: "medium",
            summary: "old summary",
            evidence: "old evidence",
            remediation: "old remediation",
          },
        ],
      },
    },
    "Strix scan failed: exit code 1",
  );

  assert.equal(failedTask.status, "failed");
  assert.equal(failedTask.report.findings.length, 0);
  assert.match(failedTask.summary.executiveSummary, /Strix scan failed: exit code 1/);
  assert.doesNotMatch(failedTask.summary.executiveSummary, /old summary/);
  assert.equal(failedTask.resultSource, "latest_real_run");
  assert.equal(failedTask.target, "./src/frontend");
});

test("buildRunningTaskFromTask marks a task as running and preserves the requested target", () => {
  const runningTask = buildRunningTaskFromTask({
    taskId: "task-004",
    name: "blackbox scan",
    target: "http://localhost:8888",
    scanMode: "standard",
    scanTimeoutSeconds: 300,
    resultSource: "latest_real_run",
    instruction: "",
    status: "created",
    summary: {
      executiveSummary: "placeholder",
      technicalAnalysis: "placeholder",
      recommendations: "placeholder",
    },
    report: {
      taskId: "task-004",
      target: "http://localhost:8888",
      findings: [],
    },
  });

  assert.equal(runningTask.status, "running");
  assert.equal(runningTask.target, "http://localhost:8888");
  assert.equal(runningTask.scanTimeoutSeconds, 300);
  assert.match(runningTask.summary.executiveSummary, /正在执行真实 Strix 扫描/);
});

test("buildFailedTaskFromError explains browser tool mismatch failures more accurately", () => {
  const failedTask = buildFailedTaskFromError(
    {
      taskId: "task-005",
      name: "blackbox scan",
      target: "http://localhost:8888",
      scanMode: "standard",
      resultSource: "latest_real_run",
      instruction: "",
      status: "running",
      summary: {
        executiveSummary: "running",
        technicalAnalysis: "running",
        recommendations: "running",
      },
      report: {
        taskId: "task-005",
        target: "http://localhost:8888",
        findings: [],
      },
    },
    "Strix scan failed: browser tool mismatch: Tool agent-browser open not found in agent strix",
  );

  assert.match(failedTask.summary.technicalAnalysis, /浏览器工具/);
  assert.match(failedTask.summary.recommendations, /切换模型|浏览器工具|黑盒/);
  assert.doesNotMatch(failedTask.summary.recommendations, /Docker daemon/);
});
