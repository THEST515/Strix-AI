import { fixtureReport } from "./fixtureData.js";

const severityLabelMap = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};

const statusLabelMap = {
  completed: "已完成",
  demo_fixture_loaded: "演示结果",
  created: "已创建",
  running: "执行中",
  failed: "执行失败",
};

const scanModeLabelMap = {
  quick: "快速",
  standard: "标准",
  deep: "深度",
};

const summaryReplacements = [
  ["# Executive Summary", "# 执行摘要"],
  ["## Executive Summary", "## 执行摘要"],
  ["# Methodology", "# 评估方法"],
  ["## Methodology", "## 评估方法"],
  ["# Technical Analysis", "# 技术分析"],
  ["## Technical Analysis", "## 技术分析"],
  ["# Recommendations", "# 修复建议"],
  ["## Recommendations", "## 修复建议"],
  ["### Codebase Architecture", "### 代码结构"],
  ["### Security Control Review", "### 安全控制审查"],
  ["### Tool Results Summary", "### 工具结果汇总"],
  ["### Conclusion", "### 结论"],
  ["### Immediate (Low Effort, Medium Impact)", "### 立即可做（低成本，中等收益）"],
  ["### Short-term (Medium Effort, Low Impact)", "### 短期优化（中等成本，较低风险）"],
  ["### Not Required", "### 暂不需要"],
  ["**Overall Risk Level: Low**", "**总体风险等级：低**"],
  ["No actively exploitable security vulnerabilities were identified.", "未发现可直接利用的安全漏洞。"],
  ["No findings.", "未发现风险项。"],
  ["Demo/Fixture mode (default)", "演示样例模式（默认）"],
  ["Live API mode", "实时接口模式"],
  ["Hardening Recommendations", "加固建议"],
  ["Key strengths observed:", "主要优点："],
  ["The application is free from actively exploitable security vulnerabilities.", "当前应用未发现可直接利用的安全漏洞。"],
  ["The primary recommendations are hardening improvements rather than vulnerability fixes.", "当前建议以加固优化为主，而不是漏洞修复。"],
  ["Add a Content Security Policy meta tag", "添加内容安全策略（CSP）元标签"],
  ["Add client-side input validation for the target URL field", "为目标地址输入框增加前端校验"],
  ["Same-origin API interaction only", "仅进行同源 API 调用"],
  ["Zero dependency footprint", "无额外第三方依赖"],
  ["Cross-Site Request Forgery", "跨站请求伪造"],
  ["Server-Side Request Forgery", "服务端请求伪造"],
  ["XML External Entity", "XML 外部实体"],
  ["XXE", "XXE"],
  ["Server-Side Template Injection", "服务端模板注入"],
  ["SSTI", "SSTI"],
  ["Open Redirect", "开放重定向"],
  ["Local File Inclusion", "本地文件包含"],
  ["LFI", "LFI"],
  ["Remote File Inclusion", "远程文件包含"],
  ["RFI", "RFI"],
  ["Insecure Deserialization", "不安全的反序列化"],
  ["Sensitive Information Exposure", "敏感信息泄露"],
  ["Default Credentials", "默认凭据"],
  ["Weak Password Policy", "弱密码策略"],
  ["Security Misconfiguration", "安全配置不当"],
  ["Clickjacking", "点击劫持"],
  ["Arbitrary File Upload", "任意文件上传"],
  ["Enable CSRF validation", "启用 CSRF 校验"],
  ["disable XXE resolution", "禁用 XXE 解析"],
  ["block open redirect sinks", "阻断开放重定向路径"],
];

const findingReplacements = [
  ["Unrestricted File Upload Leading to Remote Code Execution via .htaccess Bypass", "任意文件上传导致远程代码执行（通过 .htaccess 绕过）"],
  ["Unrestricted File Upload Leading to Remote Code Execution", "任意文件上传导致远程代码执行"],
  ["Unrestricted File Upload", "任意文件上传"],
  ["Remote Code Execution", "远程代码执行"],
  [".htaccess Bypass", ".htaccess 绕过"],
  ["Missing Authentication", "缺少身份认证"],
  ["Missing Authorization", "缺少权限校验"],
  ["Broken Access Control", "访问控制失效"],
  ["Insecure Direct Object Reference", "不安全的直接对象引用"],
  ["The file upload functionality in upload2.php only blocks files with the exact .php extension.", "upload2.php 的文件上传功能只拦截完全等于 .php 的扩展名。"],
  ["The upload2.php script processes file uploads by extracting the file extension using PHP's pathinfo() function.", "upload2.php 会先用 PHP 的 pathinfo() 函数提取上传文件扩展名，再决定是否放行。"],
  ["Implement a whitelist of allowed file extensions instead of a blacklist.", "使用允许名单校验可上传扩展名，不要继续使用黑名单。"],
  ["The file upload functionality", "该文件上传功能"],
  ["only blocks files", "只拦截文件"],
  ["exact .php extension", "完全等于 .php 的扩展名"],
  ["case-insensitive comparison", "大小写不敏感比较"],
  ["This filter is trivially bypassed", "这一过滤逻辑很容易被绕过"],
  ["uploading a .htaccess file", "上传一个 .htaccess 文件"],
  ["configure Apache", "修改 Apache 行为"],
  ["execute arbitrary file types as PHP", "把任意文件类型当作 PHP 执行"],
  ["then uploading .txt files containing PHP code", "然后再上传包含 PHP 代码的 .txt 文件"],
  ["The server runs Apache", "服务器运行环境为 Apache"],
  ["processes file uploads", "处理文件上传"],
  ["extracting the file extension", "提取文件扩展名"],
  ["using PHP's pathinfo() function", "使用 PHP 的 pathinfo() 函数"],
  ["comparing it against the string \"php\"", "并与字符串 \"php\" 做比较"],
  ["If the extension is not exactly \"php\"", "如果扩展名并不严格等于 \"php\""],
  ["the file is moved to the upload/ directory without any further validation", "文件就会被直接移动到 upload/ 目录，且没有后续校验"],
  ["Key weaknesses:", "关键薄弱点："],
  ["The extension filter is a blacklist", "扩展名过滤是黑名单逻辑"],
  ["Hidden files starting with a dot", "以点开头的隐藏文件"],
  ["There is no MIME-type validation, content inspection, or file signature verification.", "没有 MIME 类型校验、内容检查或文件签名验证。"],
  ["Attack chain:", "攻击链路："],
  ["Implement a whitelist of allowed file extensions", "实现允许名单扩展名校验"],
  ["Verify file content matches the expected type", "校验文件内容是否符合预期类型"],
  ["Rename uploaded files", "重命名上传文件"],
  ["Store uploaded files outside the web root", "将上传文件存放到 Web 根目录之外"],
  ["Disable .htaccess overrides", "禁用 .htaccess 覆写能力"],
  ["Prevent upload of hidden files", "阻止上传隐藏文件"],
];

function slugify(value) {
  return (
    String(value ?? "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "report"
  );
}

function replaceAllPairs(value, replacements) {
  return replacements.reduce(
    (result, [source, target]) => result.replaceAll(source, target),
    String(value ?? ""),
  );
}

function localizeSummaryText(value) {
  return replaceAllPairs(value, summaryReplacements);
}

function normalizeSummary(summary = {}) {
  return {
    executiveSummary: localizeSummaryText(summary.executiveSummary ?? summary.executive_summary ?? ""),
    technicalAnalysis: localizeSummaryText(summary.technicalAnalysis ?? summary.technical_analysis ?? ""),
    recommendations: localizeSummaryText(summary.recommendations ?? ""),
  };
}

function localizeFindingText(value) {
  return replaceAllPairs(value, findingReplacements);
}

function normalizeFinding(finding) {
  return {
    findingId: finding.finding_id ?? finding.findingId,
    title: localizeFindingText(finding.title),
    severity: finding.severity,
    summary: localizeFindingText(finding.summary),
    evidence: localizeFindingText(finding.evidence),
    remediation: localizeFindingText(finding.remediation),
  };
}

function buildFailureCopy(message) {
  if (message.includes("browser tool mismatch")) {
    return {
      technicalAnalysis:
        "本次黑盒扫描已成功触发，但 Strix 在浏览器交互阶段调用了当前运行环境中不可用的浏览器工具，因此未生成有效扫描结果。",
      recommendations:
        "请优先修复 Strix 黑盒浏览器工具链兼容性，或切换到与当前 Strix 版本兼容的模型后再重试；这不是目标地址本身导致的失败。",
    };
  }

  return {
    technicalAnalysis:
      "未获得本次有效扫描结果，已清空上一次的风险展示，避免误认为当前运行已完成。",
    recommendations:
      "请检查 Docker daemon、Strix 运行环境和相关密钥配置，确认后再次触发真实扫描。",
  };
}

function buildMarkdownContent(task) {
  const summary = normalizeSummary(task.summary);
  const findings = task.report.findings ?? [];
  const severityCounts = findings.reduce(
    (counts, finding) => {
      counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );

  const lines = [
    "# 扫描报告",
    "",
    "## 任务信息",
    `- 任务编号：${task.taskId}`,
    `- 任务名称：${task.name}`,
    `- 目标地址：${task.target}`,
    `- 扫描模式：${scanModeLabelMap[task.scanMode] ?? task.scanMode}`,
    `- 当前状态：${statusLabelMap[task.status] ?? task.status}`,
    "",
    "## 摘要",
    summary.executiveSummary,
    "",
    "### 技术分析",
    summary.technicalAnalysis,
    "",
    "### 修复建议",
    summary.recommendations,
    "",
    "## 风险级别统计",
    `- 严重：${severityCounts.critical}`,
    `- 高危：${severityCounts.high}`,
    `- 中危：${severityCounts.medium}`,
    `- 低危：${severityCounts.low}`,
    `- 提示：${severityCounts.info}`,
    "",
    "## 风险详情",
  ];

  if (findings.length === 0) {
    lines.push("- 未发现风险项。");
  } else {
    findings.forEach((finding) => {
      lines.push(
        "",
        `### ${finding.title}`,
        `- 编号：${finding.findingId}`,
        `- 级别：${severityLabelMap[finding.severity] ?? finding.severity}`,
        `- 摘要：${finding.summary}`,
        `- 证据：${finding.evidence}`,
        `- 修复建议：${finding.remediation}`,
      );
    });
  }

  return lines.join("\n");
}

export function buildDemoTask(formData, taskCount) {
  const demoTaskId = `task-${String(taskCount + 1).padStart(3, "0")}`;

  return {
    taskId: demoTaskId,
    name: formData.get("taskName").trim(),
    target: formData.get("target").trim(),
    scanMode: formData.get("scanMode"),
    resultSource: formData.get("resultSource") || "fixture",
    instruction: formData.get("instruction").trim(),
    status: "demo_fixture_loaded",
    summary: {
      executiveSummary: "当前处于本地演示模式，结果来自固定演示样例数据。",
      technicalAnalysis: "适合用于课程录屏时展示任务切换、摘要生成、证据阅读与报告导出。",
      recommendations: "如需展示真实扫描链路，可切换到真实 Strix 扫描并显式触发运行。",
    },
    report: {
      ...fixtureReport,
      taskId: demoTaskId,
      target: formData.get("target").trim(),
    },
  };
}

export function createTaskFromApiPayload(payload) {
  return {
    taskId: payload.task.task_id,
    name: payload.task.name,
    target: payload.task.target,
    scanMode: payload.task.scan_mode,
    scanTimeoutSeconds: payload.task.scan_timeout_seconds,
    resultSource: payload.task.result_source ?? "fixture",
    instruction: payload.task.instruction,
    status: payload.task.status,
    summary: normalizeSummary(payload.summary),
    report: {
      taskId: payload.report.task_id,
      target: payload.report.target,
      findings: payload.report.findings.map((finding) => normalizeFinding(finding)),
    },
  };
}

export function buildRunningTaskFromTask(task) {
  return {
    ...task,
    status: "running",
    summary: {
      executiveSummary: "正在执行真实 Strix 扫描，请等待本次黑盒审查完成。",
      technicalAnalysis: "当前任务已提交到真实扫描链路，页面将在返回结果后刷新摘要与风险列表。",
      recommendations: "执行期间请勿重复点击“启动真实 Strix 扫描”，避免并发创建多份运行目录。",
    },
    report: {
      taskId: task.taskId,
      target: task.target,
      findings: [],
    },
  };
}

export function buildFailedTaskFromError(task, errorMessage) {
  const message = String(errorMessage ?? "unknown error");
  const failureCopy = buildFailureCopy(message);

  return {
    ...task,
    status: "failed",
    summary: {
      executiveSummary: `本次任务执行失败：${message}`,
      technicalAnalysis: failureCopy.technicalAnalysis,
      recommendations: failureCopy.recommendations,
    },
    report: {
      taskId: task.taskId,
      target: task.target,
      findings: [],
    },
  };
}

export function buildExportFileName(task) {
  return `${task.taskId}-${slugify(task.name)}.md`;
}

export function buildLocalExportPayload(task) {
  return {
    format: "markdown",
    content: buildMarkdownContent(task),
  };
}
