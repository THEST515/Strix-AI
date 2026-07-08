import {
  renderFindingsMarkup,
  renderRuntimeWorkbenchMarkup,
  renderSummaryMarkup,
  renderTaskListMarkup,
} from "./rendering.mjs";
import {
  buildDemoTask,
  buildExportFileName,
  buildRunningTaskFromTask,
  buildFailedTaskFromError,
  buildLocalExportPayload,
  createTaskFromApiPayload,
} from "./taskData.mjs";

const apiBaseUrl = window.location.protocol.startsWith("http")
  ? `${window.location.origin}/api`
  : null;

const state = {
  tasks: [],
  activeTaskId: null,
  isRunPending: false,
  runtime: null,
  runtimePollHandle: null,
};

const elements = {
  form: document.querySelector("#task-form"),
  feedback: document.querySelector("#form-feedback"),
  taskList: document.querySelector("#task-list"),
  summaryStrip: document.querySelector("#summary-strip"),
  aiSummary: document.querySelector("#ai-summary"),
  findingsList: document.querySelector("#findings-list"),
  reportTaskName: document.querySelector("#report-task-name"),
  reportTarget: document.querySelector("#report-target"),
  reportSource: document.querySelector("#report-source"),
  runtimeStatus: document.querySelector("#runtime-status"),
  runtimeWorkbench: document.querySelector("#runtime-workbench"),
  runtimeEmptyState: document.querySelector("#runtime-empty-state"),
  runtimeLog: document.querySelector("#runtime-log"),
  runButton: document.querySelector("#run-task"),
  cancelButton: document.querySelector("#cancel-task"),
  exportButton: document.querySelector("#export-report"),
  exportKind: document.querySelector("#export-kind"),
};

async function requestJson(path, options = {}) {
  if (!apiBaseUrl) {
    throw new Error("接口暂不可用");
  }

  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
    ...options,
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.error ?? `请求失败，状态码 ${response.status}`);
  }

  return response.json();
}

async function createTaskViaApi(formData) {
  const payload = {
    name: String(formData.get("taskName") ?? "").trim(),
    target: String(formData.get("target") ?? "").trim(),
    scanMode: String(formData.get("scanMode") ?? "quick"),
    scanTimeoutSeconds: Number(String(formData.get("scanTimeoutSeconds") ?? "300")),
    resultSource: String(formData.get("resultSource") ?? "fixture"),
    instruction: String(formData.get("instruction") ?? "").trim(),
  };

  const created = await requestJson("/tasks", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  return createTaskFromApiPayload(created);
}

async function loadTasksFromApi() {
  const listing = await requestJson("/tasks");
  const tasks = await Promise.all(
    listing.tasks.map(async (task) => {
      const results = await requestJson(`/tasks/${task.task_id}/results`);
      return createTaskFromApiPayload(results);
    }),
  );

  state.tasks = tasks;
  state.activeTaskId = tasks[0]?.taskId ?? null;
  renderAll();
}

async function exportTaskViaApi(task) {
  return requestJson(`/tasks/${task.taskId}/export`);
}

async function exportBinary(path) {
  if (!apiBaseUrl) {
    throw new Error("接口暂不可用");
  }

  const response = await fetch(`${apiBaseUrl}${path}`);
  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.error ?? `请求失败，状态码 ${response.status}`);
  }

  return response.blob();
}

async function runTaskViaApi(task) {
  const rerun = await requestJson(`/tasks/${task.taskId}/run`, {
    method: "POST",
    body: "{}",
  });

  return createTaskFromApiPayload(rerun);
}

async function cancelTaskViaApi(task) {
  const cancelled = await requestJson(`/tasks/${task.taskId}/cancel`, {
    method: "POST",
    body: "{}",
  });

  return createTaskFromApiPayload(cancelled);
}

async function loadTaskRuntimeViaApi(task) {
  return requestJson(`/tasks/${task.taskId}/runtime`);
}

function triggerTextDownload(fileName, content) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  triggerBlobDownload(fileName, blob);
}

function triggerBlobDownload(fileName, blob) {
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = fileName;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

function resolveExportSelection(task) {
  const exportKind = elements.exportKind?.value ?? "markdown-current";
  if (exportKind === "docx-current") {
    return {
      format: "docx",
      scope: "current",
      fileName: `${task.taskId}.docx`,
    };
  }

  if (exportKind === "docx-all") {
    return {
      format: "docx",
      scope: "all",
      fileName: "merged-security-report.docx",
    };
  }

  return {
    format: "markdown",
    scope: "current",
    fileName: buildExportFileName(task),
  };
}

function upsertTask(nextTask) {
  const existingIndex = state.tasks.findIndex((task) => task.taskId === nextTask.taskId);
  if (existingIndex >= 0) {
    state.tasks.splice(existingIndex, 1, nextTask);
    return;
  }

  state.tasks.unshift(nextTask);
}

function sourceLabelForTask(task) {
  const mapping = {
    latest_real_run: "最新真实运行",
    fixture: "演示样例",
  };

  return mapping[task.resultSource] ?? task.status;
}

function missionToneForTask(task) {
  return task?.resultSource === "latest_real_run" ? "live" : "idle";
}

function runActionLabelForTask(task) {
  if (task?.status === "running") {
    return "真实扫描执行中";
  }

  return task?.resultSource === "latest_real_run" ? "启动真实 Strix 扫描" : "重新载入任务";
}

function failureClassificationLabel(value) {
  const mapping = {
    cancelled: "本次扫描已被用户终止。",
    validated_findings: "已形成可验证漏洞证据。",
    completed_without_findings: "本轮扫描已结束，但未形成漏洞结果。",
    environment_failed: "运行环境或模型额度异常导致扫描失败。",
    timeout_unconverged: "扫描超时，尚未收敛到可导出漏洞证据。",
    evidence_in_progress: "已进入证据整理阶段，但扫描未完整收口。",
    surface_found_but_unverified: "已识别攻击面，但尚未验证成漏洞。",
    no_surface_found: "已调用模型，但尚未识别到足够攻击面。",
  };

  return mapping[value] ?? null;
}

function convergenceStatusLabel(value) {
  const mapping = {
    validated_findings: "已形成可验证漏洞证据",
    completed_without_findings: "扫描完成，但未发现漏洞",
    no_surface_found: "尚未识别到有效攻击面",
    surface_found_but_unverified: "已发现攻击面，但尚未形成可验证漏洞",
    recon_in_progress: "仍处于侦察阶段，正在继续摸底",
    not_started: "尚未启动真实扫描",
  };

  return mapping[value] ?? value ?? "暂无收敛判断";
}

function normalizeRuntimePayload(runtime) {
  return {
    phase: runtime.phase,
    phaseLabel: runtime.phase_label ?? "运行信息不可用",
    runId: runtime.run_id ?? null,
    runStatus: runtime.run_status ?? null,
    target: runtime.target ?? null,
    startedAt: runtime.started_at ?? null,
    completedAt: runtime.completed_at ?? null,
    logTail: runtime.log_tail ?? "",
    attackSurface: {
      pages: runtime.attack_surface?.pages ?? 0,
      forms: runtime.attack_surface?.forms ?? 0,
      parameters: runtime.attack_surface?.parameters ?? 0,
      apiEndpoints: runtime.attack_surface?.api_endpoints ?? 0,
      authPoints: runtime.attack_surface?.auth_points ?? 0,
      uploadPoints: runtime.attack_surface?.upload_points ?? 0,
    },
    llmUsage: {
      requests: runtime.llm_usage?.requests ?? 0,
      totalTokens: runtime.llm_usage?.total_tokens ?? 0,
    },
    convergence: {
      status: runtime.convergence?.status ?? null,
      statusLabel: convergenceStatusLabel(runtime.convergence?.status),
      score: runtime.convergence?.score ?? null,
      scoreText: runtime.convergence?.score == null ? "-" : String(runtime.convergence.score),
      idleRounds: runtime.convergence?.idle_rounds ?? 0,
      lastMeaningfulEventAt: runtime.convergence?.last_meaningful_event_at ?? null,
    },
    failureClassification: runtime.failure_classification ?? null,
    failureClassificationLabel: failureClassificationLabel(runtime.failure_classification),
    recommendedNextAction: runtime.recommended_next_action ?? "建议继续观察真实扫描进展。",
  };
}

function renderTaskList() {
  if (state.tasks.length === 0) {
    elements.taskList.innerHTML = `
      <div class="task-list__empty">
        暂无任务
      </div>
    `;
    return;
  }

  elements.taskList.innerHTML = renderTaskListMarkup(state.tasks, state.activeTaskId);

  elements.taskList.querySelectorAll("[data-task-id]").forEach((card) => {
    card.addEventListener("click", () => {
      state.activeTaskId = card.dataset.taskId;
      renderAll();
    });
  });
}

function renderSummary(task) {
  if (!task) {
    elements.summaryStrip.innerHTML = "";
    elements.aiSummary.innerHTML = "<p>暂无摘要</p>";
    return;
  }

  const { summaryStripMarkup, aiSummaryMarkup } = renderSummaryMarkup(task);
  elements.summaryStrip.innerHTML = summaryStripMarkup;
  elements.aiSummary.innerHTML = aiSummaryMarkup;
}

function renderRuntimeWorkbench(runtime, emptyState) {
  if (!runtime) {
    elements.runtimeWorkbench.hidden = true;
    elements.runtimeWorkbench.innerHTML = "";
    elements.runtimeEmptyState.hidden = false;
    elements.runtimeEmptyState.innerHTML = renderRuntimeWorkbenchMarkup(null, emptyState);
    return;
  }

  elements.runtimeEmptyState.hidden = true;
  elements.runtimeEmptyState.innerHTML = "";
  elements.runtimeWorkbench.hidden = false;
  elements.runtimeWorkbench.innerHTML = renderRuntimeWorkbenchMarkup(runtime);
}

function buildRuntimePresentation(task) {
  if (!task) {
    return {
      status: "等待真实扫描",
      log: "当前没有可展示的 Strix 运行日志。",
      runtime: null,
      emptyState: {
        emptyTitle: "等待真实扫描",
        emptyBody: "当前没有可展示的结构化运行态信息。",
      },
    };
  }

  if (task.resultSource !== "latest_real_run") {
    return {
      status: "演示样例模式",
      log: "当前任务使用演示样例结果，不会产生真实 Strix 运行日志。",
      runtime: null,
      emptyState: {
        emptyTitle: "演示样例模式",
        emptyBody: "当前任务没有真实 Strix 运行态，执行轨迹区仅在真实扫描任务中展示阶段、攻击面和收敛诊断。",
      },
    };
  }

  if (state.runtime?.taskId === task.taskId) {
    const phaseLabels = {
      pending: "已创建，等待启动",
      running: "真实扫描执行中",
      completed: "真实扫描已完成",
      failed: "真实扫描执行失败",
      cancelled: "真实扫描已终止",
      unavailable: "运行信息不可用",
    };

    return {
      status: phaseLabels[state.runtime.phase] ?? state.runtime.phase ?? "运行状态未知",
      log: state.runtime.logTail || "Strix 已启动，但暂时还没有产生日志输出。",
      runtime: state.runtime,
      emptyState: null,
    };
  }

  if (task.status === "created") {
    return {
      status: "已创建，等待启动",
      log: "任务已创建。点击“启动真实 Strix 扫描”后，这里会持续显示真实运行日志。",
      runtime: null,
      emptyState: {
        emptyTitle: "等待启动",
        emptyBody: "真实扫描任务已创建。启动后，这里会显示阶段、攻击面、收敛状态和下一步建议。",
      },
    };
  }

  if (task.status === "running") {
    return {
      status: "真实扫描执行中",
      log: "正在等待 Strix 返回日志输出...",
      runtime: null,
      emptyState: {
        emptyTitle: "真实扫描执行中",
        emptyBody: "结构化运行态正在刷新中，请稍后查看阶段、攻击面和收敛诊断。",
      },
    };
  }

  if (task.status === "failed") {
    if ((task.report?.findings?.length ?? 0) > 0) {
      return {
        status: "真实扫描执行完成",
        log: "本次扫描未正常收口，但已保留当前已发现漏洞，可直接查看和导出结果。",
        runtime: null,
        emptyState: {
          emptyTitle: "真实扫描执行完成",
          emptyBody: "本次任务虽然以失败或超时收口，但已保留有效漏洞结果，当前页面以已完成报告展示。",
        },
      };
    }

    return {
      status: "真实扫描执行失败",
      log: "本次扫描已失败。若后端未返回日志，请检查 strix_runs 中对应目录下的 strix.log。",
      runtime: null,
      emptyState: {
        emptyTitle: "真实扫描执行失败",
        emptyBody: "本次任务没有可用的结构化运行态快照，请结合日志尾部排查问题。",
      },
    };
  }

  if (task.status === "cancelled") {
    return {
      status: "真实扫描已终止",
      log: "本次扫描已被用户终止。",
      runtime: null,
      emptyState: {
        emptyTitle: "真实扫描已终止",
        emptyBody: "任务已终止，结构化运行态保留到最后一次成功刷新为止。",
      },
    };
  }

  return {
    status: "真实扫描已完成",
    log: "本次扫描已结束。若需要回看执行细节，请重新创建真实扫描任务并执行。",
    runtime: null,
    emptyState: {
      emptyTitle: "真实扫描已完成",
      emptyBody: "当前没有保留结构化运行态快照，请查看日志尾部或重新发起任务。",
    },
  };
}

function renderRuntime(task) {
  const runtime = buildRuntimePresentation(task);
  elements.runtimeStatus.textContent = runtime.status;
  elements.runtimeLog.textContent = runtime.log;
  renderRuntimeWorkbench(runtime.runtime, runtime.emptyState);
}

function stopRuntimePolling() {
  if (state.runtimePollHandle !== null) {
    window.clearInterval(state.runtimePollHandle);
    state.runtimePollHandle = null;
  }
}

async function refreshTaskResults(task) {
  const refreshedPayload = await requestJson(`/tasks/${task.taskId}/results`);
  const refreshedTask = createTaskFromApiPayload(refreshedPayload);
  upsertTask(refreshedTask);
  return refreshedTask;
}

async function refreshRuntime(task) {
  if (!apiBaseUrl || !task || task.resultSource !== "latest_real_run") {
    return;
  }

  try {
    const payload = await loadTaskRuntimeViaApi(task);
    if (state.activeTaskId !== task.taskId) {
      return;
    }

    state.runtime = {
      taskId: task.taskId,
      ...normalizeRuntimePayload(payload.runtime),
    };

    if (payload.runtime.phase === "running") {
      const refreshedTask = await refreshTaskResults(task);
      if (state.activeTaskId !== task.taskId) {
        return;
      }
      renderTaskList();
      renderSummary(refreshedTask);
      renderReport(refreshedTask);
      return;
    }

    renderRuntime(task);

    if (["completed", "failed", "cancelled"].includes(payload.runtime.phase)) {
      stopRuntimePolling();
      await refreshTaskResults(task);
      if (state.activeTaskId !== task.taskId) {
        return;
      }
      renderAll();
    }
  } catch (error) {
    if (state.activeTaskId !== task.taskId) {
      return;
    }

    state.runtime = {
      taskId: task.taskId,
      phase: "unavailable",
      logTail: `运行监控读取失败：${error.message}`,
      phaseLabel: "运行信息不可用",
      attackSurface: {
        pages: 0,
        forms: 0,
        parameters: 0,
        apiEndpoints: 0,
        authPoints: 0,
        uploadPoints: 0,
      },
      llmUsage: {
        requests: 0,
        totalTokens: 0,
      },
      convergence: {
        status: null,
        statusLabel: "暂无收敛判断",
        score: null,
        scoreText: "-",
        idleRounds: 0,
        lastMeaningfulEventAt: null,
      },
      failureClassification: null,
      failureClassificationLabel: "运行态拉取失败。",
      recommendedNextAction: "请检查本地服务、真实扫描环境或运行目录是否可访问。",
    };
    renderRuntime(task);
    stopRuntimePolling();
  }
}

function syncRuntimePolling(task) {
  stopRuntimePolling();

  if (!task) {
    state.runtime = null;
    renderRuntime(null);
    return;
  }

  if (task.resultSource !== "latest_real_run") {
    state.runtime = null;
    renderRuntime(task);
    return;
  }

  void refreshRuntime(task);

  if (task.status === "created" || task.status === "running" || state.isRunPending) {
    state.runtimePollHandle = window.setInterval(() => {
      const activeTask = state.tasks.find((item) => item.taskId === state.activeTaskId);
      if (!activeTask || activeTask.taskId !== task.taskId) {
        stopRuntimePolling();
        return;
      }

      void refreshRuntime(activeTask);
    }, 1500);
  }
}

function renderReport(task) {
  if (!task) {
    document.body.dataset.missionTone = "idle";
    elements.reportTaskName.textContent = "暂无任务";
    elements.reportTarget.textContent = "-";
    elements.reportSource.textContent = "演示样例";
    elements.runButton.textContent = "重新载入任务";
    elements.runButton.disabled = true;
    elements.cancelButton.disabled = true;
    elements.exportButton.disabled = true;
    elements.findingsList.innerHTML = `
      <article class="finding-entry finding-entry--empty">
        暂无风险详情
      </article>
    `;
    renderRuntime(null);
    return;
  }

  document.body.dataset.missionTone = missionToneForTask(task);
  elements.reportTaskName.textContent = task.name;
  elements.reportTarget.textContent = task.target;
  elements.reportSource.textContent = sourceLabelForTask(task);
  elements.runButton.textContent = runActionLabelForTask(task);
  elements.runButton.disabled = state.isRunPending || task.status === "running";
  elements.cancelButton.disabled = !(task.resultSource === "latest_real_run" && task.status === "running");
  elements.exportButton.disabled = false;
  elements.findingsList.innerHTML = renderFindingsMarkup(task);
  renderRuntime(task);
}

function renderAll() {
  const activeTask = state.tasks.find((task) => task.taskId === state.activeTaskId) ?? null;
  renderTaskList();
  renderSummary(activeTask);
  renderReport(activeTask);
  syncRuntimePolling(activeTask);
}

elements.form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(elements.form);
  elements.feedback.textContent = "正在创建任务...";

  try {
    const task = apiBaseUrl
      ? await createTaskViaApi(formData)
      : buildDemoTask(formData, state.tasks.length);
    upsertTask(task);
    state.activeTaskId = task.taskId;
    elements.feedback.textContent = apiBaseUrl
      ? `已创建任务 ${task.taskId}。`
      : `已创建本地演示任务 ${task.taskId}。`;
    elements.form.reset();
    renderAll();
  } catch (error) {
    const task = buildDemoTask(formData, state.tasks.length);
    upsertTask(task);
    state.activeTaskId = task.taskId;
    elements.feedback.textContent = `后端暂不可用，已回退到本地演示样例模式：${error.message}`;
    elements.form.reset();
    renderAll();
  }
});

elements.runButton.addEventListener("click", async () => {
  const activeTask = state.tasks.find((task) => task.taskId === state.activeTaskId);
  if (!activeTask) {
    elements.feedback.textContent = "请先创建任务。";
    return;
  }

  if (!apiBaseUrl) {
    elements.feedback.textContent = "当前是本地演示样例模式，任务创建后已自动载入结果。";
    return;
  }

  if (state.isRunPending) {
    elements.feedback.textContent = "当前已有真实扫描在执行，请等待完成后再试。";
    return;
  }

  elements.feedback.textContent = `正在执行任务 ${activeTask.taskId}...`;
  state.isRunPending = true;
  upsertTask(buildRunningTaskFromTask(activeTask));
  renderAll();

  try {
    const refreshedTask = await runTaskViaApi(activeTask);
    upsertTask(refreshedTask);
    state.activeTaskId = refreshedTask.taskId;
    elements.feedback.textContent = activeTask.resultSource === "latest_real_run"
      ? `任务 ${refreshedTask.taskId} 已启动真实扫描。`
      : `任务 ${refreshedTask.taskId} 已刷新结果。`;
  } catch (error) {
    const failedTask = buildFailedTaskFromError(activeTask, error.message);
    upsertTask(failedTask);
    state.activeTaskId = failedTask.taskId;
    elements.feedback.textContent = `执行失败：${error.message}`;
  } finally {
    state.isRunPending = false;
    renderAll();
  }
});

elements.cancelButton.addEventListener("click", async () => {
  const activeTask = state.tasks.find((task) => task.taskId === state.activeTaskId);
  if (!activeTask || !apiBaseUrl) {
    return;
  }

  elements.feedback.textContent = `正在终止任务 ${activeTask.taskId}...`;

  try {
    const cancelledTask = await cancelTaskViaApi(activeTask);
    upsertTask(cancelledTask);
    state.activeTaskId = cancelledTask.taskId;
    state.isRunPending = false;
    stopRuntimePolling();
    elements.feedback.textContent = `任务 ${cancelledTask.taskId} 已终止。`;
  } catch (error) {
    elements.feedback.textContent = `终止失败：${error.message}`;
  } finally {
    renderAll();
  }
});

elements.exportButton.addEventListener("click", async () => {
  const activeTask = state.tasks.find((task) => task.taskId === state.activeTaskId);
  if (!activeTask) {
    elements.feedback.textContent = "请先创建任务。";
    return;
  }

  try {
    const selection = resolveExportSelection(activeTask);

    if (selection.format === "docx") {
      if (!apiBaseUrl) {
        throw new Error("DOCX 导出仅在本地服务启动后可用");
      }

      const blob = await exportBinary(
        `/tasks/${activeTask.taskId}/export?format=docx&scope=${selection.scope}`,
      );
      triggerBlobDownload(selection.fileName, blob);
      elements.feedback.textContent = `已导出 DOCX 报告 ${selection.fileName}。`;
      return;
    }

    const exported = apiBaseUrl
      ? await exportTaskViaApi(activeTask)
      : buildLocalExportPayload(activeTask);
    triggerTextDownload(selection.fileName, exported.content);
    elements.feedback.textContent = `已导出报告 ${selection.fileName}。`;
  } catch (error) {
    elements.feedback.textContent = `导出失败：${error.message}`;
  }
});

renderAll();

if (apiBaseUrl) {
  loadTasksFromApi().catch(() => {
    elements.feedback.textContent = "后端接口暂未返回可用结果，当前保留本地演示模式。";
  });
}
