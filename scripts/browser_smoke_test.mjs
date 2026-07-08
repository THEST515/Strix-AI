import { pathToFileURL } from "node:url";
import path from "node:path";

function resolvePlaywrightImportPath() {
  if (process.env.PLAYWRIGHT_IMPORT_PATH) {
    return process.env.PLAYWRIGHT_IMPORT_PATH;
  }

  const userProfile = process.env.USERPROFILE;
  if (!userProfile) {
    throw new Error("USERPROFILE is required to resolve the bundled Playwright runtime.");
  }

  return path.join(
    userProfile,
    ".cache",
    "codex-runtimes",
    "codex-primary-runtime",
    "dependencies",
    "node",
    "node_modules",
    ".pnpm",
    "playwright@1.61.1",
    "node_modules",
    "playwright",
    "index.mjs",
  );
}

async function main() {
  const baseUrl = process.argv[2] ?? "http://127.0.0.1:8000/";
  const resultSource = process.argv[3] ?? "fixture";
  const isRealRun = resultSource === "latest_real_run";
  const playwrightImportPath = resolvePlaywrightImportPath();
  const { chromium } = await import(pathToFileURL(playwrightImportPath).href);

  const browser = await chromium.launch({ headless: true, channel: "msedge" });
  const context = await browser.newContext();
  const page = await context.newPage();

  try {
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await page.locator("#task-name").fill(isRealRun ? "真实结果导入冒烟验证" : "显式运行冒烟验证");
    await page.locator("#task-target").fill(
      isRealRun ? "./placeholder" : "https://authorized-lab.example",
    );
    await page.locator("#task-mode").selectOption("quick");
    await page.locator("#task-result-source").selectOption(resultSource);
    await page
      .locator("#task-instruction")
      .fill(isRealRun ? "验证 latest_real_run 导入链路。" : "验证显式运行、摘要展示与导出链路。");
    await page.locator('button[type="submit"]').click();
    await page.waitForFunction(
      () => (document.querySelector("#form-feedback")?.textContent ?? "").includes("已通过后端 API 创建任务"),
      { timeout: 10000 },
    );

    await page.locator("#run-task").click();
    await page.waitForFunction(
      () => {
        const feedback = document.querySelector("#form-feedback")?.textContent ?? "";
        return feedback.includes("已更新任务") || feedback.includes("已完成任务");
      },
      { timeout: 10000 },
    );

    await page.locator("#export-report").click();
    await page.waitForFunction(
      () => (document.querySelector("#form-feedback")?.textContent ?? "").includes("已导出报告"),
      { timeout: 10000 },
    );

    const state = await page.evaluate(() => ({
      feedback: document.querySelector("#form-feedback")?.textContent?.trim() ?? "",
      runButtonDisabled: document.querySelector("#run-task")?.hasAttribute("disabled") ?? true,
      exportButtonDisabled: document.querySelector("#export-report")?.hasAttribute("disabled") ?? true,
      reportTaskName: document.querySelector("#report-task-name")?.textContent?.trim() ?? "",
      reportSource: document.querySelector("#report-source")?.textContent?.trim() ?? "",
      aiSummary: document.querySelector("#ai-summary")?.textContent?.trim() ?? "",
    }));

    process.stdout.write(`${JSON.stringify({ ok: true, baseUrl, resultSource, state }, null, 2)}\n`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? String(error)}\n`);
  process.exitCode = 1;
});
