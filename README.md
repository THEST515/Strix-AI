# Strix AI 辅助安全分析平台

一个面向真实黑盒扫描场景的 AI 辅助安全分析平台。

平台以 Strix 为真实扫描引擎，在保持轻量部署的前提下，把 `任务创建 -> 实时扫描 -> 运行态解释 -> 风险展示 -> 报告导出` 串成一个完整工作流。它不是单纯的扫描结果查看器，而是一个更强调“扫描是否收敛到漏洞证据、当前处于哪个阶段、下一步应该怎么做”的产品化工作台。

## 产品定位

Strix AI 辅助安全分析平台聚焦三件事：

- 让真实扫描过程可见，而不只是看到最终结果
- 让漏洞结果可解释，而不只是堆砌日志和原始 findings
- 让扫描产物可交付，支持直接导出结构化报告

平台当前采用 `原生前端 + Python 最小后端 + Strix CLI` 的轻量架构，适合本地部署、内部演示、授权测试环境验证，以及安全研究工作流的快速搭建。

## 核心能力

- 支持 `fixture` 样例路径，便于快速演示与联调
- 支持 `latest_real_run` 真实 Strix 扫描路径
- 支持显式 `run`
- 支持 `/runtime` 结构化运行态解释
- 支持 Markdown 导出
- 支持基于固定模板的 DOCX 导出
- 支持单网站导出与多网站合并导出
- 支持扫描时长预设：`3 / 5 / 10 分钟`
- 支持运行中提前吸收已落盘 findings
- 支持在 `failed / timeout / interrupted / cancelled` 后尽量保留已发现漏洞
- 支持 findings 中文化、LLM 翻译与持久化缓存

## 产品价值

### 1. 扫描过程可解释

平台不只展示“成功/失败”，还会解释真实扫描运行到了哪个阶段。

当前已接入的运行态字段：

- `phase_label`
- `attack_surface`
- `convergence`
- `failure_classification`
- `recommended_next_action`
- `llm_usage`

阶段模型：

1. `preflight`
2. `recon`
3. `surface_analysis`
4. `targeted_validation`
5. `evidence_packaging`

### 2. 风险结果更稳定

平台对 findings 中文化采用两层策略：

1. 高频漏洞类型规则表
2. 复用 Strix 同源 LLM 配置做翻译

同时会把同一真实 run 的翻译结果缓存到：

```text
strix_runs/<run>/finding_translations.zh-CN.json
```

这样可以减少重复翻译，避免同一 finding 在多次加载时反复跳版本。

### 3. 结果输出可直接交付

支持两类导出：

- Markdown 报告
- 基于固定模板的 DOCX 报告

模板文件：

```text
assets/report_template.docx
```

DOCX 支持：

- 当前网站单独导出
- 多网站合并导出

## 技术架构

- 前端：`HTML + CSS + JavaScript`
- 后端：Python 标准库最小 HTTP 服务
- 扫描引擎：`Strix CLI`
- 导出模板：`assets/report_template.docx`

当前保持轻量架构，不引入数据库、消息队列或重量级前后端框架。

## 目录说明

```text
01_新项目/
  assets/
  docs/
    architecture/
    demo/
    setup/
  scripts/
  src/
    backend/
    frontend/
  tests/
  strix_runs/
```

说明：

- `strix_runs/` 是本机真实扫描产物目录，可用于运行态解释与结果导入
- `docs/demo/` 包含演示脚本和故障口径
- `docs/setup/` 包含 Strix、Docker 和 API 配置说明

## Docker 与 Strix 部署配置

真实扫描依赖 4 个前提：

- Docker Desktop 已安装并成功启动
- Strix CLI 已安装并加入 PATH
- 当前电脑已配置可用的 LLM API
- 扫描目标已获得授权

### 1. 部署 Docker Desktop

先安装 Docker Desktop，并完成首次初始化。安装完成后启动 Docker Desktop，等待其进入运行状态。

验证命令：

```powershell
docker --version
docker info
```

判断标准：

- `docker --version` 成功，说明 Docker CLI 已安装
- `docker info` 成功，说明 Docker daemon 已就绪

如果 `docker info` 失败，`latest_real_run` 通常无法工作。

### 2. 部署 Strix CLI

确保 `strix` 已安装并加入系统 PATH。Windows 常见可执行文件路径类似：

```text
C:\Users\<用户名>\.strix\bin\strix.exe
```

验证命令：

```powershell
where strix
strix --help
```

判断标准：

- `where strix` 能找到可执行文件
- `strix --help` 能正常输出帮助信息

如果找不到 `strix`，需要把 `strix.exe` 所在目录加入 PATH 后重新打开终端。

### 3. 配置 Strix 所需 LLM API

这个项目支持两种方式：

1. 环境变量
2. Strix 本地配置文件

推荐原则：

- 项目仓库不保存任何真实 Key
- 每个使用者在自己电脑上配置自己的 Key
- 不共享你自己的本机 Key 文件

环境变量示例：

```powershell
$env:STRIX_LLM="deepseek/deepseek-v4-flash"
$env:LLM_API_KEY="你的 DeepSeek Key"
$env:DEEPSEEK_API_KEY="你的 DeepSeek Key"
```

如果希望写入用户级环境变量：

```powershell
setx STRIX_LLM "deepseek/deepseek-v4-flash"
setx LLM_API_KEY "你的 DeepSeek Key"
setx DEEPSEEK_API_KEY "你的 DeepSeek Key"
```

注意：

- `setx` 后要重新打开终端
- 不要把真实 Key 写进仓库、脚本或共享文档

也可以使用 Strix 本地配置文件：

```text
C:\Users\<用户名>\.strix\cli-config.json
```

配置模板示例：

```json
{
  "env": {
    "STRIX_LLM": "deepseek/deepseek-v4-flash",
    "LLM_API_KEY": "在这里填你自己的 Key",
    "DEEPSEEK_API_KEY": "在这里填你自己的 Key"
  }
}
```

仓库内提供了可共享模板：

- [docs/setup/cli-config.example.json](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/cli-config.example.json)

详细说明见：

- [docs/setup/strix_setup.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/strix_setup.md)

### 4. 最小自检流程

进入项目目录：

```powershell
cd C:\Users\MMK20041021\Desktop\workspace\01_新项目
```

按顺序执行：

```powershell
docker info
strix --help
```

然后确认以下至少满足一类：

- 已设置 `STRIX_LLM`
- 已设置 `LLM_API_KEY` 或 `DEEPSEEK_API_KEY`
- 已创建 `C:\Users\<用户名>\.strix\cli-config.json`

如果要做最小 Strix 启动验证，可以执行：

```powershell
strix -n --target ./src/frontend
```

期望结果：

- 命令能够启动
- 不会立即因为缺少 Docker 或 Key 退出
- 项目目录下会生成或更新 `strix_runs/`

## 项目启动全过程

### 1. 仅启动平台页面

只需要：

- Python 3
- 浏览器

启动：

```powershell
cd C:\Users\MMK20041021\Desktop\workspace\01_新项目
python scripts/run_demo_server.py
```

打开：

```text
http://127.0.0.1:8000/
```

此时可直接使用 `fixture` 路径，不依赖 Docker 和 Strix。

### 2. 启用真实 Strix 扫描

当 Docker、Strix CLI 和 API 配置都已完成后，再使用 `latest_real_run` 路径进行真实扫描。

推荐先检查：

```powershell
docker info
where strix
strix --help
```

如果这些检查都通过，再启动平台并在页面里选择真实扫描任务。

## 使用方式

推荐顺序：

1. 创建任务
2. 选择 `fixture` 或 `latest_real_run`
3. 如为真实扫描，选择时长
4. 点击 `启动真实 Strix 扫描`
5. 观察运行态阶段、攻击面、收敛判断和下一步建议
6. 查看风险详情
7. 导出 Markdown / DOCX

如果一次真实扫描没有正常收口，但已经保留了 findings，界面会按“执行完成”展示当前结果，避免把已保留的有效结果误解释为纯失败空跑。

## 常见问题

### 页面能打开，但真实扫描跑不起来

优先检查：

1. `docker info` 是否成功
2. `strix --help` 是否成功
3. `STRIX_LLM / LLM_API_KEY / DEEPSEEK_API_KEY` 是否存在
4. `~/.strix/cli-config.json` 是否是你自己的配置

### `fixture` 能跑，`latest_real_run` 不能跑

这通常不是前端问题，而是 Strix 运行环境未就绪。

### 超时或失败后为什么还有报告

这是平台的设计目标之一：

- 只要运行过程中已经落盘 findings，就尽量保留到当前任务报告
- 因此“任务失败”和“报告为空”不是一回事

### 端口 8000 异常

当前环境里 `8000` 可能残留旧进程。验收或录屏时，建议优先使用干净端口启动。

## 测试命令

前端：

```powershell
node --check src/frontend/app.js
node --check src/frontend/taskData.mjs
node --test tests/frontend/rendering.test.mjs tests/frontend/taskData.test.mjs
```

后端：

```powershell
python -m unittest discover -s tests/backend
```

浏览器 smoke：

```powershell
node scripts/browser_smoke_test.mjs http://127.0.0.1:8000/ fixture
node scripts/browser_smoke_test.mjs http://127.0.0.1:8000/ latest_real_run
```

## 相关文档

- [docs/setup/strix_setup.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/strix_setup.md)
- [docs/demo/demo_script.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/demo_script.md)
- [docs/demo/failure_playbook.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/failure_playbook.md)
- [docs/architecture/strix-convergence-design.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/architecture/strix-convergence-design.md)

## 使用边界

- 仅用于授权测试、内部演示或本地实验环境
- 不要扫描未授权目标
- 当前版本适合轻量部署与快速验证，不等同于生产级安全平台
