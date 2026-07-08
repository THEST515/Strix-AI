# 基于 Strix 的 AI 辅助安全分析平台

课程演示型 MVP。

目标不是做企业级平台，而是在保持 `原生前端 + Python 最小后端 + 真实 Strix 扫描链路` 不回退的前提下，打通：

`任务创建 -> 真实扫描 -> 运行态解释 -> 风险展示 -> Markdown/DOCX 导出`

## 1. 当前能力

- 支持 `fixture` 演示路径
- 支持 `latest_real_run` 真实 Strix 扫描路径
- 支持显式 `run`
- 支持 `/runtime` 结构化运行态解释
- 支持 Markdown 导出
- 支持基于固定模板的 DOCX 导出
- 支持单网站导出与多网站合并导出
- 支持扫描时长预设：`3 / 5 / 10 分钟`
- 支持在扫描中提前吸收已落盘 findings
- 支持在 `failed / timeout / interrupted / cancelled` 后尽量保留已发现漏洞
- 支持 findings 中文化、LLM 翻译与持久化缓存

## 2. 技术边界

- 前端：`HTML + CSS + JavaScript`
- 后端：Python 标准库最小 HTTP 服务
- 扫描引擎：`Strix CLI`
- 导出模板：`assets/report_template.docx`

不做的事：

- 不做大范围架构重构
- 不迁移到 React / Vite / 数据库 / 队列
- 不回退已有真实 Strix 扫描链路
- 不回退已有 DOCX 模板导出能力

## 3. 目录说明

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
```

说明：

- `strix_runs/` 是本机真实扫描产物目录，可用于运行态解释与结果导入
- `docs/demo/` 包含演示脚本和故障口径
- `docs/setup/` 包含 Strix、Docker 和 API 配置说明

## 4. 快速启动

### 4.1 只看演示页面

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

### 4.2 跑真实 Strix 扫描

额外需要：

- Docker Desktop
- Strix CLI
- 可用的模型配置

基础检查：

```powershell
docker --version
docker info
where strix
strix --help
```

环境变量示例：

```powershell
$env:STRIX_LLM="deepseek/deepseek-v4-flash"
$env:LLM_API_KEY="你的 Key"
$env:DEEPSEEK_API_KEY="你的 Key"
```

也可以使用本机 Strix 配置文件：

```text
C:\Users\<用户名>\.strix\cli-config.json
```

可共享模板：

- [docs/setup/cli-config.example.json](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/cli-config.example.json)

详细配置：

- [docs/setup/strix_setup.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/strix_setup.md)

## 5. 真实扫描运行态说明

平台现在不只展示“有没有结果”，还会解释 Strix 扫描处于哪个阶段。

当前前端已接入：

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

如果一次真实扫描没有正常收口，但已经保留了 findings，界面会按“执行完成”展示当前结果，避免把已保留报告误讲成纯失败空跑。

## 6. 中文化策略

当前 findings 中文化分两层：

1. 高频漏洞类型规则表
2. 复用 Strix 同源 LLM 配置做中文翻译

为避免重复翻译和同一 finding 来回跳版本：

- 会优先走规则表
- 若启用 LLM 翻译，会把翻译结果持久化缓存到对应 `strix_runs/<run>/finding_translations.zh-CN.json`
- 同一 run 后续再次读取时直接复用缓存

## 7. 推荐演示顺序

先做稳定演示：

1. 创建 `fixture` 任务
2. 查看摘要和风险详情
3. 导出 Markdown
4. 导出 DOCX

再做真实扫描演示：

1. 创建 `latest_real_run` 任务
2. 选择目标
3. 选择时长
4. 点击 `启动真实 Strix 扫描`
5. 讲解运行态阶段、攻击面、收敛判断和下一步建议
6. 如有 findings，展示中文风险详情与导出结果

演示口径：

- [docs/demo/demo_script.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/demo_script.md)
- [docs/demo/failure_playbook.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/failure_playbook.md)

## 8. 常见故障

### 8.1 页面能打开，但真实扫描跑不起来

优先检查：

1. `docker info` 是否成功
2. `strix --help` 是否成功
3. `STRIX_LLM / LLM_API_KEY / DEEPSEEK_API_KEY` 是否存在
4. `~/.strix/cli-config.json` 是否是你自己的配置

### 8.2 `fixture` 能跑，`latest_real_run` 不能跑

这通常不是前端问题，而是 Strix 运行环境未就绪。

### 8.3 超时或失败后为什么还有报告

这是当前平台的设计目标之一：

- 只要运行过程中已经落盘 findings，就尽量保留到当前任务报告
- 因此“任务失败”和“报告为空”不是一回事

### 8.4 端口 8000 异常

当前环境里 `8000` 可能残留旧进程。验收或录屏时，建议优先用干净端口启动。

## 9. 测试命令

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

## 10. 共享与 GitHub 上传

不要提交：

- 你的真实 API Key
- 你的 `~/.strix/cli-config.json`
- 本机临时运行产物

仓库内只保留：

- 说明文档
- 示例配置模板
- 代码
- 测试

已经提供 GitHub 共享副本构建脚本：

```powershell
python scripts/build_github_share.py
```

默认输出到：

```text
dist/github-share/strix-ai-security-demo-platform
```

这个共享副本会排除本机验收残留、运行产物和会话规划文件，适合直接初始化 Git 仓库后上传。

## 11. 相关文档

- [docs/setup/strix_setup.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/setup/strix_setup.md)
- [docs/demo/demo_script.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/demo_script.md)
- [docs/demo/failure_playbook.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/demo/failure_playbook.md)
- [docs/architecture/strix-convergence-design.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/docs/architecture/strix-convergence-design.md)

## 12. 注意

- 仅用于课程演示、授权测试或本地实验
- 不要扫描未授权目标
- 当前是本地 MVP，不是生产级部署方案
