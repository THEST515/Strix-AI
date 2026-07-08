# Strix 收敛式黑盒扫描设计

## 1. 设计背景

当前平台已经具备真实 `Strix` 扫描闭环：

- 可创建 `latest_real_run` 任务
- 可显式启动真实扫描
- 可读取 `strix_runs/` 产物
- 可展示执行日志与终止任务

但当前链路的核心问题不是“能不能跑起来”，而是“能不能尽可能稳定地产出漏洞证据”。

现状痛点：

1. `Strix` 容易长时间停留在开放式探索阶段。
2. 平台当前只展示“运行中 / 已完成 / 已失败”，缺少“扫描阶段、攻击面、收敛状态、有效性”的诊断视角。
3. 超时后只能得到“失败”与空 findings，无法区分：
   - 环境失败
   - 攻击面不足
   - 已发现攻击面但未完成验证
   - 已形成疑似问题但未整理成漏洞报告
4. 对不同类型网站没有策略分流，导致泛化指令在部分站点上效率很低。

## 2. 设计目标

本设计的目标不是替换 `Strix`，而是在当前最小架构内，把平台从“真实扫描启动器”升级为“收敛式黑盒扫描编排器”。

目标：

1. 让平台能区分“真实执行”与“有效扫描”。
2. 让扫描过程具备阶段感，而不是只有日志流。
3. 让不同网站目标自动切换更合适的测试策略。
4. 让超时、无结果、无攻击面、验证不足等状态可解释。
5. 保持当前原生前端 + Python 最小后端结构，不引入大型任务系统或数据库。

非目标：

1. 不做分布式调度。
2. 不引入消息队列。
3. 不引入复杂持久化数据库。
4. 不改造 `Strix` CLI 内部实现。

## 3. 核心思路

### 3.1 从“单次开放扫描”改为“平台分阶段编排”

平台不再把一次扫描视为单一动作，而是视为以下阶段的推进：

1. `preflight`
2. `recon`
3. `surface_analysis`
4. `targeted_validation`
5. `evidence_packaging`
6. `completed` / `timeout` / `failed` / `cancelled`

平台重点不在于直接控制 `Strix` 每一步，而在于：

1. 给 `Strix` 提供更明确的阶段目标与策略模板。
2. 从 `run.json`、`strix.log`、运行产物中提炼“阶段状态”和“有效性信号”。

### 3.2 从“通用 instruction”改为“策略模板 + 收缩策略”

平台内部维护多套 `Strix` 指令模板，而不是始终把用户输入直接送给 `Strix`。

模板层次：

1. 通用基础模板
2. 站点类型模板
3. 收缩模板

平台规则不是“让 prompt 更华丽”，而是：

1. 先识别站点类型。
2. 再选择最合适模板。
3. 若长时间无收敛，则自动切换为更窄、更激进的验证模板。

## 4. 数据模型扩展

在不引入数据库的前提下，为现有 `runtime` 响应新增结构化字段。

建议新增：

```json
{
  "phase": "targeted_validation",
  "phase_label": "定向漏洞验证",
  "llm_usage": {
    "requests": 39,
    "total_tokens": 1712579
  },
  "site_profile": {
    "kind": "form_app",
    "confidence": 0.74
  },
  "attack_surface": {
    "pages": 6,
    "forms": 2,
    "parameters": 9,
    "api_endpoints": 3,
    "auth_points": 1,
    "upload_points": 0
  },
  "evidence_progress": {
    "suspicions": 2,
    "validated_findings": 0,
    "reports_created": 0
  },
  "convergence": {
    "score": 0.58,
    "status": "surface_found_but_unverified",
    "last_meaningful_event_at": "...",
    "idle_rounds": 4
  },
  "failure_classification": null,
  "recommended_next_action": "收缩到表单与查询参数验证"
}
```

### 4.1 新增有效性判定

建议分类：

1. `environment_failed`
2. `no_surface_found`
3. `surface_found_but_unverified`
4. `evidence_in_progress`
5. `validated_findings`
6. `completed_without_findings`
7. `timeout_unconverged`

## 5. 运行时编排设计

### 5.1 预分析阶段

在 `run_task()` 真正启动 `Strix` 前，新增轻量预分析：

1. 标准化目标 URL
2. 检查目标更接近内容站、表单站、后台站还是 API 站
3. 生成 `site_profile`
4. 选择默认扫描模板

### 5.2 阶段推进判定

平台从 `run.json` / `strix.log` 中识别以下信号：

1. `Calling LLM`
2. `Invoking tool ...`
3. `Added vulnerability report`
4. `Vulnerability report created`
5. `targets_info`
6. `llm_usage.requests`

平台不依赖单一日志关键词，而是组合判断：

1. 攻击面是否增长
2. 疑似问题是否增长
3. 报告数量是否增长
4. 最近若干轮是否无“有意义事件”

### 5.3 收缩策略

若满足以下条件，平台将当前扫描标记为“低收敛”，并在下次创建真实扫描任务时自动注入更强约束模板：

1. `idle_rounds >= 3`
2. `validated_findings == 0`
3. `attack_surface.parameters + forms > 0`
4. 当前仍停留在 `recon` 或 `surface_analysis`

收缩行为：

1. 从“全站探索”切换为“输入点验证优先”
2. 限制持续浏览与规划
3. 优先验证：
   - XSS
   - SQL 注入
   - 未授权访问
   - IDOR
   - 文件上传
   - 路径穿越

## 6. 指令模板设计

建议将当前单一 `instruction` 拆成三层：

1. 基础模板
2. 站点模板
3. 收缩模板

### 6.1 基础模板

所有真实扫描统一附加：

- 目标是尽快形成最小可复现漏洞证据
- 不要长时间开放探索
- 无进展时必须收缩范围
- 只有可复现证据才形成漏洞报告

### 6.2 站点模板

按 `site_profile.kind` 注入：

1. `content_site`
2. `form_app`
3. `auth_app`
4. `api_app`

### 6.3 收缩模板

针对“多轮无收敛”场景：

- 停止宽泛侦察
- 只围绕已发现输入点和接口验证
- 要求优先输出单个可复现漏洞

## 7. 前端展示设计

当前执行轨迹区只有：

1. 状态文本
2. 日志尾部

建议在现有 `runtime-monitor` 上增加三组信息：

### 7.1 扫描阶段

- 当前阶段
- 站点类型
- 当前策略

### 7.2 攻击面概览

- 页面数
- 表单数
- 参数数
- 接口数
- 认证点
- 上传点

### 7.3 收敛诊断

- LLM 请求数
- 累计 token
- 疑似问题数
- 已验证漏洞数
- 最近有意义事件时间
- 当前判定

## 8. 后端改动范围

保持当前最小结构，建议只扩展以下位置：

1. `src/backend/api/demo_server.py`
2. `src/backend/services/strix_runner.py`
3. 新增：
   - `src/backend/services/runtime_analyzer.py`
   - `src/backend/services/scan_strategy.py`

## 9. 测试设计

### 9.1 后端单元测试

新增覆盖：

1. `runtime_analyzer`
2. `scan_strategy`
3. `demo_server`

### 9.2 前端回归测试

新增覆盖：

1. 执行轨迹区显示阶段与攻击面摘要
2. 无漏洞但有攻击面时，不再只显示“失败”
3. 有已验证漏洞时，运行态提示切换为“已形成证据”

## 10. MVP 分阶段落地建议

### Phase A：运行态解释增强

1. 新增 `runtime_analyzer.py`
2. `/runtime` 返回：
   - `phase_label`
   - `llm_usage`
   - `attack_surface`
   - `convergence`
   - `failure_classification`
3. 前端展示阶段、攻击面、收敛状态

### Phase B：策略模板化

1. 新增 `scan_strategy.py`
2. 平台按站点类型自动组合 instruction
3. 用户输入 instruction 作为附加约束，而不是唯一约束

### Phase C：自动收缩

1. 对无收敛扫描生成更强约束策略
2. 在下一次真实扫描任务默认启用收缩模板

## 11. 最终判断标准

平台不应再只回答“Strix 在运行”，而应能回答：

1. 当前扫描到了哪个阶段？
2. 已识别多少攻击面？
3. 是否已进入定向漏洞验证？
4. 是否形成了疑似问题？
5. 为什么现在还没出漏洞？
6. 下一步该继续、收缩还是结束？
