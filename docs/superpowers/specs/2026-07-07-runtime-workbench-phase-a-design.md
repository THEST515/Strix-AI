# Phase A Runtime Workbench Frontend Design

## 1. 背景

当前项目后端已经完成 `/runtime` 结构化解释增强，能够返回以下关键字段：

- `phase_label`
- `llm_usage`
- `attack_surface`
- `convergence`
- `failure_classification`
- `recommended_next_action`

但前端当前仍然只消费两类信息：

- `runtime-status`
- `runtime-log`

这导致平台虽然已经能真实运行 Strix，也能在后端解释扫描态势，但前端仍无法稳定回答以下答辩型问题：

1. 当前扫描处于哪个阶段
2. 已识别了多少攻击面
3. 当前为什么还没有漏洞结果
4. 下一步应该继续、收缩还是结束

本次设计目标是在不改动现有最小架构的前提下，把这些后端已有信息正式接入当前产品界面。

## 2. 目标

### 2.1 设计目标

在当前“执行轨迹”区域内完成一次最小但完整的 runtime workbench 升级，让真实扫描任务在前端具备：

1. 阶段展示
2. 攻击面展示
3. 收敛诊断展示
4. 下一步建议展示
5. 原始日志尾部保留

### 2.2 非目标

本轮明确不做：

1. 不新增新的独立页面或第二工作台
2. 不改造任务创建流
3. 不改造导出流
4. 不改造真实 Strix 调用链
5. 不推进 Phase B 策略模板化
6. 不推进 Phase C 自动收缩执行

## 3. 约束

必须遵守以下边界：

1. 保持原生 `HTML + CSS + JavaScript` 前端
2. 保持 Python 最小后端结构
3. 不回退 `latest_real_run` 真实扫描链路
4. 不回退现有 DOCX 导出能力
5. 不做大范围布局重构
6. 继续使用现有 `runtime-monitor` 作为展示容器

## 4. 推荐方案

推荐采用“单区增强”方案，而不是“新增大面板”方案。

### 4.1 方案说明

保留当前结果总览中的 `runtime-monitor`，并在日志区上方增加三组结构化信息：

1. 扫描阶段
2. 攻击面概览
3. 收敛诊断

日志尾部继续保留，作为真实运行证据流。

### 4.2 为什么选这个方案

相比新开一个 runtime 区域，这个方案的优势是：

1. 改动边界小，不会打乱当前已完成的演示布局
2. 风险低，不影响任务、报告、风险详情等既有模块
3. 更符合当前答辩场景，需要的是“解释增强”而不是“信息扩容失控”
4. 与 Phase A 的目标完全一致，只消费已有后端字段

## 5. 前端信息结构

### 5.1 扫描阶段区

展示：

- `phase_label`
- 可选 `phase`
- `failure_classification` 的中文化状态标签（仅在失败或收尾时强调）

展示目标：

- 让用户一眼知道当前属于“预检查 / 侦察识别 / 攻击面分析 / 证据整理 / 失败 / 已终止”等哪种状态

### 5.2 攻击面概览区

展示以下字段：

- `attack_surface.pages`
- `attack_surface.forms`
- `attack_surface.parameters`
- `attack_surface.api_endpoints`
- `attack_surface.auth_points`
- `attack_surface.upload_points`

展示形式：

- 使用当前页面风格一致的紧凑指标条
- 不上图表，不增加动画解释逻辑

### 5.3 收敛诊断区

展示以下字段：

- `convergence.status`
- `convergence.score`
- `convergence.idle_rounds`
- `llm_usage.requests`
- `llm_usage.total_tokens`
- `recommended_next_action`

展示目标：

- 用于回答“现在为什么还没有漏洞结果”
- 用于回答“应该继续扫还是收缩范围”

### 5.4 日志区

继续保留：

- `runtime.log_tail`

原因：

1. 日志是最直接的真实运行证据
2. 答辩时可以同时讲“平台解释”与“原始日志依据”

## 6. 交互规则

### 6.1 `fixture` 任务

行为：

- 继续显示“演示样例模式”
- 不展示完整真实运行结构化区
- 显示一条说明：当前任务没有真实 Strix 运行态

理由：

- `fixture` 本身不应伪装成真实运行态

### 6.2 `latest_real_run` 任务

行为：

- 展示完整 runtime workbench
- 运行中持续轮询
- 完成、失败、终止后保留最后一帧解释结果

### 6.3 异常与缺失字段

若 `/runtime` 某些字段缺失：

1. 前端不抛错
2. 用占位文本替代
3. 日志区仍继续显示

目标是优先保证演示稳定性。

## 7. 数据映射设计

前端需要在 `app.js` 中把 `/runtime` payload 规范化为统一对象，至少包含：

- `phase`
- `phaseLabel`
- `runId`
- `runStatus`
- `target`
- `startedAt`
- `completedAt`
- `logTail`
- `attackSurface`
- `llmUsage`
- `convergence`
- `failureClassification`
- `recommendedNextAction`

渲染层只依赖规范化后的对象，不直接依赖后端原始字段命名。

## 8. UI 文案方向

文案保持当前项目已有风格：

1. 中文
2. 冷静
3. 产品级
4. 不夸张
5. 可直接用于答辩讲述

示例文案方向：

- 当前阶段：`攻击面分析`
- 收敛判断：`已发现攻击面，但尚未形成可验证漏洞`
- 下一步建议：`建议收缩到表单与查询参数验证，优先复现单个高置信问题`

## 9. 影响文件

本轮预计只修改以下前端文件：

- `src/frontend/index.html`
- `src/frontend/styles.css`
- `src/frontend/app.js`
- `src/frontend/rendering.mjs`
- `tests/frontend/rendering.test.mjs`

如实现中发现需要补充任务数据归一化，也允许最小修改：

- `src/frontend/taskData.mjs`

## 10. 测试策略

按 TDD 执行，先补失败测试，再改实现。

### 10.1 前端测试新增覆盖

至少覆盖：

1. `index.html` 暴露 runtime 结构化容器
2. `app.js` 读取新的 `/runtime` 字段
3. `rendering.mjs` 能渲染阶段、攻击面、收敛诊断
4. `fixture` 模式下不会伪造真实运行信息

### 10.2 验证命令

实现后至少验证：

- `node --test tests/frontend/rendering.test.mjs tests/frontend/taskData.test.mjs`
- `node --check src/frontend/app.js`

## 11. 完成标准

满足以下条件即可认为本轮完成：

1. `latest_real_run` 任务的执行轨迹区不再只显示状态和日志
2. 能看到阶段、攻击面、收敛状态、下一步建议
3. `fixture` 任务仍保持合理占位说明
4. 前端测试通过
5. 不影响现有任务、摘要、风险详情、导出能力

## 12. 本轮最终边界判断

本轮不是产品重设计，也不是扫描链路重构。

本轮只是把后端已经具备的运行态解释能力，最小、安全、稳定地接进当前前端演示工作台，使平台从“只会显示日志”升级为“能解释真实扫描在做什么、做到哪一步、为何尚未出结果、下一步该怎么办”。
