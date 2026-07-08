# Strix 与 Docker 部署说明

这份文档只解决一件事：让 `latest_real_run` 真实扫描能跑起来，并且可以安全共享给别人使用。

## 1. 必备条件

- Docker Desktop
- Strix CLI
- 可用的 LLM API
- 已授权的测试目标

## 2. Docker 部署

### 2.1 安装

安装 Docker Desktop 并完成首次初始化。

### 2.2 启动

启动 Docker Desktop，等待其进入运行状态。

### 2.3 验证

```powershell
docker --version
docker info
```

判断标准：

- `docker --version` 成功：Docker CLI 已安装
- `docker info` 成功：Docker daemon 已就绪

如果 `docker info` 失败，Strix 真实扫描通常无法工作。

## 3. Strix CLI 部署

### 3.1 安装

确保 `strix` 已安装并加入 PATH。

当前机器上的可执行路径示例：

```text
C:\Users\<用户名>\.strix\bin\strix.exe
```

### 3.2 验证

```powershell
where strix
strix --help
```

判断标准：

- `where strix` 能找到可执行文件
- `strix --help` 能正常输出帮助信息

## 4. Strix API 配置方式

这个项目支持两种方式：

1. 环境变量
2. Strix 本地配置文件

推荐原则：

- 项目仓库不保存任何真实 Key
- 每个使用者在自己电脑上配置自己的 Key
- 不共享你自己的本地 Key 文件

### 4.1 方式 A：环境变量

推荐配置：

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
- 共享项目时，不要把你的真实 Key 写进脚本或 README 示例

### 4.2 方式 B：Strix 内置配置文件

Strix 支持本地配置文件。

Windows 路径：

```text
C:\Users\<用户名>\.strix\cli-config.json
```

推荐模板：

```json
{
  "env": {
    "STRIX_LLM": "deepseek/deepseek-v4-flash",
    "LLM_API_KEY": "在这里填你自己的 Key"
  }
}
```

如果你希望同时兼容 DeepSeek 专用变量：

```json
{
  "env": {
    "STRIX_LLM": "deepseek/deepseek-v4-flash",
    "LLM_API_KEY": "在这里填你自己的 Key",
    "DEEPSEEK_API_KEY": "在这里填你自己的 Key"
  }
}
```

说明：

- 这个文件是每个用户自己的本机配置
- 不应该提交到项目仓库
- 不应该直接把你自己的真实版本发给别人

## 5. 共享给别人时怎么做

正确做法：

1. 仓库中只保留文档和模板
2. 不在源码、脚本、提交记录里写死真实 Key
3. 每个使用者自己选择：
   - 配环境变量
   - 或创建 `C:\Users\<用户名>\.strix\cli-config.json`

错误做法：

- 把你自己的 `LLM_API_KEY` 发给别人
- 把你自己的 `C:\Users\<用户名>\.strix\cli-config.json` 原样共享给别人
- 把真实 Key 直接提交进仓库

## 6. 最小自检流程

先进入项目目录：

```powershell
cd C:\Users\MMK20041021\Desktop\workspace\01_新项目
```

按顺序检查：

### 6.1 检查 Docker

```powershell
docker info
```

### 6.2 检查 Strix

```powershell
strix --help
```

### 6.3 检查 API 配置是否已生效

至少满足一类：

- 已设置 `STRIX_LLM`
- 已设置 `LLM_API_KEY` 或 `DEEPSEEK_API_KEY`

或者：

- 已创建 `C:\Users\<用户名>\.strix\cli-config.json`

### 6.4 检查真实扫描最小命令

```powershell
strix -n --target ./src/frontend
```

期望结果：

- 命令能启动
- 不会立即因为缺少 Docker 或 Key 而退出
- 项目目录下会生成或更新 `strix_runs/`

## 7. 与本项目的关系

真实扫描链路是：

1. 前端创建 `latest_real_run` 任务
2. 后端显式调用 Strix
3. Strix 把产物写入 `strix_runs/`
4. 平台从 `strix_runs/` 读取：
   - 运行态
   - summary
   - vulnerabilities
5. 页面实时展示并允许导出报告

所以真实扫描能不能跑通，关键不在前端，而在下面 4 件事：

1. Docker daemon 是否正常
2. Strix CLI 是否可调用
3. LLM API 是否配置完成
4. 当前使用者是否在用自己的 Key

## 8. 常见失败原因

### 8.1 Docker 没启动

现象：

- `docker info` 失败
- Strix 很快退出

处理：

- 启动 Docker Desktop
- 等待 daemon 就绪后再试

### 8.2 API Key 没配

现象：

- Strix 启动后很快报错
- 没有有效扫描结果

处理：

- 重新设置 `LLM_API_KEY`
- 建议同时设置 `DEEPSEEK_API_KEY`
- 或重新创建自己的 `~/.strix/cli-config.json`

### 8.3 共享给别人后，别人仍在用你的 Key

现象：

- 别人可以运行，但实际上仍然消耗你的额度
- 换电脑后环境来源不透明

处理：

- 删除共享出去的真实 Key
- 改成模板 + 文档
- 让每个使用者自己填写本机配置

### 8.4 Strix CLI 没进 PATH

现象：

- `where strix` 找不到
- `strix --help` 失败

处理：

- 把 `strix.exe` 所在目录加入 PATH
- 重新打开终端

## 9. 成功标准

当下面 5 条都成立时，可以认为真实扫描环境已基本部署完成：

1. `docker info` 成功
2. `strix --help` 成功
3. 当前使用者已配置自己的 API，而不是复用他人的 Key
4. `strix -n --target ./src/frontend` 能启动并写入 `strix_runs/`
5. 页面中的 `latest_real_run` 任务可以成功点击 `run`

## 10. 下一步

环境就绪后，回到项目根目录，按 [README.md](C:/Users/MMK20041021/Desktop/workspace/01_新项目/README.md) 的“项目启动全过程”启动平台。
