# MemGuard 项目进度报告

> **日期：** 2026-06-07
> **项目地址：** https://github.com/panxiaogong/MemGuard
> **环境：** conda `andymemg` / Python 3.10+ / Windows

---

## 一、项目总览

MemGuard 是一个面向大模型 Agent 长期记忆系统的安全防护框架，参赛作品。核心能力：

| 层次 | 功能 | 状态 |
|------|------|------|
| 🧠 记忆安全层 | Prompt 注入检测 / PII 脱敏 / 免疫检测 / 周期性扫描 | ✅ 已有 |
| 🛡️ 工具安全层 | 工具调用拦截 / 策略引擎 / 审批工作流 | ✅ **本轮新增** |
| 🤖 Agent 集成 | LangChain Agent 通过安全网关调工具 | ✅ **本轮新增** |
| 📋 审计 | 所有操作全链路 JSONL 审计日志 | ✅ 已有 |

---

## 二、本轮完成的工作（P0 + P1）

### P0：工具调用监控与安全策略引擎

统一了 AI Agent 调用外部工具的入口，所有工具调用必经安全网关。

#### 新增文件

| 文件 | 干什么的 |
|------|----------|
| `tools/base.py` | 工具基类 + ToolRegistry 注册中心 |
| `tools/email_tool.py` | 模拟邮件工具（检测可疑域名/钓鱼/批量发送） |
| `tools/file_tool.py` | 模拟文件工具（检测路径穿越/自修改/危险扩展名） |
| `tools/api_tool.py` | 模拟 API 调用工具（检测内网/敏感TLD/凭据泄露） |
| `tools/shell_tool.py` | 模拟 Shell 工具（检测反向shell/rm -rf/提权/混淆） |
| `gateway/policy_engine.py` | 🎯 核心：安全策略引擎（ALLOW/DENY/ASK 三级 + 速率限制 + 审批工作流） |
| `gateway/tool_proxy.py` | 🎯 核心：工具调用拦截代理（参数校验→策略评估→执行/阻断→审计） |

#### 已硬编码的 11 条默认安全策略（在 `policy_engine.py` 的 `_DEFAULT_POLICIES` 中）

| 策略 | 条件 | 行为 | 优先级 |
|------|------|------|--------|
| Shell 高危命令 | rm -rf / nc -e / mkfs / dd | ❌ DENY | 100 |
| Shell 一般 | 任意 run_command | ⏳ ASK | 10 |
| 文件系统路径 | /etc/ /boot/ /var/log/ /.ssh/ /.git/ | ❌ DENY | 100 |
| 文件破坏性删除 | delete + /bin/ /sbin/ /usr/ /opt/ | ❌ DENY | 90 |
| 文件写操作 | write/append/delete | ⏳ ASK | 10 |
| API 内网 | localhost / 10.* / 192.168.* | ❌ DENY | 100 |
| API 外部 | 任意 call_api | ⏳ ASK | 10 |
| 邮件可疑域名 | to 含 tempmail/throwaway/mailinator 等 | ❌ DENY | 100 |
| 邮件发送 | to 非空 | ⏳ ASK | 10 |
| 兜底策略 | 所有工具 | ⏳ ASK | 0 |

**这就是 MemGuard 的"工具防火墙"。**

#### 新增 API 端点（FastAPI）

| 端点 | 用途 |
|------|------|
| `POST /v1/tools/call` | **AI 调工具的唯一入口** |
| `GET /v1/tools/list` | 查看工具列表 |
| `GET /v1/tools/pending` | 查看待审批调用 |
| `POST /v1/tools/approve` | 审批/拒绝 |
| `GET /v1/tools/policies` | 查看/管理安全策略 |
| `DELETE /v1/tools/policies/{id}` | 删除策略 |
| `GET /v1/tools/stats` | 统计信息 |

#### 架构图

```
Agent → POST /v1/tools/call → ToolProxy
  → 1️⃣ 参数校验
  → 2️⃣ PolicyEngine 评估 (allow / deny / ask)
  → 3️⃣ 执行 或 阻断
  → 4️⃣ 写审计日志
```

---

### P1：开源 Agent 应用集成（LangChain）

新增文件：**`scripts/agent_memguard_langchain.py`**

#### 架构

```
LangChain Agent (create_agent)
  → MemGuardProxyTool (BaseTool 子类)
    → MemGuardClient.call_tool()  HTTP POST
      → 网关 /v1/tools/call
        → PolicyEngine 评估 (ALLOW/DENY/ASK)
```

#### 5 个工具映射

Agent 能调用的 5 个工具，全部经过 MemGuard 安全代理：

| LangChain 工具 | 类名 | 参数 | 安全策略 |
|---------------|------|------|---------|
| `send_email` | SendEmailTool | to, subject, body, cc, priority | @company.com→ALLOW, tempmail→DENY |
| `run_command` | RunCommandTool | command, cwd, timeout | rm -rf→DENY, 其他→ASK |
| `call_api` | CallApiTool | url, method, headers, body | 内网→DENY, 外网→ASK |
| `file_io` | FileIOTool | operation, path, content | 系统路径→DENY |
| `search_memory` | SearchMemoryTool | query | 直接读记忆库（安全过滤后） |

#### 4 个演示场景

| 场景 | 用户输入 | Agent 操作 | MemGuard 反应 |
|:----:|----------|------------|--------------|
| 1️⃣ 正常邮件 | "发邮件通知项目延期" | `send_email` to @company.com | ✅ **ALLOW**（白名单） |
| 2️⃣ 危险拦截 | "删掉 /data 目录" | `run_command` rm -rf | ❌ **DENY**（高危命令） |
| 3️⃣ 审批流程 | "查天气 API" | `call_api` 外部 URL | ⏳ **ASK** → 模拟审批通过 |
| 4️⃣ 双层防御 | 记忆投毒→诱导发信 | `search_memory` → `send_email` to tempmail | 🔒 **记忆层+工具层** 双层拦截 |

#### 运行方法

```bash
conda activate andymemg

# 终端 1 — 启动 MemGuard 网关
uvicorn gateway.proxy:app --host 0.0.0.0 --port 8080

# 终端 2 — 运行 Agent 演示
python scripts/agent_memguard_langchain.py
```

> 前置条件：`.env` 中配置 `OPENAI_API_KEY`

---

## 三、技术架构全景图（当前状态）

```
用户 / 攻击者
    │
    ▼
┌───────────────────────────────────────────┐
│          FastAPI 网关 (:8080)              │
│  ┌─────────────┐  ┌──────────────────┐    │
│  │ /v1/memory  │  │  /v1/tools       │    │
│  │   read/write│  │    call / approve │    │
│  └──────┬──────┘  └────────┬─────────┘    │
│         │                  │              │
│  ┌──────▼──────┐  ┌───────▼──────────┐   │
│  │ SyncFilter  │  │  ToolProxy       │   │
│  │ (注入/PII)  │  │  →参数校验       │   │
│  └──────┬──────┘  │  →PolicyEngine   │   │
│         │         │  →执行/阻断      │   │
│  ┌──────▼──────┐  │  →审计日志       │   │
│  │ImmuneDetect │  └───────┬──────────┘   │
│  │+ ActiveImm │          │              │
│  └──────┬──────┘          │              │
│         │                 │              │
│  ┌──────▼──────┐          │              │
│  │ ChromaDB    │          │              │
│  │ (记忆存储)  │          │              │
│  └─────────────┘          │              │
└───────────────────────────┼──────────────┘
                            │
                    ┌───────▼──────────┐
                    │  模拟工具集       │
                    │  邮件/文件/API/Shell│
                    └──────────────────┘

审计日志 (JSONL) ← 所有操作全记录
```

---

## 四、待完成任务（P2~P7）

### P2 ⬜ 攻击场景脚本 + 测试用例集

**目标：** 写攻击脚本，验证 MemGuard 能不能防住

| 场景 | 攻击手法 | 预期防御 |
|:----:|----------|----------|
| A | 工具调用劫持 — 邮件重定向、文件泄露、内网扫描 | ToolProxy 阻断 |
| B | 记忆投毒 + RAG 污染 — 条件式指令劫持 | ImmuneDetector / SyncFilter |
| C | 多轮越狱 + 工具链组合攻击 — 渐进式诱导、Base64 编码绕过 | PolicyEngine 链式检测 |

输出：`scripts/` 下每个场景一个脚本 + `tests/attacks/` JSON 数据集

---

### P3 ⬜ 安全风险分析报告

**目标：** 一份完整的 Markdown 报告

- 攻击面分析（6+ 个维度）
- 对抗样本与测试用例
- 防御策略汇总
- 测试结果

输出：`docs/safety_report.md`

---

### P4 ⬜ 模型调用链路监控

**目标：** TraceID + 耗时 + 输入输出摘要

输出：`gateway/chain_monitor.py`

---

### P5 ⬜ 基座模型检测/过滤原型

**目标：** 本地小模型辅助检测

- 方案 A：ONNX + BERT 二分类
- 方案 B：KeyBERT + 语义相似度

输出：`scanner/local_detector.py`

---

### P6 ⬜ Web 仪表盘实时告警

**目标：** WebSocket 实时推送

- 阻断告警 🔴 / 待审批 🟡 / 检测告警 🔵

---

### P7 ⬜ 扩展对抗样本数据集

**目标：** 收集更多攻击手法

- Crescendo / DeepInception / Base64 绕过
- Unicode 绕过 / 翻译绕过 / 角色扮演 / Few-shot 诱导

---

## 五、快速速查

### 目录结构

```
MemGuard/
├── gateway/
│   ├── proxy.py          # FastAPI 网关主入口
│   ├── tool_proxy.py     # 🔥 工具调用拦截代理
│   ├── policy_engine.py  # 🔥 安全策略引擎
│   ├── filters.py        # 同步过滤器
│   └── immune_client.py  # 免疫检测
├── tools/
│   ├── base.py           # 工具基类
│   ├── email_tool.py     # 模拟邮件
│   ├── file_tool.py      # 模拟文件
│   ├── api_tool.py       # 模拟 API
│   └── shell_tool.py     # 模拟 Shell
├── scripts/
│   └── agent_memguard_langchain.py  # 🔥 LangChain Agent 集成演示
├── docs/
│   └── progress_report.md           # 👈 本文件
├── CLAUDE_SESSION.md     # Claude Code 会话状态
└── .env                  # API Key 配置
```

### 快速测试命令

```bash
# 1. 启动网关
uvicorn gateway.proxy:app --host 0.0.0.0 --port 8080

# 2. 测试工具调用拦截
curl -X POST "http://localhost:8080/v1/tools/call" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "send_email", "parameters": {"to": ["admin@tempmail.com"], "subject": "test", "body": "test"}}'
# → 应该返回 "blocked" + "send_email_deny_suspicious"

# 3. 查看策略
curl "http://localhost:8080/v1/tools/policies"

# 4. 查看工具列表
curl "http://localhost:8080/v1/tools/list"

# 5. 运行 Agent 演示
python scripts/agent_memguard_langchain.py
```

### 注意事项

- `conda` 环境名：`andymemg`（已装好 langchain / openai / httpx 等）
- `.env` 文件需在项目根目录，至少配置 `OPENAI_API_KEY`
- `gateway/__init__.py` 加载时会尝试 import openai，如果报错可独立 import `policy_engine` 绕过
- 审计日志写入：`logs/memguard_audit.jsonl`

---

## 六、各队友可以做什么

| 角色 | 建议任务 |
|------|----------|
| 🛡️ 安全测试 | **P2** — 写攻击脚本，验证四种工具的阻断效果 |
| 📝 文档 | **P3** — 写安全风险分析报告，整理攻击面 |
| 🔧 后端 | **P4** — TraceID 链路监控 / **P5** — 本地检测模型 |
| 🎨 前端 | **P6** — WebSocket 实时告警仪表盘 |
| 📊 数据 | **P7** — 收集+整理对抗样本数据集 |
