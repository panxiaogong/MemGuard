# MemGuard — 当前会话状态

> 生成时间：2026-06-07
> 用途：新窗口读取此文件以了解对话进度，继续工作

---

## 项目概览

MemGuard 是一个面向大模型 Agent 长期记忆系统的安全防护框架，参加信息安全竞赛。
项目 GitHub：https://github.com/panxiaogong/MemGuard
当前分支：main

---

## 已完成的工作

### 原有功能（无需改动）

| 模块 | 职责 |
|------|------|
| `gateway/proxy.py` | FastAPI 网关，读写双路径 |
| `gateway/filters.py` | 同步过滤器：Prompt Injection / Jailbreak / 伪造标签 / PII脱敏 |
| `gateway/immune_client.py` | IMAG 免疫检测 + 主动免疫双Agent |
| `models/memory_entry.py` | MemoryEntry 安全记忆对象 + Ed25519 签名 + 审计链 |
| `db/chroma_wrapper.py` | ChromaDB 向量存储封装 |
| `db/lance_wrapper.py` | LanceDB 向量存储封装（备选） |
| `scanner/periodic_scanner.py` | 周期性记忆扫描（Constitutional AI） |
| `scanner/constitutional.py` | 宪法AI原则 + 快速正则检测 |
| `audit/audit_log.py` | 结构化 JSONL 审计日志 |
| `cli.py` | CLI 命令行工具（start/demo/health） |
| `static/` | Web 仪表盘（index.html + app.js + style.css） |
| `agent_demo.py` | 原有 Agent 接入演示（仅记忆读写） |

### 本轮新增（工具调用监控层）

**新增文件清单：**

| 文件 | 说明 |
|------|------|
| `tools/base.py` | 工具基类 BaseTool + 注册中心 ToolRegistry |
| `tools/email_tool.py` | 模拟邮件工具（检测可疑域名、钓鱼内容、批量发送） |
| `tools/file_tool.py` | 模拟文件工具（检测系统路径、路径穿越、自修改、危险扩展名） |
| `tools/api_tool.py` | 模拟API调用工具（检测内网目标、敏感TLD、URL中凭据泄露） |
| `tools/shell_tool.py` | 模拟Shell执行工具（检测反向shell、rm -rf、提权、混淆命令） |
| `tools/__init__.py` | 包导出 |
| `gateway/policy_engine.py` | 安全策略引擎（allow/deny/ask 三级决策 + 速率限制 + 审批工作流） |
| `gateway/tool_proxy.py` | 工具调用拦截代理（参数验证→策略评估→执行/阻断→审计全链路） |

**修改的文件清单：**

| 文件 | 改动内容 |
|------|----------|
| `gateway/proxy.py` | 引入 ToolProxy，lifespan 中初始化并注册路由到 `/v1/tools`，health接口增加 tool_proxy 状态 |
| `gateway/__init__.py` | 导出 PolicyEngine / ToolProxy / ToolCallResponse |
| `pyproject.toml` | 新增 `MemGuard.tools` 包 |

**新增 API 端点：**

```
POST /v1/tools/call          # AI调工具的统一入口
GET  /v1/tools/list          # 查看有哪些工具可用
GET  /v1/tools/pending       # 查看待人工审批的调用
POST /v1/tools/approve       # 人工批准/拒绝
GET  /v1/tools/policies      # 查看当前安全策略
POST /v1/tools/policies      # 添加新策略
DELETE /v1/tools/policies/{rule_id} # 删除策略
GET  /v1/tools/stats         # 统计信息
```

**默认安全策略（11条已硬编码在`gateway/policy_engine.py`的`_DEFAULT_POLICIES`中）：**

| 策略ID | 匹配条件 | 行为 | 优先级 |
|--------|---------|------|--------|
| `default_shell_deny_high_risk` | run_command 含 rm -rf/nc -e/mkfs/dd | DENY | 100 |
| `default_shell_ask` | run_command 任意参数 | ASK | 10 |
| `default_file_deny_system` | file_io 路径含 /etc/ /boot/ /var/log/ /.ssh/ /.git/ | DENY | 100 |
| `default_file_deny_destructive` | file_io 操作=delete + 路径含 /bin/ /sbin/ /usr/ /opt/ | DENY | 90 |
| `default_file_ask_write` | file_io 操作=write/append/delete | ASK | 10 |
| `default_api_deny_internal` | call_api URL含内网IP(localhost/10./192.168./172.x) | DENY | 100 |
| `default_api_ask_external` | call_api 任意参数 | ASK | 10 |
| `default_email_deny_suspicious` | send_email to含tempmail/throwaway/mailinator等 | DENY | 100 |
| `default_email_ask` | send_email to不为空 | ASK | 10 |
| `default_unknown_tool_ask` | 所有工具（兜底） | ASK | 0 |

---

## 下一步工作计划

### 当前优先级排序

```
P0 ✅ 工具调用拦截代理 + 模拟业务工具集（已完成）
P1 🔜 集成开源Agent应用（当前目标）
P2 ⬜ 攻击场景脚本 + 测试用例集
P3 ⬜ 安全风险分析报告文档
P4 ⬜ 模型调用链路监控
P5 ⬜ 基座模型检测/过滤原型
P6 ⬜ Web仪表盘实时告警
P7 ⬜ 扩展对抗样本数据集
```

### 下一步：集成开源 Agent 应用（已完成）

**目标**：写一个 LangChain Agent Demo 脚本，通过 MemGuard 的 ToolProxy 调工具，展示完整链路。

**新建文件**：[scripts/agent_memguard_langchain.py](scripts/agent_memguard_langchain.py)

**架构**：
```
LangChain Agent (create_agent) → MemGuardProxyTool → POST /v1/tools/call → PolicyEngine → ALLOW / DENY / ASK
```

**5 个 LangChain 工具（均通过 MemGuard 安全网关代理）：**

| 工具名 | 类名 | 参数 | 安全策略 |
|--------|------|------|---------|
| `send_email` | SendEmailTool | to, subject, body, cc, priority | 公司域名 ALLOW / 可疑域名 DENY |
| `run_command` | RunCommandTool | command, cwd, timeout | rm -rf 等高危 DENY |
| `call_api` | CallApiTool | url, method, headers, body | 内网 DENY / 外部 ASK |
| `file_io` | FileIOTool | operation, path, content | 系统路径 DENY |
| `search_memory` | SearchMemoryTool | query | 直接查记忆库（非工具调用） |

**4 个演示场景已验证通过（代码级验证）：**

| 场景 | 触发方式 | MemGuard 反应 |
|:----:|----------|--------------|
| 1️⃣ 正常邮件 | send_email to @company.com | ✅ ALLOW（demo 白名单策略） |
| 2️⃣ 危险拦截 | run_command rm -rf | ❌ DENY（高危命令策略） |
| 3️⃣ 需审批 | call_api 外部 URL | ⏳ ASK → 模拟审批通过 |
| 4️⃣ 双层防护 | 记忆投毒 → send_email to tempmail | 🔒 记忆层 + 工具层拦截 |

**运行方式：**
```bash
# 先关掉梯子，然后输入这个命令启动网关
python -m uvicorn MemGuard.gateway.proxy:app --port 8080
# 另开一终端
python scripts/agent_memguard_langchain.py
```

**技术要点：**
- 使用 LangChain 新版 `create_agent` (graph-based, langgraph)
- 工具通过 `BaseTool` 子类 + `args_schema` (Pydantic) 定义参数
- 调用通过 `MemGuardClient.call_tool()` → HTTP POST → MemGuard 网关
- 记忆搜索直接调 `/v1/memory/read`（非工具类操作）
- 审批流程通过 `POST /v1/tools/approve` 模拟管理员操作
- 运行前需 `.env` 配置 `OPENAI_API_KEY`

**依赖：** langchain>=1.3, langchain-openai, openai, httpx, pydantic, python-dotenv

---

### 再往后：剩余任务简要规划

#### P2: 攻击场景脚本 + 测试用例集 (`scripts/`, `tests/attacks/`)
- 场景A：工具调用劫持（邮件重定向、文件泄露、内网扫描）
- 场景B：记忆投毒 + RAG 污染（条件式指令劫持、工具参数篡改）
- 场景C：多轮越狱 + 工具链组合攻击（渐进式诱导、Base64编码绕过）
- 每个场景：一个攻击脚本 + 一个 JSON 数据集

#### P3: 安全风险分析报告 (`docs/safety_report.md`)
- 攻击面分析（提示注入/越狱/数据泄露/记忆投毒/工具劫持/多轮攻击）
- 对抗样本与越狱测试用例集
- 防御策略（输入输出过滤/上下文隔离/模型行为监测/工具调用监控/安全策略引擎）
- 系统测试结果

#### P4: 模型调用链路监控 (`gateway/chain_monitor.py`)
- Trace ID 跟踪完整链路
- 每步耗时记录
- 输入输出摘要
- 审计日志增强

#### P5: 基座模型检测/过滤原型 (`scanner/local_detector.py`)
- 方案A：ONNX + 小型 BERT 模型做二分类
- 方案B：KeyBERT + 语义相似度（更轻量）
- 集成到 SyncFilter 链中

#### P6: Web 仪表盘实时告警
- `gateway/proxy.py` 加 WebSocket 端点 `/ws/alerts`
- `static/app.js` 加 WebSocket 客户端
- 阻断告警 🔴 / 待审批 🟡 / 检测告警 🔵

#### P7: 扩展对抗样本数据集
- Crescendo / DeepInception / Base64绕过 / Unicode绕过 / 翻译绕过 / 角色扮演 / Few-shot诱导

---

### 组员信息文档
组员进度同步文档：[docs/progress_report.md](docs/progress_report.md) — 包含已完成工作、技术架构图、剩余任务分工建议。

---

## 技术要点（新窗口的人注意）

### 已验证通过的功能
- `policy_engine.py` 的策略判定逻辑：send_email→tempmail→DENY, rm -rf→DENY, 普通API→ASK 都已通过测试
- 所有模块可以独立 import（只要 openai 包装了）

### 已知问题
- `gateway/__init__.py` 会导致 import 时尝试加载 openai，如果没有安装会报错。测试时可以直接 import policy_engine 绕过

### 运行方式
```bash
# 启动网关
python -m uvicorn MemGuard.gateway.proxy:app --port 8080

# 测试工具代理
curl -X POST "http://localhost:8080/v1/tools/call" \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "send_email", "parameters": {"to": ["admin@evil.com"], "subject": "test", "body": "test"}}'

# 查看策略
curl "http://localhost:8080/v1/tools/policies"

# 查看工具列表
curl "http://localhost:8080/v1/tools/list"
```

---

## 对话上下文（供参考）

用户是竞赛参与者，项目在 `d:\Codes\XinAn\MemGuard`，Windows 环境，Python 3.13，conda 环境名 `andymemg`。
已完成的对话内容包括：
1. 全面分析现有代码与竞赛命题要求的差距
2. 按优先级排序完善计划
3. 实施第一优先级：工具调用拦截代理 + 模拟业务工具集（完成并验证通过）
4. 当前正转向第二优先级：集成开源Agent应用
