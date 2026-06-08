# MemGuard — 当前会话状态

> 生成时间：2026-06-08
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
| `scripts/agent_memguard_langgraph.py` | LangGraph ReAct Agent 集成演示（4 场景安全展示） |

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

### 下一步：集成开源 Agent 应用（正确方向）

**注意：** 之前方向理解错误——不是自己写一个 Agent，而是拿**市面上已有的开源 Agent**，把 MemGuard 作为安全中间件插进去。

**计划使用**：`langgraph.prebuilt.create_react_agent`（LangGraph 官方开源的 ReAct Agent，已安装）。

**集成方案：**

```
LangGraph ReAct Agent (现成的开源Agent)
  ↓ 调用工具
MemGuardProxyTool (安全包装层 — 我们不写Agent逻辑，只封装安全层)
  ↓ HTTP POST /v1/tools/call
MemGuard 网关 → PolicyEngine (ALLOW/DENY/ASK)
```

**核心思路：**
- 不写 Agent 推理逻辑——`create_react_agent` 自带 ReAct 循环
- 只写工具封装层（`MemGuardProxyTool`），拦截它的工具调用到 MemGuard 网关
- Agent 感知不到 MemGuard 的存在，安全性是透明的

**计划新建文件：** `scripts/agent_memguard_langgraph.py`

**需要演示的 4 个场景：**

| 场景 | 触发方式 | MemGuard 反应 |
|:----:|----------|--------------|
| 1️⃣ 正常邮件 | send_email to 白名单域名 | ✅ ALLOW |
| 2️⃣ 危险拦截 | run_command rm -rf | ❌ DENY |
| 3️⃣ 需审批 | call_api 外部 URL | ⏳ ASK → 模拟审批通过 |
| 4️⃣ 双层防护 | 记忆投毒 + 诱导发信到可疑地址 | 🔒 记忆层 + 工具层拦截 |

**前置条件：**
- `.env` 中配置 `OPENAI_API_KEY`
- MemGuard 网关先启动：`uvicorn gateway.proxy:app --port 8080`
- 环境 `andymemg` 已有 `langgraph`、`langchain-openai`、`httpx`

**注意事项：**
- 不需要改任何现有代码
- Agent 只通过 HTTP 跟 MemGuard 通信（`POST /v1/tools/call`）

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

## 技术要点（新窗口的人注意）

### 已验证通过的功能
- `policy_engine.py` 的策略判定逻辑：send_email→tempmail→DENY, rm -rf→DENY, 普通API→ASK 都已通过测试
- 所有模块可以独立 import（只要 openai 包装了）

### 已知问题
- `gateway/__init__.py` 会导致 import 时尝试加载 openai，如果没有安装会报错。测试时可以直接 import policy_engine 绕过

### 运行方式
```bash
# 启动网关
uvicorn gateway.proxy:app --host 0.0.0.0 --port 8080

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

用户是竞赛参与者，项目在 `d:\Codes\XinAn\MemGuard`，Windows 环境，Python 3.10+，conda 环境名 `andymemg`。
已完成的对话内容包括：
1. 全面分析现有代码与竞赛命题要求的差距
2. 按优先级排序完善计划
3. 实施第一优先级：工具调用拦截代理 + 模拟业务工具集（完成并验证通过）
4. ~~尝试了 LangChain Agent 集成，方向理解错误，已回退~~
5. 纠正方向：集成现有开源 Agent（`langgraph.prebuilt.create_react_agent`）→ 下一窗口执行
