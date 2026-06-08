"""
Trace Chain Monitor — Trace ID + 全链路调用追踪。

为每一次通过 MemGuard 网关的请求分配全局唯一的 Trace ID，
记录链路中每个步骤的耗时、输入/输出摘要和状态，最终统一写入审计日志。

架构:
  HTTP 请求 → ChainMonitor (创建 Trace)
    → Endpoint (Step 1: filter.check)
    → Endpoint (Step 2: memory.write)
    → ToolProxy (Step 3: tool.call / policy.evaluate)
    → ChainMonitor (结束 Trace → 写入审计日志)

Trace ID 通过 response header `X-Trace-ID` 返回给调用方。
"""

from __future__ import annotations

import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ..audit.audit_log import StructuredAuditLogger


# ── Trace 数据结构 ────────────────────────────────────────────────────────────


@dataclass
class TraceStep:
    """链路中的单个步骤."""

    name: str                            # 步骤名称，如 "filter.check", "policy.evaluate"
    start_time: float                    # 开始时间戳
    end_time: Optional[float] = None     # 结束时间戳
    duration_ms: float = 0.0             # 耗时（毫秒）
    input_summary: str = ""              # 输入摘要（前 200 字符）
    output_summary: str = ""             # 输出摘要（前 200 字符）
    status: str = "pending"              # pending / success / error / blocked

    def finish(self, status: str = "success", output_summary: str = "") -> None:
        """结束步骤，记录耗时和状态."""
        self.end_time = time.time()
        self.duration_ms = round((self.end_time - self.start_time) * 1000, 2)
        self.status = status
        if output_summary:
            self.output_summary = output_summary[:200]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "input_summary": self.input_summary[:200],
            "output_summary": self.output_summary[:200],
        }


@dataclass
class TraceContext:
    """完整的请求追踪上下文."""

    trace_id: str                        # 全局唯一追踪 ID
    start_time: float                    # 请求开始时间
    steps: list[TraceStep] = field(default_factory=list)
    session_hash: str = ""
    source_id: str = ""

    def add_step(self, name: str, input_summary: str = "") -> TraceStep:
        """添加一个新步骤并返回."""
        step = TraceStep(name=name, start_time=time.time(), input_summary=input_summary[:200])
        self.steps.append(step)
        return step

    def to_dict(self) -> dict[str, Any]:
        """将整个 Trace 序列化为字典，用于审计日志."""
        return {
            "trace_id": self.trace_id,
            "timestamp": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "total_duration_ms": round((time.time() - self.start_time) * 1000, 2),
            "session_hash": self.session_hash,
            "source_id": self.source_id,
            "step_count": len(self.steps),
            "steps": [s.to_dict() for s in self.steps],
        }


# ContextVar: 在异步调用链中传递当前 Trace
_current_trace: ContextVar[Optional[TraceContext]] = ContextVar("chain_trace", default=None)


def get_current_trace() -> Optional[TraceContext]:
    """获取当前协程/请求的 TraceContext."""
    return _current_trace.get()


def set_current_trace(trace: Optional[TraceContext]) -> None:
    """设置当前协程/请求的 TraceContext."""
    _current_trace.set(trace)


# ── ChainMonitor ──────────────────────────────────────────────────────────────


class ChainMonitor:
    """
    链路监控器 —— 管理 Trace 的创建、步骤记录和最终落审计日志。

    用法:
        monitor = ChainMonitor(audit_logger)

        # 作为 FastAPI 中间件:
        app.middleware("http")(monitor.middleware)

        # 在端点中记录步骤:
        step = monitor.start_step("filter.check", input_summary=content[:100])
        ...
        monitor.finish_step(step, status="success")

        # 在工具代理中:
        step = monitor.start_step("policy.evaluate", input_summary=tool_name)
        ...
        monitor.finish_step(step, status="blocked")
    """

    def __init__(self, audit_logger: Optional[StructuredAuditLogger] = None):
        self._audit = audit_logger
        self._trace_count = 0

    @property
    def total_traces(self) -> int:
        return self._trace_count

    def set_audit_logger(self, audit_logger: StructuredAuditLogger) -> None:
        """在 lifespan 中设置审计日志记录器（因为 chain_monitor 在 app 创建前初始化）。"""
        self._audit = audit_logger

    def create_trace(
        self,
        session_hash: str = "",
        source_id: str = "",
    ) -> TraceContext:
        """创建一个新的 Trace 并设为当前上下文."""
        trace = TraceContext(
            trace_id=f"trc_{uuid.uuid4().hex[:16]}",
            start_time=time.time(),
            session_hash=session_hash,
            source_id=source_id,
        )
        set_current_trace(trace)
        self._trace_count += 1
        return trace

    def start_step(self, name: str, input_summary: str = "") -> Optional[TraceStep]:
        """在当前 Trace 上开始一个新步骤."""
        trace = get_current_trace()
        if trace is None:
            return None
        return trace.add_step(name, input_summary)

    def finish_step(
        self,
        step: Optional[TraceStep],
        status: str = "success",
        output_summary: str = "",
    ) -> None:
        """结束一个步骤."""
        if step is not None:
            step.finish(status, output_summary)

    def flush_trace(self) -> Optional[dict[str, Any]]:
        """结束当前 Trace，写入审计日志，返回序列化数据."""
        trace = get_current_trace()
        if trace is None:
            return None

        data = trace.to_dict()

        # 写入审计日志
        if self._audit:
            self._audit.log_interception(
                entry_id=f"trace:{trace.trace_id}",
                source_id=trace.source_id,
                action="TRACE_COMPLETE",
                reason=f"trace completed with {len(trace.steps)} steps in {data['total_duration_ms']}ms",
                actor="gateway.chain_monitor",
                extra={"trace_data": data},
            )

        # 清理上下文
        set_current_trace(None)
        return data

    # ── FastAPI 中间件 ────────────────────────────────────────────────────────

    async def middleware(self, request: Any, call_next: Any) -> Any:
        """
        FastAPI HTTP 中间件。

        为每个请求创建 Trace，处理完毕后刷新到审计日志，
        并在响应头中注入 X-Trace-ID。
        """
        # 创建 Trace
        trace = self.create_trace(
            session_hash=request.headers.get("X-Session-Hash", ""),
            source_id=f"http:{request.method}:{request.url.path}",
        )

        step = self.start_step(
            f"http.{request.method}",
            input_summary=f"{request.method} {request.url.path}",
        )

        try:
            response = await call_next(request)
            self.finish_step(
                step,
                status="success" if response.status_code < 400 else "error",
                output_summary=f"status={response.status_code}",
            )
        except Exception as exc:
            self.finish_step(step, status="error", output_summary=str(exc)[:200])
            # 仍然刷新 Trace 再抛异常
            self.flush_trace()
            raise
        finally:
            self.flush_trace()

        # 响应头注入 Trace ID
        response.headers["X-Trace-ID"] = trace.trace_id
        return response
