"""
MemGuard CLI — Agent Memory Protection Engine command-line interface.

Usage:
    memguard start    启动 FastAPI 网关服务
    memguard demo     运行 Agent 集成演示
    memguard health   检查网关健康状态
    memguard --help   显示帮助
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import NoReturn


def _get_version() -> str:
    try:
        from importlib.metadata import version
        return version("memguard")
    except Exception:
        return "0.1.0-dev"


# ── Subcommand: start ──────────────────────────────────────────────────

def cmd_start(args: argparse.Namespace) -> None:
    """启动 FastAPI 网关服务"""
    from MemGuard.config import settings
    import uvicorn

    host = args.host or settings.gateway_host
    port = args.port or settings.gateway_port

    try:
        uvicorn.run(
            "MemGuard.gateway.proxy:app",
            host=host,
            port=port,
            reload=args.reload,
            log_level=args.log_level,
        )
    except OSError as exc:
        print(f"错误：无法启动网关 — {exc}", file=sys.stderr)
        sys.exit(1)


# ── Subcommand: demo ───────────────────────────────────────────────────

def cmd_demo(args: argparse.Namespace) -> None:
    """运行 Agent 集成演示"""
    from MemGuard.agent_demo import main as demo_main

    try:
        asyncio.run(demo_main())
    except KeyboardInterrupt:
        print("\n演示已被用户中断。")
        sys.exit(130)
    except Exception as exc:
        print(f"错误：演示运行失败 — {exc}", file=sys.stderr)
        sys.exit(1)


# ── Subcommand: health ─────────────────────────────────────────────────

def cmd_health(args: argparse.Namespace) -> None:
    """检查网关健康状态"""

    async def _check() -> None:
        import httpx

        base_url = args.url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{base_url}/v1/health")
        except httpx.ConnectError:
            print(
                f"错误：无法连接到 {base_url}，请确认网关已启动。",
                file=sys.stderr,
            )
            sys.exit(1)
        except httpx.TimeoutException:
            print(f"错误：连接 {base_url} 超时。", file=sys.stderr)
            sys.exit(1)

        if resp.status_code == 200:
            data = resp.json()
            print(f"状态：         {data['status']}")
            print(f"攻击库：       {data['attack_bank_size']}")
            print(f"良性库：       {data['benign_bank_size']}")
            print(f"扫描器运行中： {data['scanner_running']}")
            print(f"存储后端：     {data['store']}")
            sys.exit(0)
        else:
            print(
                f"错误：健康检查返回 HTTP {resp.status_code}",
                file=sys.stderr,
            )
            sys.exit(1)

    asyncio.run(_check())


# ── Argument parser ────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memguard",
        description="MemGuard: AI Agent Memory Protection Engine (AMP Engine)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "使用示例：\n"
            "  memguard start              启动网关（默认 host:port）\n"
            "  memguard start --port 9090  指定端口启动\n"
            "  memguard start --reload     开发模式（自动重载）\n"
            "  memguard demo               运行集成演示\n"
            "  memguard health             检查 localhost:8080 健康状态\n"
            "  memguard health --url http://192.168.1.10:8080\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
        help="显示版本号并退出",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{start,demo,health}",
    )

    # --- start ---
    start_p = subparsers.add_parser(
        "start",
        help="启动 FastAPI 网关服务",
        description=(
            "启动 MemGuard FastAPI 网关。"
            "默认从 .env 或环境变量读取 GATEWAY_HOST 和 GATEWAY_PORT。"
        ),
    )
    start_p.add_argument(
        "--host",
        default=None,
        help="监听地址（默认：GATEWAY_HOST 或 0.0.0.0）",
    )
    start_p.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="端口号（默认：GATEWAY_PORT 或 8080）",
    )
    start_p.add_argument(
        "--reload",
        action="store_true",
        help="启用自动重载（开发模式）",
    )
    start_p.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="日志级别（默认：info）",
    )

    # --- demo ---
    subparsers.add_parser(
        "demo",
        help="运行 Agent 集成演示",
        description="运行三个场景的 Agent 集成演示（需要网关已启动）。",
    )

    # --- health ---
    health_p = subparsers.add_parser(
        "health",
        help="检查网关健康状态",
        description="对运行中的 MemGuard 网关执行健康检查。",
    )
    health_p.add_argument(
        "-u", "--url",
        default="http://localhost:8080",
        help="网关地址（默认：http://localhost:8080）",
    )

    return parser


# ── Entry point ────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    """CLI 入口：解析参数并分发到对应子命令。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    command_dispatch: dict[str, object] = {
        "start":  cmd_start,
        "demo":   cmd_demo,
        "health": cmd_health,
    }

    handler = command_dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(args)


if __name__ == "__main__":
    main()
