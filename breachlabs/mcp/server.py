"""Model Context Protocol (MCP) Streamable HTTP & SSE Server.

Implements the official Model Context Protocol (MCP 2024-11-05 specification)
over Streamable HTTP / Server-Sent Events (SSE) transport.

Endpoints:
- GET  /mcp or /mcp/sse       - Connect SSE stream, receive session endpoint URI
- POST /mcp or /mcp/messages  - Send JSON-RPC 2.0 requests (initialize, tools/list, tools/call, ping)
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from breachlabs.mcp.tool import ToolContext, ToolError
from breachlabs.mcp.tools import build_default_registry

mcp_router = APIRouter()

# Active SSE connection queues: session_id -> asyncio.Queue[str]
_sessions: dict[str, asyncio.Queue[str]] = {}

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "breachlabs-mcp",
    "version": "0.1.0",
}


def _build_error_response(
    request_id: Any, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


def _build_success_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _get_tool_context(params: dict[str, Any]) -> ToolContext:
    """Extract or construct a ToolContext from JSON-RPC call params / env."""
    context_data = params.get("context", {})
    repo_path = (
        context_data.get("repo_path")
        or params.get("repo_path")
        or os.environ.get("BREACHLABS_REPO_PATH")
        or os.getcwd()
    )
    target_base_url = (
        context_data.get("target_base_url")
        or params.get("target_base_url")
        or os.environ.get("BREACHLABS_TARGET_URL")
        or "http://127.0.0.1:5000"
    )
    assessment_id = context_data.get("assessment_id", f"mcp-{uuid.uuid4().hex[:8]}")
    allowed_hosts = context_data.get(
        "allowed_hosts", ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    )

    return ToolContext(
        assessment_id=assessment_id,
        repo_path=repo_path,
        target_base_url=target_base_url,
        allowed_hosts=allowed_hosts,
    )


async def handle_jsonrpc_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 message."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _build_error_response(
            msg.get("id") if isinstance(msg, dict) else None,
            -32600,
            "Invalid Request: missing jsonrpc='2.0'",
        )

    method = msg.get("method")
    req_id = msg.get("id")
    params = msg.get("params", {}) or {}

    if not isinstance(method, str):
        return _build_error_response(req_id, -32600, "Invalid Request: missing method")

    # Notifications (messages without an ID)
    if req_id is None:
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "notifications/cancelled":
            return None
        return None

    # Methods
    if method == "initialize":
        from breachlabs.mcp.skill_check import check_skill_installation
        skill_status = check_skill_installation()
        instructions = (
            "You are connected to BreachLabs Autonomous Security MCP.\n"
            + (f"{skill_status['prompt']}\n\n" if not skill_status["skill_installed"] else "")
            + "Use breachlabs tools (inspect_repository, list_routes, run_static_scan, scan_secrets, check_health, run_dast, verify_installation) "
            "to perform autonomous application security assessments."
        )
        return _build_success_response(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    },
                    "prompts": {
                        "listChanged": False,
                    },
                    "logging": {},
                },
                "serverInfo": SERVER_INFO,
                "instructions": instructions,
                "skillInstalled": skill_status["skill_installed"],
            },
        )

    if method == "ping":
        return _build_success_response(req_id, {})

    if method in ("tools/list", "mcp.list_tools"):
        registry = build_default_registry()
        tool_schemas = [tool.mcp_schema() for tool in registry._tools.values()]
        return _build_success_response(req_id, {"tools": tool_schemas})

    if method in ("tools/call", "mcp.call_tool"):
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        if not isinstance(tool_name, str):
            return _build_error_response(
                req_id, -32602, "Invalid params: 'name' is required for tools/call"
            )

        registry = build_default_registry()
        if not registry.has(tool_name):
            return _build_success_response(
                req_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error: Tool '{tool_name}' not found in BreachLabs registry.",
                        }
                    ],
                    "isError": True,
                },
            )

        context = _get_tool_context(params)
        try:
            tool_result = registry.run(tool_name, tool_args, context)
            text_output = (
                json.dumps(tool_result, indent=2)
                if isinstance(tool_result, (dict, list))
                else str(tool_result)
            )
            return _build_success_response(
                req_id,
                {
                    "content": [{"type": "text", "text": text_output}],
                    "isError": False,
                },
            )
        except ToolError as err:
            return _build_success_response(
                req_id,
                {
                    "content": [{"type": "text", "text": f"Tool Execution Error: {err}"}],
                    "isError": True,
                },
            )
        except Exception as exc:
            return _build_success_response(
                req_id,
                {
                    "content": [{"type": "text", "text": f"Internal Error: {exc}"}],
                    "isError": True,
                },
            )

    if method == "resources/list":
        return _build_success_response(req_id, {"resources": []})

    if method == "prompts/list":
        return _build_success_response(
            req_id,
            {
                "prompts": [
                    {
                        "name": "breachlabs_security_assessment",
                        "description": "Autonomous security assessment prompt incorporating MCP tools and skill lifecycle.",
                    },
                    {
                        "name": "verify_installation",
                        "description": "Verify that both BreachLabs MCP server and AI Skill are properly installed.",
                    },
                ]
            },
        )

    if method == "prompts/get":
        prompt_name = params.get("name")
        from breachlabs.mcp.skill_check import check_skill_installation, format_installation_prompt

        if prompt_name == "verify_installation":
            status = check_skill_installation()
            prompt_text = format_installation_prompt(
                skill_missing=not status["skill_installed"],
                mcp_missing=False,
            )
            return _build_success_response(
                req_id,
                {
                    "description": "Installation status check prompt",
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": prompt_text},
                        }
                    ],
                },
            )

        if prompt_name == "breachlabs_security_assessment":
            assessment_prompt = (
                "You are an autonomous application security engineer equipped with the BreachLabs MCP server.\n"
                "Before starting, ensure that BreachLabs MCP and the BreachLabs Skill (via npx -y skills add breachlabs) are installed.\n"
                "Follow the 9-phase lifecycle: Intake -> Build & Health -> Recon -> Static -> Dynamic -> Browser -> Investigate -> Verify -> Report & Fix.\n"
                "Use the allowlisted MCP tools (inspect_repository, list_routes, run_static_scan, scan_secrets, check_health, run_dast, verify_installation)."
            )
            return _build_success_response(
                req_id,
                {
                    "description": "BreachLabs Autonomous Security Assessment Prompt",
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": assessment_prompt},
                        }
                    ],
                },
            )

        return _build_error_response(req_id, -32602, f"Prompt not found: '{prompt_name}'")

    return _build_error_response(req_id, -32601, f"Method not found: '{method}'")


@mcp_router.get("", include_in_schema=False)
@mcp_router.get("/")
@mcp_router.get("/sse")
async def mcp_sse_endpoint(
    request: Request,
    accept: str | None = Header(default=None),
    max_events: int | None = Query(default=None),
) -> Response:
    """Streamable HTTP / Server-Sent Events (SSE) connection endpoint.

    When a client initiates an SSE connection, this sends an initial event
    announcing the message POST endpoint URL and maintains the stream.
    """
    session_id = uuid.uuid4().hex
    queue: asyncio.Queue[str] = asyncio.Queue()
    _sessions[session_id] = queue

    # Message endpoint URI
    msg_endpoint = f"/mcp/messages?session_id={session_id}"

    async def event_generator() -> AsyncGenerator[str, None]:
        events_sent = 0
        try:
            # Send the standard MCP initial endpoint event
            yield f"event: endpoint\ndata: {msg_endpoint}\n\n"
            events_sent += 1
            if max_events and events_sent >= max_events:
                return

            # Stream queued events/responses or periodic keepalives
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=0.5)
                    yield f"event: message\ndata: {data}\n\n"
                    events_sent += 1
                    if max_events and events_sent >= max_events:
                        break
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        break
                    # Send keepalive comment
                    yield ": keepalive\n\n"
        finally:
            _sessions.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@mcp_router.post("", include_in_schema=False)
@mcp_router.post("/")
@mcp_router.post("/messages")
async def mcp_messages_endpoint(
    request: Request,
    session_id: str | None = Query(default=None),
) -> Response:
    """JSON-RPC message receiver endpoint for HTTP & SSE clients.

    Handles single or batch JSON-RPC requests. If session_id is active, responses
    can also be pushed onto the SSE stream.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _build_error_response(None, -32700, "Parse error: Invalid JSON"),
            status_code=400,
        )

    if isinstance(body, list):
        # Batch request
        responses = []
        for item in body:
            resp = await handle_jsonrpc_message(item)
            if resp is not None:
                responses.append(resp)
        if session_id and session_id in _sessions and responses:
            await _sessions[session_id].put(json.dumps(responses))
            return Response(status_code=202)
        return JSONResponse(responses)

    if isinstance(body, dict):
        # Single request
        resp = await handle_jsonrpc_message(body)
        if resp is None:
            return Response(status_code=204)

        if session_id and session_id in _sessions:
            await _sessions[session_id].put(json.dumps(resp))
            return Response(status_code=202)

        return JSONResponse(resp)

    return JSONResponse(
        _build_error_response(None, -32600, "Invalid Request: Expected JSON object or array"),
        status_code=400,
    )
