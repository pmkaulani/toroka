from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

ALLOWED_TOOLS: set[str] = {
    "get_case_snapshot",
    "get_case_timeline",
    "get_reconstruction",
    "get_network_subgraph",
    "search_institutional_memory",
    "get_evidence_coverage",
    "get_audit_timeline",
    "get_simulation_result",
    "get_source_record_details",
    "get_case_relationships",
}

DENIED_ARGUMENTS: set[str] = {
    "installation_id",
    "tenant_id",
    "user_id",
    "actor_subject",
    "actor_role",
    "raw_identity",
    "plaintext_identity",
}


class ToolPolicyError(Exception):
    """Raised when an unapproved tool, forbidden argument, or unauthorized scope is requested."""
    pass


@dataclass(frozen=True)
class ToolContext:
    """Authenticated context passed into tool handlers.
    
    The model can NEVER supply or override these values; they are strictly
    bound to the authenticated request.
    """
    installation_id: str
    case_id: str
    actor_subject: str
    actor_role: str
    as_of: datetime | None = None


@dataclass(frozen=True)
class ToolExecutionRecord:
    tool_name: str
    parameters: dict[str, Any]
    executed_at: datetime
    success: bool
    output_size_bytes: int
    error: str | None = None


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[ToolContext, dict[str, Any]], Any]
    max_output_bytes: int = 65536
    timeout_seconds: float = 10.0


class ReadOnlyToolRegistry:
    """Read-only permission gateway enforcing strict tool and argument boundaries."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._execution_history: list[ToolExecutionRecord] = []

    def register(self, definition: ToolDefinition) -> None:
        if definition.name not in ALLOWED_TOOLS:
            raise ToolPolicyError(
                f"Tool '{definition.name}' is not in the approved read-only tool catalogue"
            )
        self._tools[definition.name] = definition

    def get_tool_catalog(self) -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            }
            for tool in self._tools.values()
        ]

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ToolContext,
    ) -> Any:
        # 1. Allowlist check
        if tool_name not in ALLOWED_TOOLS or tool_name not in self._tools:
            err_msg = f"Execution of tool '{tool_name}' is denied by policy"
            self._record_execution(tool_name, arguments, success=False, size=0, error=err_msg)
            raise ToolPolicyError(err_msg)

        # 2. Denied argument injection check
        forbidden_present = set(arguments.keys()) & DENIED_ARGUMENTS
        if forbidden_present:
            err_msg = (
                f"Tool '{tool_name}' received forbidden argument override: {sorted(forbidden_present)}. "
                "Context parameters must be established by the authenticated platform session."
            )
            self._record_execution(tool_name, arguments, success=False, size=0, error=err_msg)
            raise ToolPolicyError(err_msg)

        tool_def = self._tools[tool_name]

        # 3. Clean parameters: shallow copy safe kwargs
        safe_kwargs = {k: v for k, v in arguments.items() if k not in DENIED_ARGUMENTS}

        try:
            result = tool_def.handler(context, safe_kwargs)

            # Output size guard
            try:
                serialized = json.dumps(result, default=str)
                size_bytes = len(serialized.encode("utf-8"))
            except Exception:
                size_bytes = 0

            if tool_def.max_output_bytes and size_bytes > tool_def.max_output_bytes:
                err_msg = (
                    f"Tool '{tool_name}' output exceeded maximum permitted size "
                    f"({size_bytes} > {tool_def.max_output_bytes} bytes)"
                )
                self._record_execution(tool_name, arguments, success=False, size=size_bytes, error=err_msg)
                raise ToolPolicyError(err_msg)

            self._record_execution(tool_name, arguments, success=True, size=size_bytes)
            return result

        except Exception as exc:
            if not isinstance(exc, ToolPolicyError):
                logger.warning("Tool execution error in '%s': %s", tool_name, exc)
                self._record_execution(tool_name, arguments, success=False, size=0, error=str(exc))
            raise

    def _record_execution(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        success: bool,
        size: int,
        error: str | None = None,
    ) -> None:
        rec = ToolExecutionRecord(
            tool_name=tool_name,
            parameters={k: str(v)[:100] for k, v in parameters.items()},
            executed_at=datetime.now(timezone.utc),
            success=success,
            output_size_bytes=size,
            error=error,
        )
        self._execution_history.append(rec)

    @property
    def execution_history(self) -> list[ToolExecutionRecord]:
        return list(self._execution_history)
