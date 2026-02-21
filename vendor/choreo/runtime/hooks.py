"""
Worker loop lifecycle hooks for Choreo Python SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID


@dataclass
class RunExecutionResult:
    """Structured execution result emitted by worker loop callbacks."""

    run_id: UUID
    function_id: str
    attempt: int
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    should_retry: bool = False


@dataclass
class WorkerLeaseContext:
    """Lease context passed to hook callbacks."""

    worker_id: str
    requested_limit: int
    leased_runs: List[Dict[str, Any]] = field(default_factory=list)


class WorkerLoopHooks:
    """
    No-op lifecycle hooks for the SDK worker loop.

    Override in callers that need observability or custom policy extensions.
    """

    async def before_lease(self, context: WorkerLeaseContext) -> None:
        """Called before requesting runs from the server."""
        return None

    async def after_lease(self, context: WorkerLeaseContext) -> None:
        """Called after receiving leased runs from the server."""
        return None

    async def before_execute_run(self, run_data: Dict[str, Any]) -> None:
        """Called before a leased run starts execution."""
        return None

    async def after_execute_run(self, result: RunExecutionResult) -> None:
        """Called when a run has finished (success or failure)."""
        return None

    async def on_run_error(self, run_data: Dict[str, Any], error: Exception) -> None:
        """Called when execution raises an exception."""
        return None
