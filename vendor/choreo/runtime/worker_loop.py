"""
Core worker loop runtime used by Choreo.start_worker().
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol
from uuid import UUID

from .hooks import RunExecutionResult, WorkerLeaseContext, WorkerLoopHooks

logger = logging.getLogger(__name__)


class WorkerRuntimeError(RuntimeError):
    """Structured worker runtime error."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class SupportsWorkerApi(Protocol):
    async def lease_runs(
        self,
        worker_id: str,
        limit: int,
        lease_duration_secs: int,
    ) -> List[Dict[str, Any]]:
        ...

    async def worker_heartbeat(self, worker_id: str, run_ids: List[UUID]) -> Dict[str, Any]:
        ...

    async def fail_run(
        self,
        run_id: UUID,
        error: str,
        should_retry: bool = False,
    ) -> Dict[str, Any]:
        ...


@dataclass
class WorkerLoopConfig:
    worker_id: str
    poll_interval: float
    batch_size: int
    max_concurrent: int
    lease_duration_secs: int = 300
    heartbeat_interval_secs: int = 60


class ActiveRunTracker:
    """Tracks currently executing run IDs for heartbeat extension."""

    def __init__(self) -> None:
        self._run_ids: set[UUID] = set()
        self._lock = asyncio.Lock()

    async def add(self, run_id: UUID) -> None:
        async with self._lock:
            self._run_ids.add(run_id)

    async def remove(self, run_id: UUID) -> None:
        async with self._lock:
            self._run_ids.discard(run_id)

    async def snapshot(self) -> List[UUID]:
        async with self._lock:
            return list(self._run_ids)


class WorkerLoop:
    """Runs polling, concurrent execution, and heartbeat lease extension."""

    def __init__(
        self,
        *,
        config: WorkerLoopConfig,
        client_factory: Callable[[], Any],
        execute_run: Callable[[Any, Dict[str, Any]], Awaitable[None]],
        shutdown_event: asyncio.Event,
        hooks: Optional[WorkerLoopHooks] = None,
    ) -> None:
        self.config = config
        self._client_factory = client_factory
        self._execute_run = execute_run
        self._shutdown_event = shutdown_event
        self._hooks = hooks or WorkerLoopHooks()
        self._active_runs = ActiveRunTracker()
        self._concurrency = asyncio.Semaphore(max(1, int(config.max_concurrent)))

    async def run(self) -> None:
        """Run until shutdown event is set."""
        heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            while not self._shutdown_event.is_set():
                try:
                    await self._poll_and_execute()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("Worker loop error: %s", exc, exc_info=True)
                    await asyncio.sleep(1)
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    async def _poll_and_execute(self) -> None:
        lease_context = WorkerLeaseContext(
            worker_id=self.config.worker_id,
            requested_limit=self.config.batch_size,
        )
        await self._safe_hook("before_lease", self._hooks.before_lease(lease_context))

        async with self._client_factory() as client:
            leased_runs = await client.lease_runs(
                worker_id=self.config.worker_id,
                limit=self.config.batch_size,
                lease_duration_secs=self.config.lease_duration_secs,
            )

        lease_context.leased_runs = leased_runs
        await self._safe_hook("after_lease", self._hooks.after_lease(lease_context))

        if not leased_runs:
            await asyncio.sleep(self.config.poll_interval)
            return

        tasks = [asyncio.create_task(self._process_run(run_data)) for run_data in leased_runs]
        await asyncio.gather(*tasks, return_exceptions=False)

    async def _process_run(self, run_data: Dict[str, Any]) -> None:
        async with self._concurrency:
            await self._safe_hook(
                "before_execute_run",
                self._hooks.before_execute_run(run_data),
            )

            run_id = self._parse_run_id(run_data)
            await self._active_runs.add(run_id)

            try:
                async with self._client_factory() as client:
                    await self._execute_run(client, run_data)
                await self._safe_hook(
                    "after_execute_run",
                    self._hooks.after_execute_run(
                        RunExecutionResult(
                            run_id=run_id,
                            function_id=str(run_data.get("function_id") or ""),
                            attempt=int(run_data.get("attempt") or 0),
                            output=None,
                            error=None,
                            should_retry=False,
                        )
                    ),
                )
            except Exception as exc:
                should_retry = bool(int(run_data.get("attempt") or 0) < int(run_data.get("max_attempts") or 0))
                async with self._client_factory() as client:
                    await client.fail_run(run_id, str(exc), should_retry=should_retry)
                await self._safe_hook("on_run_error", self._hooks.on_run_error(run_data, exc))
                await self._safe_hook(
                    "after_execute_run",
                    self._hooks.after_execute_run(
                        RunExecutionResult(
                            run_id=run_id,
                            function_id=str(run_data.get("function_id") or ""),
                            attempt=int(run_data.get("attempt") or 0),
                            output=None,
                            error=str(exc),
                            should_retry=should_retry,
                        )
                    ),
                )
            finally:
                await self._active_runs.remove(run_id)

    async def _heartbeat_loop(self) -> None:
        interval = max(5, int(self.config.heartbeat_interval_secs))
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

            active_runs = await self._active_runs.snapshot()
            if not active_runs:
                continue

            try:
                async with self._client_factory() as client:
                    await client.worker_heartbeat(self.config.worker_id, active_runs)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Failed worker heartbeat worker_id=%s active_runs=%s error=%s",
                    self.config.worker_id,
                    len(active_runs),
                    exc,
                )

    async def _safe_hook(self, name: str, awaitable: Awaitable[None]) -> None:
        try:
            await awaitable
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Worker hook '%s' failed: %s", name, exc)

    def _parse_run_id(self, run_data: Dict[str, Any]) -> UUID:
        raw = run_data.get("id")
        if raw is None:
            raise WorkerRuntimeError("Run payload missing id", code="RUN_ID_MISSING")
        try:
            return UUID(str(raw))
        except Exception as exc:
            raise WorkerRuntimeError(f"Invalid run id: {raw}", code="RUN_ID_INVALID") from exc
