"""
Choreo client - connects to Choreo server
"""

import asyncio
import logging
import uuid as uuid_module
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import UUID

import httpx

from .event import Event, EventContext
from .function import FunctionDef, FunctionRegistry
from .runtime import WorkerLoop, WorkerLoopConfig, WorkerLoopHooks
from .run import FunctionRun
from .step import StepContext

logger = logging.getLogger(__name__)


@dataclass
class ChoreoConfig:
    """Configuration for Choreo client"""

    server_url: Optional[str] = None
    worker_id: Optional[str] = None
    poll_interval: float = 1.0
    batch_size: int = 10
    max_concurrent: int = 10
    lease_duration_secs: int = 300
    heartbeat_interval_secs: int = 60
    timeout: float = 30.0


class ChoreoClient:
    """Low-level HTTP client for Choreo server"""

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("Client not initialized. Use 'async with' context manager.")
        return self._client

    async def send_event(
        self,
        name: str,
        data: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send an event to trigger functions"""
        payload: Dict[str, Any] = {
            "name": name,
            "data": data,
        }
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key
        if user_id:
            payload["user_id"] = user_id

        response = await self.client.post("/events", json=payload)
        response.raise_for_status()
        return await response.json()

    async def get_event(self, event_id: Union[str, UUID]) -> Event:
        """Get an event by ID"""
        response = await self.client.get(f"/events/{event_id}")
        response.raise_for_status()
        return Event.from_dict(await response.json())

    async def get_run(self, run_id: Union[str, UUID]) -> FunctionRun:
        """Get a function run by ID"""
        response = await self.client.get(f"/runs/{run_id}")
        response.raise_for_status()
        return FunctionRun.from_dict(await response.json())

    async def cancel_run(self, run_id: Union[str, UUID]) -> FunctionRun:
        """Cancel a function run"""
        response = await self.client.post(f"/runs/{run_id}/cancel")
        response.raise_for_status()
        return FunctionRun.from_dict(await response.json())

    async def get_run_steps(self, run_id: Union[str, UUID]) -> List[Dict[str, Any]]:
        """Get steps for a function run"""
        response = await self.client.get(f"/runs/{run_id}/steps")
        response.raise_for_status()
        return await response.json()

    async def health_check(self) -> Dict[str, str]:
        """Check server health"""
        response = await self.client.get("/health")
        response.raise_for_status()
        return await response.json()

    async def lease_runs(
        self,
        worker_id: str,
        limit: int = 10,
        lease_duration_secs: int = 300,
    ) -> List[Dict[str, Any]]:
        """Lease pending runs for execution"""
        response = await self.client.post(
            "/worker/lease-runs",
            json={
                "worker_id": worker_id,
                "limit": limit,
                "lease_duration_secs": lease_duration_secs,
            },
        )
        response.raise_for_status()
        return (await response.json()).get("runs", [])

    async def complete_run(
        self,
        run_id: Union[str, UUID],
        output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Mark a run as completed with output"""
        response = await self.client.post(
            f"/runs/{run_id}/complete",
            json={"output": output},
        )
        response.raise_for_status()
        return await response.json()

    async def fail_run(
        self,
        run_id: Union[str, UUID],
        error: str,
        should_retry: bool = False,
    ) -> Dict[str, Any]:
        """Mark a run as failed"""
        response = await self.client.post(
            f"/runs/{run_id}/fail",
            json={"error": error, "should_retry": should_retry},
        )
        response.raise_for_status()
        return await response.json()

    async def save_step(
        self,
        run_id: Union[str, UUID],
        step_id: str,
        output: Any,
    ) -> Dict[str, Any]:
        """Save step output for durable execution"""
        response = await self.client.post(
            f"/runs/{run_id}/steps/{step_id}",
            json={"output": output},
        )
        response.raise_for_status()
        return await response.json()

    async def worker_heartbeat(
        self,
        worker_id: str,
        run_ids: List[Union[str, UUID]],
    ) -> Dict[str, Any]:
        """Extend leases on runs being processed"""
        response = await self.client.post(
            "/worker/heartbeat",
            json={
                "worker_id": worker_id,
                "run_ids": [str(rid) for rid in run_ids],
            },
        )
        response.raise_for_status()
        return await response.json()

    async def register_functions(
        self,
        functions: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Register function definitions with the server"""
        response = await self.client.post(
            "/functions",
            json={"functions": functions},
        )
        response.raise_for_status()
        return await response.json()


class Choreo:
    """
    Main Choreo client for defining and running durable functions.

    Usage:
        choreo = Choreo("http://localhost:8080")

        @choreo.function("my-function", trigger="my.event")
        async def my_function(ctx, step):
            result = await step.run("step-1", lambda: do_something())
            return {"result": result}

        # Send events
        await choreo.send("my.event", {"key": "value"})

        # Start worker to process functions
        await choreo.start_worker()
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        config: Optional[ChoreoConfig] = None,
    ):
        self.config = config or ChoreoConfig(server_url=server_url)
        self.registry = FunctionRegistry()
        self._client: Optional[ChoreoClient] = None
        self._shutdown = asyncio.Event()

    def function(
        self,
        function_id: str,
        *,
        trigger: Optional[str] = None,
        triggers: Optional[List[str]] = None,
        cron: Optional[str] = None,
        retries: int = 3,
        timeout: int = 300,
        concurrency: Optional[int] = None,
        concurrency_key: Optional[str] = None,
        priority: int = 0,
        throttle_limit: Optional[int] = None,
        throttle_period: Optional[int] = None,
        debounce_period: Optional[int] = None,
    ) -> Callable:
        """
        Decorator to register a function with Choreo.

        Args:
            function_id: Unique identifier for the function
            trigger: Event name that triggers this function
            triggers: List of event names that trigger this function
            cron: Cron expression for scheduled execution
            retries: Maximum retry attempts (default: 3)
            timeout: Execution timeout in seconds (default: 300)
            concurrency: Maximum concurrent executions
            concurrency_key: Expression for per-key concurrency
            priority: Execution priority (higher = processed first)
            throttle_limit: Maximum executions per throttle_period
            throttle_period: Throttle period in seconds
            debounce_period: Debounce period in seconds
        """
        all_triggers: List[str] = []
        if trigger:
            all_triggers.append(trigger)
        if triggers:
            all_triggers.extend(triggers)

        def decorator(func: Callable) -> Callable:
            func_def = FunctionDef(
                id=function_id,
                name=func.__name__,
                triggers=all_triggers,
                cron=cron,
                retries=retries,
                timeout=timeout,
                concurrency=concurrency,
                concurrency_key=concurrency_key,
                priority=priority,
                throttle_limit=throttle_limit,
                throttle_period=throttle_period,
                debounce_period=debounce_period,
            )
            self.registry.register(func_def, func)
            return func

        return decorator

    async def send(
        self,
        event_name: str,
        data: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send an event to trigger functions"""
        async with self._get_client() as client:
            return await client.send_event(event_name, data, idempotency_key, user_id)

    async def get_run(self, run_id: Union[str, UUID]) -> FunctionRun:
        """Get a function run by ID"""
        async with self._get_client() as client:
            return await client.get_run(run_id)

    async def cancel_run(self, run_id: Union[str, UUID]) -> FunctionRun:
        """Cancel a function run"""
        async with self._get_client() as client:
            return await client.cancel_run(run_id)

    def _get_client(self) -> ChoreoClient:
        """Get HTTP client for server communication"""
        if not self.config.server_url:
            raise RuntimeError("Server URL not configured")
        return ChoreoClient(self.config.server_url, self.config.timeout)

    async def start_worker(self, hooks: Optional[WorkerLoopHooks] = None) -> None:
        """
        Start a worker to process function runs.

        This will poll the server for pending runs and execute them locally.
        """
        worker_id = self.config.worker_id or f"worker-{uuid_module.uuid4().hex[:8]}"
        logger.info(f"Starting Choreo worker: {worker_id}")

        # Register functions with server
        await self._register_functions()

        runtime = WorkerLoop(
            config=WorkerLoopConfig(
                worker_id=worker_id,
                poll_interval=self.config.poll_interval,
                batch_size=self.config.batch_size,
                max_concurrent=self.config.max_concurrent,
                lease_duration_secs=self.config.lease_duration_secs,
                heartbeat_interval_secs=self.config.heartbeat_interval_secs,
            ),
            client_factory=self._get_client,
            execute_run=self._execute_run,
            shutdown_event=self._shutdown,
            hooks=hooks,
        )
        await runtime.run()

        logger.info("Choreo worker stopped")

    async def _execute_run(self, client: ChoreoClient, run_data: Dict[str, Any]) -> None:
        """Execute a single function run"""
        run_id = UUID(run_data["id"])
        function_id = run_data["function_id"]
        event_data = run_data["event"]
        cached_steps = run_data.get("cached_steps", [])

        # Get the handler
        handler = self.registry.get_handler(function_id)
        if not handler:
            raise RuntimeError(f"No handler registered for function: {function_id}")

        # Build event context
        event = Event.from_dict(event_data)
        ctx = EventContext(
            event=event,
            run_id=run_id,
            attempt=run_data["attempt"],
            function_id=function_id,
        )

        # Build step context with cached steps for replay
        cached_step_outputs = {
            step["step_id"]: step.get("output")
            for step in cached_steps
            if step.get("status") == "completed"
        }
        step = StepContext(
            run_id=run_id,
            client=client,
            cached_steps=cached_step_outputs,
        )

        # Execute the handler
        logger.info(
            f"Executing function {function_id} (run: {run_id}, attempt: {run_data['attempt']})"
        )

        if asyncio.iscoroutinefunction(handler):
            result = await handler(ctx, step)
        else:
            result = handler(ctx, step)

        # Complete the run
        output = result if isinstance(result, dict) else {"result": result}
        await client.complete_run(run_id, output)
        logger.info(f"Completed run {run_id}")

    async def _register_functions(self) -> None:
        """Register all functions with the server"""
        definitions = self.registry.all_definitions()
        if not definitions:
            logger.warning("No functions registered")
            return

        function_defs = [d.to_dict() for d in definitions]
        async with self._get_client() as client:
            result = await client.register_functions(function_defs)
            logger.info(f"Registered {result.get('registered', 0)} functions")

    def shutdown(self) -> None:
        """Signal the worker to stop"""
        self._shutdown.set()
