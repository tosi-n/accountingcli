"""
Step context for durable execution
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
from uuid import UUID

logger = logging.getLogger(__name__)

T = TypeVar("T")


class StepError(Exception):
    """Error during step execution"""

    pass


@dataclass
class StepResult(Generic[T]):
    """Result of a step execution"""

    step_id: str
    output: T
    cached: bool = False


class StepContext:
    """
    Context for executing durable steps within a function.

    Each step is:
    1. Checked for existing output (replay on restart)
    2. Executed if not cached
    3. Persisted before returning

    Usage:
        async def my_function(ctx, step):
            # This step will be replayed if the function restarts
            user = await step.run("fetch-user", lambda: fetch_user(ctx.event.user_id))

            # Sleep survives restarts
            await step.sleep("wait-1h", hours=1)

            # Send events from within functions
            await step.send_event("notify", "user.notified", {"user_id": user.id})
    """

    def __init__(
        self,
        run_id: Union[str, UUID],
        client=None,  # ChoreoClient for persistence
        cached_steps: Optional[Dict[str, Any]] = None,
    ):
        self.run_id = str(run_id)
        self._client = client
        self._cached_steps = cached_steps or {}
        self._executed_steps: list[str] = []

    async def run(
        self,
        step_id: str,
        func: Callable[[], Any],
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        """
        Execute a step with durable caching.

        If the step was already completed in a previous attempt,
        returns the cached output. Otherwise executes the function
        and persists the result.

        Args:
            step_id: Unique identifier for this step (within the run)
            func: Function to execute (sync or async)
            timeout: Optional timeout in seconds

        Returns:
            The step output (from cache or fresh execution)

        Raises:
            StepError: If the step fails
        """
        # Check cache first
        if step_id in self._cached_steps:
            logger.debug(f"Replaying cached step: {step_id}")
            return self._cached_steps[step_id]

        logger.info(f"Executing step: {step_id}")

        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                if timeout:
                    result = await asyncio.wait_for(func(), timeout=timeout)
                else:
                    result = await func()
            else:
                if timeout:
                    result = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(None, func),
                        timeout=timeout,
                    )
                else:
                    result = func()
                    # Handle case where func is a lambda returning a coroutine
                    # e.g., lambda: async_func(arg) returns a coroutine
                    if asyncio.iscoroutine(result):
                        result = await result

            # Cache the result
            self._cached_steps[step_id] = result
            self._executed_steps.append(step_id)

            # Persist to server if client available
            if self._client:
                await self._persist_step(step_id, result)

            logger.info(f"Step completed: {step_id}")
            return result

        except asyncio.TimeoutError:
            raise StepError(f"Step {step_id} timed out after {timeout}s")
        except Exception as e:
            logger.error(f"Step {step_id} failed: {e}")
            raise StepError(f"Step {step_id} failed: {e}") from e

    async def sleep(
        self,
        step_id: str,
        *,
        seconds: float = 0,
        minutes: float = 0,
        hours: float = 0,
        days: float = 0,
    ) -> None:
        """
        Sleep for a duration (durable - survives restarts).

        The sleep is persisted, so if the function restarts,
        it will skip already-elapsed sleep time.

        Args:
            step_id: Unique identifier for this sleep step
            seconds, minutes, hours, days: Duration components
        """
        total_seconds = seconds + minutes * 60 + hours * 3600 + days * 86400

        async def do_sleep():
            await asyncio.sleep(total_seconds)
            return {"slept_seconds": total_seconds}

        await self.run(step_id, do_sleep)

    async def sleep_until(
        self,
        step_id: str,
        until: datetime,
    ) -> None:
        """
        Sleep until a specific timestamp (durable).

        Args:
            step_id: Unique identifier for this sleep step
            until: Datetime to sleep until
        """

        async def do_sleep():
            now = datetime.utcnow()
            if until > now:
                delta = (until - now).total_seconds()
                await asyncio.sleep(delta)
            return {"slept_until": until.isoformat()}

        await self.run(step_id, do_sleep)

    async def send_event(
        self,
        step_id: str,
        event_name: str,
        data: Dict[str, Any],
        *,
        idempotency_key: Optional[str] = None,
    ) -> str:
        """
        Send an event from within a function (for fan-out patterns).

        Args:
            step_id: Unique identifier for this step
            event_name: Name of the event to send
            data: Event payload
            idempotency_key: Optional idempotency key

        Returns:
            Event ID
        """

        async def do_send():
            if self._client:
                result = await self._client.send_event(event_name, data, idempotency_key)
                return result.get("id")
            else:
                import uuid

                return str(uuid.uuid4())

        return await self.run(step_id, do_send)

    async def invoke(
        self,
        step_id: str,
        function_id: str,
        input_data: Dict[str, Any],
        *,
        wait: bool = True,
        timeout: Optional[float] = None,
    ) -> Any:
        """
        Invoke another function and optionally wait for result.

        Args:
            step_id: Unique identifier for this step
            function_id: ID of the function to invoke
            input_data: Input data for the function
            wait: Whether to wait for the function to complete
            timeout: Timeout for waiting (if wait=True)

        Returns:
            Function output if wait=True, otherwise run ID
        """
        # This is a placeholder - full implementation would
        # create a run via the API and optionally poll for completion
        raise NotImplementedError("invoke() not yet implemented")

    async def _persist_step(self, step_id: str, output: Any) -> None:
        """Persist step result to server"""
        if self._client:
            try:
                await self._client.save_step(self.run_id, step_id, output)
                logger.debug(f"Persisted step {step_id}")
            except Exception as e:
                logger.warning(f"Failed to persist step {step_id}: {e}")
        else:
            logger.debug(f"No client available, step {step_id} not persisted to server")

    def get_completed_steps(self) -> list[str]:
        """Get list of completed step IDs"""
        return list(self._cached_steps.keys())
