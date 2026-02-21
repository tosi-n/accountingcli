"""
Choreo - Durable workflow orchestration

Usage:
    from choreo import Choreo

    choreo = Choreo("http://localhost:8080")

    @choreo.function("process-order", trigger="order.created")
    async def process_order(ctx, step):
        user = await step.run("fetch-user", lambda: fetch_user(ctx.event.user_id))
        await step.run("send-email", lambda: send_email(user.email))
        return {"processed": True}

    # Start worker
    await choreo.start_worker()
"""

from .client import Choreo, ChoreoClient, ChoreoConfig
from .event import Event, EventContext
from .function import FunctionDef, TriggerDef, function
from .runtime import RunExecutionResult, WorkerLeaseContext, WorkerLoopConfig, WorkerLoopHooks
from .run import FunctionRun, RunStatus
from .step import StepContext, StepError

__version__ = "0.1.2"
__all__ = [
    "Choreo",
    "ChoreoClient",
    "ChoreoConfig",
    "function",
    "FunctionDef",
    "TriggerDef",
    "StepContext",
    "StepError",
    "Event",
    "EventContext",
    "FunctionRun",
    "RunStatus",
    "RunExecutionResult",
    "WorkerLeaseContext",
    "WorkerLoopConfig",
    "WorkerLoopHooks",
]
