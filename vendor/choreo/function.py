"""
Function definitions and registry
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class TriggerDef:
    """Trigger definition"""

    type: str  # "event" or "cron"
    event_name: Optional[str] = None
    cron_schedule: Optional[str] = None
    filter: Optional[str] = None  # CEL expression


@dataclass
class FunctionDef:
    """Function definition with metadata"""

    id: str
    name: str = ""
    triggers: List[str] = field(default_factory=list)
    cron: Optional[str] = None
    retries: int = 3
    timeout: int = 300
    concurrency: Optional[int] = None
    concurrency_key: Optional[str] = None
    priority: int = 0
    throttle_limit: Optional[int] = None
    throttle_period: Optional[int] = None
    debounce_period: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API"""
        triggers: List[Dict[str, Any]] = [{"type": "event", "name": t} for t in self.triggers]
        if self.cron:
            triggers.append({"type": "cron", "schedule": self.cron})

        result: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "triggers": triggers,
            "retries": {
                "max_attempts": self.retries,
            },
            "timeout_secs": self.timeout,
            "priority": self.priority,
        }

        if self.concurrency:
            result["concurrency"] = {
                "limit": self.concurrency,
                "key": self.concurrency_key,
            }

        if self.throttle_limit and self.throttle_period:
            result["throttle"] = {
                "limit": self.throttle_limit,
                "period_secs": self.throttle_period,
            }

        if self.debounce_period:
            result["debounce"] = {
                "period_secs": self.debounce_period,
            }

        return result


class FunctionRegistry:
    """Registry for function definitions and handlers"""

    def __init__(self):
        self._definitions: Dict[str, FunctionDef] = {}
        self._handlers: Dict[str, Callable] = {}
        self._event_map: Dict[str, List[str]] = {}

    def register(self, definition: FunctionDef, handler: Callable) -> None:
        """Register a function with its handler"""
        self._definitions[definition.id] = definition
        self._handlers[definition.id] = handler

        # Build event mapping
        for trigger in definition.triggers:
            if trigger not in self._event_map:
                self._event_map[trigger] = []
            self._event_map[trigger].append(definition.id)

    def get_handler(self, function_id: str) -> Optional[Callable]:
        """Get handler for a function"""
        return self._handlers.get(function_id)

    def get_definition(self, function_id: str) -> Optional[FunctionDef]:
        """Get function definition"""
        return self._definitions.get(function_id)

    def get_functions_for_event(self, event_name: str) -> List[str]:
        """Get function IDs triggered by an event"""
        return self._event_map.get(event_name, [])

    def all_definitions(self) -> List[FunctionDef]:
        """Get all registered function definitions"""
        return list(self._definitions.values())


def function(
    choreo,
    function_id: str,
    **kwargs,
):
    """
    Standalone decorator for registering functions.

    Usage:
        @function(choreo, "my-function", trigger="my.event")
        async def my_function(ctx, step):
            ...
    """
    return choreo.function(function_id, **kwargs)
