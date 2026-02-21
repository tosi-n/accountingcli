"""
Event model
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID


@dataclass
class Event:
    """An event that triggers function runs"""

    id: UUID
    name: str
    data: Dict[str, Any]
    timestamp: datetime
    idempotency_key: Optional[str] = None
    user_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create from API response"""
        return cls(
            id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
            name=data["name"],
            data=data.get("data", {}),
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
            idempotency_key=data.get("idempotency_key"),
            user_id=data.get("user_id"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result: Dict[str, Any] = {
            "id": str(self.id),
            "name": self.name,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.idempotency_key:
            result["idempotency_key"] = self.idempotency_key
        if self.user_id:
            result["user_id"] = self.user_id
        return result


@dataclass
class EventContext:
    """Context passed to function handlers"""

    event: Event
    run_id: UUID
    attempt: int
    function_id: str

    @property
    def data(self) -> Dict[str, Any]:
        """Shortcut to event data"""
        return self.event.data

    def __getattr__(self, name: str) -> Any:
        """Allow accessing event data as attributes"""
        if name in self.event.data:
            return self.event.data[name]
        raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")
