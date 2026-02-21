"""
Function run model
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID


class RunStatus(Enum):
    """Status of a function run"""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal status"""
        return self in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED)


@dataclass
class FunctionRun:
    """A function run instance"""

    id: UUID
    function_id: str
    event_id: UUID
    status: RunStatus
    attempt: int
    max_attempts: int
    input: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FunctionRun":
        """Create from API response"""
        return cls(
            id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
            function_id=data["function_id"],
            event_id=(
                UUID(data["event_id"]) if isinstance(data["event_id"], str) else data["event_id"]
            ),
            status=RunStatus(data["status"]),
            attempt=data["attempt"],
            max_attempts=data["max_attempts"],
            input=data.get("input", {}),
            output=data.get("output"),
            error=data.get("error"),
            created_at=_parse_datetime(data.get("created_at")),
            started_at=_parse_datetime(data.get("started_at")),
            ended_at=_parse_datetime(data.get("ended_at")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "id": str(self.id),
            "function_id": self.function_id,
            "event_id": str(self.event_id),
            "status": self.status.value,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "input": self.input,
        }
        if self.output:
            result["output"] = self.output
        if self.error:
            result["error"] = self.error
        if self.created_at:
            result["created_at"] = self.created_at.isoformat()
        if self.started_at:
            result["started_at"] = self.started_at.isoformat()
        if self.ended_at:
            result["ended_at"] = self.ended_at.isoformat()
        return result

    @property
    def is_complete(self) -> bool:
        """Check if run is complete (success or failure)"""
        return self.status.is_terminal

    @property
    def can_retry(self) -> bool:
        """Check if run can be retried"""
        return self.attempt < self.max_attempts and self.status != RunStatus.COMPLETED


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime string"""
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
