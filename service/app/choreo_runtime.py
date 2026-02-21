from __future__ import annotations

import uuid

from app.settings import settings

from choreo import Choreo, ChoreoConfig


choreo = Choreo(
    config=ChoreoConfig(
        server_url=settings.CHOREO_SERVER_URL,
        worker_id=f"accountingcli-worker-{uuid.uuid4().hex[:8]}",
        poll_interval=5.0,
        batch_size=5,
        max_concurrent=2,
    )
)

