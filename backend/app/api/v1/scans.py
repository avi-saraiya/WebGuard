from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter

from app import __version__
from app.schemas.scan import ScanRequest, ScanResponse, ScanTarget, SeveritySummary

router = APIRouter(tags=["scans"])


@router.post("/scans")
async def create_scan(request: ScanRequest) -> ScanResponse:
    # v0.1 skeleton: no analysis yet. Returns an empty, clearly-marked mock result.
    parts = urlsplit(request.url)
    return ScanResponse(
        scan_id=uuid4(),
        target=ScanTarget(url=request.url, host=parts.hostname or "", scheme=parts.scheme),
        summary=SeveritySummary(),
        findings=[],
        checks=[],
        engine_version=f"{__version__}-mock",
        analyzed_at=datetime.now(UTC),
    )
