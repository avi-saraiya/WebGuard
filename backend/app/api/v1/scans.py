from fastapi import APIRouter

from app.analyzers.engine import analyze
from app.rules import registry
from app.schemas.scan import ScanRequest, ScanResponse

router = APIRouter(tags=["scans"])


@router.post("/scans")
async def create_scan(request: ScanRequest) -> ScanResponse:
    return analyze(request, registry)
