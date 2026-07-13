"""
Analytics API Package.
Aggregates all analytics sub-routers into a single router.
"""

from fastapi import APIRouter

from api.analytics.heatmap import router as heatmap_router
from api.analytics.lifecycle import router as lifecycle_router
from api.analytics.predictions import router as predictions_router

router = APIRouter()
router.include_router(heatmap_router)
router.include_router(lifecycle_router)
router.include_router(predictions_router)
