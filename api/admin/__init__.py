"""
Admin API Package.
Aggregates all admin sub-routers into a single router for inclusion in the main app.
"""

from fastapi import APIRouter

from api.admin.dashboard import router as dashboard_router
from api.admin.errors import router as errors_router
from api.admin.chronology import router as chronology_router
from api.admin.rules import router as rules_router
from api.admin.analytics_intelligence import router as analytics_intelligence_router
from api.admin.system import router as system_router

router = APIRouter()
router.include_router(dashboard_router)
router.include_router(errors_router)
router.include_router(chronology_router)
router.include_router(rules_router)
router.include_router(analytics_intelligence_router)
router.include_router(system_router)
