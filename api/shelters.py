"""
SirenUA Shelters API Router.
FastAPI routes for searching nearby shelters and uploading new shelters.
"""

import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from core.globals import shelter_manager
from database.db_helpers import HAS_FIREBASE
from api.schemas import ShelterUploadRequest

router = APIRouter()

@router.get("/api/shelters")
async def get_shelters(
    lat: float,
    lon: float,
    radius: float = 1500,
    limit: int = 50,
    region: Optional[str] = None
):
    """Пошук найближчих укриттів у заданому радіусі (метри) з автовизначенням області."""
    # Clamp values
    radius = max(100, min(radius, 50_000))  # 100m — 50km
    limit = max(1, min(limit, 100))

    results, reg_code, reg_name = await shelter_manager.find_nearby_with_region_async(
        lat=lat, lon=lon, radius_m=radius, limit=limit, region_filter=region
    )

    primary_count = sum(1 for s in results if s.get("is_primary"))
    secondary_count = sum(1 for s in results if not s.get("is_primary"))

    return {
        "count": len(results),
        "radius_m": radius,
        "region_code": reg_code,
        "region_name": reg_name,
        "primary_count": primary_count,
        "secondary_count": secondary_count,
        "total_in_db": shelter_manager.total_count,
        "shelters": results,
    }


@router.get("/api/shelters/by_region")
async def get_shelters_by_region(region: str = Query(..., description="Код або назва області (наприклад 'lviv', 'Львівська область', 'kyiv_city')")):
    """Отримання всіх укриттів 1-го та 2-го порядку для обраної області."""
    shelters = shelter_manager.get_shelters_by_region(region)
    primary_count = sum(1 for s in shelters if s.get("is_primary"))
    secondary_count = sum(1 for s in shelters if not s.get("is_primary"))

    return {
        "region": region,
        "count": len(shelters),
        "primary_count": primary_count,
        "secondary_count": secondary_count,
        "shelters": shelters,
    }


@router.get("/api/shelters/search")
async def search_shelters(
    q: str = Query("", description="Текстовий запит (назва міста, вулиця або заклад)"),
    region: Optional[str] = Query(None, description="Опціональний фільтр за областю"),
    only_primary: bool = Query(False, description="Шукати лише офіційні капітальні бомбосховища 1-го порядку"),
    limit: int = Query(50, ge=1, le=200, description="Ліміт результатів")
):
    """Пошук укриттів за назвою міста, адресою чи типом з підтримкою регіональних фільтрів."""
    results = shelter_manager.search_shelters(
        query=q,
        region=region,
        only_primary=only_primary,
        limit=limit
    )

    primary_count = sum(1 for s in results if s.get("is_primary"))
    secondary_count = sum(1 for s in results if not s.get("is_primary"))

    return {
        "query": q,
        "region": region,
        "only_primary": only_primary,
        "count": len(results),
        "primary_count": primary_count,
        "secondary_count": secondary_count,
        "shelters": results,
    }


@router.get("/api/shelters/regions")
async def get_shelter_regions():
    """Отримання зведеної статистики та координат центроїдів усіх 26 регіонів України."""
    regions_summary = shelter_manager.get_all_regions_summary()
    total_shelters = sum(r["total_count"] for r in regions_summary)
    total_primary = sum(r["primary_count"] for r in regions_summary)
    total_secondary = sum(r["secondary_count"] for r in regions_summary)

    return {
        "total_regions": len(regions_summary),
        "total_shelters": total_shelters,
        "total_primary": total_primary,
        "total_secondary": total_secondary,
        "regions": regions_summary,
    }



@router.post("/api/shelters/upload_json")
async def upload_shelters_json(req: ShelterUploadRequest):
    """Прихований ендпоінт для завантаження масиву укриттів (JSON) в Firestore."""
    if not HAS_FIREBASE:
        raise HTTPException(status_code=500, detail="Firebase не ініціалізовано")
        
    try:
        from firebase_admin import firestore
        db = firestore.client()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка Firestore: {e}")
        
    batch = db.batch()
    count = 0
    
    for s in req.shelters:
        doc_ref = db.collection("sirenua_shelters").document()
        batch.set(doc_ref, {
            "name": s.name,
            "address": s.address,
            "lat": s.lat,
            "lon": s.lon,
            "type": s.type,
            "capacity": s.capacity,
            "accessible": s.accessible,
            "source": "gov"
        })
        count += 1
        
        # Обмеження Firestore batch - 500 операцій
        if count % 400 == 0:
            batch.commit()
            batch = db.batch()
            
    if count % 400 != 0:
        batch.commit()
        
    # Перезавантажуємо кеш укриттів
    asyncio.create_task(shelter_manager.load())
    
    return {"status": "success", "uploaded": count}
