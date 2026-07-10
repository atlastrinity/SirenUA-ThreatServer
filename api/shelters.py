"""
SirenUA Shelters API Router.
FastAPI routes for searching nearby shelters and uploading new shelters.
"""

import asyncio
from fastapi import APIRouter, HTTPException

from core.globals import shelter_manager
from database.db_helpers import HAS_FIREBASE
from api.schemas import ShelterUploadRequest

router = APIRouter()

@router.get("/api/shelters")
async def get_shelters(lat: float, lon: float, radius: float = 1500, limit: int = 50):
    """Пошук найближчих укриттів у заданому радіусі (метри)."""
    if not shelter_manager.is_loaded:
        raise HTTPException(status_code=503, detail="Shelter database is loading, try again in a minute.")

    # Clamp values
    radius = max(100, min(radius, 50_000))  # 100m — 50km
    limit = max(1, min(limit, 100))

    results = shelter_manager.find_nearby(lat, lon, radius, limit=limit)
    return {
        "count": len(results),
        "radius_m": radius,
        "total_in_db": shelter_manager.total_count,
        "shelters": results,
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
