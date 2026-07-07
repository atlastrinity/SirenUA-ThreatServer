"""
Shelter Manager — завантаження та пошук укриттів по всій Україні.

Джерело: OpenStreetMap (Overpass API).
Пошук: R-tree просторовий індекс для швидкого гео-запиту.
Оновлення: автоматично раз на 24 години.
"""

import asyncio
import math
import time
import logging
import os
import json
from dataclasses import dataclass, asdict
from typing import List, Optional

import aiohttp

try:
    from firebase_admin import firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

logger = logging.getLogger("shelter_manager")

GOV_DATASET_URLS = os.environ.get("GOV_DATASET_URLS", "").split(",")
GOV_DATASET_URLS = [url.strip() for url in GOV_DATASET_URLS if url.strip()]

import aiohttp

try:
    from firebase_admin import firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

logger = logging.getLogger("shelter_manager")

# ──────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────

@dataclass
class Shelter:
    id: str
    name: Optional[str]
    address: Optional[str]
    lat: float
    lon: float
    type: str           # bomb_shelter | bunker | metro | underground
    capacity: Optional[int]
    accessible: bool
    source: str         # osm | kyiv_open_data

    def to_dict(self, distance_m: float = 0) -> dict:
        d = asdict(self)
        d["distance_m"] = round(distance_m, 1)
        return d


# ──────────────────────────────────────────────────────────────
# Haversine distance (metres)
# ──────────────────────────────────────────────────────────────

_R = 6_371_000  # Earth radius in metres

def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return distance in metres between two lat/lon points."""
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ / 2) ** 2
    return _R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ──────────────────────────────────────────────────────────────
# Simple grid-based spatial index (no C-extension dependency)
# ──────────────────────────────────────────────────────────────

class _GridIndex:
    """
    Fixed-grid spatial index.  Divides the map into cells of
    ~CELL_SIZE_DEG × CELL_SIZE_DEG.  find_nearby returns candidates
    from neighbouring cells and then filters by exact haversine distance.
    """
    CELL_SIZE_DEG = 0.05  # ~5.5 km at Ukraine's latitude

    def __init__(self):
        self._cells: dict[tuple[int, int], list[Shelter]] = {}
        self._count = 0

    def _key(self, lat: float, lon: float) -> tuple[int, int]:
        return (int(lat / self.CELL_SIZE_DEG), int(lon / self.CELL_SIZE_DEG))

    def insert(self, s: Shelter):
        k = self._key(s.lat, s.lon)
        self._cells.setdefault(k, []).append(s)
        self._count += 1

    def find_nearby(self, lat: float, lon: float, radius_m: float,
                    limit: int = 50) -> List[Shelter]:
        # How many grid cells to scan (~radius in degrees)
        expand = max(1, int(math.ceil(radius_m / (_R * math.radians(self.CELL_SIZE_DEG)))))
        cx, cy = self._key(lat, lon)

        candidates: list[tuple[float, Shelter]] = []
        for dx in range(-expand, expand + 1):
            for dy in range(-expand, expand + 1):
                cell = self._cells.get((cx + dx, cy + dy))
                if cell:
                    for s in cell:
                        d = _haversine(lat, lon, s.lat, s.lon)
                        if d <= radius_m:
                            candidates.append((d, s))

        candidates.sort(key=lambda x: x[0])
        return [s for _, s in candidates[:limit]]

    def __len__(self):
        return self._count


# ──────────────────────────────────────────────────────────────
# Overpass API loader
# ──────────────────────────────────────────────────────────────

OVERPASS_URL = "https://overpass-api.de/api/interpreter"

OVERPASS_QUERY = """
[out:json][timeout:120];
area["name:en"="Ukraine"]["type"="boundary"]->.searchArea;
(
  nwr["amenity"="shelter"]["shelter_type"="bomb_shelter"](area.searchArea);
  nwr["military"="bunker"]["bunker_type"="bomb_shelter"](area.searchArea);
  nwr["amenity"="shelter"]["shelter_type"="public_transport"](area.searchArea);
  nwr["building"="bunker"](area.searchArea);
);
out center;
"""


def _parse_osm_element(elem: dict) -> Optional[Shelter]:
    """Parse a single OSM element into a Shelter object."""
    tags = elem.get("tags", {})

    # Coordinates: for ways/relations use "center", for nodes use lat/lon
    lat = elem.get("lat") or (elem.get("center", {}).get("lat"))
    lon = elem.get("lon") or (elem.get("center", {}).get("lon"))
    if lat is None or lon is None:
        return None

    osm_type = elem.get("type", "node")
    osm_id = elem.get("id", 0)
    shelter_id = f"osm_{osm_type}_{osm_id}"

    # Name
    name = tags.get("name") or tags.get("name:uk") or tags.get("name:en")
    if not name:
        # Build a description from tags
        st = tags.get("shelter_type", tags.get("bunker_type", ""))
        name = f"Укриття ({st})" if st else "Укриття"

    # Address
    addr_parts = []
    street = tags.get("addr:street")
    house = tags.get("addr:housenumber")
    if street:
        addr_parts.append(street)
    if house:
        addr_parts.append(house)
    address = ", ".join(addr_parts) if addr_parts else None

    # Type classification
    shelter_type = "bomb_shelter"
    if tags.get("station") == "subway" or "метро" in (name or "").lower():
        shelter_type = "metro"
    elif tags.get("military") == "bunker":
        shelter_type = "bunker"
    elif tags.get("shelter_type") == "public_transport":
        shelter_type = "underground"

    # Capacity
    cap = tags.get("capacity")
    capacity = int(cap) if cap and cap.isdigit() else None

    # Accessibility
    accessible = tags.get("wheelchair") in ("yes", "limited")

    return Shelter(
        id=shelter_id,
        name=name,
        address=address,
        lat=round(lat, 6),
        lon=round(lon, 6),
        type=shelter_type,
        capacity=capacity,
        accessible=accessible,
        source="osm",
    )


async def _fetch_osm_shelters() -> List[Shelter]:
    """Fetch all shelters in Ukraine from Overpass API."""
    logger.info("📡 Завантаження укриттів з OpenStreetMap (Overpass API)...")
    t0 = time.time()

    async with aiohttp.ClientSession() as session:
        async with session.post(
            OVERPASS_URL,
            data={"data": OVERPASS_QUERY},
            timeout=aiohttp.ClientTimeout(total=180),
        ) as resp:
            if resp.status != 200:
                text = await resp.text()
                logger.error(f"Overpass API error {resp.status}: {text[:200]}")
                return []
            data = await resp.json(content_type=None)

    elements = data.get("elements", [])
    shelters: List[Shelter] = []
    seen_coords: set[tuple[float, float]] = set()

    for elem in elements:
        s = _parse_osm_element(elem)
        if s is None:
            continue
        # Deduplicate by coordinates (~5m precision)
        coord_key = (round(s.lat, 4), round(s.lon, 4))
        if coord_key in seen_coords:
            continue
        seen_coords.add(coord_key)
        shelters.append(s)

    elapsed = time.time() - t0
    logger.info(f"✅ Завантажено {len(shelters)} укриттів з OSM за {elapsed:.1f}с")
    return shelters


async def _fetch_firestore_shelters() -> List[Shelter]:
    """Fetch official shelters from Firestore."""
    if not HAS_FIREBASE:
        return []
    
    logger.info("📡 Завантаження офіційних укриттів з Firestore (sirenua_shelters)...")
    try:
        import asyncio
        loop = asyncio.get_running_loop()
        
        def _get_docs():
            try:
                db = firestore.client()
                return list(db.collection("sirenua_shelters").stream())
            except ValueError:
                return []  # Firebase not initialized yet
                
        docs = await loop.run_in_executor(None, _get_docs)
        
        shelters = []
        for doc in docs:
            data = doc.to_dict()
            s = Shelter(
                id=doc.id,
                name=data.get("name"),
                address=data.get("address"),
                lat=data.get("lat", 0.0),
                lon=data.get("lon", 0.0),
                type=data.get("type", "bomb_shelter"),
                capacity=data.get("capacity"),
                accessible=data.get("accessible", False),
                source="gov"
            )
            shelters.append(s)
            
        logger.info(f"✅ Завантажено {len(shelters)} укриттів з Firestore")
        return shelters
    except Exception as e:
        logger.error(f"⚠️ Помилка завантаження з Firestore: {e}")
        return []


# ──────────────────────────────────────────────────────────────
# Shelter Manager (singleton-like, used by FastAPI server)
# ──────────────────────────────────────────────────────────────

class ShelterManager:
    """Manages the in-memory shelter database with spatial index."""

    REFRESH_INTERVAL = 24 * 3600  # 24 hours

    def __init__(self):
        self._index = _GridIndex()
        self._shelters: List[Shelter] = []
        self._loaded = False
        self._refresh_task: Optional[asyncio.Task] = None
        self._last_load_time: Optional[float] = None

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def total_count(self) -> int:
        return len(self._shelters)

    async def load(self):
        """Initial load of shelters from OSM and Firestore."""
        osm_shelters = await _fetch_osm_shelters()
        gov_shelters = await _fetch_firestore_shelters()
        
        idx = _GridIndex()
        final_shelters = []
        
        # 1. Спочатку додаємо офіційні укриття
        for s in gov_shelters:
            idx.insert(s)
            final_shelters.append(s)
            
        # 2. Додаємо OSM укриття, уникаючи дублікатів (радіус 15 метрів)
        skipped = 0
        for s in osm_shelters:
            if gov_shelters:
                nearby = idx.find_nearby(s.lat, s.lon, radius_m=15.0, limit=1)
                # Якщо поруч є офіційне укриття, пропускаємо OSM
                if nearby and nearby[0].source == "gov":
                    skipped += 1
                    continue
            
            idx.insert(s)
            final_shelters.append(s)

        if skipped > 0:
            logger.info(f"🔄 Відкинуто {skipped} дублікатів з OSM (перекрито офіційними)")

        if final_shelters:
            self._index = idx
            self._shelters = final_shelters
            self._loaded = True
            self._last_load_time = time.time()
            logger.info(f"🌍 Всього доступно укриттів: {len(self._shelters)}")
            logger.info(f"🗺️ Індекс побудовано: {len(idx)} укриттів")
        else:
            logger.warning("⚠️ Не вдалося завантажити укриття. Буде повторна спроба через 5 хв.")

    def find_nearby(self, lat: float, lon: float, radius_m: float = 1500,
                    limit: int = 50) -> List[dict]:
        """Find shelters within radius_m of (lat, lon)."""
        if not self._loaded:
            return []

        results = self._index.find_nearby(lat, lon, radius_m, limit=limit)
        return [
            s.to_dict(distance_m=_haversine(lat, lon, s.lat, s.lon))
            for s in results
        ]

    async def start_refresh_loop(self):
        """Start background refresh task."""
        self._refresh_task = asyncio.create_task(self._refresh_loop())
        self._sync_task = asyncio.create_task(self._sync_gov_data_loop())

    async def _sync_gov_data_loop(self):
        """Автоматична синхронізація офіційних укриттів (data.gov.ua) з Firestore щоночі."""
        if not HAS_FIREBASE:
            return
            
        # Чекаємо 10 хвилин після старту сервера, щоб не навантажувати систему відразу
        await asyncio.sleep(600)
        
        while True:
            if not GOV_DATASET_URLS:
                # Якщо URL-ів немає, чекаємо добу і перевіряємо знову
                await asyncio.sleep(24 * 3600)
                continue
                
            try:
                logger.info("⬇️ Починаємо автоматичну синхронізацію укриттів з відкритих даних...")
                total_synced = 0
                
                async with aiohttp.ClientSession() as session:
                    for url in GOV_DATASET_URLS:
                        try:
                            async with session.get(url, timeout=60) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    if isinstance(data, list):
                                        total_synced += await self._upload_to_firestore(data)
                                    elif isinstance(data, dict) and "result" in data: # CKAN API fallback
                                        records = data["result"].get("records", [])
                                        total_synced += await self._upload_to_firestore(records)
                        except Exception as e:
                            logger.error(f"Помилка завантаження датасету з {url}: {e}")
                            
                logger.info(f"✅ Синхронізація завершена. Оновлено {total_synced} укриттів.")
                
                # Перезавантажуємо кеш, бо дані у базі оновилися
                await self.load()
                
                # Успіх - чекаємо 24 години до наступної спроби
                await asyncio.sleep(24 * 3600)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"⚠️ Помилка синхронізації офіційних укриттів: {e}")
                # При помилці чекаємо 1 годину і повторюємо
                await asyncio.sleep(3600)

    async def _upload_to_firestore(self, records: List[dict]) -> int:
        """Uploads a list of dictionaries to Firestore sirenua_shelters."""
        try:
            loop = asyncio.get_running_loop()
            def _upload():
                db = firestore.client()
                batch = db.batch()
                count = 0
                
                for r in records:
                    lat = float(r.get("lat") or r.get("latitude") or 0.0)
                    lon = float(r.get("lon") or r.get("longitude") or 0.0)
                    if lat == 0.0 or lon == 0.0:
                        continue
                        
                    # Deterministic ID to overwrite old data and avoid duplication
                    doc_id = f"gov_{round(lat, 5)}_{round(lon, 5)}".replace(".", "_")
                    doc_ref = db.collection("sirenua_shelters").document(doc_id)
                    
                    capacity_str = str(r.get("capacity") or "0")
                    capacity = int(''.join(filter(str.isdigit, capacity_str))) if any(c.isdigit() for c in capacity_str) else 0

                    batch.set(doc_ref, {
                        "name": str(r.get("name") or r.get("title") or "Укриття"),
                        "address": str(r.get("address") or r.get("location") or ""),
                        "lat": lat,
                        "lon": lon,
                        "type": str(r.get("type") or r.get("shelter_type") or "bomb_shelter"),
                        "capacity": capacity,
                        "accessible": bool(r.get("accessible") or False),
                        "source": "gov"
                    })
                    count += 1
                    
                    if count % 400 == 0:
                        batch.commit()
                        batch = db.batch()
                        
                if count % 400 != 0:
                    batch.commit()
                return count
                
            return await loop.run_in_executor(None, _upload)
        except Exception as e:
            logger.error(f"Firestore upload error: {e}")
            return 0

    async def _refresh_loop(self):
        """Periodically re-fetch shelters from OSM."""
        while True:
            try:
                await asyncio.sleep(self.REFRESH_INTERVAL)
                logger.info("🔄 Оновлення бази укриттів...")
                await self.load()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Помилка оновлення укриттів: {e}")
                await asyncio.sleep(300)  # retry in 5 min

    async def stop(self):
        if self._refresh_task:
            self._refresh_task.cancel()
        if hasattr(self, '_sync_task') and self._sync_task:
            self._sync_task.cancel()
        
        try:
            if self._refresh_task:
                await self._refresh_task
        except asyncio.CancelledError:
            pass
        try:
            if hasattr(self, '_sync_task') and self._sync_task:
                await self._sync_task
        except asyncio.CancelledError:
            pass
