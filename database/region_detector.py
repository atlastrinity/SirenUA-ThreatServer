"""
Region Detector — Визначення області України за географічними координатами.
Містить центроїди, коди та україномовні назви всіх 25 регіонів України.
"""

import math
from typing import Optional, Dict, Tuple

# Центроїди областей України (lat, lon)
REGION_CENTROIDS: Dict[str, Tuple[float, float, str]] = {
    "kyiv_city": (50.4501, 30.5234, "м. Київ"),
    "kyiv_oblast": (50.0500, 30.1500, "Київська область"),
    "lviv": (49.8397, 24.0297, "Львівська область"),
    "kharkiv": (49.9935, 36.2304, "Харківська область"),
    "dnipro": (48.4647, 35.0462, "Дніпропетровська область"),
    "odesa": (46.4825, 30.7233, "Одеська область"),
    "vinnytsia": (49.2331, 28.4682, "Вінницька область"),
    "volyn": (50.7412, 25.3201, "Волинська область"),
    "zhytomyr": (50.2547, 28.6587, "Житомирська область"),
    "zakarpattia": (48.6208, 22.2879, "Закарпатська область"),
    "zaporizhzhia": (47.8388, 35.1396, "Запорізька область"),
    "ivano_frankivsk": (48.9226, 24.7111, "Івано-Франківська область"),
    "kirovohrad": (48.5079, 32.2623, "Кіровоградська область"),
    "mykolaiv": (46.9750, 31.9946, "Миколаївська область"),
    "poltava": (49.5883, 34.5514, "Полтавська область"),
    "rivne": (50.6199, 26.2516, "Рівненська область"),
    "sumy": (50.9077, 34.7981, "Сумська область"),
    "ternopil": (49.5535, 25.5948, "Тернопільська область"),
    "khmelnytskyi": (49.4230, 26.9871, "Хмельницька область"),
    "cherkasy": (49.4444, 32.0598, "Черкаська область"),
    "chernivtsi": (48.2915, 25.9352, "Чернівецька область"),
    "chernihiv": (51.4982, 31.2893, "Чернігівська область"),
    "donetsk": (48.0159, 37.8028, "Донецька область"),
    "luhansk": (48.5740, 39.3078, "Луганська область"),
    "kherson": (46.6354, 32.6169, "Херсонська область"),
    "crimea": (45.3000, 34.1000, "Автономна Республіка Крим"),
}

# Синоніми для швидкого резолвінгу за назвою
REGION_NAME_TO_CODE: Dict[str, str] = {
    "м. київ": "kyiv_city",
    "київ": "kyiv_city",
    "kyiv": "kyiv_city",
    "київська область": "kyiv_oblast",
    "київська": "kyiv_oblast",
    "львівська область": "lviv",
    "львівська": "lviv",
    "львів": "lviv",
    "lviv": "lviv",
    "харківська область": "kharkiv",
    "харківська": "kharkiv",
    "харків": "kharkiv",
    "дніпропетровська область": "dnipro",
    "дніпропетровська": "dnipro",
    "дніпро": "dnipro",
    "одеська область": "odesa",
    "одеська": "odesa",
    "одеса": "odesa",
    "вінницька область": "vinnytsia",
    "вінницька": "vinnytsia",
    "вінниця": "vinnytsia",
    "волинська область": "volyn",
    "волинська": "volyn",
    "луцьк": "volyn",
    "житомирська область": "zhytomyr",
    "житомирська": "zhytomyr",
    "житомир": "zhytomyr",
    "закарпатська область": "zakarpattia",
    "закарпатська": "zakarpattia",
    "ужгород": "zakarpattia",
    "запорізька область": "zaporizhzhia",
    "запорізька": "zaporizhzhia",
    "запоріжжя": "zaporizhzhia",
    "івано-франківська область": "ivano_frankivsk",
    "івано-франківська": "ivano_frankivsk",
    "івано-франківськ": "ivano_frankivsk",
    "кіровоградська область": "kirovohrad",
    "кіровоградська": "kirovohrad",
    "кропивницький": "kirovohrad",
    "миколаївська область": "mykolaiv",
    "миколаївська": "mykolaiv",
    "миколаїв": "mykolaiv",
    "полтавська область": "poltava",
    "полтавська": "poltava",
    "полтава": "poltava",
    "рівненська область": "rivne",
    "рівненська": "rivne",
    "рівне": "rivne",
    "сумська область": "sumy",
    "сумська": "sumy",
    "суми": "sumy",
    "тернопільська область": "ternopil",
    "тернопільська": "ternopil",
    "тернопіль": "ternopil",
    "хмельницька область": "khmelnytskyi",
    "хмельницька": "khmelnytskyi",
    "хмельницький": "khmelnytskyi",
    "черкаська область": "cherkasy",
    "черкаська": "cherkasy",
    "черкаси": "cherkasy",
    "чернівецька область": "chernivtsi",
    "чернівецька": "chernivtsi",
    "чернівці": "chernivtsi",
    "чернігівська область": "chernihiv",
    "чернігівська": "chernihiv",
    "чернігів": "chernihiv",
    "донецька область": "donetsk",
    "донецька": "donetsk",
    "донецьк": "donetsk",
    "луганська область": "luhansk",
    "луганська": "luhansk",
    "луганськ": "luhansk",
    "херсонська область": "kherson",
    "херсонська": "kherson",
    "херсон": "kherson",
    "автономна республіка крим": "crimea",
    "ар крим": "crimea",
    "крим": "crimea",
    "севастополь": "crimea",
}

_R = 6_371_000

def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ / 2) ** 2
    return _R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def detect_region_by_coordinates(lat: float, lon: float) -> str:
    """
    Визначає код регіону України за географічними координатами.
    Враховує окремо м. Київ (радіус 22 км від Хрещатика).
    """
    kyiv_dist = _haversine(lat, lon, 50.4501, 30.5234)
    if kyiv_dist <= 22_000:
        return "kyiv_city"

    closest_code = "kyiv_oblast"
    min_dist = float("inf")

    for code, (c_lat, c_lon, _) in REGION_CENTROIDS.items():
        if code == "kyiv_city":
            continue
        d = _haversine(lat, lon, c_lat, c_lon)
        if d < min_dist:
            min_dist = d
            closest_code = code

    return closest_code


def resolve_region_code(query: str) -> Optional[str]:
    """Резолвить назву або код регіону до канонічного ідентифікатора."""
    q = query.strip().lower()
    if q in REGION_CENTROIDS:
        return q
    return REGION_NAME_TO_CODE.get(q)


def get_region_name(code: str) -> str:
    """Повертає офіційну україномовну назву регіону за кодом."""
    if code in REGION_CENTROIDS:
        return REGION_CENTROIDS[code][2]
    return code
