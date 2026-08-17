"""
Centralized Threat Types, Kinematics, Speeds, Russian Airbases, and Calculation Constants Registry.
Serves as the single source of truth for all departure and arrival threat objects across the system.
"""

from typing import Dict, Tuple, Optional, List, Any
import re

# ==============================================================================
# 1. THREAT TYPE IDENTIFIER CONSTANTS (Single Source of Truth)
# ==============================================================================
THREAT_SHAHED = "shahed"
THREAT_CRUISE_MISSILE = "cruise_missile"
THREAT_BALLISTIC = "ballistic"
THREAT_MIG31K = "mig31k"
THREAT_KAB = "kab"
THREAT_TU95 = "tu95"
THREAT_TU22M3 = "tu22m3"
THREAT_SU35 = "su35_su57"
THREAT_SU35_ALT = "su35"
THREAT_ISKANDER = "iskander"
THREAT_ARTILLERY = "artillery"
THREAT_URBAN_FIGHTS = "urban_fights"
THREAT_CHEMICAL = "chemical"
THREAT_NUCLEAR = "nuclear"
THREAT_ZIRCON = "zircon"
THREAT_MLRS = "mlrs"
THREAT_FPV = "fpv"
THREAT_RECON = "recon"
THREAT_RECON_UAV = "recon_uav"
THREAT_OFFICIAL_ALARM = "official_alarm"
THREAT_UNKNOWN = "unknown"

ALL_THREAT_TYPES: List[str] = [
    THREAT_SHAHED,
    THREAT_CRUISE_MISSILE,
    THREAT_BALLISTIC,
    THREAT_MIG31K,
    THREAT_KAB,
    THREAT_TU95,
    THREAT_TU22M3,
    THREAT_SU35,
    THREAT_ISKANDER,
    THREAT_ARTILLERY,
    THREAT_URBAN_FIGHTS,
    THREAT_CHEMICAL,
    THREAT_NUCLEAR,
    THREAT_ZIRCON,
    THREAT_MLRS,
    THREAT_FPV,
    THREAT_RECON,
    THREAT_RECON_UAV,
    THREAT_OFFICIAL_ALARM,
    THREAT_UNKNOWN,
]

# ==============================================================================
# 2. DISPLAY TITLES & SHORT NAMES (UKRAINIAN)
# ==============================================================================
THREAT_TITLES: Dict[str, str] = {
    THREAT_SHAHED: "БПЛА Shahed-136",
    THREAT_CRUISE_MISSILE: "Крилаті ракети",
    THREAT_BALLISTIC: "Балістична ракета",
    THREAT_MIG31K: "МіГ-31К (Кинджал)",
    THREAT_KAB: "Керовані авіабомби (КАБ)",
    THREAT_TU95: "Ту-95МС (крилаті ракети)",
    THREAT_TU22M3: "Ту-22М3 (ракети Х-22/Х-32)",
    THREAT_SU35: "Су-35/Су-57 (тактична авіація)",
    THREAT_SU35_ALT: "Су-35/Су-57 (тактична авіація)",
    THREAT_ISKANDER: "Іскандер-М",
    THREAT_ARTILLERY: "Артилерія",
    THREAT_URBAN_FIGHTS: "Вуличні бої",
    THREAT_CHEMICAL: "Хімічна загроза",
    THREAT_NUCLEAR: "Радіаційна небезпека",
    THREAT_ZIRCON: "Гіперзвукова ракета 3M22 Циркон",
    THREAT_MLRS: "РСЗВ (Торнадо-С / Град / Ураган)",
    THREAT_FPV: "FPV дрон / Ланцет",
    THREAT_RECON: "Розвідувальний БПЛА",
    THREAT_RECON_UAV: "Розвідувальний БПЛА",
    THREAT_OFFICIAL_ALARM: "Повітряна тривога",
    THREAT_UNKNOWN: "Повітряна загроза",
}

# Alias for backwards compatibility across modules
THREAT_TYPES = THREAT_TITLES

THREAT_SHORT_NAMES: Dict[str, str] = {
    THREAT_SHAHED: "БпЛА",
    THREAT_CRUISE_MISSILE: "крилата ракета",
    THREAT_BALLISTIC: "балістика",
    THREAT_MIG31K: "МіГ-31К",
    THREAT_KAB: "КАБ",
    THREAT_TU95: "Ту-95МС",
    THREAT_TU22M3: "Ту-22М3",
    THREAT_SU35: "Су-35",
    THREAT_SU35_ALT: "Су-35",
    THREAT_ISKANDER: "Іскандер-М",
    THREAT_ARTILLERY: "обстріл",
    THREAT_URBAN_FIGHTS: "вуличні бої",
    THREAT_CHEMICAL: "хімнебезпека",
    THREAT_NUCLEAR: "радіація",
    THREAT_ZIRCON: "Циркон",
    THREAT_MLRS: "РСЗВ",
    THREAT_FPV: "FPV-дрон",
    THREAT_RECON: "розвідник",
    THREAT_RECON_UAV: "розвідник",
    THREAT_OFFICIAL_ALARM: "тривога",
    THREAT_UNKNOWN: "загроза",
}

# ==============================================================================
# 3. KINEMATICS & CRUISING SPEEDS (KM/H & KM/MIN)
# ==============================================================================
DEFAULT_SPEEDS_KMH: Dict[str, float] = {
    THREAT_SHAHED: 165.0,          # ~150-180 km/h (Shahed-136/Geran)
    THREAT_CRUISE_MISSILE: 850.0,  # ~800-900 km/h (Kh-101/Kalibr)
    THREAT_BALLISTIC: 5500.0,      # ~4500-7000 km/h (Iskander-M/S-300)
    THREAT_MIG31K: 2500.0,         # ~2500 km/h (Kh-47M2 Kinzhal launch phase)
    THREAT_KAB: 900.0,             # ~800-1000 km/h (FAB with UMPK gliding after Su-34 supersonic/subsonic drop)
    THREAT_TU95: 800.0,            # ~800 km/h cruising after launch
    THREAT_TU22M3: 4200.0,         # ~4000-4500 km/h (Kh-22/Kh-32 supersonic)
    THREAT_SU35: 950.0,            # ~900-1000 km/h (Kh-59/69 tactical)
    THREAT_ISKANDER: 5500.0,       # ~4500-7000 km/h
    THREAT_ARTILLERY: 1200.0,      # ~1000-2500 km/h
    THREAT_URBAN_FIGHTS: 0.0,
    THREAT_CHEMICAL: 50.0,
    THREAT_NUCLEAR: 0.0,
    THREAT_ZIRCON: 11000.0,        # ~Mach 9 hypersonic (3M22 Zircon)
    THREAT_MLRS: 2200.0,           # ~2000-2500 km/h MLRS rockets
    THREAT_FPV: 140.0,             # ~120-150 km/h kamikaze drones
    THREAT_RECON: 120.0,           # ~100-140 km/h (Supercam/Orlan/Zala)
    THREAT_RECON_UAV: 120.0,
    THREAT_OFFICIAL_ALARM: 0.0,
    THREAT_UNKNOWN: 300.0,
}

KM_PER_MINUTE: Dict[str, float] = {
    t: round(speed / 60.0, 2) for t, speed in DEFAULT_SPEEDS_KMH.items()
}

# ==============================================================================
# 4. AUTO-CLEAR TIMEOUTS (TTL SECONDS) & DEFAULT ETAS
# ==============================================================================
THREAT_AUTO_CLEAR_DELAYS: Dict[str, Tuple[int, int]] = {
    THREAT_SHAHED: (10800, 10800),         # 3 hours max TTL
    THREAT_CRUISE_MISSILE: (2700, 3600),   # 45-60 mins
    THREAT_BALLISTIC: (600, 1800),         # 10-30 mins
    THREAT_MIG31K: (1800, 2700),           # 30-45 mins
    THREAT_KAB: (300, 420),                # 5-7 mins max TTL (glide bomb physical flight limit)
    THREAT_TU95: (5400, 5400),             # 90 mins
    THREAT_TU22M3: (3600, 3600),           # 60 mins
    THREAT_SU35: (2700, 3600),             # 45 mins
    THREAT_ISKANDER: (1200, 1800),         # 20-30 mins
    THREAT_ARTILLERY: (1800, 1800),        # 30 mins
    THREAT_URBAN_FIGHTS: (3600, 3600),     # 60 mins
    THREAT_CHEMICAL: (3600, 3600),         # 60 mins
    THREAT_NUCLEAR: (7200, 7200),          # 120 mins
    THREAT_ZIRCON: (600, 1200),            # 10-20 mins
    THREAT_MLRS: (1200, 1800),             # 20-30 mins
    THREAT_FPV: (1800, 1800),              # 30 mins
    THREAT_RECON: (3600, 3600),            # 60 mins
    THREAT_RECON_UAV: (3600, 3600),        # 60 mins
    THREAT_OFFICIAL_ALARM: (3600, 3600),
    THREAT_UNKNOWN: (3600, 3600),
}

THREAT_DEFAULT_ETAS: Dict[str, Tuple[str, str]] = {
    THREAT_SHAHED: ("до 3 год", "до 1.5 год"),
    THREAT_CRUISE_MISSILE: ("до 55 хв", "до 30 хв"),
    THREAT_BALLISTIC: ("до 15 хв", "до 5 хв"),
    THREAT_MIG31K: ("до 40 хв", "до 40 хв"),
    THREAT_KAB: ("до 5 хв", "до 5 хв"),
    THREAT_TU95: ("до 2 год", "до 1.5 год"),
    THREAT_TU22M3: ("до 15 хв", "до 10 хв"),
    THREAT_SU35: ("до 20 хв", "до 15 хв"),
    THREAT_ISKANDER: ("до 25 хв", "до 5 хв"),
    THREAT_ARTILLERY: ("до 10 хв", "до 5 хв"),
    THREAT_URBAN_FIGHTS: ("в зоні", "в зоні"),
    THREAT_CHEMICAL: ("до 30 хв", "до 15 хв"),
    THREAT_NUCLEAR: ("в зоні", "в зоні"),
    THREAT_ZIRCON: ("до 5 хв", "до 3 хв"),
    THREAT_MLRS: ("до 10 хв", "до 5 хв"),
    THREAT_FPV: ("до 20 хв", "до 15 хв"),
    THREAT_RECON: ("до 30 хв", "до 30 хв"),
    THREAT_RECON_UAV: ("до 30 хв", "до 30 хв"),
    THREAT_OFFICIAL_ALARM: ("-", "-"),
    THREAT_UNKNOWN: ("до 30 хв", "до 30 хв"),
}

THREAT_PREDICTIVE_WEIGHTS: Dict[str, float] = {
    THREAT_SHAHED: 0.15,
    THREAT_CRUISE_MISSILE: 0.08,
    THREAT_MIG31K: 0.05,
    THREAT_BALLISTIC: 0.0,
    THREAT_KAB: 0.02,
    THREAT_TU95: 0.10,
    THREAT_TU22M3: 0.05,
    THREAT_SU35: 0.04,
    THREAT_ISKANDER: 0.0,
    THREAT_ARTILLERY: 0.01,
    THREAT_URBAN_FIGHTS: 0.0,
    THREAT_CHEMICAL: 0.0,
    THREAT_NUCLEAR: 0.0,
    THREAT_ZIRCON: 0.0,
    THREAT_MLRS: 0.01,
    THREAT_FPV: 0.02,
    THREAT_RECON: 0.05,
    THREAT_RECON_UAV: 0.05,
    THREAT_OFFICIAL_ALARM: 0.0,
    THREAT_UNKNOWN: 0.05,
}

THREAT_ETA_DEFAULTS_SECONDS: Dict[str, int] = {
    THREAT_SHAHED: 5400,
    THREAT_CRUISE_MISSILE: 1200,
    THREAT_BALLISTIC: 180,
    THREAT_MIG31K: 1200,
    THREAT_KAB: 300,
    THREAT_TU95: 3600,
    THREAT_TU22M3: 300,
    THREAT_SU35: 900,
    THREAT_ISKANDER: 180,
    THREAT_ARTILLERY: 120,
    THREAT_URBAN_FIGHTS: 0,
    THREAT_CHEMICAL: 900,
    THREAT_NUCLEAR: 0,
    THREAT_ZIRCON: 120,
    THREAT_MLRS: 180,
    THREAT_FPV: 900,
    THREAT_RECON: 1800,
    THREAT_RECON_UAV: 1800,
    THREAT_OFFICIAL_ALARM: 1800,
    THREAT_UNKNOWN: 1800,
}

# ==============================================================================
# 4b. THREAT ICON REGISTRY (SFSYMBOL CONSTANTS)
# ==============================================================================
THREAT_ICONS: Dict[str, str] = {
    THREAT_SHAHED: "airplane.circle.fill",
    THREAT_CRUISE_MISSILE: "paperplane.fill",
    THREAT_BALLISTIC: "flame.fill",
    THREAT_MIG31K: "bolt.fill",
    THREAT_KAB: "circle.circle.fill",
    THREAT_TU95: "airplane",
    THREAT_TU22M3: "airplane",
    THREAT_SU35: "airplane.departure",
    THREAT_ISKANDER: "flame.fill",
    THREAT_ARTILLERY: "burst.fill",
    THREAT_URBAN_FIGHTS: "shield.slash.fill",
    THREAT_CHEMICAL: "smoke.fill",
    THREAT_NUCLEAR: "atom",
    THREAT_ZIRCON: "bolt.horizontal.fill",
    THREAT_MLRS: "sparkles",
    THREAT_FPV: "viewfinder",
    THREAT_RECON: "eye.fill",
    THREAT_RECON_UAV: "eye.fill",
    THREAT_OFFICIAL_ALARM: "bell.fill",
    THREAT_UNKNOWN: "exclamationmark.triangle.fill",
}

def get_threat_icon(threat_type: Optional[str]) -> str:
    """Returns official SFSymbol icon for a given threat object type."""
    if not threat_type:
        return THREAT_ICONS[THREAT_UNKNOWN]
    return THREAT_ICONS.get(threat_type, THREAT_ICONS[THREAT_UNKNOWN])

# ==============================================================================
# 5. KEYWORD CLASSIFICATION MAPPINGS FOR TELEGRAM PARSER
# ==============================================================================
THREAT_KEYWORDS: Dict[str, List[str]] = {
    THREAT_MIG31K: [
        "міг-31", "міг31", "миг-31", "миг31", "mig-31", "mig31",
        "кинджал", "кинжал", "kinzhal", "х-47", "х47", "х-47м2", "х47м2"
    ],
    THREAT_TU95: [
        "ту-95", "ту95", "tu-95", "tu95", "ту-160", "tu160", "стратегіч", "стратегическ"
    ],
    THREAT_TU22M3: [
        "ту-22", "ту22", "tu-22", "tu22", "х-22", "х22", "х-32", "х32"
    ],
    THREAT_SHAHED: [
        "шахед", "shahed", "бпла", "дрон", "безпілотник", "беспилотник", "мопед",
        "балалайк", "герань", "гербер", "пароді", "імітатор", "имитатор",
        "фальш-ціль", "фальш ціль", "ударні бпла", "ударний бпла"
    ],
    THREAT_RECON: [
        "розвідник", "розвідувальн", "разведчик", "разведывательн", "орлан", "orlan",
        "supercam", "суперкам", "zala", "зала", "мерлін", "merlin", "форпост", "forpost"
    ],
    THREAT_RECON_UAV: [
        "розвідувальний бпла", "разведывательный бпла"
    ],
    THREAT_ISKANDER: [
        "іскандер-м", "іскандер", "искандер-м", "искандер", "iskander"
    ],
    THREAT_BALLISTIC: [
        "баліст", "баллист", "балістична", "балістичне", "балістичного",
        "s-300", "с-300", "с300", "s-400", "с-400", "с400",
        "kn-23", "кн-23", "точка-у", "орєшнік", "орешник", "рубєж", "рубеж", "рс-26",
        "швидкісна ціль", "скоростная цель"
    ],
    THREAT_CRUISE_MISSILE: [
        "ракет", "крилат", "крылат", "калібр", "калибр", "kalibr",
        "х-101", "х101", "х-55", "х55", "х-555", "х555",
        "х-59", "х59", "х-69", "х69", "х-31", "х31", "х-35", "х35",
        "онікс", "оникс", "oniks", "п-800", "p-800", "іскандер-к", "искандер-к"
    ],
    THREAT_ZIRCON: [
        "циркон", "zircon", "3м22", "3m22", "гіперзвук", "гиперзвук"
    ],
    THREAT_ARTILLERY: [
        "артобстріл", "артилері", "артиллери", "обстріл", "обстрел", "міномет", "сау"
    ],
    THREAT_MLRS: [
        "рсзв", "рсзо", "торнадо-с", "торнадо", "град", "ураган", "смерч", "солнцепек", "вільха", "ольха"
    ],
    THREAT_FPV: [
        "fpv", "фпв", "ланцет", "lancet", "молнія", "молния", "куб", "барражир", "дрон-камікадзе"
    ],
    THREAT_SU35: [
        "су-34", "су34", "су-35", "су35", "су-30", "су30", "су-57", "су57", "сушка", "сушки", "тактична авіація", "тактической авиации"
    ],
    THREAT_KAB: [
        "каб", "каби", "кабів", "авіабомб", "авиабомб", "умпк", "умпб", "керован", "управляемые",
        "фаб", "уаб", "одаб", "рбк", "грім-е1", "гром-е1", "бомбардуван", "плануюч", "планирующ"
    ],
    THREAT_OFFICIAL_ALARM: [
        "повітряна тривога", "воздушная тревога", "тривога в області", "сирена"
    ]
}

# ==============================================================================
# 5b. DEPARTURE AIRFIELDS & LAUNCH ORIGIN CONSTANTS
# ==============================================================================
AIRBASE_SAVASLEYKA = "savasleyka"
AIRBASE_OLENYA = "olenya"
AIRBASE_ENGELS = "engels"
AIRBASE_SHAYKOVKA = "shaykovka"
AIRBASE_AKHTUBINSK = "akhtubinsk"
AIRBASE_PRIMORSKO_AKHTARSK = "primorsko_akhtarsk"
AIRBASE_YEYSK = "yeysk"
AIRBASE_MILLEROVO = "millerovo"
AIRBASE_MOROZOVSK = "morozovsk"
AIRBASE_BUTURLINOVKA = "buturlinovka"
AIRBASE_KUSHCHEVSKAYA = "kushchevskaya"
AIRBASE_TAGANROG = "taganrog"
AIRBASE_KURSK = "kursk"
AIRBASE_BELGOROD = "belgorod"
AIRBASE_MOZDOK = "mozdok"
AIRBASE_BALTIMOR = "baltimor_voronezh"
AIRBASE_HALINO = "halino_kursk"
AIRBASE_DYAGILEVO = "dyagilevo_ryazan"
AIRBASE_BELBEK = "belbek_crimea"
AIRBASE_SAKY = "saky_crimea"
AIRBASE_GVARDEYSKOYE = "gvardeyskoye_crimea"
AIRBASE_SOLTSY = "soltsy"
AIRBASE_LIPETSK = "lipetsk"
AIRBASE_SESHCHA = "seshcha"
AIRBASE_KRYMSK = "krymsk"
LAUNCH_HUB_CHAUDA = "chauda_crimea"
LAUNCH_HUB_BLACK_SEA = "black_sea"
LAUNCH_HUB_CASPIAN_SEA = "caspian_sea"

RUSSIAN_AIRBASES: Dict[str, Dict[str, Any]] = {
    AIRBASE_SAVASLEYKA: {
        "title": "Аеродром Саваслейка (Нижньогородська обл.)",
        "primary_threat": THREAT_MIG31K,
        "keywords": ["саваслейка", "саваслейкі", "savasleyka"],
        "lat_lon": (55.45, 42.31),
    },
    AIRBASE_OLENYA: {
        "title": "Аеродром Оленья (Мурманська обл.)",
        "primary_threat": THREAT_TU95,
        "keywords": ["оленья", "оленью", "оленья!", "olenya"],
        "lat_lon": (68.15, 33.46),
    },
    AIRBASE_ENGELS: {
        "title": "Аеродром Енгельс (Саратовська обл.)",
        "primary_threat": THREAT_TU95,
        "keywords": ["енгельс", "энгельс", "engels"],
        "lat_lon": (51.48, 46.21),
    },
    AIRBASE_SHAYKOVKA: {
        "title": "Аеродром Шайковка (Калузька обл.)",
        "primary_threat": THREAT_TU22M3,
        "keywords": ["шайковка", "шайковки", "shaykovka"],
        "lat_lon": (54.22, 34.36),
    },
    AIRBASE_AKHTUBINSK: {
        "title": "Аеродром Ахтубінськ (Астраханська обл.)",
        "primary_threat": THREAT_SU35,
        "keywords": ["ахтубінськ", "ахтубинск", "akhtubinsk"],
        "lat_lon": (48.31, 46.12),
    },
    AIRBASE_PRIMORSKO_AKHTARSK: {
        "title": "Аеродром Приморсько-Ахтарськ (Краснодарський край)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["приморсько-ахтарськ", "приморско-ахтарск", "приахтарськ"],
        "lat_lon": (46.04, 38.01),
    },
    AIRBASE_YEYSK: {
        "title": "Аеродром Єйськ (Краснодарський край)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["єйськ", "ейск", "yeysk"],
        "lat_lon": (46.68, 38.25),
    },
    AIRBASE_MILLEROVO: {
        "title": "Аеродром Міллерово (Ростовська обл.)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["міллерово", "миллерово", "millerovo"],
        "lat_lon": (48.95, 40.30),
    },
    AIRBASE_MOROZOVSK: {
        "title": "Аеродром Морозовськ (Ростовська обл.)",
        "primary_threat": THREAT_KAB,
        "keywords": ["морозовськ", "морозовск", "morozovsk"],
        "lat_lon": (48.31, 41.79),
    },
    AIRBASE_BUTURLINOVKA: {
        "title": "Аеродром Бутурлинівка (Воронезька обл.)",
        "primary_threat": THREAT_KAB,
        "keywords": ["бутурлинівка", "бутурлиновка", "buturlinovka"],
        "lat_lon": (50.84, 40.60),
    },
    AIRBASE_KUSHCHEVSKAYA: {
        "title": "Аеродром Кущевська (Краснодарський край)",
        "primary_threat": THREAT_KAB,
        "keywords": ["кущевська", "кущевская", "kushchevskaya"],
        "lat_lon": (46.54, 39.55),
    },
    AIRBASE_TAGANROG: {
        "title": "Аеродром Таганрог (Ростовська обл.)",
        "primary_threat": THREAT_SU35,
        "keywords": ["таганрог", "taganrog"],
        "lat_lon": (47.20, 38.84),
    },
    AIRBASE_KURSK: {
        "title": "Аеродром Курськ-Східний (Курська обл.)",
        "primary_threat": THREAT_SU35,
        "keywords": ["курськ", "курск", "kursk"],
        "lat_lon": (51.75, 36.29),
    },
    AIRBASE_BELGOROD: {
        "title": "Пусковий район Бєлгород (Бєлгородська обл.)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["бєлгород", "белгород", "belgorod"],
        "lat_lon": (50.60, 36.58),
    },
    AIRBASE_MOZDOK: {
        "title": "Аеродром Моздок (Північна Осетія)",
        "primary_threat": THREAT_TU22M3,
        "keywords": ["моздок", "mozdok"],
        "lat_lon": (43.78, 44.60),
    },
    AIRBASE_BALTIMOR: {
        "title": "Аеродром Балтімор (Воронеж)",
        "primary_threat": THREAT_SU35,
        "keywords": ["балтімор", "балтимор", "baltimor"],
        "lat_lon": (51.62, 39.15),
    },
    AIRBASE_HALINO: {
        "title": "Аеродром Халіно (Курськ)",
        "primary_threat": THREAT_SU35,
        "keywords": ["халіно", "халино", "halino"],
        "lat_lon": (51.75, 36.30),
    },
    AIRBASE_DYAGILEVO: {
        "title": "Аеродром Дягілєво (Рязань)",
        "primary_threat": THREAT_TU95,
        "keywords": ["дягілєво", "дягилево", "dyagilevo"],
        "lat_lon": (54.64, 39.57),
    },
    AIRBASE_BELBEK: {
        "title": "Аеродром Бельбек (Севастополь, Крим)",
        "primary_threat": THREAT_SU35,
        "keywords": ["бельбек", "belbek"],
        "lat_lon": (44.69, 33.57),
    },
    AIRBASE_SAKY: {
        "title": "Аеродром Саки / Новофедорівка (Крим)",
        "primary_threat": THREAT_SU35,
        "keywords": ["саки", "новофедорівка", "новофедоровка", "saky"],
        "lat_lon": (45.09, 33.59),
    },
    AIRBASE_GVARDEYSKOYE: {
        "title": "Аеродром Гвардійське (Крим)",
        "primary_threat": THREAT_SU35,
        "keywords": ["гвардійське", "гвардейское", "gvardeyskoye"],
        "lat_lon": (45.11, 33.97),
    },
    AIRBASE_SOLTSY: {
        "title": "Аеродром Сольці (Новгородська обл.)",
        "primary_threat": THREAT_TU22M3,
        "keywords": ["сольці", "сольцы", "soltsy"],
        "lat_lon": (58.14, 30.33),
    },
    AIRBASE_LIPETSK: {
        "title": "Авіацентр Липецьк-2 (Липецька обл.)",
        "primary_threat": THREAT_SU35,
        "keywords": ["липецьк", "липецк", "lipetsk"],
        "lat_lon": (52.64, 39.45),
    },
    AIRBASE_KRYMSK: {
        "title": "Аеродром Кримськ (Краснодарський край)",
        "primary_threat": THREAT_SU35,
        "keywords": ["кримськ", "крымск", "krymsk"],
        "lat_lon": (44.96, 37.99),
    },
    AIRBASE_SESHCHA: {
        "title": "Авіабаза Сеща (Брянська обл.)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["сеща", "seshcha"],
        "lat_lon": (53.71, 33.34),
    },
    LAUNCH_HUB_CHAUDA: {
        "title": "Мис Чауда (АР Крим)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["чауда", "chauda"],
        "lat_lon": (45.00, 35.83),
    },
    LAUNCH_HUB_BLACK_SEA: {
        "title": "Акваторія Чорного моря",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["чорне море", "чорного моря", "чм"],
        "lat_lon": (43.50, 32.50),
    },
    LAUNCH_HUB_CASPIAN_SEA: {
        "title": "Акваторія Каспійського моря",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["каспійське море", "каспійського моря", "каспій"],
        "lat_lon": (42.00, 51.00),
    },
}

# ==============================================================================
# 🛰️ GROUND DRONE LAUNCH SITES (Наземні полігони та майданчики пуску БпЛА Shahed/Гербера)
# ==============================================================================
DRONE_SITE_CHAUDA = "drone_site_chauda"
DRONE_SITE_PRIMORSKO_AKHTARSK = "drone_site_primorsko_akhtarsk"
DRONE_SITE_YEYSK = "drone_site_yeysk"
DRONE_SITE_KURSK = "drone_site_kursk"
DRONE_SITE_OREL = "drone_site_orel"
DRONE_SITE_SESHCHA = "drone_site_seshcha"
DRONE_SITE_MILLEROVO = "drone_site_millerovo"
DRONE_SITE_GVARDEYSKOYE = "drone_site_gvardeyskoye"

DRONE_LAUNCH_SITES: Dict[str, Dict[str, Any]] = {
    DRONE_SITE_CHAUDA: {
        "title": "Мис Чауда (АР Крим)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["чауда", "chauda", "крим", "ар крим", "феодосія", "чорне море"],
        "lat_lon": (45.00, 35.83),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область", "Кіровоградська область", "Вінницька область", "Черкаська область"],
    },
    DRONE_SITE_PRIMORSKO_AKHTARSK: {
        "title": "Приморсько-Ахтарськ (Краснодарський край РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["приморсько-ахтарськ", "приморско-ахтарск", "приморськ", "ахтарськ"],
        "lat_lon": (46.05, 38.16),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Полтавська область", "Харківська область", "Кіровоградська область"],
    },
    DRONE_SITE_YEYSK: {
        "title": "Єйськ (Краснодарський край РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["єйськ", "ейск", "yeysk"],
        "lat_lon": (46.68, 38.25),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Донецька область", "Харківська область"],
    },
    DRONE_SITE_KURSK: {
        "title": "Полігон Халіно / Курськ (РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["курськ", "курск", "халіно", "kursk"],
        "lat_lon": (51.75, 36.29),
        "target_regions": ["Сумська область", "Чернігівська область", "Полтавська область", "Київська область", "Черкаська область"],
    },
    DRONE_SITE_OREL: {
        "title": "Полігон Південний / Орел (РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["орел", "орьол", "orel"],
        "lat_lon": (52.93, 36.00),
        "target_regions": ["Сумська область", "Чернігівська область", "Київська область", "Житомирська область"],
    },
    DRONE_SITE_SESHCHA: {
        "title": "Авіабаза Сеща (Брянська обл. РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["сеща", "брянськ", "брянск", "seshcha"],
        "lat_lon": (53.71, 33.34),
        "target_regions": ["Чернігівська область", "Київська область", "Житомирська область"],
    },
    DRONE_SITE_MILLEROVO: {
        "title": "Міллерово (Ростовська обл. РФ)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["міллерово", "миллерово", "millerovo"],
        "lat_lon": (48.95, 40.30),
        "target_regions": ["Харківська область", "Дніпропетровська область", "Донецька область", "Полтавська область"],
    },
    DRONE_SITE_GVARDEYSKOYE: {
        "title": "Гвардійське / Джанкой (АР Крим)",
        "primary_threat": THREAT_SHAHED,
        "keywords": ["гвардійське", "джанкой", "гвардейское"],
        "lat_lon": (45.11, 33.97),
        "target_regions": ["Херсонська область", "Миколаївська область", "Одеська область", "Запорізька область"],
    },
}

# ==============================================================================
# ⚓ NAVAL LAUNCH BASES & SEAS (Морські райони базування флоту для ракет «Калібр»/«Циркон»)
# ==============================================================================
NAVAL_BASE_BLACK_SEA = "naval_base_black_sea"
NAVAL_BASE_CASPIAN_SEA = "naval_base_caspian_sea"
NAVAL_BASE_NOVOROSSIYSK = "naval_base_novorossiysk"
NAVAL_BASE_SEVASTOPOL = "naval_base_sevastopol"

NAVAL_LAUNCH_BASES: Dict[str, Dict[str, Any]] = {
    NAVAL_BASE_BLACK_SEA: {
        "title": "Акваторія Чорного моря (Флот РФ)",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["чорне море", "чорного моря", "чм", "фрегат", "варшавянка", "калібр з моря"],
        "lat_lon": (44.50, 32.00),
        "target_regions": ["Одеська область", "Миколаївська область", "Вінницька область", "Хмельницька область", "Львівська область", "Черкаська область"],
    },
    NAVAL_BASE_CASPIAN_SEA: {
        "title": "Акваторія Каспійського моря (Флотилія РФ)",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["каспійське море", "каспійського моря", "каспій", "дагестан", "буян-м"],
        "lat_lon": (42.00, 51.50),
        "target_regions": ["Київська область", "Полтавська область", "Черкаська область", "Дніпропетровська область", "Харківська область"],
    },
    NAVAL_BASE_NOVOROSSIYSK: {
        "title": "Військово-морська база Новоросійськ (Краснодарський край)",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["новоросійськ", "новороссийск", "вмб новоросійськ"],
        "lat_lon": (44.72, 37.78),
        "target_regions": ["Одеська область", "Миколаївська область", "Вінницька область"],
    },
    NAVAL_BASE_SEVASTOPOL: {
        "title": "Севастопольська бухта (ТОТ Крим)",
        "primary_threat": THREAT_CRUISE_MISSILE,
        "keywords": ["севастополь", "севастопольська бухта", "південна бухта"],
        "lat_lon": (44.62, 33.53),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область"],
    },
}

# ==============================================================================
# 🚀 BALLISTIC & COASTAL MISSILE SITES (Позиційні райони ОТРК Іскандер-М/KN-23/Бастіон/С-300)
# ==============================================================================
BALLISTIC_SITE_TARKHANKUT = "ballistic_site_tarkhankut"
BALLISTIC_SITE_DZHANkOY = "ballistic_site_dzhankoy"
BALLISTIC_SITE_BELGOROD = "ballistic_site_belgorod"
BALLISTIC_SITE_KURSK = "ballistic_site_kursk"
BALLISTIC_SITE_BRYANSK = "ballistic_site_bryansk"
BALLISTIC_SITE_VORONEZH = "ballistic_site_voronezh"
BALLISTIC_SITE_ROSTOV = "ballistic_site_rostov"
BALLISTIC_SITE_KAPUSTIN_YAR = "ballistic_site_kapustin_yar"
BALLISTIC_SITE_TOT_ZAPORIZHZHIA = "ballistic_site_tot_zaporizhzhia"

BALLISTIC_LAUNCH_SITES: Dict[str, Dict[str, Any]] = {
    BALLISTIC_SITE_TARKHANKUT: {
        "title": "Позиційний район мис Тарханкут (АР Крим)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["тарханкут", "бастіон", "онікс", "іскандер крим"],
        "lat_lon": (45.34, 32.50),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область"],
    },
    BALLISTIC_SITE_DZHANkOY: {
        "title": "Позиційний район Джанкой / Чауда (АР Крим)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["джанкой", "чауда балістика", "іскандер джанкой"],
        "lat_lon": (45.71, 34.39),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Миколаївська область", "Одеська область"],
    },
    BALLISTIC_SITE_BELGOROD: {
        "title": "Позиційний район Бєлгородська обл. РФ",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["бєлгород", "белгород", "с-300 бєлгород", "іскандер бєлгород"],
        "lat_lon": (50.60, 36.58),
        "target_regions": ["Харківська область", "Сумська область", "Полтавська область"],
    },
    BALLISTIC_SITE_KURSK: {
        "title": "Позиційний район Курська обл. РФ",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["курськ", "курск", "іскандер курськ", "kn-23"],
        "lat_lon": (51.70, 35.50),
        "target_regions": ["Сумська область", "Чернігівська область", "Київська область", "Полтавська область"],
    },
    BALLISTIC_SITE_BRYANSK: {
        "title": "Позиційний район Брянська обл. РФ (Клинці/Унеча)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["брянськ", "клинці", "унеча", "брянск"],
        "lat_lon": (52.50, 33.50),
        "target_regions": ["Чернігівська область", "Київська область", "Житомирська область"],
    },
    BALLISTIC_SITE_VORONEZH: {
        "title": "Позиційний район Воронезька обл. РФ",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["воронеж", "воронезька"],
        "lat_lon": (51.00, 39.50),
        "target_regions": ["Харківська область", "Полтавська область", "Дніпропетровська область"],
    },
    BALLISTIC_SITE_ROSTOV: {
        "title": "Позиційний район Ростовська обл. / Таганрог РФ",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["ростов", "таганрог", "іскандер ростов"],
        "lat_lon": (47.25, 39.00),
        "target_regions": ["Донецька область", "Запорізька область", "Дніпропетровська область", "Харківська область"],
    },
    BALLISTIC_SITE_KAPUSTIN_YAR: {
        "title": "Полігон Капустін Яр (Астраханська обл. РФ)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["капустін яр", "капустин яр", "орєшнік", "рс-26"],
        "lat_lon": (48.58, 45.74),
        "target_regions": ["Дніпропетровська область", "Київська область", "Львівська область", "Харківська область"],
    },
    BALLISTIC_SITE_TOT_ZAPORIZHZHIA: {
        "title": "Позиційний район ТОТ Запорізької обл. (Бердянськ/Мелітополь)",
        "primary_threat": THREAT_BALLISTIC,
        "keywords": ["бердянськ", "мелітополь", "тот запоріз", "с-300 запоріж"],
        "lat_lon": (47.15, 35.80),
        "target_regions": ["Запорізька область", "Дніпропетровська область"],
    },
}

# ==============================================================================
# 💥 ARTILLERY & MLRS FIRING POSITIONS (Вогневі позиції ствольної артилерії та РСЗВ)
# ==============================================================================
ARTILLERY_POS_TOT_ZAPORIZHZHIA = "artillery_pos_tot_zaporizhzhia"
ARTILLERY_POS_TOT_KHERSON = "artillery_pos_tot_kherson"
ARTILLERY_POS_TOT_DONETSK = "artillery_pos_tot_donetsk"
ARTILLERY_POS_TOT_LUHANSK = "artillery_pos_tot_luhansk"
ARTILLERY_POS_BELGOROD_BORDER = "artillery_pos_belgorod_border"
ARTILLERY_POS_KURSK_BORDER = "artillery_pos_kursk_border"
ARTILLERY_POS_BRYANSK_BORDER = "artillery_pos_bryansk_border"
ARTILLERY_POS_KINBURN_SPIT = "artillery_pos_kinburn_spit"

ARTILLERY_MLRS_LAUNCH_SITES: Dict[str, Dict[str, Any]] = {
    ARTILLERY_POS_TOT_ZAPORIZHZHIA: {
        "title": "Вогневі позиції ТОТ Запорізької обл. (Енергодар / Пологи)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["енергодар", "кам'янка-дніпровська", "пологи", "василівка", "дніпрорудне", "запорізька арт"],
        "lat_lon": (47.45, 34.65),
        "target_regions": ["Запорізька область", "Дніпропетровська область"],
    },
    ARTILLERY_POS_TOT_KHERSON: {
        "title": "Вогневі позиції ТОТ Херсонської обл. (Олешки / Каховка)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["олешки", "каховка", "гола пристань", "лівий берег", "херсонська арт"],
        "lat_lon": (46.61, 32.72),
        "target_regions": ["Херсонська область", "Миколаївська область"],
    },
    ARTILLERY_POS_TOT_DONETSK: {
        "title": "Вогневі позиції ТОТ Донецької обл. (Горлівка / Донецьк / Волноваха)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["горлівка", "донецьк арт", "волноваха", "макіївка", "донецька арт"],
        "lat_lon": (48.00, 37.80),
        "target_regions": ["Донецька область", "Харківська область", "Дніпропетровська область"],
    },
    ARTILLERY_POS_TOT_LUHANSK: {
        "title": "Вогневі позиції ТОТ Луганської обл. (Кремінна / Лисичанськ)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["кремінна", "лисичанськ", "рубіжне", "луганська арт"],
        "lat_lon": (48.95, 38.25),
        "target_regions": ["Харківська область", "Донецька область", "Луганська область"],
    },
    ARTILLERY_POS_BELGOROD_BORDER: {
        "title": "Вогневі позиції Бєлгородської обл. РФ (Шебекіно / Грайворон)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["шебекіно", "грайворон", "валуйки", "бєлгород арт"],
        "lat_lon": (50.41, 36.89),
        "target_regions": ["Харківська область", "Сумська область"],
    },
    ARTILLERY_POS_KURSK_BORDER: {
        "title": "Вогневі позиції Курської обл. РФ (Тьоткіно / Глушково)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["тьоткіно", "глушково", "суджа", "курськ арт"],
        "lat_lon": (51.27, 34.60),
        "target_regions": ["Сумська область", "Чернігівська область"],
    },
    ARTILLERY_POS_BRYANSK_BORDER: {
        "title": "Вогневі позиції Брянської обл. РФ (Климово / Суземка)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["климово", "суземка", "стародуб", "брянськ арт"],
        "lat_lon": (52.38, 32.18),
        "target_regions": ["Чернігівська область", "Сумська область"],
    },
    ARTILLERY_POS_KINBURN_SPIT: {
        "title": "Вогневі позиції Кінбурнська коса (ТОТ Херсон/Миколаїв)",
        "primary_threat": THREAT_ARTILLERY,
        "keywords": ["кінбурн", "кінбурнська коса", "очаків арт", "куцуруб"],
        "lat_lon": (46.52, 31.65),
        "target_regions": ["Миколаївська область", "Херсонська область"],
    },
}

# ==============================================================================
# 🎮 FPV & RECON DRONE LAUNCH POSITIONS (Позиції розрахунків FPV та БпЛА розвідки)
# ==============================================================================
FPV_POS_ZAPORIZHZHIA = "fpv_pos_zaporizhzhia"
FPV_POS_KHERSON = "fpv_pos_kherson"
FPV_POS_DONETSK = "fpv_pos_donetsk"
FPV_POS_KHARKIV = "fpv_pos_kharkiv"
FPV_POS_SUMY_BORDER = "fpv_pos_sumy_border"
FPV_POS_CRIMEA = "fpv_pos_crimea"

FPV_RECON_LAUNCH_SITES: Dict[str, Dict[str, Any]] = {
    FPV_POS_ZAPORIZHZHIA: {
        "title": "Передові позиції ЛБЗ (Запорізький напрямок)",
        "primary_threat": THREAT_FPV,
        "keywords": ["оріхів фпв", "роботине", "гуляйполе фпв", "запорізький напрямок фпв"],
        "lat_lon": (47.50, 35.80),
        "target_regions": ["Запорізька область", "Дніпропетровська область"],
    },
    FPV_POS_KHERSON: {
        "title": "Передові позиції лівий берег Дніпра (Херсонський напрямок)",
        "primary_threat": THREAT_FPV,
        "keywords": ["кринки", "козачі лагері", "лівий берег фпв", "херсонський напрямок фпв"],
        "lat_lon": (46.65, 32.65),
        "target_regions": ["Херсонська область", "Миколаївська область"],
    },
    FPV_POS_DONETSK: {
        "title": "Передові позиції ЛБЗ (Покровський / Торецький напрямок)",
        "primary_threat": THREAT_FPV,
        "keywords": ["покровськ фпв", "торецьк фпв", "курахове фпв", "донецький напрямок фпв"],
        "lat_lon": (48.15, 37.30),
        "target_regions": ["Донецька область", "Дніпропетровська область"],
    },
    FPV_POS_KHARKIV: {
        "title": "Передові позиції ЛБЗ (Куп'янський / Вовчанський напрямок)",
        "primary_threat": THREAT_FPV,
        "keywords": ["куп'янськ фпв", "вовчанськ фпв", "харківський напрямок фпв", "липці"],
        "lat_lon": (50.10, 37.10),
        "target_regions": ["Харківська область"],
    },
    FPV_POS_SUMY_BORDER: {
        "title": "Прикордонні позиції РФ (Сумський / Чернігівський напрямок)",
        "primary_threat": THREAT_FPV,
        "keywords": ["сумське прикордоння фпв", "чернігівське прикордоння фпв"],
        "lat_lon": (51.50, 35.00),
        "target_regions": ["Сумська область", "Чернігівська область"],
    },
    FPV_POS_CRIMEA: {
        "title": "Авіамайданчики та полігони ТОТ Криму (Гвардійське / Джанкой)",
        "primary_threat": THREAT_RECON_UAV,
        "keywords": ["орлан крим", "зала крим", "суперкам крим", "джанкой бпла"],
        "lat_lon": (45.20, 34.00),
        "target_regions": ["Херсонська область", "Миколаївська область", "Одеська область", "Запорізька область"],
    },
}

# ==============================================================================
# 🛡️ SPECIAL HAZARDS & COMBAT ZONES (Вуличні бої / Радіація / Хімнебезпека / Циркон)
# ==============================================================================
SITE_ZIRCON_CRIMEA = "site_zircon_crimea"
SITE_ZNPP_ZONE = "site_znpp_zone"
SITE_URBAN_DONETSK = "site_urban_donetsk"
SITE_URBAN_KHARKIV = "site_urban_kharkiv"

SPECIAL_THREAT_SITES: Dict[str, Dict[str, Any]] = {
    SITE_ZIRCON_CRIMEA: {
        "title": "БРК Бастіон / Кораблі ЧФ (ТОТ Крим / Севастополь)",
        "primary_threat": THREAT_ZIRCON,
        "keywords": ["циркон", "zircon", "3м22", "гіперзвук з криму"],
        "lat_lon": (44.60, 33.50),
        "target_regions": ["Київська область", "Одеська область", "Миколаївська область", "Дніпропетровська область", "Запорізька область"],
    },
    SITE_ZNPP_ZONE: {
        "title": "Зона ризику ЗАЕС (м. Енергодар)",
        "primary_threat": THREAT_NUCLEAR,
        "keywords": ["заес", "енергодар радіація", "ядерна небезпека", "запорізька аес"],
        "lat_lon": (47.51, 34.58),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Херсонська область", "Миколаївська область"],
    },
    SITE_URBAN_DONETSK: {
        "title": "Район активних міських боїв (Донеччина)",
        "primary_threat": THREAT_URBAN_FIGHTS,
        "keywords": ["міські бої покровськ", "міські бої торецьк", "міські бої часів яр"],
        "lat_lon": (48.28, 37.18),
        "target_regions": ["Донецька область"],
    },
    SITE_URBAN_KHARKIV: {
        "title": "Район активних міських боїв (Куп'янськ / Вовчанськ)",
        "primary_threat": THREAT_URBAN_FIGHTS,
        "keywords": ["міські бої куп'янськ", "міські бої вовчанськ"],
        "lat_lon": (50.29, 36.94),
        "target_regions": ["Харківська область"],
    },
}

# ==============================================================================
# AVIATION LAUNCH SECTORS (Рубежі пусків / прикордонні коридори входження в повітряний простір України)
# ==============================================================================
SECTOR_BELGOROD = "sector_belgorod"
SECTOR_KURSK = "sector_kursk"
SECTOR_BRYANSK = "sector_bryansk"
SECTOR_AZOV_SEA = "sector_azov_sea"
SECTOR_BLACK_SEA = "sector_black_sea"
SECTOR_TOT_ZAPORIZHZHIA = "sector_tot_zaporizhzhia"
SECTOR_TOT_DONETSK = "sector_tot_donetsk"
SECTOR_TOT_KHERSON = "sector_tot_kherson"
SECTOR_CASPIAN_SEA = "sector_caspian_sea"
SECTOR_SARATOV_ENGELS = "sector_saratov_engels"
SECTOR_RYAZAN_TAMBOV = "sector_ryazan_tambov"
SECTOR_CHAUDA = "sector_chauda"
SECTOR_PRIMORSKO_AKHTARSK = "sector_primorsko_akhtarsk"
SECTOR_YEYSK = "sector_yeysk"
SECTOR_OREL = "sector_orel"
SECTOR_CRIMEA_TARKHANKUT = "sector_crimea_tarkhankut"
SECTOR_VORONEZH = "sector_voronezh"
SECTOR_ROSTOV_TAGANROG = "sector_rostov_taganrog"
SECTOR_BELARUS_GOMEL = "sector_belarus_gomel"
SECTOR_BELARUS_BREST = "sector_belarus_brest"
SECTOR_KINBURN = "sector_kinburn"

AVIATION_LAUNCH_SECTORS: Dict[str, Dict[str, Any]] = {
    SECTOR_BELGOROD: {
        "title": "Бєлгородський прикордонний рубіж (вхід: Харківщина / Сумщина)",
        "lat_lon": (50.60, 36.58),
        "target_regions": ["Харківська область", "Сумська область", "Полтавська область"],
        "keywords": ["бєлгород", "белгород", "бєлгородщин", "шебекіно", "грайворон"],
    },
    SECTOR_KURSK: {
        "title": "Курський прикордонний рубіж (вхід: Сумщина / Чернігівщина)",
        "lat_lon": (51.70, 35.50),
        "target_regions": ["Сумська область", "Чернігівська область", "Полтавська область", "Харківська область"],
        "keywords": ["курськ", "курск", "курщин", "глушково", "рильськ", "суджа"],
    },
    SECTOR_BRYANSK: {
        "title": "Брянський прикордонний рубіж (вхід: Чернігівщина / Сумщина / Київщина)",
        "lat_lon": (52.50, 33.50),
        "target_regions": ["Чернігівська область", "Сумська область", "Київська область"],
        "keywords": ["брянськ", "брянск", "брянщин", "клинці"],
    },
    SECTOR_AZOV_SEA: {
        "title": "Акваторія Азовського моря (Приазовський коридор)",
        "lat_lon": (46.20, 36.50),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Донецька область", "Херсонська область", "Миколаївська область", "Одеська область", "Кіровоградська область", "Полтавська область", "Черкаська область"],
        "keywords": ["азов", "азовськ", "азовське море", "приазов"],
    },
    SECTOR_BLACK_SEA: {
        "title": "Акваторія Чорного моря (Південний морський коридор)",
        "lat_lon": (44.50, 32.00),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область", "Кіровоградська область", "Вінницька область", "Черкаська область"],
        "keywords": ["чорне море", "чорного моря", "севастополь", "тарханкут", "з моря", "морського базування", "чорноморськ"],
    },
    SECTOR_TOT_ZAPORIZHZHIA: {
        "title": "Прифронтовий рубіж ТОТ Запорізької обл. (ЛБЗ)",
        "lat_lon": (47.15, 35.80),
        "target_regions": ["Запорізька область", "Дніпропетровська область"],
        "keywords": ["тот запоріз", "окупована запоріз", "токмак", "мелітополь", "пологи", "бердянськ"],
    },
    SECTOR_TOT_DONETSK: {
        "title": "Прифронтовий рубіж ТОТ Донецької обл. (ЛБЗ)",
        "lat_lon": (47.90, 37.80),
        "target_regions": ["Донецька область", "Харківська область", "Дніпропетровська область"],
        "keywords": ["тот донец", "окупована донец", "донецьк", "волноваха", "маріуполь"],
    },
    SECTOR_TOT_KHERSON: {
        "title": "Прифронтовий рубіж ТОТ Херсонщини (Лівобережжя / Дніпро)",
        "lat_lon": (46.50, 33.20),
        "target_regions": ["Херсонська область", "Миколаївська область"],
        "keywords": ["лівобережж", "тот херсон", "окупована херсон", "каховка", "скадовськ", "олешки"],
    },
    SECTOR_CASPIAN_SEA: {
        "title": "Східний повітряний коридор (пусковий рубіж Каспій / Волгодонськ)",
        "lat_lon": (43.00, 50.00),
        "target_regions": ["Вся Україна"],
        "keywords": ["каспій", "каспійське море", "каспий"],
    },
    SECTOR_SARATOV_ENGELS: {
        "title": "Північно-східний повітряний коридор (пусковий рубіж Саратов / Енгельс)",
        "lat_lon": (51.48, 46.21),
        "target_regions": ["Вся Україна"],
        "keywords": ["енгельс", "энгельс", "саратов"],
    },
    SECTOR_RYAZAN_TAMBOV: {
        "title": "Північний коридор пуску Кинджалів (Рязань / Тула / Липецьк)",
        "lat_lon": (53.50, 40.50),
        "target_regions": ["Вся Україна"],
        "keywords": ["саваслейка", "липецьк", "рязань", "тамбов"],
    },
    SECTOR_CHAUDA: {
        "title": "Кримський перешийок / Причорноморський коридор (ТОТ АР Крим)",
        "lat_lon": (45.00, 35.83),
        "target_regions": ["Херсонська область", "Запорізька область", "Дніпропетровська область", "Одеська область", "Миколаївська область"],
        "keywords": ["чауда", "чауди", "мис чауда", "феодосія", "крим", "криму"],
    },
    SECTOR_PRIMORSKO_AKHTARSK: {
        "title": "Приазовський повітряний коридор (Азовське море / Краснодарський край)",
        "lat_lon": (46.04, 38.17),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Донецька область", "Харківська область", "Полтавська область"],
        "keywords": ["приморсько-ахтарськ", "приморско-ахтарск", "приморськ-ахтарськ", "ахтарськ", "краснодарськ"],
    },
    SECTOR_YEYSK: {
        "title": "Приазовсько-Донбаський коридор (Таганрозька затока / Єйськ)",
        "lat_lon": (46.68, 38.28),
        "target_regions": ["Донецька область", "Запорізька область", "Дніпропетровська область"],
        "keywords": ["єйськ", "ейськ", "ейск"],
    },
    SECTOR_OREL: {
        "title": "Північно-східний прикордонний рубіж (Орел / Курськ / Брянськ)",
        "lat_lon": (52.96, 36.06),
        "target_regions": ["Сумська область", "Чернігівська область", "Полтавська область", "Київська область", "Харківська область"],
        "keywords": ["орел", "орловськ", "орла"],
    },
    SECTOR_CRIMEA_TARKHANKUT: {
        "title": "Західно-Кримський морський коридор (мис Тарханкут / Чорне море)",
        "lat_lon": (45.34, 32.50),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область", "Запорізька область"],
        "keywords": ["тарханкут", "джанкой", "гвардійське", "іскандер-м крим"],
    },
    SECTOR_VORONEZH: {
        "title": "Східний прикордонний рубіж (Воронезька обл. РФ)",
        "lat_lon": (51.66, 39.20),
        "target_regions": ["Харківська область", "Полтавська область", "Дніпропетровська область"],
        "keywords": ["воронеж", "воронежчин", "воронежськ"],
    },
    SECTOR_ROSTOV_TAGANROG: {
        "title": "Східно-Приазовський прикордонний рубіж (Ростовська обл. РФ)",
        "lat_lon": (47.23, 38.89),
        "target_regions": ["Донецька область", "Запорізька область", "Дніпропетровська область", "Харківська область"],
        "keywords": ["таганрог", "ростов", "ростовськ", "міллерово"],
    },
    SECTOR_BELARUS_GOMEL: {
        "title": "Білоруський північний коридор (Гомельська обл. РБ $\\rightarrow$ Київщина/Чернігівщина)",
        "lat_lon": (52.10, 31.00),
        "target_regions": ["Чернігівська область", "Київська область", "Житомирська область"],
        "keywords": ["білорусь", "гомель", "мозир", "зябровка", "лунинець"],
    },
    SECTOR_BELARUS_BREST: {
        "title": "Білоруський західний коридор (Брестська обл. РБ $\\rightarrow$ Волинь/Рівненщина)",
        "lat_lon": (51.90, 25.50),
        "target_regions": ["Волинська область", "Рівненська область", "Житомирська область"],
        "keywords": ["брест", "барановичі", "мачулищі білорусь"],
    },
    SECTOR_KINBURN: {
        "title": "Приморський рубіж Кінбурнська коса (Дніпро-Бузький лиман)",
        "lat_lon": (46.54, 31.65),
        "target_regions": ["Миколаївська область", "Одеська область", "Херсонська область"],
        "keywords": ["кінбурн", "кінбурнськ", "очаків арт"],
    },
}

# ==============================================================================
# 6. KINEMATIC CALCULATIONS & ETA UTILITIES
# ==============================================================================

def get_threat_speed(threat_type: Optional[str], custom_speed: Optional[float] = None) -> float:
    """Returns exact speed in km/h for a given threat object, prioritizing telemetry speed."""
    if custom_speed and custom_speed > 0:
        return float(custom_speed)
    if not threat_type:
        return DEFAULT_SPEEDS_KMH[THREAT_UNKNOWN]
    return DEFAULT_SPEEDS_KMH.get(threat_type, DEFAULT_SPEEDS_KMH[THREAT_UNKNOWN])

def format_eta_seconds_to_str(eta_seconds: Optional[int]) -> str:
    """Formats ETA in seconds into standardized human-readable Ukrainian string with unified 'до ...' format."""
    if eta_seconds is None or eta_seconds <= 0:
        return "в області"
    
    total_mins = max(1, round(eta_seconds / 60))
    if total_mins < 60:
        return f"до {total_mins} хв"
    else:
        hours = total_mins // 60
        mins = total_mins % 60
        if mins == 0:
            return f"до {hours} год"
        return f"до {hours} год {mins} хв"

def calculate_kinematic_eta(
    distance_km: float, 
    threat_type: Optional[str], 
    speed_kmh: Optional[float] = None
) -> Tuple[int, str]:
    """
    Calculates exact flight duration (seconds) and formatted ETA text
    using physics ballistics formulas for departure & arrival threat objects.
    """
    if distance_km <= 0:
        return 0, "в області"
        
    speed = get_threat_speed(threat_type, speed_kmh)
    if speed <= 0:
        return 0, "в області"
        
    eta_seconds = int((distance_km / speed) * 3600)
    
    # Specific object kinematics buffer / launch offset adjustments:
    if threat_type in (THREAT_BALLISTIC, THREAT_ISKANDER, THREAT_TU22M3):
        eta_seconds = max(120, eta_seconds + 60)  # 1 min detection buffer
    elif threat_type == THREAT_MIG31K:
        eta_seconds = max(300, eta_seconds + 120)  # 2 min launch prep buffer
    elif threat_type in (THREAT_TU95, THREAT_SU35):
        eta_seconds = max(900, eta_seconds + 600)  # standoff launch buffer

    eta_str = format_eta_seconds_to_str(eta_seconds)
    return eta_seconds, eta_str

def get_threat_title(threat_type: Optional[str]) -> str:
    """Returns official Ukrainian title for a threat object type."""
    if not threat_type:
        return THREAT_TITLES[THREAT_UNKNOWN]
    return THREAT_TITLES.get(threat_type, THREAT_TITLES[THREAT_UNKNOWN])

NOTIFICATION_THREAT_NAMES: Dict[str, str] = {
    THREAT_BALLISTIC: "Балістична загроза",
    THREAT_SHAHED: "Загроза БпЛА Shahed",
    THREAT_CRUISE_MISSILE: "Загроза крилатих ракет",
    THREAT_KAB: "Загроза КАБ",
    THREAT_MIG31K: "Зліт МіГ-31К (Кинджал)",
    THREAT_TU95: "Зліт Ту-95МС (крилаті ракети)",
    THREAT_TU22M3: "Зліт Ту-22М3 (ракети Х-22/Х-32)",
    THREAT_SU35: "Активність Су-34/35 (КАБ/ракети)",
    "su35": "Активність Су-34/35 (КАБ/ракети)",
    THREAT_ISKANDER: "Загроза Іскандер-М",
    THREAT_ARTILLERY: "Загроза артобстрілу",
    THREAT_URBAN_FIGHTS: "Загроза вуличних боїв",
    THREAT_CHEMICAL: "Хімічна небезпека",
    THREAT_NUCLEAR: "Радіаційна небезпека",
    THREAT_ZIRCON: "Загроза ракети Циркон",
    THREAT_MLRS: "Загроза обстрілу РСЗВ",
    THREAT_FPV: "Загроза FPV-дронів",
    THREAT_RECON: "Виявлено розвідувальний БпЛА",
    THREAT_RECON_UAV: "Виявлено розвідувальний БпЛА",
    THREAT_OFFICIAL_ALARM: "Офіційна повітряна тривога",
    THREAT_UNKNOWN: "Повітряна загроза",
}

def format_threat_notification_title(
    threat_type: Optional[str],
    confidence: Optional[int],
    region: str,
    is_official_alarm: bool = False,
    is_clear: bool = False
) -> str:
    """
    Unified title generator ensuring 100% mathematical and string symmetry
    with Swift ThreatConstants.notificationTitle.
    """
    if is_clear:
        if is_official_alarm:
            return f"🟢 Відбій тривоги: {region}"
        return f"🟢 Відбій загрози: {region}"

    if is_official_alarm:
        return f"🔴 Повітряна тривога: {region}"

    threat_name = NOTIFICATION_THREAT_NAMES.get(threat_type, "Повітряна загроза") if threat_type else "Повітряна загроза"
    conf = confidence if confidence is not None else 75

    if conf >= 85:
        indicator = "🔴 Висока ймовірність"
    elif conf >= 60:
        indicator = "🟠 Ймовірна загроза"
    else:
        indicator = "🟡 Можлива загроза"

    return f"{indicator}: {threat_name} ({region})"

def get_threat_short_name(threat_type: Optional[str]) -> str:
    """Returns short Ukrainian name for a threat object type."""
    if not threat_type:
        return threat_type or ""
    return THREAT_SHORT_NAMES.get(threat_type, threat_type)

def get_threat_delay_and_eta(threat_type: Optional[str], is_regex: bool = False) -> Tuple[int, str]:
    """Returns default auto-clear TTL (seconds) and default ETA string for a given threat object type."""
    if not threat_type or threat_type not in THREAT_AUTO_CLEAR_DELAYS:
        return 3600, ""
    
    delays = THREAT_AUTO_CLEAR_DELAYS[threat_type]
    etas = THREAT_DEFAULT_ETAS[threat_type]
    
    idx = 1 if is_regex else 0
    return delays[idx], etas[idx]

# Alias for backwards-compatibility & clarity across modules
get_threat_auto_clear_delay = get_threat_delay_and_eta

THREAT_OFFICIAL_ALARM = "official_alarm"

def detect_threat_type_from_text(text: str) -> Optional[str]:
    """Parses raw text and identifies departure/arrival threat object type using centralized keyword registry."""
    if not text:
        return None
    text_lower = text.lower()
    for threat_type, keywords in THREAT_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return threat_type
    if "повітрян" in text_lower and "тривог" in text_lower:
        return THREAT_OFFICIAL_ALARM
    return THREAT_UNKNOWN

def detect_launch_origin_from_text(text: str) -> Optional[str]:
    """Identifies Russian airfield, drone pad, naval base, artillery pos, or launch hub from text using all registries."""
    if not text:
        return None
    text_lower = text.lower()
    all_registries = [
        RUSSIAN_AIRBASES,
        DRONE_LAUNCH_SITES,
        NAVAL_LAUNCH_BASES,
        BALLISTIC_LAUNCH_SITES,
        ARTILLERY_MLRS_LAUNCH_SITES,
        FPV_RECON_LAUNCH_SITES,
        SPECIAL_THREAT_SITES
    ]
    for reg in all_registries:
        for origin_key, info in reg.items():
            if any(kw in text_lower for kw in info.get("keywords", [])):
                return origin_key
    return None

def get_launch_origin_title(origin_key: Optional[str]) -> str:
    """Returns official title for an airbase, launch pad, naval base, or firing position."""
    if not origin_key:
        return ""
    all_registries = [
        RUSSIAN_AIRBASES,
        DRONE_LAUNCH_SITES,
        NAVAL_LAUNCH_BASES,
        BALLISTIC_LAUNCH_SITES,
        ARTILLERY_MLRS_LAUNCH_SITES,
        FPV_RECON_LAUNCH_SITES,
        SPECIAL_THREAT_SITES
    ]
    for reg in all_registries:
        if origin_key in reg:
            return reg[origin_key]["title"]
    return origin_key

def detect_launch_sector_from_text(text: str) -> Optional[str]:
    """Identifies aviation launch sector or patrol zone from text."""
    if not text:
        return None
    text_lower = text.lower()
    for sector_key, info in AVIATION_LAUNCH_SECTORS.items():
        if any(kw in text_lower for kw in info["keywords"]):
            return sector_key
    return None

def get_launch_sector_title(sector_key: Optional[str]) -> str:
    """Returns official title for an aviation launch sector."""
    if sector_key and sector_key in AVIATION_LAUNCH_SECTORS:
        return AVIATION_LAUNCH_SECTORS[sector_key]["title"]
    return sector_key or ""

def resolve_aviation_strike_profile(
    threat_type: Optional[str],
    text: Optional[str] = None,
    target_region: Optional[str] = None,
    transit_from: Optional[str] = None
) -> Dict[str, Any]:
    """
    Resolves complete two-tier tactical profile for ALL 20 weapon categories and ALL Ukrainian regions:
    1. Platform type (drone_pad, airbase, naval_vessel, ballistic_launcher, artillery_position, fpv_recon_pad, combat_zone, special_hazard_zone)
    2. Origin launch base / airfield / polygon / firing position (with coordinates and title)
    3. Launch/drop sector / flight approach corridor (with coordinates and title)
    4. Carrier / munition classification
    """
    is_aviation = threat_type in [
        THREAT_KAB, THREAT_SU35, "su35", "su34",
        THREAT_MIG31K, THREAT_TU95, THREAT_TU22M3,
        THREAT_CRUISE_MISSILE
    ] or bool(text and any(w in text.lower() for w in ["каб", "су-34", "су-35", "міг-31", "ту-95", "ту-22", "кинджал", "х-59", "х-69", "х-101", "х-22"]))

    carrier_type = None
    airbase_key = None
    sector_key = None
    platform_type = "airbase" if is_aviation else "unknown"

    text_lower = text.lower() if text else ""

    # Check explicit origins and sectors in text
    if text:
        airbase_key = detect_launch_origin_from_text(text)
        sector_key = detect_launch_sector_from_text(text)
        if not transit_from:
            match = re.search(r'з\s+([А-Яа-яіЇїЄє\s\'-]+?)(?:\s+області|\s+область|\s+РФ|\s+Криму|щини|чини|\s+\()', text, re.IGNORECASE)
            if match:
                src_text = match.group(1).strip().lower()
                ORIGIN_MAP = {
                    "одес": "Одеська область", "одещ": "Одеська область",
                    "сумск": "Сумська область", "сумськ": "Сумська область", "сумщ": "Сумська область",
                    "харків": "Харківська область", "харківщ": "Харківська область",
                    "чернігів": "Чернігівська область", "чернігівщ": "Чернігівська область",
                    "полтав": "Полтавська область", "полтавщ": "Полтавська область",
                    "дніпро": "Дніпропетровська область", "дніпропетровщ": "Дніпропетровська область",
                    "донецьк": "Донецька область", "донечч": "Донецька область",
                    "луганськ": "Луганська область", "луганщ": "Луганська область",
                    "запоріж": "Запорізька область",
                    "херсон": "Херсонська область", "херсонщ": "Херсонська область",
                    "миколаїв": "Миколаївська область", "миколаївщ": "Миколаївська область",
                    "київ": "Київська область", "київщ": "Київська область",
                    "крим": "АР Крим"
                }
                for stem, reg in ORIGIN_MAP.items():
                    if stem in src_text:
                        transit_from = reg
                        break

    # =========================================================================
    # A. БПЛА / ДРОНИ (Shahed-136, Реактивні БпЛА, Гербера)
    # Фізичний майданчик пуску — ЗАВЖДИ сухопутний полігон РФ/Криму!
    # =========================================================================
    if threat_type in [THREAT_SHAHED, "shahed", "shahed_136", "reactive_uav"]:
        platform_type = "drone_pad"
        carrier_type = "drone_launcher"
        
        # Check drone site keywords in text
        drone_site_found = None
        for site_key, site_info in DRONE_LAUNCH_SITES.items():
            if any(kw in text_lower for kw in site_info["keywords"]):
                drone_site_found = site_key
                break
        
        # 1. If specific drone site explicitly mentioned in text, use it as physical launchpad
        if drone_site_found:
            airbase_key = drone_site_found
            if not sector_key:
                if airbase_key == DRONE_SITE_CHAUDA:
                    sector_key = SECTOR_BLACK_SEA
                elif airbase_key in [DRONE_SITE_PRIMORSKO_AKHTARSK, DRONE_SITE_YEYSK]:
                    sector_key = SECTOR_AZOV_SEA if target_region in ["Запорізька область", "Дніпропетровська область"] else SECTOR_PRIMORSKO_AKHTARSK
                elif airbase_key in [DRONE_SITE_KURSK, DRONE_SITE_OREL]:
                    sector_key = SECTOR_KURSK
                elif airbase_key == DRONE_SITE_MILLEROVO:
                    sector_key = SECTOR_BELGOROD
        else:
            # 2. Regional heuristics for all 26 Ukrainian regions
            if "чорн" in text_lower or "мор" in text_lower or target_region in ["Одеська область", "Миколаївська область", "Херсонська область"]:
                airbase_key = DRONE_SITE_CHAUDA
                sector_key = SECTOR_BLACK_SEA
            elif target_region in ["Запорізька область", "Дніпропетровська область", "Донецька область"]:
                airbase_key = DRONE_SITE_PRIMORSKO_AKHTARSK
                sector_key = SECTOR_AZOV_SEA
            elif target_region in ["Сумська область", "Чернігівська область", "Київська область", "Житомирська область"]:
                airbase_key = DRONE_SITE_OREL if "орел" in text_lower else DRONE_SITE_KURSK
                sector_key = SECTOR_KURSK
            elif target_region in ["Харківська область", "Полтавська область"]:
                airbase_key = DRONE_SITE_MILLEROVO if "міллеров" in text_lower else DRONE_SITE_PRIMORSKO_AKHTARSK
                sector_key = SECTOR_BELGOROD
            elif target_region in ["Вінницька область", "Хмельницька область", "Черкаська область", "Кіровоградська область"]:
                airbase_key = DRONE_SITE_CHAUDA if "південь" in text_lower else DRONE_SITE_PRIMORSKO_AKHTARSK
                sector_key = SECTOR_BLACK_SEA if "південь" in text_lower else SECTOR_PRIMORSKO_AKHTARSK
            elif target_region in ["Львівська область", "Тернопільська область", "Івано-Франківська область", "Рівненська область", "Волинська область", "Чернівецька область", "Закарпатська область"]:
                airbase_key = DRONE_SITE_KURSK if "північ" in text_lower else DRONE_SITE_CHAUDA
                sector_key = SECTOR_KURSK if "північ" in text_lower else SECTOR_BLACK_SEA
            else:
                airbase_key = DRONE_SITE_PRIMORSKO_AKHTARSK
                if not sector_key:
                    sector_key = SECTOR_PRIMORSKO_AKHTARSK

        pad_info = DRONE_LAUNCH_SITES.get(airbase_key) or RUSSIAN_AIRBASES.get(airbase_key)
        sector_info = AVIATION_LAUNCH_SECTORS.get(sector_key)
        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": pad_info["title"] if pad_info else "Мис Чауда (АР Крим)",
            "carrier_origin_latitude": pad_info["lat_lon"][0] if pad_info else 45.00,
            "carrier_origin_longitude": pad_info["lat_lon"][1] if pad_info else 35.83,
            "launch_sector_name": sector_info["title"] if sector_info else "Акваторія Чорного моря",
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else 44.50,
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else 32.00,
        }

    # =========================================================================
    # B. FPV-ДРОНИ ТА РОЗВІДУВАЛЬНІ БПЛА (Орлан-10, Zala, Supercam, FPV)
    # =========================================================================
    if threat_type in [THREAT_FPV, THREAT_RECON, THREAT_RECON_UAV, "fpv", "recon", "recon_uav"]:
        platform_type = "fpv_recon_pad"
        carrier_type = "fpv_recon_operator"
        
        fpv_key = None
        for site_key, site_info in FPV_RECON_LAUNCH_SITES.items():
            if any(kw in text_lower for kw in site_info["keywords"]):
                fpv_key = site_key
                break
        
        if not fpv_key:
            if target_region in ["Запорізька область", "Дніпропетровська область"]:
                fpv_key = FPV_POS_ZAPORIZHZHIA
                sector_key = SECTOR_TOT_ZAPORIZHZHIA
            elif target_region in ["Херсонська область", "Миколаївська область", "Одеська область"]:
                fpv_key = FPV_POS_KHERSON
                sector_key = SECTOR_TOT_KHERSON
            elif target_region in ["Донецька область", "Луганська область"]:
                fpv_key = FPV_POS_DONETSK
                sector_key = SECTOR_TOT_DONETSK
            elif target_region in ["Харківська область"]:
                fpv_key = FPV_POS_KHARKIV
                sector_key = SECTOR_BELGOROD
            elif target_region in ["Сумська область", "Чернігівська область"]:
                fpv_key = FPV_POS_SUMY_BORDER
                sector_key = SECTOR_KURSK
            else:
                fpv_key = FPV_POS_CRIMEA
                sector_key = SECTOR_BLACK_SEA

        fpv_info = FPV_RECON_LAUNCH_SITES.get(fpv_key)
        sector_info = AVIATION_LAUNCH_SECTORS.get(sector_key)
        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": fpv_info["title"] if fpv_info else "Передові позиції ЛБЗ",
            "carrier_origin_latitude": fpv_info["lat_lon"][0] if fpv_info else 47.50,
            "carrier_origin_longitude": fpv_info["lat_lon"][1] if fpv_info else 35.80,
            "launch_sector_name": sector_info["title"] if sector_info else (fpv_info["title"] if fpv_info else None),
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else 47.50,
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else 35.80,
        }

    # =========================================================================
    # C. СТВОЛЬНА АРТИЛЕРІЯ ТА РСЗВ (Град, Ураган, Смерч, Торнадо-С)
    # =========================================================================
    if threat_type in [THREAT_ARTILLERY, THREAT_MLRS, "artillery", "mlrs"]:
        platform_type = "artillery_position"
        carrier_type = "artillery_battery"
        
        art_key = None
        for site_key, site_info in ARTILLERY_MLRS_LAUNCH_SITES.items():
            if any(kw in text_lower for kw in site_info["keywords"]):
                art_key = site_key
                break
        
        if not art_key:
            if target_region in ["Миколаївська область", "Одеська область"] and ("кінбурн" in text_lower or "очаків" in text_lower):
                art_key = ARTILLERY_POS_KINBURN_SPIT
                sector_key = SECTOR_BLACK_SEA
            elif target_region in ["Херсонська область", "Миколаївська область"]:
                art_key = ARTILLERY_POS_TOT_KHERSON
                sector_key = SECTOR_TOT_KHERSON
            elif target_region in ["Запорізька область", "Дніпропетровська область"]:
                art_key = ARTILLERY_POS_TOT_ZAPORIZHZHIA
                sector_key = SECTOR_TOT_ZAPORIZHZHIA
            elif target_region in ["Донецька область"]:
                art_key = ARTILLERY_POS_TOT_DONETSK
                sector_key = SECTOR_TOT_DONETSK
            elif target_region in ["Харківська область"]:
                art_key = ARTILLERY_POS_BELGOROD_BORDER
                sector_key = SECTOR_BELGOROD
            elif target_region in ["Сумська область"]:
                art_key = ARTILLERY_POS_KURSK_BORDER
                sector_key = SECTOR_KURSK
            elif target_region in ["Чернігівська область"]:
                art_key = ARTILLERY_POS_BRYANSK_BORDER
                sector_key = SECTOR_BRYANSK
            else:
                art_key = ARTILLERY_POS_TOT_DONETSK
                sector_key = SECTOR_TOT_DONETSK

        art_info = ARTILLERY_MLRS_LAUNCH_SITES.get(art_key)
        sector_info = AVIATION_LAUNCH_SECTORS.get(sector_key)
        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": art_info["title"] if art_info else "Вогневі позиції ворога",
            "carrier_origin_latitude": art_info["lat_lon"][0] if art_info else 47.45,
            "carrier_origin_longitude": art_info["lat_lon"][1] if art_info else 34.65,
            "launch_sector_name": sector_info["title"] if sector_info else (art_info["title"] if art_info else None),
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else 47.45,
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else 34.65,
        }

    # =========================================================================
    # D. СПЕЦІАЛЬНІ ЗАГРОЗИ: ЦИРКОН, ВУЛИЧНІ БОЇ, РАДІАЦІЯ, ХІМНЕБЕЗПЕКА
    # =========================================================================
    if threat_type in [THREAT_ZIRCON, THREAT_URBAN_FIGHTS, THREAT_NUCLEAR, THREAT_CHEMICAL, "zircon", "urban_fights", "nuclear", "chemical"]:
        if threat_type in [THREAT_ZIRCON, "zircon"]:
            platform_type = "coastal_hypersonic"
            carrier_type = "bastion_zircon"
            site_info = SPECIAL_THREAT_SITES[SITE_ZIRCON_CRIMEA]
            sector_info = AVIATION_LAUNCH_SECTORS[SECTOR_BLACK_SEA]
        elif threat_type in [THREAT_NUCLEAR, "nuclear"]:
            platform_type = "special_hazard_zone"
            carrier_type = "cbrn_threat"
            site_info = SPECIAL_THREAT_SITES[SITE_ZNPP_ZONE]
            sector_info = AVIATION_LAUNCH_SECTORS[SECTOR_TOT_ZAPORIZHZHIA]
        elif threat_type in [THREAT_URBAN_FIGHTS, "urban_fights"]:
            platform_type = "combat_zone"
            carrier_type = "ground_forces"
            site_info = SPECIAL_THREAT_SITES[SITE_URBAN_KHARKIV] if target_region == "Харківська область" else SPECIAL_THREAT_SITES[SITE_URBAN_DONETSK]
            sector_info = AVIATION_LAUNCH_SECTORS[SECTOR_TOT_DONETSK]
        else:
            platform_type = "special_hazard_zone"
            carrier_type = "cbrn_threat"
            site_info = SPECIAL_THREAT_SITES[SITE_ZNPP_ZONE]
            sector_info = AVIATION_LAUNCH_SECTORS[SECTOR_TOT_ZAPORIZHZHIA]

        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": site_info["title"],
            "carrier_origin_latitude": site_info["lat_lon"][0],
            "carrier_origin_longitude": site_info["lat_lon"][1],
            "launch_sector_name": sector_info["title"] if sector_info else site_info["title"],
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else site_info["lat_lon"][0],
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else site_info["lat_lon"][1],
        }

    # =========================================================================
    # E. МОРСЬКІ НОСІЇ (Калібр / Циркон з Чорного чи Каспійського морів)
    # =========================================================================
    if threat_type == THREAT_CRUISE_MISSILE and (any(kw in text_lower for kw in ["калібр", "мор", "чорн", "фрегат", "підводн", "варшавянк"]) or (target_region in ["Одеська область", "Миколаївська область"] and not airbase_key)):
        platform_type = "naval_vessel"
        carrier_type = "naval_carrier"
        if "каспій" in text_lower:
            base_info = NAVAL_LAUNCH_BASES[NAVAL_BASE_CASPIAN_SEA]
            sector_info = AVIATION_LAUNCH_SECTORS.get(SECTOR_CASPIAN_SEA)
        else:
            base_info = NAVAL_LAUNCH_BASES[NAVAL_BASE_BLACK_SEA]
            sector_info = AVIATION_LAUNCH_SECTORS.get(SECTOR_BLACK_SEA)

        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": base_info["title"],
            "carrier_origin_latitude": base_info["lat_lon"][0],
            "carrier_origin_longitude": base_info["lat_lon"][1],
            "launch_sector_name": sector_info["title"] if sector_info else base_info["title"],
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else base_info["lat_lon"][0],
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else base_info["lat_lon"][1],
        }

    # =========================================================================
    # F. БАЛІСТИЧНІ ТА БЕРЕГОВІ РАКЕТНІ КОМПЛЕКСИ (Іскандер-М / KN-23 / Бастіон / С-300)
    # =========================================================================
    if threat_type in [THREAT_BALLISTIC, THREAT_ISKANDER, "iskander", "ballistic", "bastion", "onyx"]:
        platform_type = "ballistic_launcher"
        carrier_type = "otrk_launcher"
        
        ballistic_site_key = None
        for site_key, site_info in BALLISTIC_LAUNCH_SITES.items():
            if any(kw in text_lower for kw in site_info["keywords"]):
                ballistic_site_key = site_key
                break
        
        if not ballistic_site_key:
            if target_region in ["Одеська область", "Миколаївська область", "Херсонська область"]:
                ballistic_site_key = BALLISTIC_SITE_TARKHANKUT
                sector_key = SECTOR_CRIMEA_TARKHANKUT
            elif target_region in ["Харківська область", "Сумська область", "Полтавська область"]:
                ballistic_site_key = BALLISTIC_SITE_BELGOROD
                sector_key = SECTOR_BELGOROD
            elif target_region in ["Чернігівська область", "Київська область", "Житомирська область"]:
                ballistic_site_key = BALLISTIC_SITE_BRYANSK if "брянськ" in text_lower else BALLISTIC_SITE_KURSK
                sector_key = SECTOR_BRYANSK if "брянськ" in text_lower else SECTOR_KURSK
            elif target_region in ["Донецька область", "Запорізька область", "Дніпропетровська область"]:
                ballistic_site_key = BALLISTIC_SITE_ROSTOV
                sector_key = SECTOR_ROSTOV_TAGANROG
            elif target_region in ["Львівська область", "Івано-Франківська область", "Волинська область", "Рівненська область", "Тернопільська область", "Хмельницька область", "Чернівецька область", "Закарпатська область"]:
                ballistic_site_key = BALLISTIC_SITE_KAPUSTIN_YAR
                sector_key = SECTOR_VORONEZH
            else:
                ballistic_site_key = BALLISTIC_SITE_TARKHANKUT
                sector_key = SECTOR_CRIMEA_TARKHANKUT

        site_info = BALLISTIC_LAUNCH_SITES.get(ballistic_site_key)
        sector_info = AVIATION_LAUNCH_SECTORS.get(sector_key)
        return {
            "is_aviation": False,
            "platform_type": platform_type,
            "carrier_type": carrier_type,
            "carrier_origin_name": site_info["title"] if site_info else "Позиційний район Бєлгородська обл. РФ",
            "carrier_origin_latitude": site_info["lat_lon"][0] if site_info else 50.60,
            "carrier_origin_longitude": site_info["lat_lon"][1] if site_info else 36.58,
            "launch_sector_name": sector_info["title"] if sector_info else (site_info["title"] if site_info else None),
            "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else 50.60,
            "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else 36.58,
        }

    # =========================================================================
    # G. АВІАЦІЯ: ТАКТИЧНА ТА СТРАТЕГІЧНА (Су-34/35, МіГ-31К, Ту-95МС, Ту-22М3)
    # =========================================================================
    platform_type = "airbase"
    if threat_type == THREAT_KAB:
        carrier_type = "su34"
    elif threat_type in [THREAT_SU35, "su35"]:
        carrier_type = "su35"
    elif threat_type == THREAT_MIG31K:
        carrier_type = "mig31k"
    elif threat_type == THREAT_TU95:
        carrier_type = "tu95"
    elif threat_type == THREAT_TU22M3:
        carrier_type = "tu22m3"
    elif is_aviation:
        carrier_type = "tactical_aviation"

    # Sector heuristics if not explicitly mentioned in text
    if not sector_key:
        if transit_from:
            if transit_from in ["Сумська область", "Чернігівська область"]:
                sector_key = SECTOR_KURSK
            elif transit_from in ["Харківська область"]:
                sector_key = SECTOR_BELGOROD
            elif transit_from in ["Запорізька область", "Дніпропетровська область"]:
                sector_key = SECTOR_AZOV_SEA if threat_type != THREAT_KAB else SECTOR_TOT_ZAPORIZHZHIA
            elif transit_from in ["Херсонська область", "Миколаївська область", "Одеська область", "АР Крим"]:
                sector_key = SECTOR_BLACK_SEA if threat_type in [THREAT_CRUISE_MISSILE, THREAT_SU35] else SECTOR_TOT_KHERSON
            elif transit_from in ["Донецька область", "Луганська область"]:
                sector_key = SECTOR_TOT_DONETSK if threat_type in [THREAT_KAB, THREAT_ARTILLERY, THREAT_MLRS] else SECTOR_ROSTOV_TAGANROG
            else:
                sector_key = SECTOR_KURSK
        elif target_region in ["Харківська область", "Сумська область"]:
            sector_key = SECTOR_BELGOROD
        elif target_region in ["Чернігівська область", "Київська область", "Житомирська область"]:
            sector_key = SECTOR_KURSK if threat_type != THREAT_MIG31K else SECTOR_RYAZAN_TAMBOV
        elif target_region in ["Запорізька область", "Дніпропетровська область"]:
            sector_key = SECTOR_AZOV_SEA if threat_type == THREAT_KAB else SECTOR_TOT_ZAPORIZHZHIA
        elif target_region in ["Херсонська область", "Миколаївська область", "Одеська область"]:
            sector_key = SECTOR_BLACK_SEA if threat_type in [THREAT_CRUISE_MISSILE, THREAT_SU35] else SECTOR_TOT_KHERSON
        elif target_region in ["Донецька область", "Луганська область"]:
            sector_key = SECTOR_TOT_DONETSK
        elif target_region in ["Львівська область", "Волинська область", "Рівненська область", "Тернопільська область", "Івано-Франківська область", "Хмельницька область", "Чернівецька область", "Закарпатська область"]:
            sector_key = SECTOR_CASPIAN_SEA if threat_type in [THREAT_TU95, THREAT_CRUISE_MISSILE] else SECTOR_RYAZAN_TAMBOV

    # Special handling for strategic aviation
    if threat_type == THREAT_MIG31K:
        if not airbase_key:
            airbase_key = AIRBASE_SAVASLEYKA
        if not sector_key:
            sector_key = SECTOR_RYAZAN_TAMBOV
    elif threat_type == THREAT_TU95:
        if not airbase_key:
            airbase_key = AIRBASE_OLENYA
        if not sector_key:
            sector_key = SECTOR_CASPIAN_SEA
    elif threat_type == THREAT_TU22M3:
        if not airbase_key:
            airbase_key = AIRBASE_SHAYKOVKA
        if not sector_key:
            sector_key = SECTOR_BLACK_SEA if target_region in ["Одеська область", "Миколаївська область"] else SECTOR_KURSK

    # Tactical airbase default fallback based on sector
    if not airbase_key and is_aviation:
        if sector_key == SECTOR_BELGOROD:
            airbase_key = AIRBASE_BALTIMOR
        elif sector_key == SECTOR_KURSK:
            airbase_key = AIRBASE_HALINO
        elif sector_key in [SECTOR_AZOV_SEA, SECTOR_TOT_ZAPORIZHZHIA, SECTOR_TOT_DONETSK]:
            airbase_key = AIRBASE_MOROZOVSK
        elif sector_key in [SECTOR_BLACK_SEA, SECTOR_TOT_KHERSON]:
            airbase_key = AIRBASE_BELBEK

    airbase_info = RUSSIAN_AIRBASES.get(airbase_key) if airbase_key else None
    sector_info = AVIATION_LAUNCH_SECTORS.get(sector_key) if sector_key else None

    return {
        "is_aviation": is_aviation,
        "platform_type": platform_type,
        "carrier_type": carrier_type,
        "carrier_origin_name": airbase_info["title"] if airbase_info else None,
        "carrier_origin_latitude": airbase_info["lat_lon"][0] if airbase_info else None,
        "carrier_origin_longitude": airbase_info["lat_lon"][1] if airbase_info else None,
        "launch_sector_name": sector_info["title"] if sector_info else None,
        "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else None,
        "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else None,
    }


WEAPON_SUBTYPE_TRANSLATIONS: Dict[str, str] = {
    # Tactical Aviation & Carriers
    "su_34/su_35_tactical_aviation": "Су-34/Су-35 (Тактична авіація)",
    "su_34/su_35": "Су-34/Су-35 (Тактична авіація)",
    "tactical_aviation": "Тактична авіація РФ",
    "su34": "Су-34 (Фронтовий бомбардувальник)",
    "su35": "Су-35 (Багатоцільовий винищувач)",
    "su57": "Су-57 (Винищувач 5-го покоління)",
    "su30": "Су-30 (Винищувач)",
    "mig31k": "МіГ-31К (Носій Кинджалу)",
    "tu95": "Ту-95МС (Стратегічний ракетоносець)",
    "tu95ms": "Ту-95МС (Стратегічний ракетоносець)",
    "tu22m3": "Ту-22М3 (Дальній бомбардувальник)",
    "tu160": "Ту-160 (Стратегічний ракетоносець)",
    
    # Drones & UAVs
    "reactive_uav": "Реактивний ударний БпЛА",
    "reactive_drone": "Реактивний ударний дрон",
    "jet_shahed": "Реактивний БпЛА Shahed-238",
    "jet_drone": "Реактивний ударний дрон",
    "shahed": "Ударний БпЛА Shahed-136",
    "shahed_136": "Ударний БпЛА Shahed-136",
    "shahed_131": "Ударний БпЛА Shahed-131",
    "geran": "Ударний БпЛА Shahed-136 (Герань-2)",
    "geran_2": "Ударний БпЛА Shahed-136 (Герань-2)",
    "recon_drone": "Розвідувальний БпЛА",
    "recon_uav": "Розвідувальний БпЛА (Орлан / ZALA / Supercam)",
    "reconnaissance_uav": "Розвідувальний БпЛА",
    "orlan": "Розвідувальний БпЛА Орлан-10",
    "orlan_10": "Розвідувальний БпЛА Орлан-10",
    "zala": "Розвідувальний БпЛА ZALA",
    "supercam": "Розвідувальний БпЛА Supercam",
    "fpv_drone": "FPV-дрон камікадзе",
    "fpv": "FPV-дрон",
    "lancet": "Ударний БпЛА Ланцет",
    
    # Bombs & Guided Munitions
    "guided_bomb": "Керована авіабомба (КАБ)",
    "glide_bomb": "Плануюча авіабомба з УМПК",
    "kab": "КАБ (Керована авіабомба)",
    "uab": "КАБ (Керована авіабомба)",
    "fab": "ФАБ з УМПК (Авіабомба)",
    "umpk": "ФАБ з модулем УМПК",
    "umpb": "УМПБ Д-30СН (Плануючий боєприпас)",
    "odab": "ОДАБ (Термобарична авіабомба)",
    "rbk": "РБК (Касетна авіабомба)",
    "grom_e1": "Гром-Е1 (Гібридна ракета-бомба)",
    
    # Missiles & Ballistics
    "cruise_missile": "Крилата ракета",
    "ballistic_missile": "Балістична ракета",
    "ballistic": "Балістична ракета",
    "kinzhal": "Аеробалістична ракета Х-47М2 Кинджал",
    "kh47m2": "Аеробалістична ракета Х-47М2 Кинджал",
    "kh101": "Крилата ракета Х-101",
    "kh_101": "Крилата ракета Х-101",
    "kh555": "Крилата ракета Х-555",
    "kh_555": "Крилата ракета Х-555",
    "kh59": "Керована авіаційна ракета Х-59/Х-69",
    "kh_59": "Керована авіаційна ракета Х-59/Х-69",
    "kh69": "Керована авіаційна ракета Х-69",
    "kh_69": "Керована авіаційна ракета Х-69",
    "kh22": "Надзвукова крилата ракета Х-22",
    "kh_22": "Надзвукова крилата ракета Х-22",
    "kh32": "Надзвукова крилата ракета Х-32",
    "kh_32": "Надзвукова крилата ракета Х-32",
    "kh31p": "Протирадіолокаційна ракета Х-31П",
    "kh_31p": "Протирадіолокаційна ракета Х-31П",
    "kh35": "Протикорабельна/тактична ракета Х-35",
    "kh_35": "Протикорабельна/тактична ракета Х-35",
    "kalibr": "Крилата ракета Калібр",
    "iskander_m": "Балістична ракета 9М723 Іскандер-М",
    "iskander_k": "Крилата ракета 9М728 Іскандер-К",
    "iskander": "Ракетний комплекс Іскандер",
    "kn23": "Балістична ракета KN-23",
    "zircon": "Гіперзвукова ракета 3M22 Циркон",
    "onyx": "Надзвукова протикорабельна ракета Онікс",
    "oniks": "Надзвукова протикорабельна ракета Онікс",
    "s300": "ЗРК С-300 (удар по наземних цілях)",
    "s400": "ЗРК С-400 (удар по наземних цілях)",
    "mlrs": "РСЗВ (Торнадо-С / Град / Ураган)",
    "tornado_s": "РСЗВ Торнадо-С (високоточна)",
    "artillery": "Ствольна артилерія",
}


def translate_weapon_subtype_to_ukrainian(subtype: Optional[str]) -> str:
    """Translates any English/foreign weapon subtype string to proper Ukrainian terminology."""
    if not subtype:
        return ""
    s = str(subtype).strip()
    s_norm = s.lower().replace("-", "_").replace(" ", "_")
    
    # 1. Exact normalized match
    if s_norm in WEAPON_SUBTYPE_TRANSLATIONS:
        return WEAPON_SUBTYPE_TRANSLATIONS[s_norm]
    if s.lower() in WEAPON_SUBTYPE_TRANSLATIONS:
        return WEAPON_SUBTYPE_TRANSLATIONS[s.lower()]
        
    # 2. Pattern and substring match
    st_upper = s.upper().replace("-", "_")
    if "УАБ" in st_upper or "UAB" in st_upper:
        return "КАБ (Керована авіабомба)"
    elif "ФАБ" in st_upper or "FAB" in st_upper:
        if "УМПК" not in st_upper:
            return f"{s} з УМПК (Авіабомба)"
        return f"{s} (Авіабомба)"
    elif "УМПБ" in st_upper:
        return "УМПБ Д-30СН (Плануючий боєприпас)"
    elif "ОДАБ" in st_upper or "ODAB" in st_upper:
        return f"{s} (Термобарична авіабомба)"
    elif "РБК" in st_upper or "RBK" in st_upper:
        return f"{s} (Касетна авіабомба)"
    elif "ГРОМ" in st_upper or "ГРІМ" in st_upper or "GROM" in st_upper:
        return "Гром-Е1 (Гібридна ракета-бомба)"
    elif "SU_34" in st_upper or "СУ_34" in st_upper or "SU34" in st_upper:
        return "Су-34 (Фронтовий бомбардувальник)"
    elif "SU_35" in st_upper or "СУ_35" in st_upper or "SU35" in st_upper:
        return "Су-35 (Тактична авіація)"
    elif "TACTICAL" in st_upper:
        return "Тактична авіація РФ"
    elif "REACTIVE" in st_upper or "JET" in st_upper:
        return "Реактивний ударний БпЛА"
    elif "SHAHED" in st_upper:
        return "БПЛА Shahed-136"
    elif "KALIBR" in st_upper:
        return "Крилата ракета Калібр"
    elif "KH_101" in st_upper or "X_101" in st_upper or "X101" in st_upper or "KH101" in st_upper:
        return "Крилата ракета Х-101"
    elif "ISKANDER" in st_upper or "ИСКАНДЕР" in st_upper:
        return "Іскандер-М (Балістика)"
    elif "KINZHAL" in st_upper or "КИНЖАЛ" in st_upper or "КІНДЖАЛ" in st_upper:
        return "Аеробалістична ракета Х-47М2 Кинджал"
    elif "ZIRCON" in st_upper or "ЦИРКОН" in st_upper:
        return "Гіперзвукова ракета 3M22 Циркон"
        
    return s


def infer_threat_type_details(
    threat_type: Optional[str] = None,
    telemetry: Optional[Dict[str, Any]] = None,
    text: Optional[str] = None
) -> str:
    """
    Intelligently determines the Ukrainian display string for any threat object.
    If threat_type is known, returns the official registered title (and weapon subtype if present).
    If threat_type is unknown, systematically checks text keywords, Russian launch airbases/origins,
    and kinematic radar cruising speeds across all 20 threat types in the registry.
    """
    telemetry = telemetry or {}
    weapon_subtype = telemetry.get("weapon_subtype")
    if weapon_subtype and str(weapon_subtype).lower() not in ["unknown", "none", ""]:
        return translate_weapon_subtype_to_ukrainian(weapon_subtype)

    # 1. Direct match with registered threat types
    if threat_type and threat_type.lower() != THREAT_UNKNOWN and threat_type.lower() in THREAT_TITLES:
        return THREAT_TITLES[threat_type.lower()]

    # 2. Text keyword detection if text is provided
    if text:
        detected = detect_threat_type_from_text(text)
        if detected and detected != THREAT_UNKNOWN and detected in THREAT_TITLES:
            return THREAT_TITLES[detected]

    # 3. Airbase / Launch Hub detection
    launch_origin = telemetry.get("launch_origin") or (detect_launch_origin_from_text(text) if text else None)
    if launch_origin:
        lo_lower = str(launch_origin).lower()
        if any(h in lo_lower for h in ["саваслейка"]):
            return "МіГ-31К (Кинджал)"
        elif any(h in lo_lower for h in ["оленья", "енгельс"]):
            return "Ту-95МС (крилаті ракети)"
        elif any(h in lo_lower for h in ["шайковка", "моздок"]):
            return "Ту-22М3 (ракети Х-22/Х-32)"
        elif any(h in lo_lower for h in ["приморсько", "єйськ", "чауда", "курськ"]):
            return "БПЛА Shahed-136"
        elif any(h in lo_lower for h in ["капустин", "бєлгород"]):
            return "Балістичне озброєння / Іскандер-М"
        elif any(h in lo_lower for h in ["чорне море", "каспій"]):
            return "Крилаті ракети (Калібр/Х-101)"

    # 4. Kinematics & Radar Speed Profiling (covering all 20 registered types)
    speed = telemetry.get("speed_kmh")
    if speed:
        try:
            sp = float(speed)
            if sp <= 50:
                return "Хімічна / локальна загроза"
            elif sp <= 145:
                return "Малошвидкісна ціль (ймовірно FPV-дрон або розвідувальний БпЛА)"
            elif sp <= 240:
                return "Повітряна ціль (ймовірно ударний БпЛА Shahed-136)"
            elif sp <= 550:
                return "Швидкісна ціль (ймовірно реактивний БпЛА / швидкісний дрон)"
            elif sp <= 1100:
                return "Швидкісна ціль (ймовірно крилата ракета Х-101/Калібр або КАБ)"
            elif sp <= 1700:
                return "Швидкісна ціль (ймовірно авіаційна ракета або артилерійський снаряд)"
            elif sp <= 3200:
                return "Високошвидкісна ціль (ймовірно РСЗВ / аеробалістична ракета Кинджал)"
            elif sp <= 8000:
                return "Надзвукова / балістична ціль (ймовірно надзвукова ракета Х-22 або Іскандер-М)"
            else:
                return "Гіперзвукова ракета (ймовірно 3M22 Циркон)"
        except (ValueError, TypeError):
            pass

    # 5. Altitude profiling if speed is missing
    alt = telemetry.get("altitude_category")
    if alt:
        alt_l = str(alt).lower()
        if alt_l == "low":
            return "Низьковисотна ціль (ймовірно БпЛА або крилата ракета)"
        elif alt_l == "high":
            return "Висотна ціль (ймовірно тактична авіація або балістика)"

    return "Невстановлена повітряна ціль"


