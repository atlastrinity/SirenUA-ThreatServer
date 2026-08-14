"""
Centralized Threat Types, Kinematics, Speeds, Russian Airbases, and Calculation Constants Registry.
Serves as the single source of truth for all departure and arrival threat objects across the system.
"""

from typing import Dict, Tuple, Optional, List, Any

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
THREAT_ISKANDER = "iskander"
THREAT_ARTILLERY = "artillery"
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
    THREAT_ISKANDER: "Іскандер-М",
    THREAT_ARTILLERY: "Артилерія",
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
    THREAT_ISKANDER: "Іскандер-М",
    THREAT_ARTILLERY: "обстріл",
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
    THREAT_ZIRCON: (600, 1200),            # 10-20 mins
    THREAT_MLRS: (1200, 1800),             # 20-30 mins
    THREAT_FPV: (1800, 1800),              # 30 mins
    THREAT_RECON: (3600, 3600),            # 60 mins
    THREAT_RECON_UAV: (3600, 3600),        # 60 mins
    THREAT_OFFICIAL_ALARM: (3600, 3600),
    THREAT_UNKNOWN: (3600, 3600),
}

THREAT_DEFAULT_ETAS: Dict[str, Tuple[str, str]] = {
    THREAT_SHAHED: ("~200 хв", "+1-2 год"),
    THREAT_CRUISE_MISSILE: ("~55 хв", "+15-30 хв"),
    THREAT_BALLISTIC: ("~15 хв", "~2-5 хв"),
    THREAT_MIG31K: ("~40 хв", "~20-40 хв"),
    THREAT_KAB: ("~5 хв", "~3-5 хв"),
    THREAT_TU95: ("~110 хв", "~30-90 хв"),
    THREAT_TU22M3: ("~15 хв", "~3-10 хв"),
    THREAT_SU35: ("~20 хв", "~5-15 хв"),
    THREAT_ISKANDER: ("~25 хв", "~2-5 хв"),
    THREAT_ARTILLERY: ("~10 хв", "~0-5 хв"),
    THREAT_ZIRCON: ("~5 хв", "~1-3 хв"),
    THREAT_MLRS: ("~10 хв", "~0-5 хв"),
    THREAT_FPV: ("~20 хв", "~5-15 хв"),
    THREAT_RECON: ("~30 хв", "~15-30 хв"),
    THREAT_RECON_UAV: ("~30 хв", "~15-30 хв"),
    THREAT_OFFICIAL_ALARM: ("-", "-"),
    THREAT_UNKNOWN: ("~30 хв", "~30 хв"),
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
        "каб", "каби", "кабів", "авіабомб", "авиабомб", "умпк", "керован", "управляемые", "фаб", "уаб", "бомбардуван"
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
        "title": "Авіацентр Липецьк (Липецька обл.)",
        "primary_threat": THREAT_SU35,
        "keywords": ["липецьк", "липецк", "lipetsk"],
        "lat_lon": (52.64, 39.45),
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
# AVIATION LAUNCH SECTORS (Рубежі пусків / райони патрулювання тактичної та стратегічної авіації)
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

AVIATION_LAUNCH_SECTORS: Dict[str, Dict[str, Any]] = {
    SECTOR_BELGOROD: {
        "title": "Рубіж Бєлгородська обл. РФ",
        "lat_lon": (50.60, 36.58),
        "target_regions": ["Харківська область", "Сумська область", "Полтавська область"],
        "keywords": ["бєлгород", "белгород", "бєлгородщин", "шебекіно", "грайворон"],
    },
    SECTOR_KURSK: {
        "title": "Рубіж Курська обл. РФ",
        "lat_lon": (51.70, 35.50),
        "target_regions": ["Сумська область", "Чернігівська область", "Полтавська область", "Харківська область"],
        "keywords": ["курськ", "курск", "курщин", "глушково", "рильськ", "суджа"],
    },
    SECTOR_BRYANSK: {
        "title": "Рубіж Брянська обл. РФ",
        "lat_lon": (52.50, 33.50),
        "target_regions": ["Чернігівська область", "Сумська область", "Київська область"],
        "keywords": ["брянськ", "брянск", "брянщин", "клинці"],
    },
    SECTOR_AZOV_SEA: {
        "title": "Акваторія Азовського моря",
        "lat_lon": (46.20, 36.50),
        "target_regions": ["Запорізька область", "Дніпропетровська область", "Донецька область", "Херсонська область"],
        "keywords": ["азов", "азовськ", "азовське море", "приазов"],
    },
    SECTOR_BLACK_SEA: {
        "title": "Акваторія Чорного моря",
        "lat_lon": (44.50, 32.00),
        "target_regions": ["Одеська область", "Миколаївська область", "Херсонська область"],
        "keywords": ["чорне море", "чорного моря", "севастополь", "тарханкут"],
    },
    SECTOR_TOT_ZAPORIZHZHIA: {
        "title": "Рубіж ТОТ Запорізької обл.",
        "lat_lon": (47.15, 35.80),
        "target_regions": ["Запорізька область", "Дніпропетровська область"],
        "keywords": ["тот запоріз", "окупована запоріз", "токмак", "мелітополь", "пологи", "бердянськ"],
    },
    SECTOR_TOT_DONETSK: {
        "title": "Рубіж ТОТ Донецької обл.",
        "lat_lon": (47.90, 37.80),
        "target_regions": ["Донецька область", "Харківська область", "Дніпропетровська область"],
        "keywords": ["тот донец", "окупована донец", "донецьк", "волноваха", "маріуполь"],
    },
    SECTOR_TOT_KHERSON: {
        "title": "Рубіж ТОТ Херсонської обл. (Лівобережжя)",
        "lat_lon": (46.50, 33.20),
        "target_regions": ["Херсонська область", "Миколаївська область"],
        "keywords": ["лівобережж", "тот херсон", "окупована херсон", "каховка", "скадовськ", "олешки"],
    },
    SECTOR_CASPIAN_SEA: {
        "title": "Район пусків Каспійське море",
        "lat_lon": (43.00, 50.00),
        "target_regions": ["Вся Україна"],
        "keywords": ["каспій", "каспійське море", "каспий"],
    },
    SECTOR_SARATOV_ENGELS: {
        "title": "Район пусків Енгельс / Саратов",
        "lat_lon": (51.48, 46.21),
        "target_regions": ["Вся Україна"],
        "keywords": ["енгельс", "энгельс", "саратов"],
    },
    SECTOR_RYAZAN_TAMBOV: {
        "title": "Рубіж пуску Кинджалів (Рязань / Тамбов / Липецьк)",
        "lat_lon": (53.50, 40.50),
        "target_regions": ["Вся Україна"],
        "keywords": ["саваслейка", "липецьк", "рязань", "тамбов"],
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
    """Formats ETA in seconds into standardized human-readable Ukrainian string (hours as integers, remaining as minutes)."""
    if eta_seconds is None or eta_seconds <= 0:
        return "в області"
    elif eta_seconds < 300:
        return "~2-5 хв"
    elif eta_seconds < 900:
        mins = eta_seconds // 60
        return f"~{mins}-{mins + 5} хв"
    elif eta_seconds < 3600:
        mins = eta_seconds // 60
        return f"~{mins} хв"
    else:
        hours = eta_seconds // 3600
        mins = (eta_seconds % 3600) // 60
        if mins == 0:
            return f"~{hours} год"
        return f"~{hours} год {mins} хв"

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
    """Identifies Russian airfield or launch hub from text using centralized registry."""
    text_lower = text.lower()
    for origin_key, info in RUSSIAN_AIRBASES.items():
        if any(kw in text_lower for kw in info["keywords"]):
            return origin_key
    return None

def get_launch_origin_title(origin_key: Optional[str]) -> str:
    """Returns official title for an airbase or launch hub."""
    if origin_key and origin_key in RUSSIAN_AIRBASES:
        return RUSSIAN_AIRBASES[origin_key]["title"]
    return origin_key or ""

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
    target_region: Optional[str] = None
) -> Dict[str, Any]:
    """
    Resolves complete two-tier tactical aviation profile:
    1. Carrier aircraft (Su-34, Su-35, MiG-31K, Tu-95MS, Tu-22M3)
    2. Origin airbase (with coordinates and title)
    3. Launch/drop sector (with coordinates and title)
    4. Munition combat kinetics & ETA
    """
    is_aviation = threat_type in [
        THREAT_KAB, THREAT_SU35, "su35", "su34",
        THREAT_MIG31K, THREAT_TU95, THREAT_TU22M3,
        THREAT_CRUISE_MISSILE
    ] or bool(text and any(w in text.lower() for w in ["каб", "су-34", "су-35", "міг-31", "ту-95", "ту-22", "кинджал", "х-59", "х-69", "х-101", "х-22"]))

    # Default fallback values
    carrier_type = None
    airbase_key = None
    sector_key = None

    if text:
        airbase_key = detect_launch_origin_from_text(text)
        sector_key = detect_launch_sector_from_text(text)

    # 1. Determine Carrier Aircraft Type
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
    elif threat_type == THREAT_CRUISE_MISSILE and text and "калібр" in text.lower():
        carrier_type = "naval_carrier"
    elif is_aviation:
        carrier_type = "tactical_aviation"

    # 2. Sector heuristics if not explicitly mentioned in text
    if not sector_key and target_region:
        if target_region in ["Харківська область", "Сумська область"]:
            sector_key = SECTOR_BELGOROD
        elif target_region in ["Чернігівська область", "Київська область"]:
            sector_key = SECTOR_KURSK if threat_type != THREAT_MIG31K else SECTOR_RYAZAN_TAMBOV
        elif target_region in ["Запорізька область", "Дніпропетровська область"]:
            sector_key = SECTOR_AZOV_SEA if threat_type == THREAT_KAB else SECTOR_TOT_ZAPORIZHZHIA
        elif target_region in ["Херсонська область", "Миколаївська область", "Одеська область"]:
            sector_key = SECTOR_BLACK_SEA if threat_type in [THREAT_CRUISE_MISSILE, THREAT_SU35] else SECTOR_TOT_KHERSON
        elif target_region == "Донецька область":
            sector_key = SECTOR_TOT_DONETSK

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
        "carrier_type": carrier_type,
        "carrier_origin_name": airbase_info["title"] if airbase_info else None,
        "carrier_origin_latitude": airbase_info["lat_lon"][0] if airbase_info else None,
        "carrier_origin_longitude": airbase_info["lat_lon"][1] if airbase_info else None,
        "launch_sector_name": sector_info["title"] if sector_info else None,
        "launch_sector_latitude": sector_info["lat_lon"][0] if sector_info else None,
        "launch_sector_longitude": sector_info["lat_lon"][1] if sector_info else None,
    }

