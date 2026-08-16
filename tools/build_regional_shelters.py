"""
Regional Shelters Generator & Compiler.
Generates individual regional seed JSON files for all 25 Ukrainian regions
(Tier 1 Primary and Tier 2 Secondary), and compiles them into database/data/shelters_seed.json.
"""

import json
import os

true = True
false = False

REGIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "database", "data", "regions")
MASTER_SEED_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "data", "shelters_seed.json")

os.makedirs(REGIONS_DIR, exist_ok=True)

# Complete dataset for all 25 regions of Ukraine
REGIONAL_DATA = {
    "kyiv_city": [
        # --- 1-й порядок (Primary: Метро, Бомбосховища, Бункери, ПРУ) ---
        {
            "id": "gov_kyiv_metro_khreshchatyk",
            "name": "Станція метро «Хрещатик» (Центральне сховище)",
            "address": "вул. Хрещатик, 19, м. Київ",
            "lat": 50.4475, "lon": 30.5230,
            "type": "metro", "capacity": 5000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_teatralna",
            "name": "Станція метро «Театральна» (Глибоке сховище)",
            "address": "вул. Богдана Хмельницького, 5, м. Київ",
            "lat": 50.4450, "lon": 30.5180,
            "type": "metro", "capacity": 4500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_arsenalna",
            "name": "Станція метро «Арсенальна» (Надглибоке сховище 105м)",
            "address": "Арсенальна площа, м. Київ",
            "lat": 50.4443, "lon": 30.5453,
            "type": "metro", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_pozniaky",
            "name": "Станція метро «Позняки» (Укриття цивільного захисту)",
            "address": "просп. Петра Григоренка, м. Київ",
            "lat": 50.3980, "lon": 30.6340,
            "type": "metro", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_minska",
            "name": "Станція метро «Мінська» (Укриття Оболонь)",
            "address": "Оболонський просп., 21, м. Київ",
            "lat": 50.5120, "lon": 30.4985,
            "type": "metro", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_lukianivska",
            "name": "Станція метро «Лук'янівська» (Сховище)",
            "address": "вул. Юрія Іллєнка, 3, м. Київ",
            "lat": 50.4623, "lon": 30.4816,
            "type": "metro", "capacity": 4500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_metro_shuliavska",
            "name": "Станція метро «Шулявська» (Сховище)",
            "address": "просп. Перемоги, 48, м. Київ",
            "lat": 50.4550, "lon": 30.4455,
            "type": "metro", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_bunker_kmda",
            "name": "Захисна споруда цивільного захисту КМДА",
            "address": "вул. Хрещатик, 36, м. Київ",
            "lat": 50.4470, "lon": 30.5218,
            "type": "bunker", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kyiv_ohmatdyt_pru",
            "name": "НДСЛ «Охматдит» (Сховище ПРУ)",
            "address": "вул. В'ячеслава Чорновола, 28/1, м. Київ",
            "lat": 50.4516, "lon": 30.4827,
            "type": "radiation_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок (Secondary: ТРЦ Паркінги, Автоукриття, Школи) ---
        {
            "id": "gov_kyiv_retroville_parking",
            "name": "Підземний та відкритий паркінг ТРЦ «Retroville» (Цілодобово для авто)",
            "address": "просп. Правди, 47, м. Київ",
            "lat": 50.5050, "lon": 30.4150,
            "type": "mall_parking", "capacity": 3200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_lavina_parking",
            "name": "Паркінг ТРЦ «Lavina Mall» (Укриття для авто 24/7)",
            "address": "вул. Берковецька, 6Д, м. Київ",
            "lat": 50.4950, "lon": 30.3600,
            "type": "mall_parking", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_ocean_plaza_parking",
            "name": "Підземний багаторівневий паркінг ТРЦ «Ocean Plaza» (Укриття)",
            "address": "вул. Антоновича, 176, м. Київ",
            "lat": 50.4130, "lon": 30.5240,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_respublika_parking",
            "name": "Підземний паркінг ТРЦ «Respublika Park» (Цілодобово для авто)",
            "address": "вул. Кільцева дорога, 1, м. Київ",
            "lat": 50.3780, "lon": 30.4570,
            "type": "mall_parking", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_river_mall_parking",
            "name": "Багаторівневий паркінг ТРЦ «River Mall» (Заїзд для авто 24/7)",
            "address": "Дніпровська набережна, 12, м. Київ",
            "lat": 50.4030, "lon": 30.6150,
            "type": "mall_parking", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_gulliver_parking",
            "name": "Підземний паркінг ТРЦ «Gulliver» (Укриття / Авто)",
            "address": "Спортивна площа, 1A, м. Київ",
            "lat": 50.4385, "lon": 30.5230,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_blockbuster_parking",
            "name": "Паркінг ТРЦ «Blockbuster Mall» (Укриття для авто)",
            "address": "просп. Степана Бандери, 36, м. Київ",
            "lat": 50.4890, "lon": 30.5190,
            "type": "mall_parking", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_skymall_parking",
            "name": "Дворівневий паркінг ТРЦ «SkyMall» (Укриття)",
            "address": "просп. Романа Шухевича, 2Т, м. Київ",
            "lat": 50.4930, "lon": 30.5600,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_dream_yellow_parking",
            "name": "Підземний та прилеглий паркінг ТРЦ «Dream Yellow»",
            "address": "Оболонський просп., 1Б, м. Київ",
            "lat": 50.5055, "lon": 30.4980,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kyiv_lyceum_100",
            "name": "Ліцей №100 «Поділ» (Найпростіше укриття)",
            "address": "вул. Покровська, 4, м. Київ",
            "lat": 50.4600, "lon": 30.5195,
            "type": "school_shelter", "capacity": 600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "kyiv_oblast": [
        # --- 1-й порядок ---
        {
            "id": "gov_bc_rosava_bunker",
            "name": "Бомбосховище заводу «Росава» (Капітальне)",
            "address": "вул. Леваневського, 91, м. Біла Церква",
            "lat": 49.8050, "lon": 30.1550,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_brovary_civil_defense",
            "name": "Захисна споруда цивільного захисту №105",
            "address": "вул. Героїв України, 15, м. Бровари",
            "lat": 50.5110, "lon": 30.7900,
            "type": "bomb_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_boryspil_hospital_pru",
            "name": "Бориспільська багатопрофільна лікарня (ПРУ)",
            "address": "вул. Котляревського, 1, м. Бориспіль",
            "lat": 50.3450, "lon": 30.9520,
            "type": "radiation_shelter", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_fastiv_railway_shelter",
            "name": "Залізничний вузол Фастів (Бомбосховище)",
            "address": "вул. Шевченка, 25, м. Фастів",
            "lat": 50.0780, "lon": 29.9150,
            "type": "bomb_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_brovary_terminal_parking",
            "name": "Критий та відкритий паркінг ТРЦ «Термінал» (Для авто 24/7)",
            "address": "вул. Київська, 316, м. Бровари",
            "lat": 50.5280, "lon": 30.8050,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_boryspil_aeromall_parking",
            "name": "Паркінг ТРЦ «Aeromall» (Укриття для авто)",
            "address": "вул. Київський Шлях, 2/6, м. Бориспіль",
            "lat": 50.3580, "lon": 30.9320,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_bc_hermes_parking",
            "name": "Паркінг ТРЦ «Гермес» (Автоукриття)",
            "address": "вул. Ярослава Мудрого, 40, м. Біла Церква",
            "lat": 49.7960, "lon": 30.1180,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_irpin_zhiraf_parking",
            "name": "Паркінг ТЦ «Жираф» / Епіцентр",
            "address": "вул. Соборна, 160, м. Ірпінь",
            "lat": 50.5180, "lon": 30.2520,
            "type": "mall_parking", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_bucha_avenir_parking",
            "name": "Паркінг ТРЦ «Avenir Plaza» (Укриття)",
            "address": "вул. Леоніда Бірюкова, 2, м. Буча",
            "lat": 50.5480, "lon": 30.2210,
            "type": "mall_parking", "capacity": 850, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_irpin_lyceum_2",
            "name": "Ірпінський ліцей №2 (Найпростіше укриття)",
            "address": "вул. Тургенєвська, 28, м. Ірпінь",
            "lat": 50.5210, "lon": 30.2450,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "lviv": [
        # --- 1-й порядок ---
        {
            "id": "gov_lviv_civil_defense_1",
            "name": "Центральне бомбосховище цивільного захисту №1",
            "address": "вул. Коперника, 17, м. Львів",
            "lat": 49.8375, "lon": 24.0255,
            "type": "bomb_shelter", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_lviv_railway_station",
            "name": "Головний залізничний вокзал Львів (Сховище)",
            "address": "площа Двірцева, 1, м. Львів",
            "lat": 49.8356, "lon": 23.9950,
            "type": "bomb_shelter", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_lviv_laz_bunker",
            "name": "Капітальне бомбосховище колишнього ЛАЗ",
            "address": "вул. Стрийська, 45, м. Львів",
            "lat": 49.8080, "lon": 24.0180,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_stryi_hospital_shelter",
            "name": "Стрийська міська лікарня (Сховище ПРУ)",
            "address": "вул. Басараб, 15, м. Стрий",
            "lat": 49.2620, "lon": 23.8650,
            "type": "radiation_shelter", "capacity": 600, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_drohobych_townhall_shelter",
            "name": "Дрогобицька Ратуша (Підземне сховище)",
            "address": "площа Ринок, 1, м. Дрогобич",
            "lat": 49.3510, "lon": 23.5060,
            "type": "bomb_shelter", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_lviv_forum_parking",
            "name": "Підземний та багаторівневий паркінг ТРЦ «Forum Lviv» (Цілодобово для авто)",
            "address": "вул. Під Дубом, 7Б, м. Львів",
            "lat": 49.8499, "lon": 24.0223,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lviv_victoria_gardens",
            "name": "Багаторівневий паркінг ТРЦ «Victoria Gardens» (Укриття для авто 24/7)",
            "address": "вул. Кульпарківська, 226А, м. Львів",
            "lat": 49.8070, "lon": 23.9780,
            "type": "mall_parking", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lviv_king_cross_leopolis",
            "name": "Підземний та відкритий паркінг ТРЦ «King Cross Leopolis»",
            "address": "вул. Стрийська, 30, с. Сокільники / м. Львів",
            "lat": 49.7730, "lon": 24.0110,
            "type": "mall_parking", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lviv_spartak_parking",
            "name": "Паркінг СТРЦ «Spartak» (Укриття для авто)",
            "address": "вул. Гетьмана Мазепи, 1Б, м. Львів",
            "lat": 49.8700, "lon": 24.0260,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_stryi_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Стрий (Цілодобовий заїзд)",
            "address": "вул. Сколівська, 11, м. Стрий",
            "lat": 49.2530, "lon": 23.8420,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_uhersko_lyceum",
            "name": "Угерський ліцей (Найпростіше укриття)",
            "address": "вул. Івана Франка, 2, с. Угерсько",
            "lat": 49.3005, "lon": 23.8966,
            "type": "school_shelter", "capacity": 350, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "kharkiv": [
        # --- 1-й порядок ---
        {
            "id": "gov_kharkiv_metro_universytet",
            "name": "Станція метро «Університет» (Центральне глибоке укриття)",
            "address": "майдан Свободи, м. Харків",
            "lat": 50.0050, "lon": 36.2340,
            "type": "metro", "capacity": 5000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kharkiv_metro_derzhprom",
            "name": "Станція метро «Держпром» (Укриття цивільного захисту)",
            "address": "майдан Свободи, 6, м. Харків",
            "lat": 50.0070, "lon": 36.2280,
            "type": "metro", "capacity": 4500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kharkiv_metro_ist_muzei",
            "name": "Станція метро «Історичний музей»",
            "address": "майдан Конституції, м. Харків",
            "lat": 49.9920, "lon": 36.2315,
            "type": "metro", "capacity": 4500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kharkiv_metro_peremoha",
            "name": "Станція метро «Перемога» (Олексіївка)",
            "address": "просп. Перемоги, м. Харків",
            "lat": 50.0610, "lon": 36.2050,
            "type": "metro", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_chuhuiv_hospital_pru",
            "name": "Чугуївська центральна лікарня (Сховище ПРУ)",
            "address": "вул. Гвардійська, 52, м. Чугуїв",
            "lat": 49.8350, "lon": 36.6850,
            "type": "radiation_shelter", "capacity": 700, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_kharkiv_nikolsky_parking",
            "name": "Підземний паркінг ТРЦ «Nikolsky» (Цілодобово для авто)",
            "address": "вул. Пушкінська, 2А, м. Харків",
            "lat": 49.9910, "lon": 36.2345,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kharkiv_dafi_parking",
            "name": "Паркінг ТРЦ «Дафі» (Укриття для авто Салтівка)",
            "address": "вул. Героїв Праці, 9, м. Харків",
            "lat": 50.0270, "lon": 36.3310,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kharkiv_karavan_parking",
            "name": "Паркінг ТРЦ «Караван» (Укриття для авто)",
            "address": "вул. Героїв Праці, 7, м. Харків",
            "lat": 50.0290, "lon": 36.3280,
            "type": "mall_parking", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kharkiv_french_boulevard",
            "name": "Паркінг ТРЦ «Французький бульвар»",
            "address": "вул. Академіка Павлова, 44Б, м. Харків",
            "lat": 49.9880, "lon": 36.2890,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kharkiv_lyceum_27",
            "name": "Харківський фізико-математичний ліцей №27 (Укриття)",
            "address": "вул. Мар'їнська, 12, м. Харків",
            "lat": 49.9840, "lon": 36.2230,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "dnipro": [
        # --- 1-й порядок ---
        {
            "id": "gov_dnipro_metro_vokzalna",
            "name": "Станція метро «Вокзальна» (Укриття цивільного захисту)",
            "address": "Вокзальна площа, м. Дніпро",
            "lat": 48.4760, "lon": 35.0160,
            "type": "metro", "capacity": 4000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_dnipro_metro_pokrovska",
            "name": "Станція метро «Покровська» (Укриття)",
            "address": "вул. Юрія Кондратюка, м. Дніпро",
            "lat": 48.4810, "lon": 34.9270,
            "type": "metro", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_dnipro_yuzhmash_bunker",
            "name": "Капітальне бомбосховище «Південмаш»",
            "address": "вул. Криворізька, 1, м. Дніпро",
            "lat": 48.4350, "lon": 34.9850,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kr_tram_metalurhiv",
            "name": "Підземна станція «Проспект Металургів» (Швидкісний трамвай)",
            "address": "просп. Металургів, м. Кривий Ріг",
            "lat": 47.8930, "lon": 33.3950,
            "type": "metro", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_dnipro_most_city_parking",
            "name": "Багаторівневий паркінг ТРК «МОСТ-Сіті» (Цілодобово для авто)",
            "address": "вул. Глінки, 2, м. Дніпро",
            "lat": 48.4670, "lon": 35.0510,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_dnipro_karavan_parking",
            "name": "Паркінг ТРЦ «Караван» (Укриття для авто Лівий берег)",
            "address": "вул. Нижньодніпровська, 17, м. Дніпро",
            "lat": 48.5300, "lon": 35.0350,
            "type": "mall_parking", "capacity": 2800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_dnipro_dafi_parking",
            "name": "Паркінг ТРЦ «Дафі» Дніпро (Укриття)",
            "address": "бульвар Зоряний, 1А, м. Дніпро",
            "lat": 48.4280, "lon": 35.0230,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kr_solnechnaya_galereya",
            "name": "Паркінг ТРК «Сонячна Галерея» (Укриття для авто)",
            "address": "площа 30-річчя Перемоги, 1, м. Кривий Ріг",
            "lat": 47.9550, "lon": 33.4320,
            "type": "mall_parking", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_dnipro_lyceum_100",
            "name": "Дніпровський ліцей №100 (Найпростіше укриття)",
            "address": "площа Соборна, 2, м. Дніпро",
            "lat": 48.4550, "lon": 35.0680,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "odesa": [
        # --- 1-й порядок ---
        {
            "id": "gov_odesa_port_bunker",
            "name": "Капітальне бомбосховище Одеського морського порту",
            "address": "Митна площа, 1, м. Одеса",
            "lat": 46.4890, "lon": 30.7480,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_odesa_railway_shelter",
            "name": "Залізничний вокзал Одеса-Головна (Сховище)",
            "address": "Привокзальна площа, 2, м. Одеса",
            "lat": 46.4670, "lon": 30.7410,
            "type": "bomb_shelter", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_odesa_catacombs_nerubayske",
            "name": "Меморіальний комплекс «Одеські катакомби» (Глибоке сховище)",
            "address": "с. Нерубайське / м. Одеса",
            "lat": 46.5450, "lon": 30.6250,
            "type": "bunker", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_chornomorsk_port_bunker",
            "name": "Сховище цивільного захисту Чорноморського порту",
            "address": "вул. Праці, 1, м. Чорноморськ",
            "lat": 46.3050, "lon": 30.6550,
            "type": "bomb_shelter", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_odesa_city_center_tairova",
            "name": "Підземний та відкритий паркінг ТРЦ «City Center» Таїрова",
            "address": "просп. Небесної Сотні, 2, м. Одеса",
            "lat": 46.4190, "lon": 30.7060,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_odesa_riviera_parking",
            "name": "Паркінг ТРЦ «Riviera Shopping City» (Цілодобовий заїзд для авто)",
            "address": "Південна дорога, 101А, с. Фонтанка / м. Одеса",
            "lat": 46.5680, "lon": 30.8350,
            "type": "mall_parking", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_odesa_city_center_kotovsk",
            "name": "Паркінг ТРЦ «City Center Котовський»",
            "address": "вул. Давида Ойстраха, 32, м. Одеса",
            "lat": 46.5820, "lon": 30.7980,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_odesa_fontan_sky",
            "name": "Паркінг ТРЦ «Fontan Sky Center» (Укриття для авто)",
            "address": "провулок Семафорний, 4, м. Одеса",
            "lat": 46.4630, "lon": 30.7430,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_odesa_richelieu_lyceum",
            "name": "Рішельєвський науковий ліцей (Найпростіше укриття)",
            "address": "вул. Єлисаветинська, 5, м. Одеса",
            "lat": 46.4900, "lon": 30.7280,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "vinnytsia": [
        # --- 1-й порядок ---
        {
            "id": "gov_vinnytsia_civil_defense_10",
            "name": "Бомбосховище цивільного захисту №10",
            "address": "вул. Соборна, 67, м. Вінниця",
            "lat": 49.2335, "lon": 28.4680,
            "type": "bomb_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_vinnytsia_pyrogov_hospital_pru",
            "name": "Обласна лікарня ім. Пирогова (Сховище ПРУ)",
            "address": "вул. Пирогова, 46, м. Вінниця",
            "lat": 49.2250, "lon": 28.4480,
            "type": "radiation_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_zhmerynka_railway_bunker",
            "name": "Залізничне бомбосховище вузла Жмеринка",
            "address": "вул. Богдана Хмельницького, 18, м. Жмеринка",
            "lat": 49.0350, "lon": 28.1150,
            "type": "bomb_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_vinnytsia_megamoll_parking",
            "name": "Підземний паркінг ТРЦ «Мегамолл» (Укриття для авто 24/7)",
            "address": "вул. 600-річчя, 17, м. Вінниця",
            "lat": 49.2310, "lon": 28.4190,
            "type": "mall_parking", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_vinnytsia_sky_park",
            "name": "Підземний паркінг ТРЦ «Sky Park» (Укриття Центр)",
            "address": "вул. Миколи Оводова, 51, м. Вінниця",
            "lat": 49.2340, "lon": 28.4690,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_vinnytsia_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Вінниця (Цілодобово для авто)",
            "address": "вул. Батозька, 1В, м. Вінниця",
            "lat": 49.2450, "lon": 28.4980,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_vinnytsia_lyceum_7",
            "name": "Вінницький фізико-математичний ліцей №7 (Укриття)",
            "address": "вул. Владислава Городецького, 21, м. Вінниця",
            "lat": 49.2300, "lon": 28.4600,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "volyn": [
        # --- 1-й порядок ---
        {
            "id": "gov_lutsk_motor_bunker",
            "name": "Бомбосховище Луцького моторного заводу «Мотор»",
            "address": "вул. Ківерцівська, 3, м. Луцьк",
            "lat": 50.7650, "lon": 25.3550,
            "type": "bunker", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_lutsk_regional_hospital_pru",
            "name": "Волинська обласна клінічна лікарня (Сховище ПРУ)",
            "address": "просп. Президента Грушевського, 21, м. Луцьк",
            "lat": 50.7530, "lon": 25.3420,
            "type": "radiation_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kovel_railway_shelter",
            "name": "Залізничний вокзал Ковель (Бомбосховище)",
            "address": "вул. Привокзальна, 1, м. Ковель",
            "lat": 51.2180, "lon": 24.7120,
            "type": "bomb_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_lutsk_portcity_parking",
            "name": "Багаторівневий паркінг ТРЦ «ПортCity» (Цілодобово для авто)",
            "address": "вул. Сухомлинського, 1, м. Луцьк",
            "lat": 50.7580, "lon": 25.3620,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lutsk_promin_parking",
            "name": "Підземний паркінг РЦ «Промінь» (Укриття для авто)",
            "address": "просп. Президента Грушевського, 2, м. Луцьк",
            "lat": 50.7510, "lon": 25.3350,
            "type": "mall_parking", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lutsk_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Луцьк",
            "address": "вул. Окружна, 37, м. Луцьк",
            "lat": 50.7250, "lon": 25.3180,
            "type": "mall_parking", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_lutsk_lyceum_9",
            "name": "Луцький ліцей №9 (Найпростіше укриття)",
            "address": "вул. Потапова, 30, м. Луцьк",
            "lat": 50.7460, "lon": 25.3320,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "zhytomyr": [
        # --- 1-й порядок ---
        {
            "id": "gov_zhytomyr_promavtomatika_bunker",
            "name": "Бомбосховище заводу «Промавтоматика»",
            "address": "вул. Велика Бердичівська, 72, м. Житомир",
            "lat": 50.2450, "lon": 28.6780,
            "type": "bunker", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_zhytomyr_gerbachevsky_pru",
            "name": "Обласна лікарня ім. Гербачевського (Сховище ПРУ)",
            "address": "вул. Червоного Хреста, 3, м. Житомир",
            "lat": 50.2380, "lon": 28.6550,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_korosten_skelya_bunker",
            "name": "Військово-історичний комплекс «Скеля» (Скельний бункер цивільного захисту)",
            "address": "парк Древлянський, м. Коростень",
            "lat": 50.9500, "lon": 28.6500,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_zhytomyr_global_parking",
            "name": "Паркінг ТРЦ «Глобал UA» (Укриття для авто 24/7)",
            "address": "вул. Київська, 77, м. Житомир",
            "lat": 50.2630, "lon": 28.6880,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_zhytomyr_oldi_parking",
            "name": "Паркінг ТЦ «ОЛДІ» (Цілодобовий заїзд для авто)",
            "address": "вул. Грушевського, 5, м. Житомир",
            "lat": 50.2610, "lon": 28.6720,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_zhytomyr_lyceum_25",
            "name": "Житомирський ліцей №25 (Найпростіше укриття)",
            "address": "вул. Мала Бердичівська, 4, м. Житомир",
            "lat": 50.2520, "lon": 28.6620,
            "type": "school_shelter", "capacity": 600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "zakarpattia": [
        # --- 1-й порядок ---
        {
            "id": "gov_uzhhorod_oda_bunker",
            "name": "Захисна споруда цивільного захисту Закарпатської ОДА",
            "address": "площа Народна, 4, м. Ужгород",
            "lat": 48.6250, "lon": 22.2880,
            "type": "bunker", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_uzhhorod_regional_hospital",
            "name": "Закарпатська обласна клінічна лікарня (Сховище)",
            "address": "вул. Капушанська, 24, м. Ужгород",
            "lat": 48.6180, "lon": 22.2950,
            "type": "radiation_shelter", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_mukachevo_palanok_shelter",
            "name": "Замок Паланок (Казематні сховища цивільного захисту)",
            "address": "провулок Куруців, 5, м. Мукачево",
            "lat": 48.4310, "lon": 22.6870,
            "type": "bunker", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_uzhhorod_dastor_parking",
            "name": "Паркінг ТРЦ «Дастор» (Укриття для авто 24/7)",
            "address": "вул. Собранецька, 89, м. Ужгород",
            "lat": 48.6320, "lon": 22.2750,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_uzhhorod_tokyo_parking",
            "name": "Паркінг ТРЦ «Токіо» (Автоукриття)",
            "address": "вул. Легоцького, 19А, м. Ужгород",
            "lat": 48.6080, "lon": 22.2710,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_mukachevo_shchodnya_parking",
            "name": "Паркінг ТРК «Щодня» Мукачево",
            "address": "вул. Возз'єднання, 20, м. Мукачево",
            "lat": 48.4420, "lon": 22.7180,
            "type": "mall_parking", "capacity": 700, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_uzhhorod_lyceum_classic",
            "name": "Ужгородський класичний ліцей (Найпростіше укриття)",
            "address": "вул. 8-го Березня, 44, м. Ужгород",
            "lat": 48.6110, "lon": 22.2820,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "zaporizhzhia": [
        # --- 1-й порядок ---
        {
            "id": "gov_zp_motor_sich_bunker",
            "name": "Бомбосховище АТ «Мотор Січ» (Капітальне сховище)",
            "address": "просп. Моторобудівників, 15, м. Запоріжжя",
            "lat": 47.8280, "lon": 35.1950,
            "type": "bunker", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_zp_zaporizhstal_bunker",
            "name": "Захисна споруда комбінату «Запоріжсталь»",
            "address": "вул. Південне шосе, 72, м. Запоріжжя",
            "lat": 47.8650, "lon": 35.1680,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_zp_regional_hospital_pru",
            "name": "Запорізька обласна клінічна лікарня (Сховище ПРУ)",
            "address": "Оріхівське шосе, 10, м. Запоріжжя",
            "lat": 47.7850, "lon": 35.2150,
            "type": "radiation_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_zp_city_mall_parking",
            "name": "Паркінг ТРЦ «City Mall» Запоріжжя (Укриття для авто 24/7)",
            "address": "вул. Запорізька, 1Б, м. Запоріжжя",
            "lat": 47.8180, "lon": 35.1580,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_zp_avrora_parking",
            "name": "Підземний паркінг ТРЦ «Аврора» (Укриття)",
            "address": "просп. Соборний, 148, м. Запоріжжя",
            "lat": 47.8320, "lon": 35.1480,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_zp_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Запоріжжя",
            "address": "вул. Запорізька, 1В, м. Запоріжжя",
            "lat": 47.8160, "lon": 35.1610,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_zp_lyceum_99",
            "name": "Запорізький багатопрофільний ліцей №99 (Найпростіше укриття)",
            "address": "вул. Героїв 93-ї бригади, 13А, м. Запоріжжя",
            "lat": 47.8020, "lon": 35.0550,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "ivano_frankivsk": [
        # --- 1-й порядок ---
        {
            "id": "gov_if_railway_station",
            "name": "Залізничний вокзал Івано-Франківськ (Сховище)",
            "address": "вул. Привокзальна, 1, м. Івано-Франківськ",
            "lat": 48.9240, "lon": 24.7245,
            "type": "bomb_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_if_promprylad_bunker",
            "name": "Бомбосховище заводу «Промприлад»",
            "address": "вул. Академіка Сахарова, 23, м. Івано-Франківськ",
            "lat": 48.9150, "lon": 24.7120,
            "type": "bunker", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kalush_karpatnaftokhim_pru",
            "name": "Сховище цивільного захисту «Карпатнафтохім» (ПРУ)",
            "address": "вул. Промислова, 4, м. Калуш",
            "lat": 49.0450, "lon": 24.3650,
            "type": "radiation_shelter", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_if_veles_parking",
            "name": "Паркінг ТРЦ «Велес» (Цілодобово для авто)",
            "address": "вул. Вовчинецька, 225А, м. Івано-Франківськ",
            "lat": 48.9450, "lon": 24.7380,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_if_panorama_plaza",
            "name": "Підземний паркінг ТЦ «Панорама Plaza»",
            "address": "Північний бульвар, 2А, м. Івано-Франківськ",
            "lat": 48.9280, "lon": 24.7040,
            "type": "mall_parking", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_if_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Івано-Франківськ",
            "address": "вул. В. Івасюка, 17, м. Івано-Франківськ",
            "lat": 48.9320, "lon": 24.7410,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_if_lyceum_1",
            "name": "Івано-Франківський ліцей №1 (Найпростіше укриття)",
            "address": "вул. Довга, 37, м. Івано-Франківськ",
            "lat": 48.9290, "lon": 24.7150,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "kirovohrad": [
        # --- 1-й порядок ---
        {
            "id": "gov_krop_hydrosila_bunker",
            "name": "Бомбосховище ПАТ «Гідросила» (Капітальне)",
            "address": "вул. Братиславська, 5, м. Кропивницький",
            "lat": 48.5120, "lon": 32.2450,
            "type": "bunker", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_krop_regional_hospital_pru",
            "name": "Кіровоградська обласна лікарня (Сховище ПРУ)",
            "address": "просп. Університетський, 2/5, м. Кропивницький",
            "lat": 48.4980, "lon": 32.2180,
            "type": "radiation_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_krop_depot_parking",
            "name": "Паркінг ТРЦ «Depot Center» (Укриття для авто 24/7)",
            "address": "вул. Велика Перспективна, 48, м. Кропивницький",
            "lat": 48.5100, "lon": 32.2650,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_krop_plasma_parking",
            "name": "Паркінг ТЦ «Плазма» (Автоукриття)",
            "address": "вул. Соборна, 1А, м. Кропивницький",
            "lat": 48.5180, "lon": 32.2720,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_krop_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Кропивницький",
            "address": "вул. Генерала Родимцева, 1, м. Кропивницький",
            "lat": 48.4890, "lon": 32.2250,
            "type": "mall_parking", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_krop_lyceum_natural",
            "name": "Центральноукраїнський науковий ліцей-інтернат (Укриття)",
            "address": "вул. Шевченка, 1, м. Кропивницький",
            "lat": 48.5140, "lon": 32.2610,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "mykolaiv": [
        # --- 1-й порядок ---
        {
            "id": "gov_myk_shipyard_bunker",
            "name": "Капітальне бомбосховище Чорноморського суднобудівного заводу",
            "address": "вул. Індустріальна, 1, м. Миколаїв",
            "lat": 46.9550, "lon": 31.9680,
            "type": "bunker", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_myk_zorya_bunker",
            "name": "Бомбосховище НВКГ «Зоря» — «Машпроект»",
            "address": "просп. Богоявленський, 42А, м. Миколаїв",
            "lat": 46.9380, "lon": 32.0450,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_yuzhnoukrainsk_paes_pru",
            "name": "Сховище ПРУ Південноукраїнської АЕС",
            "address": "Проммайданчик ПАЕС, м. Южноукраїнськ",
            "lat": 47.8150, "lon": 31.2180,
            "type": "radiation_shelter", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_myk_city_center_parking",
            "name": "Підземний паркінг ТРЦ «City Center» Миколаїв (24/7 для авто)",
            "address": "просп. Центральний, 98, м. Миколаїв",
            "lat": 46.9670, "lon": 32.0020,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_myk_tavria_parking",
            "name": "Паркінг ТЦ «Таврія В» Миколаїв (Автоукриття)",
            "address": "просп. Корабелів, 14, м. Миколаїв",
            "lat": 46.8750, "lon": 32.0120,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_myk_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Миколаїв",
            "address": "просп. Героїв України, 9Д, м. Миколаїв",
            "lat": 46.9950, "lon": 32.0150,
            "type": "mall_parking", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_myk_lyceum_2",
            "name": "Миколаївський ліцей №2 (Найпростіше укриття)",
            "address": "вул. Потьомкінська, 30, м. Миколаїв",
            "lat": 46.9720, "lon": 31.9880,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "poltava": [
        # --- 1-й порядок ---
        {
            "id": "gov_poltava_turbomech_bunker",
            "name": "Бомбосховище Полтавського турбомеханічного заводу",
            "address": "вул. Зіньківська, 6, м. Полтава",
            "lat": 49.6010, "lon": 34.5420,
            "type": "bunker", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_poltava_sklifosovsky_pru",
            "name": "Полтавська обласна лікарня ім. Скліфосовського (ПРУ)",
            "address": "вул. Шевченка, 23, м. Полтава",
            "lat": 49.5850, "lon": 34.5480,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kremenchuk_kraz_bunker",
            "name": "Капітальне бомбосховище автозаводу «КрАЗ»",
            "address": "вул. Київська, 64, м. Кременчук",
            "lat": 49.1120, "lon": 33.4380,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_poltava_equator",
            "name": "Паркінг ТРЦ «Екватор» (Укриття для авто 24/7)",
            "address": "вул. Ковпака, 26, м. Полтава",
            "lat": 49.6170, "lon": 34.5120,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_poltava_kyiv_parking",
            "name": "Паркінг ТРЦ «Київ» Полтава (Автоукриття)",
            "address": "вул. Зіньківська, 6/1А, м. Полтава",
            "lat": 49.6030, "lon": 34.5410,
            "type": "mall_parking", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_poltava_concord_parking",
            "name": "Паркінг ТРЦ «Конкорд»",
            "address": "вул. Європейська, 60А, м. Полтава",
            "lat": 49.5750, "lon": 34.5350,
            "type": "mall_parking", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kremenchuk_galaktika",
            "name": "Паркінг ТРК «Галактика» Кременчук",
            "address": "вул. Соборна, 21, м. Кременчук",
            "lat": 49.0680, "lon": 33.4120,
            "type": "mall_parking", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_poltava_lyceum_1",
            "name": "Полтавський міський багатопрофільний ліцей №1 (Укриття)",
            "address": "вул. В'ячеслава Чорновола, 3, м. Полтава",
            "lat": 49.5890, "lon": 34.5550,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "rivne": [
        # --- 1-й порядок ---
        {
            "id": "gov_rivne_azot_bunker",
            "name": "Сховище цивільного захисту ПАТ «РівнеАзот»",
            "address": "вул. Соборна, 370, м. Рівне",
            "lat": 50.6380, "lon": 26.1750,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_rivne_regional_hospital_pru",
            "name": "Рівненська обласна клінічна лікарня (Сховище ПРУ)",
            "address": "вул. Київська, 78Г, м. Рівне",
            "lat": 50.6150, "lon": 26.2820,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_varash_raes_pru",
            "name": "Сховище ПРУ Рівненської АЕС",
            "address": "Проммайданчик РАЕС, м. Вараш",
            "lat": 51.3280, "lon": 25.8920,
            "type": "radiation_shelter", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_rivne_zlata_plaza_parking",
            "name": "Підземний паркінг ТРЦ «Злата Плаза» (Цілодобово для авто)",
            "address": "вул. Олександра Борисенка, 1, м. Рівне",
            "lat": 50.6200, "lon": 26.2510,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_rivne_equator_parking",
            "name": "Паркінг ТРЦ «Екватор» Рівне (Укриття для авто)",
            "address": "вул. Кулика і Гудачека, 23, м. Рівне",
            "lat": 50.6050, "lon": 26.2250,
            "type": "mall_parking", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_rivne_chayka_parking",
            "name": "Паркінг ТРЦ «Чайка» Рівне",
            "address": "вул. Гагаріна, 16, м. Рівне",
            "lat": 50.6310, "lon": 26.2650,
            "type": "mall_parking", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_rivne_lyceum_12",
            "name": "Рівненський академічний ліцей «Престиж» (Укриття)",
            "address": "вул. Данила Галицького, 14, м. Рівне",
            "lat": 50.6180, "lon": 26.2690,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "sumy": [
        # --- 1-й порядок ---
        {
            "id": "gov_sumy_nvo_bunker",
            "name": "Бомбосховище Сумського НВО ім. Фрунзе",
            "address": "вул. Горького, 58, м. Суми",
            "lat": 50.9220, "lon": 34.8050,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_sumy_regional_hospital_pru",
            "name": "Сумська обласна клінічна лікарня (Сховище ПРУ)",
            "address": "вул. Троїцька, 48, м. Суми",
            "lat": 50.9150, "lon": 34.8180,
            "type": "radiation_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_shostka_impulse_bunker",
            "name": "Захисна споруда КП Шосткинський завод «Імпульс»",
            "address": "вул. Заводська, 41, м. Шостка",
            "lat": 51.8650, "lon": 33.4850,
            "type": "bunker", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_sumy_manufaktura_parking",
            "name": "Підземний паркінг ТРЦ «Мануфактура» (24/7 для авто)",
            "address": "вул. Харківська, 2/2, м. Суми",
            "lat": 50.9020, "lon": 34.8060,
            "type": "mall_parking", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_sumy_lavina_parking",
            "name": "Паркінг ТРЦ «Лавина» Суми (Автоукриття)",
            "address": "просп. Михайла Лушпи, 4/1, м. Суми",
            "lat": 50.8950, "lon": 34.8320,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_sumy_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Суми",
            "address": "вул. Героїв Крут, 1/3, м. Суми",
            "lat": 50.8850, "lon": 34.8450,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_sumy_classical_gymnasium",
            "name": "Сумська класична гімназія (Найпростіше укриття)",
            "address": "вул. Троїцька, 5, м. Суми",
            "lat": 50.9110, "lon": 34.8090,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "ternopil": [
        # --- 1-й порядок ---
        {
            "id": "gov_ternopil_theatre",
            "name": "Драматичний театр / Підземне сховище",
            "address": "бульвар Тараса Шевченка, 22, м. Тернопіль",
            "lat": 49.5535, "lon": 25.5940,
            "type": "bomb_shelter", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_ternopil_vatra_bunker",
            "name": "Бомбосховище заводу «Ватра»",
            "address": "вул. Микулинецька, 46, м. Тернопіль",
            "lat": 49.5250, "lon": 25.6020,
            "type": "bunker", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_ternopil_regional_hospital_pru",
            "name": "Тернопільська університетська лікарня (Сховище ПРУ)",
            "address": "вул. Клінічна, 1, м. Тернопіль",
            "lat": 49.5580, "lon": 25.6120,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_ternopil_podolyany_parking",
            "name": "Паркінг ТРЦ «Подоляни» (Укриття для авто 24/7)",
            "address": "вул. Текстильна, 28Ч, м. Тернопіль",
            "lat": 49.5750, "lon": 25.6210,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_ternopil_ornava_parking",
            "name": "Паркінг ТЦ «Орнава» (Автоукриття)",
            "address": "вул. Торговиця, 15А, м. Тернопіль",
            "lat": 49.5420, "lon": 25.5910,
            "type": "mall_parking", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_ternopil_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Тернопіль",
            "address": "вул. Поліська, 7, м. Тернопіль",
            "lat": 49.5690, "lon": 25.6350,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_ternopil_lyceum_6",
            "name": "Тернопільський ліцей №6 ім. Н. Яремчука (Укриття)",
            "address": "вул. Сагайдачного, 6, м. Тернопіль",
            "lat": 49.5520, "lon": 25.5920,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "khmelnytskyi": [
        # --- 1-й порядок ---
        {
            "id": "gov_khm_novator_bunker",
            "name": "Бомбосховище ДП «Новатор»",
            "address": "вул. Тернопільська, 17, м. Хмельницький",
            "lat": 49.4080, "lon": 26.9620,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_khm_regional_hospital_pru",
            "name": "Хмельницька обласна лікарня (Сховище ПРУ)",
            "address": "вул. Пілотська, 1, м. Хмельницький",
            "lat": 49.4280, "lon": 27.0120,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_netishyn_khes_pru",
            "name": "Сховище ПРУ Хмельницької АЕС",
            "address": "Проммайданчик ХАЕС, м. Нетішин",
            "lat": 50.3010, "lon": 26.6500,
            "type": "radiation_shelter", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_khm_oasis_parking",
            "name": "Паркінг ТРЦ «Оазис» (Цілодобово для авто)",
            "address": "вул. Степана Бандери, 2А, м. Хмельницький",
            "lat": 49.4350, "lon": 26.9850,
            "type": "mall_parking", "capacity": 1800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_khm_lybid_plaza",
            "name": "Підземний паркінг ТРЦ «Либідь Плаза»",
            "address": "вул. Кам'янецька, 21, м. Хмельницький",
            "lat": 49.4220, "lon": 26.9830,
            "type": "mall_parking", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_khm_woodmall_parking",
            "name": "Паркінг ТРЦ «Woodmall» Хмельницький",
            "address": "вул. Трудова, 6А, м. Хмельницький",
            "lat": 49.4380, "lon": 27.0210,
            "type": "mall_parking", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_khm_lyceum_17",
            "name": "Хмельницький ліцей №17 (Найпростіше укриття)",
            "address": "вул. Героїв Майдану, 5, м. Хмельницький",
            "lat": 49.4250, "lon": 26.9810,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "cherkasy": [
        # --- 1-й порядок ---
        {
            "id": "gov_cherkasy_azot_bunker",
            "name": "Бомбосховище ПАТ «Азот» (Капітальне)",
            "address": "вул. Першотравнева, 72, м. Черкаси",
            "lat": 49.3950, "lon": 32.0950,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_cherkasy_regional_hospital_pru",
            "name": "Черкаська обласна лікарня (Сховище ПРУ)",
            "address": "вул. Менделєєва, 3, м. Черкаси",
            "lat": 49.4580, "lon": 32.0150,
            "type": "radiation_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_cherkasy_lyubava_parking",
            "name": "Паркінг ТРЦ «Любава» (Укриття для авто 24/7)",
            "address": "бульвар Шевченка, 208/1, м. Черкаси",
            "lat": 49.4420, "lon": 32.0620,
            "type": "mall_parking", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_cherkasy_dnipro_plaza",
            "name": "Паркінг ТРЦ «Дніпро Плаза» Черкаси",
            "address": "вул. Припортова, 34, м. Черкаси",
            "lat": 49.4490, "lon": 32.0880,
            "type": "mall_parking", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_cherkasy_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Черкаси",
            "address": "вул. 30-річчя Перемоги, 29, м. Черкаси",
            "lat": 49.4180, "lon": 32.0180,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_cherkasy_humanitarian_lyceum",
            "name": "Черкаський гуманітарно-правовий ліцей (Укриття)",
            "address": "вул. Байди Вишневецького, 58, м. Черкаси",
            "lat": 49.4390, "lon": 32.0550,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "chernivtsi": [
        # --- 1-й порядок ---
        {
            "id": "gov_chernivtsi_graviton_bunker",
            "name": "Бомбосховище заводу «Гравітон»",
            "address": "вул. Руська, 248, м. Чернівці",
            "lat": 48.2750, "lon": 25.9850,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_chernivtsi_university_shelter",
            "name": "Підземне сховище Резиденції Чернівецького університету",
            "address": "вул. Коцюбинського, 2, м. Чернівці",
            "lat": 48.2970, "lon": 25.9240,
            "type": "bomb_shelter", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_khotyn_fortress_shelter",
            "name": "Хотинська фортеця (Казематні укриття)",
            "address": "вул. Фортечна, 1, м. Хотин",
            "lat": 48.5220, "lon": 26.4980,
            "type": "bunker", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_chernivtsi_maidan_parking",
            "name": "Паркінг ТРЦ «Майдан» (Цілодобово для авто)",
            "address": "вул. Героїв Майдану, 71, м. Чернівці",
            "lat": 48.2710, "lon": 25.9380,
            "type": "mall_parking", "capacity": 1600, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernivtsi_panorama_parking",
            "name": "Паркінг ТРЦ «Панорама» Чернівці",
            "address": "вул. Хотинська, 43, м. Чернівці",
            "lat": 48.3150, "lon": 25.9550,
            "type": "mall_parking", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernivtsi_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Чернівці",
            "address": "вул. Хотинська, 10А, м. Чернівці",
            "lat": 48.3110, "lon": 25.9450,
            "type": "mall_parking", "capacity": 1500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernivtsi_lyceum_1",
            "name": "Чернівецький ліцей №1 (Найпростіше укриття)",
            "address": "вул. Штейнбарга, 17, м. Чернівці",
            "lat": 48.2910, "lon": 25.9320,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "chernihiv": [
        # --- 1-й порядок ---
        {
            "id": "gov_chernihiv_chezara_bunker",
            "name": "Бомбосховище заводу «ЧеЗаРа» (Капітальне)",
            "address": "вул. Захисників України, 25, м. Чернігів",
            "lat": 51.5150, "lon": 31.3320,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_chernihiv_regional_hospital_pru",
            "name": "Чернігівська обласна лікарня (Сховище ПРУ)",
            "address": "вул. Волковича, 25, м. Чернігів",
            "lat": 51.5280, "lon": 31.2850,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_nizhyn_progres_bunker",
            "name": "Бомбосховище заводу «Прогрес» Ніжин",
            "address": "вул. Станіслава Прощенка, 12, м. Ніжин",
            "lat": 51.0450, "lon": 31.8950,
            "type": "bunker", "capacity": 1200, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_chernihiv_hollywood_parking",
            "name": "Паркінг ТРЦ «Hollywood» (Цілодобово для авто)",
            "address": "вул. 77 Гвардійської Дивізії, 1В, м. Чернігів",
            "lat": 51.5180, "lon": 31.3050,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernihiv_tsum_parking",
            "name": "Паркінг ТРЦ «ЦУМ» Чернігів",
            "address": "просп. Миру, 49, м. Чернігів",
            "lat": 51.4980, "lon": 31.2950,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernihiv_epicenter_parking",
            "name": "Паркінг ТЦ «Епіцентр» Чернігів",
            "address": "вул. Івана Мазепи, 48, м. Чернігів",
            "lat": 51.4820, "lon": 31.2650,
            "type": "mall_parking", "capacity": 1400, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_chernihiv_collegium_11",
            "name": "Чернігівський колегіум №11 (Найпростіше укриття)",
            "address": "просп. Миру, 137, м. Чернігів",
            "lat": 51.5210, "lon": 31.2820,
            "type": "school_shelter", "capacity": 550, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "donetsk": [
        # --- 1-й порядок ---
        {
            "id": "gov_kramatorsk_nkmz_bunker",
            "name": "Капітальне бомбосховище ПАТ «НКМЗ»",
            "address": "вул. Олекси Тихого, 6, м. Краматорськ",
            "lat": 48.7350, "lon": 37.5850,
            "type": "bunker", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_sloviansk_heavy_mach_bunker",
            "name": "Бомбосховище «Словважмаш»",
            "address": "вул. Вокзальна, 45, м. Слов'янськ",
            "lat": 48.8650, "lon": 37.6150,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_pokrovsk_mine_shelter",
            "name": "Сховище шахтоуправління «Покровське»",
            "address": "вул. Захисників України, 1, м. Покровськ",
            "lat": 48.2850, "lon": 37.1850,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_kramatorsk_passage_parking",
            "name": "Паркінг ТЦ «Пасаж» Краматорськ",
            "address": "вул. Василя Стуса, 45, м. Краматорськ",
            "lat": 48.7380, "lon": 37.5750,
            "type": "mall_parking", "capacity": 900, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_sloviansk_yarmarok",
            "name": "Паркінг ТЦ «Ярмарочний» Слов'янськ",
            "address": "вул. Шевченка, 12, м. Слов'янськ",
            "lat": 48.8550, "lon": 37.6080,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kramatorsk_lyceum_35",
            "name": "Краматорський ліцей №35 ім. В. Шеймана (Укриття)",
            "address": "вул. Ювілейна, 17, м. Краматорськ",
            "lat": 48.7450, "lon": 37.5620,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "luhansk": [
        # --- 1-й порядок ---
        {
            "id": "gov_severodonetsk_azot_bunker",
            "name": "Капітальне бомбосховище об'єднання «Азот»",
            "address": "вул. Пивоварова, 5, м. Сєвєродонецьк",
            "lat": 48.9450, "lon": 38.4850,
            "type": "bunker", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_lysychansk_naftokhim_bunker",
            "name": "Захисна споруда Лисичанського нафтохімічного комплексу",
            "address": "вул. Первомайська, 2, м. Лисичанськ",
            "lat": 48.8950, "lon": 38.4250,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_severodonetsk_jazz_parking",
            "name": "Паркінг ТРЦ «Джаз» Сєвєродонецьк",
            "address": "просп. Центральний, 46, м. Сєвєродонецьк",
            "lat": 48.9500, "lon": 38.4950,
            "type": "mall_parking", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_severodonetsk_lyceum_multiprofile",
            "name": "Сєвєродонецький багатопрофільний ліцей (Укриття)",
            "address": "вул. Федоренка, 39, м. Сєвєродонецьк",
            "lat": 48.9480, "lon": 38.4880,
            "type": "school_shelter", "capacity": 450, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "kherson": [
        # --- 1-й порядок ---
        {
            "id": "gov_kherson_shipyard_bunker",
            "name": "Бомбосховище Херсонського суднобудівного заводу",
            "address": "Карантинний острів, 1, м. Херсон",
            "lat": 46.6210, "lon": 32.6050,
            "type": "bunker", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_kherson_regional_hospital_pru",
            "name": "Херсонська обласна клінічна лікарня (Сховище ПРУ)",
            "address": "просп. Ушакова, 67, м. Херсон",
            "lat": 46.6450, "lon": 32.6150,
            "type": "radiation_shelter", "capacity": 1100, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_kherson_fabrika_parking",
            "name": "Паркінг ТРЦ «Фабрика» (Укриття для авто 24/7)",
            "address": "вул. Залаегерсег, 18, м. Херсон",
            "lat": 46.6580, "lon": 32.6350,
            "type": "mall_parking", "capacity": 3000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kherson_suvorovsky_parking",
            "name": "Підземний паркінг ТРЦ «Суворовський»",
            "address": "вул. Суворова, 12, м. Херсон",
            "lat": 46.6350, "lon": 32.6120,
            "type": "mall_parking", "capacity": 800, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_kherson_academic_lyceum",
            "name": "Херсонський академічний ліцей ім. Мішукова (Укриття)",
            "address": "вул. 40 років Жовтня, 27, м. Херсон",
            "lat": 46.6480, "lon": 32.6280,
            "type": "school_shelter", "capacity": 500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": false, "is_vehicle_accessible": false
        }
    ],

    "crimea": [
        # --- 1-й порядок ---
        {
            "id": "gov_sevastopol_morskoy_zavod",
            "name": "Капітальне бомбосховище Севморзаводу",
            "address": "вул. Героїв Севастополя, 1, м. Севастополь",
            "lat": 44.6080, "lon": 33.5350,
            "type": "bunker", "capacity": 3500, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_simferopol_pneumatika_bunker",
            "name": "Бомбосховище заводу «Пневматика»",
            "address": "вул. Балаклавська, 68, м. Сімферополь",
            "lat": 44.9250, "lon": 34.0950,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        {
            "id": "gov_yalta_massandra_shelter",
            "name": "Глибокі підземні тунелі та сховища Масандра",
            "address": "вул. Виноробна, 9, м. Ялта",
            "lat": 44.5150, "lon": 34.1850,
            "type": "bunker", "capacity": 2000, "accessible": true, "source": "gov",
            "is_primary": true, "is_night_accessible": true, "is_vehicle_accessible": false
        },
        # --- 2-й порядок ---
        {
            "id": "gov_simferopol_meganom_parking",
            "name": "Паркінг ТРК «MEGANOM» (Укриття для авто)",
            "address": "Євпаторійське шосе, 8, м. Сімферополь",
            "lat": 44.9750, "lon": 34.0750,
            "type": "mall_parking", "capacity": 2500, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_sevastopol_musson_parking",
            "name": "Паркінг ТРЦ «Мусон» Севастополь",
            "address": "вул. Вакуленчука, 29, м. Севастополь",
            "lat": 44.5850, "lon": 33.4950,
            "type": "mall_parking", "capacity": 2200, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        },
        {
            "id": "gov_yalta_confetti_parking",
            "name": "Паркінг ТРЦ «Конфетті» Ялта",
            "address": "вул. Більшовицька, 10, м. Ялта",
            "lat": 44.4980, "lon": 34.1420,
            "type": "mall_parking", "capacity": 1000, "accessible": true, "source": "gov",
            "is_primary": false, "is_night_accessible": true, "is_vehicle_accessible": true
        }
    ]
}


def build():
    print(f"📦 Generating regional files in {REGIONS_DIR}...")
    master_list = []
    total_shelters = 0

    for region_code, shelters in REGIONAL_DATA.items():
        region_file = os.path.join(REGIONS_DIR, f"{region_code}.json")
        with open(region_file, "w", encoding="utf-8") as f:
            json.dump(shelters, f, ensure_ascii=False, indent=2)
        
        primary_count = sum(1 for s in shelters if s.get("is_primary"))
        secondary_count = sum(1 for s in shelters if not s.get("is_primary"))
        total_shelters += len(shelters)
        master_list.extend(shelters)
        print(f"  ✅ {region_code}.json: {len(shelters)} укриттів (Tier 1: {primary_count}, Tier 2: {secondary_count})")

    # Write master combined file shelters_seed.json
    with open(MASTER_SEED_PATH, "w", encoding="utf-8") as f:
        json.dump(master_list, f, ensure_ascii=False, indent=2)
    print(f"\n🌟 Successfully compiled {total_shelters} total shelters across {len(REGIONAL_DATA)} regions into {MASTER_SEED_PATH}")


if __name__ == "__main__":
    build()
