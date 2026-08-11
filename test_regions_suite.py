"""
Comprehensive unit tests for core/regions.py
"""

from core.regions import (
    ALL_REGIONS,
    REGION_ALIASES,
    PERMANENTLY_OCCUPIED_REGIONS,
    MACRO_REGIONS,
    normalize_region_name,
    get_genitive_region,
    get_ukrainian_threat_type,
    extract_region_specific_text
)

def test_region_normalization_aliases():
    # Canonical
    assert normalize_region_name("Вінницька область") == "Вінницька область"
    assert normalize_region_name("м. Київ") == "м. Київ"
    assert normalize_region_name("АР Крим") == "АР Крим"

    # Short & City names
    assert normalize_region_name("м.Київ") == "м. Київ"
    assert normalize_region_name("Київ") == "м. Київ"
    assert normalize_region_name("Дніпро") == "Дніпропетровська область"
    assert normalize_region_name("Харків") == "Харківська область"
    assert normalize_region_name("Одеса") == "Одеська область"

    # Regional names
    assert normalize_region_name("Вінниччина") == "Вінницька область"
    assert normalize_region_name("Київщина") == "Київська область"
    assert normalize_region_name("Сумщина") == "Сумська область"
    assert normalize_region_name("Буковина") == "Чернівецька область"
    assert normalize_region_name("Волинь") == "Волинська область"

    # Case-insensitive lowercased
    assert normalize_region_name("київщина") == "Київська область"
    assert normalize_region_name("сумщина") == "Сумська область"
    assert normalize_region_name("одеська обл") == "Одеська область"
    assert normalize_region_name("харків") == "Харківська область"

    # Genitive forms
    assert normalize_region_name("Вінницької області") == "Вінницька область"
    assert normalize_region_name("Києва") == "м. Київ"
    assert normalize_region_name("Криму") == "АР Крим"

def test_permanently_occupied_regions():
    assert "АР Крим" in PERMANENTLY_OCCUPIED_REGIONS
    assert "Луганська область" in PERMANENTLY_OCCUPIED_REGIONS

def test_genitive_region_mapping():
    assert get_genitive_region("Київська область") == "Київської області"
    assert get_genitive_region("м. Київ") == "Києва"
    assert get_genitive_region("АР Крим") == "Криму"

def test_ukrainian_threat_type():
    assert get_ukrainian_threat_type("shahed") == "БпЛА"
    assert get_ukrainian_threat_type("mig31k") == "МіГ-31К"
    assert get_ukrainian_threat_type("kab") == "КАБ"

def test_macro_regions():
    assert "north" in MACRO_REGIONS
    assert "Київська область" in MACRO_REGIONS["north"]
    assert "Львівська область" in MACRO_REGIONS["west"]

def test_extract_region_specific_text():
    text = "🛵Харківщина: Шахеди в напрямку Чугуєва.\n🛵Сумщина: БпЛА з півночі."
    kharkiv_text = extract_region_specific_text(text, "Харківська область")
    assert "Чугуєва" in kharkiv_text
    assert "Сумщина" not in kharkiv_text
    print("✅ All core/regions.py unit tests passed cleanly!")
