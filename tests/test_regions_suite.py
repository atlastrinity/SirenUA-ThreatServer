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
    # 1. Emoji bullet lines
    text1 = "🛵Харківщина: Шахеди в напрямку Чугуєва.\n🛵Сумщина: БпЛА з півночі."
    kharkiv_text = extract_region_specific_text(text1, "Харківська область")
    assert "Чугуєва" in kharkiv_text
    assert "Сумщина" not in kharkiv_text

    # 2. Section Header format with sub-bullets (Exact user real-world case)
    text2 = """Дніпропетровська область
 ◦ Ударний Бп 1 грп.
 ◦ Реактивний 1 грп.
Запорізька область
 ◦ Реактивний 1 грп.
Кіровоградська область
 ◦ Реактивний 2 грп.
Миколаївська область
 ◦ Реактивний 1 грп."""
    
    zaporizhia_text = extract_region_specific_text(text2, "Запорізька область")
    assert "Запорізька область" in zaporizhia_text
    assert "Реактивний 1 грп." in zaporizhia_text
    assert "Дніпропетровська" not in zaporizhia_text
    assert "Кіровоградська" not in zaporizhia_text
    assert "Миколаївська" not in zaporizhia_text

    dnipro_text = extract_region_specific_text(text2, "Дніпропетровська область")
    assert "Дніпропетровська область" in dnipro_text
    assert "Ударний Бп 1 грп." in dnipro_text
    assert "Запорізька" not in dnipro_text

    # 3. Numbered list format
    text3 = """Рух ударних БпЛА:
1. БпЛА на півдні Харківщини, курс західний.
2. БпЛА на півночі Дніпропетровщини, курс на Полтавщину.
3. БпЛА на Запоріжжі в напрямку Дніпра.
4. БпЛА на півдні Одещини курсом на Татарбунари."""

    zapo_list = extract_region_specific_text(text3, "Запорізька область")
    assert "БпЛА на Запоріжжі в напрямку Дніпра" in zapo_list
    assert "Харківщини" not in zapo_list
    assert "Татарбунари" not in zapo_list

    # 4. Single-region text preservation
    text4 = "Запоріжжя - загроза застосування балістичного озброєння з півдня!"
    single_res = extract_region_specific_text(text4, "Запорізька область")
    assert single_res == text4

    print("✅ All core/regions.py unit tests passed cleanly!")
