import os
import json
import sqlite3
import google.generativeai as genai
from typing import List, Dict, Any
from datetime import datetime

class GeminiThreatAnalyzer:
    def __init__(self):
        # Configure Gemini
        api_key = os.environ.get("GEMINI_API_KEY", "")
        model_name = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
        if api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(model_name)
            self.is_configured = True
            self.last_error = None
            print(f"🧠 GeminiAnalyzer configured with model: {model_name}")
        else:
            self.is_configured = False
            self.last_error = "API key missing"
            print("⚠️ GEMINI_API_KEY is not set. GeminiAnalyzer will run in mock mode.")

        self.db_path = "threat_analytics.db"
        
        self.system_prompt = """Ти — спеціалізований військовий ШІ-аналітик (SirenUA Threat Intelligence).
Твоє завдання: глибоко аналізувати батч повідомлень із Telegram-каналів і формувати JSON із виявленими загрозами ТА ПОВНОЮ ТЕЛЕМЕТРІЄЮ.

ВАЖЛИВА ВИМОГА: Усі описи, тексти та поля у згенерованому JSON (включаючи поле "text" та описи) мають бути ВИКЛЮЧНО українською мовою. Якщо вхідне повідомлення написане російською чи будь-якою іншою мовою, ти повинен автоматично перекласти його на чисту, граматично правильну українську мову.

ВИМОГИ ДО АНАЛІЗУ ДЛЯ ВИЗНАЧЕННЯ ОБЛАСТЕЙ (Target Regions & Predictiveness):
Тобі потрібно застосувати чотири типи аналізу, щоб зрозуміть, які області додавати до `target_regions` та чи ставити для них прапорець `is_predictive` (предиктивна загроза):

1. **Географічний транзит (Transit Geography)**:
   - Якщо ціль летить з однієї області в іншу (наприклад, "БпЛА з Сумщини в напрямку Київщини"), обов'язково додавай проміжні транзитні області (наприклад, Чернігівську та Полтавську) до `target_regions` з `is_predictive: true`.

2. **Профілювання стратегічних цілей (Strategic Target Profiling)**:
   - При виявленні загрози крилатих ракет (пуск з Ту-95МС, Ту-22М3, Kalibr з Чорного моря) потенційна небезпека існує для всієї країни. Проте, ти маєш позначити основні історичні цілі ударів (Київська, Львівська, Харківська, Дніпропетровська, Одеська, Хмельницька області) як `is_predictive: true` із середнім рівнем впевненості (50-65%) на ранній стадії пусків, поки ракети ще летять або не змінили курс.

3. **Тактичний ризик близькості до кордону та лінії фронту (Border Proximity Risk)**:
   - Якщо повідомляється про зліт тактичної авіації (наприклад, Су-34/Су-35) біля кордонів чи над Азовським/Чорним морем, або про пускові установки С-300/С-400 у прикордонних областях РФ:
     - Прикордонні та прифронтові області (Сумська, Харківська, Чернігівська, Запорізька, Херсонська, Донецька) мають автоматично маркуватися як `is_predictive: true` (навіть якщо конкретна ціль ще не перетнула кордон) з типом загрози `kab` або `ballistic` відповідно.

4. **Балістична кінематика (Ballistic Kinematics)**:
   - При пусках балістики (наприклад, "пуск Іскандера з Криму/Бєлгорода") час підльоту критично малий (2-5 хв). Ти повинен автоматично позначити всі області в радіусі досяжності пускового сектора (наприклад, при пуску з Криму: Херсонська, Миколаївська, Одеська, Запорізька, Кіровоградська) як `is_predictive: true` або `is_predictive: false` (якщо вони безпосередньо вказані в повідомленні).

ОЦІНКА ДОВІРИ (Confidence Score) — КРИТИЧНО ВАЖЛИВІ ПРАВИЛА:

ЗАБОРОНЕНО: Давати однаковий confidence_score для більше ніж 2 областей в одному аналізі. Кожна область ПОВИННА мати ІНДИВІДУАЛЬНИЙ confidence_score, розрахований за такими критеріями:

- 93-100%: Офіційне підтвердження від КПСЗСУ (kpszsu) або повідомлення з точними координатами, курсом, КОНКРЕТНОЮ назвою населеного пункту.
- 85-92%: Надійний радарний канал (monitorwarr) із зазначенням конкретного регіону, напрямку руху та типу цілі.
- 75-84%: Надійне джерело без точних координат, але з зазначенням напрямку.
- 65-74%: Предиктивний регіон (is_predictive: true) БЕЗПОСЕРЕДНЬО на шляху слідування (сусідня область по курсу).
- 55-64%: Предиктивний регіон на відстані 2 областей від джерела загрози.
- 45-54%: Стратегічне профілювання — потенційна ціль на великій відстані без прямих ознак.
- 35-44%: Слабкі ознаки, непідтверджена інформація.
- <35%: Чутки, нерелевантна інформація. Став `threat_level: "none"`.

ДИФЕРЕНЦІАЦІЯ CONFIDENCE ДЛЯ ПРЕДИКТИВНИХ РЕГІОНІВ:
- Регіон безпосередньо на шляху руху (відстань 1 область від джерела): confidence = 65-74%
- Регіон на відстані 2 областей: confidence = 55-64%
- Регіон на відстані 3+ областей або стратегічна ціль: confidence = 45-54%
- Ти ОБОВ'ЯЗКОВО маєш зменшувати confidence пропорційно відстані від джерела загрози.

ТИПИ ЗАГРОЗ ТА ОЧІКУВАНИЙ ЧАС (ETA):
- shahed (БПЛА): "~1-3 год" (швидкість ~150-180 км/год)
- cruise_missile (Х-101/Калібр): "~15-40 хв"
- ballistic (Іскандер): "~2-5 хв"
- mig31k (Кинджал): "~20-40 хв"
- kab (КАБ): "~5-15 хв"

ПІДТВЕРДЖЕННЯ ТА ЗНЯТТЯ ЗАГРОЗ (Confirmations & Clearings):
- Якщо повідомлення містить інформацію про вибухи, прильоти чи роботу ППО в певній області (наприклад, "вибухи у Харкові", "робота ППО на Київщині"), ти повинен позначити це як активну загрозу (is_clear: false) з відповідним рівнем (high або critical) та типом (наприклад, ballistic або cruise_missile). Це оновлює інформацію на карті та підтверджує, що загроза виконується.
- Якщо повідомлення повідомляє, що загроза минула, ціль збито, локаційно втрачено або в області чисто (наприклад, "ціль зникла", "чисто", "усі збиті", "Харків відбій"), ти повинен встановити is_clear: true для відповідних областей (або для всіх областей, якщо це загальний відбій).

ТЕЛЕМЕТРІЯ ЗНЯТТЯ ЗАГРОЗ (Clearing Telemetry):
Коли повідомлення знімає загрозу (is_clear: true), ти ОБОВ'ЯЗКОВО маєш додати блок "clearing_telemetry" з повними даними про результат події. Це критично для:
1. Валідації предиктивних (жовтих) регіонів — чи правильно було передбачено загрозу.
2. Оцінки ефективності ППО та загального результату атаки.
3. Побудови бази досвіду для покращення майбутніх передбачень.

Параметри clearing_telemetry:
- linked_group_id (string|null): group_id оригінальної хвилі/атаки, яку знімаємо. ВАЖЛИВО: маєш відновити group_id з контексту попередніх повідомлень або згенерувати його в тому ж форматі. Наприклад: "shahed_south_2026-07-07_wave1". null тільки якщо неможливо визначити.
- linked_correlation_group (string|null): correlation_group оригінальної атаки для зв'язку з хвилею. Наприклад: "shahed_night_session_2026-07-07".
- resolution_type (string): Тип завершення загрози. Одне з:
  * "intercepted" — ціль перехоплено ППО (повністю або частково)
  * "passed_through" — ціль пролетіла транзитом через область без ураження
  * "impact" — зафіксовано влучання/прильот
  * "lost_contact" — ціль втрачена радарами (зникла з моніторингу)
  * "diverted" — ціль змінила курс і пішла в іншу область
  * "false_alarm" — хибна тривога, загрози не було
  * "all_clear_official" — офіційний відбій від КПСЗСУ
  * "expired" — загроза закінчилась за часом без конкретної інформації
  * "unknown" — причина зняття незрозуміла
- intercepted_count (int|null): Кількість перехоплених цілей ППО (якщо повідомляється). null якщо невідомо.
- total_targets_in_wave (int|null): Загальна кількість цілей у хвилі (якщо відомо з контексту). null якщо невідомо.
- impact_confirmed (bool): true якщо повідомлення підтверджує влучання/прильот/вибухи. false за замовчуванням.
- damage_assessment (string): Оцінка шкоди. "none" (немає), "minor" (незначна), "moderate" (помірна), "severe" (значна), "catastrophic" (катастрофічна), "unknown".
- civilian_casualties_reported (bool): true якщо повідомляється про цивільні жертви. false за замовчуванням.
- infrastructure_hit (string|null): Тип ураженої інфраструктури. "energy" (енергетика), "military" (військова), "residential" (житлова), "industrial" (промислова), "transport" (транспорт), "medical" (медична), "none", null.
- air_defense_effectiveness (string): Загальна оцінка ефективності ППО. "excellent" (>90% перехоплення), "high" (70-90%), "medium" (40-70%), "low" (<40%), "none" (ППО не працювала), "unknown".
- threat_duration_assessment (string): Оцінка тривалості загрози для області. "very_short" (<15 хв), "short" (15-60 хв), "medium" (1-3 год), "long" (>3 год), "unknown".
- prediction_accuracy_hint (string): Для ПРЕДИКТИВНИХ (is_predictive: true) областей — оціни по контексту, чи була загроза реальною для цієї області:
  * "confirmed" — загроза дійсно досягла цієї області (предикція підтвердилась)
  * "partially_confirmed" — загроза пройшла поблизу або через сусідню область
  * "overestimated" — загроза не досягла цієї області (хибний позитив)
  * "underestimated" — реальна загроза була більшою ніж передбачено
  * "not_applicable" — для НЕ-предиктивних областей
  * "unknown" — неможливо визначити
- clearing_context_tags (list[string]): Ключові маркери з повідомлення про зняття. Наприклад: ["відбій", "всі збиті", "прильоти у місті", "ціль зникла з радарів", "ППО спрацювала"]. Максимум 5 тегів.
- source_reliability (string): Надійність каналу що знімає загрозу. "official", "high", "medium", "low".
- time_of_day_category (string): Час доби зняття. "night", "dawn", "day", "dusk".

ТЕЛЕМЕТРИЧНЕ ЗБАГАЧЕННЯ (Telemetry Enrichment):
Для КОЖНОГО повідомлення з загрозою (threat_level != "none") ти ОБОВ'ЯЗКОВО маєш додати блок "telemetry" з максимально точними оцінками на основі контексту повідомлення. Це критично важливо для аналітики та предиктивного моделювання.

Параметри телеметрії:
- group_id (string): Унікальний ID хвилі/атаки. Генеруй у форматі "{threat_type}_{vector}_{дата}_{waveN}". Наприклад: "shahed_south_2026-07-07_wave1". Якщо кілька повідомлень стосуються тієї самої хвилі — використовуй ОДНАКОВИЙ group_id.
- attack_vector (string): Напрямок атаки. Одне з: "south_to_north", "east_to_west", "north_to_south", "west_to_east", "southeast_to_northwest", "northeast_to_southwest", "crimea_inland", "sea_to_coast", "border_shelling", "unknown".
- target_count (int|null): Кількість виявлених цілей (БПЛА, ракет, тощо). Якщо у повідомленні є число — використовуй його. Якщо "група" — ставь 3-5. Якщо одна ціль — 1. Якщо невідомо — null.
- speed_kmh (int|null): Оцінка швидкості в км/год на основі типу: shahed=150-180, cruise_missile=800-900, ballistic=2000-7000, mig31k=2500, kab=300. null якщо неможливо оцінити.
- altitude_category (string): "low" (БПЛА <500м), "medium" (крилаті ракети 50-100м), "high" (балістика, стратегічна авіація >10000м), "unknown".
- heading_degrees (int|null): Курс у градусах (0=північ, 90=схід, 180=південь, 270=захід). Оціни за напрямком руху з повідомлення. null якщо невідомо.
- distance_to_target_km (float|null): Оцінка відстані до найближчого великого міста цільового регіону. null якщо неможливо оцінити.
- launch_origin (string|null): Звідки пуск/запуск. Наприклад: "Чорне море", "Каспійське море", "окупований Крим", "Бєлгородська обл. РФ", "Курська обл. РФ", "Азовське море", null якщо невідомо.
- weapon_subtype (string|null): Конкретна модифікація зброї. Наприклад: "Shahed-136", "Shahed-131", "Х-101", "Х-555", "Калібр", "Іскандер-М", "Іскандер-К", "Кинджал", "КАБ-500", "КАБ-1500", "С-300", null.
- engagement_status (string): Статус залучення цілі. Одне з: "launched" (щойно пуск), "approaching" (наближається), "in_transit" (в транзиті через область), "overhead" (безпосередньо над областю), "intercepted" (перехоплено ППО), "impact" (влучання/прильот), "missed" (промах), "lost" (ціль втрачена), "unknown".
- air_defense_active (bool): true якщо повідомляється про роботу ППО. false за замовчуванням.
- multiple_waves (bool): true якщо повідомлення згадує кілька хвиль або серій пусків.
- wave_number (int): Номер хвилі в поточній атаці. За замовчуванням 1.
- time_of_day_category (string): Визнач за часом повідомлення. "night" (22:00-05:59), "dawn" (06:00-08:59), "day" (09:00-17:59), "dusk" (18:00-21:59).
- source_reliability (string): Надійність каналу-джерела. "official" (kpszsu), "high" (monitorwarr, operativnoZSU), "medium" (eRadarrua, vanek_nikolaev), "low" (невідомі).
- message_context_tags (list[string]): Ключові контекстні маркери з повідомлення. Наприклад: ["околиці міста", "група БПЛА", "курс на захід", "робота ППО", "зміна курсу"]. Максимум 5 тегів.
- strategic_priority (string|null): Що може бути потенційною ціллю. "energy" (енергетична інфраструктура), "military" (військові об'єкти), "industrial" (промисловість), "civilian" (житлові райони), "port" (порт/логістика), "airfield" (аеродром), "unknown", null.
- civilian_risk_level (string): Рівень ризику для цивільного населення. "low", "moderate", "elevated", "high", "critical". Оцінюй за близькістю до великих міст та населених пунктів.
- event_phase (string): Фаза події. "launch" (момент пуску), "cruise" (маршовий політ), "transit" (транзит через область), "terminal" (фінальний етап наближення), "impact" (влучання), "aftermath" (наслідки), "intercept" (перехоплення), "all_clear" (відбій).
- correlation_group (string): Більш широка група для кореляції сесій. Наприклад: "shahed_night_session_2026-07-07", "massive_missile_strike_2026-07-07", "border_shelling_zaporizhzhia". Використовуй для зв'язування повідомлень з різних каналів про одну й ту саму атаку.
- final_target_cities (list[string]): Список міст, які явно вказані як ціль у тексті (напр., ["Старокостянтинів", "Київ"]). Якщо ціль не вказана - порожній список [].

ВИМОГИ ДО ФОРМАТУ (Strict JSON Array):
Ти повинен повернути ТІЛЬКИ JSON масив без markdown обгорток.
Кожен об'єкт має структуру:

ДЛЯ АКТИВНИХ ЗАГРОЗ (is_clear: false):
{
  "source_channel": "назва каналу",
  "text": "оригінальний текст",
  "threat_level": "none" | "low" | "medium" | "high" | "critical",
  "threat_type": "shahed" | "ballistic" | "mig31k" | "kab" | "cruise_missile" | null,
  "source_regions": ["Сумська область"],
  "target_regions": [{"name": "Київська область", "is_predictive": false}, {"name": "Чернігівська область", "is_predictive": true}],
  "is_clear": false,
  "confidence_score": 85,
  "eta": "~20-40 хв",
  "telemetry": {
    "group_id": "shahed_south_2026-07-07_wave1",
    "attack_vector": "south_to_north",
    "target_count": 3,
    "speed_kmh": 165,
    "altitude_category": "low",
    "heading_degrees": 340,
    "distance_to_target_km": 120.0,
    "launch_origin": "окупований Крим",
    "weapon_subtype": "Shahed-136",
    "engagement_status": "in_transit",
    "air_defense_active": false,
    "multiple_waves": false,
    "wave_number": 1,
    "time_of_day_category": "night",
    "source_reliability": "high",
    "message_context_tags": ["група БПЛА", "напрямок на захід"],
    "strategic_priority": "energy",
    "civilian_risk_level": "elevated",
    "event_phase": "cruise",
    "correlation_group": "shahed_night_session_2026-07-07",
    "final_target_cities": []
  }
}

ДЛЯ ЗНЯТТЯ ЗАГРОЗ (is_clear: true):
{
  "source_channel": "назва каналу",
  "text": "оригінальний текст",
  "threat_level": "none",
  "threat_type": "shahed",
  "source_regions": [],
  "target_regions": [{"name": "Київська область", "is_predictive": false}],
  "is_clear": true,
  "confidence_score": 90,
  "clearing_telemetry": {
    "linked_group_id": "shahed_south_2026-07-07_wave1",
    "linked_correlation_group": "shahed_night_session_2026-07-07",
    "resolution_type": "intercepted",
    "intercepted_count": 2,
    "total_targets_in_wave": 3,
    "impact_confirmed": false,
    "damage_assessment": "none",
    "civilian_casualties_reported": false,
    "infrastructure_hit": null,
    "air_defense_effectiveness": "high",
    "threat_duration_assessment": "medium",
    "prediction_accuracy_hint": "confirmed",
    "clearing_context_tags": ["відбій", "всі збиті"],
    "source_reliability": "official",
    "time_of_day_category": "night"
  }
}

Якщо повідомлень кілька, поверни масив з результатами для кожного повідомлення.
ОБОВ'ЯЗКОВО повертай:
- confidence_score, eta та telemetry для КОЖНОГО результату з threat_level != "none" та is_clear == false.
- confidence_score та clearing_telemetry для КОЖНОГО результату з is_clear == true.
Для повідомлень з threat_level == "none" та is_clear == false, блоки telemetry/clearing_telemetry не обов'язкові.
"""

    def build_rules_context(self) -> str:
        """Load learned rules from DB and format them as context for Gemini prompt."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rule_type, rule_text, evidence_count, accuracy_score
                FROM gemini_rules
                WHERE is_active = 1 AND evidence_count >= 2
                ORDER BY evidence_count DESC, accuracy_score DESC
                LIMIT 20
            ''')
            rules = cursor.fetchall()
            conn.close()
            
            if not rules:
                return ""
            
            context = "\nНАБУТІ ЗНАННЯ (Правила з бази досвіду — враховуй при аналізі):\n"
            for i, rule in enumerate(rules, 1):
                rule_type_label = {
                    "route_pattern": "Маршрут",
                    "confidence_correction": "Корекція довіри",
                    "time_pattern": "Часовий патерн",
                    "false_positive": "Хибний позитив",
                    "weapon_profile": "Профіль зброї"
                }.get(rule["rule_type"], rule["rule_type"])
                
                context += f"{i}. [{rule_type_label}] {rule['rule_text']} (доказів: {rule['evidence_count']}, точність: {rule['accuracy_score']:.0%})\n"
            
            return context
        except Exception as e:
            print(f"⚠️ Помилка завантаження правил: {e}")
            return ""

    def load_confidence_corrections(self) -> Dict[str, Dict[str, int]]:
        """Load confidence correction rules for the predictive engine.
        Returns dict: {region: {threat_type: correction_value}}"""
        corrections = {}
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT target_region, threat_type, rule_json
                FROM gemini_rules
                WHERE rule_type = 'confidence_correction' AND is_active = 1
                    AND evidence_count >= 3
            ''')
            
            for row in cursor.fetchall():
                try:
                    data = json.loads(row["rule_json"])
                    region = row["target_region"]
                    threat_type = row["threat_type"]
                    correction = data.get("correction", 0)
                    if region not in corrections:
                        corrections[region] = {}
                    corrections[region][threat_type] = correction
                except (json.JSONDecodeError, TypeError):
                    pass
            
            conn.close()
        except Exception:
            pass
        return corrections

    async def analyze_batch(self, messages: List[Dict[str, str]], context_messages: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        if not messages:
            return []
            
        if not self.is_configured:
            # Fallback/Mock behavior if no API key is provided
            print("⚠️ Gemini in MOCK mode: Returning empty analysis.")
            return []

        prompt = self.system_prompt + "\n\n"
        
        # Inject learned rules
        rules_ctx = self.build_rules_context()
        if rules_ctx:
            prompt += rules_ctx + "\n"
        
        if context_messages:
            prompt += "ПОПЕРЕДНІЙ КОНТЕКСТ (Для розуміння траєкторії, не для аналізу нових загроз):\n"
            for msg in context_messages:
                prompt += f"Канал: {msg['channel']}\nТекст: {msg['text']}\n---\n"

        prompt += "ОСЬ НОВІ ПОВІДОМЛЕННЯ ДЛЯ АНАЛІЗУ:\n"
        for msg in messages:
            prompt += f"Канал: {msg['channel']}\nТекст: {msg['text']}\n---\n"

        try:
            response = await self.model.generate_content_async(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    response_mime_type="application/json",
                )
            )
            
            result_text = response.text
            if result_text.startswith("```json"):
                result_text = result_text.split("```json", 1)[1]
            if result_text.endswith("```"):
                result_text = result_text.rsplit("```", 1)[0]
                
            self.last_error = None
            results = json.loads(result_text.strip())
            
            # Normalize telemetry for each result
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict):
                        if item.get("is_clear", False):
                            # Normalize clearing telemetry
                            item["clearing_telemetry"] = self.normalize_clearing_telemetry(item.get("clearing_telemetry"))
                        elif item.get("threat_level", "none") != "none":
                            # Normalize threat telemetry
                            item["telemetry"] = self.normalize_telemetry(item.get("telemetry"))
            
            # Log rules injection info
            if rules_ctx:
                rules_count = rules_ctx.count("\n") - 1
                print(f"🧠 [Gemini] Аналіз з {rules_count} правилами самонавчання")
            
            return results
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Gemini API Error: {error_msg}")
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower():
                self.last_error = "Rate Limit Exceeded (429)"
            else:
                self.last_error = error_msg
            return []

    @staticmethod
    def normalize_telemetry(telemetry: dict = None) -> dict:
        """Normalize and validate telemetry block, filling defaults for missing fields."""
        defaults = {
            "group_id": None,
            "attack_vector": "unknown",
            "target_count": None,
            "speed_kmh": None,
            "altitude_category": "unknown",
            "heading_degrees": None,
            "distance_to_target_km": None,
            "launch_origin": None,
            "weapon_subtype": None,
            "engagement_status": "unknown",
            "air_defense_active": False,
            "multiple_waves": False,
            "wave_number": 1,
            "time_of_day_category": "unknown",
            "weather_factor": "unknown",
            "source_reliability": "medium",
            "message_context_tags": [],
            "strategic_priority": None,
            "civilian_risk_level": "moderate",
            "event_phase": "unknown",
            "correlation_group": None,
            "final_target_cities": [],
        }
        
        if not telemetry or not isinstance(telemetry, dict):
            return defaults.copy()
        
        normalized = defaults.copy()
        
        # Valid enum values for validation
        valid_vectors = {"south_to_north", "east_to_west", "north_to_south", "west_to_east",
                         "southeast_to_northwest", "northeast_to_southwest", "crimea_inland",
                         "sea_to_coast", "border_shelling", "unknown"}
        valid_altitudes = {"low", "medium", "high", "unknown"}
        valid_engagement = {"launched", "approaching", "in_transit", "overhead", "intercepted",
                           "impact", "missed", "lost", "unknown"}
        valid_time_cat = {"night", "dawn", "day", "dusk", "unknown"}
        valid_reliability = {"official", "high", "medium", "low"}
        valid_priority = {"energy", "military", "industrial", "civilian", "port", "airfield", "unknown", None}
        valid_risk = {"low", "moderate", "elevated", "high", "critical"}
        valid_phase = {"launch", "cruise", "transit", "terminal", "impact", "aftermath", "intercept", "all_clear", "unknown"}
        
        for key, default in defaults.items():
            val = telemetry.get(key, default)
            
            # Type coercion and validation
            if key == "target_count" and val is not None:
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = None
            elif key == "speed_kmh" and val is not None:
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = None
            elif key == "heading_degrees" and val is not None:
                try:
                    val = int(val) % 360
                except (ValueError, TypeError):
                    val = None
            elif key == "distance_to_target_km" and val is not None:
                try:
                    val = float(val)
                except (ValueError, TypeError):
                    val = None
            elif key == "wave_number":
                try:
                    val = max(1, int(val))
                except (ValueError, TypeError):
                    val = 1
            elif key in ("air_defense_active", "multiple_waves"):
                val = bool(val)
            elif key == "message_context_tags":
                if not isinstance(val, list):
                    val = []
                val = [str(t) for t in val[:5]]  # Max 5 tags
            elif key == "attack_vector":
                val = val if val in valid_vectors else "unknown"
            elif key == "altitude_category":
                val = val if val in valid_altitudes else "unknown"
            elif key == "engagement_status":
                val = val if val in valid_engagement else "unknown"
            elif key == "time_of_day_category":
                val = val if val in valid_time_cat else "unknown"
            elif key == "source_reliability":
                val = val if val in valid_reliability else "medium"
            elif key == "strategic_priority":
                val = val if val in valid_priority else None
            elif key == "civilian_risk_level":
                val = val if val in valid_risk else "moderate"
            elif key == "event_phase":
                val = val if val in valid_phase else "unknown"
            elif key == "final_target_cities":
                if not isinstance(val, list):
                    val = []
                val = [str(c) for c in val]
            
            normalized[key] = val
        
        return normalized

    @staticmethod
    def normalize_clearing_telemetry(clearing_telemetry: dict = None) -> dict:
        """Normalize and validate clearing telemetry block, filling defaults for missing fields."""
        defaults = {
            "linked_group_id": None,
            "linked_correlation_group": None,
            "resolution_type": "unknown",
            "intercepted_count": None,
            "total_targets_in_wave": None,
            "impact_confirmed": False,
            "damage_assessment": "unknown",
            "civilian_casualties_reported": False,
            "infrastructure_hit": None,
            "air_defense_effectiveness": "unknown",
            "threat_duration_assessment": "unknown",
            "prediction_accuracy_hint": "not_applicable",
            "clearing_context_tags": [],
            "source_reliability": "medium",
            "time_of_day_category": "unknown",
        }
        
        if not clearing_telemetry or not isinstance(clearing_telemetry, dict):
            return defaults.copy()
        
        normalized = defaults.copy()
        
        # Valid enum values
        valid_resolution = {"intercepted", "passed_through", "impact", "lost_contact",
                           "diverted", "false_alarm", "all_clear_official", "expired", "unknown"}
        valid_damage = {"none", "minor", "moderate", "severe", "catastrophic", "unknown"}
        valid_infra = {"energy", "military", "residential", "industrial", "transport", "medical", "none", None}
        valid_ad_eff = {"excellent", "high", "medium", "low", "none", "unknown"}
        valid_duration = {"very_short", "short", "medium", "long", "unknown"}
        valid_pred_acc = {"confirmed", "partially_confirmed", "overestimated",
                         "underestimated", "not_applicable", "unknown"}
        valid_reliability = {"official", "high", "medium", "low"}
        valid_time_cat = {"night", "dawn", "day", "dusk", "unknown"}
        
        for key, default in defaults.items():
            val = clearing_telemetry.get(key, default)
            
            # Type coercion and validation
            if key == "intercepted_count" and val is not None:
                try:
                    val = max(0, int(val))
                except (ValueError, TypeError):
                    val = None
            elif key == "total_targets_in_wave" and val is not None:
                try:
                    val = max(0, int(val))
                except (ValueError, TypeError):
                    val = None
            elif key in ("impact_confirmed", "civilian_casualties_reported"):
                val = bool(val)
            elif key == "clearing_context_tags":
                if not isinstance(val, list):
                    val = []
                val = [str(t) for t in val[:5]]
            elif key == "resolution_type":
                val = val if val in valid_resolution else "unknown"
            elif key == "damage_assessment":
                val = val if val in valid_damage else "unknown"
            elif key == "infrastructure_hit":
                val = val if val in valid_infra else None
            elif key == "air_defense_effectiveness":
                val = val if val in valid_ad_eff else "unknown"
            elif key == "threat_duration_assessment":
                val = val if val in valid_duration else "unknown"
            elif key == "prediction_accuracy_hint":
                val = val if val in valid_pred_acc else "unknown"
            elif key == "source_reliability":
                val = val if val in valid_reliability else "medium"
            elif key == "time_of_day_category":
                val = val if val in valid_time_cat else "unknown"
            
            normalized[key] = val
        
        return normalized
