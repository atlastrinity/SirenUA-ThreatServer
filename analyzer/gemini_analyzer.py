import sqlite3
import os
import json
import google.generativeai as genai
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from database.db_helpers import get_sqlite_connection

class GeminiThreatAnalyzer:
    def __init__(self, error_callback=None, rule_audit_callback=None):
        # Configure Gemini
        keys_str = os.environ.get("GEMINI_API_KEYS", "")
        if keys_str:
            self.api_keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        else:
            single_key = os.environ.get("GEMINI_API_KEY", "")
            self.api_keys = [single_key] if single_key else []
            
        self.model_name = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
        self.current_key_idx = 0
        
        if self.api_keys:
            genai.configure(api_key=self.api_keys[self.current_key_idx])
            self.model = genai.GenerativeModel(self.model_name)
            self.is_configured = True
            self.last_error = None
            print(f"🧠 GeminiAnalyzer configured with {len(self.api_keys)} keys, using model: {self.model_name}")
        else:
            self.is_configured = False
            self.last_error = "API key missing"
            print("⚠️ GEMINI_API_KEYS is not set. GeminiAnalyzer will run in mock mode.")

        self.db_path = "threat_analytics.db"
        self._error_callback = error_callback
        self._rule_audit_callback = rule_audit_callback
        self.system_prompt = """You are a specialized military AI threat analyst (SirenUA Threat Intelligence System).
Your task: deeply analyze batches of messages from Ukrainian Telegram channels and produce a JSON array with detected threats AND full telemetry data.

=== CRITICAL RULE #1: OUTPUT LANGUAGE ===
ALL text fields in your JSON output (including "text", descriptions, ETA, context tags) MUST be EXCLUSIVELY in Ukrainian language.
If the input message is in Russian or any other language, you MUST translate it to clean, grammatically correct Ukrainian.

=== CRITICAL RULE #2: ACTIVE THREATS vs INFORMATIONAL MESSAGES ===
You MUST strictly distinguish between these categories. Getting this wrong causes false alarms for millions of users.

✅ ACTIVE THREAT (set threat_level > "none", is_clear: false):
- Messages about missiles/drones CURRENTLY IN FLIGHT ("БПЛА в напрямку...", "ракета курсом на...")
- Launch reports ("пуск балістики з...", "зліт МіГ-31К")
- Real-time tracking updates ("група шахедів входить в...", "крилата ракета над...")
- Air defense engagement DURING an active attack ("робота ППО по цілі")
- Official air raid warnings about CURRENT threats from KPSZSU

❌ INFORMATIONAL / AFTERMATH — MUST return threat_level: "none":
- Casualty reports ("постраждалих", "загиблих", "поранених", "травмованих")
- Official statements about CONSEQUENCES ("Кличко повідомив", "ОВА повідомляє", "за попередніми даними")
- Past-tense attack descriptions ("атакували", "було зафіксовано", "влучання було", "завдали удару")
- Summary/retrospective reports ("протягом дня", "за минулу добу", "раніше", "зранку ворог")
- Infrastructure damage reports WITHOUT ongoing flight data ("зруйновано", "пошкоджено", "влучання в будинок")
- Humanitarian updates ("евакуація", "відключення електроенергії внаслідок удару")
- Political/military commentary without active threat data

KEY DISTINCTION: "Вибухи в Харкові" during an active missile attack = ACTIVE THREAT (impact phase).
But "В Харкові зафіксовано влучання, 5 постраждалих" as a standalone aftermath report = INFORMATIONAL (threat_level: "none").
If the message describes events that ALREADY HAPPENED (past tense) and there is NO indication of ongoing threat, it is INFORMATIONAL.

For informational messages, still return a JSON object but with:
- threat_level: "none"
- is_clear: false
- confidence_score: 0
- No telemetry block needed
- text field should contain the Ukrainian translation of the message

=== ANALYSIS METHODOLOGY FOR TARGET REGIONS ===
Apply four types of analysis to determine target_regions and is_predictive flags:

1. **Transit Geography**: If a target flies from one oblast to another, add intermediate transit oblasts to target_regions with is_predictive: true.

2. **Strategic Target Profiling**: For cruise missiles (Tu-95MS, Tu-22M3, Kalibr from Black Sea), mark major historical strike targets (Kyivska, Lvivska, Kharkivska, Dnipropetrovska, Odeska, Khmelnytska) as is_predictive: true with medium confidence (50-65%) during early launch phase.

3. **Border Proximity Risk**: If tactical aviation (Su-34/Su-35) takes off near borders or S-300/S-400 launchers are reported in Russian border oblasts, automatically mark border/frontline oblasts (Sumska, Kharkivska, Chernihivska, Zaporizka, Khersonska, Donetska) as is_predictive: true with threat_type "kab" or "ballistic".

4. **Ballistic Kinematics**: For ballistic launches (Iskander from Crimea/Belgorod), flight time is critically short (2-5 min). Automatically mark all oblasts within launch sector range as is_predictive: true or false (if explicitly mentioned).

=== CONFIDENCE SCORING — CRITICAL RULES ===
FORBIDDEN: Assigning identical confidence_score to more than 2 oblasts in the same analysis. Each oblast MUST have an INDIVIDUAL score based on:

- 93-100%: Official KPSZSU confirmation with exact coordinates, heading, specific city name.
- 85-92%: Reliable radar channel (monitorwarr) with specific region, direction, and target type.
- 75-84%: Reliable source without exact coordinates but with direction specified.
- 65-74%: Predictive region (is_predictive: true) DIRECTLY on the flight path (adjacent oblast).
- 55-64%: Predictive region 2 oblasts away from threat source.
- 45-54%: Strategic profiling — potential target at large distance without direct evidence.
- 35-44%: Weak signals, unconfirmed information.
- <35%: Rumors, irrelevant information. Set threat_level: "none".

PREDICTIVE REGION CONFIDENCE DIFFERENTIATION:
- Region directly on flight path (1 oblast from source): confidence = 65-74%
- Region 2 oblasts away: confidence = 55-64%
- Region 3+ oblasts away or strategic target: confidence = 45-54%
- You MUST decrease confidence proportionally with distance from threat source.

=== THREAT TYPES AND EXPECTED ETA ===
- shahed (UAV/drone): "~1-3 год" (speed ~150-180 km/h)
- cruise_missile (Kh-101/Kalibr): "~15-40 хв" (speed ~800-900 km/h)
- ballistic (ballistic missile): "~2-5 хв" (speed ~4500-7000 km/h)
- mig31k (Kinzhal): "~20-40 хв" (speed ~2500 km/h)
- kab (guided aerial bomb): "~5-15 хв" (speed ~300 km/h)
- tu95 (strategic bomber takeoff/threat): "~30-90 хв" (speed ~800 km/h)
- iskander (Iskander-M ballistic missile): "~2-5 хв" (speed ~4500-7000 km/h)
- artillery (artillery shelling/MLRS): "~0-5 хв" (speed ~1000-2500 km/h)


=== THREAT CONFIRMATION AND CLEARING ===
- If a message reports explosions, impacts, or air defense engagement in a specific oblast DURING an active attack, mark it as an active threat (is_clear: false) with appropriate level (high or critical).
- If a message reports the threat has passed, target was shot down, lost on radar, or area is clear ("ціль зникла", "чисто", "усі збиті", "відбій"), set is_clear: true for the relevant oblasts.

=== CLEARING TELEMETRY ===
When a message clears a threat (is_clear: true), you MUST add a "clearing_telemetry" block. This is critical for:
1. Validating predictive (yellow) regions — was the threat prediction correct.
2. Evaluating air defense effectiveness.
3. Building experience database for future prediction improvement.

clearing_telemetry parameters:
- linked_group_id (string|null): group_id of the original wave/attack being cleared. Reconstruct from context or generate in same format. Example: "shahed_south_2026-07-07_wave1". null only if impossible to determine.
- linked_correlation_group (string|null): correlation_group of the original attack session.
- resolution_type (string): One of: "intercepted", "passed_through", "impact", "lost_contact", "diverted", "false_alarm", "all_clear_official", "expired", "unknown".
- intercepted_count (int|null): Number of targets intercepted by air defense. null if unknown.
- total_targets_in_wave (int|null): Total targets in the wave. null if unknown.
- impact_confirmed (bool): true if message confirms impact/strike. false by default.
- damage_assessment (string): "none", "minor", "moderate", "severe", "catastrophic", "unknown".
- civilian_casualties_reported (bool): true if civilian casualties reported. false by default.
- infrastructure_hit (string|null): "energy", "military", "residential", "industrial", "transport", "medical", "none", null.
- air_defense_effectiveness (string): "excellent" (>90%), "high" (70-90%), "medium" (40-70%), "low" (<40%), "none", "unknown".
- threat_duration_assessment (string): "very_short" (<15min), "short" (15-60min), "medium" (1-3h), "long" (>3h), "unknown".
- prediction_accuracy_hint (string): For PREDICTIVE regions — was the threat real for this oblast: "confirmed", "partially_confirmed", "overestimated", "underestimated", "not_applicable", "unknown".
- clearing_context_tags (list[string]): Key markers. Max 5 tags. In Ukrainian.
- source_reliability (string): "official", "high", "medium", "low".
- time_of_day_category (string): "night", "dawn", "day", "dusk".

=== TELEMETRY ENRICHMENT ===
For EVERY message with a threat (threat_level != "none"), you MUST add a "telemetry" block with maximum precision estimates.

Telemetry parameters:
- group_id (string): Unique wave/attack ID. Format: "{threat_type}_{vector}_{date}_{waveN}". Use SAME group_id for messages about the same wave.
- attack_vector (string): One of: "south_to_north", "east_to_west", "north_to_south", "west_to_east", "southeast_to_northwest", "northeast_to_southwest", "crimea_inland", "sea_to_coast", "border_shelling", "unknown".
- target_count (int|null): Number of detected targets. If "група" → 3-5. If single → 1. null if unknown.
- speed_kmh (int|null): Estimated speed: shahed=150-180, cruise_missile=800-900, ballistic=4500-7000, mig31k=2500, kab=300, tu95=800, iskander=4500-7000, artillery=1000-2500. null if impossible to estimate.
- altitude_category (string): "low" (UAV <500m), "medium" (cruise 50-100m), "high" (ballistic/strategic >10000m), "unknown".
- heading_degrees (int|null): Heading in degrees (0=north, 90=east, 180=south, 270=west). null if unknown.
- distance_to_target_km (float|null): Estimated distance to nearest major city. null if impossible.
- launch_origin (string|null): Launch location. Examples: "Чорне море", "Каспійське море", "окупований Крим", "Бєлгородська обл. РФ". null if unknown.
- weapon_subtype (string|null): Specific weapon variant. Examples: "Shahed-136", "Х-101", "Калібр", "Іскандер-М", "Кинджал", "КАБ-500". null if unknown.
- engagement_status (string): "launched", "approaching", "in_transit", "overhead", "intercepted", "impact", "missed", "lost", "unknown".
- air_defense_active (bool): true if air defense engagement reported. false by default.
- multiple_waves (bool): true if multiple waves mentioned.
- wave_number (int): Wave number. Default 1.
- time_of_day_category (string): "night" (22:00-05:59), "dawn" (06:00-08:59), "day" (09:00-17:59), "dusk" (18:00-21:59).
- source_reliability (string): "official" (kpszsu), "high" (monitorwarr, operativnoZSU), "medium" (eRadarrua, vanek_nikolaev), "low" (unknown).
- message_context_tags (list[string]): Key context markers in Ukrainian. Max 5 tags.
- strategic_priority (string|null): "energy", "military", "industrial", "civilian", "port", "airfield", "unknown", null.
- civilian_risk_level (string): "low", "moderate", "elevated", "high", "critical".
- event_phase (string): "launch", "cruise", "transit", "terminal", "impact", "aftermath", "intercept", "all_clear".
- correlation_group (string): Broader session grouping. Example: "shahed_night_session_2026-07-07".
- final_target_cities (list[string]): Cities explicitly named as targets in Ukrainian. Empty list if none.
- target_cities_coords (dict[string, list[float]]): Dict mapping each city named in final_target_cities to its [latitude, longitude] coordinates. You MUST use your general military and geographic knowledge of Ukraine to estimate these coordinates. Example: {"Умань": [48.7484, 30.2223]}. Empty dict if no cities.

=== OUTPUT FORMAT (Strict JSON Array) ===
Return ONLY a JSON array without markdown wrappers.

FOR ACTIVE THREATS (is_clear: false):
{
  "source_channel": "channel name",
  "text": "original text in Ukrainian",
  "threat_level": "none" | "low" | "medium" | "high" | "critical",
  "threat_type": "shahed" | "ballistic" | "mig31k" | "kab" | "cruise_missile" | "tu95" | "iskander" | "artillery" | null,
  "source_regions": ["Сумська область"],
  "target_regions": [{"name": "Київська область", "is_predictive": false}, {"name": "Чернігівська область", "is_predictive": true}],
  "is_clear": false,
  "confidence_score": 85,
  "eta": "~20-40 хв",
  "telemetry": { ... full telemetry block ... },
  "rules_applied": [1, 5]
}

FOR THREAT CLEARINGS (is_clear: true):
{
  "source_channel": "channel name",
  "text": "original text in Ukrainian",
  "threat_level": "none",
  "threat_type": "shahed",
  "source_regions": [],
  "target_regions": [{"name": "Київська область", "is_predictive": false}],
  "is_clear": true,
  "confidence_score": 90,
  "clearing_telemetry": { ... full clearing telemetry block ... },
  "rules_applied": []
}

FOR INFORMATIONAL MESSAGES (aftermath, news, retrospective):
{
  "source_channel": "channel name",
  "text": "original text in Ukrainian",
  "threat_level": "none",
  "threat_type": null,
  "source_regions": [],
  "target_regions": [],
  "is_clear": false,
  "confidence_score": 0,
  "rules_applied": []
}

If multiple messages, return an array with results for each message.
MANDATORY fields:
- For threat_level != "none" and is_clear == false: confidence_score, eta, telemetry, rules_applied.
- For is_clear == true: confidence_score, clearing_telemetry, rules_applied.
- For informational (threat_level == "none", is_clear == false): rules_applied as [].
"""





    def _handle_api_error(self, e: Exception, attempt: int, max_attempts: int, endpoint: str, context: str) -> bool:
        """
        Handles Gemini API errors, switches API keys on rate limits, and triggers error callback.
        Returns True if it switched keys and execution should retry.
        Returns False if it is a terminal failure.
        """
        error_msg = str(e)
        print(f"❌ Gemini API Error in {endpoint} (Attempt {attempt + 1}/{max_attempts}): {error_msg}")
        is_rate_limit = "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower()
        
        if is_rate_limit and len(self.api_keys) > 1:
            self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
            print(f"🔄 Перемикання на наступний API ключ (Індекс {self.current_key_idx})")
            genai.configure(api_key=self.api_keys[self.current_key_idx])
            self.model = genai.GenerativeModel(self.model_name)
            return True
            
        if is_rate_limit:
            self.last_error = "Rate Limit Exceeded (429)"
        else:
            self.last_error = error_msg
            
        if self._error_callback:
            self._error_callback("gemini", error_msg, endpoint=endpoint, context=context)
            
        return False

    def build_rules_context(self) -> str:
        """Load learned rules from DB and format them as context for Gemini prompt.
        Only feeds active rules with solid evidence (>= 3 events) and high accuracy (>= 60%)."""
        try:
            conn = get_sqlite_connection(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rule_type, rule_text, evidence_count, accuracy_score
                FROM gemini_rules
                WHERE is_active = 1 AND evidence_count >= 3 AND accuracy_score >= 0.60
                ORDER BY evidence_count DESC, accuracy_score DESC
                LIMIT 25
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
            conn = get_sqlite_connection(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT target_region, threat_type, rule_json
                FROM gemini_rules
                WHERE rule_type = 'confidence_correction' AND is_active = 1
                    AND evidence_count >= 3 AND accuracy_score >= 0.60
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

    def _decay_outdated_rules(self, cursor):
        """Applies rule decay: deactivates rules with low accuracy or stale timestamp."""
        # Rules with low accuracy get deactivated
        cursor.execute('''
            UPDATE gemini_rules 
            SET is_active = 0 
            WHERE is_active = 1 AND accuracy_score < 0.50
        ''')
        decayed_low_accuracy = cursor.rowcount
        
        # Rules that haven't been validated/updated in 14 days get deactivated
        cursor.execute('''
            UPDATE gemini_rules 
            SET is_active = 0 
            WHERE is_active = 1 AND datetime(updated_at) < datetime('now', '-14 days')
        ''')
        decayed_stale = cursor.rowcount
        
        if decayed_low_accuracy > 0 or decayed_stale > 0:
            print(f"📉 [Rule Decay] Деактивовано {decayed_low_accuracy} правил через низьку точність та {decayed_stale} через застарілість")
            if self._rule_audit_callback:
                if decayed_low_accuracy > 0:
                    self._rule_audit_callback("deactivated", reason=f"Low accuracy (<0.50): {decayed_low_accuracy} rules")
                if decayed_stale > 0:
                    self._rule_audit_callback("deactivated", reason=f"Stale (>14 days): {decayed_stale} rules")

    def _learn_route_patterns(self, cursor) -> int:
        """Derives route rules from historical paired events."""
        rules_updated = 0
        cursor.execute('''
            SELECT 
                pe1.region as source_region,
                pe2.region as target_region,
                pe1.threat_type,
                COUNT(*) as occurrence_count,
                AVG(CASE WHEN pe2.prediction_accuracy = 'confirmed' THEN 1.0 
                         WHEN pe2.prediction_accuracy = 'mitigated' THEN 0.8
                         WHEN pe2.prediction_accuracy = 'partially_confirmed' THEN 0.7
                         WHEN pe2.prediction_accuracy = 'overestimated' THEN 0.2
                         ELSE 0.5 END) as accuracy
            FROM paired_events pe1
            JOIN paired_events pe2 ON pe1.gemini_group_id = pe2.gemini_group_id
                AND pe1.region != pe2.region
                AND pe2.was_predictive = 1
                AND ABS(strftime('%s', pe1.created_at) - strftime('%s', pe2.created_at)) <= 10800
            WHERE pe1.lifecycle_status = 'cleared'
                AND pe1.was_predictive = 0
                AND pe1.created_at >= datetime('now', '-30 days')
            GROUP BY pe1.region, pe2.region, pe1.threat_type
            HAVING occurrence_count >= 5
        ''')
        
        for row in cursor.fetchall():
            rule_text = (f"Загрози типу {row['threat_type']} з {row['source_region']} "
                         f"мають {row['accuracy']*100:.0f}% шанс досягти {row['target_region']} "
                         f"(підтверджено {row['occurrence_count']} раз)")
            rule_json = json.dumps({
                "source": row["source_region"],
                "target": row["target_region"],
                "type": row["threat_type"],
                "accuracy": round(row["accuracy"], 2),
                "count": row["occurrence_count"]
            }, ensure_ascii=False)
            
            cursor.execute('''
                DELETE FROM gemini_rules 
                WHERE rule_type = 'route_pattern' 
                  AND source_region = ? AND target_region = ? AND threat_type = ?
            ''', (row["source_region"], row["target_region"], row["threat_type"]))
            
            cursor.execute('''
                INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type,
                    rule_text, rule_json, evidence_count, accuracy_score, is_active, updated_at)
                VALUES ('route_pattern', ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            ''', (row["source_region"], row["target_region"], row["threat_type"],
                  rule_text, rule_json, row["occurrence_count"], round(row["accuracy"], 2)))
            rules_updated += 1
            if self._rule_audit_callback:
                self._rule_audit_callback("added", rule_type="route_pattern", rule_text=rule_text,
                    source_region=row["source_region"], target_region=row["target_region"],
                    threat_type=row["threat_type"], reason=f"evidence={row['occurrence_count']}, accuracy={row['accuracy']:.2f}")
        return rules_updated

    def _learn_confidence_corrections(self, cursor) -> int:
        """Derives confidence correction rules based on prediction accuracy statistics."""
        rules_updated = 0
        cursor.execute('''
            SELECT 
                region,
                threat_type,
                COUNT(*) as total,
                SUM(CASE WHEN prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                SUM(CASE WHEN prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                AVG(confidence_at_set) as avg_confidence_set
            FROM paired_events
            WHERE was_predictive = 1 AND lifecycle_status = 'cleared'
                AND created_at >= datetime('now', '-30 days')
            GROUP BY region, threat_type
            HAVING total >= 7
        ''')
        
        for row in cursor.fetchall():
            total = row["total"]
            overest = row["overestimated"]
            conf = row["confirmed"]
            overest_rate = overest / total if total > 0 else 0
            confirm_rate = conf / total if total > 0 else 0
            
            if overest_rate > 0.6:
                correction = -15
                rule_text = (f"Для {row['region']} при {row['threat_type']} — знижувати confidence "
                            f"на 15% ({overest}/{total} = хибні позитиви)")
            elif confirm_rate > 0.7:
                correction = +10
                rule_text = (f"Для {row['region']} при {row['threat_type']} — підвищувати confidence "
                            f"на 10% ({conf}/{total} = підтверджених)")
            else:
                continue
            
            rule_json = json.dumps({
                "region": row["region"],
                "type": row["threat_type"],
                "correction": correction,
                "overestimated_rate": round(overest_rate, 2),
                "confirmed_rate": round(confirm_rate, 2)
            }, ensure_ascii=False)
            
            cursor.execute('''
                DELETE FROM gemini_rules 
                WHERE rule_type = 'confidence_correction' 
                  AND target_region = ? AND threat_type = ?
            ''', (row["region"], row["threat_type"]))
            
            cursor.execute('''
                INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type,
                    rule_text, rule_json, evidence_count, accuracy_score, is_active, updated_at)
                VALUES ('confidence_correction', NULL, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            ''', (row["region"], row["threat_type"], rule_text, rule_json,
                  total, round(1 - overest_rate, 2)))
            rules_updated += 1
            if self._rule_audit_callback:
                self._rule_audit_callback("added", rule_type="confidence_correction", rule_text=rule_text,
                    target_region=row["region"], threat_type=row["threat_type"],
                    reason=f"overest_rate={overest_rate:.2f}, confirm_rate={confirm_rate:.2f}")
        return rules_updated

    def _learn_time_patterns(self, cursor) -> int:
        """Derives time-of-day attack target rules from historical paired events."""
        rules_updated = 0
        cursor.execute('''
            SELECT 
                pe.created_at,
                pe.threat_type,
                pe.region
            FROM paired_events pe
            WHERE pe.lifecycle_status = 'cleared'
                AND pe.prediction_accuracy = 'confirmed'
                AND pe.created_at >= datetime('now', '-30 days')
        ''')
        
        from datetime import datetime
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
        raw_patterns = {}
        for row in cursor.fetchall():
            created_at_str = row["created_at"]
            if not created_at_str:
                continue
            try:
                dt_utc = datetime.fromisoformat(created_at_str.replace(' ', 'T') + "+00:00")
            except Exception:
                continue
            dt_kiev = dt_utc.astimezone(kiev_tz)
            hour = dt_kiev.hour
            key = (hour, row["threat_type"], row["region"])
            raw_patterns[key] = raw_patterns.get(key, 0) + 1
        
        time_patterns = {}
        for (hour, threat_type, region), count in raw_patterns.items():
            if count < 5:
                continue
            key = (hour, threat_type)
            if key not in time_patterns:
                time_patterns[key] = {"regions": [], "total": 0}
            time_patterns[key]["regions"].append({"region": region, "count": count})
            time_patterns[key]["total"] += count
        
        for (hour, threat_type), data in time_patterns.items():
            if data["total"] < 7:
                continue
            time_cat = "ніч" if hour < 6 or hour >= 22 else ("ранок" if hour < 9 else ("день" if hour < 18 else "вечір"))
            top_regions = sorted(data["regions"], key=lambda x: x["count"], reverse=True)[:5]
            regions_str = ", ".join([f"{r['region']} ({r['count']})" for r in top_regions])
            rule_text = f"Атаки {threat_type} о {hour}:00 ({time_cat}) найчастіше цілять: {regions_str}"
            rule_json = json.dumps({
                "hour": hour, "type": threat_type,
                "targets": top_regions, "total": data["total"]
            }, ensure_ascii=False)
            
            cursor.execute('''
                DELETE FROM gemini_rules 
                WHERE rule_type = 'time_pattern' AND threat_type = ? AND rule_text LIKE ?
            ''', (threat_type, f"%о {hour}:00%"))
            
            cursor.execute('''
                INSERT INTO gemini_rules (rule_type, threat_type,
                    rule_text, rule_json, evidence_count, accuracy_score, is_active, updated_at)
                VALUES ('time_pattern', ?, ?, ?, ?, 0.7, 1, CURRENT_TIMESTAMP)
            ''', (threat_type, rule_text, rule_json, data["total"]))
            rules_updated += 1
            if self._rule_audit_callback:
                self._rule_audit_callback("added", rule_type="time_pattern", rule_text=rule_text,
                    threat_type=threat_type, reason=f"total={data['total']}, hour={hour}")
        return rules_updated

    def run_rules_learner(self) -> int:
        """Central Rules Learner engine. Analyzes historical paired events,
        derives route/time/confidence rules, and performs rule decay (aging out old patterns)."""
        try:
            conn = get_sqlite_connection(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 1. Decay outdated rules
            self._decay_outdated_rules(cursor)
            
            # 2. Learn rule patterns
            rules_updated = 0
            rules_updated += self._learn_route_patterns(cursor)
            rules_updated += self._learn_confidence_corrections(cursor)
            rules_updated += self._learn_time_patterns(cursor)
            
            # 3. Clean up stale active paired events
            cursor.execute('''
                UPDATE paired_events SET lifecycle_status = 'expired'
                WHERE lifecycle_status = 'active'
                    AND created_at < datetime('now', '-24 hours')
            ''')
            
            conn.commit()
            conn.close()
            
            # Автоматично створюємо резервну копію у Firestore після навчання правил
            try:
                from mock_mode import backup_sqlite_to_firestore
                backup_sqlite_to_firestore()
            except Exception as backup_err:
                print(f"⚠️ [Backup] Не вдалося автоматично зберегти правила у Firestore: {backup_err}")
                
            return rules_updated
        except Exception as e:
            print(f"⚠️ [Rules Engine] Помилка навчання: {e}")
            if self._error_callback:
                self._error_callback("gemini", str(e), endpoint="run_rules_learner")
            return 0

    def _clean_and_parse_json(self, response_text: str) -> Any:
        """Cleans markdown JSON fences from response text and parses it."""
        result_text = response_text.strip()
        if result_text.startswith("```json"):
            result_text = result_text.split("```json", 1)[1]
        if result_text.endswith("```"):
            result_text = result_text.rsplit("```", 1)[0]
        return json.loads(result_text.strip())

    def _build_analysis_prompt(self, messages: List[Dict[str, str]], context_messages: List[Dict[str, str]] = None) -> Tuple[str, Optional[str]]:
        """Helper to construct the prompt with Kyiv timezone, rules, and message payloads."""
        from datetime import datetime
        try:
            import zoneinfo
            kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except ImportError:
            kyiv_tz = None
        current_time_kyiv = datetime.now(kyiv_tz).strftime("%Y-%m-%d %H:%M:%S")

        prompt = self.system_prompt + f"\n\nПОТОЧНИЙ КИЇВСЬКИЙ ЧАС: {current_time_kyiv}\n\n"
        
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
            
        return prompt, rules_ctx

    async def analyze_batch(self, messages: List[Dict[str, str]], context_messages: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        if not messages:
            return []
            
        if not self.is_configured:
            # Fallback/Mock behavior if no API key is provided
            print("⚠️ Gemini in MOCK mode: Returning empty analysis.")
            return []

        prompt, rules_ctx = self._build_analysis_prompt(messages, context_messages)

        max_attempts = len(self.api_keys) if self.api_keys else 1
        for attempt in range(max_attempts):
            try:
                response = await self.model.generate_content_async(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                    )
                )
                
                self.last_error = None
                results = self._clean_and_parse_json(response.text)
                
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
                    print(f"🧠 [Gemini] Аналіз з {rules_count} правилами самонавчання (Ключ {self.current_key_idx + 1}/{len(self.api_keys)})")
                
                return results
            except Exception as e:
                if self._handle_api_error(e, attempt, max_attempts, endpoint="analyze_batch", context=f"messages_count={len(messages)}"):
                    continue
                return []
        
        # If we exhausted all attempts
        self.last_error = "Rate Limit Exceeded across all available keys"
        if self._error_callback:
            self._error_callback("gemini", "All API keys rate limited", endpoint="analyze_batch", context=f"messages_count={len(messages)}")
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
            "target_cities_coords": {},
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
            elif key == "target_cities_coords":
                if not isinstance(val, dict):
                    val = {}
                else:
                    cleaned_coords = {}
                    for city, coords in val.items():
                        if isinstance(coords, list) and len(coords) == 2:
                            try:
                                cleaned_coords[str(city)] = [float(coords[0]), float(coords[1])]
                            except (ValueError, TypeError):
                                pass
                    val = cleaned_coords
            
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

    async def reevaluate_expired_threat(self, region: str, threat_type: str, set_time: str, recent_messages: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
            
        msgs_context = ""
        for msg in recent_messages:
            msgs_context += f"Канал: {msg['channel']}\nТекст: {msg['text']}\n---\n"
            
        prompt = f"""You are a military threat analyst for SirenUA.
An early warning (predictive threat) was declared for {region} (type: {threat_type}) at {set_time} (Kyiv time).
The estimated time of arrival (ETA) has passed, but the official state air raid siren has NOT been activated.

Your task is to analyze the recent Telegram messages below and determine:
1. Is the threat still active for {region}? (e.g., UAV is still flying in/towards the region, or active air defense is working right now).
2. If the threat is NOT active (neutralized, passed, or was a false alarm), determine the reason (resolution_type) and prediction accuracy.

=== CRITICAL EVALUATION RULES ===
- If the messages contain no mentions of {region} or any threats in its direction since {set_time}, and the official alarm never started, it is highly likely a "false_alarm" or "lost_contact".
- If the messages say that the targets were shot down ("збито"), intercepted, or destroyed in/near {region}, set resolution_type to "intercepted" and accuracy to "mitigated" (since air defense resolved it).
- If the messages say that targets passed through the region without impact, set resolution_type to "passed_through" and accuracy to "confirmed" (the threat was real but passed).
- If there is absolutely no info, no sirens, and no matches, set resolution_type to "expired" and accuracy to "overestimated" (since it was predicted but nothing materialized).

=== OUTPUT FORMAT ===
Return a JSON object with:
{{
  "is_active": true | false,
  "resolution_type": "intercepted" | "passed_through" | "impact" | "lost_contact" | "false_alarm" | "expired",
  "prediction_accuracy": "confirmed" | "mitigated" | "overestimated",
  "reasoning_ukr": "Brief explanation in Ukrainian why this decision was made."
}}

Here are the latest Telegram messages:
{msgs_context}
"""

        max_attempts = len(self.api_keys) if self.api_keys else 1
        for attempt in range(max_attempts):
            try:
                response = await self.model.generate_content_async(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                    )
                )
                
                self.last_error = None
                return self._clean_and_parse_json(response.text)
            except Exception as e:
                if self._handle_api_error(e, attempt, max_attempts, endpoint="reevaluate_expired_threat", context=f"region={region}"):
                    continue
                return None
        return None

