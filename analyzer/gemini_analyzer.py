import os
import json
import sqlite3
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from datetime import datetime

from analyzer.prompts import SYSTEM_PROMPT
from analyzer.sanitizer import parse_gemini_json

class GeminiThreatAnalyzer:
    def __init__(self, error_callback=None, rule_audit_callback=None):
        # Configure Gemini
        keys_str = os.environ.get("GEMINI_API_KEYS", "")
        if keys_str:
            self.api_keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        else:
            single_key = os.environ.get("GEMINI_API_KEY", "")
            self.api_keys = [single_key] if single_key else []
            
        self.model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
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
        self.system_prompt = SYSTEM_PROMPT


    def build_rules_context(self) -> str:
        """Load learned rules from DB and format them as context for Gemini prompt.
        Only feeds active rules with solid evidence (>= 3 events) and high accuracy (>= 60%)."""
        try:
            conn = sqlite3.connect(self.db_path)
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
            conn = sqlite3.connect(self.db_path)
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

    def run_rules_learner(self) -> int:
        """Central Rules Learner engine. Analyzes historical paired events,
        derives route/time/confidence/eta rules, and performs rule decay."""
        try:
            from analyzer.rules import GeminiRulesLearner
            learner = GeminiRulesLearner(db_path=self.db_path, rule_audit_callback=self._rule_audit_callback)
            total_learned = learner.run_rules_learner()
            
            # Автоматично створюємо резервну копію у Firestore після навчання правил
            try:
                from database.db_helpers import backup_sqlite_to_firestore
                backup_sqlite_to_firestore()
            except Exception as backup_err:
                print(f"⚠️ [Backup] Не вдалося автоматично зберегти правила у Firestore: {backup_err}")
                
            return total_learned
        except Exception as e:
            print(f"⚠️ [Rules Engine] Помилка навчання: {e}")
            if self._error_callback:
                self._error_callback("gemini", str(e), endpoint="run_rules_learner")
            return 0

    async def analyze_batch(self, messages: List[Dict[str, str]], context_messages: List[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        if not messages:
            return []
            
        if not self.is_configured:
            # Fallback/Mock behavior if no API key is provided
            print("⚠️ Gemini in MOCK mode: Returning empty analysis.")
            return []

        # Отримуємо поточний час у Києві для часового контексту Gemini
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

        max_attempts = len(self.api_keys) if self.api_keys else 1
        for attempt in range(max_attempts):
            try:
                response = await self.model.generate_content_async(
                    prompt,
                    generation_config=genai.types.GenerationConfig(
                        response_mime_type="application/json",
                    )
                )
                
                results = parse_gemini_json(response.text)
                if results is None:
                    raise ValueError("Failed to parse JSON response from Gemini API")
                self.last_error = None
                
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
                error_msg = str(e)
                print(f"❌ Gemini API Error (Attempt {attempt + 1}/{max_attempts}): {error_msg}")
                self.last_error = error_msg
                
                if len(self.api_keys) > 1 and attempt < max_attempts - 1:
                    # Switch key
                    self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
                    print(f"🔄 Перемикання на наступний API ключ (Індекс {self.current_key_idx})")
                    genai.configure(api_key=self.api_keys[self.current_key_idx])
                    self.model = genai.GenerativeModel(self.model_name)
                    # Continue to next attempt
                else:
                    # Log error via callback
                    if self._error_callback:
                        self._error_callback("gemini", error_msg, endpoint="analyze_batch", context=f"messages_count={len(messages)}")
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

    async def reevaluate_expired_threat(self, region: str, threat_type: str, set_time: str, recent_messages: List[Dict[str, Any]], is_official_alarm_active: bool = False) -> Optional[Dict[str, Any]]:
        if not self.is_configured:
            return None
            
        msgs_context = ""
        for msg in recent_messages:
            msgs_context += f"Канал: {msg['channel']}\nТекст: {msg['text']}\n---\n"
            
        alarm_status_str = "ACTIVE (ON)" if is_official_alarm_active else "INACTIVE (OFF)"
        prompt = f"""You are a military threat analyst for SirenUA.
An active or early-warning threat was registered for {region} (type: {threat_type}) at {set_time} (Kyiv time).
Current official state air raid siren status for {region}: {alarm_status_str}.

Your task is to analyze the recent Telegram messages below and determine:
1. Is the threat object still active in/approaching {region}? (e.g., UAV/missile is still flying in/towards the region, or active air defense is working right now).
2. If the official siren is INACTIVE (OFF) and the messages contain no active ongoing flight/strike reports for {region}, the threat object is OUTDATED / STALE and MUST be marked as inactive (is_active: false).
3. If the threat is NOT active (neutralized, passed, expired, or false alarm), determine the reason (resolution_type) and prediction accuracy.

=== CRITICAL EVALUATION RULES ===
- If official siren is OFF and messages contain no mentions of active targets in {region} since {set_time}, return is_active: false, resolution_type: "expired" or "false_alarm".
- If the messages say that the targets were shot down ("збито"), intercepted, or destroyed in/near {region}, set is_active: false, resolution_type: "intercepted" and accuracy: "mitigated".
- If the messages say that targets passed through the region without impact, set is_active: false, resolution_type: "passed_through" and accuracy: "confirmed".
- If there is no active flight info, no sirens, and no matches, set is_active: false, resolution_type: "expired" and accuracy: "overestimated".

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
                
                result_text = response.text
                if result_text.startswith("```json"):
                    result_text = result_text.split("```json", 1)[1]
                if result_text.endswith("```"):
                    result_text = result_text.rsplit("```", 1)[0]
                    
                self.last_error = None
                return json.loads(result_text.strip())
            except Exception as e:
                error_msg = str(e)
                print(f"❌ Gemini Re-evaluation API Error (Attempt {attempt + 1}/{max_attempts}): {error_msg}")
                is_rate_limit = "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower()
                
                if is_rate_limit and len(self.api_keys) > 1:
                    self.current_key_idx = (self.current_key_idx + 1) % len(self.api_keys)
                    print(f"🔄 Перемикання на наступний API ключ (Індекс {self.current_key_idx})")
                    genai.configure(api_key=self.api_keys[self.current_key_idx])
                    self.model = genai.GenerativeModel(self.model_name)
                else:
                    if is_rate_limit:
                        self.last_error = "Rate Limit Exceeded (429)"
                    else:
                        self.last_error = error_msg
                    
                    if self._error_callback:
                        self._error_callback("gemini", error_msg, endpoint="reevaluate_expired_threat", context=f"region={region}")
                    return None
        return None

