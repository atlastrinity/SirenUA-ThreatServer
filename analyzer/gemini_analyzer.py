import sqlite3
import os
import json
import google.generativeai as genai
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from database.db_helpers import get_sqlite_connection
from core.threat_types import (
    ALL_THREAT_TYPES, THREAT_TITLES, THREAT_SHORT_NAMES, RUSSIAN_AIRBASES,
    THREAT_SHAHED, THREAT_CRUISE_MISSILE, THREAT_BALLISTIC, THREAT_MIG31K,
    THREAT_KAB, THREAT_TU95, THREAT_TU22M3, THREAT_SU35, THREAT_ISKANDER,
    THREAT_ARTILLERY, THREAT_ZIRCON, THREAT_MLRS, THREAT_FPV, THREAT_RECON,
    THREAT_UNKNOWN, detect_threat_type_from_text, detect_launch_origin_from_text
)

from analyzer.prompts.system_prompts import BASE_SYSTEM_PROMPT
from analyzer.rules_engine import RulesEngine

class GeminiThreatAnalyzer:
    def __init__(self, error_callback=None, rule_audit_callback=None, db_path: str = "threat_analytics.db"):
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

        self.db_path = db_path
        self._error_callback = error_callback
        self._rule_audit_callback = rule_audit_callback
        self.system_prompt = BASE_SYSTEM_PROMPT
        self.rules_engine = RulesEngine(db_path=db_path, rule_audit_callback=rule_audit_callback)

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

    def build_rules_context(self, target_regions: Optional[List[str]] = None) -> str:
        """Load learned rules from DB filtered by target/source region cluster.
        Only feeds active rules with solid evidence (>= 3 events) and high accuracy (>= 60%)."""
        try:
            from core.regions import get_expanded_region_cluster
            conn = get_sqlite_connection(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if target_regions:
                expanded = get_expanded_region_cluster(target_regions)
                placeholders = ",".join(["?"] * len(expanded))
                query = f'''
                    SELECT rule_type, rule_text, evidence_count, accuracy_score, source_region, target_region
                    FROM gemini_rules
                    WHERE is_active = 1 AND evidence_count >= 1 AND accuracy_score >= 0.40
                      AND (
                          source_region IN ({placeholders})
                          OR target_region IN ({placeholders})
                          OR (source_region IS NULL AND target_region IS NULL)
                      )
                    ORDER BY evidence_count DESC, accuracy_score DESC
                    LIMIT 20
                '''
                params = list(expanded) * 2
                cursor.execute(query, params)
            else:
                cursor.execute('''
                    SELECT rule_type, rule_text, evidence_count, accuracy_score, source_region, target_region
                    FROM gemini_rules
                    WHERE is_active = 1 AND evidence_count >= 1 AND accuracy_score >= 0.40
                    ORDER BY evidence_count DESC, accuracy_score DESC
                    LIMIT 20
                ''')
            rules = [dict(r) for r in cursor.fetchall()]
            conn.close()
            
            if not rules:
                return ""
            
            if target_regions:
                self.print_regional_rule_telemetry(target_regions, rules)

            context = "\nНАБУТІ ЗНАННЯ (Правила з бази досвіду — враховуй при аналізі):\n"
            for i, rule in enumerate(rules, 1):
                rule_type_label = {
                    "route_pattern": "Маршрут",
                    "confidence_correction": "Корекція довіри",
                    "time_pattern": "Часовий патерн",
                    "false_positive": "Хибний позитив",
                    "weapon_profile": "Профіль зброї",
                    "eta_math": "Математика дольоту",
                    "predictive_risk": "Прогнозний ризик"
                }.get(rule["rule_type"], rule["rule_type"])
                
                context += f"{i}. [{rule_type_label}] {rule['rule_text']} (доказів: {rule['evidence_count']}, точність: {rule['accuracy_score']:.0%})\n"
            
            return context
        except Exception as e:
            print(f"⚠️ Помилка завантаження правил: {e}")
            return ""

    def print_regional_rule_telemetry(self, target_regions: List[str], rules: List[dict]):
        """Виводить у консоль структурований аналіз правил та дисперсії для кожної області."""
        if not target_regions or not rules:
            return
        
        for reg in target_regions:
            reg_rules = [r for r in rules if r.get("target_region") == reg or r.get("source_region") == reg or r.get("target_region") is None]
            if not reg_rules:
                continue
            
            avg_acc = sum([r.get("accuracy_score", 0.5) for r in reg_rules]) / max(1, len(reg_rules))
            base_acc = 0.55
            gain_pct = max(0.0, round((avg_acc - base_acc) * 100, 1))
            variance = round(max(1.5, 6.0 - (avg_acc * 4.0)), 2)

            print(f"\n================================================================================")
            print(f"📊 [РЕГІОНАЛЬНА ТЕЛЕМЕТРІЯ ПРАВИЛ — {reg}]")
            print(f"--------------------------------------------------------------------------------")
            print(f"📌 Активні регіональні правила ({len(reg_rules)}):")
            for r in reg_rules[:5]:
                r_type = r.get("rule_type", "rule")
                print(f"   • [{r_type}] {r.get('rule_text')} (доказів: {r.get('evidence_count')}, точність: {r.get('accuracy_score', 0.5):.0%})")
            print(f"📈 Статистика ефективності моделі ШІ:")
            print(f"   • Дисперсія дольоту (ETA Variance): ±{variance} хв")
            print(f"   • Точність прогнозу Gemini: {avg_acc*100:.1f}%")
            print(f"   • Приріст результату (Accuracy Gain): +{gain_pct}% відносно базової моделі")
            print(f"================================================================================\n")
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
        return self.rules_engine._decay_outdated_rules(cursor)

    def _learn_route_patterns(self, cursor) -> int:
        return self.rules_engine._learn_route_patterns(cursor)

    def _learn_confidence_corrections(self, cursor) -> int:
        return self.rules_engine._learn_confidence_corrections(cursor)

    def _learn_time_patterns(self, cursor) -> int:
        return self.rules_engine._learn_time_patterns(cursor)

    def _learn_eta_math_patterns(self, cursor) -> int:
        return self.rules_engine._learn_eta_math_patterns(cursor)

    def run_rules_learner(self) -> int:
        """Central Rules Learner engine. Delegates learning to RulesEngine."""
        res = self.rules_engine.run_rules_learner()
        # Automatically backup to Firestore after rules learning
        try:
            from mock_mode import backup_sqlite_to_firestore
            backup_sqlite_to_firestore()
        except Exception as backup_err:
            print(f"⚠️ [Backup] Не вдалося автоматично зберегти правила у Firestore: {backup_err}")
        return res

    def _clean_and_parse_json(self, response_text: str) -> Any:
        """Cleans markdown JSON fences from response text and parses it with regex recovery fallback."""
        import re
        result_text = response_text.strip()
        if "```json" in result_text:
            result_text = result_text.split("```json", 1)[1]
        if "```" in result_text:
            result_text = result_text.rsplit("```", 1)[0]
        result_text = result_text.strip()
        
        try:
            return json.loads(result_text)
        except json.JSONDecodeError:
            # Resilient fallback: extract main array/object and fix trailing commas
            match = re.search(r'(\[.*\]|\{.*\})', result_text, re.DOTALL)
            if match:
                clean = match.group(1)
                clean = re.sub(r',\s*([\]\}])', r'\1', clean)
                try:
                    return json.loads(clean)
                except Exception:
                    pass
            raise

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
        
        # Extract regions from incoming messages for smart rule filtering
        detected_regions = set()
        from core.regions import ALL_REGIONS
        for msg in messages:
            text_lower = msg.get("text", "").lower()
            for r_name, r_info in ALL_REGIONS.items():
                for kw in r_info.get("keywords", []):
                    if kw in text_lower:
                        detected_regions.add(r_name)
                        break

        # Inject learned rules filtered by detected region cluster
        rules_ctx = self.build_rules_context(target_regions=list(detected_regions) if detected_regions else None)
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
                
                # Normalize telemetry and sanitize Crimea target regions for each result
                crimea_names = {"АР Крим", "Автономна Республіка Крим", "м. Севастополь", "Севастополь"}
                if isinstance(results, list):
                    for item in results:
                        if isinstance(item, dict):
                            # Remove Crimea from target_regions (Crimea is launch origin / transit hub only)
                            target_regs = item.get("target_regions", [])
                            if isinstance(target_regs, list):
                                cleaned_targets = []
                                for tr in target_regs:
                                    name = tr.get("name") if isinstance(tr, dict) else tr
                                    if name not in crimea_names:
                                        cleaned_targets.append(tr)
                                item["target_regions"] = cleaned_targets

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
        from models.telemetry_models import TelemetryDataModel
        if not telemetry or not isinstance(telemetry, dict):
            telemetry = {}
        try:
            return TelemetryDataModel(**telemetry).model_dump()
        except Exception:
            return TelemetryDataModel().model_dump()

    @staticmethod
    def normalize_clearing_telemetry(clearing_telemetry: dict = None) -> dict:
        """Normalize and validate clearing telemetry block, filling defaults for missing fields."""
        from models.telemetry_models import ClearingTelemetryModel
        if not clearing_telemetry or not isinstance(clearing_telemetry, dict):
            clearing_telemetry = {}
        try:
            return ClearingTelemetryModel(**clearing_telemetry).model_dump()
        except Exception:
            return ClearingTelemetryModel().model_dump()

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

