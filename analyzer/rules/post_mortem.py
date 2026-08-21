"""
Autonomous Gemini Post-Mortem Reflection Engine.
Analyzes completed attack waves, evaluates prediction accuracy vs reality,
and autonomously synthesizes new or updated empirical rules into SQLite.
"""

import json
import sqlite3
import asyncio
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable
import google.generativeai as genai

from core.config import DB_PATH, logger
from database.db_helpers import get_sqlite_connection
from analyzer.prompts import SYSTEM_PROMPT


POST_MORTEM_SYSTEM_PROMPT = """Ти — головний тактичний офіцер та аналітик протиповітряної оборони SirenUA.
Твоє завдання: провести глибокий самоаналіз (Post-Mortem Reflection) щойно завершеної атаки/сесії повітряних загроз.

На вхід ти отримуєш:
1. Хронологію сесії (повідомлення, початкові прогнози ШІ, реальний статус тривог, час дольоту).
2. Результати відбоїв (типи завершення: intercepted/збито, impact/влучання, out_of_airspace/вийшов, overestimated/хибна тривога).

Твоя мета:
1. Оцінити точність роботи системи: де прогноз спрацював ідеально, а де трапилася помилка або переоцінка загрози.
2. Виявити нові тактичні патерни ворога (маневри, зміна висот, нові коридори транзиту).
3. Сформулювати від 1 до 3 чітких емпіричних правил для бази знань системи самонавчання.

Виведи відповідь ВИКЛЮЧНО у форматі JSON без жодного зайвого тексту чи markdown-форматування:
{
  "session_accuracy_score": 0.85,
  "tactical_assessment": "Стислий опис сесії та оцінка дій ворога українською мовою",
  "anomalies_detected": ["Список виявлених відхилень або нової тактики"],
  "derived_rules": [
    {
      "rule_type": "route_pattern | launch_site_pattern | aviation_strike_pattern | confidence_correction | time_pattern | eta_math",
      "source_region": "Назва області або району пуску",
      "target_region": "Назва цільової області",
      "threat_type": "shahed | reactive_uav | cruise_missile | ballistic | kab | mig31k",
      "rule_text": "Чітке формулювання правила українською мовою",
      "confidence_score": 0.88,
      "reason": "Чому це правило сформульовано на основі цієї сесії"
    }
  ]
}
"""


class GeminiPostMortemAnalyzer:
    """Performs autonomous post-mortem tactical reflection after threat sessions clear."""

    def __init__(self, db_path: str = DB_PATH, rule_audit_callback: Optional[Callable] = None):
        self.db_path = db_path
        self._rule_audit_callback = rule_audit_callback

    def fetch_recent_session_data(self, hours: int = 4, limit: int = 50) -> Dict[str, Any]:
        """Fetch recently cleared paired events and threat clearings for analysis."""
        conn = get_sqlite_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Cleared paired events
        cursor.execute("""
            SELECT 
                pe.id, pe.created_at, pe.region, pe.threat_level, pe.threat_type,
                pe.confidence_at_set, pe.confidence_at_clear, pe.was_predictive,
                pe.prediction_accuracy, pe.duration_seconds, pe.gemini_group_id,
                tc.resolution_type, tc.air_defense_effectiveness, tc.threat_duration_assessment,
                tc.clearing_message_text, tc.clearing_source_channel
            FROM paired_events pe
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.lifecycle_status = 'cleared'
              AND pe.created_at >= datetime('now', ?)
            ORDER BY pe.id DESC
            LIMIT ?
        """, (f"-{hours} hours", limit))
        paired_rows = [dict(r) for r in cursor.fetchall()]

        # Recent error logs during the session
        cursor.execute("""
            SELECT source, error_type, message, timestamp
            FROM error_log
            WHERE timestamp >= datetime('now', ?)
            ORDER BY id DESC
            LIMIT 10
        """, (f"-{hours} hours",))
        error_rows = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return {
            "session_window_hours": hours,
            "total_cleared_events": len(paired_rows),
            "paired_events": paired_rows,
            "session_errors": error_rows,
        }

    async def run_post_mortem(self, hours: int = 4, custom_model=None) -> Dict[str, Any]:
        """Execute autonomous Gemini post-mortem reflection and save derived rules."""
        session_data = self.fetch_recent_session_data(hours=hours)
        if session_data["total_cleared_events"] < 2:
            logger.info("ℹ️ [Post-Mortem] Недостатньо завершених подій для аналізу сесії (менше 2).")
            return {"status": "skipped", "reason": "insufficient_cleared_events"}

        logger.info(f"🧠 [Post-Mortem] Початок ШІ-рефлексії для {session_data['total_cleared_events']} завершених подій...")

        prompt = f"""
Проаналізуй наступні завершені події останньої бойової сесії:
{json.dumps(session_data, ensure_ascii=False, indent=2)}
"""
        model = custom_model
        if model is None:
            import os
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEYS", "").split(",")[0].strip()
            if not api_key:
                logger.warning("⚠️ [Post-Mortem] Відсутній GEMINI_API_KEY для виконання рефлексії.")
                return {"status": "skipped", "reason": "no_api_key"}
            genai.configure(api_key=api_key)
            model_name = os.environ.get("GEMINI_MODEL", "gemini-flash-lite-latest")
            model = genai.GenerativeModel(model_name=model_name, system_instruction=POST_MORTEM_SYSTEM_PROMPT)

        try:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(None, lambda: model.generate_content(prompt))
            resp_text = response.text.strip()
            
            # Clean JSON markdown fences
            if resp_text.startswith("```"):
                lines = resp_text.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                resp_text = "\n".join(lines).strip()

            analysis_result = json.loads(resp_text)
            saved_rules = self.save_derived_rules(analysis_result.get("derived_rules", []))
            
            logger.info(
                f"✅ [Post-Mortem] Рефлексія успішна! Точність сесії: {analysis_result.get('session_accuracy_score', 0)*100:.0f}%, "
                f"Збережено/оновлено правил: {len(saved_rules)}"
            )

            return {
                "status": "success",
                "session_accuracy_score": analysis_result.get("session_accuracy_score"),
                "tactical_assessment": analysis_result.get("tactical_assessment"),
                "anomalies_detected": analysis_result.get("anomalies_detected", []),
                "saved_rules_count": len(saved_rules),
                "rules": saved_rules
            }

        except Exception as e:
            logger.error(f"❌ [Post-Mortem Error] Помилка під час ШІ-рефлексії: {e}")
            from database.analytics_db import log_error_to_db
            log_error_to_db("gemini_post_mortem", str(e), endpoint="run_post_mortem", error_type="gemini_api_error")
            return {"status": "error", "error": str(e)}

    def save_derived_rules(self, derived_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Insert or update derived rules into gemini_rules and log to gemini_rules_audit."""
        if not derived_rules:
            return []

        conn = get_sqlite_connection(self.db_path)
        cursor = conn.cursor()
        saved = []

        for r in derived_rules:
            rule_type = r.get("rule_type", "route_pattern")
            source_region = r.get("source_region")
            target_region = r.get("target_region")
            threat_type = r.get("threat_type")
            rule_text = r.get("rule_text", "")
            confidence = float(r.get("confidence_score", 0.85))
            reason = r.get("reason", "ШІ-рефлексія після завершення атаки")

            rule_json = json.dumps({
                "source": source_region,
                "target": target_region,
                "type": threat_type,
                "accuracy": confidence,
                "source_mechanism": "gemini_post_mortem"
            }, ensure_ascii=False)

            # Check if matching rule already exists
            cursor.execute("""
                SELECT id, evidence_count, accuracy_score FROM gemini_rules
                WHERE rule_type = ? AND source_region = ? AND target_region = ? AND threat_type = ?
            """, (rule_type, source_region, target_region, threat_type))
            existing = cursor.fetchone()

            if existing:
                new_evidence = existing[1] + 1
                new_accuracy = round((existing[2] * existing[1] + confidence) / new_evidence, 2)
                cursor.execute("""
                    UPDATE gemini_rules
                    SET rule_text = ?, rule_json = ?, evidence_count = ?, accuracy_score = ?,
                        is_active = 1, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (rule_text, rule_json, new_evidence, new_accuracy, existing[0]))
                action = "updated"
            else:
                cursor.execute("""
                    INSERT INTO gemini_rules (
                        rule_type, source_region, target_region, threat_type,
                        rule_text, rule_json, evidence_count, accuracy_score, is_active, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1, CURRENT_TIMESTAMP)
                """, (rule_type, source_region, target_region, threat_type, rule_text, rule_json, confidence))
                action = "added"

            # Log to gemini_rules_audit
            cursor.execute("""
                INSERT INTO gemini_rules_audit (
                    action, rule_type, rule_text, source_region, target_region, threat_type, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (action, rule_type, rule_text, source_region, target_region, threat_type, f"[Post-Mortem] {reason}"))

            if self._rule_audit_callback:
                try:
                    self._rule_audit_callback(action, rule_type=rule_type, rule_text=rule_text,
                                              source_region=source_region, target_region=target_region,
                                              threat_type=threat_type, reason=f"[Post-Mortem] {reason}")
                except Exception:
                    pass

            saved.append({
                "action": action,
                "rule_type": rule_type,
                "rule_text": rule_text,
                "source_region": source_region,
                "target_region": target_region,
                "threat_type": threat_type,
                "accuracy": confidence
            })

        conn.commit()
        conn.close()
        return saved
