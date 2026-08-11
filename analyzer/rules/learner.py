"""
Autonomous Gemini Rules Learner Engine.
Analyzes historical paired events and derives active rules for route patterns, confidence corrections, time of day attacks, and flight ETA math.
"""

import json
import sqlite3
from typing import Optional, Callable
from database.db_helpers import get_sqlite_connection
from analyzer.rules.decay import apply_rule_decay


class GeminiRulesLearner:
    """Autonomous learner engine that creates and updates Gemini rules in SQLite."""

    def __init__(self, db_path: str = "threat_analytics.db", rule_audit_callback: Optional[Callable] = None):
        self.db_path = db_path
        self._rule_audit_callback = rule_audit_callback

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

    def _learn_eta_math_patterns(self, cursor) -> int:
        """Derives mathematical flight duration rules (eta_math) per threat object and region trajectory."""
        rules_updated = 0
        try:
            cursor.execute('''
                SELECT 
                    pe1.region as source_region,
                    pe2.region as target_region,
                    pe1.threat_type,
                    COUNT(*) as occurrence_count,
                    AVG(ABS(strftime('%s', pe2.created_at) - strftime('%s', pe1.created_at))) / 60.0 as avg_eta_minutes,
                    MIN(ABS(strftime('%s', pe2.created_at) - strftime('%s', pe1.created_at))) / 60.0 as min_eta_minutes,
                    MAX(ABS(strftime('%s', pe2.created_at) - strftime('%s', pe1.created_at))) / 60.0 as max_eta_minutes,
                    AVG(CASE WHEN pe2.prediction_accuracy IN ('confirmed', 'mitigated', 'partially_confirmed') THEN 1.0 ELSE 0.3 END) as accuracy
                FROM paired_events pe1
                JOIN paired_events pe2 ON pe1.gemini_group_id = pe2.gemini_group_id
                    AND pe1.region != pe2.region
                    AND pe2.was_predictive = 1
                    AND ABS(strftime('%s', pe1.created_at) - strftime('%s', pe2.created_at)) BETWEEN 60 AND 14400
                WHERE pe1.lifecycle_status = 'cleared'
                    AND pe1.created_at >= datetime('now', '-30 days')
                GROUP BY pe1.region, pe2.region, pe1.threat_type
                HAVING occurrence_count >= 3 AND accuracy >= 0.55
            ''')

            for row in cursor.fetchall():
                avg_min = max(1, int(round(row["avg_eta_minutes"])))
                min_min = max(1, int(round(row["min_eta_minutes"])))
                max_min = max(min_min, int(round(row["max_eta_minutes"])))
                threat_type = row["threat_type"]
                source = row["source_region"]
                target = row["target_region"]
                count = row["occurrence_count"]
                acc = round(row["accuracy"], 2)

                if avg_min < 60:
                    eta_str = f"~{avg_min} хв (діапазон {min_min}-{max_min} хв)"
                else:
                    h_val = round(avg_min / 60.0, 1)
                    eta_str = f"~{h_val} год"

                rule_text = (f"Математика дольоту [{threat_type}] з {source} до {target}: "
                             f"розрахований середній час {eta_str} (підтверджено {count} раз, точність {acc:.0%})")

                rule_json = json.dumps({
                    "source": source,
                    "target": target,
                    "threat_type": threat_type,
                    "avg_eta_minutes": avg_min,
                    "min_eta_minutes": min_min,
                    "max_eta_minutes": max_min,
                    "eta_str": eta_str,
                    "accuracy": acc,
                    "count": count
                }, ensure_ascii=False)

                cursor.execute('''
                    DELETE FROM gemini_rules 
                    WHERE rule_type = 'eta_math' 
                      AND source_region = ? AND target_region = ? AND threat_type = ?
                ''', (source, target, threat_type))

                cursor.execute('''
                    INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type,
                        rule_text, rule_json, evidence_count, accuracy_score, is_active, updated_at)
                    VALUES ('eta_math', ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                ''', (source, target, threat_type, rule_text, rule_json, count, acc))

                rules_updated += 1
                if self._rule_audit_callback:
                    self._rule_audit_callback("added", rule_type="eta_math", rule_text=rule_text,
                        source_region=source, target_region=target, threat_type=threat_type,
                        reason=f"avg_eta={avg_min}min, count={count}, accuracy={acc:.2f}")

        except Exception as e:
            print(f"⚠️ [Rules Learner] Помилка навчання математики дольоту: {e}")
        return rules_updated

    def run_rules_learner(self) -> int:
        """Central Rules Learner loop executed autonomously."""
        try:
            conn = get_sqlite_connection(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            apply_rule_decay(cursor, self._rule_audit_callback)
            r1 = self._learn_route_patterns(cursor)
            r2 = self._learn_confidence_corrections(cursor)
            r3 = self._learn_time_patterns(cursor)
            r4 = self._learn_eta_math_patterns(cursor)

            conn.commit()
            conn.close()

            total_learned = r1 + r2 + r3 + r4
            print(f"🧠 [Rules Learner] Навчання завершено: {total_learned} активних правил (маршрути: {r1}, confidence: {r2}, час: {r3}, ETA: {r4})")
            return total_learned
        except Exception as e:
            print(f"⚠️ [Rules Learner] Помилка виконання циклу навчання: {e}")
            return 0
