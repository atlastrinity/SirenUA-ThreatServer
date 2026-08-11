"""
Rule Decay Manager.
Handles automatic deactivation of outdated or inaccurate Gemini rules.
"""

from typing import Optional, Callable


def apply_rule_decay(cursor, audit_callback: Optional[Callable] = None) -> int:
    """
    Applies decay logic to gemini_rules:
    - Deactivates rules with accuracy_score < 0.50
    - Deactivates rules untouched for > 14 days
    """
    cursor.execute('''
        UPDATE gemini_rules
        SET is_active = 0
        WHERE is_active = 1 AND accuracy_score < 0.50
    ''')
    decayed_low_accuracy = cursor.rowcount

    cursor.execute('''
        UPDATE gemini_rules
        SET is_active = 0
        WHERE is_active = 1 AND datetime(updated_at) < datetime('now', '-14 days')
    ''')
    decayed_stale = cursor.rowcount

    total_decayed = decayed_low_accuracy + decayed_stale

    if total_decayed > 0:
        print(f"📉 [Rule Decay] Деактивовано {decayed_low_accuracy} правил через низьку точність та {decayed_stale} через застарілість")
        if audit_callback:
            if decayed_low_accuracy > 0:
                audit_callback("deactivated", reason=f"Low accuracy (<0.50): {decayed_low_accuracy} rules")
            if decayed_stale > 0:
                audit_callback("deactivated", reason=f"Stale (>14 days): {decayed_stale} rules")

    return total_decayed
