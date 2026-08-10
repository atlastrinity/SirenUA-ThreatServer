"""
Rules Evaluator & Learning Loop for SirenUA Threat Server.
Periodically analyzes paired threat events to derive and validate AI rules.
"""

import asyncio

async def run_rules_learner_loop(monitor_instance):
    """Background task that analyzes paired events every 6 hours to derive new rules."""
    # Wait 5 minutes before first run to let data accumulate
    await asyncio.sleep(300)
    
    while getattr(monitor_instance, "is_running", False):
        try:
            count = run_rules_learner(monitor_instance)
            if count > 0:
                print(f"🧠 [Rules Learner] Автонавчання завершено: {count} правил створено/оновлено")
        except Exception as e:
            print(f"⚠️ [Rules Learner] Помилка: {e}")
        
        # Sleep 6 hours
        await asyncio.sleep(6 * 3600)


def run_rules_learner(monitor_instance) -> int:
    """Analyze paired events and derive rules by delegating to analyzer's central engine."""
    analyzer = getattr(monitor_instance, "analyzer", None)
    if analyzer and hasattr(analyzer, 'run_rules_learner'):
        return analyzer.run_rules_learner()
    return 0
