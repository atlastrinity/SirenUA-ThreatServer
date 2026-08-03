"""
Background monitor loop & auto-clear scheduler for Telegram Threat Monitor.
"""

import asyncio
from typing import Dict, Any, Optional, Callable


class ThreatScheduler:
    def __init__(self, threat_manager: Any, auto_clear_callback: Optional[Callable] = None):
        self.threat_manager = threat_manager
        self.auto_clear_callback = auto_clear_callback
        self.auto_clear_tasks: Dict[str, asyncio.Task] = {}

    def schedule_auto_clear(self, region: str, delay_seconds: int = 1800, threat_type: Optional[str] = None, group_id: Optional[str] = None):
        """Schedules auto-clearing of threats after delay_seconds if no new updates arrive."""
        if region in self.auto_clear_tasks:
            self.auto_clear_tasks[region].cancel()
            
        async def _auto_clear():
            await asyncio.sleep(delay_seconds)
            state = self.threat_manager.threats.get(region)
            if state and state.level != "none":
                print(f"⏱️ [AutoClear] Автоматичне зняття загрози за таймаутом ({delay_seconds//60}хв) для {region}")
                self.threat_manager.clear_threat(region)
                if self.auto_clear_callback:
                    self.auto_clear_callback(region, threat_type=threat_type, group_id=group_id)
                    
        self.auto_clear_tasks[region] = asyncio.create_task(_auto_clear())
