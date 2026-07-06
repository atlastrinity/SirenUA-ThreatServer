import asyncio
import re
import aiohttp
from bs4 import BeautifulSoup
from mock_mode import ThreatState, ALL_REGIONS, THREAT_TYPES

# Цільові канали для автоматичного прослуховування
TARGET_CHANNELS = [
    "kpszsu",            # Повітряні Сили ЗСУ
    "monitor",           # Найшвидша аналітика радарів
    "vanek_nikolaev"     # Николаевский Ванек
]

# Ключові слова загроз
CRITICAL_KEYWORDS = [r"масований\s*(ракетний\s*)?удар", r"масований\s*обстріл", r"комбінований\s*удар"]
HIGH_KEYWORDS = [
    r"МіГ[-\s]?31", r"Кинджал", r"Ту[-\s]?95", r"Ту[-\s]?22", r"Ту[-\s]?160",
    r"стратегічн\w+\s*авіаці", r"крилат\w+\s*ракет", r"[ХX][-\s]?101",
    r"[ХX][-\s]?555", r"Калібр", r"Іскандер", r"балістичн\w+", r"пуски?\s*ракет"
]
MEDIUM_KEYWORDS = [r"[ШШ]ахед", r"Shahed", r"БПЛА", r"безпілотни", r"дрон", r"БпЛА", r"мопед"]
LOW_KEYWORDS = [r"зліт", r"підйом\s*авіаці", r"активність\s*авіаці", r"загроза\s*балістики"]
CLEAR_KEYWORDS = [r"відбій", r"загроз\w*\s*нема", r"загроз\w*\s*відсутн", r"збит[оіа]", r"знищен[оіа]", r"посадка", r"чисто", r"дорозвідка"]

class TelegramThreatMonitor:
    def __init__(self, threat_manager):
        self.threat_manager = threat_manager
        self.is_running = False
        self._clear_tasks = {}
        # Зберігаємо ID останніх оброблених постів для кожного каналу
        self.last_seen_posts = {channel: None for channel in TARGET_CHANNELS}

    async def start(self):
        print("🌐 Запуск Web Scraper для Telegram каналів...")
        self.is_running = True
        # Запускаємо безкінечний цикл перевірки як фонове завдання
        asyncio.create_task(self._scrape_loop())
        print(f"📥 Автоматичний моніторинг (кожні 20 сек) активний для: {', '.join(TARGET_CHANNELS)}")

    async def stop(self):
        self.is_running = False
        print("🛑 Web Scraper зупинено.")

    async def _scrape_loop(self):
        async with aiohttp.ClientSession() as session:
            while self.is_running:
                for channel in TARGET_CHANNELS:
                    await self._scrape_channel(session, channel)
                # Чекаємо 20 секунд перед наступною перевіркою
                await asyncio.sleep(20)

    async def _scrape_channel(self, session, channel):
        url = f"https://t.me/s/{channel}"
        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Знаходимо всі текстові блоки повідомлень
                messages = soup.select('.tgme_widget_message')
                if not messages:
                    return
                
                # Беремо 3 останні повідомлення
                recent_messages = messages[-3:]
                
                for msg in recent_messages:
                    post_id = msg.get('data-post')
                    if not post_id:
                        continue
                        
                    # Якщо це перший запуск, просто запам'ятовуємо останній пост і не реагуємо на старі загрози
                    if self.last_seen_posts[channel] is None:
                        self.last_seen_posts[channel] = messages[-1].get('data-post')
                        return
                    
                    # Перевіряємо, чи пост новіший за останній оброблений (напр. "kpszsu/1234")
                    try:
                        current_id = int(post_id.split('/')[-1])
                        last_id = int(self.last_seen_posts[channel].split('/')[-1])
                        if current_id <= last_id:
                            continue
                        
                        # Оновлюємо останній оброблений ID
                        if current_id > last_id:
                            self.last_seen_posts[channel] = post_id
                    except:
                        continue

                    # Дістаємо текст
                    text_div = msg.select_one('.tgme_widget_message_text')
                    if text_div:
                        # Замінюємо <br> на нові рядки для зручності читання
                        for br in text_div.find_all("br"):
                            br.replace_with("\n")
                        text = text_div.get_text()
                        await self._process_message(text, channel)
        except Exception as e:
            # Ігноруємо помилки мережі, щоб не спамити в консоль
            pass

    async def _process_message(self, text, channel):
        # Перевірка на зняття загрози
        is_clear = any(re.search(kw, text, re.IGNORECASE) for kw in CLEAR_KEYWORDS)
        
        if is_clear:
            regions = self._extract_regions(text)
            if regions:
                for region in regions:
                    self.threat_manager.clear_threat(region)
                    if region in self._clear_tasks:
                        self._clear_tasks[region].cancel()
                print(f"✅ [{channel}] Загрозу знято для: {', '.join(regions)}")
            else:
                self.threat_manager.clear_all()
                print(f"✅ [{channel}] Всі загрози скасовано (відбій тривог/дорозвідка)")
            return

        level = self._detect_threat_level(text)
        if not level:
            return

        threat_type = self._detect_threat_type(text)
        regions = self._extract_regions(text)
        
        # Якщо загроза критична/висока і немає конкретних областей — це для всієї України
        if not regions and level in ("critical", "high"):
            regions = list(ALL_REGIONS)
            
        if not regions:
            return

        detail = f"{THREAT_TYPES.get(threat_type, 'Загроза')}: {text[:80]}..."
        for region in regions:
            self.threat_manager.set_threat(region, level, threat_type, detail)
            self._schedule_auto_clear(region)

        print(f"🔴 [{channel}] Рівень {level.upper()} встановлено для {len(regions)} областей.")

    def _detect_threat_level(self, text: str):
        if any(re.search(kw, text, re.IGNORECASE) for kw in CRITICAL_KEYWORDS):
            return "critical"
        if any(re.search(kw, text, re.IGNORECASE) for kw in HIGH_KEYWORDS):
            return "high"
        if any(re.search(kw, text, re.IGNORECASE) for kw in MEDIUM_KEYWORDS):
            return "medium"
        if any(re.search(kw, text, re.IGNORECASE) for kw in LOW_KEYWORDS):
            return "low"
        return None

    def _detect_threat_type(self, text: str):
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["шахед", "shahed", "бпла", "дрон", "мопед"]):
            return "drone"
        if any(kw in text_lower for kw in ["балісти", "іскандер", "кинджал"]):
            return "ballistic"
        if any(kw in text_lower for kw in ["ракета", "крилата", "калібр", "х-101"]):
            return "missile"
        if any(kw in text_lower for kw in ["міг", "ту-", "авіація"]):
            return "aviation"
        if any(kw in text_lower for kw in ["артилерія", "рсзв", "обстріл"]):
            return "artillery"
        return "unknown"

    def _extract_regions(self, text: str):
        found = set()
        for region, info in ALL_REGIONS.items():
            for kw in info["keywords"]:
                if re.search(kw, text, re.IGNORECASE):
                    found.add(region)
        return list(found)

    def _schedule_auto_clear(self, region: str):
        if region in self._clear_tasks:
            self._clear_tasks[region].cancel()
        
        async def auto_clear():
            await asyncio.sleep(3600)  # 1 година
            self.threat_manager.clear_threat(region)
            print(f"⏳ Автоматичне зняття загрози для {region} (таймаут 1 год)")
            
        self._clear_tasks[region] = asyncio.create_task(auto_clear())
