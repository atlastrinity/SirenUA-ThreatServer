import asyncio
import os
import re
from typing import Optional
from telethon import TelegramClient, events
import aiohttp
from bs4 import BeautifulSoup
from mock_mode import ThreatState, ALL_REGIONS, THREAT_TYPES

# Target Telegram channels to monitor
TARGET_CHANNELS = [
    "kpszsu",            # Повітряні Сили ЗСУ
    "monitorwarr",       # Найшвидша аналітика радарів
    "vanek_nikolaev",    # Николаевский Ванек
    "eRadarrua",         # eРадар (ОСІНТ радари)
    "operativnoZSU"      # Оперативно ЗСУ
]

# Threat Keywords (Refined for >90% Siren Correlation)
CRITICAL_KEYWORDS = [
    r"масований\s*(ракетний\s*)?удар", 
    r"масований\s*обстріл", 
    r"комбінований\s*удар",
    r"крилаті\s*ракети\s*в\s*повітряному\s*просторі"
]

HIGH_KEYWORDS = [
    r"МіГ[-\s]?31", 
    r"Кинджал", 
    r"Ту[-\s]?95", 
    r"Ту[-\s]?22", 
    r"Ту[-\s]?160",
    r"стратегічн\w+\s*авіаці", 
    r"крилат\w+\s*ракет", 
    r"[ХX][-\s]?101",
    r"[ХX][-\s]?555", 
    r"Калібр", 
    r"Іскандер", 
    r"балісти",            # Matches "балістика", "балістичний", "балістики" (99% chance of siren)
    r"пуски?\s*ракет",
    r"ракета\s*(в\s*напрямку|на)",  # Missile heading directly towards a region
    r"керована\s*авіаційна\s*ракета",
    r"[ХX][-\s]?59",
    r"[ХX][-\s]?69"
]

MEDIUM_KEYWORDS = [
    r"[ШШ]ахед", 
    r"Shahed", 
    r"БПЛА", 
    r"безпілотни", 
    r"дрон", 
    r"БпЛА", 
    r"мопед",
    r"ударн\w+\s*бпла"
]

LOW_KEYWORDS = [
    r"зліт\s*(тактичної|су|міг-29)", 
    r"підйом\s*авіаці", 
    r"активність\s*авіаці", 
    r"загроза\s*застосування\s*каб",
    r"пусти\s*каб",
    r"каб\s*в\s*напрямку"
]

CLEAR_KEYWORDS = [
    r"відбій", 
    r"загроз\w*\s*нема", 
    r"загроз\w*\s*відсутн", 
    r"збит[оіа]", 
    r"знищен[оіа]", 
    r"посадка", 
    r"чисто", 
    r"дорозвідка"
]

# API credentials
TELEGRAM_API_ID = 20294647
TELEGRAM_API_HASH = "454a9c055308a8d118608bb6b032bc30"

class TelegramThreatMonitor:
    def __init__(self, threat_manager):
        self.threat_manager = threat_manager
        self.is_running = False
        self.use_mtproto = False
        self.client: Optional[TelegramClient] = None
        self._clear_tasks = {}
        
        # Session file path detection
        self.session_paths = [
            "sirenua_userbot_session.session",
            "threat_server/sirenua_userbot_session.session"
        ]
        
        # State for web scraper fallback
        self.last_seen_posts = {channel: None for channel in TARGET_CHANNELS}

    async def start(self):
        self.is_running = True
        self._schedule_initial_auto_clears()
        
        # 1. Try to load from environment variable (StringSession) - best for Render production
        session_string = os.environ.get("TELEGRAM_SESSION_STRING")
        if session_string:
            print("🔥 Знайдено TELEGRAM_SESSION_STRING в змінних оточення. Ініціалізуємо MTProto...")
            try:
                from telethon.sessions import StringSession
                self.client = TelegramClient(StringSession(session_string), TELEGRAM_API_ID, TELEGRAM_API_HASH)
                await self.client.connect()
                if await self.client.is_user_authorized():
                    self.use_mtproto = True
                    print("✅ Юзербот авторизований через StringSession! Отримуємо повідомлення МИТТЄВО.")
                    self._setup_event_handlers()
                    return
                else:
                    print("⚠️ StringSession надано, але сесія не авторизована.")
            except Exception as e:
                print(f"⚠️ Помилка ініціалізації StringSession: {e}")
                if self.client:
                    await self.client.disconnect()

        # 2. Try to load from local file session (fallback)
        session_found = None
        for path in self.session_paths:
            if os.path.exists(path):
                session_found = path.replace(".session", "")
                break
                
        if session_found:
            print(f"🔥 Знайдено локальний файл сесії: {session_found}. Ініціалізуємо MTProto...")
            try:
                self.client = TelegramClient(session_found, TELEGRAM_API_ID, TELEGRAM_API_HASH)
                await self.client.connect()
                
                if await self.client.is_user_authorized():
                    self.use_mtproto = True
                    print("✅ Юзербот авторизований через локальний файл! Отримуємо повідомлення МИТТЄВО.")
                    self._setup_event_handlers()
                    return
                else:
                    print("⚠️ Файл сесії знайдено, але користувач не авторизований.")
            except Exception as e:
                print(f"⚠️ Помилка ініціалізації MTProto: {e}")
                if self.client:
                    await self.client.disconnect()
                    
        print("🟡 Сесію юзербота не знайдено або не авторизовано. Запускаємо резервний Web Scraper...")
        self.use_mtproto = False
        asyncio.create_task(self._scrape_loop())
        print(f"📥 Автоматичний веб-моніторинг (кожні 20 сек) активний для: {', '.join(TARGET_CHANNELS)}")

    def _setup_event_handlers(self):
        if not self.client:
            return
            
        @self.client.on(events.NewMessage(chats=TARGET_CHANNELS))
        async def handler(event):
            if not self.is_running:
                return
            text = event.message.text
            if text:
                try:
                    channel = event.chat.username or str(event.chat_id)
                except:
                    channel = "unknown"
                
                short_text = text.strip().replace('\n', ' ')[:80]
                print(f"⚡ [MTProto: {channel}] Нове повідомлення: \"{short_text}...\"")
                await self._process_message(text, channel)

    async def stop(self):
        self.is_running = False
        for task in self._clear_tasks.values():
            task.cancel()
        self._clear_tasks.clear()
        
        if self.client:
            await self.client.disconnect()
            
        print("🛑 Telegram Monitor зупинено.")

    # --- Web Scraper Fallback Loop ---
    async def _scrape_loop(self):
        async with aiohttp.ClientSession() as session:
            while self.is_running and not self.use_mtproto:
                for channel in TARGET_CHANNELS:
                    await self._scrape_channel(session, channel)
                await asyncio.sleep(20)

    async def _scrape_channel(self, session, channel):
        url = f"https://t.me/s/{channel}"
        try:
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                messages = soup.select('.tgme_widget_message')
                if not messages:
                    return
                
                is_first_run = self.last_seen_posts[channel] is None
                
                if is_first_run:
                    max_id = 0
                    for msg in messages:
                        post_id = msg.get('data-post')
                        if post_id:
                            try:
                                current_id = int(post_id.split('/')[-1])
                                if current_id > max_id:
                                    max_id = current_id
                                    self.last_seen_posts[channel] = post_id
                            except:
                                continue
                    print(f"📡 [{channel}] Первинний запуск веб-скрейпера. Базовий ID: {max_id}")
                    return

                last_id = 0
                if self.last_seen_posts[channel] is not None:
                    last_id = int(self.last_seen_posts[channel].split('/')[-1])

                for msg in messages:
                    post_id = msg.get('data-post')
                    if not post_id:
                        continue
                        
                    try:
                        current_id = int(post_id.split('/')[-1])
                        if current_id <= last_id:
                            continue
                        self.last_seen_posts[channel] = post_id
                    except:
                        continue

                    text_div = msg.select_one('.tgme_widget_message_text')
                    if text_div:
                        for br in text_div.find_all("br"):
                            br.replace_with("\n")
                        text = text_div.get_text()
                        
                        short_text = text.strip().replace('\n', ' ')[:80]
                        print(f"📖 [Web: {channel}] Нове повідомлення (ID: {current_id}): \"{short_text}...\"")
                        await self._process_message(text, channel)
        except Exception as e:
            pass

    # --- Message Parser Logic (Shared by both MTProto & Web Scraper) ---
    async def _process_message(self, text, channel):
        is_clear = any(re.search(kw, text, re.IGNORECASE) for kw in CLEAR_KEYWORDS)
        
        if is_clear:
            regions = self._extract_regions(text)
            if regions:
                for region in regions:
                    self.threat_manager.clear_threat(region)
                    if region in self._clear_tasks:
                        self._clear_tasks[region].cancel()
                print(f"🟢 [{channel}] Зняття загрози розпізнано для: {', '.join(regions)}")
            else:
                self.threat_manager.clear_all()
                print(f"🟢 [{channel}] Зняття загрози розпізнано для ВСІХ областей (відбій/чисто)")
            return

        level = self._detect_threat_level(text)
        if not level:
            print(f"💡 [{channel}] Повідомлення проігноровано (не містить ключових слів загроз)")
            return

        threat_type = self._detect_threat_type(text)
        regions = self._extract_regions(text)
        
        if not regions and level in ("critical", "high"):
            regions = list(ALL_REGIONS)
            print(f"🚨 [{channel}] Виявлено загальну небезпеку {level.upper()} для всієї України")
            
        if not regions:
            print(f"💡 [{channel}] Рівень {level.upper()} розпізнано, але не знайдено відповідних областей")
            return

        for region in regions:
            detail = self._build_region_detail(text, region, threat_type)
            self.threat_manager.set_threat(region, level, threat_type, detail)
            self._schedule_auto_clear(region)

        print(f"🔴 [{channel}] Рівень {level.upper()} встановлено для {len(regions)} областей: {', '.join(regions)}")

    def _build_region_detail(self, text: str, region: str, threat_type: str) -> str:
        prefix = THREAT_TYPES.get(threat_type, "Загроза")
        keywords = ALL_REGIONS.get(region, {}).get("keywords", [])
        
        text = re.sub(r' +', ' ', text).strip()
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        relevant_parts = []
        
        for line in lines:
            if any(re.search(kw, line, re.IGNORECASE) for kw in keywords):
                relevant_parts.append(line)
            else:
                sentences = re.split(r'(?<=[.!?])\s+', line)
                for sentence in sentences:
                    if any(re.search(kw, sentence, re.IGNORECASE) for kw in keywords):
                        relevant_parts.append(sentence)
                        
        if relevant_parts:
            unique_parts = []
            for part in relevant_parts:
                if part not in unique_parts:
                    unique_parts.append(part)
            content = " ".join(unique_parts)
            if len(content) > 160:
                content = content[:157] + "..."
            return f"{prefix}: {content}"
            
        cleaned_text = text.replace('\n', ' ')
        if len(cleaned_text) > 120:
            cleaned_text = cleaned_text[:117] + "..."
        return f"{prefix}: {cleaned_text}"

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
        if any(kw in text_lower for kw in ["міг-31", "міг31", "mig-31", "mig31", "кинджал"]):
            return "mig31k"
        if any(kw in text_lower for kw in ["ту-95", "ту95", "tu-95", "tu95", "ту-22", "ту22", "tu-22", "tu22"]):
            return "tu95"
        if any(kw in text_lower for kw in ["шахед", "shahed", "бпла", "дрон", "мопед"]):
            return "shahed"
        if any(kw in text_lower for kw in ["балісти", "іскандер"]):
            return "ballistic"
        if any(kw in text_lower for kw in ["ракет", "крилат", "калібр", "х-101"]):
            return "cruise_missile"
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

    def _schedule_auto_clear(self, region: str, delay_seconds: float = 3600):
        if region in self._clear_tasks:
            self._clear_tasks[region].cancel()
        
        async def auto_clear():
            await asyncio.sleep(delay_seconds)
            self.threat_manager.clear_threat(region)
            print(f"⏳ Автоматичне зняття загрози для {region} (таймаут {int(delay_seconds)} сек)")
            
        self._clear_tasks[region] = asyncio.create_task(auto_clear())

    def _schedule_initial_auto_clears(self):
        from datetime import datetime, timezone
        for region, state in self.threat_manager.threats.items():
            if state.level != "none" and state.since:
                try:
                    since_str = state.since.replace("Z", "+00:00")
                    since_dt = datetime.fromisoformat(since_str)
                    elapsed = (datetime.now(timezone.utc) - since_dt).total_seconds()
                    remaining = 3600 - elapsed
                    if remaining <= 0:
                        self.threat_manager.clear_threat(region)
                        print(f"⏳ Загроза для {region} застаріла під час офлайну. Очищено.")
                    else:
                        self._schedule_auto_clear(region, remaining)
                        print(f"⏳ Заплановано автозняття загрози для {region} через {int(remaining)} сек.")
                except Exception as e:
                    self._schedule_auto_clear(region, 3600)
