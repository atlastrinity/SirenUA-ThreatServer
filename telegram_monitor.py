import asyncio
import os
import re
import sys
from typing import Optional
from telethon import TelegramClient, events
import aiohttp
from bs4 import BeautifulSoup
from mock_mode import ThreatState, ALL_REGIONS, THREAT_TYPES, UKRAINE_TOPOLOGY, SHAHED_ROUTES
from gemini_analyzer import GeminiThreatAnalyzer

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

def get_genitive_region(region: str) -> str:
    mapping = {
        "Вінницька область": "Вінницької області",
        "Волинська область": "Волинської області",
        "Дніпропетровська область": "Дніпропетровської області",
        "Донецька область": "Донецької області",
        "Житомирська область": "Житомирської області",
        "Закарпатська область": "Закарпатської області",
        "Запорізька область": "Запорізької області",
        "Івано-Франківська область": "Івано-Франківської області",
        "Київська область": "Київської області",
        "м. Київ": "Києва",
        "Кіровоградська область": "Кіровоградської області",
        "Луганська область": "Луганської області",
        "Львівська область": "Львівської області",
        "Миколаївська область": "Миколаївської області",
        "Одеська область": "Одеської області",
        "Полтавська область": "Полтавської області",
        "Рівненська область": "Рівненської області",
        "Сумська область": "Сумської області",
        "Тернопільська область": "Тернопільської області",
        "Харківська область": "Харківської області",
        "Херсонська область": "Херсонської області",
        "Хмельницька область": "Хмельницької області",
        "Черкаська область": "Черкаської області",
        "Чернівецька область": "Чернівецької області",
        "Чернігівська область": "Чернігівської області",
        "АР Крим": "Криму",
    }
    return mapping.get(region, region)

def get_ukrainian_threat_type(threat_type: str) -> str:
    mapping = {
        "shahed": "БпЛА",
        "cruise_missile": "крилата ракета",
        "ballistic": "балістика",
        "mig31k": "МіГ-31К",
        "kab": "КАБ",
        "tu95": "Ту-95МС",
        "iskander": "Іскандер-М",
        "artillery": "обстріл",
    }
    return mapping.get(threat_type, threat_type)

def clean_user_facing_threat_detail(text: str) -> str:
    if not text:
        return ""
    # Remove any brackets like [AI], [Telegram], [kpszsu], etc.
    text = re.sub(r'\[[A-Za-z0-9_.\-\s]+\]', '', text)
    # Remove Telegram handles like @monitoring_channel
    text = re.sub(r'@[A-Za-z0-9_]+', '', text)
    # Remove URL links
    text = re.sub(r'https?://\S+', '', text)
    # Replace references to AI / ШІ with system
    text = re.sub(r'(?i)\bШІ\b', 'системи', text)
    text = re.sub(r'(?i)\bAI\b', 'системи', text)
    # Clean up double spaces or leading/trailing whitespace
    text = re.sub(r' +', ' ', text).strip()
    return text


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
    r"ракет[аи]\s*(в\s*напрямку|на)",  # Missile heading directly towards a region
    r"керована\s*авіаційна\s*ракета",
    r"[ХX][-\s]?59",
    r"[ХX][-\s]?69",
    r"\bукритт[яі]\b",
    r"\bтривог[аи]\b"
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
    r"каб\s*в\s*напрямку",
    r"\bкаб(и|ів)?\b",
    r"пуск\w*\s*каб[и]?",
    r"керован\w*\s*авіаційн\w*\s*бомб\w*"
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

CITY_COORDINATES = {
    "київ": (50.4501, 30.5234),
    "харків": (50.0000, 36.2300),
    "одеса": (46.4825, 30.7233),
    "дніпро": (48.4647, 35.0462),
    "львів": (49.8397, 24.0297),
    "запоріжжя": (47.8388, 35.1396),
    "кривий ріг": (47.9105, 33.3918),
    "миколаїв": (46.9750, 31.9946),
    "маріуполь": (47.0971, 37.5434),
    "луганськ": (48.5740, 39.3078),
    "вінниця": (49.2331, 28.4682),
    "херсон": (46.6354, 32.6169),
    "полтава": (49.5883, 34.5514),
    "чернігів": (51.4982, 31.2893),
    "черкаси": (49.4444, 32.0598),
    "суми": (50.9077, 34.7981),
    "житомир": (50.2547, 28.6587),
    "хмельницький": (49.4230, 26.9871),
    "рівне": (50.6199, 26.2516),
    "кропивницький": (48.5079, 32.2623),
    "кам'янське": (48.5140, 34.6148),
    "чернівці": (48.2908, 25.9345),
    "кременчук": (49.0630, 33.4038),
    "івано-франківськ": (48.9215, 24.7097),
    "тернопіль": (49.5535, 25.5948),
    "луцьк": (50.7472, 25.3254),
    "біла церква": (49.8020, 30.1154),
    "краматорськ": (48.7390, 37.5838),
    "ужгород": (48.6208, 22.2879),
    "бровари": (50.5112, 30.7900),
    "конотоп": (51.2407, 33.2040),
    "умань": (48.7484, 30.2223),
    "шостка": (51.8622, 33.4842),
    "старокостянтинів": (49.7547, 27.2206),
    "миргород": (49.9678, 33.6119),
    "шепетівка": (50.1808, 27.0658),
    "стрий": (49.2570, 23.8560),
    "коростень": (50.9542, 28.6367),
    "ковель": (51.2163, 24.6936),
    "коломия": (48.5284, 25.0396),
}

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
        
        from server import log_error_to_db, log_rule_audit_to_db
        self.analyzer = GeminiThreatAnalyzer(error_callback=log_error_to_db, rule_audit_callback=log_rule_audit_to_db)
        self.message_queue = asyncio.Queue()
        self.batch_task = None
        self.message_history = []
        
        # Session file path detection
        self.session_paths = [
            "sirenua_userbot_session.session",
            "threat_server/sirenua_userbot_session.session"
        ]
        
        # State for web scraper fallback
        self.last_seen_posts = {channel: None for channel in TARGET_CHANNELS}

    async def _join_target_channels(self):
        if not self.client:
            return
        for channel in TARGET_CHANNELS:
            try:
                from telethon.tl.functions.channels import JoinChannelRequest
                await self.client(JoinChannelRequest(channel))
                print(f"✅ Юзербот перевірив/підписався на канал: {channel}")
            except Exception as e:
                print(f"⚠️ Помилка підписки на {channel}: {e}")

    async def start(self):
        self.is_running = True
        self._schedule_initial_auto_clears()
        
        # Запускаємо фоновий процес батч-аналізу через Gemini
        self.batch_task = asyncio.create_task(self._batch_processor_loop())
        
        # Запускаємо фоновий таск самонавчання правил (кожні 6 годин)
        self._rules_learner_task = asyncio.create_task(self._rules_learner_loop())
        
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
                    await self._join_target_channels()
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
                    await self._join_target_channels()
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

    def _find_path(self, start_region: str, end_region: str) -> list[str]:
        """BFS algorithm to find the shortest path between two regions."""
        if start_region not in UKRAINE_TOPOLOGY or end_region not in UKRAINE_TOPOLOGY:
            return []
        
        queue = [[start_region]]
        visited = set([start_region])
        
        while queue:
            path = queue.pop(0)
            node = path[-1]
            
            if node == end_region:
                return path
                
            for adjacent in UKRAINE_TOPOLOGY.get(node, []):
                if adjacent not in visited:
                    visited.add(adjacent)
                    new_path = list(path)
                    new_path.append(adjacent)
                    queue.append(new_path)
        return []

    # --- Pre-filter: skip obviously non-threat messages before sending to Gemini ---
    _THREAT_KEYWORDS = {
        # Дрони / БПЛА
        "бпла", "бпла!", "шахед", "shahed", "дрон", "безпілотник", "мопед", "балалайк",
        "крило", "орлан", "supercam",
        # Ракети / Балістика
        "ракет", "пуск", "балістик", "балістич", "кинджал", "х-47", "х47м2",
        "міг-31", "міг31", "mig-31", "mig31", "калібр", "іскандер", "крилат",
        "х-101", "х-55", "х-555", "х-22", "х-32", "х-59", "х-69", "с-300", "с-400", "c300", "c400",
        # Авіація
        "су-34", "су-35", "су-30", "су-57", "сушки", "сушка", "су ",
        "ту-95", "ту-22", "ту-160", "ту95", "ту22", "ту160", "міг-29", "міг29", "mig-29", "mig29",
        "борт", "авіац", "зліт", "виліт", "посадка", "підйом", "активність",
        # Бомби / КАБи
        "каб", "кабами", "фаб", "уаб", "авіабомб",
        # Тривоги / Стан
        "тривог", "вибух", "ппо", "повітр", "курс", "напрямк", "загроз",
        "цілі", "ціль", "перехопл", "відбій", "відбої", "чисто", "збит", "зник",
        "відстежен", "маневру", "дорозвідка", "безпечно", "увага", "небезпека", "гучно",
        "приліт", "прильот", "обстріл", "артилерія", "рсзв", "град", "смерч", "ураган"
    }
    
    def _is_threat_relevant(self, text: str) -> bool:
        """Quick keyword check to filter out obviously informational messages."""
        text_lower = text.lower()
        for kw in self._THREAT_KEYWORDS:
            if kw in text_lower:
                return True
        return False

    # --- LLM Batching Loop ---
    async def _batch_processor_loop(self):
        """Фоновий процес, що збирає повідомлення та відправляє їх до Gemini раз на 30с."""
        while self.is_running:
            await asyncio.sleep(30) # Wait 30 seconds
            
            messages = []
            while not self.message_queue.empty():
                try:
                    msg = self.message_queue.get_nowait()
                    messages.append(msg)
                    self.message_history.append(msg)
                except asyncio.QueueEmpty:
                    break
                    
            if len(self.message_history) > 15:
                self.message_history = self.message_history[-15:]
                
            if messages:
                # Pre-filter: separate threat-relevant vs informational messages
                threat_messages = [m for m in messages if self._is_threat_relevant(m.get("text", ""))]
                skipped = len(messages) - len(threat_messages)
                
                if skipped > 0:
                    print(f"📋 [Pre-filter] Пропущено {skipped} інформаційних повідомлень (не відправлено до Gemini)")
                
                if not threat_messages:
                    print(f"📋 [Pre-filter] Всі {len(messages)} повідомлень — інформаційні. Gemini API не викликано.")
                    continue
                
                print(f"🧠 Відправка батчу ({len(threat_messages)} повідомлень) до Gemini API...")
                context_messages = [m for m in self.message_history if m not in threat_messages][-10:]
                results = await self.analyzer.analyze_batch(threat_messages, context_messages=context_messages)
                if results:
                    # Enable batch mode: skip individual Firestore saves during batch processing
                    self.threat_manager._batch_mode = True
                    try:
                        await self._apply_gemini_analysis(results)
                    finally:
                        self.threat_manager._batch_mode = False
                    # One atomic Firestore save for the entire batch
                    self.threat_manager._execute_save_to_db()
                    # Flush buffered Firestore history writes in one batch
                    from server import flush_history_batch
                    flush_history_batch()
                    # Flush buffered FCM notifications (sound only on first)
                    self.threat_manager.flush_fcm_batch()
                    print(f"💾 Атомарний запис у Firestore після батчу ({len(results)} результатів)")



    async def _apply_gemini_analysis(self, results, is_test: bool = False):
        """Applies Gemini AI analysis results with confidence-based filtering, level adjustment, and telemetry enrichment."""
        for item in results:
            if not isinstance(item, dict):
                continue
                
            level = item.get("threat_level", "none")
            threat_type = item.get("threat_type")
            is_clear = item.get("is_clear", False)
            source_channel = item.get("source_channel", "AI")
            text = item.get("text", "")
            confidence = item.get("confidence_score")
            telemetry = item.get("telemetry")  # Extract telemetry block
            rules_applied = item.get("rules_applied", [])
            
            # Validate confidence as int
            if confidence is not None:
                try:
                    confidence = int(confidence)
                except (ValueError, TypeError):
                    confidence = None
            
            # Обробка відбою з clearing_telemetry
            if is_clear:
                clearing_telemetry = item.get("clearing_telemetry", {})
                targets = item.get("target_regions", [])
                source_channel = item.get("source_channel", "AI")
                text = item.get("text", "")
                
                if not targets:
                    # Global clearing — all regions
                    self.threat_manager.clear_all()
                    # Log clearing for each previously active region
                    for r_name, r_state in self.threat_manager.threats.items():
                        if r_state.level != "none" or True:  # Log for all since we just cleared
                            from server import log_clearing_to_db
                            log_clearing_to_db(
                                region=r_name,
                                clearing_telemetry=clearing_telemetry,
                                source_channel=source_channel,
                                message_text=text,
                                clearing_confidence=confidence,
                                was_predictive=False
                            )
                    res_type = clearing_telemetry.get("resolution_type", "unknown") if clearing_telemetry else "unknown"
                    print(f"🟢 [Gemini] Зняття загрози для ВСІХ областей (тип: {res_type})")
                else:
                    for tgt in targets:
                        if isinstance(tgt, dict):
                            region = tgt.get("name")
                            was_pred = tgt.get("is_predictive", False)
                        else:
                            region = tgt
                            was_pred = False
                        
                        if not region:
                            continue
                        
                        # Log clearing BEFORE clearing the threat (to capture original state)
                        from server import log_clearing_to_db
                        log_clearing_to_db(
                            region=region,
                            clearing_telemetry=clearing_telemetry,
                            source_channel=source_channel,
                            message_text=text,
                            clearing_confidence=confidence,
                            was_predictive=was_pred
                        )
                        
                        self.threat_manager.clear_threat(region, clearing_telemetry=clearing_telemetry)
                        if region in self._clear_tasks:
                            self._clear_tasks[region].cancel()
                            del self._clear_tasks[region]
                        
                        # Enhanced clearing log
                        res_type = clearing_telemetry.get("resolution_type", "unknown") if clearing_telemetry else "unknown"
                        pred_str = ""
                        if was_pred and clearing_telemetry:
                            pred_hint = clearing_telemetry.get("prediction_accuracy_hint", "unknown")
                            pred_str = f" | предикція: {pred_hint}"
                        ad_eff = ""
                        if clearing_telemetry and clearing_telemetry.get("air_defense_effectiveness", "unknown") != "unknown":
                            ad_eff = f" | ППО: {clearing_telemetry['air_defense_effectiveness']}"
                        print(f"🟢 [Gemini] Зняття загрози: {region} (тип: {res_type}{pred_str}{ad_eff})")
                continue

            if level == "none":
                continue

            # Фільтрація за порогом довіри ШІ (мінімум 40%)
            if confidence is not None and confidence < 40:
                print(f"⚠️ [Gemini] Загроза відхилена (довіра {confidence}% < 40%): {text[:60]}...")
                continue
                
            # Коригування рівня загрози на основі довіри
            adjusted_level = level
            if confidence is not None:
                if confidence >= 85:
                    # Висока довіра — зберігаємо оригінальний рівень
                    adjusted_level = level
                elif confidence >= 60:
                    # Середня довіра — знижуємо на один рівень
                    level_downgrade = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
                    adjusted_level = level_downgrade.get(level, level)
                else:
                    # Низька довіра (40-59%) — встановлюємо low
                    adjusted_level = "low"
                    
                if adjusted_level != level:
                    print(f"📥 [Gemini] Рівень знижено {level} → {adjusted_level} (довіра {confidence}%)")

            target_regions = item.get("target_regions", [])
            for tgt in target_regions:
                if isinstance(tgt, dict):
                    region = tgt.get("name")
                    is_pred = tgt.get("is_predictive", False)
                else:
                    region = tgt
                    is_pred = False
                
                if not region or region not in ALL_REGIONS:
                    continue
                
                # Знижуємо довіру для предиктивних регіонів
                region_confidence = confidence
                if is_pred and region_confidence is not None:
                    region_confidence = max(0, region_confidence - 20)
                
                # ETA: prefer Gemini's AI-provided ETA, fallback to heuristic
                gemini_eta = item.get("eta", "")
                
                # --- Dynamic auto-clear delay based on telemetry ---
                delay = 3600  # default 1 hour
                eta_str = gemini_eta if gemini_eta else ""
                
                # Try to calculate delay from telemetry speed + distance
                telemetry_delay = None
                if telemetry and isinstance(telemetry, dict):
                    t_speed = telemetry.get("speed_kmh")
                    t_distance = telemetry.get("distance_to_target_km")
                    if t_speed and t_distance and t_speed > 0:
                        # Calculate ETA in seconds: distance/speed * 3600, with 50% buffer
                        telemetry_delay = int((t_distance / t_speed) * 3600 * 1.5)
                        telemetry_delay = max(300, min(telemetry_delay, 14400))  # clamp 5min-4hours
                
                if telemetry_delay:
                    delay = telemetry_delay
                elif threat_type == "mig31k":
                    delay = 1800  # 30 хв
                    if not eta_str:
                        eta_str = "~20-40 хв"
                elif threat_type == "ballistic":
                    delay = 600   # 10 хв
                    if not eta_str:
                        eta_str = "~2-5 хв"
                elif threat_type == "kab":
                    delay = 1200  # 20 хв
                    if not eta_str:
                        eta_str = "~5-15 хв"
                elif threat_type == "shahed":
                    delay = 10800  # 3 години
                    if not eta_str:
                        eta_str = "+1-2 год"
                elif threat_type == "cruise_missile":
                    delay = 2700  # 45 хв
                    if not eta_str:
                        eta_str = "+15-30 хв"
                elif threat_type == "tu95":
                    delay = 5400  # 1.5 год
                    if not eta_str:
                        eta_str = "~30-90 хв"
                elif threat_type == "iskander":
                    delay = 1200  # 20 хв
                    if not eta_str:
                        eta_str = "~2-5 хв"
                elif threat_type == "artillery":
                    delay = 1800  # 30 хв
                    if not eta_str:
                        eta_str = "~0-5 хв"
                    
                detail = clean_user_facing_threat_detail(text)
                
                # Append telemetry details in a readable format if available
                telemetry_info = []
                if telemetry and isinstance(telemetry, dict):
                    # 1. Distance
                    distance = telemetry.get("distance_to_target_km")
                    if distance:
                        telemetry_info.append(f"Відстань до цілі: ~{distance:.0f} км")
                    
                    # 2. Target Count (Кількість цілей)
                    target_count = telemetry.get("target_count")
                    if target_count:
                        telemetry_info.append(f"Кількість цілей: {target_count}")
                    
                    # 3. Launch Origin (Район запуску)
                    launch_origin = telemetry.get("launch_origin")
                    if launch_origin and launch_origin.lower() != "unknown":
                        telemetry_info.append(f"Напрямок запуску: {launch_origin}")
                        
                    # 4. Weapon Subtype (Конкретна модель)
                    weapon_subtype = telemetry.get("weapon_subtype")
                    if weapon_subtype and weapon_subtype.lower() != "unknown":
                        telemetry_info.append(f"Тип: {weapon_subtype}")
                        
                    # 5. Speed (Швидкість)
                    speed = telemetry.get("speed_kmh")
                    if speed:
                        telemetry_info.append(f"Швидкість руху: ~{speed} км/год")
                        
                    # 6. Altitude (Висота)
                    alt = telemetry.get("altitude_category")
                    if alt and alt.lower() != "unknown":
                        alt_mapping = {"low": "мала", "medium": "середня", "high": "велика"}
                        alt_ukr = alt_mapping.get(alt.lower(), alt)
                        telemetry_info.append(f"Висота польоту: {alt_ukr}")
                
                if telemetry_info:
                    detail += "\n" + "\n".join(telemetry_info)
                
                if is_pred:
                    detail += f"\n⚠️ Ціль може прямувати через область."
                    if eta_str:
                        detail += f" Очікуваний час: {eta_str}"
                elif eta_str:
                    detail += f"\n(Очікуваний час: {eta_str})"

                self.threat_manager.set_threat(region, adjusted_level, threat_type, detail,
                                               confidence=region_confidence, eta=eta_str, is_predictive=is_pred,
                                               is_test=is_test, telemetry=telemetry, rules_applied=rules_applied)
                self._schedule_auto_clear(region, delay)
                
                # Enhanced logging with telemetry info
                conf_str = f", довіра: {region_confidence}%" if region_confidence is not None else ""
                telem_str = ""
                if telemetry and isinstance(telemetry, dict):
                    parts = []
                    if telemetry.get("group_id"):
                        parts.append(f"група: {telemetry['group_id']}")
                    if telemetry.get("speed_kmh"):
                        parts.append(f"швидкість: {telemetry['speed_kmh']} км/год")
                    if telemetry.get("engagement_status") and telemetry["engagement_status"] != "unknown":
                        parts.append(f"статус: {telemetry['engagement_status']}")
                    if telemetry.get("target_count"):
                        parts.append(f"цілей: {telemetry['target_count']}")
                    if parts:
                        telem_str = f" | {', '.join(parts)}"
                
                print(f"🔴 [Gemini] Встановлено загрозу ({adjusted_level}) для: {region}{conf_str}{telem_str}")

        # === PREDICTIVE PROPAGATION ENGINE ===
        # After all Gemini-set threats, propagate predictions to adjacent regions
        await self._propagate_predictive_threats()


    # --- Predictive Propagation Engine ---
    # Coordinate centroids for heading-based prediction (approximate lat/lon centers)
    REGION_CENTROIDS = {
        "Вінницька область": (49.23, 28.47),
        "Волинська область": (51.0, 25.0),
        "Дніпропетровська область": (48.46, 35.05),
        "Донецька область": (48.0, 37.8),
        "Житомирська область": (50.45, 28.66),
        "Закарпатська область": (48.62, 22.3),
        "Запорізька область": (47.85, 35.15),
        "Івано-Франківська область": (48.92, 24.72),
        "Київська область": (50.45, 30.52),
        "м. Київ": (50.45, 30.52),
        "Кіровоградська область": (48.5, 32.27),
        "Луганська область": (48.57, 39.32),
        "Львівська область": (49.84, 24.03),
        "Миколаївська область": (47.0, 32.0),
        "Одеська область": (46.48, 30.73),
        "Полтавська область": (49.59, 34.55),
        "Рівненська область": (50.62, 26.25),
        "Сумська область": (50.91, 34.8),
        "Тернопільська область": (49.55, 25.6),
        "Харківська область": (49.99, 36.23),
        "Херсонська область": (46.64, 32.62),
        "Хмельницька область": (49.42, 27.0),
        "Черкаська область": (49.44, 32.06),
        "Чернівецька область": (48.3, 25.94),
        "Чернігівська область": (51.49, 31.29),
        "АР Крим": (45.3, 34.1),
    }

    # Direction vectors for attack_vector → approximate bearing
    VECTOR_BEARINGS = {
        "south_to_north": 0,
        "north_to_south": 180,
        "east_to_west": 270,
        "west_to_east": 90,
        "southeast_to_northwest": 315,
        "northeast_to_southwest": 225,
        "crimea_inland": 0,       # Generally north from Crimea
        "sea_to_coast": 0,        # Generally north (Black Sea)
        "border_shelling": None,  # No directional prediction
    }

    def _get_city_coordinates(self, city_name: str, telemetry: dict = None) -> Optional[tuple[float, float]]:
        if not city_name:
            return None
        city_lower = city_name.lower().strip()
        
        # 1. Try static coordinates dictionary
        for name, coords in CITY_COORDINATES.items():
            if name in city_lower or city_lower in name:
                return coords
                
        # 2. Try Gemini-determined dynamic coordinates from telemetry
        if telemetry and telemetry.get("target_cities_coords"):
            coords_dict = telemetry["target_cities_coords"]
            for name, coords in coords_dict.items():
                if name.lower().strip() in city_lower or city_lower in name.lower().strip():
                    if isinstance(coords, list) and len(coords) == 2:
                        try:
                            return (float(coords[0]), float(coords[1]))
                        except (ValueError, TypeError):
                            pass
        return None

    def _city_to_region(self, city_name: str) -> str:
        """Resolve a city/town name to its region using ALL_REGIONS keywords from mock_mode.
        Falls back to simple substring matching. Returns None if no match."""
        city_lower = city_name.lower().strip()
        for region, data in ALL_REGIONS.items():
            for kw in data.get("keywords", []):
                if kw in city_lower or city_lower in kw:
                    return region
        return None

    async def _propagate_predictive_threats(self):
        """
        Predictive Propagation Engine:
        Analyzes active threats with telemetry and automatically predicts
        which adjacent regions should become yellow (predictive) zones.
        
        Uses:
        1. Heading/attack_vector → direction-aligned adjacency scoring
        2. Speed + distance → ETA calculation for predictive regions  
        3. Historical patterns from DB → route confidence boosts
        4. SHAHED_ROUTES → known drone corridors
        5. Topology graph → adjacency validation
        """
        import math
        
        # Collect all currently active (non-none, non-predictive) threats with telemetry
        active_threats = {}
        for region, state in self.threat_manager.threats.items():
            if state.level != "none" and not state.is_predictive and state.threat_type:
                active_threats[region] = state
        
        if not active_threats:
            return
        
        # Collect candidate predictive regions
        predictions = {}  # region -> {score, source_region, threat_type, eta, detail, ...}
        
        for source_region, state in active_threats.items():
            threat_type = state.threat_type
            
            # Get telemetry for this region from the latest DB entry
            telemetry = self._get_latest_telemetry(source_region)
            
            # Calculate direction bearing
            bearing = None
            if telemetry:
                if telemetry.get("heading_degrees") is not None:
                    bearing = telemetry["heading_degrees"]
                elif telemetry.get("attack_vector"):
                    bearing = self.VECTOR_BEARINGS.get(telemetry["attack_vector"])
            
            # Speed for ETA calculation
            speed = None
            if telemetry and telemetry.get("speed_kmh"):
                speed = telemetry["speed_kmh"]
            else:
                # Default speeds by threat type
                speed_defaults = {
                    "shahed": 165, "cruise_missile": 850, "ballistic": 4000,
                    "mig31k": 2500, "kab": 300, "tu95": 800, "iskander": 4500,
                    "artillery": 1200,
                }
                speed = speed_defaults.get(threat_type, 300)
                
            # Pathfinding to final target cities
            path_boost_regions = set()
            if telemetry and telemetry.get("final_target_cities"):
                final_targets = telemetry["final_target_cities"]
                for city in final_targets:
                    target_region = self._city_to_region(city)
                    if target_region:
                        path = self._find_path(source_region, target_region)
                        if path:
                            for pr in path[1:]:
                                path_boost_regions.add(pr)
            
            # Get adjacent regions from topology
            adjacent = UKRAINE_TOPOLOGY.get(source_region, [])
            if not adjacent:
                continue
            
            for adj_region in adjacent:
                # Skip if already has active (non-predictive) threat
                adj_state = self.threat_manager.threats.get(adj_region)
                if not adj_state:
                    continue
                if adj_state.level != "none" and not adj_state.is_predictive:
                    continue  # Already red — skip
                
                # Calculate direction alignment score (0.0 - 1.0)
                direction_score = 0.5  # Neutral if no bearing
                if bearing is not None and source_region in self.REGION_CENTROIDS and adj_region in self.REGION_CENTROIDS:
                    src_coords = self.REGION_CENTROIDS[source_region]
                    adj_coords = self.REGION_CENTROIDS[adj_region]
                    
                    # Calculate bearing from source to adjacent
                    dlat = adj_coords[0] - src_coords[0]
                    dlon = adj_coords[1] - src_coords[1]
                    adj_bearing = math.degrees(math.atan2(dlon, dlat)) % 360
                    
                    # Angular difference (0-180)
                    diff = abs(bearing - adj_bearing)
                    if diff > 180:
                        diff = 360 - diff
                    
                    # Convert to score: 0° diff = 1.0, 90° diff = 0.3, 180° diff = 0.0
                    direction_score = max(0.0, 1.0 - (diff / 180.0))
                    # Boost forward-aligned regions
                    if diff < 45:
                        direction_score = min(1.0, direction_score * 1.3)
                
                # Skip if direction is completely wrong (>120° off course)
                if bearing is not None and direction_score < 0.2:
                    continue
                
                # Calculate distance and ETA
                eta_seconds = None
                distance_km = None
                if source_region in self.REGION_CENTROIDS and adj_region in self.REGION_CENTROIDS:
                    src = self.REGION_CENTROIDS[source_region]
                    
                    # If target region has a specific final target city, use its exact coordinates!
                    target_coords = None
                    if telemetry and telemetry.get("final_target_cities"):
                        for city in telemetry["final_target_cities"]:
                            if self._city_to_region(city) == adj_region:
                                target_coords = self._get_city_coordinates(city, telemetry)
                                if target_coords:
                                    break
                    
                    adj = target_coords if target_coords else self.REGION_CENTROIDS[adj_region]
                    
                    # Approximate distance in km (Haversine simplified)
                    dlat = abs(src[0] - adj[0]) * 111
                    dlon = abs(src[1] - adj[1]) * 111 * math.cos(math.radians((src[0] + adj[0]) / 2))
                    distance_km = math.sqrt(dlat**2 + dlon**2)
                    if speed and speed > 0:
                        eta_seconds = int((distance_km / speed) * 3600)
                
                # Check historical patterns (known SHAHED routes)
                route_boost = 0.0
                
                # Apply massive boost if region is on the path to a known final target
                if adj_region in path_boost_regions:
                    route_boost = 0.8
                else:
                    for route_name, route_regions in SHAHED_ROUTES.items():
                        if source_region in route_regions and adj_region in route_regions:
                            src_idx = route_regions.index(source_region)
                            adj_idx = route_regions.index(adj_region)
                            if adj_idx > src_idx:  # Forward in the route
                                route_boost = 0.25
                                break
                
                # Check DB for historical patterns
                db_boost = self._get_historical_route_score(source_region, adj_region)
                
                # Calculate final prediction score
                base_score = direction_score * 0.5 + 0.2  # 20-70% base from direction
                
                # Threat type weight (slow = more predictable trajectory)
                type_weight = {"shahed": 0.15, "cruise_missile": 0.08, "mig31k": 0.05, "ballistic": 0.0, "kab": 0.02, "tu95": 0.10, "iskander": 0.0, "artillery": 0.01}
                base_score += type_weight.get(threat_type, 0.05)
                
                # Apply boosts
                total_score = min(1.0, base_score + route_boost + db_boost)
                
                # Threshold: only predict if score >= 0.4
                if total_score < 0.4:
                    continue
                
                # --- DIFFERENTIATED CONFIDENCE CALCULATION ---
                # Non-linear base confidence from total_score
                if total_score >= 0.85:
                    base_conf = 75
                elif total_score >= 0.70:
                    base_conf = 65
                elif total_score >= 0.55:
                    base_conf = 55
                elif total_score >= 0.45:
                    base_conf = 45
                else:
                    base_conf = 35
                
                # Distance modifier (closer = higher confidence)
                dist_mod = 0
                if distance_km is not None:
                    if distance_km < 80:
                        dist_mod = 8
                    elif distance_km < 150:
                        dist_mod = 4
                    elif distance_km < 250:
                        dist_mod = 0
                    elif distance_km < 400:
                        dist_mod = -4
                    else:
                        dist_mod = -8
                
                # Route history modifier (known route = higher confidence)
                route_mod = int(route_boost * 12)  # 0-9
                
                # DB pattern modifier
                db_mod = int(db_boost * 8)  # 0-1
                
                # Time-of-day modifier
                time_mod = self._get_time_of_day_modifier(threat_type)
                
                # Learned rules correction
                rules_correction = 0
                try:
                    corrections = self.analyzer.load_confidence_corrections()
                    if adj_region in corrections:
                        rules_correction = corrections[adj_region].get(threat_type, 0)
                except Exception:
                    pass
                
                # Final confidence with all modifiers
                raw_confidence = base_conf + dist_mod + route_mod + db_mod + time_mod + rules_correction
                confidence = max(25, min(80, raw_confidence))
                
                # Ensure uniqueness: add small pseudo-random offset based on region name hash
                region_hash_offset = (hash(adj_region) % 5) - 2  # -2 to +2
                confidence = max(25, min(80, confidence + region_hash_offset))
                
                # Generate ETA string
                eta_str = ""
                if eta_seconds:
                    if eta_seconds < 300:
                        eta_str = "~2-5 хв"
                    elif eta_seconds < 900:
                        eta_str = f"~{eta_seconds // 60}-{eta_seconds // 60 + 10} хв"
                    elif eta_seconds < 3600:
                        eta_str = f"~{eta_seconds // 60} хв"
                    else:
                        hours = eta_seconds / 3600
                        eta_str = f"~{hours:.1f} год"
                
                # Keep the best prediction for each region
                if adj_region not in predictions or predictions[adj_region]["score"] < total_score:
                    predictions[adj_region] = {
                        "score": total_score,
                        "source_region": source_region,
                        "threat_type": threat_type,
                        "eta_str": eta_str,
                        "eta_seconds": eta_seconds,
                        "direction_score": direction_score,
                        "distance_km": distance_km,
                        "route_boost": route_boost,
                        "db_boost": db_boost,
                        "confidence": confidence,
                        "source_level": state.level,
                        "is_test": state.is_test,
                    }
        
        # Apply predictions
        predictions_applied = 0
        for region, pred in predictions.items():
            # Determine threat level for predictive zone
            pred_level = "low"
            if pred["score"] >= 0.75:
                pred_level = "medium"
            elif pred["score"] >= 0.55:
                pred_level = "low"
            
            # Reduce by one level vs source (predictions are always weaker)
            level_reduce = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
            max_level = level_reduce.get(pred["source_level"], "low")
            if {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(pred_level, 0) > \
               {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(max_level, 0):
                pred_level = max_level
            
            source_reg_genitive = get_genitive_region(pred['source_region'])
            threat_type_ukr = get_ukrainian_threat_type(pred['threat_type'])
            detail = f"Ціль з {source_reg_genitive} ({threat_type_ukr}) прямує в напрямку області."
            if pred["eta_str"]:
                detail += f"\nОчікуваний час: {pred['eta_str']}"
            if pred["distance_km"]:
                detail += f"\nВідстань: ~{pred['distance_km']:.0f} км"
            if pred["route_boost"] > 0:
                detail += "\nІсторичний маршрут підтверджено"
            if pred["db_boost"] > 0:
                detail += "\nПатерн підтверджений аналітикою"
            
            # Auto-clear delay for predictions (shorter than for direct threats)
            auto_clear_delay = pred.get("eta_seconds") or 1800
            auto_clear_delay = int(auto_clear_delay * 2.0)  # 2x the ETA as buffer
            auto_clear_delay = max(600, min(auto_clear_delay, 7200))  # 10min - 2hrs
            
            self.threat_manager.set_threat(
                region, pred_level, pred["threat_type"], detail,
                confidence=pred["confidence"],
                eta=pred["eta_str"],
                is_predictive=True,
                is_test=pred.get("is_test", False),
                telemetry=None  # No direct telemetry for predictions
            )
            self._schedule_auto_clear(region, auto_clear_delay)
            predictions_applied += 1
            
            score_detail = f"score={pred['score']:.2f} (dir={pred['direction_score']:.2f}, route=+{pred['route_boost']:.2f}, db=+{pred['db_boost']:.2f})"
            print(f"🟡 [Предикція] {region} ← {pred['source_region']} "
                  f"({pred['threat_type']}, {pred_level}) {score_detail} "
                  f"ETA: {pred['eta_str'] or '?'}")
        
        if predictions_applied:
            print(f"🟡 [Предикція] Всього виставлено {predictions_applied} предиктивних зон")

    def _get_latest_telemetry(self, region: str) -> dict:
        """Get the latest telemetry data for a region from the DB."""
        try:
            import sqlite3
            conn = sqlite3.connect("threat_analytics.db")
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT td.* FROM telemetry_data td
                JOIN threat_history th ON td.threat_event_id = th.id
                WHERE th.region = ? AND th.timestamp >= datetime('now', '-2 hours')
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()
            conn.close()
            if row:
                res = dict(row)
                if res.get("target_cities_coords"):
                    try:
                        import json
                        res["target_cities_coords"] = json.loads(res["target_cities_coords"])
                    except Exception:
                        res["target_cities_coords"] = {}
                return res
        except Exception:
            pass
        return {}

    def _get_historical_route_score(self, source: str, target: str) -> float:
        """Check DB for historical threat progression from source → target region."""
        try:
            import sqlite3
            conn = sqlite3.connect("threat_analytics.db")
            cursor = conn.cursor()
            # Look for clearings where target had a threat shortly after source
            cursor.execute('''
                SELECT COUNT(*) FROM threat_clearings
                WHERE region = ? AND linked_group_id IN (
                    SELECT td.group_id FROM telemetry_data td
                    JOIN threat_history th ON td.threat_event_id = th.id
                    WHERE th.region = ?
                )
                AND prediction_accuracy_hint = 'confirmed'
                AND timestamp >= datetime('now', '-30 days')
            ''', (target, source))
            count = cursor.fetchone()[0]
            conn.close()
            # Score: 0 events=0, 1-2=0.05, 3-5=0.1, 6+=0.15
            if count >= 6:
                return 0.15
            elif count >= 3:
                return 0.1
            elif count >= 1:
                return 0.05
        except Exception:
            pass
        return 0.0


    async def _process_message(self, text, channel):
        if self.analyzer.is_configured:
            # Queue for Gemini
            await self.message_queue.put({"channel": channel, "text": text})
            print(f"📥 Повідомлення додано до черги ШІ. В черзі: {self.message_queue.qsize()}")
        else:
            # Fallback to Regex
            await self._process_message_regex(text, channel)

    # --- Message Parser Logic (Shared by both MTProto & Web Scraper) ---
    async def _process_message_regex(self, text, channel, is_test: bool = False):
        # Clean double spaces and split into lines, then logical sentences
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        segments = []
        for line in lines:
            parts = re.split(r'(?<=[.!?])\s+', line)
            for part in parts:
                p = part.strip()
                if p:
                    segments.append(p)
                    
        if not segments:
            return

        # We will parse segment by segment with a stateful context
        context_level = None
        context_type = None
        context_text = None
        context_regions = []
        
        # Keep track of modified regions in this execution
        set_regions = {}
        cleared_regions = set()
        cleared_all = False

        for segment in segments:
            is_seg_clear = any(re.search(kw, segment, re.IGNORECASE) for kw in CLEAR_KEYWORDS)
            
            if is_seg_clear:
                seg_regions = self._extract_regions(segment)
                if seg_regions:
                    for region in seg_regions:
                        self.threat_manager.clear_threat(region)
                        if region in self._clear_tasks:
                            self._clear_tasks[region].cancel()
                            del self._clear_tasks[region]
                        cleared_regions.add(region)
                else:
                    # If it says 'clear' but names no regions, it might be a general clear.
                    # We only clear all if the entire message contains no other region mentions
                    if not self._extract_regions(text):
                        self.threat_manager.clear_all(only_test=is_test)
                        cleared_all = True
                    else:
                        if "област" in segment or "всіх" in segment or not seg_regions:
                            self.threat_manager.clear_all(only_test=is_test)
                            cleared_all = True
                
                # Reset context on clear
                context_level = None
                context_type = None
                context_text = None
                context_regions = []
                continue

            # Detect threat level and type for this segment
            level = self._detect_threat_level(segment)
            threat_type = self._detect_threat_type(segment)
            
            # If this segment has a threat level, update our active context
            if level:
                context_level = level
                context_type = threat_type
                context_text = segment
            
            # Extract regions for this segment
            regions = self._extract_regions(segment)
            
            # If no regions in segment, but we detected a threat context, apply it to the whole country
            # if the level is critical or high (like MiG-31 takeoff, cruise missiles)
            if not regions and context_level in ("critical", "high"):
                if not self._extract_regions(text):
                    regions = list(ALL_REGIONS)
            
            # Extract Vector Context (Predictive routing)
            predictive_regions = set()
            
            # If we have regions in context from previous segment, maybe this is a vector
            if context_regions and regions and not level:
                # previous segment had regions, current segment has new regions
                source_region = context_regions[-1]
                target_region = regions[0]
                path = self._find_path(source_region, target_region)
                if len(path) > 2:
                    for r in path[1:-1]:
                        predictive_regions.add(r)
            
            # Also check if multiple regions are in the same segment
            if len(regions) >= 2:
                for i in range(len(regions) - 1):
                    path = self._find_path(regions[i], regions[i+1])
                    if len(path) > 2:
                        for r in path[1:-1]:
                            predictive_regions.add(r)

            # Update context_regions
            if regions:
                context_regions = regions

            # Stateful fallback: if segment has regions but no threat level was detected in it,
            # we use the context from the previous segment of the same message (if available)
            if not level and regions and context_level:
                level = context_level
                threat_type = context_type
                detail_text = f"{context_text} {segment}"
            else:
                detail_text = segment

            # Combine explicit regions and predictive regions
            final_regions = list(set(regions) | predictive_regions)

            # Set threat for the detected regions
            if level and final_regions:
                for region in final_regions:
                    # Determine dynamic auto-clear delay and ETA based on threat type
                    delay = 3600
                    eta_str = ""
                    if threat_type == "mig31k":
                        delay = 2700
                        eta_str = "~20-40 хв"
                    elif threat_type == "ballistic":
                        delay = 1800
                        eta_str = "~2-5 хв"
                    elif threat_type == "shahed":
                        delay = 10800
                        eta_str = "+1-2 год"
                    elif threat_type == "cruise_missile":
                        delay = 3600
                        eta_str = "+15-30 хв"
                    elif threat_type == "tu95":
                        delay = 5400
                        eta_str = "~30-90 хв"
                    elif threat_type == "iskander":
                        delay = 1800
                        eta_str = "~2-5 хв"
                    elif threat_type == "artillery":
                        delay = 1800
                        eta_str = "~0-5 хв"
                        
                    is_pred = region in predictive_regions
                    
                    # Default confidence scores for regex fallback (no AI)
                    regex_confidence = 75  # Base confidence for regex
                    if level == "critical":
                        regex_confidence = 90
                    elif level == "high":
                        regex_confidence = 80
                    elif level == "medium":
                        regex_confidence = 65
                    elif level == "low":
                        regex_confidence = 50
                    if is_pred:
                        regex_confidence = max(0, regex_confidence - 20)
                    
                    detail = self._build_region_detail(detail_text, region, threat_type)
                    detail = clean_user_facing_threat_detail(detail)
                    if is_pred:
                        detail += f" ⚠️ Ціль може прямувати через область. Очікуваний час: {eta_str}" if eta_str else " ⚠️ Ціль може прямувати через область."
                    elif eta_str:
                        detail += f" (Очікуваний час: {eta_str})"

                    self.threat_manager.set_threat(region, level, threat_type, detail,
                                                  confidence=regex_confidence, eta=eta_str, is_predictive=is_pred,
                                                  is_test=is_test)
                    self._schedule_auto_clear(region, delay)
                    set_regions[region] = level

        # Print consolidated status update for the logs
        if cleared_all:
            print(f"🟢 [{channel}] Зняття загрози розпізнано для ВСІХ областей (відбій/чисто)")
        elif cleared_regions:
            print(f"🟢 [{channel}] Зняття загрози розпізнано для: {', '.join(cleared_regions)}")
            
        if set_regions:
            for lvl in ["low", "medium", "high", "critical"]:
                matching = [r for r, l in set_regions.items() if l == lvl]
                if matching:
                    print(f"🔴 [{channel}] Рівень {lvl.upper()} встановлено для {len(matching)} областей: {', '.join(matching)}")

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
        if any(kw in text_lower for kw in ["міг-31", "міг31", "mig-31", "mig31", "кинджал", "х-47", "х47"]):
            return "mig31k"
        if any(kw in text_lower for kw in ["ту-95", "ту95", "tu-95", "tu95", "ту-22", "ту22", "tu-22", "tu22", "ту-160", "tu160"]):
            return "tu95"
        if any(kw in text_lower for kw in ["шахед", "shahed", "бпла", "дрон", "мопед", "гербер", "орлан", "supercam", "крило"]):
            return "shahed"
        if any(kw in text_lower for kw in ["іскандер", "iskander"]):
            return "iskander"
        if any(kw in text_lower for kw in ["балісти", "с-300", "с300", "с-400", "с400", "c-300", "c300", "c-400", "c400"]):
            return "ballistic"
        if any(kw in text_lower for kw in ["ракет", "крилат", "калібр", "х-101", "х101", "х-55", "х55", "х-555", "х555", "х-59", "х59", "х-69", "х69"]):
            return "cruise_missile"
        if any(kw in text_lower for kw in ["артилерія", "рсзв", "обстріл", "град", "смерч", "ураган", "міномет"]):
            return "artillery"
        if re.search(r"\bкаб(и|ів)?\b|авіабомб|фаб|уаб", text_lower) or any(kw in text_lower for kw in ["су-34", "су-35", "су-30", "су-57", "сушка", "сушки"]):
            return "kab"
        return "unknown"

    def _extract_regions(self, text: str):
        found = set()
        for region, info in ALL_REGIONS.items():
            for kw in info["keywords"]:
                if re.search(kw, text, re.IGNORECASE):
                    found.add(region)
                    
        # Macro-directions mapping
        text_lower = text.lower()
        
        west_regions = ["Львівська область", "Волинська область", "Рівненська область", "Тернопільська область", "Хмельницька область", "Івано-Франківська область", "Закарпатська область", "Чернівецька область"]
        north_regions = ["Київська область", "м. Київ", "Чернігівська область", "Сумська область", "Житомирська область"]
        center_regions = ["Черкаська область", "Кіровоградська область", "Полтавська область", "Вінницька область", "Дніпропетровська область"]
        south_regions = ["Одеська область", "Миколаївська область", "Херсонська область", "Запорізька область"]
        east_regions = ["Харківська область", "Донецька область", "Луганська область", "Дніпропетровська область", "Запорізька область"]

        # Check for West
        if re.search(r"\bзахідн\w*\b|\bзаході\b|\bзахід\b", text_lower):
            if not any(landing_kw in text_lower for landing_kw in ["посадка", "захід на посадку"]):
                for r in west_regions:
                    found.add(r)
                    
        # Check for North
        if re.search(r"\bпівнічн\w*\b|\bпівночі\b|\bпівніч\b", text_lower):
            for r in north_regions:
                found.add(r)
                
        # Check for Center
        if re.search(r"\bцентральн\w*\b|\bцентрі\b|\bцентр\b", text_lower):
            if not any(skip in text_lower for skip in ["прес-центр", "інфо-центр"]):
                for r in center_regions:
                    found.add(r)
                    
        # Check for South
        if re.search(r"\bпівденн\w*\b|\bпівдні\b|\bпівдень\b", text_lower):
            for r in south_regions:
                found.add(r)
                
        # Check for East
        if re.search(r"\bсхідн\w*\b|\bсході\b|\bсхід\b", text_lower):
            for r in east_regions:
                found.add(r)
                
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
                # Determine delay based on threat type
                t_type = state.threat_type
                delay = 3600
                if t_type == "mig31k":
                    delay = 1800
                elif t_type == "ballistic":
                    delay = 600
                elif t_type == "kab":
                    delay = 1200
                elif t_type == "shahed":
                    delay = 10800
                elif t_type == "cruise_missile":
                    delay = 2700
                elif t_type == "tu95":
                    delay = 5400
                elif t_type == "iskander":
                    delay = 1200
                elif t_type == "artillery":
                    delay = 1800
                try:
                    since_str = state.since.replace("Z", "+00:00")
                    since_dt = datetime.fromisoformat(since_str)
                    elapsed = (datetime.now(timezone.utc) - since_dt).total_seconds()
                    remaining = delay - elapsed
                    if remaining <= 0:
                        self.threat_manager.clear_threat(region)
                        print(f"⏳ Загроза для {region} ({t_type}) застаріла під час офлайну. Очищено.")
                    else:
                        self._schedule_auto_clear(region, remaining)
                        print(f"⏳ Заплановано автозняття загрози для {region} ({t_type}) через {int(remaining)} сек.")
                except Exception as e:
                    self._schedule_auto_clear(region, delay)

    def _get_time_of_day_modifier(self, threat_type: str) -> int:
        """Returns a confidence modifier based on current time of day and threat type.
        Night attacks with shaheds are statistically more common → boost confidence."""
        from datetime import datetime, timezone
        try:
            import zoneinfo
            kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except ImportError:
            return 0
        
        hour = datetime.now(kyiv_tz).hour
        
        # Shaheds predominantly attack at night (22:00-06:00)
        if threat_type == "shahed":
            if 22 <= hour or hour < 6:
                return 5  # Night shahed attack — boost
            elif 6 <= hour < 9:
                return 2  # Early morning — still possible
            else:
                return -3  # Daytime shahed — less likely
        
        # Ballistic and cruise missiles — any time, slight daytime bias
        if threat_type in ("ballistic", "iskander", "cruise_missile"):
            if 5 <= hour < 8:
                return 3  # Dawn attacks are historically common
            return 0
        
        # KABs — primarily daytime (requires visual targeting)
        if threat_type == "kab":
            if 7 <= hour < 17:
                return 3  # Daytime — prime KAB window
            else:
                return -4  # Night — unlikely for KABs
        
        return 0

    async def _rules_learner_loop(self):
        """Background task that analyzes paired events every 6 hours to derive new rules."""
        # Wait 5 minutes before first run to let data accumulate
        await asyncio.sleep(300)
        
        while self.is_running:
            try:
                count = self._run_rules_learner()
                if count > 0:
                    print(f"🧠 [Rules Learner] Автонавчання завершено: {count} правил створено/оновлено")
            except Exception as e:
                print(f"⚠️ [Rules Learner] Помилка: {e}")
            
            # Sleep 6 hours
            await asyncio.sleep(6 * 3600)

    def _run_rules_learner(self) -> int:
        """Analyze paired events and derive rules by delegating to the analyzer's central engine."""
        if self.analyzer and hasattr(self.analyzer, 'run_rules_learner'):
            return self.analyzer.run_rules_learner()
        return 0
