import asyncio
import os
import re
import sys
from typing import Optional
from telethon import TelegramClient, events
import aiohttp
from bs4 import BeautifulSoup
from mock_mode import ThreatState, ALL_REGIONS, THREAT_TYPES, UKRAINE_TOPOLOGY
from gemini_analyzer import GeminiThreatAnalyzer

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass


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
        
        self.analyzer = GeminiThreatAnalyzer()
        self.message_queue = asyncio.Queue()
        self.batch_task = None
        
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

    # --- LLM Batching Loop ---
    async def _batch_processor_loop(self):
        """Фоновий процес, що збирає повідомлення та відправляє їх до Gemini раз на 60с."""
        while self.is_running:
            await asyncio.sleep(60) # Wait 60 seconds
            
            messages = []
            while not self.message_queue.empty():
                try:
                    msg = self.message_queue.get_nowait()
                    messages.append(msg)
                except asyncio.QueueEmpty:
                    break
                    
            if messages:
                print(f"🧠 Відправка батчу ({len(messages)} повідомлень) до Gemini API...")
                results = await self.analyzer.analyze_batch(messages)
                if results:
                    await self._apply_gemini_analysis(results)

    async def _apply_gemini_analysis(self, results, is_test: bool = False):
        """Applies Gemini AI analysis results with confidence-based filtering and level adjustment."""
        for item in results:
            if not isinstance(item, dict):
                continue
                
            level = item.get("threat_level", "none")
            threat_type = item.get("threat_type")
            is_clear = item.get("is_clear", False)
            source_channel = item.get("source_channel", "AI")
            text = item.get("text", "")
            confidence = item.get("confidence_score")
            
            # Validate confidence as int
            if confidence is not None:
                try:
                    confidence = int(confidence)
                except (ValueError, TypeError):
                    confidence = None
            
            # Обробка відбою
            if is_clear:
                targets = item.get("target_regions", [])
                if not targets:
                    self.threat_manager.clear_all()
                    print(f"🟢 [Gemini] Зняття загрози розпізнано для ВСІХ областей")
                else:
                    for tgt in targets:
                        region = tgt if isinstance(tgt, str) else tgt.get("name")
                        if region:
                            self.threat_manager.clear_threat(region)
                            if region in self._clear_tasks:
                                self._clear_tasks[region].cancel()
                                del self._clear_tasks[region]
                            print(f"🟢 [Gemini] Зняття загрози: {region}")
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
                    
                delay = 3600
                eta_str = gemini_eta if gemini_eta else ""
                if threat_type == "mig31k":
                    delay = 2700
                    if not eta_str:
                        eta_str = "~20-40 хв"
                elif threat_type == "ballistic":
                    delay = 1800
                    if not eta_str:
                        eta_str = "~2-5 хв"
                elif threat_type == "shahed":
                    delay = 10800
                    if not eta_str:
                        eta_str = "+1-2 год"
                elif threat_type == "cruise_missile":
                    delay = 3600
                    if not eta_str:
                        eta_str = "+15-30 хв"
                    
                detail = f"[{source_channel}] {text}"
                if is_pred:
                    detail += f"\n⚠️ Предиктивний аналіз ШІ: ціль може прямувати через область."
                    if eta_str:
                        detail += f" Очікуваний час: {eta_str}"
                elif eta_str:
                    detail += f"\n(Очікуваний час: {eta_str})"

                self.threat_manager.set_threat(region, adjusted_level, threat_type, detail,
                                               confidence=region_confidence, eta=eta_str, is_predictive=is_pred,
                                               is_test=is_test)
                self._schedule_auto_clear(region, delay)
                conf_str = f", довіра: {region_confidence}%" if region_confidence is not None else ""
                print(f"🔴 [Gemini] Встановлено загрозу ({adjusted_level}) для: {region}{conf_str}")


    async def _process_message(self, text, channel):
        if self.analyzer.is_configured:
            # Queue for Gemini
            await self.message_queue.put({"channel": channel, "text": text})
            print(f"📥 Повідомлення додано до черги ШІ. В черзі: {self.message_queue.qsize()}")
        else:
            # Fallback to Regex
            await self._process_message_regex(text, channel)

    # --- Message Parser Logic (Shared by both MTProto & Web Scraper) ---
    async def _process_message_regex(self, text, channel):
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
                        self.threat_manager.clear_all()
                        cleared_all = True
                    else:
                        if "област" in segment or "всіх" in segment or not seg_regions:
                            self.threat_manager.clear_all()
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
                    if is_pred:
                        detail += f" ⚠️ Предиктивний аналіз: ціль може прямувати через область. Очікуваний час: {eta_str}" if eta_str else " ⚠️ Предиктивний аналіз: ціль може прямувати через область."
                    elif eta_str:
                        detail += f" (Очікуваний час: {eta_str})"

                    self.threat_manager.set_threat(region, level, threat_type, detail,
                                                  confidence=regex_confidence, eta=eta_str, is_predictive=is_pred)
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
        if re.search(r"\bкаб(и|ів)?\b|авіабомб", text_lower):
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
