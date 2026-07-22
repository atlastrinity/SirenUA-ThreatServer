import asyncio
import os
import re
import sqlite3
import sys
import time
from typing import Optional, Tuple
from telethon import TelegramClient, events
import aiohttp
from bs4 import BeautifulSoup

from core.threat_state import ThreatState
from core.regions import ALL_REGIONS, get_genitive_region, get_ukrainian_threat_type
from core.threat_state import THREAT_TYPES
from core.topology import UKRAINE_TOPOLOGY, SHAHED_ROUTES, REGION_CENTROIDS, VECTOR_BEARINGS, CITY_COORDINATES
from analyzer.gemini_analyzer import GeminiThreatAnalyzer
from core.config import (
    TELEGRAM_API_ID,
    TELEGRAM_API_HASH,
    TARGET_CHANNELS,
    CRITICAL_KEYWORDS,
    HIGH_KEYWORDS,
    MEDIUM_KEYWORDS,
    LOW_KEYWORDS,
    CLEAR_KEYWORDS,
    DB_PATH
)
from database.db_helpers import get_sqlite_connection

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

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

def sanitize_region_in_flight_text(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'\bв\s+([А-Яа-яЄєІіЇїҐґ\s\-]+(?:області|областях|регіоні))', r'у напрямку \1', text, flags=re.IGNORECASE)
    for p in ["в області", "в межах області", "у межах області", "в повітряному просторі"]:
        text = re.sub(re.escape(p), "у напрямку області", text, flags=re.IGNORECASE)
    return text

def parse_eta_seconds(eta_str: str) -> Optional[int]:
    if not eta_str:
        return None
    # Remove tilde, plus, spaces
    clean = eta_str.replace("~", "").replace("+", "").strip().lower()
    # Handle "в області"
    if "в області" in clean:
        return 0
    # Check minutes
    if "хв" in clean:
        val = clean.replace("хв", "").strip()
        if "-" in val:
            parts = val.split("-")
            try:
                # Use max of the range to be safe
                return int(float(parts[1].strip()) * 60)
            except (ValueError, IndexError):
                pass
        else:
            try:
                return int(float(val) * 60)
            except ValueError:
                pass
    # Check hours
    elif "год" in clean:
        val = clean.replace("год", "").strip()
        if "-" in val:
            parts = val.split("-")
            try:
                return int(float(parts[1].strip()) * 3600)
            except (ValueError, IndexError):
                pass
        else:
            try:
                return int(float(val) * 3600)
            except ValueError:
                pass
    return None

class TelegramThreatMonitor:
    def __init__(self, threat_manager):
        self.threat_manager = threat_manager
        self.is_running = False
        self.use_mtproto = False
        self.client: Optional[TelegramClient] = None
        self._clear_tasks = {}
        
        from database.analytics_db import log_error_to_db, log_rule_audit_to_db
        self.log_error = log_error_to_db
        self.analyzer = GeminiThreatAnalyzer(error_callback=log_error_to_db, rule_audit_callback=log_rule_audit_to_db)
        self.message_queue = asyncio.Queue()
        self.batch_task = None
        self.message_history = []
        self.channel_message_buffers = {channel: [] for channel in TARGET_CHANNELS}
        self._reevaluation_tasks = {}
        
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
        
        # Запускаємо фоновий цикл загасання довіри
        self._decay_task = asyncio.create_task(self._confidence_decay_loop())
        
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
                    self._init_scrape_base_id(channel, messages)
                    return

                await self._process_scraped_messages(channel, messages)
        except Exception as e:
            self.log_error("telegram", f"Помилка скрейпера для каналу {channel}: {e}", endpoint="_scrape_channel")

    def _init_scrape_base_id(self, channel: str, messages):
        """Finds and sets the initial maximum message ID on first run."""
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

    async def _process_scraped_messages(self, channel: str, messages):
        """Processes new scraped messages that have IDs greater than last seen."""
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
                try:
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
                        from database.analytics_db import flush_history_batch
                        flush_history_batch()
                        # Flush buffered FCM notifications (sound only on first)
                        self.threat_manager.flush_fcm_batch()
                        print(f"💾 Атомарний запис у Firestore після батчу ({len(results)} результатів)")
                except Exception as e:
                    self.log_error("telegram", f"Помилка батч-процесингу повідомлень: {e}", endpoint="_batch_processor_loop")



    def _handle_gemini_clearing(self, item: dict, confidence: Optional[int], threat_type: Optional[str], is_test: bool):
        """Helper to process clearing actions from Gemini analysis."""
        clearing_telemetry = item.get("clearing_telemetry", {})
        targets = item.get("target_regions", [])
        source_channel = item.get("source_channel", "AI")
        text = item.get("text", "")
        
        if not targets:
            # Global clearing — all regions
            self.threat_manager.clear_all()
            # Log clearing for each previously active region
            for r_name in self.threat_manager.threats.keys():
                from database.analytics_db import log_clearing_to_db
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
                from database.analytics_db import log_clearing_to_db
                log_clearing_to_db(
                    region=region,
                    clearing_telemetry=clearing_telemetry,
                    source_channel=source_channel,
                    message_text=text,
                    clearing_confidence=confidence,
                    was_predictive=was_pred
                )
                
                clearing_gid = clearing_telemetry.get("linked_group_id") if clearing_telemetry else None
                self.threat_manager.clear_threat(region, clearing_telemetry=clearing_telemetry, threat_type=threat_type, group_id=clearing_gid)
                self._cancel_clear_tasks(region, threat_type=threat_type, group_id=clearing_gid)
                
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

    def _get_threat_type_delay_and_eta(self, threat_type: Optional[str], is_regex: bool = False) -> tuple[int, str]:
        """Returns the default auto-clear delay and default ETA string for a given threat type."""
        regex_map = {
            "mig31k": (2700, "~20-40 хв"),
            "ballistic": (1800, "~2-5 хв"),
            "shahed": (10800, "+1-2 год"),
            "cruise_missile": (3600, "+15-30 хв"),
            "tu95": (5400, "~30-90 хв"),
            "iskander": (1800, "~2-5 хв"),
            "artillery": (1800, "~0-5 хв")
        }
        
        default_map = {
            "mig31k": (1800, "~40 хв"),
            "ballistic": (600, "~15 хв"),
            "kab": (1200, "~25 хв"),
            "shahed": (10800, "~200 хв"),
            "cruise_missile": (2700, "~55 хв"),
            "tu95": (5400, "~110 хв"),
            "iskander": (1200, "~25 хв"),
            "artillery": (1800, "~10 хв")
        }
        
        mapping = regex_map if is_regex else default_map
        if threat_type in mapping:
            return mapping[threat_type]
            
        return 3600, ""

    def _calculate_auto_clear_delay(self, item: dict, telemetry: Optional[dict], threat_type: Optional[str]) -> tuple[int, Optional[str], Optional[int]]:
        """Calculates dynamic/default auto-clear delay in seconds, ETA string, and ETA seconds."""
        gemini_eta = item.get("eta", "")
        delay, default_eta = self._get_threat_type_delay_and_eta(threat_type)
        eta_str = gemini_eta if gemini_eta else default_eta
        eta_seconds = None
        
        telemetry_delay = None
        if telemetry and isinstance(telemetry, dict):
            t_speed = telemetry.get("speed_kmh")
            t_distance = telemetry.get("distance_to_target_km")
            if t_speed and t_distance and t_speed > 0:
                eta_seconds = int((t_distance / t_speed) * 3600)
                
                if not gemini_eta:
                    buffer_minutes = 5
                    if eta_seconds > 1800:
                        buffer_minutes = 10
                    if threat_type == "shahed":
                        buffer_minutes = 20
                    eta_minutes = int(eta_seconds / 60) + buffer_minutes
                    eta_str = f"~{eta_minutes} хв"
                
                telemetry_delay = int(eta_seconds * 1.5)
                telemetry_delay = max(300, min(telemetry_delay, 14400))  # clamp 5min-4hours
        
        if telemetry_delay:
            delay = telemetry_delay

        if eta_seconds is None and eta_str:
            eta_seconds = parse_eta_seconds(eta_str)
                
        return delay, eta_str or None, eta_seconds

    def _format_telemetry_info(self, telemetry: dict) -> list[str]:
        """Formats the telemetry dict to Ukrainian user-friendly text lines."""
        telemetry_info = []
        if not telemetry or not isinstance(telemetry, dict):
            return telemetry_info
            
        distance = telemetry.get("distance_to_target_km")
        if distance:
            telemetry_info.append(f"Відстань до цілі: ~{distance:.0f} км")
            
        target_count = telemetry.get("target_count")
        if target_count:
            telemetry_info.append(f"Кількість цілей: {target_count}")
            
        launch_origin = telemetry.get("launch_origin")
        if launch_origin and launch_origin.lower() != "unknown":
            telemetry_info.append(f"Напрямок запуску: {launch_origin}")
                
        weapon_subtype = telemetry.get("weapon_subtype")
        if weapon_subtype and weapon_subtype.lower() != "unknown":
            telemetry_info.append(f"Тип: {weapon_subtype}")
                
        speed = telemetry.get("speed_kmh")
        if speed:
            telemetry_info.append(f"Швидкість руху: ~{speed} км/год")
                
        alt = telemetry.get("altitude_category")
        if alt and alt.lower() != "unknown":
            alt_mapping = {"low": "мала", "medium": "середня", "high": "велика"}
            alt_ukr = alt_mapping.get(alt.lower(), alt)
            telemetry_info.append(f"Висота польоту: {alt_ukr}")
            
        return telemetry_info

    def _apply_single_gemini_threat(self, item: dict, adjusted_level: str, threat_type: Optional[str], confidence: Optional[int], telemetry: Optional[dict], rules_applied: list, is_test: bool):
        """Processes and sets a single threat event item."""
        target_regions = item.get("target_regions", [])
        group_id = telemetry.get("group_id") if telemetry else None
        text = item.get("text", "")
        
        for tgt in target_regions:
            if isinstance(tgt, dict):
                region = tgt.get("name")
                is_pred = tgt.get("is_predictive", False)
            else:
                region = tgt
                is_pred = False
            
            if not region or region not in ALL_REGIONS:
                continue
            
            # If distance to target > 15 km, target is approaching/predictive
            dist_km = telemetry.get("distance_to_target_km") if telemetry else None
            if dist_km and dist_km > 15:
                is_pred = True

            region_confidence = confidence
            if is_pred and region_confidence is not None:
                region_confidence = max(0, region_confidence - 20)
            
            delay, eta_str, eta_seconds = self._calculate_auto_clear_delay(item, telemetry, threat_type)
            
            detail = clean_user_facing_threat_detail(text)
            if is_pred:
                detail = sanitize_region_in_flight_text(detail)

            telemetry_info = self._format_telemetry_info(telemetry)
            if telemetry_info:
                detail += "\n" + "\n".join(telemetry_info)
            
            if is_pred:
                detail += f"\n⚠️ Ціль може прямувати через область."
                if eta_str:
                    detail += f" Очікуваний час: {eta_str}"
            elif eta_str:
                detail += f"\n(Очікуваний час: {eta_str})"

            # Cross-Region Transit Handshake check
            launch_origin = telemetry.get("launch_origin") if telemetry else None
            if launch_origin:
                for reg in ALL_REGIONS:
                    if reg in launch_origin or launch_origin in reg:
                        self._handle_cross_region_transit(reg, region, threat_type, group_id)
                        break

            self.threat_manager.set_threat(region, adjusted_level, threat_type, detail,
                                           confidence=region_confidence, eta=eta_str, is_predictive=is_pred,
                                           is_test=is_test, telemetry=telemetry, rules_applied=rules_applied,
                                           eta_seconds=eta_seconds)
            self._schedule_auto_clear(region, delay, threat_type=threat_type, group_id=group_id)
            
            # Schedule ETA-based alarm escalation for all non-test threats (including predictive)
            if not is_test:
                eta_sec = eta_seconds
                if eta_sec is None:
                    eta_defaults = {
                        "mig31k": 1200,
                        "ballistic": 180,
                        "kab": 600,
                        "shahed": 5400,
                        "cruise_missile": 1200,
                        "tu95": 3600,
                        "iskander": 180,
                        "artillery": 120,
                    }
                    eta_sec = eta_defaults.get(threat_type, 1800)
                if eta_sec and eta_sec > 0:
                    self._schedule_eta_escalation(region, eta_sec, adjusted_level, threat_type, group_id)
            
            if is_pred:
                grace_period = 300
                eta_sec = eta_seconds
                if eta_sec is None:
                    eta_defaults = {
                        "mig31k": 1200,
                        "ballistic": 180,
                        "kab": 600,
                        "shahed": 5400,
                        "cruise_missile": 1200,
                        "tu95": 3600,
                        "iskander": 180,
                        "artillery": 120,
                    }
                    eta_sec = eta_defaults.get(threat_type, 1800)
                
                reeval_delay = eta_sec + grace_period
                self._schedule_predictive_reevaluation(region, reeval_delay, threat_type, group_id)
            else:
                self._cancel_reevaluation_task(region, threat_type, group_id)
            
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

    async def _apply_gemini_analysis(self, results, is_test: bool = False):
        """Applies Gemini AI analysis results with confidence-based filtering, level adjustment, and telemetry enrichment."""
        for item in results:
            if not isinstance(item, dict):
                continue
                
            level = item.get("threat_level", "none")
            threat_type = item.get("threat_type")
            if threat_type:
                threat_type = threat_type.lower().strip()
            is_clear = item.get("is_clear", False)
            text = item.get("text", "")
            confidence = item.get("confidence_score")
            telemetry = item.get("telemetry")
            rules_applied = item.get("rules_applied", [])
            
            if confidence is not None:
                try:
                    confidence = int(confidence)
                except (ValueError, TypeError):
                    confidence = None
            
            if is_clear:
                self._handle_gemini_clearing(item, confidence, threat_type, is_test)
                continue

            if level == "none":
                continue

            if confidence is not None and confidence < 40:
                print(f"⚠️ [Gemini] Загроза відхилена (довіра {confidence}% < 40%): {text[:60]}...")
                continue
                
            adjusted_level = level
            if confidence is not None:
                if confidence >= 85:
                    adjusted_level = level
                elif confidence >= 60:
                    level_downgrade = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
                    adjusted_level = level_downgrade.get(level, level)
                else:
                    adjusted_level = "low"
                    
                if adjusted_level != level:
                    print(f"📥 [Gemini] Рівень знижено {level} → {adjusted_level} (довіра {confidence}%)")

            self._apply_single_gemini_threat(item, adjusted_level, threat_type, confidence, telemetry, rules_applied, is_test)

        await self._propagate_predictive_threats()


    # --- Predictive Propagation Engine ---
    REGION_CENTROIDS = REGION_CENTROIDS
    VECTOR_BEARINGS = VECTOR_BEARINGS

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
                pred_dict = self._evaluate_prediction_candidate(
                    source_region, state, adj_region, telemetry, bearing, speed, path_boost_regions
                )
                if not pred_dict:
                    continue
                
                # Keep the best prediction for each region
                if adj_region not in predictions or predictions[adj_region]["score"] < pred_dict["score"]:
                    predictions[adj_region] = pred_dict
        
        # Apply predictions
        self._apply_predictions(predictions)

    def _format_prediction_eta_str(self, eta_seconds: Optional[int]) -> str:
        """Helper to format prediction ETA seconds into Ukrainian readable text."""
        if not eta_seconds:
            return ""
        if eta_seconds < 300:
            return "~2-5 хв"
        elif eta_seconds < 900:
            return f"~{eta_seconds // 60}-{eta_seconds // 60 + 10} хв"
        elif eta_seconds < 3600:
            return f"~{eta_seconds // 60}-{eta_seconds // 60 + 5} хв"
        else:
            h = eta_seconds // 3600
            m = (eta_seconds % 3600) // 60
            if m > 0:
                return f"~{h} год {m}-{m + 10} хв"
            else:
                return f"~{h} год"

    def _calc_direction_score(self, source_region: str, adj_region: str, bearing: Optional[float]) -> float:
        import math
        direction_score = 0.5
        if bearing is not None and source_region in self.REGION_CENTROIDS and adj_region in self.REGION_CENTROIDS:
            src_coords = self.REGION_CENTROIDS[source_region]
            adj_coords = self.REGION_CENTROIDS[adj_region]
            
            dlat = adj_coords[0] - src_coords[0]
            dlon = adj_coords[1] - src_coords[1]
            adj_bearing = math.degrees(math.atan2(dlon, dlat)) % 360
            
            diff = abs(bearing - adj_bearing)
            if diff > 180:
                diff = 360 - diff
            
            direction_score = max(0.0, 1.0 - (diff / 180.0))
            if diff < 45:
                direction_score = min(1.0, direction_score * 1.3)
        return direction_score

    def _calc_distance_and_eta(self, source_region: str, adj_region: str, telemetry: Optional[dict], speed: float) -> tuple[Optional[float], Optional[int]]:
        import math
        eta_seconds = None
        distance_km = None
        if source_region in self.REGION_CENTROIDS and adj_region in self.REGION_CENTROIDS:
            src = self.REGION_CENTROIDS[source_region]
            target_coords = None
            if telemetry and telemetry.get("final_target_cities"):
                for city in telemetry["final_target_cities"]:
                    if self._city_to_region(city) == adj_region:
                        target_coords = self._get_city_coordinates(city, telemetry)
                        if target_coords:
                            break
            
            adj = target_coords if target_coords else self.REGION_CENTROIDS[adj_region]
            
            dlat = abs(src[0] - adj[0]) * 111
            dlon = abs(src[1] - adj[1]) * 111 * math.cos(math.radians((src[0] + adj[0]) / 2))
            distance_km = math.sqrt(dlat**2 + dlon**2)
            if speed and speed > 0:
                eta_seconds = int((distance_km / speed) * 3600)
        return distance_km, eta_seconds

    def _calc_route_boost(self, source_region: str, adj_region: str, path_boost_regions: set) -> float:
        route_boost = 0.0
        if adj_region in path_boost_regions:
            route_boost = 0.8
        else:
            for route_name, route_regions in SHAHED_ROUTES.items():
                if source_region in route_regions and adj_region in route_regions:
                    src_idx = route_regions.index(source_region)
                    adj_idx = route_regions.index(adj_region)
                    if adj_idx > src_idx:
                        route_boost = 0.25
                        break
        return route_boost

    def _calc_total_score(self, direction_score: float, route_boost: float, db_boost: float, threat_type: str) -> float:
        base_score = direction_score * 0.5 + 0.2
        type_weight = {"shahed": 0.15, "cruise_missile": 0.08, "mig31k": 0.05, "ballistic": 0.0, "kab": 0.02, "tu95": 0.10, "iskander": 0.0, "artillery": 0.01}
        base_score += type_weight.get(threat_type, 0.05)
        return min(1.0, base_score + route_boost + db_boost)

    def _calc_confidence(self, total_score: float, distance_km: Optional[float], route_boost: float, db_boost: float, threat_type: str, adj_region: str) -> int:
        if total_score >= 0.85: base_conf = 75
        elif total_score >= 0.70: base_conf = 65
        elif total_score >= 0.55: base_conf = 55
        elif total_score >= 0.45: base_conf = 45
        else: base_conf = 35
        
        dist_mod = 0
        if distance_km is not None:
            if distance_km < 80: dist_mod = 8
            elif distance_km < 150: dist_mod = 4
            elif distance_km < 250: dist_mod = 0
            elif distance_km < 400: dist_mod = -4
            else: dist_mod = -8
            
        route_mod = int(route_boost * 12)
        db_mod = int(db_boost * 8)
        time_mod = self._get_time_of_day_modifier(threat_type)
        
        rules_correction = 0
        try:
            corrections = self.analyzer.load_confidence_corrections()
            if adj_region in corrections:
                rules_correction = corrections[adj_region].get(threat_type, 0)
        except Exception:
            pass
            
        raw_confidence = base_conf + dist_mod + route_mod + db_mod + time_mod + rules_correction
        confidence = max(25, min(80, raw_confidence))
        
        region_hash_offset = (hash(adj_region) % 5) - 2
        return max(25, min(80, confidence + region_hash_offset))

    def _evaluate_prediction_candidate(
        self,
        source_region: str,
        state,
        adj_region: str,
        telemetry: Optional[dict],
        bearing: Optional[float],
        speed: float,
        path_boost_regions: set
    ) -> Optional[dict]:
        """Evaluates prediction score and confidence from source_region to adj_region."""
        adj_state = self.threat_manager.threats.get(adj_region)
        if not adj_state or (adj_state.level != "none" and not adj_state.is_predictive):
            return None

        direction_score = self._calc_direction_score(source_region, adj_region, bearing)
        if bearing is not None and direction_score < 0.2:
            return None
        
        distance_km, eta_seconds = self._calc_distance_and_eta(source_region, adj_region, telemetry, speed)
        route_boost = self._calc_route_boost(source_region, adj_region, path_boost_regions)
        db_boost = self._get_historical_route_score(source_region, adj_region)
        
        total_score = self._calc_total_score(direction_score, route_boost, db_boost, state.threat_type)
        if total_score < 0.4:
            return None
            
        confidence = self._calc_confidence(total_score, distance_km, route_boost, db_boost, state.threat_type, adj_region)
        eta_str = self._format_prediction_eta_str(eta_seconds)
        
        return {
            "score": total_score,
            "source_region": source_region,
            "threat_type": state.threat_type,
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

    def _apply_predictions(self, predictions: dict):
        """Applies evaluated predictions to threat manager."""
        predictions_applied = 0
        for region, pred in predictions.items():
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
            
            pred_gid = f"pred_{region}_{pred['threat_type']}"
            self.threat_manager.set_threat(
                region, pred_level, pred["threat_type"], detail,
                confidence=pred["confidence"],
                eta=pred["eta_str"],
                is_predictive=True,
                is_test=pred.get("is_test", False),
                telemetry={"group_id": pred_gid},
                eta_seconds=pred.get("eta_seconds")
            )
            self._schedule_auto_clear(region, auto_clear_delay, threat_type=pred["threat_type"], group_id=pred_gid)
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
            conn = get_sqlite_connection(DB_PATH)
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
            conn = get_sqlite_connection(DB_PATH)
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
        # Store in rolling channel buffer
        channel_key = channel.lower().strip() if isinstance(channel, str) else channel
        if channel_key in self.channel_message_buffers:
            self.channel_message_buffers[channel_key].append({
                "text": text,
                "timestamp": time.time()
            })
            if len(self.channel_message_buffers[channel_key]) > 10:
                self.channel_message_buffers[channel_key] = self.channel_message_buffers[channel_key][-10:]

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
            is_seg_clear, is_cleared_all = self._handle_regex_clearing(text, segment, is_test, cleared_regions)
            if is_cleared_all:
                cleared_all = True
            
            if is_seg_clear:
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
            predictive_regions = self._extract_regex_predictive_regions(regions, context_regions, level)

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
                    is_pred = region in predictive_regions
                    self._apply_regex_threat(region, level, threat_type, detail_text, is_pred, is_test, set_regions)

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

    def _handle_regex_clearing(self, text: str, segment: str, is_test: bool, cleared_regions: set) -> Tuple[bool, bool]:
        """Handles clearing logic in regex processing. Returns (is_seg_clear, cleared_all)."""
        is_seg_clear = any(re.search(kw, segment, re.IGNORECASE) for kw in CLEAR_KEYWORDS)
        cleared_all = False
        if is_seg_clear:
            seg_regions = self._extract_regions(segment)
            if seg_regions:
                for region in seg_regions:
                    self.threat_manager.clear_threat(region)
                    self._cancel_clear_tasks(region)
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
        return is_seg_clear, cleared_all

    def _extract_regex_predictive_regions(self, regions: list, context_regions: list, level: Optional[str]) -> set:
        """Helper to extract predictive routing regions for regex processing."""
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
                        
        return predictive_regions

    def _apply_regex_threat(self, region: str, level: str, threat_type: str, detail_text: str, is_pred: bool, is_test: bool, set_regions: dict):
        """Helper to set threat and auto-clear delay in regex processing."""
        # Determine dynamic auto-clear delay and ETA based on threat type
        delay, eta_str = self._get_threat_type_delay_and_eta(threat_type, is_regex=True)
            
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

    def _cancel_matching_tasks(self, tasks_dict: dict, region: str, threat_type: str = None, group_id: str = None):
        """Cancels all tasks in the dict matching the region, type, and group_id."""
        to_delete = []
        for key, task in tasks_dict.items():
            k_region, k_type, k_gid = key
            if k_region == region:
                match = True
                if threat_type and k_type != threat_type:
                    match = False
                if group_id and k_gid != group_id:
                    match = False
                if match:
                    task.cancel()
                    to_delete.append(key)
        for key in to_delete:
            del tasks_dict[key]

    def _cancel_clear_tasks(self, region: str, threat_type: str = None, group_id: str = None):
        self._cancel_matching_tasks(self._clear_tasks, region, threat_type, group_id)
        self._cancel_matching_tasks(self._reevaluation_tasks, region, threat_type, group_id)

    def _cancel_reevaluation_task(self, region: str, threat_type: str = None, group_id: str = None):
        key = (region, threat_type, group_id)
        if key in self._reevaluation_tasks:
            self._reevaluation_tasks[key].cancel()
            del self._reevaluation_tasks[key]

    def _schedule_task_helper(self, tasks_dict: dict, key: tuple, delay_seconds: float, callback_coro_or_func, description: str, *args, **kwargs):
        """
        Helper method to schedule an asynchronous task with a delay, after cancelling any existing task with the same key.
        """
        if key in tasks_dict:
            tasks_dict[key].cancel()
            
        async def task_wrapper():
            await asyncio.sleep(delay_seconds)
            try:
                if asyncio.iscoroutinefunction(callback_coro_or_func):
                    await callback_coro_or_func(*args, **kwargs)
                else:
                    callback_coro_or_func(*args, **kwargs)
            except Exception as e:
                print(f"⚠️ [{description}] Error executing task: {e}")
            tasks_dict.pop(key, None)
            
        tasks_dict[key] = asyncio.create_task(task_wrapper())

    def _schedule_predictive_reevaluation(self, region: str, delay_seconds: float, threat_type: str, group_id: str):
        key = (region, threat_type, group_id)
        self._schedule_task_helper(
            self._reevaluation_tasks,
            key,
            delay_seconds,
            self._run_predictive_reevaluation,
            "Re-evaluation",
            region,
            threat_type,
            group_id
        )
        print(f"⏳ Заплановано переоцінку предиктивної загрози для {region} (тип: {threat_type}, група: {group_id}) через {int(delay_seconds)} сек")

    async def _run_predictive_reevaluation(self, region: str, threat_type: str, group_id: str):
        state = self.threat_manager.threats.get(region)
        if not state or state.level == "none" or state.is_active:
            # Threat is cleared or official siren became active, no need to reevaluate
            return
            
        target_threat = None
        for t in state.active_threats:
            if (group_id and t.group_id == group_id) or (not group_id and t.threat_type == threat_type):
                if t.is_predictive:
                    target_threat = t
                    break
                    
        if not target_threat:
            return
            
        print(f"🔍 [Re-evaluation] Початок автоматичної переоцінки загрози для {region} (тип: {threat_type}, група: {group_id})")
        
        # Collect last 5 messages from all channels
        recent_messages = []
        for channel, msgs in self.channel_message_buffers.items():
            for m in msgs[-5:]:
                recent_messages.append({
                    "channel": channel,
                    "text": m["text"],
                    "timestamp": m["timestamp"]
                })
                
        # Sort by timestamp desc and take top 15
        recent_messages.sort(key=lambda x: x["timestamp"], reverse=True)
        latest_msgs = recent_messages[:15]
        
        result = await self.analyzer.reevaluate_expired_threat(
            region=region,
            threat_type=threat_type,
            set_time=target_threat.since,
            recent_messages=latest_msgs
        )
        
        if result and not result.get("is_active", True):
            res_type = result.get("resolution_type", "expired")
            pred_acc = result.get("prediction_accuracy", "overestimated")
            reasoning = result.get("reasoning_ukr", "Час ETA минув, сирена не активна.")
            
            print(f"🟢 [Re-evaluation] Gemini підтвердив неактивність загрози для {region}. Причина: {res_type} ({pred_acc}). Обгрунтування: {reasoning}")
            
            clearing_telemetry = {
                "linked_group_id": group_id,
                "resolution_type": res_type,
                "prediction_accuracy_hint": pred_acc,
                "damage_assessment": "none",
                "impact_confirmed": False,
                "clearing_context_tags": ["авто_переоцінка", res_type]
            }
            
            # Log clearing to DB
            from database.analytics_db import log_clearing_to_db
            log_clearing_to_db(
                region=region,
                clearing_telemetry=clearing_telemetry,
                source_channel="Gemini_Reevaluation",
                message_text=f"[Авто-переоцінка] {reasoning}",
                clearing_confidence=target_threat.confidence,
                was_predictive=True
            )
            
            # Clear in manager
            self.threat_manager.clear_threat(region, clearing_telemetry=clearing_telemetry, threat_type=threat_type, group_id=group_id)
            self._cancel_clear_tasks(region, threat_type=threat_type, group_id=group_id)
        else:
            print(f"🟡 [Re-evaluation] Gemini визначив загрозу як АКТИВНУ або не зміг відповісти для {region}. Залишаємо загрозу діяти.")

    def _execute_auto_clear_callback(self, region: str, delay_seconds: float, threat_type: str, group_id: str):
        self.threat_manager.clear_threat(region, threat_type=threat_type, group_id=group_id)
        print(f"⏳ Автоматичне зняття загрози для {region} (тип: {threat_type or 'all'}, група: {group_id or 'all'}, таймаут {int(delay_seconds)} сек)")

    def _schedule_auto_clear(self, region: str, delay_seconds: float = 3600, threat_type: str = None, group_id: str = None):
        key = (region, threat_type, group_id)
        self._schedule_task_helper(
            self._clear_tasks,
            key,
            delay_seconds,
            self._execute_auto_clear_callback,
            "Auto-clear",
            region,
            delay_seconds,
            threat_type,
            group_id
        )

    def _schedule_eta_escalation(self, region: str, eta_seconds: float, current_level: str, threat_type: str = None, group_id: str = None):
        """
        Schedules a task to escalate the threat level and activate the air alarm 
        once the ETA expires for a confirmed threat.
        """
        key = (region, threat_type, group_id)
        if not hasattr(self, '_eta_escalation_tasks'):
            self._eta_escalation_tasks = {}
        self._schedule_task_helper(
            self._eta_escalation_tasks,
            key,
            eta_seconds,
            self._execute_eta_escalation_callback,
            "ETA-Escalation",
            region,
            threat_type,
            group_id,
            current_level
        )
        print(f"⏱️  [ETA-Escalation] Заплановано активацію тривоги для {region} (тип: {threat_type}, ETA: {int(eta_seconds)} сек)")

    def _execute_eta_escalation_callback(self, region: str, threat_type: str, group_id: str, original_level: str):
        """
        Fires when ETA expires for a threat.
        If the official state alarm is NOT active, triggers Gemini re-evaluation for predictive threats.
        Never forces critical red or fake alarms on unconfirmed threats.
        """
        state = self.threat_manager.threats.get(region)
        if not state or state.level == "none":
            print(f"⚠️  [ETA-Escalation] Загроза для {region} вже знята — ескалацію скасовано.")
            return

        is_official = getattr(state, "_is_official_active", False)
        if is_official:
            print(f"ℹ️  [ETA-Escalation] Офіційна тривога для {region} вже активна — пропускаємо.")
            return

        matching_threat = None
        for t in state.active_threats:
            if t.threat_type == threat_type and not t.is_test:
                if group_id is None or t.group_id == group_id:
                    matching_threat = t
                    break

        if not matching_threat:
            print(f"⚠️  [ETA-Escalation] Активна загроза для {region} (тип: {threat_type}) не знайдена — ескалацію скасовано.")
            return

        print(f"⏳ [ETA-Escalation] Час ETA для загрози {region} минув, але офіційної тривоги немає. Запускаємо переоцінку...")
        self._schedule_predictive_reevaluation(region, 0.0, threat_type, group_id)

    def _schedule_initial_auto_clears(self):
        from datetime import datetime, timezone
        for region, state in self.threat_manager.threats.items():
            if state.level != "none" and state.active_threats:
                for threat in list(state.active_threats):
                    t_type = threat.threat_type
                    t_gid = threat.group_id
                    since_str = threat.since
                    if not since_str:
                        continue
                    is_pred = getattr(threat, "is_predictive", False)
                    if is_pred:
                        pred_eta = getattr(threat, "eta_seconds", None) or 1800
                        delay = pred_eta + 300  # ETA + 5 minutes grace period
                    else:
                        delay, _ = self._get_threat_type_delay_and_eta(t_type)
                            
                    try:
                        since_str_normalized = since_str.replace("Z", "+00:00")
                        since_dt = datetime.fromisoformat(since_str_normalized)
                        elapsed = (datetime.now(timezone.utc) - since_dt).total_seconds()
                        remaining = delay - elapsed
                        
                        if is_pred:
                            if remaining <= 0:
                                # Process immediately via reevaluation instead of silent clear
                                self._schedule_predictive_reevaluation(region, 5.0, t_type, t_gid)
                                print(f"⏳ Предиктивна загроза для {region} (тип: {t_type}) застаріла під час офлайну. Заплановано миттєву переоцінку.")
                            else:
                                self._schedule_predictive_reevaluation(region, remaining, t_type, t_gid)
                                print(f"⏳ Відновлено таймер переоцінки предиктивної загрози для {region} (тип: {t_type}) через {int(remaining)} сек.")
                        else:
                            if remaining <= 0:
                                self.threat_manager.clear_threat(region, threat_type=t_type, group_id=t_gid)
                                print(f"⏳ Офіційна загроза для {region} (тип: {t_type}) застаріла під час офлайну. Очищено.")
                            else:
                                self._schedule_auto_clear(region, remaining, threat_type=t_type, group_id=t_gid)
                                print(f"⏳ Заплановано автозняття загрози для {region} (тип: {t_type}) через {int(remaining)} сек.")
                                
                                # Re-arm ETA escalation if ETA hasn't fired yet
                                eta_sec = getattr(threat, "eta_seconds", None)
                                is_official = getattr(state, "_is_official_active", False)
                                if eta_sec and eta_sec > 0 and not is_official and not threat.is_test:
                                    since_str_n = since_str.replace("Z", "+00:00")
                                    since_dt2 = datetime.fromisoformat(since_str_n)
                                    elapsed2 = (datetime.now(timezone.utc) - since_dt2).total_seconds()
                                    eta_remaining = eta_sec - elapsed2
                                    if eta_remaining > 0:
                                        self._schedule_eta_escalation(region, eta_remaining, threat.level, t_type, t_gid)
                                    else:
                                        # ETA already expired while offline — escalate immediately
                                        self._execute_eta_escalation_callback(region, t_type, t_gid, threat.level)
                                        print(f"🚨 [ETA-Escalation] ETA для {region} (тип: {t_type}) вже минув під час офлайну — миттєва ескалація.")
                    except Exception as e:
                        print(f"⚠️ Помилка відновлення таймерів для {region}: {e}")
                        if is_pred:
                            self._schedule_predictive_reevaluation(region, float(delay), t_type, t_gid)
                        else:
                            self._schedule_auto_clear(region, float(delay), threat_type=t_type, group_id=t_gid)

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

    async def _confidence_decay_loop(self):
        """
        Фоновий цикл загасання довіри (Confidence Decay).
        Кожні 60 секунд перевіряє загрози. Якщо загроза не оновлювалася > 10 хвилин,
        зменшує confidence на 10%. Якщо confidence < 20%, виконує авто-очищення (lost_contact).
        """
        while self.is_running:
            try:
                await asyncio.sleep(60)
                self._apply_confidence_decay_step()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"⚠️  [Confidence Decay] Помилка в циклі загасання: {e}")

    def _apply_confidence_decay_step(self):
        """Виконує один крок перевірки та зменшення довіри загроз."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        
        for region, state in list(self.threat_manager.threats.items()):
            if state.level == "none" or not state.active_threats:
                continue
                
            for threat in list(state.active_threats):
                updated_str = getattr(threat, "last_updated_at", None) or threat.since
                if not updated_str:
                    continue
                    
                try:
                    dt_updated = datetime.fromisoformat(updated_str.replace("Z", "+00:00"))
                    idle_seconds = (now - dt_updated).total_seconds()
                except Exception:
                    continue
                    
                if idle_seconds >= 600:
                    old_conf = threat.confidence or 50
                    new_conf = threat.apply_confidence_decay(10)
                    print(f"📉 [Confidence Decay] {region} ({threat.threat_type}): confidence {old_conf}% -> {new_conf}% (немає оновлень {int(idle_seconds/60)} хв)")
                    
                    if new_conf < 20:
                        print(f"🧹 [Confidence Decay] {region} ({threat.threat_type}): confidence < 20% -> авто-зняття (lost_contact)")
                        clearing_telemetry = {
                            "linked_group_id": threat.group_id,
                            "resolution_type": "lost_contact",
                            "prediction_accuracy_hint": "overestimated",
                            "damage_assessment": "none",
                            "impact_confirmed": False,
                            "clearing_context_tags": ["confidence_decay", "lost_contact"]
                        }
                        try:
                            from database.analytics_db import log_clearing_to_db
                            log_clearing_to_db(
                                region=region,
                                clearing_telemetry=clearing_telemetry,
                                source_channel="ConfidenceDecay",
                                message_text="[Decay] Втрачено контакт з ціллю (відсутні оновлення понад 15 хв).",
                                clearing_confidence=new_conf,
                                was_predictive=threat.is_predictive
                            )
                        except Exception:
                            pass
                        self.threat_manager.clear_threat(
                            region,
                            clearing_telemetry=clearing_telemetry,
                            threat_type=threat.threat_type,
                            group_id=threat.group_id
                        )

    def _handle_cross_region_transit(self, source_region: str, target_region: str, threat_type: str, group_id: str = None):
        """
        Автоматично обробляє транзит загрози із source_region у target_region.
        Знімає/знижує загрозу у source_region (passed_through) і передає у target_region.
        """
        from core.regions import ALL_REGIONS
        if not source_region or source_region not in ALL_REGIONS:
            return
        if not target_region or target_region not in ALL_REGIONS or source_region == target_region:
            return

        source_state = self.threat_manager.threats.get(source_region)
        if not source_state or source_state.level == "none":
            return

        matching_threat = None
        for t in source_state.active_threats:
            if t.threat_type == threat_type:
                if group_id is None or t.group_id == group_id:
                    matching_threat = t
                    break

        if matching_threat:
            print(f"🔄 [Cross-Region Transit] Ціль ({threat_type}) перейшла з {source_region} → {target_region}. Очищаємо {source_region}...")
            clearing_telemetry = {
                "linked_group_id": group_id or matching_threat.group_id,
                "resolution_type": "passed_through",
                "prediction_accuracy_hint": "confirmed",
                "damage_assessment": "none",
                "impact_confirmed": False,
                "clearing_context_tags": ["cross_region_transit", f"to_{target_region}"]
            }
            try:
                from database.analytics_db import log_clearing_to_db
                log_clearing_to_db(
                    region=source_region,
                    clearing_telemetry=clearing_telemetry,
                    source_channel="CrossRegionTransit",
                    message_text=f"[Транзит] Ціль перейшла в {target_region}.",
                    clearing_confidence=matching_threat.confidence,
                    was_predictive=matching_threat.is_predictive
                )
            except Exception:
                pass
            self.threat_manager.clear_threat(
                source_region,
                clearing_telemetry=clearing_telemetry,
                threat_type=threat_type,
                group_id=group_id or matching_threat.group_id
            )
