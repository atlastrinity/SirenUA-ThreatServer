import os
import json
import google.generativeai as genai
from typing import List, Dict, Any

class GeminiThreatAnalyzer:
    def __init__(self):
        # Configure Gemini
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if api_key:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
            self.is_configured = True
        else:
            self.is_configured = False
            print("⚠️ GEMINI_API_KEY is not set. GeminiAnalyzer will run in mock mode.")

        self.system_prompt = """Ти — спеціалізований військовий ШІ-аналітик (SirenUA Threat Intelligence).
Твоє завдання: глибоко аналізувати батч повідомлень із Telegram-каналів і формувати JSON із виявленими загрозами.

УРОК НА ГЛИБОКИЙ АНАЛІЗ (Словник та Закономірності):
1. **Типи загроз**:
   - "мопеди", "бляшанки", "шахеди", "бпла" -> shahed
   - "балістика", "іскандер" -> ballistic
   - "кинджал", "міг-31к", "зліт міг" -> mig31k
   - "каб", "керовані авіабомби" -> kab
   - "крилата ракета", "х-101", "калібр" -> cruise_missile
2. **Вектори та Азимути (Транзитна географія)**:
   - Якщо вказано "Рух з Сумщини на захід/північний захід", ціль може прямувати через Чернігівську або Київську області. Додавай їх до `target_regions` з поміткою `is_predictive: true`.
   - "з Сум на Київ" -> source: Сумська, target: Київська. Проміжні області: Чернігівська, Полтавська.
3. **Оцінка Довіри (Confidence Score)**:
   - Якщо повідомлення з офіційних джерел (kpszsu), або текст виглядає дуже чітким (вказана висота, курс) -> 90-100%.
   - Якщо це радар-канал (monitorwarr) і текст загальний -> 60-80%.
4. **Відбої**:
   - Слова "чисто", "відбій", "дорозвалюються", "зникли" -> is_clear: true для цих областей.
   - Слова "область/всі області" + "відбій" -> target_regions порожній, is_clear: true

ВИМОГИ ДО ФОРМАТУ (Strict JSON Array):
Ти повинен повернути ТІЛЬКИ JSON масив без markdown обгорток.
Кожен об'єкт має структуру:
{
  "source_channel": "назва каналу",
  "text": "оригінальний текст",
  "threat_level": "none" | "low" | "medium" | "high" | "critical",
  "threat_type": "shahed" | "ballistic" | "mig31k" | "kab" | "cruise_missile" | null,
  "source_regions": ["Сумська область"],
  "target_regions": [{"name": "Київська область", "is_predictive": false}, {"name": "Чернігівська область", "is_predictive": true}],
  "is_clear": false,
  "confidence_score": 85
}
Якщо повідомлень кілька, поверни масив з результатами для кожного повідомлення.
"""

    async def analyze_batch(self, messages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        if not messages:
            return []
            
        if not self.is_configured:
            # Fallback/Mock behavior if no API key is provided
            print("⚠️ Gemini in MOCK mode: Returning empty analysis.")
            return []

        prompt = self.system_prompt + "\n\nОСЬ ПОВІДОМЛЕННЯ ДЛЯ АНАЛІЗУ:\n"
        for msg in messages:
            prompt += f"Канал: {msg['channel']}\nТекст: {msg['text']}\n---\n"

        try:
            response = await self.model.generate_content_async(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    response_mime_type="application/json",
                )
            )
            
            result_text = response.text
            if result_text.startswith("```json"):
                result_text = result_text.split("```json", 1)[1]
            if result_text.endswith("```"):
                result_text = result_text.rsplit("```", 1)[0]
                
            return json.loads(result_text.strip())
        except Exception as e:
            print(f"❌ Gemini API Error: {e}")
            return []
