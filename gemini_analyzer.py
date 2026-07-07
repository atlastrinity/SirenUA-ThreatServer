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
            self.model = genai.GenerativeModel('gemini-flash-latest')
            self.is_configured = True
            self.last_error = None
        else:
            self.is_configured = False
            self.last_error = "API key missing"
            print("⚠️ GEMINI_API_KEY is not set. GeminiAnalyzer will run in mock mode.")

        self.system_prompt = """Ти — спеціалізований військовий ШІ-аналітик (SirenUA Threat Intelligence).
Твоє завдання: глибоко аналізувати батч повідомлень із Telegram-каналів і формувати JSON із виявленими загрозами.

ВИМОГИ ДО АНАЛІЗУ ДЛЯ ВИЗНАЧЕННЯ ОБЛАСТЕЙ (Target Regions & Predictiveness):
Тобі потрібно застосувати чотири типи аналізу, щоб зрозуміть, які області додавати до `target_regions` та чи ставити для них прапорець `is_predictive` (предиктивна загроза):

1. **Географічний транзит (Transit Geography)**:
   - Якщо ціль летить з однієї області в іншу (наприклад, "БпЛА з Сумщини в напрямку Київщини"), обов'язково додавай проміжні транзитні області (наприклад, Чернігівську та Полтавську) до `target_regions` з `is_predictive: true`.

2. **Профілювання стратегічних цілей (Strategic Target Profiling)**:
   - При виявленні загрози крилатих ракет (пуск з Ту-95МС, Ту-22М3, Kalibr з Чорного моря) потенційна небезпека існує для всієї країни. Проте, ти маєш позначити основні історичні цілі ударів (Київська, Львівська, Харківська, Дніпропетровська, Одеська, Хмельницька області) як `is_predictive: true` із середнім рівнем впевненості (50-65%) на ранній стадії пусків, поки ракети ще летять або не змінили курс.

3. **Тактичний ризик близькості до кордону та лінії фронту (Border Proximity Risk)**:
   - Якщо повідомляється про зліт тактичної авіації (наприклад, Су-34/Су-35) біля кордонів чи над Азовським/Чорним морем, або про пускові установки С-300/С-400 у прикордонних областях РФ:
     - Прикордонні та прифронтові області (Сумська, Харківська, Чернігівська, Запорізька, Херсонська, Донецька) мають автоматично маркуватися як `is_predictive: true` (навіть якщо конкретна ціль ще не перетнула кордон) з типом загрози `kab` або `ballistic` відповідно.

4. **Балістична кінематика (Ballistic Kinematics)**:
   - При пусках балістики (наприклад, "пуск Іскандера з Криму/Бєлгорода") час підльоту критично малий (2-5 хв). Ти повинен автоматично позначити всі області в радіусі досяжності пускового сектора (наприклад, при пуску з Криму: Херсонська, Миколаївська, Одеська, Запорізька, Кіровоградська) як `is_predictive: true` або `is_predictive: false` (якщо вони безпосередньо вказані в повідомленні).

ОЦІНКА ДОВІРИ (Confidence Score) ТА РІВЕНЬ ЗАГРОЗИ:
- 90-100%: Офіційні джерела (kpszsu), або повідомлення з точними координатами, курсом, типом ракет.
- 75-89%: Надійні радарні канали (monitorwarr) з конкретними даними про рух цілей.
- 60-74%: Загальні повідомлення радарів без деталізації або предиктивні регіони (is_predictive: true) на шляху слідування.
- 40-59%: Непідтверджена інформація, предиктивні цілі на великій відстані (стратегічне профілювання).
- <40%: Чутки, нерелевантна інформація. Став `threat_level: "none"`.

ТИПИ ЗАГРОЗ ТА ОЧІКУВАНИЙ ЧАС (ETA):
- shahed (БПЛА): "~1-3 год" (швидкість ~150-180 км/год)
- cruise_missile (Х-101/Калібр): "~15-40 хв"
- ballistic (Іскандер): "~2-5 хв"
- mig31k (Кинджал): "~20-40 хв"
- kab (КАБ): "~5-15 хв"

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
  "confidence_score": 85,
  "eta": "~20-40 хв"
}
Якщо повідомлень кілька, поверни масив з результатами для кожного повідомлення.
ОБОВ'ЯЗКОВО повертай confidence_score та eta для КОЖНОГО результату!
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
                
            self.last_error = None
            return json.loads(result_text.strip())
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Gemini API Error: {error_msg}")
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower():
                self.last_error = "Rate Limit Exceeded (429)"
            else:
                self.last_error = error_msg
            return []
