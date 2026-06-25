// УЗД-протокол МВП — бекенд
// Викликає Claude Code CLI у headless-режимі (`claude -p`),
// авторизований через вашу підписку Claude Max. Жодних API-ключів.

const express = require("express");
const multer = require("multer");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

// Завантажуємо секрети з .env (якщо файл є) — без зовнішніх залежностей.
// Файл .env у .gitignore і в репозиторій не потрапляє.
(() => {
  try {
    const envPath = path.join(__dirname, ".env");
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
      const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*?)\s*$/);
      if (m && m[1] && !line.trim().startsWith("#") && !(m[1] in process.env)) {
        process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
      }
    }
  } catch (_) { /* ігноруємо — спрацюють значення за замовчуванням */ }
})();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ───────────────────────── Аналітика ─────────────────────────
// Пишемо ЛИШЕ події і числа (тривалість, час генерації, оцінка).
// Текст диктовок / протоколів НІКОЛИ не логуються.

// Секретний ключ доступу до статистики — береться з .env (ADMIN_KEY).
// Значення за замовчуванням лишене, щоб сайт не зламався, якщо .env відсутній.
const ADMIN_KEY = process.env.ADMIN_KEY || "admtest";

const ANALYTICS_FILE = path.join(__dirname, "analytics.jsonl");
const ALLOWED_EVENTS = new Set([
  "visit", "rec_start", "rec_stop", "transcribe",
  "generate", "generate_ok", "generate_err",
  "export_word", "export_pdf", "export_copy", "rating",
]);

// Витягуємо логін з Basic Auth (його ставить nginx: test, test2...)
function getAuthUser(req) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Basic ")) return "невідомо";
    return Buffer.from(h.slice(6), "base64").toString("utf8").split(":")[0] || "невідомо";
  } catch (_) { return "невідомо"; }
}

function logEvent(uid, event, value, user) {
  const row = JSON.stringify({
    t: Date.now(),
    uid: String(uid || "anon").slice(0, 40),
    user: String(user || "невідомо").slice(0, 40),
    event,
    value: typeof value === "number" ? value : null,
  });
  fs.appendFile(ANALYTICS_FILE, row + "\n", () => {});
}

app.post("/api/track", (req, res) => {
  const { uid, event, value } = req.body || {};
  if (!ALLOWED_EVENTS.has(event)) return res.status(400).json({ ok: false });
  logEvent(uid, event, value, getAuthUser(req));
  res.json({ ok: true });
});

app.get("/stats", (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(403).send("Доступ заборонено");
  res.sendFile(path.join(__dirname, "stats.html"));
});

app.get("/api/stats", (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: "forbidden" });
  let rows = [];
  try {
    rows = fs.readFileSync(ANALYTICS_FILE, "utf8")
      .split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch (_) { return null; } })
      .filter(Boolean);
  } catch (_) { /* файлу ще немає */ }

  // Список усіх користувачів — до фільтрації
  const allUsers = [...new Set(rows.map((r) => r.user || "—"))].sort();

  // Фільтр по конкретному користувачу: /api/stats?key=...&user=test
  const filterUser = req.query.user;
  if (filterUser) rows = rows.filter((r) => (r.user || "—") === filterUser);

  const uniq = new Set();
  const days = {};
  const users = {};
  const sum = {
    visits: 0, recStarts: 0, recStops: 0, recSecTotal: 0,
    gen: 0, genOk: 0, genErr: 0, genSecTotal: 0,
    word: 0, pdf: 0, copy: 0,
    ratingTotal: 0, ratingCount: 0, ratingDist: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
  };

  function userOf(r) {
    const k = r.user || "—";
    users[k] = users[k] || { visits: 0, recordings: 0, recSec: 0, protocols: 0, errors: 0, exports: 0, ratingTotal: 0, ratingCount: 0 };
    return users[k];
  }

  for (const r of rows) {
    uniq.add(r.uid);
    const d = new Date(r.t).toISOString().slice(0, 10);
    days[d] = days[d] || { visits: 0, recordings: 0, protocols: 0, exports: 0 };
    const u = userOf(r);
    switch (r.event) {
      case "visit": sum.visits++; days[d].visits++; u.visits++; break;
      case "rec_start": sum.recStarts++; break;
      case "rec_stop":
        sum.recStops++; days[d].recordings++; u.recordings++;
        if (r.value) { sum.recSecTotal += r.value; u.recSec += r.value; } break;
      case "generate": sum.gen++; break;
      case "generate_ok":
        sum.genOk++; days[d].protocols++; u.protocols++;
        if (r.value) sum.genSecTotal += r.value; break;
      case "generate_err": sum.genErr++; u.errors++; break;
      case "export_word": sum.word++; days[d].exports++; u.exports++; break;
      case "export_pdf": sum.pdf++; days[d].exports++; u.exports++; break;
      case "export_copy": sum.copy++; days[d].exports++; u.exports++; break;
      case "rating":
        if (r.value >= 1 && r.value <= 5) {
          sum.ratingTotal += r.value; sum.ratingCount++;
          sum.ratingDist[Math.round(r.value)]++;
          u.ratingTotal += r.value; u.ratingCount++;
        }
        break;
    }
  }

  res.json({
    users: allUsers,
    filteredBy: filterUser || null,
    uniqueDevices: uniq.size,
    visits: sum.visits,
    recordings: sum.recStops,
    avgRecordingSec: sum.recStops ? Math.round(sum.recSecTotal / sum.recStops) : 0,
    protocolsGenerated: sum.genOk,
    generateErrors: sum.genErr,
    avgGenerateSec: sum.genOk ? Math.round(sum.genSecTotal / sum.genOk) : 0,
    exports: { word: sum.word, pdf: sum.pdf, copy: sum.copy },
    rating: {
      avg: sum.ratingCount ? Math.round(sum.ratingTotal / sum.ratingCount * 10) / 10 : null,
      count: sum.ratingCount,
      dist: sum.ratingDist,
    },
    byUser: users,
    byDay: days,
  });
});

const SYSTEM_PROMPT = `Ти — медичний редактор, що оформлює протоколи ультразвукового дослідження українською мовою.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

Твоє завдання:
1. Структурувати текст у стандартний протокол УЗД з розділами, що відповідають продиктованому типу дослідження (наприклад ОЧП: Печінка, Жовчний міхур, Підшлункова залоза, Селезінка, Нирки; або інший тип, якщо з диктовки зрозуміло інше).
2. Нормалізувати числа й одиниці: "сто сорок два міліметри" -> "142 мм", "чотири на шість" -> "4 × 6 мм".
3. Виправити очевидно покалічені розпізнаванням медичні терміни, ЛИШЕ якщо з контексту однозначно зрозуміло, що малося на увазі.
4. Якщо слово/число сумнівне або термін неоднозначний — залиши його і додай позначку [?] одразу після нього.
5. КАТЕГОРИЧНО ЗАБОРОНЕНО вигадувати дані: розміри, структури, висновки, яких немає в диктовці. Якщо розділ не згадано — не додавай його. Якщо параметр не названо — не пиши "норма" і не підставляй типове значення.
6. Якщо лікар продиктував заключення — оформи його в кінці розділом "ВИСНОВОК". Якщо ні — додай порожній розділ "ВИСНОВОК:" без тексту.

Формат відповіді: ЛИШЕ HTML-фрагмент (без <html>, <head>, <body>, без markdown, без пояснень):
- <h2> для назви дослідження
- <h3> для розділів (назви органів, ВИСНОВОК)
- <p> для тексту
Нічого, крім цього HTML-фрагмента, не виводь.`;

// ───────────── Промпт для test3: дитяча ехокардіографія у вигляді таблиць ─────────────
// Результат — лише HTML-таблиці, БЕЗ даних пацієнта. Структура жорстко задана нижче;
// модель лише підставляє продиктовані значення у відповідні клітинки.
const SYSTEM_PROMPT_TESTER3 = `Ти — медичний редактор, що оформлює протокол ДИТЯЧОЇ ЕХОКАРДІОГРАФІЇ українською мовою у вигляді HTML-ТАБЛИЦЬ.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КАТЕГОРИЧНІ ПРАВИЛА ДАНИХ:
1. БЕЗ даних пацієнта: НЕ додавай ПІБ, вік, стать, вагу, зріст, дату — нічого з цього.
2. Підставляй ЛИШЕ продиктовані числа та факти. Числа нормалізуй: "два цілих три" → "2,3"; "сто сорок два" → "142"; десятковий роздільник — кома; розміри "чотири на шість" → "4 × 6".
3. Якщо параметр НЕ продиктовано — постав [не вказано]. НЕ вигадуй розмірів, швидкостей, ФВ тощо.
4. Z-score/SD і градієнти (ΔР), якщо НЕ названо — лишай порожні дужки: "Z,SD = ( )" та "ΔР max ... = ( )".
5. Якісні/анатомічні формулювання в шаблоні нижче — це НОРМАЛЬНІ значення за замовчуванням. Лишай їх як є, АЛЕ якщо в диктовці названо патологію чи інше — ЗАМІНИ формулювання на продиктоване.
6. Сумнівне розпізнавання познач [?] одразу після слова/числа.
7. Нічого зайвого не додавай: жодних розділів чи рядків поза шаблоном.

ФОРМАТ HTML (лише фрагмент: без <html>, <head>, <body>, без markdown, без пояснень, без \`\`\`):
- Заголовок усього: <h2>Ехокардіографічне обстеження</h2>
- Назва кожного блоку: <h3>
- Кожен блок — окрема <table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">.
- Кожна <td> і <th>: style="border:1px solid #999;padding:6px 10px;vertical-align:top". <th> додатково: text-align:left;background:#f0f0f0.
- Назви парних структур — у <th> (двоколонкові таблиці).

ВИКОРИСТАЙ РІВНО ТАКУ СТРУКТУРУ (підстав значення у місця з [не вказано]/( ); якісні значення заміни лише за наявності патології в диктовці):

<h2>Ехокардіографічне обстеження</h2>

<h3>Анатомія</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Розташування передсердь</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Solitus</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Розташування серця</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Лівокардія</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Серце</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">двошлуночкове</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">АВ-сполучення</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">конкордантне</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ШлА-сполучення</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">конкордантне</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Хід магістральних судин</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">перехресний</td></tr>
</table>

<h3>Передсердя</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Праве передсердя</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Ліве передсердя</th></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">розмір: [не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">розмір: [не вказано]</td></tr>
</table>

<h3>Вени та перетинки</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Порожнисті вени</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">впадають</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Легеневі вени</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">впадають всі</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Безіменна вена</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">наявна, діаметр [не вказано]</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Додаткова ВПВ</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">немає</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Міжпередсердна перетинка</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">інтактна</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Коронарний синус</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">не розширений</td></tr>
</table>

<h3>Атріовентрикулярні клапани</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Тристулковий клапан</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Мітральний клапан</th></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">діаметр: [не вказано] мм (Z,SD = ( ); N = [не вказано] мм)</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">діаметр: [не вказано] мм (Z,SD = ( ); N = [не вказано] мм)</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">швидкість: [не вказано] м/с</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">швидкість: [не вказано] м/с</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">недостатність: відсутня</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">недостатність: відсутня</td></tr>
</table>

<h3>Шлуночки</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Правий шлуночок</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Лівий шлуночок</th></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">порожнина не розширена</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">порожнина норма, до верхівки доходить</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">скоротливість добра</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">скоротливість добра</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">до верхівки доходить</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ФВ = [не вказано] %</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top"></td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">КДР = [не вказано]; КДО = [не вказано]; КДІ = [не вказано]</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top"></td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ТМШП = [не вказано]; ТЗСЛШ = [не вказано]</td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:6px 10px;vertical-align:top">Міжшлуночкова перетинка — інтактна</td></tr>
</table>

<h3>Магістральні судини</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Легенева артерія</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Аорта</th></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">клапан ЛА: [не вказано] мм (Z,SD = ( ); N = [не вказано] мм)</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">клапан Ао: [не вказано] мм (Z,SD = ( ); N = [не вказано] мм)</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">стовбур ЛА: [не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">синус Вальсальви: [не вказано]</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">права гілка ЛА: [не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ST-сполучення: [не вказано]</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ліва гілка ЛА: [не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">клапан Ао тристулковий</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ΔР max клапан = ( ) мм.рт.ст</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ΔР max клапан = ( ) мм.рт.ст</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">недостатність: відсутня</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">недостатність: відсутня</td></tr>
</table>

<h3>Додатково</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Відкрита артеріальна протока</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">відсутня</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Легенева гіпертензія</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">відсутня</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Рідина в перикарді</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">відсутня</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Кровотік у черевній аорті</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">пульсуючий</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Коронарні артерії</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">без особливостей</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Дуга аорти</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">ΔР max = ( ); дуга лівостороння; коарктації немає</td></tr>
</table>

<h3>Додаткові дані</h3>
<p>[заповни за диктовкою; якщо нічого не продиктовано — [не вказано]]</p>

<h3>Висновок</h3>
<p>[за диктовкою; якщо висновок не продиктовано — «Даних за структурну патологію серця немає»]</p>

Нічого, крім цього HTML-фрагмента, не виводь.`;

// ───────────── Промпт для test4: протокол УЗД щитоподібної залози ─────────────
// Структурований протокол (h2/h3/p + таблиця розмірів часток). БЕЗ даних пацієнта.
// Жорстко заборонено вигадувати числа й висновки — лише те, що продиктовано.
const SYSTEM_PROMPT_TESTER4 = `Ти — медичний редактор, що оформлює протокол УЗД ЩИТОПОДІБНОЇ ЗАЛОЗИ українською мовою.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КАТЕГОРИЧНІ ПРАВИЛА ДАНИХ:
1. БЕЗ даних пацієнта: НЕ додавай ПІБ, вік, стать, дату — нічого з цього.
2. Підставляй ЛИШЕ продиктовані числа та факти. Числа нормалізуй: "два цілих три" → "2,3"; "сто сорок два" → "142"; десятковий роздільник — кома; розміри "сорок чотири на п'ятнадцять на тринадцять" → "44 × 15 × 13 мм".
3. Якщо параметр НЕ продиктовано — постав [не вказано]. НЕ вигадуй розмірів, об'ємів, ехогенності, висновків тощо. Якщо розділ узагалі не згадано в диктовці — пропусти його.
4. Об'єм часток рахуй ЛИШЕ якщо продиктовано всі три розміри (формула еліпсоїда: довжина × ширина × товщина × 0,479, у см³); якщо хоч один розмір відсутній — постав [не вказано], нічого не додумуй.
5. Якісні формулювання-замовчування у шаблоні (контури, ехоструктура, ехогенність тощо) лишай ЛИШЕ якщо лікар прямо підтвердив норму або не сказав інше; якщо продиктовано патологію — ЗАМІНИ на продиктоване.
6. Вузли описуй ЛИШЕ ті, що продиктовані: локалізація, розміри, ехоструктура, контури, кальцинати, кровотік, за наявності — категорія TI-RADS (лише якщо названа лікарем). Якщо вузлів не згадано — напиши "Вогнищевих утворень не виявлено" ТІЛЬКИ якщо лікар це підтвердив; інакше [не вказано].
7. Сумнівне розпізнавання познач [?] одразу після слова/числа.

Формат відповіді: ЛИШЕ HTML-фрагмент (без <html>, <head>, <body>, без markdown, без \`\`\`, без пояснень):
- <h2>УЗД щитоподібної залози</h2>
- <h3> для розділів
- <p> для тексту
- для розмірів часток використай <table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">, кожна <td>/<th> зі style="border:1px solid #999;padding:6px 10px;vertical-align:top", <th> додатково text-align:left;background:#f0f0f0.

ОРІЄНТОВНА СТРУКТУРА (розділи, яких немає в диктовці, — пропускай; значення-плейсхолдери заповнюй за диктовкою або став [не вказано]):

<h2>УЗД щитоподібної залози</h2>

<h3>Розміри та об'єм</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 14px">
<tr><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Частка</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Розміри (Д × Ш × Т)</th><th style="border:1px solid #999;padding:6px 10px;text-align:left;background:#f0f0f0">Об'єм</th></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Права</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">[не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">[не вказано] см³</td></tr>
<tr><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">Ліва</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">[не вказано]</td><td style="border:1px solid #999;padding:6px 10px;vertical-align:top">[не вказано] см³</td></tr>
</table>
<p>Перешийок: [не вказано] мм. Сумарний об'єм: [не вказано] см³.</p>

<h3>Структура</h3>
<p>Контури: [не вказано]. Ехоструктура: [не вказано]. Ехогенність: [не вказано].</p>

<h3>Вогнищеві утворення</h3>
<p>[опиши продиктовані вузли: локалізація, розміри, ехоструктура, контури, кальцинати, кровотік, TI-RADS — якщо названо; інакше [не вказано]]</p>

<h3>Кровотік (ЦДК)</h3>
<p>[не вказано]</p>

<h3>Регіонарні лімфатичні вузли</h3>
<p>[не вказано]</p>

<h3>ВИСНОВОК</h3>
<p>[за диктовкою; якщо висновок не продиктовано — лиши розділ порожнім]</p>

Нічого, крім цього HTML-фрагмента, не виводь.`;

// Вибір промпта за логіном Basic Auth. Для test3 — ехокардіографія таблицями;
// для test4 — щитоподібна залоза; для всіх інших — стандартний SYSTEM_PROMPT.
const PROMPTS_BY_USER = {
  test3: SYSTEM_PROMPT_TESTER3,
  test4: SYSTEM_PROMPT_TESTER4,
};

// ───────────────────────── Транскрипція (Whisper через Groq) ─────────────────────────
// Приймає аудіо (multipart, поле "audio") від будь-якого клієнта — веб, PWA, майбутній
// десктоп — і повертає розпізнаний текст. Модель large-v3 обробляє весь запис із
// контекстом, тому добре ловить швидку мову й медтерміни. Текст аудіо НІКОЛИ не логуємо.
const uploadAudio = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 26 * 1024 * 1024 }, // ~25 МБ — ліміт файлу Groq
});

// Підказка-словник для Whisper: задає домен (УЗД) і написання термінів — підвищує точність.
const UZD_PROMPT = [
  "Протокол ультразвукового дослідження (УЗД).",
  "Терміни: ехогенність, ехоструктура, паренхіма, контури, капсула, кровоток, доплер,",
  "печінка, жовчний міхур, підшлункова залоза, селезінка, нирки, сечовий міхур,",
  "щитоподібна залоза, перешийок, вузол, лімфовузли, ехокардіографія, передсердя,",
  "шлуночок, мітральний клапан, тристулковий клапан, аорта, легенева артерія,",
  "фракція викиду, градієнт, регургітація. Розміри в міліметрах і сантиметрах.",
].join(" ");

app.post("/api/transcribe", uploadAudio.single("audio"), async (req, res) => {
  if (!process.env.GROQ_API_KEY) {
    return res.status(500).json({ error: "Транскрипція не налаштована: відсутній GROQ_API_KEY на сервері." });
  }
  if (!req.file || !req.file.buffer || !req.file.buffer.length) {
    return res.status(400).json({ error: "Порожній аудіофайл." });
  }

  try {
    const form = new FormData();
    const blob = new Blob([req.file.buffer], { type: req.file.mimetype || "audio/webm" });
    form.append("file", blob, req.file.originalname || "audio.webm");
    form.append("model", "whisper-large-v3");
    form.append("language", "uk");
    form.append("prompt", UZD_PROMPT);
    form.append("temperature", "0");
    form.append("response_format", "json");

    const r = await fetch("https://api.groq.com/openai/v1/audio/transcriptions", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.GROQ_API_KEY}` },
      body: form,
    });

    if (!r.ok) {
      const detail = (await r.text().catch(() => "")).slice(0, 300);
      return res.status(502).json({ error: "Помилка розпізнавання (Groq)." + (detail ? " Деталі: " + detail : "") });
    }

    const data = await r.json();
    res.json({ text: (data.text || "").trim() });
  } catch (err) {
    res.status(500).json({ error: "Не вдалося розпізнати аудіо: " + (err.message || "невідома помилка") });
  }
});

app.post("/api/protocol", (req, res) => {
  const raw = (req.body && req.body.text || "").trim();
  if (!raw) {
    return res.status(400).json({ error: "Порожній текст диктовки." });
  }

  const user = getAuthUser(req);
  const systemPrompt = PROMPTS_BY_USER[user] || SYSTEM_PROMPT;
  const prompt = systemPrompt + "\n\n--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw;

  // claude -p читає промпт зі stdin; --output-format text повертає чистий текст
  const child = spawn("claude", ["-p", "--output-format", "text"], {
    env: process.env,
    timeout: 180000,
  });

  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));

  child.on("error", () => {
    res.status(500).json({
      error: "Не вдалося запустити Claude Code. Перевірте: npm i -g @anthropic-ai/claude-code і логін через підписку (команда: claude).",
    });
  });

  child.on("close", (code) => {
    if (res.headersSent) return;
    if (code !== 0 || !out.trim()) {
      return res.status(500).json({
        error: "Claude не повернув результат. " + (err.trim() ? "Деталі: " + err.trim().slice(0, 300) : "Можливо, вичерпано ліміт підписки Max — спробуйте пізніше."),
      });
    }
    // Прибираємо можливі markdown-обгортки ```html ... ```
    const html = out.trim().replace(/^```(?:html)?\s*/i, "").replace(/```\s*$/, "");
    res.json({ html });
  });

  child.stdin.write(prompt);
  child.stdin.end();
});

app.listen(PORT, () => {
  console.log(`УЗД МВП працює: http://localhost:${PORT}`);
});
