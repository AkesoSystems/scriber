// УЗД-протокол МВП — бекенд
// Викликає Claude Code CLI у headless-режимі (`claude -p`),
// авторизований через вашу підписку Claude Max. Жодних API-ключів.

const express = require("express");
const multer = require("multer");
const Anthropic = require("@anthropic-ai/sdk");
const { BedrockRuntimeClient, ConverseCommand } = require("@aws-sdk/client-bedrock-runtime");
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
// Дефолт "admtest" вважається НЕзаданим: /stats і /api/stats тоді віддають 503
// (бо дашборд тепер показує детальну активність по кожному лікарю).
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const ADMIN_KEY_OK = ADMIN_KEY && ADMIN_KEY !== "admtest";
if (!ADMIN_KEY_OK) {
  console.error("[stats] ADMIN_KEY не заданий (або дефолтний) — /stats і /api/stats вимкнені до налаштування env.");
}

const ANALYTICS_FILE = path.join(__dirname, "analytics.jsonl");
const ALLOWED_EVENTS = new Set([
  "visit", "rec_start", "rec_stop", "transcribe_ok", "transcribe_err",
  "generate", "generate_ok", "generate_err",
  "export_word", "export_pdf", "export_copy", "rating",
]);

// ── Whitelist значень meta — PHI-firewall ──
// У analytics.jsonl потрапляють ЛИШЕ enum/числа з цих наборів. Жодного вільного тексту
// (Groq-body, .message, CLI stderr можуть містити фрагменти диктовки → ніколи не логуємо).
const EV_PROVIDERS = new Set(["bedrock", "anthropic", "cli"]);
const EV_STAGES = new Set(["transcribe", "generate"]);
const EV_CODES = new Set([
  "groq_badkey", "groq_empty", "groq_500", "groq_network",
  "bedrock_throttle", "bedrock_empty", "bedrock_timeout", "bedrock_throw",
  "anthropic_empty", "anthropic_throw",
  "cli_timeout", "cli_limit", "cli_notfound", "cli_empty",
  "no_provider", "network", "unknown",
]);
const EV_MODELS = new Set([
  "us.amazon.nova-pro-v1:0", "amazon.nova-pro-v1:0", "claude-opus-4-8", "claude-cli-max",
]);

// Захист від необмеженого росту файлу (volume — один файл, тому НЕ rollover, а обрізання
// найстаріших рядків з тим самим inode-шляхом). При 6 юзерах майже ніколи не спрацює.
const ANALYTICS_MAX_LINES = 500000;
let _appendsSinceTrim = 0;
function maybeTrimAnalytics() {
  if (++_appendsSinceTrim < 2000) return;
  _appendsSinceTrim = 0;
  try {
    const lines = fs.readFileSync(ANALYTICS_FILE, "utf8").split("\n").filter(Boolean);
    if (lines.length > ANALYTICS_MAX_LINES) {
      const tail = lines.slice(lines.length - ANALYTICS_MAX_LINES);
      fs.writeFileSync(ANALYTICS_FILE, tail.join("\n") + "\n");
    }
  } catch (_) { /* файлу ще нема або зайнятий — пропускаємо */ }
}

// Витягуємо логін з Basic Auth (його ставить nginx: test, test2...)
function getAuthUser(req) {
  try {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Basic ")) return "невідомо";
    return Buffer.from(h.slice(6), "base64").toString("utf8").split(":")[0] || "невідомо";
  } catch (_) { return "невідомо"; }
}

// meta — необов'язковий об'єкт; беремо ЛИШЕ whitelisted ключі (див. PHI-firewall вище).
function logEvent(uid, event, value, user, meta) {
  const row = {
    t: Date.now(),
    uid: String(uid || "anon").slice(0, 40),
    user: String(user || "невідомо").slice(0, 40),
    event,
    value: typeof value === "number" ? value : null,
  };
  if (meta && typeof meta === "object") {
    if (EV_PROVIDERS.has(meta.provider)) row.provider = meta.provider;
    if (EV_STAGES.has(meta.stage)) row.stage = meta.stage;
    if (meta.code !== undefined) row.code = EV_CODES.has(meta.code) ? meta.code : "unknown";
    if (EV_MODELS.has(meta.model)) row.model = meta.model;
    if (typeof meta.ms === "number" && isFinite(meta.ms) && meta.ms >= 0 && meta.ms <= 600000) {
      row.ms = Math.round(meta.ms);
    }
    if (meta.fallback === true) row.fallback = true;
  }
  fs.appendFile(ANALYTICS_FILE, JSON.stringify(row) + "\n", (err) => {
    if (err) console.error("[analytics] запис не вдався:", err.message);
  });
  maybeTrimAnalytics();
}

app.post("/api/track", (req, res) => {
  const { uid, event, value, provider, model, code, stage, ms, fallback } = req.body || {};
  if (!ALLOWED_EVENTS.has(event)) return res.status(400).json({ ok: false });
  // logEvent пересанітизує meta через whitelist — ворожий клієнт текст не вкине.
  logEvent(uid, event, value, getAuthUser(req), { provider, model, code, stage, ms, fallback });
  res.json({ ok: true });
});

// Ключ дня YYYY-MM-DD у Europe/Kyiv (стабільний для byDay/byUserDay/today).
function dayKey(t) {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/Kyiv", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(new Date(t));
}
// Різниця в календарних днях між двома ключами (a - b).
function dayDiff(aKey, bKey) {
  return Math.round((Date.parse(aKey) - Date.parse(bKey)) / 86400000);
}

app.get("/stats", (req, res) => {
  if (!ADMIN_KEY_OK) return res.status(503).send("Статистика не налаштована: задайте ADMIN_KEY у середовищі.");
  if (req.query.key !== ADMIN_KEY) return res.status(403).send("Доступ заборонено");
  res.sendFile(path.join(__dirname, "stats.html"));
});

app.get("/api/stats", (req, res) => {
  if (!ADMIN_KEY_OK) return res.status(503).json({ error: "stats_disabled" });
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
  const byUserDay = {};
  const errBy = { code: {}, provider: {}, stage: {} };
  const sum = {
    visits: 0, recStarts: 0, recStops: 0, recSecTotal: 0,
    gen: 0, genOk: 0, genErr: 0, genSecTotal: 0, genMsTotal: 0, genMsCount: 0,
    word: 0, pdf: 0, copy: 0,
    ratingTotal: 0, ratingCount: 0, ratingDist: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
  };

  function userOf(r) {
    const k = r.user || "—";
    users[k] = users[k] || { visits: 0, recordings: 0, recSec: 0, protocols: 0, errors: 0, exports: 0, ratingTotal: 0, ratingCount: 0 };
    return users[k];
  }
  function udOf(user, d) {
    byUserDay[user] = byUserDay[user] || {};
    byUserDay[user][d] = byUserDay[user][d] || { visits: 0, recordings: 0, protocols: 0, errors: 0, exports: 0 };
    return byUserDay[user][d];
  }
  function bumpErr(r) {
    if (r.code) errBy.code[r.code] = (errBy.code[r.code] || 0) + 1;
    if (r.provider) errBy.provider[r.provider] = (errBy.provider[r.provider] || 0) + 1;
    if (r.stage) errBy.stage[r.stage] = (errBy.stage[r.stage] || 0) + 1;
  }

  for (const r of rows) {
    uniq.add(r.uid);
    const d = dayKey(r.t);
    days[d] = days[d] || { visits: 0, recordings: 0, protocols: 0, exports: 0 };
    const u = userOf(r);
    const ud = udOf(r.user || "—", d);
    switch (r.event) {
      case "visit": sum.visits++; days[d].visits++; u.visits++; ud.visits++; break;
      case "rec_start": sum.recStarts++; break;
      case "rec_stop":
        sum.recStops++; days[d].recordings++; u.recordings++; ud.recordings++;
        if (r.value) { sum.recSecTotal += r.value; u.recSec += r.value; } break;
      case "generate": sum.gen++; break;
      case "generate_ok":
        // Рахуємо ВСІ generate_ok: історичні (старий клієнт, без provider) + нові (сервер, з provider).
        // Подвоєння нема — у тому ж релізі клієнтський generate_ok прибрано, тож рядок на протокол один.
        sum.genOk++; days[d].protocols++; u.protocols++; ud.protocols++;
        if (typeof r.ms === "number") { sum.genMsTotal += r.ms; sum.genMsCount++; }
        else if (r.value) sum.genSecTotal += r.value;
        break;
      case "generate_err": sum.genErr++; u.errors++; ud.errors++; bumpErr(r); break;
      case "transcribe_err": bumpErr(r); break;
      case "export_word": sum.word++; days[d].exports++; u.exports++; ud.exports++; break;
      case "export_pdf": sum.pdf++; days[d].exports++; u.exports++; ud.exports++; break;
      case "export_copy": sum.copy++; days[d].exports++; u.exports++; ud.exports++; break;
      case "rating":
        if (r.value >= 1 && r.value <= 5) {
          sum.ratingTotal += r.value; sum.ratingCount++;
          sum.ratingDist[Math.round(r.value)]++;
          u.ratingTotal += r.value; u.ratingCount++;
        }
        break;
    }
  }

  // Engagement per-user (із byUserDay) — «кому написати»
  const today = dayKey(Date.now());
  const engagement = Object.keys(byUserDay).map((user) => {
    const dmap = byUserDay[user];
    const activeDays = Object.keys(dmap).filter((d) => dmap[d].protocols > 0).sort();
    const lastActiveDay = activeDays.length ? activeDays[activeDays.length - 1] : null;
    let protocols7d = 0, protocols30d = 0;
    for (const d of Object.keys(dmap)) {
      const diff = dayDiff(today, d);
      if (diff >= 0 && diff <= 6) protocols7d += dmap[d].protocols;
      if (diff >= 0 && diff <= 29) protocols30d += dmap[d].protocols;
    }
    // Серія: послідовні календарні дні з протоколами, що закінчуються на lastActiveDay.
    let streak = 0;
    if (lastActiveDay) {
      const set = new Set(activeDays);
      let cur = lastActiveDay;
      while (set.has(cur)) { streak++; cur = dayKey(Date.parse(cur) - 86400000); }
    }
    const uu = users[user] || {};
    const protocols = uu.protocols || 0;
    const errors = uu.errors || 0;
    return {
      user,
      lastActiveDay,
      daysSinceActive: lastActiveDay ? dayDiff(today, lastActiveDay) : null,
      protocols7d, protocols30d,
      activeDaysStreak: streak,
      protocolsTotal: protocols,
      errorRate: (protocols + errors) ? Math.round(errors / (protocols + errors) * 100) : 0,
      avgRating: uu.ratingCount ? Math.round(uu.ratingTotal / uu.ratingCount * 10) / 10 : null,
    };
  }).sort((a, b) => {
    if (a.daysSinceActive === null) return 1;   // хто жодного протоколу — в кінець
    if (b.daysSinceActive === null) return -1;
    return b.daysSinceActive - a.daysSinceActive; // найбільш «затихлий» — перший
  });

  res.json({
    users: allUsers,
    filteredBy: filterUser || null,
    uniqueDevices: uniq.size,
    visits: sum.visits,
    recordings: sum.recStops,
    avgRecordingSec: sum.recStops ? Math.round(sum.recSecTotal / sum.recStops) : 0,
    protocolsGenerated: sum.genOk,
    generateErrors: sum.genErr,
    // Середній час: із серверного ms (точний, без RTT) для нових рядків, інакше зі старих секунд.
    avgGenerateSec: sum.genMsCount ? Math.round(sum.genMsTotal / sum.genMsCount / 1000)
      : (sum.genOk ? Math.round(sum.genSecTotal / sum.genOk) : 0),
    exports: { word: sum.word, pdf: sum.pdf, copy: sum.copy },
    rating: {
      avg: sum.ratingCount ? Math.round(sum.ratingTotal / sum.ratingCount * 10) / 10 : null,
      count: sum.ratingCount,
      dist: sum.ratingDist,
    },
    byUser: users,
    byDay: days,
    byUserDay,
    engagement,
    errors: {
      byCode: errBy.code, byProvider: errBy.provider, byStage: errBy.stage,
      total: sum.genErr,
      errorRate: (sum.genOk + sum.genErr) ? Math.round(sum.genErr / (sum.genOk + sum.genErr) * 100) : 0,
    },
  });
});

const SYSTEM_PROMPT = `Ти — медичний редактор, що оформлює протоколи ультразвукового дослідження українською мовою у вигляді СУЦІЛЬНОГО ОПИСУ.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

Твоє завдання:
1. Оформити текст як суцільний клінічний опис УЗД: один абзац на орган або ділянку, де назва органа стоїть НА ПОЧАТКУ речення (напр. "Печінка не збільшена, права частка — 135 мм…"). БЕЗ підзаголовків-органів, БЕЗ таблиць, БЕЗ лейблів із двокрапкою типу "Печінка:".
2. Нормалізувати числа й одиниці: "сто сорок два міліметри" -> "142 мм", "чотири на шість" -> "4 × 6 мм".
3. Виправити очевидно покалічені розпізнаванням медичні терміни, ЛИШЕ якщо з контексту однозначно зрозуміло, що малося на увазі.
4. Якщо слово/число сумнівне або термін неоднозначний — залиши його і додай позначку [?] одразу після нього.
5. КАТЕГОРИЧНО ЗАБОРОНЕНО вигадувати дані: розміри, структури, висновки, яких немає в диктовці. Якщо орган/ділянку не згадано — не додавай абзац про них. Якщо параметр не названо — не пиши "норма" і не підставляй типове значення.
6. Останнім абзацом завжди йде висновок, що починається зі слова "Висновок:". Якщо лікар продиктував заключення — постав його після "Висновок:". Якщо ні — лиши абзац порожнім (лише "Висновок:" без тексту).

Формат відповіді: ЛИШЕ HTML-фрагмент (без <html>, <head>, <body>, без markdown, без пояснень):
- <h2> — назва дослідження, підібрана за змістом диктовки (напр. "УЗД органів черевної порожнини", "УЗД щитоподібної залози"); тип дослідження бери лише з диктовки, не вигадуй.
- <p> — по одному абзацу на орган/ділянку суцільним текстом, і окремий <p> для висновку.
Жодних <h3>, жодних <table>. Нічого, крім цього HTML-фрагмента, не виводь.`;

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

// Вибір промпта за логіном Basic Auth. Для test2 — ехокардіографія таблицями;
// для test3 — щитоподібна залоза; для всіх інших (test і нові логіни) — стандартний SYSTEM_PROMPT.
const PROMPTS_BY_USER = {
  test2: SYSTEM_PROMPT_TESTER3, // ехокардіографія
  test3: SYSTEM_PROMPT_TESTER4, // щитоподібна залоза
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
  const user = getAuthUser(req);
  const uid = (req.body && req.body.uid) || "server";
  if (!process.env.GROQ_API_KEY) {
    logEvent(uid, "transcribe_err", null, user, { stage: "transcribe", code: "groq_badkey" });
    return res.status(500).json({ error: "Транскрипція не налаштована: відсутній GROQ_API_KEY на сервері." });
  }
  if (!req.file || !req.file.buffer || !req.file.buffer.length) {
    logEvent(uid, "transcribe_err", null, user, { stage: "transcribe", code: "groq_empty" });
    return res.status(400).json({ error: "Порожній аудіофайл." });
  }

  const t0 = Date.now();
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
      // Тіло помилки Groq показуємо лікарю, але НЕ логуємо (може містити фрагменти диктовки).
      const detail = (await r.text().catch(() => "")).slice(0, 300);
      logEvent(uid, "transcribe_err", null, user, { stage: "transcribe", code: "groq_500" });
      return res.status(502).json({ error: "Помилка розпізнавання (Groq)." + (detail ? " Деталі: " + detail : "") });
    }

    const data = await r.json();
    const ms = Date.now() - t0;
    logEvent(uid, "transcribe_ok", Math.round(ms / 1000), user, { stage: "transcribe", ms });
    res.json({ text: (data.text || "").trim() });
  } catch (err) {
    logEvent(uid, "transcribe_err", null, user, { stage: "transcribe", code: "groq_network" });
    res.status(500).json({ error: "Не вдалося розпізнати аудіо: " + (err.message || "невідома помилка") });
  }
});

// Прибирає можливі markdown-обгортки ```html ... ``` навколо HTML-фрагмента.
function stripFences(s) {
  return s.trim().replace(/^```(?:html)?\s*/i, "").replace(/```\s*$/, "");
}

// ── Провайдери формування протоколу (пріоритет: Bedrock → Anthropic API → Max CLI) ──
// Bedrock (AWS Converse) вмикається наявністю AWS_REGION + кредів; оплата AWS-кредитами.
// Модель задається BEDROCK_MODEL (за замовч. Amazon Nova Pro — доступна на кредитах одразу;
// коли розблокують Claude на Bedrock, достатньо змінити цю env, код той самий).
const bedrock = process.env.AWS_REGION
  ? new BedrockRuntimeClient({
      region: process.env.AWS_REGION,
      credentials: (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
        ? { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY }
        : undefined,
    })
  : null;
const BEDROCK_MODEL = process.env.BEDROCK_MODEL || "us.amazon.nova-pro-v1:0";
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic() : null;

// Типізована помилка провайдера — несе ЛИШЕ enum-код (без сирих повідомлень → без PHI).
class ProviderError extends Error {
  constructor(code) { super(code); this.code = code; }
}

// Повідомлення лікарю за кодом (текст помилки на екран; у лог іде лише код).
const ERROR_MESSAGES = {
  bedrock_throttle: "Сервіс тимчасово перевантажений (ліміт запитів). Спробуйте за хвилину.",
  bedrock_timeout: "Перевищено час очікування генерації. Спробуйте ще раз.",
  bedrock_empty: "Модель не повернула результат. Спробуйте ще раз.",
  bedrock_throw: "Помилка генерації протоколу. Спробуйте ще раз.",
  anthropic_empty: "Claude не повернув результат. Спробуйте ще раз.",
  anthropic_throw: "Помилка Claude API. Спробуйте ще раз.",
  cli_timeout: "Не вдалося сформувати протокол за 3 хвилини (таймаут). Спробуйте ще раз.",
  cli_limit: "Можливо, вичерпано ліміт підписки Max — спробуйте пізніше.",
  cli_notfound: "Сервіс генерації недоступний на сервері. Зверніться до адміністратора.",
  cli_empty: "Не вдалося сформувати протокол. Спробуйте ще раз.",
  no_provider: "Генерація протоколу не налаштована на сервері.",
  unknown: "Невідома помилка формування протоколу.",
};

// Формування через AWS Bedrock (Converse). Повертає HTML або кидає ProviderError(code).
async function protocolViaBedrock(systemPrompt, raw) {
  let r;
  try {
    r = await bedrock.send(new ConverseCommand({
      modelId: BEDROCK_MODEL,
      system: [{ text: systemPrompt }],
      messages: [{ role: "user", content: [{ text: "--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw }] }],
      inferenceConfig: { maxTokens: 4000, temperature: 0 },
    }));
  } catch (e) {
    const name = (e && (e.name || e.__type || "")) + "";
    if (/Throttl|TooManyRequests/i.test(name)) throw new ProviderError("bedrock_throttle");
    if (/Timeout/i.test(name)) throw new ProviderError("bedrock_timeout");
    throw new ProviderError("bedrock_throw");
  }
  const text = ((r.output && r.output.message && r.output.message.content) || [])
    .map((b) => b.text || "").join("").trim();
  if (!text) throw new ProviderError("bedrock_empty");
  return stripFences(text);
}

// Формування через Anthropic API (Claude Opus 4.8). Стрімінг — щоб не впертись у таймаут.
async function protocolViaAnthropic(systemPrompt, raw) {
  let msg;
  try {
    const stream = anthropic.messages.stream({
      model: "claude-opus-4-8",
      max_tokens: 8000,
      output_config: { effort: "low" },
      system: systemPrompt,
      messages: [{ role: "user", content: "--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw }],
    });
    msg = await stream.finalMessage();
  } catch (e) {
    throw new ProviderError("anthropic_throw");
  }
  const text = (msg.content || []).filter((b) => b.type === "text").map((b) => b.text).join("").trim();
  if (!text) throw new ProviderError("anthropic_empty");
  return stripFences(text);
}

// Резервний шлях: `claude -p` на підписці Max. Повертає HTML або кидає ProviderError(code).
function protocolViaCLI(systemPrompt, raw) {
  return new Promise((resolve, reject) => {
    const prompt = systemPrompt + "\n\n--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw;
    const child = spawn("claude", ["-p", "--output-format", "text"], { env: process.env, timeout: 180000 });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => reject(new ProviderError(e && e.code === "ENOENT" ? "cli_notfound" : "unknown")));
    child.on("close", (code, signal) => {
      if (signal === "SIGTERM") return reject(new ProviderError("cli_timeout")); // вбито по таймауту 180с
      if (code !== 0 || !out.trim()) {
        // ліміт Max vs інше — за маркером у stderr; сам stderr НЕ логуємо (може містити текст).
        return reject(new ProviderError(/limit|usage|quota|rate/i.test(err) ? "cli_limit" : "cli_empty"));
      }
      resolve(stripFences(out));
    });
    child.stdin.write(prompt);
    child.stdin.end();
  });
}

app.post("/api/protocol", async (req, res) => {
  const raw = (req.body && req.body.text || "").trim();
  if (!raw) {
    return res.status(400).json({ error: "Порожній текст диктовки." });
  }

  const user = getAuthUser(req);
  const uid = (req.body && req.body.uid) || "server";
  const systemPrompt = PROMPTS_BY_USER[user] || SYSTEM_PROMPT;

  // Ланцюг провайдерів: основний → резерв. Кожен збій логуємо з кодом; успіх після збою — fallback:true.
  const chain = [];
  if (bedrock) chain.push({ provider: "bedrock", model: BEDROCK_MODEL, run: protocolViaBedrock });
  if (anthropic) chain.push({ provider: "anthropic", model: "claude-opus-4-8", run: protocolViaAnthropic });
  chain.push({ provider: "cli", model: "claude-cli-max", run: protocolViaCLI });

  let fallback = false;
  for (let i = 0; i < chain.length; i++) {
    const step = chain[i];
    const t0 = Date.now();
    try {
      const html = await step.run(systemPrompt, raw);
      const ms = Date.now() - t0;
      logEvent(uid, "generate_ok", Math.round(ms / 1000), user,
        { provider: step.provider, model: step.model, stage: "generate", ms, fallback });
      return res.json({ html, ms, provider: step.provider, model: step.model });
    } catch (e) {
      const ms = Date.now() - t0;
      const code = (e && e.code) || "unknown";
      logEvent(uid, "generate_err", null, user,
        { provider: step.provider, model: step.model, stage: "generate", code, ms });
      if (i === chain.length - 1) {
        return res.status(500).json({ error: ERROR_MESSAGES[code] || ERROR_MESSAGES.unknown });
      }
      fallback = true; // наступний провайдер — це вже резерв
      console.error(`[protocol] провайдер ${step.provider} впав (${code}), резерв на наступний`);
    }
  }
});

app.listen(PORT, () => {
  console.log(`УЗД МВП працює: http://localhost:${PORT}`);
});
