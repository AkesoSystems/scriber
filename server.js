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
const crypto = require("crypto");

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
  "no_provider", "network", "trial_over", "unknown",
]);
const EV_MODELS = new Set([
  "us.amazon.nova-pro-v1:0", "amazon.nova-pro-v1:0", "claude-opus-4-8", "claude-cli-max",
  "us.anthropic.claude-sonnet-4-6",
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

// Людський нік за логіном Basic Auth — щоб у дашборді/аналітиці було видно, ХТО конкретно
// заходив, а не сухий "test2". Лише для відображення; PHI-firewall не зачіпає (нік — не PHI).
// Зміна списку = git push + редеплой. Логін без запису → показуємо сам логін.
const NICKNAMES_BY_USER = {
  test:       "Юрій Юрійович",
  test2:      "Головатий Василь",
  test3:      "Даниїл Шипов",
  test4:      "Андрій Дутчак",
  test5:      "Ілля Андрійович (вет)",
  test9: "Ірина Левадна",
  test10:     "Катерина Кравченко",
  test6:      "Ольга Дебель",
  test7:      "Долгушина Альбіна",
  test8:      "Роксоляна Денисюк",
  demo:       "ЛАБ (тест)",
};
function nickOf(user) { return NICKNAMES_BY_USER[user] || user; }

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
  const user = getAuthUser(req);
  // Не логуємо події без логіна basic-auth (healthcheck / service worker / боти) — це фоновий
  // шум «невідомо», не реальний лікар. Тихо підтверджуємо, щоб клієнт не отримав помилку.
  if (user === "невідомо") return res.json({ ok: true });
  // logEvent пересанітизує meta через whitelist — ворожий клієнт текст не вкине.
  logEvent(uid, event, value, user, { provider, model, code, stage, ms, fallback });
  res.json({ ok: true });
});

// Видалити ВСЮ аналітику конкретного логіна (очистка тест-акаунту / запит на видалення даних).
// Захищено тим самим ADMIN_KEY, що й /api/stats. Переписує analytics.jsonl, лишаючи рядки
// інших користувачів байт-у-байт; незпарсені рядки зберігаються. POST /api/admin/purge-user?key=...&user=test7
app.post("/api/admin/purge-user", (req, res) => {
  if (!ADMIN_KEY_OK) return res.status(503).json({ ok: false, error: "ADMIN_KEY не налаштований" });
  if (String(req.query.key || "") !== ADMIN_KEY) return res.status(403).json({ ok: false, error: "forbidden" });
  const target = String(req.query.user || "").slice(0, 40);
  if (!target) return res.status(400).json({ ok: false, error: "параметр user обов'язковий" });
  let lines;
  try { lines = fs.readFileSync(ANALYTICS_FILE, "utf8").split("\n"); }
  catch (e) { return res.status(500).json({ ok: false, error: e.message }); }
  let removed = 0;
  const kept = lines.filter((l) => {
    if (!l) return false;
    let r; try { r = JSON.parse(l); } catch (_) { return true; } // незпарсений рядок — лишаємо
    if (r && r.user === target) { removed++; return false; }
    return true;
  });
  try { fs.writeFileSync(ANALYTICS_FILE, kept.length ? kept.join("\n") + "\n" : ""); }
  catch (e) { return res.status(500).json({ ok: false, error: e.message }); }
  console.log("[analytics] purge-user " + target + ": видалено " + removed + " рядків, лишилось " + kept.length);
  res.json({ ok: true, user: target, removed, remaining: kept.length });
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

// ── Тестовий період: N днів від ПЕРШОГО протоколу кожного акаунту (логіну Basic Auth) ──
// База — TRIAL_DAYS (env, дефолт 7). Адмін може коригувати персонально через події у
// analytics.jsonl: "trial_reset" (рестарт відліку) і "trial_bonus" (value = +дні). Зберігати
// оверайди в аналітиці зручно — файл уже на volume, тож вони переживають редеплой без нового маунта.
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS) > 0 ? Number(process.env.TRIAL_DAYS) : 7;
const DAY_MS = 24 * 60 * 60 * 1000;

// Українська відмінкова форма для "день/дні/днів".
function trialDaysWord(n) {
  if (n % 10 === 1 && n % 100 !== 11) return "день";
  if (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 10 || n % 100 >= 20)) return "дні";
  return "днів";
}

function readAnalyticsRows() {
  try {
    return fs.readFileSync(ANALYTICS_FILE, "utf8")
      .split("\n").filter(Boolean)
      .map((l) => { try { return JSON.parse(l); } catch (_) { return null; } })
      .filter(Boolean);
  } catch (_) { return []; }
}

// Синхронний запис службового рядка (адмін-оверайди періоду) — щоб відповідь одразу бачила зміну.
function appendRowSync(row) {
  try { fs.appendFileSync(ANALYTICS_FILE, JSON.stringify(row) + "\n"); }
  catch (e) { console.error("[analytics] sync append не вдався:", e.message); }
}

// Квота протоколів (ЛИШЕ відстеження, БЕЗ блокування): логін → базовий пакет протоколів.
// Показуємо «використано/база» лікарю в апці та в консолі /stats. Відсутній логін = без квоти.
const PROTOCOL_QUOTA_BY_USER = { test2: 100 };
function protocolsUsed(user, rows) {
  rows = rows || readAnalyticsRows();
  // «Обнулення» (адмін-подія quota_reset) переводить лічильник: рахуємо лише generate_ok ПІСЛЯ
  // останнього reset. Історичні протоколи лишаються в аналітиці, але в квоту не входять.
  let resetAt = 0;
  for (const r of rows) if (r.user === user && r.event === "quota_reset" && typeof r.t === "number" && r.t > resetAt) resetAt = r.t;
  let n = 0;
  for (const r of rows) if (r.user === user && r.event === "generate_ok" && (r.t || 0) >= resetAt) n++;
  return n;
}

// Стан тестового періоду логіну з урахуванням адмін-оверайдів.
function trialState(user, rows) {
  // demo — безстроково. Квота-клієнти (PROTOCOL_QUOTA_BY_USER, напр. test2) — теж без тесту-в-днях:
  // у них інша модель (лічильник протоколів), тож trial-відлік/гейт до них не застосовуємо.
  if (NEUTRAL_USERS.has(user) || PROTOCOL_QUOTA_BY_USER[user]) {
    return { started: false, expired: false, unlimited: true, daysRemaining: null, limitDays: null, bonusDays: 0, firstAt: 0 };
  }
  rows = rows || readAnalyticsRows();
  // Останній reset для цього юзера «переводить годинник»: ранні протоколи й бонуси не рахуються.
  let resetAt = 0;
  for (const r of rows) {
    if (r.user === user && r.event === "trial_reset" && typeof r.t === "number" && r.t > resetAt) resetAt = r.t;
  }
  // Події цього юзера після reset — у ХРОНОЛОГІЧНОМУ порядку. Порядок критичний: бонус, що
  // прийшов уже ПІСЛЯ завершення тріалу, має продовжувати відлік від дня видачі, а не від
  // давно минулого кінця — інакше «+ дні» лікарю з простроченим періодом візуально нічого
  // не додає (limitDays росте, але вікно все одно позаду). Кінець тримаємо як timestamp endAt.
  const mine = rows
    .filter((r) => r.user === user && typeof r.t === "number" && r.t >= resetAt
      && (r.event === "generate_ok" || r.event === "trial_bonus"))
    .sort((a, b) => a.t - b.t);
  let firstAt = 0, bonusDays = 0, endAt = 0;
  for (const r of mine) {
    if (r.event === "generate_ok") {
      // Перший протокол запускає відлік. Бонуси, видані ДО нього, уже в bonusDays —
      // тож стартове вікно одразу їх враховує.
      if (!firstAt) { firstAt = r.t; endAt = firstAt + (TRIAL_DAYS + bonusDays) * DAY_MS; }
    } else if (r.event === "trial_bonus" && typeof r.value === "number") {
      bonusDays += r.value;
      // Після старту продовжуємо від ПІЗНІШОГО з двох: наявний кінець (тріал ще живий) або
      // момент видачі (уже прострочено) — так лікар завжди отримує повні N днів наперед.
      if (firstAt) endAt = Math.max(endAt, r.t) + r.value * DAY_MS;
    }
  }
  const limitDays = Math.max(0, TRIAL_DAYS + bonusDays);
  if (!firstAt) return { started: false, expired: false, daysRemaining: limitDays, limitDays, bonusDays, firstAt: 0 };
  const remainingMs = endAt - Date.now();
  return {
    started: true,
    expired: remainingMs <= 0,
    daysRemaining: Math.max(0, Math.ceil(remainingMs / DAY_MS)),
    limitDays, bonusDays, firstAt,
  };
}

// Кожен акаунт бачить ЛИШЕ свій період (за власним Basic Auth-логіном) — ADMIN_KEY не потрібен.
app.get("/api/trial", (req, res) => {
  const user = getAuthUser(req);
  // Випадайку шаблонів показуємо двом категоріям: нейтральним QA-акаунтам (усі шаблони) і реальним
  // лікарям із власним набором (TEMPLATE_CHOICES_BY_USER) — напр. Долгушина обирає ЩЗ/ЕХОКГ.
  const isNeutral = NEUTRAL_USERS.has(user);
  const choices   = TEMPLATE_CHOICES_BY_USER[user];
  const canPick   = isNeutral || (Array.isArray(choices) && choices.length > 1);
  const keys      = isNeutral ? Object.keys(TEMPLATES) : (choices || []);
  const templates = canPick
    ? keys.filter((key) => TEMPLATES[key]).map((key) => ({ key, label: TEMPLATES[key].label, testers: testersForTemplate(key) }))
    : null;
  const primary   = PROMPTS_BY_USER[user] || null; // пре-вибір у UI
  const quota = PROTOCOL_QUOTA_BY_USER[user];
  const usage = quota ? { protocolQuota: quota, protocolsUsed: protocolsUsed(user) } : {};
  const conclusions = CONCLUSIONS_BY_USER[user] || null;  // бібліотека готових заключень (own-only)
  const beam = BEAM_USERS.has(user) || isNeutral;         // синк телефон→комп (test8 + нейтральні/demo для прев'ю)
  res.json(Object.assign({ user, isNeutral, canPick, templates, primary, conclusions, beam }, trialState(user), usage));
});

// ── Ефемерний «beam» телефон→комп У МЕЖАХ ОДНОГО акаунта (той самий Basic Auth-логін) ──
// Роксоляна (test8) диктує з телефона й доводить на комп'ютері. Клінічний текст свідомо тримаємо
// ЛИШЕ в пам'яті: без диска, без логів, короткий TTL і single-use (перше ж отримання стирає) — щоб
// не порушувати PHI-firewall (нуль клінічного тексту на диску/в аналітиці). Ключ = логін акаунта.
const BEAM_USERS = new Set(["test8"]);      // кому показуємо синк (нейтральні/demo вмикаються окремо, для прев'ю)
const BEAM_TTL_MS = 5 * 60 * 1000;          // 5 хв — «пару хвилин», щоб встигнути перейти на комп
const beamStore = new Map();                 // user → { t, dictation, protocol }
function beamSweep() {                        // прибирання протухлих (якщо ніхто не забрав)
  const now = Date.now();
  for (const [u, v] of beamStore) if (!v || now - v.t > BEAM_TTL_MS) beamStore.delete(u);
}
const beamTimer = setInterval(beamSweep, 60 * 1000);
if (beamTimer.unref) beamTimer.unref();      // не тримати процес живим лише заради підмітання

// Телефон кладе поточну диктовку+протокол під свій акаунт. Перезапис — останній виграє.
app.post("/api/beam", (req, res) => {
  const user = getAuthUser(req);
  if (user === "невідомо") return res.status(401).json({ error: "no_auth" });
  const dictation = String((req.body && req.body.dictation) || "").slice(0, 100000);
  const protocol  = String((req.body && req.body.protocol)  || "").slice(0, 400000);
  if (!dictation && !protocol) return res.status(400).json({ error: "empty" });
  beamStore.set(user, { t: Date.now(), dictation, protocol });
  res.json({ ok: true, ttlMs: BEAM_TTL_MS });
});

// Комп забирає (single-use): віддали й одразу стерли — клінічний текст не залежується в пам'яті.
app.get("/api/beam", (req, res) => {
  const user = getAuthUser(req);
  if (user === "невідомо") return res.status(401).json({ error: "no_auth" });
  const v = beamStore.get(user);
  beamStore.delete(user);                    // забрали або протухло — в обох випадках чистимо
  if (!v || Date.now() - v.t > BEAM_TTL_MS) return res.json({ empty: true });
  res.json({ dictation: v.dictation, protocol: v.protocol, t: v.t });
});

// ── Адмін-керування періодом (за ADMIN_KEY): продовжити (+дні) / скинути ──
app.post("/api/admin/trial", (req, res) => {
  if (!ADMIN_KEY_OK) return res.status(503).json({ error: "stats_disabled" });
  const key = (req.body && req.body.key) || req.query.key;
  if (key !== ADMIN_KEY) return res.status(403).json({ error: "forbidden" });
  const user = (req.body && req.body.user || "").toString().slice(0, 40);
  const action = req.body && req.body.action;
  if (!user) return res.status(400).json({ error: "no_user" });
  if (action === "extend") {
    const days = Math.round(Number(req.body.days) || 7);
    if (!(days > 0 && days <= 365)) return res.status(400).json({ error: "bad_days" });
    appendRowSync({ t: Date.now(), uid: "admin", user, event: "trial_bonus", value: days });
  } else if (action === "reset") {
    appendRowSync({ t: Date.now(), uid: "admin", user, event: "trial_reset", value: null });
  } else if (action === "quota_reset") {
    appendRowSync({ t: Date.now(), uid: "admin", user, event: "quota_reset", value: null });
  } else {
    return res.status(400).json({ error: "bad_action" });
  }
  res.json({ ok: true, user, trial: trialState(user) });
});

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

  // Сирий per-recording список — ЛИШЕ коли фільтруємо по юзеру (інакше payload росте).
  // Дає «кожен запис який записував лікар і скільки» без агрегації/середніх. PHI-safe:
  // тільки час + число тривалості/ms + enum-код помилки. Жодного тексту диктовки/протоколу.
  const RECORDINGS_CAP = 2000;
  let recordings = null;
  if (filterUser) {
    recordings = [];
    for (const r of rows) {
      if (r.event === "rec_stop") recordings.push({ t: r.t, kind: "rec", durationSec: r.value || 0 });
      else if (r.event === "generate_ok") recordings.push({ t: r.t, kind: "proto", ms: typeof r.ms === "number" ? r.ms : null });
      else if (r.event === "generate_err") recordings.push({ t: r.t, kind: "err", code: r.code || "unknown" });
      else if (r.event === "rating" && r.value >= 1 && r.value <= 5) recordings.push({ t: r.t, kind: "rating", value: r.value });
    }
    recordings.sort((a, b) => b.t - a.t); // новіші зверху
    if (recordings.length > RECORDINGS_CAP) recordings = recordings.slice(0, RECORDINGS_CAP);
  }

  const uniq = new Set();
  const days = {};
  const users = {};
  const byUserDay = {};
  const errBy = { code: {}, provider: {}, stage: {} };
  const sum = {
    visits: 0, recStarts: 0, recStops: 0, recSecTotal: 0, recStopsReal: 0, recSecReal: 0,
    gen: 0, genOk: 0, genErr: 0, genSecTotal: 0, genMsTotal: 0, genMsCount: 0,
    word: 0, pdf: 0, copy: 0,
    ratingTotal: 0, ratingCount: 0, ratingDist: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
  };

  function userOf(r) {
    const k = r.user || "—";
    users[k] = users[k] || { visits: 0, recordings: 0, recSec: 0, protocols: 0, errors: 0, exports: 0, exWord: 0, exPdf: 0, exCopy: 0, ratingTotal: 0, ratingCount: 0 };
    return users[k];
  }
  function udOf(user, d) {
    byUserDay[user] = byUserDay[user] || {};
    byUserDay[user][d] = byUserDay[user][d] || { visits: 0, recordings: 0, protocols: 0, errors: 0, exports: 0, exWord: 0, exPdf: 0, exCopy: 0 };
    return byUserDay[user][d];
  }
  function bumpErr(r) {
    if (r.code) errBy.code[r.code] = (errBy.code[r.code] || 0) + 1;
    if (r.provider) errBy.provider[r.provider] = (errBy.provider[r.provider] || 0) + 1;
    if (r.stage) errBy.stage[r.stage] = (errBy.stage[r.stage] || 0) + 1;
  }

  for (const r of rows) {
    // Адмін-оверайди періоду — службові рядки; у статистику не йдуть (їх читає trialState).
    if (r.event === "trial_bonus" || r.event === "trial_reset" || r.event === "quota_reset") continue;
    // demo (NEUTRAL_USERS) = QA-акаунт: per-user рядок (users/byUserDay) будуємо ЗАВЖДИ, щоб demo
    // лишався видимим для QA, але у KPI-агрегати (uniqueDevices, sum, byDay, помилки) demo НЕ тече —
    // інакше load-тести завищують числа в ~5× (demo = 81% протоколів).
    const neutral = NEUTRAL_USERS.has(r.user || "—");
    const d = dayKey(r.t);
    const u = userOf(r);
    const ud = udOf(r.user || "—", d);
    if (!neutral) {
      uniq.add(r.uid);
      days[d] = days[d] || { visits: 0, recordings: 0, protocols: 0, exports: 0 };
    }
    switch (r.event) {
      case "visit":
        u.visits++; ud.visits++;
        if (!neutral) { sum.visits++; days[d].visits++; }
        break;
      case "rec_start": if (!neutral) sum.recStarts++; break;
      case "rec_stop": {
        u.recordings++; ud.recordings++;
        if (r.value) u.recSec += r.value;
        const realRec = r.value >= 5 && r.value <= 1200; // <5с фальстарти, >20хв привиди — не в середню тривалість
        if (!neutral) {
          sum.recStops++; days[d].recordings++;
          if (r.value) sum.recSecTotal += r.value;
          if (realRec) { sum.recStopsReal++; sum.recSecReal += r.value; }
        }
        break;
      }
      case "generate": if (!neutral) sum.gen++; break;
      case "generate_ok":
        // Рахуємо ВСІ generate_ok: історичні (старий клієнт, без provider) + нові (сервер, з provider).
        // Подвоєння нема — у тому ж релізі клієнтський generate_ok прибрано, тож рядок на протокол один.
        u.protocols++; ud.protocols++;
        if (!neutral) {
          sum.genOk++; days[d].protocols++;
          if (typeof r.ms === "number") { sum.genMsTotal += r.ms; sum.genMsCount++; }
          else if (r.value) sum.genSecTotal += r.value;
        }
        break;
      case "generate_err":
        u.errors++; ud.errors++;
        if (!neutral) { sum.genErr++; bumpErr(r); }
        break;
      case "transcribe_err": if (!neutral) bumpErr(r); break;
      case "export_word": u.exports++; u.exWord++; ud.exports++; ud.exWord++; if (!neutral) { sum.word++; days[d].exports++; } break;
      case "export_pdf":  u.exports++; u.exPdf++;  ud.exports++; ud.exPdf++;  if (!neutral) { sum.pdf++;  days[d].exports++; } break;
      case "export_copy": u.exports++; u.exCopy++; ud.exports++; ud.exCopy++; if (!neutral) { sum.copy++; days[d].exports++; } break;
      case "rating":
        if (r.value >= 1 && r.value <= 5) {
          u.ratingTotal += r.value; u.ratingCount++;
          if (!neutral) {
            sum.ratingTotal += r.value; sum.ratingCount++;
            sum.ratingDist[Math.round(r.value)]++;
          }
        }
        break;
    }
  }

  // Engagement per-user (із byUserDay) — «кому написати»
  const today = dayKey(Date.now());
  const engagement = Object.keys(byUserDay).filter((user) => !NEUTRAL_USERS.has(user)).map((user) => {
    const dmap = byUserDay[user];
    const activeDays = Object.keys(dmap).filter((d) => dmap[d].protocols > 0).sort();
    const lastActiveDay = activeDays.length ? activeDays[activeDays.length - 1] : null;
    let protocols7d = 0, protocols30d = 0;
    const ex7 = { word: 0, pdf: 0, copy: 0 };
    for (const d of Object.keys(dmap)) {
      const diff = dayDiff(today, d);
      if (diff >= 0 && diff <= 6) {
        protocols7d += dmap[d].protocols;
        ex7.word += dmap[d].exWord || 0; ex7.pdf += dmap[d].exPdf || 0; ex7.copy += dmap[d].exCopy || 0;
      }
      if (diff >= 0 && diff <= 29) protocols30d += dmap[d].protocols;
    }
    const outputOut7d = (ex7.word + ex7.pdf + ex7.copy) > 0;
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
    const ts = trialState(user, rows);
    return {
      user,
      lastActiveDay,
      daysSinceActive: lastActiveDay ? dayDiff(today, lastActiveDay) : null,
      protocols7d, protocols30d,
      exports7d: ex7, outputOut7d,
      activeDaysStreak: streak,
      protocolsTotal: protocols,
      protocolQuota: PROTOCOL_QUOTA_BY_USER[user] || null,
      protocolsUsedQuota: PROTOCOL_QUOTA_BY_USER[user] ? protocolsUsed(user, rows) : null,
      trialUnlimited: ts.unlimited || false,
      errorRate: (protocols + errors) ? Math.round(errors / (protocols + errors) * 100) : 0,
      avgRating: uu.ratingCount ? Math.round(uu.ratingTotal / uu.ratingCount * 10) / 10 : null,
      trialStarted: ts.started,
      trialExpired: ts.expired,
      trialDaysLeft: ts.daysRemaining,
      trialLimitDays: ts.limitDays,
      trialBonusDays: ts.bonusDays,
    };
  }).sort((a, b) => {
    if (a.daysSinceActive === null) return 1;   // хто жодного протоколу — в кінець
    if (b.daysSinceActive === null) return -1;
    return b.daysSinceActive - a.daysSinceActive; // найбільш «затихлий» — перший
  });

  res.json({
    users: allUsers,
    nicks: Object.fromEntries(allUsers.map((u) => [u, nickOf(u)])),
    filteredBy: filterUser || null,
    uniqueDevices: uniq.size,
    visits: sum.visits,
    recordings: sum.recStops,
    avgRecordingSec: sum.recStopsReal ? Math.round(sum.recSecReal / sum.recStopsReal) : 0,
    recordingsTrimmed: sum.recStops - sum.recStopsReal,
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
    recordingsLog: recordings, // сирий per-recording список (лише при ?user=), інакше null
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
// Точний вигляд шаблону лікаря (Ехо КГ дитяче.docx): заголовок по центру, шапка пацієнта,
// ОДНА суцільна 4-колонкова таблиця (Times New Roman, чорні рамки, заголовки секцій жирні без заливки)
// курсивом, підпис. Поля пацієнта ПОРОЖНІ (лікар вписує вручну — PHI не йде в LLM).
// Принцип як у решти: незгадане/сумнівне → [?]; патологія замінює норму; висновок — по знахідках.
const SYSTEM_PROMPT_TESTER3 = `Ти — медичний редактор, що оформлює протокол ДИТЯЧОЇ ЕХОКАРДІОГРАФІЇ українською мовою у вигляді HTML-ТАБЛИЦІ.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КАТЕГОРИЧНІ ПРАВИЛА ДАНИХ:
1. Поля пацієнта (Дата, Пацієнт, Вік, Дата народження, Стать, Вага, Зріст, Площа поверхні тіла) лиши ПОРОЖНІМИ — лікар впише вручну. НЕ вписуй ПІБ/вік/стать/дату навіть якщо це продиктовано.
2. Підставляй ЛИШЕ продиктовані числа та факти. Числа нормалізуй: "два цілих три" → "2,3"; "сто сорок два" → "142"; десятковий роздільник — кома; розміри "чотири на шість" → "4 × 6".
3. Якщо число/параметр НЕ продиктовано — постав [?] на його місці (його підсвітять). НЕ вигадуй розмірів, швидкостей, ФВ тощо, НЕ лишай порожньо. Одиниці (мм, м/с, мм.рт.ст) і дужки (Z,SD = [?]; N = [?] мм) лишай як у шаблоні.
4. Якісні/анатомічні формулювання в шаблоні нижче — це НОРМАЛЬНІ значення за замовчуванням. Лишай їх як є, АЛЕ якщо в диктовці названо патологію чи інше — ЗАМІНИ формулювання на продиктоване.
5. Сумнівне розпізнавання / нерозчуте слово познач [?] одразу після нього.
6. ІГНОРУЙ поза-контекст: розмови з пацієнтом, побутові репліки, команди ("дихай", "не рухайся") — НЕ вписуй.
7. Нічого зайвого не додавай: жодних рядків поза шаблоном.
8. ВИСНОВОК генеруй ПО СУТІ протоколу: якщо є патологія — вкажи саме її; якщо все в нормі — «Даних за структурну патологію серця немає».

ФОРМАТ — лише HTML-фрагмент (без <html>, <head>, <body>, без markdown, без \`\`\`, без пояснень). Шрифт усього протоколу — Times New Roman, рамки чорні (1px solid #000), заголовки секцій — жирні по центру БЕЗ заливки (як у файлі лікаря):
- Заголовок по центру: <h2 style="text-align:center;font-family:'Times New Roman',serif">Ехокардіографічне обстеження</h2>.
- ОДНА таблиця <table style="border-collapse:collapse;width:100%;margin:0 0 14px;font-family:'Times New Roman',serif;font-size:13px">.
- Звичайна клітинка: <td style="border:1px solid #000;padding:1px 5px;vertical-align:top">; значення — у <em>.
- Заголовок-рядок (Праве передсердя, Тристулковий клапан тощо): <td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">.
- НЕ використовуй <h3>, не розбивай на кілька таблиць.

ВИКОРИСТАЙ РІВНО ТАКУ СТРУКТУРУ (підстав значення у місця з [?]; поля пацієнта лиши порожніми; якісні значення заміни лише за наявності патології в диктовці):

<h2 style="text-align:center;font-family:'Times New Roman',serif">Ехокардіографічне обстеження</h2>

<p style="font-family:'Times New Roman',serif"><strong>Дата :</strong><br>
<strong>Пацієнт:</strong><br>
<strong>Вік :</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Дата народження:</strong><br>
<strong>Стать:</strong><br>
<strong>Вага:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Площа поверхні тіла:</strong></p>

<table style="border-collapse:collapse;width:100%;margin:0 0 14px;font-family:'Times New Roman',serif;font-size:13px">
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Розташування передсердь</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Solitus</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Розташування серця</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Лівокардія</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Серце</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Двошлуночкове</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Передсердно шлуночкове сполучення</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Конкордантне</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Шлуночково-артеріальне сполучення</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Конкордантне</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top">Хід магістральних судин</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Перехресний</em></td></tr>

<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Праве передсердя</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Ліве передсердя</td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Розмір</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>норма</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Розмір [?] мм</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>норма</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Порожнисті вени</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Впадають</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Легеневі вени</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Впадають всі</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Безіменна вена</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Наявна, діаметр [?]</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Додаткова ВПВ</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>немає</em></td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Міжпередсердна перетинка</td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Коронарний синус</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Не розширений</em></td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>інтактна</em></td></tr>

<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Тристулковий клапан</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Мітральний клапан</td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Діаметр</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Діаметр</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Швидкість</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] м/с</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Швидкість</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] м/с</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Недостатність</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>відсутня</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Недостатність</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>відсутня</em></td></tr>

<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Правий шлуночок</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Лівий шлуночок</td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Порожнина</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>не розширена</em></td><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Порожнина — норма, до верхівки доходить</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Скоротливість</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>добра</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Скоротливість</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Добра; ФВ = [?] %</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">До верхівки</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>доходить</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">КДР/КДО/КДІ</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм / [?] мл / [?] мл/м²</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">ТМШП/ТЗСЛШ</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм / [?] мм</em></td></tr>
<tr><td colspan="4" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Міжшлуночкова перетинка</strong> — <em>інтактна</em></td></tr>

<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Легенева артерія</td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Аорта</td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Клапан ЛА</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Клапан Ао</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Стовбур ЛА</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Синус Вальсальви</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Права гілка ЛА</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">ST сполучення</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Ліва гілка ЛА</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Клапан Ао</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>тристулковий</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">ΔР max клапан</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм.рт.ст</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">ΔР max клапан</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм.рт.ст</em></td></tr>
<tr><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">недостатність</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>відсутня</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">недостатність</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>відсутня</em></td></tr>

<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Відкрита артеріальна протока</strong> — <em>відсутня</em></td><td colspan="2" style="border:1px solid #000;padding:1px 5px;text-align:center;font-weight:bold">Дуга аорти</td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Легенева гіпертензія</strong> — <em>відсутня</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">ΔР max</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>[?] мм.рт.ст</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Рідина в порожнині перикарду</strong> — <em>відсутня</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Дуга</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>лівостороння</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>В черевній аорті кровотік</strong> — <em>пульсуючий</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top">Коарктації аорти</td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>немає</em></td></tr>
<tr><td colspan="2" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Коронарні артерії</strong> — <em>без особливостей</em></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #000;padding:1px 5px;vertical-align:top"></td></tr>

<tr><td colspan="4" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><em>Додаткові дані:</em> [за диктовкою; якщо нічого не продиктовано — лиши порожнім]</td></tr>
<tr><td colspan="4" style="border:1px solid #000;padding:1px 5px;vertical-align:top"><strong>Висновок:</strong> [сформулюй за фактичними знахідками; норм-варіант — Даних за структурну патологію серця немає]</td></tr>
</table>

<p style="font-family:'Times New Roman',serif"><strong>Лікар-кардіолог дитячий Шипов Д.О.</strong></p>

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

// ───────────── Промпт для test2: мультишаблон (черево + щитоподібна + дефолт) ─────────────
// Модель сама визначає тип УЗД з диктовки і бере відповідний шаблон; якщо тип не збігається
// з жодним — дефолтний суцільний опис. Незгадане/сумнівне підсвічується [?]. Висновок —
// по фактичних знахідках, а не дефолтна норма. Розмови з пацієнтом ігноруються.
const SYSTEM_PROMPT_TESTER2 = `Ти — медичний редактор, що оформлює протоколи ультразвукового дослідження українською мовою.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КРОК 1 — ВИЗНАЧ ТИП ДОСЛІДЖЕННЯ з диктовки:
- Якщо йдеться про органи черевної порожнини (печінка, жовчний міхур, підшлункова, селезінка, нирки, надниркові, сечовий міхур, ворітна вена тощо) → використай ШАБЛОН А (черевна порожнина).
- Якщо йдеться про щитоподібну залозу (частки, перешийок, вузли, фолікули, TI-RADS, прищитоподібні) → використай ШАБЛОН Б (щитоподібна залоза).
- Якщо йдеться про молочні залози (залозистий компонент, протоки, вогнищеві утворення, BIRADS, аксілярні лімфовузли, мамолог) → використай ШАБЛОН В (молочні залози).
- Якщо йдеться про передміхурову залозу / простату (сім'яні міхурці, парапростатичне сплетення, залишкова сеча, трансректально, уролог) → використай ШАБЛОН Г (передміхурова залоза).
- Якщо йдеться про органи калитки / яєчка (праве/ліве яєчко, додаток яєчка, лозовидне сплетення, проба Вальсальви) → використай ШАБЛОН Д (органи калитки).
- Якщо це інший тип УЗД, для якого шаблону нема, або тип незрозумілий → НЕ бери жоден шаблон, а оформи суцільний опис: <h2> з назвою дослідження за змістом + абзаци <p> по органах + фінальний <p> "Висновок:".

КРОК 2 — ЗАПОВНИ ОБРАНИЙ ШАБЛОН за такими правилами:
1. Слухай ВСЕ і редагуй шаблон під фактичні знахідки: підстав продиктовані числа на місця плейсхолдерів (000, 00×00). Числа нормалізуй: "сто сорок два" → "142", десятковий роздільник — кома, розміри "чотири на шість" → "4 × 6".
2. Якщо лікар диктує патологію там, де в шаблоні стоїть норма ("не збільшена" → лікар каже "збільшена"; "контури рівні" → "контури горбисті") — ЗАМІНИ формулювання шаблону на продиктоване. Якісні норм-формулювання, яких лікар не спростував, лишай як є.
3. Якщо лікар продиктував додаткову знахідку, якої нема в шаблоні — допиши її у відповідний розділ.
4. ПІДСВІЧУВАННЯ [?] (постав маркер [?] прямо в тексті — його підсвітять):
   - будь-яке число/поле, якого лікар НЕ продиктував → постав [?] замість значення (НЕ лишай "000", НЕ вигадуй, НЕ підставляй типове число);
   - якщо про орган/розділ нічого не сказано → лиши блок, але всі його незаповнені значення познач [?];
   - слово/число, яке погано розпізналося або є сумнів у правильності → лиши його і додай [?] одразу після.
5. ІГНОРУЙ поза-контекст: розмови з пацієнтом, побутові репліки, команди ("дихайте", "поверніться"), усе, що не є описом дослідження — НЕ вписуй у протокол.
6. НЕ додавай даних пацієнта (ПІБ, вік, дату).

КРОК 3 — ВИСНОВОК (Заключення) генеруй ПО СУТІ протоколу:
- проаналізуй фактичні знахідки в зібраному протоколі;
- якщо є патологія — у "Заключення" вкажи саме її (а не дефолтну норму "змін не виявлено");
- якщо все в межах норми — нормальний висновок;
- норм-висновок із шаблону — лише орієнтир, а не текст, який треба копіювати завжди.

ФОРМАТ ВІДПОВІДІ — ЛИШЕ HTML-фрагмент (без <html>, <head>, <body>, без markdown, без \`\`\`, без пояснень):
- <h2> — назва протоколу;
- назви органів і розділів ("Печінка:", "Жовчевий міхур:", "Підшлункова залоза:", "Селезінка:", "Права нирка", "Ліва нирка", "Сечовий міхур", "Заключення:", "Рекомендовано:") — у <strong>;
- латинські терміни (Vps, V. cava inferior, V. lienalis, RI, TR, ACR TI-RADS, Brunn тощо) — у <em>;
- кожен блок органа — окремий <p>; підрядки всередині блоку — через <br>; порожній рядок між блоками = новий <p>;
- марковані пункти лишай рядком, що починається з "• ".

═══════ ШАБЛОН А — ОРГАНИ ЧЕРЕВНОЇ ПОРОЖНИНИ ═══════

<h2>Протокол ультразвукового обстеження органів черевної порожнини</h2>

<p><strong>Печінка:</strong> контури рівні, чіткі, нижній край лівої долі гострий.<br>
Розміри (не збільшені): товщина лівої частки – [?] мм, товщина правої частки – [?] мм, КВР – [?] мм.<br>
Ехогенність паренхіми в межах норми.<br>
Звукопровідність не змінена.<br>
Судинний малюнок не змінений.<br>
Ехоструктура дрібнозерниста, гомогенна.</p>

<p>Ворітна вена – [?] мм, не розширена, із типовим допплерівським спектром та швидкістю при доплерографії. <em>Vps</em> – [?] см/сек.</p>

<p><em>V. cava inferior</em> – [?] мм, не розширена.<br>
Холедох – [?] мм, візуалізується до ретродуоденальної частини, не розширений. Внутрішньопечінкові жовчні протоки не розширені.</p>

<p><strong>Жовчевий міхур:</strong> розмірами – [?] × [?] мм, об'ємом – [?] мл, правильної овальної форми; перегини – відсутні; стінка – [?] мм, структурно не змінена, не потовщена; вміст – гомогенний.<br>
Конкременти на момент огляду не виявлені.</p>

<p><strong>Підшлункова залоза:</strong> не збільшена, із чіткими та рівними контурами.<br>
Розмірами: головка – [?] мм, тіло – [?] мм, хвіст – [?] мм. Ехогенність не змінена, ехоструктура однорідна.<br>
Вірсунгів протік не розширений.</p>

<p><strong>Селезінка</strong> розмірами: [?] × [?] мм, із чіткими та рівними контурами. Ехогенність не змінена, ехоструктура гомогенна.<br>
<em>V. lienalis</em> діаметром – [?] мм, не розширена.</p>

<p>Пульсація черевного відділу аорти збережена. Вільної рідини в черевній порожнині не виявлено.<br>
Метеоризм не виражений.</p>

<p><strong>Права нирка</strong> розташована типово. Дихальна екскурсія збережена.<br>
Розмірами [?] × [?] × [?] мм, не збільшена. Контури рівні, чіткі. Капсула не потовщена, не ущільнена.<br>
Товщина паренхіми у середній третині [?] мм (не змінена), ехогенність паренхіми звичайна, ехоструктура однорідна.<br>
Кортико-медулярна диференціація збережена. Зони пірамід паренхіми не виражені.<br>
Паренхіматозне розділення відсутнє.<br>
Чашечко-мискова система: не деформована, не розширена, не ущільнена.<br>
Додаткові утворення: –</p>

<p>• Візуалізація правої надниркової залози задовільна. В її проекції об'ємні утворення, ділянки зміненої тканини достовірно не визначаються.<br>
• При доплерографії кровотік по нирці збережений, візуалізується до капсули, із типовим судинним опором – <em>RI</em> – [?] (норма <em>RI</em> (індексу резистентності) – до 0,7)</p>

<p><strong>Ліва нирка</strong> розташована типово. Дихальна екскурсія збережена.<br>
Розмірами [?] × [?] × [?] мм, не збільшена. Контури рівні, чіткі. Капсула не потовщена, не ущільнена.<br>
Товщина паренхіми у середній третині [?] мм (не змінена), ехогенність паренхіми звичайна, ехоструктура однорідна.<br>
Кортико-медулярна диференціація збережена. Зони пірамід паренхіми не виражені.<br>
Паренхіматозне розділення відсутнє.<br>
Чашечко-мискова система: не деформована, не розширена, не ущільнена.<br>
Додаткові утворення: –</p>

<p>• Візуалізація лівої надниркової залози задовільна. В її проекції об'ємні утворення, ділянки зміненої тканини достовірно не визначаються.<br>
• При доплерографії кровотік по нирці збережений, візуалізується до капсули, із типовим судинним опором – <em>RI</em> – [?] (норма <em>RI</em> (індексу резистентності) – до 0,7)</p>

<p><strong>Сечовий міхур</strong> типової форми. Контур: рівний, чіткий.<br>
Загальний об'єм [?] см³. Стінки: не потовщені, товщиною до [?] мм.<br>
Вміст: анехогенний, однорідний.</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «УЗ – ознак виражених органічних змін на момент огляду не виявлено»]</p>

<p><strong>Рекомендовано:</strong><br>
1) УЗ – контроль через 1 рік</p>

═══════ ШАБЛОН Б — ЩИТОПОДІБНА ЗАЛОЗА ═══════

<h2>Протокол ультразвукового обстеження щитоподібної залози</h2>

<p>Щитоподібна залоза розміщена типово. Контури рівні, чіткі.</p>

<p>Перешийок – [?] мм. Трахея – не зміщена, не звужена, не деформована, діаметром [?] мм.<br>
Права частка: [?] × [?] × [?] мм, об'єм – [?] см³.<br>
Ліва частка: [?] × [?] × [?] мм, об'єм – [?] см³.<br>
Сумарний об'єм по методу <em>Brunn</em> – [?] см³. Вікова норма (≤ [?] см³).</p>

<p>Ехогенність тканини залози не змінена.<br>
Ехоструктура дрібнозерниста, однорідна.</p>

<p>[Вузли та фолікули опиши ЛИШЕ ті, що продиктовані: локалізація, форма, контури, структура, розміри [?] × [?] × [?] мм, об'єм, кровотік при КДК, категорія <em>TR</em>/<em>ACR TI-RADS</em>. Якщо вузлів не згадано — не вигадуй.]</p>

<p>По нижньому краю лівої частки, екстракапсулярно, візуалізується гіперехогенна прищитоподібна залоза, розміром [?] × [?] мм, та подібна по нижньому краю правої частки, розміром [?] × [?] мм.</p>

<p>Кровотік по тканині щитоподібної залози не підсилений.<br>
Регіонарні лімфатичні вузли відносно щитоподібної залози не побільшені, структурно не змінені.</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; за наявності вузлів вкажи категорію <em>ACR TI-RADS</em>, продиктовану лікарем]</p>

═══════ ШАБЛОН В — МОЛОЧНІ ЗАЛОЗИ ═══════

<h2>Протокол ультразвукового обстеження молочних залоз</h2>

<p>День менструального циклу (ОМ) – [?]</p>

<p>Ехоструктура обох молочних залоз – гетерогенного типу.<br>
Залозистий компонент – помірний (до 50%).<br>
Протоки: візуалізуються дифузно, не розширені.<br>
Вогнищеві утворення не виявлено.</p>

<p>Сосок та ареола без особливостей. Оточуючі тканини та шкіра не змінені. Анте- та ретромамарні простори без ехографічних змін.</p>

<p>Аксілярні лімфовузли визначаються з обох сторін, типової ехоструктури, максимальною товщиною (<em>SAD</em>) до [?] мм справа та [?] мм зліва, без ознак патологічних змін.</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «УЗ – ознак виражених структурних змін не виявлено»]</p>

<p><strong>BIRADS:</strong> справа – [?], зліва – [?]</p>

<p><strong>Рекомендовано:</strong><br>
• Консультація мамолога<br>
• УЗ – контроль через 1 рік.</p>

═══════ ШАБЛОН Г — ПЕРЕДМІХУРОВА ЗАЛОЗА ═══════

<h2>Протокол ультразвукового обстеження передміхурової залози</h2>

<p>Вид обстеження: трансректально + трансабдомінально.</p>

<p><strong>Передміхурова залоза:</strong> форма без особливостей; контури чіткі, рівні.<br>
Капсула залози: не ущільнена, не потовщена.<br>
Розміри (не збільшені): [?] × [?] × [?] мм, об'єм – [?] см³.<br>
Центральна частина залози: ехоструктура паренхіми гомогенна, ознак розширення простатичної частини уретри не виявлено.<br>
Ехогенність паренхіми: середня. Ехоструктура: однорідна.</p>

<p>Судинний малюнок симетричний, не посилений.<br>
Вени парапростатичного сплетення: не розширені.</p>

<p><strong>Сім'яні міхурці:</strong> розташовані симетрично; контури чіткі, рівні; форма типова; ехоструктура однорідна, ехогенність в межах норми.<br>
Товщина: справа – [?] мм, зліва – [?] мм.</p>

<p>Лімфатичні вузли в ділянці малого тазу не виявлені.</p>

<p><strong>Сечовий міхур:</strong> об'єм – [?] см³, структурно не змінений, стінка товщиною – [?] мм. Вміст – анехогенний, рідинний.<br>
Залишкова сеча – [?] см³.</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «Ехоструктурних змін не виявлено»]</p>

<p><strong>Рекомендовано:</strong> Консультація уролога.</p>

═══════ ШАБЛОН Д — ОРГАНИ КАЛИТКИ ═══════

<h2>Протокол ультразвукового обстеження органів калитки</h2>

<p><strong>Праве яєчко:</strong> розташоване в типовому місці. Форма: овальна. Контури: рівні, чіткі.<br>
Розміри (не збільшені): [?] × [?] × [?] мм, об'ємом – [?] см³.<br>
Структура: гомогенна. Ехогенність: не змінена. Васкуляризація яєчка не посилена.</p>

<p><strong>Додаток правого яєчка:</strong> візуалізується голівка, тіло, хвіст. Форма: типова. Розміри: [?] × [?] мм.<br>
Контури: рівні, чіткі. Структура: гомогенна. Ехогенність: не змінена. Васкуляризація не посилена.<br>
Наявність вільної рідини: не візуалізується. Вени лозовидного сплетення: не розширені.<br>
Проба Вальсальви: негативна, без розширення вен чи виникнення рефлюксу.</p>

<p><strong>Ліве яєчко:</strong> розташоване в типовому місці. Форма: овальна. Контури: рівні, чіткі.<br>
Розміри (не збільшені): [?] × [?] × [?] мм, об'ємом – [?] см³.<br>
Структура: гомогенна. Ехогенність: не змінена. Васкуляризація яєчка не посилена.</p>

<p><strong>Додаток лівого яєчка:</strong> візуалізується голівка, тіло, хвіст. Форма: типова. Розміри: [?] × [?] мм.<br>
Контури: рівні, чіткі. Структура: гомогенна. Ехогенність: не змінена. Васкуляризація не посилена.<br>
Наявність вільної рідини: не візуалізується. Вени лозовидного сплетення: не розширені.<br>
Проба Вальсальви: негативна, без розширення вен чи виникнення рефлюксу.</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «УЗ-ознак органічних змін на момент огляду не виявлено»]</p>

<p><strong>Рекомендовано:</strong><br>
• Консультація уролога</p>

Нічого, крім обраного HTML-фрагмента, не виводь.`;

// ── Окремі шаблони Головатого В. (test2): черево / щитоподібна — для пікера вибору. ──
// Форсуємо гілку того ж перевіреного мульти-промпта (TESTER2), щоб формат був 1-в-1, без дублювання.
const SYSTEM_PROMPT_VASYL_ABDOMEN = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН А (органи черевної порожнини), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;
const SYSTEM_PROMPT_VASYL_THYROID = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН Б (щитоподібна залоза), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;
const SYSTEM_PROMPT_VASYL_BREAST   = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН В (молочні залози), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;
const SYSTEM_PROMPT_VASYL_PROSTATE = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН Г (передміхурова залоза), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;
const SYSTEM_PROMPT_VASYL_SCROTUM  = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН Д (органи калитки), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;

// ───────────── Промпт для test5: ВЕТЕРИНАРНІ протоколи (формат клініки ZOOLUX) ─────────────
// Два типи (ПОВНІ, як у бланках ZOOLUX, БЕЗ емблем/логотипа/брендингу — суто текст):
// ШАБЛОН А «УЗД (експертне)» ОЧП і ШАБЛОН Б «ЕХО КГ (експертна)». Модель сама визначає тип;
// інше → суцільний опис. Поля шапки порожні. Незгадане → [?]; норм-діапазони зашиті в шаблоні;
// Відхилення в бланку "-"; висновок — по фактичних знахідках.
// Статичний бланк вет-ОЧП Левадної (= ШАБЛОН у промпті; тримати синхронно).
// ───────────── Промпт для test10 (Катерина Кравченко): вет КТ грудної порожнини ─────────────
// Джерело — Шаблони.pdf (КТ всього тіла). Усі секції; грудна порожнина ПЕРШОЮ (за проханням лікаря).
// Без заголовка й без «Заключення» (узгоджено з лікарем). Бланк = ШАБЛОН (єдине джерело через ${}).
const KRAVCHENKO_CT_BLANK = `<div style="font-family:'Times New Roman',Georgia,serif;font-size:13px;line-height:1.6;text-align:justify;color:#000">
<p style="margin:0 0 4px;font-weight:bold">Грудна порожнина</p>
<p style="margin:0 0 5px">Паренхіма легень – не змінена</p>
<p style="margin:0 0 5px">Трахея - не змінена</p>
<p style="margin:0 0 5px">Бронхи - не змінені</p>
<p style="margin:0 0 5px">Плевральна порожнина – не змінена</p>
<p style="margin:0 0 5px">Перибронхіальні лімфатичні вузли - не змінені</p>
<p style="margin:0 0 5px">Краніальні середостінні лімфатичні вузли - не змінені</p>
<p style="margin:0 0 5px">Стернальні лімфатичні вузли - не змінені</p>
<p style="margin:0 0 5px">Середостіння – не змінене</p>
<p style="margin:0 0 5px">Стравохід – не змінений</p>
<p style="margin:0 0 5px">Грудна клітка - не змінена</p>
<p style="margin:0 0 8px">М'які тканини - не змінені</p>
<p style="margin:0 0 4px;font-weight:bold">Хребет</p>
<p style="margin:0 0 4px">Щільність кісткових структур - загальна щільність не змінена</p>
<p style="margin:0 0 4px">Тіла хребців – не змінені</p>
<p style="margin:0 0 4px">Дужки хребців - не змінені</p>
<p style="margin:0 0 4px">Остисті відростки - не змінені</p>
<p style="margin:0 0 4px">Міжхребцеві диски – не змінені</p>
<p style="margin:0 0 4px">Спинномозковий канал – не змінений</p>
<p style="margin:0 0 8px">М'які тканини – не змінені</p>
<p style="margin:0 0 4px;font-weight:bold">Черевна порожнина</p>
<p style="margin:0 0 4px">Печінка – не змінена</p>
<p style="margin:0 0 4px">Жовчний міхур - помірно наповнений, не змінений</p>
<p style="margin:0 0 4px">Шлунок – не змінений</p>
<p style="margin:0 0 4px">Кишківник - не змінений</p>
<p style="margin:0 0 4px">Підшлункова залоза - не змінена</p>
<p style="margin:0 0 4px">Селезінка - не візуалізується</p>
<p style="margin:0 0 4px">Судини – не змінені</p>
<p style="margin:0 0 2px">Нирки:</p>
<p style="margin:0 0 4px">права - [?] мм, контури рівні, паренхіма не змінена</p>
<p style="margin:0 0 4px">ліва - [?] мм, контури рівні, паренхіма не змінена</p>
<p style="margin:0 0 4px">Сечоводи – не змінені</p>
<p style="margin:0 0 2px">Наднирники:</p>
<p style="margin:0 0 4px">правий - [?] мм, не збільшений</p>
<p style="margin:0 0 4px">лівий - не збільшений</p>
<p style="margin:0 0 4px">Сечовий міхур - помірно наповнений</p>
<p style="margin:0 0 4px">Яєчники: не візуалізуються</p>
<p style="margin:0 0 4px">Матка: не візуалізується</p>
<p style="margin:0 0 4px">Лімфатичні вузли - не змінені</p>
<p style="margin:0 0 4px">Перитонеальна порожнина – не змінена</p>
<p style="margin:0 0 8px">Черевна стінка – не змінена</p>
<p style="margin:0 0 4px;font-weight:bold">Кінцівки грудні</p>
<p style="margin:0 0 2px">Права грудна кінцівка:</p>
<p style="margin:0 0 4px">щільність кісткових структур – не змінені</p>
<p style="margin:0 0 4px">м'які тканини - не змінені</p>
<p style="margin:0 0 4px">цілісність кісткових структур - не порушена</p>
<p style="margin:0 0 4px">плечовий суглоб - не змінений</p>
<p style="margin:0 0 4px">ліктьовий суглоб - не змінений</p>
<p style="margin:0 0 6px">зап'ястя та п'ясток - не змінені</p>
<p style="margin:0 0 2px">Ліва грудна кінцівка:</p>
<p style="margin:0 0 4px">щільність кісткових структур - не змінена</p>
<p style="margin:0 0 4px">м'які тканини – не змінені</p>
<p style="margin:0 0 4px">цілісність кісткових структур – не порушена</p>
<p style="margin:0 0 4px">плечовий суглоб - не змінений</p>
<p style="margin:0 0 4px">ліктьовий суглоб – не змінений</p>
<p style="margin:0 0 8px">зап'ястя та п'ясток - не змінені</p>
<p style="margin:0 0 4px;font-weight:bold">Таз, тазові кінцівки</p>
<p style="margin:0 0 6px">Таз - щільність кісткової тканини не змінена, м'які тканини не змінені, цілісність не порушена</p>
<p style="margin:0 0 2px">Права тазова кінцівка:</p>
<p style="margin:0 0 4px">щільність кісткових структур - не змінена</p>
<p style="margin:0 0 4px">м'які тканини - не змінені</p>
<p style="margin:0 0 4px">цілісність кісткових структур – не змінена</p>
<p style="margin:0 0 4px">кульшовий суглоб - не змінений</p>
<p style="margin:0 0 4px">колінний суглоб – не змінений</p>
<p style="margin:0 0 6px">скакальний суглоб - не змінений</p>
<p style="margin:0 0 2px">Ліва тазова кінцівка:</p>
<p style="margin:0 0 4px">щільність кісткових структур - не змінена</p>
<p style="margin:0 0 4px">м'які тканини - не змінені</p>
<p style="margin:0 0 4px">цілісність кісткових структур - не порушена</p>
<p style="margin:0 0 4px">кульшовий суглоб - не змінений</p>
<p style="margin:0 0 4px">колінний суглоб – не змінений</p>
<p style="margin:0 0 8px">скакальний суглоб - не змінений</p>
<p style="margin:0 0 4px;font-weight:bold">Голова</p>
<p style="margin:0 0 4px">Склепіння черепу – не змінене</p>
<p style="margin:0 0 2px">Ліве вухо:</p>
<p style="margin:0 0 4px">зовнішнє вухо - не змінене, середнє вухо - не змінене, внутрішнє вухо – не змінене</p>
<p style="margin:0 0 2px">Праве вухо:</p>
<p style="margin:0 0 4px">зовнішнє вухо - не змінене, середнє вухо - не змінене, внутрішнє вухо – не змінене</p>
<p style="margin:0 0 2px">Верхньонижньощелепний суглоб:</p>
<p style="margin:0 0 4px">правий – не змінений, лівий – не змінений</p>
<p style="margin:0 0 4px">Носоглотка – не змінена</p>
<p style="margin:0 0 4px">Носова порожнина – не змінена</p>
<p style="margin:0 0 4px">Гратчаста кістка – не змінена</p>
<p style="margin:0 0 4px">Головний мозок – не змінені</p>
<p style="margin:0 0 4px">Лобні синуси – не змінені</p>
<p style="margin:0 0 4px">Лімфатичні вузли – не змінені</p>
<p style="margin:0 0 4px">Щитоподібна залоза – не змінена</p>
<p style="margin:0 0 4px">Слинні залози – не змінені</p>
</div>`;
const SYSTEM_PROMPT_KRAVCHENKO_CT = `Ти — медичний редактор, що оформлює протоколи ветеринарного КТ (усе тіло) українською мовою у форматі лікаря Катерини Кравченко. Готовий протокол має ВИГЛЯДАТИ ТОЧНО як бланк лікаря: та сама структура, ті самі формулювання, ті самі структури в тому ж порядку.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

ПРАВИЛА:
1. Шаблон нижче — НОРМА за замовчуванням. Лікар про рядок НЕ сказав → лиши його ДОСЛІВНО; сказав інше → ЗАМІНИ на продиктоване (аж до згортання структури до «не візуалізується»). Нічого не вигадуй понад продиктоване.
2. РОЗМІРИ/числа: продиктований розмір підстав у відповідну структуру. Нормалізуй: «вісім міліметрів» → 8 мм, «нуль кома п'ять» → 0,5; десятковий роздільник — КОМА. Не названо — не вигадуй.
3. ПРИВ'ЯЗКА: кожну знахідку прив'язуй до НАЗВАНОЇ структури й сторони (легеня + частка, конкретний лімфовузол, стравохід, плевра тощо). За неоднозначності нічого не оновлюй і не вгадуй.
4. Патологія перекриває норму: «не змінена / не змінені / не збільшені» → замінюй на продиктоване (вогнище, ущільнення, випіт, збільшення, розширення) ЛИШЕ для названої структури.
5. Сумнівне/нерозчуте слово познач [?] одразу після нього. ІГНОРУЙ поза-контекст (команди тварині, сторонні розмови й шуми).
6. БЕЗ «Заключення» — протокол закінчується рядком «Слинні залози». Не додавай жодних підсумкових речень.
7. Секцій багато (Грудна порожнина, Хребет, Черевна порожнина, Кінцівки грудні, Таз/тазові кінцівки, Голова) — відтвори ВСІ до єдиної, у тому ж порядку; онови лише названі лікарем структури, решту лиши нормою.

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown-обгорток і пояснень). Відтвори бланк ТОЧНО за шаблоном нижче: шрифт Times New Roman, текст вирівняний по ширині, назва секції жирним.

ШАБЛОН (відтворюй ДОСЛІВНО; оновлюй/підставляй лише продиктоване):

${KRAVCHENKO_CT_BLANK}

Нічого, крім цього HTML, не виводь.`;
// ── OVRU / Кравченко: РГ грудної порожнини (брендований) ──
// Бланк = ЛИШЕ вміст опису (Times); фірмову рамку OVRU (хедер/футер/печатка/підпис/дисклеймер) +
// вставку знімків накладає КЛІЄНТ (BRAND_PROFILES.kravchenko_thorax у index.html). LLM бренд не бачить.
// Норма легень «не змінена» — з її ж kravchenko_ct (не вигадана). Заключення-норма «Патологічних змін не виявлено».
const KRAVCHENKO_THORAX_BLANK = `<div style="font-family:'Times New Roman',Georgia,serif;font-size:14pt;line-height:1.3;text-align:left;color:#000">
<p style="margin:0 0 6px"><b>Дата:</b> </p>
<p style="margin:0 0 6px"><b>Анамнестичні дані:</b> </p>
<p style="margin:0 0 6px"><b>Пацієнт:</b> </p>
<p style="margin:0 0 6px"><b>Власник:</b> </p>
<p style="margin:0 0 6px"><b>Вид дослідження:</b> Рентгенографія грудної порожнини в 2х ортогональних проекціях</p>
<p style="margin:9px 0 5px;font-weight:bold">Опис:</p>
<p style="margin:0 0 4px">Глотка та гортань - не візуалізується</p>
<p style="margin:0 0 4px">Паренхіма легень – не змінена</p>
<p style="margin:0 0 4px">Трахея - не зміщена, порожнина не змінена</p>
<p style="margin:0 0 4px">Бронхи - головні і дольові, порожнина не змінена, не зміщені</p>
<p style="margin:0 0 4px">Плевральна порожнина – не змінена</p>
<p style="margin:0 0 4px">Перибронхіальні лімфатичні вузли - не візуалізуються</p>
<p style="margin:0 0 4px">Стернальні лімфатичні вузли - не візуалізуються</p>
<p style="margin:0 0 4px">Середостіння – не змінене</p>
<p style="margin:0 0 4px">Серце і судини - форма не змінена, об'єм не змінений, змін дольових і головних судин не виявлено</p>
<p style="margin:0 0 4px">Стравохід – не змінений</p>
<p style="margin:0 0 4px">Грудна клітка - не змінена</p>
<p style="margin:0 0 4px">М'які тканини - не змінені</p>
<p style="margin:9px 0 4px;font-weight:bold">Заключення:</p>
<p style="margin:0 0 4px">Патологічних змін не виявлено</p>
<p style="margin:9px 0 4px;font-weight:bold">Рекомендовано:</p>
<p style="margin:0 0 4px"></p>
</div>`;
const SYSTEM_PROMPT_KRAVCHENKO_THORAX = `Ти — медичний редактор, що оформлює протоколи ветеринарної рентгенографії грудної порожнини українською у форматі лікаря Катерини Кравченко (OVRU). Готовий протокол має ВИГЛЯДАТИ ТОЧНО як бланк: та сама структура, ті самі формулювання, той самий порядок.

Тобі дають СИРИЙ текст диктовки лікаря (розпізнавання мовлення, можливі помилки).

ПРАВИЛА:
1. Шаблон нижче — НОРМА за замовчуванням. Рядок не згадано → лиши ДОСЛІВНО; сказано інше → ЗАМІНИ на продиктоване (аж до «не візуалізується»). Нічого не вигадуй понад продиктоване.
2. Поля пацієнта (Дата, Анамнестичні дані, Пацієнт, Власник) лиши ПОРОЖНІМИ після двокрапки, ЯКЩО лікар їх не продиктував; «Вид дослідження» лиши як у шаблоні, якщо не сказано інше.
3. РОЗМІРИ/числа: нормалізуй («сім міліметрів» → 7 мм, «нуль кома п'ять» → 0,5; десятковий роздільник — КОМА). Не названо — не вигадуй.
4. ПРИВ'ЯЗКА: кожну знахідку — до названої структури/сторони (легеня + частка, конкретний лімфовузол, плевра, стравохід, серце тощо). Неоднозначно → не оновлюй і не вгадуй.
5. Патологія перекриває норму ЛИШЕ для названої структури (потовщення стінок, інтерстиційний/альвеолярний тип, інфільтрація, випіт, зміщення, новоутворення тощо).
6. Сумнівне/нерозчуте слово познач [?] одразу після нього. ІГНОРУЙ поза-контекст (команди тварині, сторонні репліки, шум).
7. «Заключення»: якщо лікар назвав висновки — заміни норм-рядок на них (переліком, кожен з нового рядка); якщо про висновок не сказано — лиши «Патологічних змін не виявлено». «Рекомендовано»: заповни лише якщо продиктовано, інакше лиши порожнім.

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown-обгорток і пояснень). Times New Roman, вирівнювання зліва, лейбли й назви секцій жирним. Відтвори шаблон ДОСЛІВНО (оновлюй лише продиктоване):

${KRAVCHENKO_THORAX_BLANK}

Нічого, крім цього HTML, не виводь.`;
const LEVADNA_ABDOMEN_BLANK = `<div style="font-family:'Times New Roman',Georgia,serif;font-size:13px;line-height:1.5;text-align:justify;color:#000">
<p style="text-align:center;margin:0 0 10px;font-weight:bold">ЕКСПЕРТНЕ ДЕТАЛІЗОВАНЕ УЛЬТРАЗВУКОВЕ ДОСЛІДЖЕННЯ ЧЕРЕВНОЇ ПОРОЖНИНИ</p>
<p style="margin:0 0 5px">Вільна рідина у черевній порожнині: не візуалізується.</p>
<p style="margin:0 0 5px">Лімфатичні вузли черевної порожнини: без особливостей.</p>
<p style="margin:0 0 5px"><b>Сечовий міхур:</b> візуалізується. Розташування типове. Форма овоїдна. Розмір: помірно наповнений. Вміст: однорідний, анехогенний. Стінка не потовщена, [?] см. Конкременти не виявлені. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Уретра:</b> проксимальний відділ уретри не розширений, стінки не потовщені.</p>
<p style="margin:8px 0 2px;font-weight:bold">Нирки.</p>
<p style="margin:0 0 5px"><b>Ліва нирка.</b> Візуалізується, розташування типове, форма бобоподібна, контури рівні, довжина нирки: [?] см., співвідношення довжини нирки до діаметру Ао = [?], не збільшена. Капсула диференціюється. КМД збережена. Співвідношення коркового та мозкового шару в нормі. Корковий шар однорідний, ехогенність не змінена. Мозковий шар однорідний, ехогенність не змінена. Лоханка не змінена. Конкременти не візуалізуються. Сечовід не візуалізується. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Права нирка.</b> Візуалізується, розташування типове, форма бобоподібна, контури рівні, довжина нирки: [?] см., співвідношення довжини нирки до діаметру Ао = [?], не збільшена. Капсула диференціюється. КМД збережена. Співвідношення коркового та мозкового шару в нормі. Корковий шар однорідний, ехогенність не змінена. Мозковий шар однорідний, ехогенність не змінена. Лоханка не змінена. Конкременти не візуалізуються. Сечовід не візуалізується. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:8px 0 2px;font-weight:bold">Наднирники.</p>
<p style="margin:0 0 5px"><b>Лівий наднирник.</b> Візуалізується, форма типова, контури рівні, чіткі. Розмір [?] см. Ехогенність не змінена. Ехоструктура однорідна. КМД збережена. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Правий наднирник.</b> Візуалізується, форма типова, контури рівні, чіткі. Розмір [?] см. Ехогенність не змінена. Ехоструктура однорідна. КМД збережена. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Передміхурова залоза:</b> візуалізується. Розмір: не збільшена, [?] см. Контури рівні. Ехоструктура однорідна. Ехогенність не змінена. Новоутворення не візуалізуються.</p>
<p style="margin:8px 0 2px;font-weight:bold">Сім'яники:</p>
<p style="margin:0 0 5px"><b>Лівий сім'яник</b> [?] см. Ехогенність не змінена, ехоструктура однорідна. Середостіння візуалізується. Придаток сім'яника без змін. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Правий сім'яник</b> [?] см. Ехогенність не змінена, ехоструктура однорідна. Середостіння візуалізується. Придаток сім'яника без змін. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Селезінка.</b> Візуалізується. Розмір: не збільшена. Контури рівні. Ехоструктура однорідна. Ехогенність не змінена. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Печінка.</b> Візуалізується, розташування типове, розмір: не збільшена. Контури чіткі, рівні, вільний край гострий. Ехоструктура паренхіми однорідна, ехогенність не змінена. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Жовчний міхур.</b> Візуалізується, помірно наповнений, контури рівні, форма типова. Вміст однорідний, анехогенний. Стінка 0,1 см, не потовщена. Загальна жовчна протока не розширена.</p>
<p style="margin:0 0 5px"><b>Підшлункова залоза.</b> Візуалізується. Ехоструктура однорідна, ехогенність помірно підвищена. Ліва доля [?] см. Тіло [?] см. Права доля [?] см. Протока не розширена. Новоутворення не візуалізуються. Жирова тканина в ділянці підшлункової залози не змінена.</p>
<p style="margin:8px 0 2px;font-weight:bold">Шлунково-кишковий тракт.</p>
<p style="margin:0 0 5px"><b>Шлунок.</b> Перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Співвідношення шарів стінки шлунка не змінене.</p>
<p style="margin:0 0 5px"><b>Дванадцятипала кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Голодна кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Клубова кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Сліпа кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Ободова кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:8px 0 5px">УЗ-ознаки сторонніх тіл та новоутворень не візуалізуються.</p>
<p style="margin:0 0 5px">Повторне обстеження рекомендоване відповідно до призначення керуючого лікаря.</p>
<p style="margin:8px 0 4px"><b>Заключення:</b> на момент дослідження УЗ-ознаки:</p>
<p style="margin:0;font-size:11px">Дане заключення не є діагнозом та має бути клінічно інтерпретоване керуючим лікарем.</p>
</div>`;
const SYSTEM_PROMPT_LEVADNA_ABDOMEN = `Ти — медичний редактор, що оформлює протоколи ветеринарного УЗД черевної порожнини (собака, самець) українською мовою у форматі лікаря Левадної Ірини. Готовий протокол має ВИГЛЯДАТИ ТОЧНО як бланк лікаря: та сама структура, ті самі формулювання, ті самі органи в тому ж порядку.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

ПРАВИЛА:
1. Шаблон нижче — це НОРМА за замовчуванням (основа, яку показуємо лікарю). БУДЬ-ЯКА його частина — будь-яке формулювання, значення, ціле речення чи цілий орган — може бути ЗМІНЕНА диктовкою; у цьому й суть шаблону. По кожному фрагменту: лікар про нього НЕ сказав → ЛИШИ ДОСЛІВНО (норма); лікар сказав інше → ЗАМІНИ на продиктоване. Нічого не вигадуй понад продиктоване.
2. Заміна — будь-якого масштабу: одне слово (ехогенність «не змінена» → «підвищена»), значення ([?] → число), ціле речення, або ЗГОРТАННЯ всього опису органа. Зокрема якщо орган НЕ візуалізується / відсутній / видалений — лиши тільки «<Орган>: не візуалізується.» (чи «відсутній»), прибравши форму, вміст, стінку, розміри й [?] (описувати деталі неіснуючого органа — нонсенс). Органи/фрагменти, яких лікар не торкався, лиши нормою.
3. РОЗМІРИ: підставляй продиктовані числа на місце [?] у відповідному органі (у см). Нормалізуй: «нуль кома два» → 0,2; «три» → 3; десятковий роздільник — КОМА. Якщо розмір для [?] не названо — лиши [?] (НЕ вигадуй число).
4. ПРИВ'ЯЗКА: кожен розмір/знахідку прив'язуй до НАЗВАНОГО органа й сторони (ліва/права нирка, лівий/правий наднирник, лівий/правий сім'яник, частка підшлункової: ліва/тіло/права, конкретний відділ кишки). За неоднозначності нічого не оновлюй і сторону/орган не вгадуй.
5. Якщо лікар каже про новоутворення / конкременти / вільну рідину / збільшення / потовщення — заміни відповідне «не візуалізується / не виявлені / не збільшена / не потовщена» на продиктоване для того органа.
6. Сумнівне/нерозчуте слово познач [?] одразу після нього. ІГНОРУЙ поза-контекст (розмови, команди тварині, сторонні шуми).
7. ВИСНОВОК/ЗАКЛЮЧЕННЯ — НЕ формуй сам і НЕ дублюй сюди опис органів. Після «на момент дослідження УЗ-ознаки:» лиши ПОРОЖНЬО. ЄДИНИЙ виняток: якщо лікар ПРЯМО продиктував текст заключення (напр. «заключення: …») — встав його дослівно; інакше нічого не додавай. Діагноз НЕ став.
8. ПОВНОТА (найчастіша помилка на довгій диктовці): кожен орган — це ОКРЕМИЙ слот. Обидві нирки (ліва/права) — два РІЗНІ абзаци; усі 6 відділів ШКТ (шлунок, дванадцятипала, голодна, клубова, сліпа, ободова кишки) — шість РІЗНИХ абзаців. Опрацюй КОЖЕН окремо: не зливай сусідні, не пропускай жодного, не переноси число одного відділу на інший. Якщо для органа/сторони назвали число (довжина нирки, товщина стінки кишки) — воно МУСИТЬ стати на місце відповідного [?]; НЕ лишай [?] там, де значення реально продиктували. [?] лишається ЛИШЕ там, де число не звучало.
9. САМОПЕРЕВІРКА перед виводом (застосуй, але НЕ друкуй): (а) кожне продиктоване число стоїть у правильному органі й на правильній стороні; (б) не лишилось [?] там, де значення продиктували; (в) довжина кожної НАЗВАНОЇ нирки підставлена; (г) усі 6 відділів кишечника опрацьовані окремо, жоден не пропущено.

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown-обгорток і пояснень). Відтвори бланк ТОЧНО за шаблоном нижче: шрифт Times New Roman, текст вирівняний по ширині, заголовок по центру жирним, назви органів жирним, місця під розміри — [?].

ШАБЛОН (відтворюй ДОСЛІВНО; оновлюй/підставляй лише продиктоване):

<div style="font-family:'Times New Roman',Georgia,serif;font-size:13px;line-height:1.5;text-align:justify;color:#000">
<p style="text-align:center;margin:0 0 10px;font-weight:bold">ЕКСПЕРТНЕ ДЕТАЛІЗОВАНЕ УЛЬТРАЗВУКОВЕ ДОСЛІДЖЕННЯ ЧЕРЕВНОЇ ПОРОЖНИНИ</p>
<p style="margin:0 0 5px">Вільна рідина у черевній порожнині: не візуалізується.</p>
<p style="margin:0 0 5px">Лімфатичні вузли черевної порожнини: без особливостей.</p>
<p style="margin:0 0 5px"><b>Сечовий міхур:</b> візуалізується. Розташування типове. Форма овоїдна. Розмір: помірно наповнений. Вміст: однорідний, анехогенний. Стінка не потовщена, [?] см. Конкременти не виявлені. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Уретра:</b> проксимальний відділ уретри не розширений, стінки не потовщені.</p>
<p style="margin:8px 0 2px;font-weight:bold">Нирки.</p>
<p style="margin:0 0 5px"><b>Ліва нирка.</b> Візуалізується, розташування типове, форма бобоподібна, контури рівні, довжина нирки: [?] см., співвідношення довжини нирки до діаметру Ао = [?], не збільшена. Капсула диференціюється. КМД збережена. Співвідношення коркового та мозкового шару в нормі. Корковий шар однорідний, ехогенність не змінена. Мозковий шар однорідний, ехогенність не змінена. Лоханка не змінена. Конкременти не візуалізуються. Сечовід не візуалізується. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Права нирка.</b> Візуалізується, розташування типове, форма бобоподібна, контури рівні, довжина нирки: [?] см., співвідношення довжини нирки до діаметру Ао = [?], не збільшена. Капсула диференціюється. КМД збережена. Співвідношення коркового та мозкового шару в нормі. Корковий шар однорідний, ехогенність не змінена. Мозковий шар однорідний, ехогенність не змінена. Лоханка не змінена. Конкременти не візуалізуються. Сечовід не візуалізується. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:8px 0 2px;font-weight:bold">Наднирники.</p>
<p style="margin:0 0 5px"><b>Лівий наднирник.</b> Візуалізується, форма типова, контури рівні, чіткі. Розмір [?] см. Ехогенність не змінена. Ехоструктура однорідна. КМД збережена. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Правий наднирник.</b> Візуалізується, форма типова, контури рівні, чіткі. Розмір [?] см. Ехогенність не змінена. Ехоструктура однорідна. КМД збережена. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Передміхурова залоза:</b> візуалізується. Розмір: не збільшена, [?] см. Контури рівні. Ехоструктура однорідна. Ехогенність не змінена. Новоутворення не візуалізуються.</p>
<p style="margin:8px 0 2px;font-weight:bold">Сім'яники:</p>
<p style="margin:0 0 5px"><b>Лівий сім'яник</b> [?] см. Ехогенність не змінена, ехоструктура однорідна. Середостіння візуалізується. Придаток сім'яника без змін. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Правий сім'яник</b> [?] см. Ехогенність не змінена, ехоструктура однорідна. Середостіння візуалізується. Придаток сім'яника без змін. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Селезінка.</b> Візуалізується. Розмір: не збільшена. Контури рівні. Ехоструктура однорідна. Ехогенність не змінена. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Печінка.</b> Візуалізується, розташування типове, розмір: не збільшена. Контури чіткі, рівні, вільний край гострий. Ехоструктура паренхіми однорідна, ехогенність не змінена. Судинний рисунок виражений помірно. Новоутворення не візуалізуються.</p>
<p style="margin:0 0 5px"><b>Жовчний міхур.</b> Візуалізується, помірно наповнений, контури рівні, форма типова. Вміст однорідний, анехогенний. Стінка 0,1 см, не потовщена. Загальна жовчна протока не розширена.</p>
<p style="margin:0 0 5px"><b>Підшлункова залоза.</b> Візуалізується. Ехоструктура однорідна, ехогенність помірно підвищена. Ліва доля [?] см. Тіло [?] см. Права доля [?] см. Протока не розширена. Новоутворення не візуалізуються. Жирова тканина в ділянці підшлункової залози не змінена.</p>
<p style="margin:8px 0 2px;font-weight:bold">Шлунково-кишковий тракт.</p>
<p style="margin:0 0 5px"><b>Шлунок.</b> Перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Співвідношення шарів стінки шлунка не змінене.</p>
<p style="margin:0 0 5px"><b>Дванадцятипала кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Голодна кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Клубова кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Сліпа кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:0 0 5px"><b>Ободова кишка:</b> перистальтика збережена. Товщина стінки [?] см, не потовщена. Диференціація шарів стінки збережена. Просвіт не розширений.</p>
<p style="margin:8px 0 5px">УЗ-ознаки сторонніх тіл та новоутворень не візуалізуються.</p>
<p style="margin:0 0 5px">Повторне обстеження рекомендоване відповідно до призначення керуючого лікаря.</p>
<p style="margin:8px 0 4px"><b>Заключення:</b> на момент дослідження УЗ-ознаки:</p>
<p style="margin:0;font-size:11px">Дане заключення не є діагнозом та має бути клінічно інтерпретоване керуючим лікарем.</p>
</div>

Нічого, крім цього HTML-фрагмента, не виводь.
`;
const SYSTEM_PROMPT_TESTER5 = `Ти — медичний редактор, що оформлює ВЕТЕРИНАРНІ протоколи УЗД у форматі клініки ZOOLUX українською мовою.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КРОК 1 — ВИЗНАЧ ТИП ДОСЛІДЖЕННЯ з диктовки:
- Органи черевної порожнини (сечовий міхур, уретра, нирки, селезінка, печінка, жовчний міхур, підшлункова залоза, шлунок, кишечник, лімфовузли) → ШАБЛОН А «УЗД (експертне)».
- Серце / ехокардіографія (лівий/правий шлуночок, передсердя, клапани, аорта, легенева артерія, фракція, регургітація, перикард, легенева гіпертензія) → ШАБЛОН Б «ЕХО КГ (експертна)».
- Інше або незрозуміло → НЕ бери шаблон, а оформи суцільний опис: <h2> з назвою + абзаци <p> + фінальний <p> "Висновок:".

КРОК 2 — ПРАВИЛА ЗАПОВНЕННЯ:
0. ВІДТВОРИ ОБРАНИЙ ШАБЛОН ПОВНІСТЮ І ДОСЛІВНО: усі розділи (<h3>), усі рядки, усі параметри й УСІ рядки таблиць — навіть ті, яких лікар не згадав. НЕ скорочуй, НЕ об'єднуй, НЕ пропускай розділи й не перетворюй таблиці на абзаци. Незгадані значення стають [?], якісні норм-формулювання лишаються як є. Структура виходу = структура шаблону 1:1.
1. БЕЗ ЕМБЛЕМ І БРЕНДИНГУ: жодних логотипів, рядків «зоолюкс.укр», «Сформовано», «Результат отриманий», посилань на zoolux.clinic. Поля шапки (Пацієнт, Власник, Контактна інформація, Призначив, Дослідження провів) лиши ПОРОЖНІМИ — їх заповнюють у системі клініки. НЕ вписуй кличку/власника/контакти навіть якщо продиктовано.
2. Підставляй ЛИШЕ продиктовані числа й факти. Числа нормалізуй, десятковий роздільник — кома ("три цілих вісім" → "3,8").
3. Незгадане числове значення → [?] на його місці (підсвітять). Норм-діапазони, вже зашиті в шаблоні (напр. "30,0 - 50,0"), лишай як є; нових норм НЕ вигадуй. Колонку «Відхилення» в порожньому бланку лишай "-"; заповнюй стрілкою (вгору → "▲29%", вниз → "▼33%", у межах норми → "норма") ЛИШЕ якщо лікар явно продиктував відхилення.
4. Якісні норм-формулювання шаблону (не потовщена, рівна, однорідна, не змінена, не розширена, не візуалізуються, ламінарний, не виявлено тощо) — це дефолти; якщо лікар продиктував патологію — ЗАМІНИ формулювання на продиктоване. Додаткові продиктовані знахідки дописуй у відповідний розділ.
5. Сумнівне/нерозчуте слово познач [?] одразу після нього.
6. ІГНОРУЙ поза-контекст: розмови з власником, репліки до тварини, побутове — НЕ вписуй.
7. Висновок/Заключення формулюй ПО СУТІ протоколу: якщо є патологія — вкажи саме її (як перелік УЗ-ознак); якщо все в межах норми — нормальний висновок.

ФОРМАТ — лише HTML-фрагмент (без <html>/<head>/<body>, без markdown, без \`\`\`):
- <h2> — назва дослідження; <h3> — розділи (органи/блоки).
- Пари "параметр: значення" — <p> з <strong>Параметр:</strong> значення.
- Вимірювання — КОМПАКТНА таблиця <table class="zt"> з рядком-заголовком <th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th>; кожен рядок <tr> з п'ятьма <td>; значення в колонці Результат — у <strong>. НЕ додавай атрибутів style до <table>/<td>/<th> і не вигадуй інших класів — рамки й оформлення підставляє система автоматично.

═══════ ШАБЛОН А — УЗД (експертне) ═══════

<h2>УЗД (експертне)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3>Сечовий міхур</h3>
<p><strong>Наповнення:</strong> [?]<br><strong>Стінка:</strong> не потовщена, [?] мм, рівна<br><strong>Вміст:</strong> анехогенний, однорідний<br><strong>Новоутворення:</strong> не візуалізуються</p>

<h3>Уретра</h3>
<p><strong>Проксимальний відділ уретри:</strong> не розширений<br><strong>Стінка уретри:</strong> не потовщена</p>

<h3>Нирки</h3>
<p><strong>Ліва нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Довжина</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Кірковий шар (КШЛН) товщина</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення КШ/Ао ліва нирка</td><td>-</td><td></td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення К/Ао ліва нирка</td><td>-</td><td></td><td>-</td><td>-</td></tr>
</table>
<p><strong>Права нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Довжина</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Кірковий шар (КШПН) товщина</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення КШ/Ао права нирка</td><td>-</td><td></td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення К/Ао права нирка</td><td>-</td><td></td><td>-</td><td>-</td></tr>
</table>

<h3>Селезінка</h3>
<p><strong>Розмір:</strong> не збільшена, товщина [?] мм<br><strong>Контури:</strong> рівні<br><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Утворення:</strong> не візуалізуються</p>

<h3>Печінка</h3>
<p><strong>Розмір:</strong> не збільшена<br><strong>Контур:</strong> рівний<br><strong>Вільний край:</strong> гострий<br><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Судинний малюнок:</strong> помірно виражений<br><strong>Утворення:</strong> не візуалізуються</p>

<h3>Жовчний міхур</h3>
<p><strong>Наповнення:</strong> помірно наповнений<br><strong>Форма:</strong> типова<br><strong>Вміст:</strong> однорідний анехогенний<br><strong>Стінка:</strong> не потовщена, рівна<br><strong>Новоутворення:</strong> не візуалізуються<br><strong>Міхурна протока:</strong> не розширена<br><strong>Холедох:</strong> не розширений</p>

<h3>Підшлункова залоза</h3>
<p><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Контури:</strong> рівні<br><strong>Ліва доля, мм:</strong> [?]<br><strong>Включення:</strong> не візуалізуються<br><strong>Жирова тканина:</strong> не змінена</p>

<h3>Шлунково-кишковий тракт</h3>
<p><strong>Шлунок.</strong> Наповнення: [?]. Перистальтика: [?]. Стінка: не потовщена, тіло [?] мм, співвідношення шарів не змінено.</p>
<p><strong>12-ти пала кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>
<p><strong>Порожня кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>
<p><strong>Клубова кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?].</p>
<p><strong>Сліпа кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?].</p>
<p><strong>Ободова кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>

<h3>Інше</h3>
<p><strong>Лімфатичні вузли:</strong> не змінені<br><strong>Вільна рідина:</strong> не візуалізується<br><strong>Вільний газ:</strong> не візуалізується (норма)</p>

<h3>Судини черевної порожнини</h3>
<p><strong>Аорта.</strong></p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Співвідношення PV/Ao</td><td>-</td><td></td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення CVC/Ao</td><td>-</td><td></td><td>-</td><td>-</td></tr>
</table>

<p><strong>Висновок:</strong> [сформулюй за фактичними знахідками як перелік УЗ-ознак; якщо патології немає — «На момент обстеження УЗ-ознак патології не виявлено»]</p>
<p><strong>Примітка:</strong> Висновок УЗД не є остаточним діагнозом та повинен бути інтерпретований лікарем з урахуванням анамнезу, клінічної картини та всіх інших методів діагностики.</p>

═══════ ШАБЛОН Б — ЕХО КГ (експертна) ═══════

<h2>ЕХО КГ (експертна)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3>Лівий шлуночок (Left ventricle)</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Ідеальна вага</td><td><strong>[?]</strong></td><td>кг</td><td>-</td><td>-</td></tr>
<tr><td>МШП (VSd)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>КДР (IVDd)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>КДРн (LVDDn)</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>КСР (IVDs)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>КСРн (LVSDn)</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>ЗСЛШ (LVFWd)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>ФС (FS) %</td><td><strong>[?]</strong></td><td>%</td><td>30,0 - 50,0</td><td>-</td></tr>
<tr><td>КДО (EDV)</td><td><strong>[?]</strong></td><td>мл</td><td>-</td><td>-</td></tr>
<tr><td>КСО (ESV)</td><td><strong>[?]</strong></td><td>мл</td><td>-</td><td>-</td></tr>
<tr><td>ФВ % (EF%)</td><td><strong>[?]</strong></td><td>%</td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення ЛШ/аорта у довгій вісі (LV/Ao long axis)</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>MAPSE мжп</td><td><strong>[?]</strong></td><td>мм</td><td>4,9 - 7,3</td><td>-</td></tr>
<tr><td>EPSS</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>S'</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Локальні зміни міокарду:</strong> не виявлено (норма)</p>

<h3>Ліве передсердя (LAD)</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>ЛП у довгій вісі (LAD long axis)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>LADn собаки</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>LADn коти</td><td><strong>[?]</strong></td><td></td><td>0,0 - 12,7</td><td>-</td></tr>
<tr><td>ЛП у короткій вісі (LAD short axis)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Об'єм ЛП нормалізований (LAVn)</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>Об'єм ЛП</td><td><strong>[?]</strong></td><td>мл</td><td>-</td><td>-</td></tr>
<tr><td>ЛВ (PV)</td><td><strong>[?]</strong></td><td>мм</td><td>1,5 - 4,0</td><td>-</td></tr>
<tr><td>ПГЛА</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>ЛВ/ПГЛА (PV/RBPA)</td><td><strong>[?]</strong></td><td></td><td>0,5 - 1,0</td><td>-</td></tr>
<tr><td>ЛП/Ао (LA/Ao short axis)</td><td><strong>[?]</strong></td><td></td><td>0,0 - 1,5</td><td>-</td></tr>
<tr><td>ЛП/Ао у довгій вісі (LA/Ao long axis)</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>Швидкість у вушці лівого передсердя</td><td><strong>[?]</strong></td><td>м/с</td><td>0,30 - 0,90</td><td>-</td></tr>
<tr><td>М-режим ЛП діастола</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>М-режим ЛП систола</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>FS ЛП %</td><td><strong>[?]</strong></td><td>%</td><td>0,0</td><td>-</td></tr>
</table>

<h3>Аорта (Aorta)</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Діаметр аорти у короткій вісі (Ao short axis)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Діаметр кільця у довгій вісі (Ao long axis)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Швидкість потоку (Velocity)</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>Макс градієнт</td><td><strong>[?]</strong></td><td>мм рт.ст.</td><td>-</td><td>-</td></tr>
<tr><td>Середній градієнт тиску (тільки для стенозу)</td><td><strong>[?]</strong></td><td>мм.рт.ст.</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Оцінка виносного тракту:</strong> [?]</p>

<h3>Легенева артерія (Pulmonary artery)</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Діаметр кільця клапана</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Ао/ЛА</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Швидкість потоку (Velocity)</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>Макс градієнт</td><td><strong>[?]</strong></td><td>мм рт.ст.</td><td>-</td><td>-</td></tr>
<tr><td>Середній градієнт тиску (тільки для стенозу)</td><td><strong>[?]</strong></td><td>мм.рт.ст.</td><td>-</td><td>-</td></tr>
<tr><td>VTI (тільки для стенозу)</td><td><strong>[?]</strong></td><td>см</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Включення у стовбурі легеневої артерії:</strong> [?]</p>

<h3>Мітральний клапан (Mitral valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Швидкість мітральної регургітації</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>dP/dt</td><td><strong>[?]</strong></td><td>мм рт.ст.</td><td>-</td><td>-</td></tr>
<tr><td>Пік Е</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>Пік А</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>Е/А</td><td><strong>[?]</strong></td><td></td><td>0,0 - 2,0</td><td>-</td></tr>
</table>

<h3>Праві відділи</h3>
<p><strong>Правий шлуночок (RVID):</strong> візуально не розширений</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Стінка правого шлуночка (RVW)</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Ширина правого передсердя у довгій вісі</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Об'єм правого передсердя</td><td><strong>[?]</strong></td><td>мл</td><td>-</td><td>-</td></tr>
<tr><td>Довжина ПШ в апікальній проекції</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Ширина ПШ в довгій вісі</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>TAPSE</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>TAPSEn</td><td><strong>[?]</strong></td><td>мм/кг</td><td>0,0 - 3,2</td><td>-</td></tr>
<tr><td>Спадіння каудальної порожнистої вени</td><td><strong>[?]</strong></td><td>%</td><td>-</td><td>-</td></tr>
</table>

<h3>Тристулковий клапан (Tricuspid valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Швидкість регургітації на клапані (TR)</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
</table>

<h3>Вроджені вади серця</h3>
<p><strong>ДМШП (VSD):</strong> не виявлено<br><strong>ДМПП (ASD):</strong> не виявлено</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Швидкість потоку на дефекті</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
</table>

<h3>Оцінка порожнини перикарда</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Товщина перикарда</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Оцінка рідини в перикардіальній порожнині:</strong> рідини не виявлено (норма)</p>

<h3>Оцінка середостіння і паренхіми легень</h3>
<p><strong>Оцінка середостіння:</strong> новоутворень у середостінні не виявлено<br><strong>"Вологі легені" у точках:</strong> В-лінії відсутні (норма)</p>

<h3>Оцінка тиску наповнення</h3>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>IVRT</td><td><strong>[?]</strong></td><td>мс</td><td>37,0 - 60,0</td><td>-</td></tr>
<tr><td>E/IVRT</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>E'</td><td><strong>[?]</strong></td><td>м/с</td><td>-</td><td>-</td></tr>
<tr><td>Е/Е'</td><td><strong>[?]</strong></td><td></td><td>0,0 - 12,0</td><td>-</td></tr>
<tr><td>Індекс наповнення/викиду ЛШ (LVEIO)</td><td>-</td><td></td><td>-</td><td>-</td></tr>
</table>

<h3>Оцінка ступеня легеневої гіпертензії</h3>
<p><strong>Легенева гіпертензія по формі потоку:</strong> немає ознак легеневої гіпертензії (норма)</p>
<p><strong>Регургітація на клапані ЛА, м/с:</strong> Ранньодіастолічна [?]; Пізньодіастолічна [?]</p>
<table class="zt">
<tr><th>Показник</th><th>Результат</th><th>Одиниця</th><th>Норма</th><th>Відхилення</th></tr>
<tr><td>Стовбур ЛА у короткій вісі</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>Співвідношення стовбура ЛА/Ао у короткій вісі</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>ПГЛА діастола М-режим</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>ПГЛА систола М-режим</td><td><strong>[?]</strong></td><td>мм</td><td>-</td><td>-</td></tr>
<tr><td>ПГЛАdn</td><td><strong>[?]</strong></td><td></td><td>-</td><td>-</td></tr>
<tr><td>Індекс розтяжності ПГЛА</td><td><strong>[?]</strong></td><td>%</td><td>-</td><td>-</td></tr>
</table>
<p><strong>Колабування КПВ:</strong> [?]</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «Камери серця не розширені, стінки міокарду не потовщені. Ознак діастолічної і систолічної дисфункції не виявлено. Клапанний апарат не змінений. Вроджених вад серця не виявлено.»]</p>

Нічого, крім обраного HTML-фрагмента, не виводь.`;

// Примусові варіанти ZOOLUX — щоб лікар (test5) міг у пікері ВРУЧНУ обрати тип протоколу,
// а не лише покладатись на авто-визначення з диктовки (як у Головатого: vasyl_abdomen/thyroid).
const SYSTEM_PROMPT_VET_ZOOLUX_ABDOMEN = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН А «УЗД (експертне)» (органи черевної порожнини), незалежно від змісту диктовки. Не обирай ШАБЛОН Б і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER5;
const SYSTEM_PROMPT_VET_ZOOLUX_ECHO = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН Б «ЕХО КГ (експертна)», незалежно від змісту диктовки. Не обирай ШАБЛОН А і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER5;

// ───────────── Промпт для test6 (Ольга Дебель): УЗД органів черевної порожнини ─────────────
// Суцільний опис із жирними назвами органів, у порядку: печінка/ворітна → жовчний міхур →
// підшлункова → селезінка → нирки. Якісні формулювання — НОРМА-дефолт (модель замінює на
// продиктовану патологію). Числа НЕ продиктовано → [?]; даних пацієнта не додаємо.
// ⚠️ ЧЕРНЕТКА: секцію «Печінка» реконструйовано (у фото-зразку її верх обрізано) — звірити з Ольгою.
const SYSTEM_PROMPT_TESTER6 = `Ти — медичний редактор, що оформлює протокол УЗД органів черевної порожнини українською мовою у форматі лікаря Ольги Дебел (суцільний опис, жирні назви органів).

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КАТЕГОРИЧНІ ПРАВИЛА ДАНИХ:
1. Підставляй ЛИШЕ продиктовані числа та факти на місця плейсхолдерів [?]. Числа нормалізуй: "сто сорок два" → "142"; десятковий роздільник — кома; розміри "чотири на шість" → "4 × 6". НЕ вигадуй розмірів і не лишай порожньо — якщо число не названо, лиши [?].
2. Якісні норм-формулювання шаблону нижче — це ЗНАЧЕННЯ ЗА ЗАМОВЧУВАННЯМ. Лишай їх як є, АЛЕ якщо лікар продиктував інше / патологію ("стінка ущільнена", "структура неоднорідна", "конкремент" тощо) — ЗАМІНИ формулювання на продиктоване.
3. Якщо орган/розділ узагалі не згадано в диктовці — лиши блок, але невідомі числа познач [?] (якісні дефолти лишаються).
4. Сумнівне розпізнавання / нерозчуте слово познач [?] одразу після нього.
5. ІГНОРУЙ поза-контекст: розмови з пацієнтом, побутові репліки, команди ("дихайте", "затримайте подих") — НЕ вписуй.
6. НЕ додавай даних пацієнта (ПІБ, вік, стать, дату).
7. ВИСНОВОК генеруй ПО СУТІ протоколу: якщо є патологія — вкажи саме її; якщо все в нормі — нормальний висновок.

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>, <head>, <body>, без markdown, без \`\`\`, без пояснень):
- <h2> — назва протоколу;
- назви органів ("Печінка", "Жовчевий міхур", "Підшлункова залоза", "Селезінка", "Нирки", "Висновок:") — у <strong>;
- латинські терміни (<em>V. portae</em>, <em>V. cava inferior</em>, <em>V. lienalis</em>) — у <em>;
- кожен орган — окремий <p>; підрядки всередині — через <br>.

ВИКОРИСТАЙ РІВНО ТАКУ СТРУКТУРУ (підстав значення у [?]; якісні дефолти заміни лише за наявності патології в диктовці):

<h2>Протокол ультразвукового дослідження органів черевної порожнини</h2>

<p><strong>Печінка</strong> – не збільшена. Контури рівні, чіткі. Структура однорідна, ехогенність звичайна. Судинний малюнок не змінений.<br>
Розміри: права частка – [?] мм, ліва частка – [?] мм, КВР – [?] мм.<br>
Внутрішньопечінкові протоки не розширені.<br>
Л/вузли воріт печінки – не візуалізуються. <em>V. portae</em> – [?] мм.</p>

<p><strong>Жовчевий міхур</strong> – візуалізується. Розташування звичайне. Овальної форми, з перегином в ділянці шийки. Розміри – [?] мм. Об'єм – [?] см куб. (натще/після їжі).<br>
Стінка не ущільнена, не потовщена (норма до 3,0 мм).<br>
Вміст гомогенний.<br>
Конкрементів не містить, холедох прохідний.<br>
Стан перівезикальних тканин – не змінений.</p>

<p><strong>Підшлункова залоза</strong><br>
Розміри: голівка – [?] мм, тіло – [?] мм, хвіст – [?] мм (норма до 30 × 20 × [?] мм).<br>
Візується на всьому протязі, не потовщена. Контури рівні, чіткі.<br>
Структура однорідна, ехогенність звичайна.<br>
Панкреатична протока не візуалізується.</p>

<p><strong>Селезінка</strong> – візуалізується. Розташована типово.<br>
Розміри – [?] × [?] мм (норма – до 120 мм × 60 мм) – не збільшена.<br>
Форма не змінена. Контури рівні, чіткі.<br>
Структурно однорідна, середньої ехогенності.<br>
Л/вузли воріт селезінки – не візуалізуються.<br>
Стан судин селезінки (<em>селезінкова вена</em>) – не змінений.</p>

<p><strong>Нирки</strong> – розміщені типово.<br>
Права нирка – [?] × [?] мм, паренхіма – [?] мм.<br>
Ліва нирка – [?] × [?] мм, паренхіма – [?] мм.<br>
Контури нирок чіткі, рівні.<br>
Диференціація коркового мозкового шарів збережена.<br>
Ехогенність паренхіми нирок звичайна.<br>
Серединний комплекс не поширений, не ущільнений.<br>
Видільна система не поширена.<br>
Проксимальні відділи сечоводів – не поширені.<br>
Дистальні відділи сечоводів – не поширені.</p>

<p><strong>Висновок:</strong> [сформулюй за фактичними знахідками]</p>

Нічого, крім цього HTML-фрагмента, не виводь.`;

// ───────────── Шаблони Долгушиної А.В. (test7): ЩЗ та ЕХОКГ — два окремі шаблони ─────────────
// Раніше це був один промпт-роутер (модель сама вгадувала тип). Розбито на два чисті шаблони, бо
// лікар обирає тип ВРУЧНУ в UI (надійніше за авто-визначення — див. онбординг recall-ризик).
// Формат КНП «Дитяча міська поліклініка №2» ОМР, Одеса. Поля пацієнта ПОРОЖНІ (PHI не йде в LLM);
// непродиктовані числа → [?]; S ПТ/КДІ → [?] (рахує лікар). Якісні дефолти = норма; патологію з
// диктовки підставляємо замість дефолту (меню не-норми — в ОРІЄНТИРАХ кожного шаблону).

// ── ШАБЛОН: Щитоподібна залоза (сітка бланка Долгушиної 1-в-1) ──
// Статичні порожні бланки Долгушиної (= ШАБЛОН у промптах; тримати синхронно). Віддаються
// напряму через /api/skeleton — миттєво й детерміновано, без 30-60с LLM-генерації.
const DOLHUSHYNA_THYROID_BLANK = `<h2 style="text-align:center;margin:0 0 2px;font-size:15px">Протокол дослідження щитоподібної залози</h2>
<p style="text-align:center;font-size:10px;margin:0 0 4px">КНП «Дитяча міська поліклініка №2» ОМР · Кабінет УЗД, м. Одеса, вул. Владислава Бувалкіна, 59 · Апарат: Toshiba Xario 100, датчик 14L5</p>
<p style="font-size:11px;margin:0 0 4px"><strong>Дата дослідження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>ПІБ:</strong><br>
<strong>Дата народження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вік:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст (см):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вага (кг):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>S ПТ (м²):</strong> [?]</p>
<p style="font-size:11px;margin:3px 0">Акустичний доступ: без особливостей.</p>
<p style="font-size:11px;margin:3px 0">Щитоподібна залоза розташована типово. Форма: звичайна. Анатомічна будова: класична (2 частки та перешийок).</p>
<p style="font-size:11px;margin:3px 0"><strong>Капсула:</strong> збережена, диференціюється чітко.</p>
<p style="font-size:11px;margin:3px 0"><strong>Контури:</strong> рівні, чіткі.</p>
<p style="font-size:11px;margin:3px 0"><strong>Структура:</strong> однорідна.</p>
<p style="font-size:11px;margin:3px 0"><strong>Ехогенність:</strong> середня.</p>
<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:11px;line-height:1.15">
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Загальний обʼєм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма до</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Обʼєм правої частки</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Обʼєм лівої частки</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Перешийок</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
</table>
<p style="font-size:11px;margin:3px 0">Кольорове допплерівське картування: в межах норми, васкуляризація паренхіми симетрична.</p>
<p style="font-size:11px;margin:3px 0">Наявність утворень: не виявлено.</p>
<p style="font-size:11px;margin:4px 0 2px"><strong>Висновок дослідження:</strong></p>
<p style="font-size:11px;margin:0 0 2px"><strong>Рекомендовано:</strong> УЗ щитоподібної залози профілактично 1 раз на рік.</p>
<p style="font-size:11px;margin:0">Лікар УЗД: Долгушина Альбіна Вячеславівна</p>

<div style="page-break-before:always;border-top:1px dashed #c0c0c0;margin:14px 0 8px"></div>

<table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Щитоподібна залоза</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">розташована типово</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Загальний обʼєм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Вікова норма</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Права частка</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³ ([?] × [?] × [?] мм), (N [?] см³)</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва частка</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³ ([?] × [?] × [?] мм), (N [?] см³)</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Перешийок</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм, не збільшений</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Контур</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">рівний, чіткий</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Структура</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">однорідна</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ехогенність</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">середня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Утворення (вузли / вогнища)</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлено</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">При КДК васкуляризація залози</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">рівномірна, в межах норми</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Регіонарні лімфовузли</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">яремні (верхні, середні, нижні), паратрахеальні, парастернальні — не збільшені</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Висновок дослідження</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top"></td></tr>
</table>`;
const DOLHUSHYNA_ECHO_BLANK = `<h2 style="text-align:center;margin:0 0 2px;font-size:15px">Протокол ехокардіографії</h2>
<p style="text-align:center;font-size:10px;margin:0 0 4px">КНП «Дитяча міська поліклініка №2» ОМР · Кабінет УЗД, м. Одеса, вул. Владислава Бувалкіна, 59 · Апарат: Toshiba Xario 100, датчик 5S2</p>
<p style="font-size:11px;margin:0 0 4px"><strong>Дата дослідження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>ПІБ:</strong><br>
<strong>Дата народження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вік:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст (см):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вага (кг):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>S ПТ (м²):</strong> [?]</p>
<p style="font-size:11px;margin:0 0 4px">Розташування передсердь: <em>Solitus</em>. Розташування серця: лівокардія. Передсердно-шлуночкове і шлуночково-артеріальне сполучення: конкордантні. Хід магістральних судин: перехресний.</p>
<table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ПРАВЕ ПЕРЕДСЕРДЯ</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛІВЕ ПЕРЕДСЕРДЯ</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Легеневі вени</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">впадають у ліве передсердя</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнисті вени</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">впадають у праве передсердя</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛІВИЙ ШЛУНОЧОК</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва безіменна вена</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">візуалізована</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Коронарний синус</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширений</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стінка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ПРАВИЙ ШЛУНОЧОК</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Скоротливість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">достатня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДР</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">МШП</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КСР</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ЗС</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Скоротливість</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">достатня, до верхівки доходить</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДО</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДІ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл/м²</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Систолічний тиск у ПШ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КСО</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ФВ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] %</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Міжпередсердна перетинка</td><td colspan="5" style="border:1px solid #999;padding:1px 5px;vertical-align:top">інтактна</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Міжшлуночкова перетинка</td><td colspan="5" style="border:1px solid #999;padding:1px 5px;vertical-align:top">інтактна</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ТРИСТУЛКОВИЙ КЛАПАН</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">МІТРАЛЬНИЙ КЛАПАН</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регургітація мінімальна (фізіол.)</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">АОРТА</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛЕГЕНЕВА АРТЕРІЯ</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан Ао</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Синуси Вальсальви</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стовбур ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ST сполучення</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Права гілка ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан Ао</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">тристулковий</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва гілка ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР</em> Права гілка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР</em> Ліва гілка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Коронарні артерії</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відходження без особливостей</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регургітація мінімальна (фізіол.)</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ДУГА АОРТИ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Відкрита артеріальна протока</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Нисхідна Ао <em>ΔР max</em></td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Легенева гіпертензія</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Дуга</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">лівостороння</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Рідина в порожнині перикарду</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Брахіоцефальний ст.</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">розгалуження візуалізовано</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ЧСС</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] уд/хв</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Черевна аорта</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">кровотік пульсуючий</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ритм</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регулярний</td></tr>
</table>
<p style="font-size:11px;margin:4px 0 2px"><strong>Висновок дослідження:</strong></p>
<p style="font-size:11px;margin:0 0 2px"><strong>Рекомендовано:</strong> УЗД серця 1 раз на рік.</p>
<p style="font-size:11px;margin:0">Лікар УЗД: Долгушина А.В.</p>`;
const SYSTEM_PROMPT_DOLHUSHYNA_THYROID = `Ти — медичний редактор, що оформлює протоколи УЗД щитоподібної залози українською мовою у форматі лікаря Долгушиної А.В. (КНП «Дитяча міська поліклініка №2» ОМР, Одеса).

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

ПРАВИЛА:
1. Поля пацієнта (ПІБ, Дата народження, Вік, Зріст, Вага, S ПТ) лиши ПОРОЖНІМИ — лікар впише вручну. НЕ вписуй ПІБ/вік/дату, навіть якщо продиктовано.
2. Підставляй ЛИШЕ продиктовані числа на місця [?]. Нормалізуй: "сто сорок два" → "142"; десятковий роздільник — кома; «на» між розмірами → «×» (одиниці розмірів — за п.2a). Якщо число не названо — лиши [?] (НЕ вигадуй, НЕ лишай порожнім).
2a. РОЗМІРИ ЧАСТКИ — в мм. Переводь у мм (× 10) ЛИШЕ за однієї з умов: (а) лікар явно сказав «сантиметри/см»; АБО (б) ВСІ ТРИ розміри частки <10 (тоді весь триплет — це см: «4 × 1,5 × 1,5» → «40 × 15 × 15 мм»). НІКОЛИ не множ ОКРЕМЕ число лише тому, що воно <10: мішаний триплет «18 × 7 × 6» лишай як є (це мм). ПЕРЕШИЙОК НЕ конвертуй автоматично — постав продиктоване число як є (норма 1–5 мм); × 10 ЛИШЕ за явним «см». Об'єм (см³) НЕ чіпай. За сумнівом — постав як продиктовано + [?].
3. S ПТ завжди лиши [?] (її рахує лікар окремо — потребує площі тіла).
4. Якісні клітинки таблиці — це НОРМА за замовчуванням (ОДИН варіант, НЕ перелік через «/»). Якщо лікар продиктував патологію/інше — ЗАМІНИ дефолт на продиктоване (орієнтири не-норми нижче). Норм-формулювання, які лікар не спростував, лишай як є.
5. Сумнівне/нерозчуте слово познач [?] одразу після нього. ІГНОРУЙ поза-контекст (розмови з пацієнтом, команди «дихай», «не рухайся»).
2c. «Загальний об'єм» вписуй ЛИШЕ в рядок «Загальний об'єм». Об'єм ЧАСТКИ (см³ у рядку частки) — ОКРЕМЕ значення: якщо лікар не назвав об'єм кожної частки окремо, лиши [?]. НІКОЛИ не копіюй загальний об'єм у частки.
6. ВИСНОВОК — згенеруй ПО СУТІ і впиши замість токена [ВИСНОВОК] (НЕ став норм-стем за наявності патології):
   - НОРМА (утворень НЕ виявлено, нічого патологічного не диктувалось) → постав: «Щитоподібна залоза без ознак структурної патології. Васкуляризація рівномірна, без особливостей. <em>TIRADS 1</em> правої та <em>TIRADS 1</em> лівої частки щитоподібної залози.»
   - Є ВУЗОЛ/ВОГНИЩЕ → ЗАБОРОНЕНО писати «без ознак структурної патології» і «TIRADS 1». Почни з вузла: «Вузлове утворення … частки щитоподібної залози», постав названу лікарем категорію або <em>TIRADS [?]</em>; за потреби — рекомендація (ендокринолог / ТАПБ / УЗ-контроль).
   - Об'єм: «Загальний об'єм в межах вікової норми» додавай ЛИШЕ якщо лікар підтвердив норму АБО назвав вікову норму і об'єм у неї вкладається; інакше про норму об'єму НЕ згадуй.
   - Кожна продиктована патологія (структура/ехогенність/лімфовузли/розташування) МАЄ бути у висновку; норм-фразу, що їй суперечить, прибери.
7. ДВІ СТОРІНКИ — ОДИН протокол. Стор.1 = наративна форма, стор.2 = детальна сітка (між ними <div style="page-break-before:always">). Ті самі продиктовані значення (об'єми, перешийок, структура, ехогенність, вузли) і ВИСНОВОК мають ЗБІГАТИСЯ на обох сторінках: сформуй висновок ОДИН раз і встав ТОЙ САМИЙ текст у [ВИСНОВОК] на стор.1 (абзац) і на стор.2 (рядок сітки «Висновок дослідження»). Якщо лікар продиктував патологію — онови відповідне поле на ОБОХ сторінках (наратив стор.1 і клітинка сітки стор.2).

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown, без \`\`\`):
- ВЕСЬ протокол — дві сторінки A4, кожна влазить у СВОЮ сторінку. Компактно: таблиця <table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">; клітинка <td style="border:1px solid #999;padding:1px 5px;vertical-align:top">; заголовок-секція — <td ... style="...;text-align:center;background:#f0f0f0;font-weight:bold">. Шапку/абзаци теж дрібним шрифтом (font-size:11px).
- латина (TIRADS) — у <em>. Нічого, крім HTML-фрагмента, не виводь.

ШАБЛОН (норма за замовчуванням — заповнюй на цій основі):

<h2 style="text-align:center;margin:0 0 2px;font-size:15px">Протокол дослідження щитоподібної залози</h2>
<p style="text-align:center;font-size:10px;margin:0 0 4px">КНП «Дитяча міська поліклініка №2» ОМР · Кабінет УЗД, м. Одеса, вул. Владислава Бувалкіна, 59 · Апарат: Toshiba Xario 100, датчик 14L5</p>
<p style="font-size:11px;margin:0 0 4px"><strong>Дата дослідження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>ПІБ:</strong><br>
<strong>Дата народження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вік:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст (см):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вага (кг):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>S ПТ (м²):</strong> [?]</p>
<p style="font-size:11px;margin:3px 0">Акустичний доступ: без особливостей.</p>
<p style="font-size:11px;margin:3px 0">Щитоподібна залоза розташована типово. Форма: звичайна. Анатомічна будова: класична (2 частки та перешийок).</p>
<p style="font-size:11px;margin:3px 0"><strong>Капсула:</strong> збережена, диференціюється чітко.</p>
<p style="font-size:11px;margin:3px 0"><strong>Контури:</strong> рівні, чіткі.</p>
<p style="font-size:11px;margin:3px 0"><strong>Структура:</strong> однорідна.</p>
<p style="font-size:11px;margin:3px 0"><strong>Ехогенність:</strong> середня.</p>
<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:11px;line-height:1.15">
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Загальний обʼєм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма до</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Обʼєм правої частки</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Обʼєм лівої частки</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"></td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Перешийок</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?]</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">мм</td></tr>
</table>
<p style="font-size:11px;margin:3px 0">Кольорове допплерівське картування: в межах норми, васкуляризація паренхіми симетрична.</p>
<p style="font-size:11px;margin:3px 0">Наявність утворень: не виявлено.</p>
<p style="font-size:11px;margin:4px 0 2px"><strong>Висновок дослідження:</strong> [ВИСНОВОК — згенеруй за п.6; ТОЙ САМИЙ текст постав у рядок «Висновок дослідження» сітки на стор.2; НЕ виводь цей дужковий текст]</p>
<p style="font-size:11px;margin:0 0 2px"><strong>Рекомендовано:</strong> УЗ щитоподібної залози профілактично 1 раз на рік.</p>
<p style="font-size:11px;margin:0">Лікар УЗД: Долгушина Альбіна Вячеславівна</p>

<div style="page-break-before:always;border-top:1px dashed #c0c0c0;margin:14px 0 8px"></div>

<table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Щитоподібна залоза</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">розташована типово</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Загальний обʼєм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Вікова норма</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Права частка</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³ ([?] × [?] × [?] мм), (N [?] см³)</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва частка</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см³ ([?] × [?] × [?] мм), (N [?] см³)</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Перешийок</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм, не збільшений</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Контур</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">рівний, чіткий</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Структура</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">однорідна</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ехогенність</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">середня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Утворення (вузли / вогнища)</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлено</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">При КДК васкуляризація залози</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">рівномірна, в межах норми</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Регіонарні лімфовузли</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">яремні (верхні, середні, нижні), паратрахеальні, парастернальні — не збільшені</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top;font-weight:bold">Висновок дослідження</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[ВИСНОВОК — той самий текст, що на стор.1]</td></tr>
</table>

КОЛИ ПРОДИКТОВАНО ВУЗОЛ/ВОГНИЩЕ/УТВОРЕННЯ (будь-який опис вузла: розмір, ехогенність, контур, TIRADS, кальцинати тощо) — ти ЗОБОВʼЯЗАНИЙ замінити рядок «Утворення (вузли / вогнища) … не виявлено» (на стор.2) на ПОВНУ матрицю нижче: рядок-заголовок N1 + УСІ 9 атрибутів окремими рядками. ❌ КАТЕГОРИЧНО ЗАБОРОНЕНО лишати в цьому рядку лише «є» / «виявлено» / короткий текст — це втрата клінічних даних. Розкладай продиктоване по рядках матриці: розмір вузла → «Розміри (мм)»; ехогенність вузла → «Ехогенність»; контур → «Контур»; форма → «Форма»; локалізація (яка частка) → «Локалізація»; кальцинати/обідок/включення → «Особливості». За замовчуванням — ОДИН стовпець N1 (як показано). ДОДАЙ стовпець N2 (далі N3, N4…) ЛИШЕ якщо продиктовано 2-й (3-й…) вузол — тоді у кожному рядку зроби окремі клітинки N1 | N2 | … замість colspan. У матриці НЕ застосовуй норм-дефолти: непродиктований ЧИСЛОВИЙ атрибут → [?], ЯКІСНИЙ → лиши ПОРОЖНІМ (вузол не має «нормальних» характеристик за замовчуванням). ПРИКЛАД: «у правій частці гіпоехогенне утворення 8 мм, контур нечіткий, мікрокальцинати, TIRADS 4» → Розміри (мм)=8, Локалізація=права частка, Контур=нечіткий, Ехогенність=гіпоехогенне, Особливості=мікрокальцинати (категорію <em>TIRADS 4</em> — лише у Висновок, НЕ в матрицю):
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Утворення: № вузла / вогнища</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">N1</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Розміри (мм)</td><td colspan="3" style="border:1px solid #999;padding:1px 5px">[?]</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Обʼєм (см³)</td><td colspan="3" style="border:1px solid #999;padding:1px 5px">[?]</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Локалізація</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Форма</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Контур</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Ехогенність</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Структура</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px">Особливості</td><td colspan="3" style="border:1px solid #999;padding:1px 5px"></td></tr>

ОРІЄНТИРИ НЕ-НОРМИ (підставляй ЛИШЕ якщо лікар продиктував; інакше лишай норму вище):
- Щитоподібна залоза (розташування): розташована типово (норма) / розташована низько / оперована.
- Структура: однорідна (норма) / помірно неоднорідна (дрібні макрофолікули до [?] мм) / дифузно-неоднорідна / неоднорідна / «п'ятиста».
- Ехогенність: середня (норма) / підвищена / знижена / змішана / нерівномірна з ділянками підвищеної та зниженої.
- Перешийок: не збільшений (норма) / збільшений / не візуалізується; контур рівний, чіткий (норма) / нерівний / нечіткий.
- Норми обʼєму (за статтю/віком, якщо названо): N 4,4–18,0 см³ (жін.), 7,7–25,0 см³ (чол.). Перешийок: немовлята 1–2 мм, 1–5 р 1–3 мм, 6–10 р 2–4 мм, підлітки 4–5 мм.
- КДК: рівномірна, в межах норми (норма) / збіднення дрібної судинної сітки / суттєво знижена / підсилена / підсилена по периферичних ділянках від вузлів.
- Вузли/утворення (опиши лише продиктовані, у матриці N1–N3): гіпоехогенне / солідно-кістозне / гіперехогенне / анехогенне утворення; з гіперехогенними включеннями, анехогенним обідком, зонами кістозної дегенерації, локусами пери-/інтранодулярного кровообігу, мікрокальцинатами [?] мм; категорія <em>TIRADS 2/3/4</em> (лише якщо названа лікарем). ⚠️ Розмір вузла вписуй ЛИШЕ в матрицю утворень (рядок «Розміри (мм)») — НІКОЛИ не в дужки розмірів частки (Д×Ш×Т). Розміри частки лишай [?], якщо лікар не продиктував саме розміри частки.
- Регіонарні лімфовузли: не збільшені (норма) / збільшені праворуч до [?] мм, ліворуч до [?] мм / «ланцюжок» max [?] мм.
- Висновок (варіанти): гіперплазія ЩЗ / дифузні зміни паренхіми / <em>TIRADS 2</em> правої та лівої частки / двостороння регіонарна лімфаденопатія. Рекомендації за потреби: консультація ендокринолога, УЗ-контроль.

Нічого, крім HTML-фрагмента, не виводь.`;

// ── ШАБЛОН: Ехокардіографія (формат Долгушиної) ──
const SYSTEM_PROMPT_DOLHUSHYNA_ECHO = `Ти — медичний редактор, що оформлює протоколи ехокардіографії українською мовою у форматі лікаря Долгушиної А.В. (КНП «Дитяча міська поліклініка №2» ОМР, Одеса).

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

ПРАВИЛА:
1. Поля пацієнта (ПІБ, Дата народження, Вік, Зріст, Вага, S ПТ) лиши ПОРОЖНІМИ — лікар впише вручну. НЕ вписуй ПІБ/вік/дату, навіть якщо продиктовано.
2. Підставляй ЛИШЕ продиктовані числа на місця [?]. Нормалізуй: "сто сорок два" → "142"; десятковий роздільник — кома. Якщо число не названо — лиши [?] (НЕ вигадуй, НЕ лишай порожнім).
2a. ШВИДКІСТЬ: клітинки у см/с. Якщо швидкість продиктовано у М/С (напр. «один метр», «1,2 метра») — заміни ВЕСЬ плейсхолдер «[?] см/с» на «1 м/с [?]» (одиниця як продиктовано + [?] для звірки; НЕ лишай хвостове «см/с»). НЕ став число з м/с у клітинку «см/с» без позначки (це 100× похибка).
2b. Прив'язуй кожен розмір/швидкість до тієї КАМЕРИ / СТОРОНИ / ГІЛКИ, яку назвав лікар (праве/ліве передсердя, ЛШ/ПШ, тристулковий/мітральний, аорта/ЛА, права/ліва гілка). За неоднозначності — [?]; сторону НЕ вгадуй.
3. S ПТ і КДІ завжди лиши [?] (їх рахує лікар окремо — потребують віку/площі тіла).
4. Якісні формулювання в бланку — це НОРМА за замовчуванням. Якщо лікар продиктував патологію — ЗАМІНИ дефолт на продиктоване (орієнтири не-норми нижче). Норм-формулювання, які лікар не спростував, лишай як є.
5. Сумнівне/нерозчуте слово познач [?] одразу після нього. ІГНОРУЙ поза-контекст (розмови з пацієнтом, команди «дихай», «не рухайся»).

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown, без \`\`\`):
- <h2 style="text-align:center"> — назва; під ним рядок клініки/апарата; блок полів пацієнта <p> (порожні).
- ВЕСЬ протокол має вміщатись в ОДНУ сторінку A4 → компактно: таблиця <table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">; клітинка <td style="border:1px solid #999;padding:1px 5px;vertical-align:top">; заголовок-секція — <td ... style="...;text-align:center;background:#f0f0f0;font-weight:bold">. Шапку/абзаци теж дрібним шрифтом.
- СІТКА = 6 колонок. Парний рядок: <td>підпис</td><td colspan="2">значення</td><td>підпис</td><td colspan="2">значення</td>. Заголовок секції на півряду = colspan="3". Шлуночковий рядок (Діаметр|КДР|МШП…) = 6 окремих клітинок без colspan. Перетинка = <td>підпис</td><td colspan="5">значення</td>. Відтворюй структуру колонок ТОЧНО як у шаблоні нижче.
- латина (ΔР, Solitus) — у <em>.

<h2 style="text-align:center;margin:0 0 2px;font-size:15px">Протокол ехокардіографії</h2>
<p style="text-align:center;font-size:10px;margin:0 0 4px">КНП «Дитяча міська поліклініка №2» ОМР · Кабінет УЗД, м. Одеса, вул. Владислава Бувалкіна, 59 · Апарат: Toshiba Xario 100, датчик 5S2</p>
<p style="font-size:11px;margin:0 0 4px"><strong>Дата дослідження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>ПІБ:</strong><br>
<strong>Дата народження:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вік:</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст (см):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>Вага (кг):</strong>&nbsp;&nbsp;&nbsp;&nbsp;<strong>S ПТ (м²):</strong> [?]</p>
<p style="font-size:11px;margin:0 0 4px">Розташування передсердь: <em>Solitus</em>. Розташування серця: лівокардія. Передсердно-шлуночкове і шлуночково-артеріальне сполучення: конкордантні. Хід магістральних судин: перехресний.</p>
<table style="border-collapse:collapse;width:100%;margin:0 0 6px;font-size:11px;line-height:1.15">
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ПРАВЕ ПЕРЕДСЕРДЯ</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛІВЕ ПЕРЕДСЕРДЯ</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Легеневі вени</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">впадають у ліве передсердя</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнисті вени</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">впадають у праве передсердя</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛІВИЙ ШЛУНОЧОК</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва безіменна вена</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">візуалізована</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Коронарний синус</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширений</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стінка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">норма</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ПРАВИЙ ШЛУНОЧОК</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Скоротливість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">достатня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДР</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">МШП</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Порожнина</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">не розширена</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КСР</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ЗС</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Скоротливість</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">достатня, до верхівки доходить</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДО</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДІ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл/м²</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Систолічний тиск у ПШ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КСО</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ФВ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] %</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Міжпередсердна перетинка</td><td colspan="5" style="border:1px solid #999;padding:1px 5px;vertical-align:top">інтактна</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Міжшлуночкова перетинка</td><td colspan="5" style="border:1px solid #999;padding:1px 5px;vertical-align:top">інтактна</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ТРИСТУЛКОВИЙ КЛАПАН</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">МІТРАЛЬНИЙ КЛАПАН</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Діаметр</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регургітація мінімальна (фізіол.)</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">АОРТА</td><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ЛЕГЕНЕВА АРТЕРІЯ</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан Ао</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Синуси Вальсальви</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стовбур ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ST сполучення</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Права гілка ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Клапан Ао</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">тристулковий</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ліва гілка ЛА</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мм</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Швидкість</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] см/с</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР max</em> клапан</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР</em> Права гілка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top"><em>ΔР</em> Ліва гілка</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Стеноз</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">немає</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Коронарні артерії</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відходження без особливостей</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Недостатність</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регургітація мінімальна (фізіол.)</td></tr>
<tr><td colspan="3" style="border:1px solid #999;padding:1px 5px;text-align:center;background:#f0f0f0;font-weight:bold">ДУГА АОРТИ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Відкрита артеріальна протока</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Нисхідна Ао <em>ΔР max</em></td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] mmHg</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Легенева гіпертензія</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">відсутня</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Дуга</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">лівостороння</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Рідина в порожнині перикарду</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">не виявлена</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Брахіоцефальний ст.</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">розгалуження візуалізовано</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">ЧСС</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] уд/хв</td></tr>
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Черевна аорта</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">кровотік пульсуючий</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Ритм</td><td colspan="2" style="border:1px solid #999;padding:1px 5px;vertical-align:top">регулярний</td></tr>
</table>
<p style="font-size:11px;margin:4px 0 2px"><strong>Висновок дослідження:</strong> [ВИСНОВОК — згенеруй за блоком «⚠️ ВИСНОВОК» нижче; НЕ виводь цей дужковий текст]</p>
<p style="font-size:11px;margin:0 0 2px"><strong>Рекомендовано:</strong> УЗД серця 1 раз на рік.</p>
<p style="font-size:11px;margin:0">Лікар УЗД: Долгушина А.В.</p>

ОРІЄНТИРИ НЕ-НОРМИ (підставляй ЛИШЕ якщо лікар продиктував):
- Міжпередсердна перетинка: інтактна (норма) / «Відкрите овальне вікно [?] мм, ліво-правий шунт» / дефект міжпередсердної перетинки [?] мм.
  ⚠️ «ДЕФЕКТ перетинки» і «ВІДКРИТЕ ОВАЛЬНЕ ВІКНО» — це РІЗНІ діагнози, НІКОЛИ не підміняй один одним. Будь-яке розмовне позначення наскрізного отвору в перегородці («отвір / дірка / скид у перегородці», «отвір між передсердями/шлуночками», «скид через перегородку») = ДЕФЕКТ відповідної перетинки, а НЕ овальне вікно. «Відкрите овальне вікно / foramen ovale / ВОВ» постав ВИКЛЮЧНО коли лікар вимовив буквально «овальне вікно» або «foramen ovale». Якщо сказано «дефект» — «дефект міжпередсердної перетинки [розмір] мм».
  ПРИКЛАД (обовʼязково): «між передсердями отвір 7 мм» → «дефект міжпередсердної перетинки 7 мм» (НЕ «відкрите овальне вікно»). «скид через перегородку» → дефект. За НЕОДНОЗНАЧНОСТІ (просто «отвір», без слів «овальне вікно») обирай ДЕФЕКТ, а не ВОВ — ніколи не зводь описану патологію до доброякіснішого варіанту самостійно.
  ⚠️ Напрямок шунта зберігай ДОСЛІВНО як продиктовано: «зліва направо» / «ліво-правий» vs «справа наліво» / «право-лівий» — НЕ перевертай і не став дефолтний напрямок, якщо лікар назвав інший.
- Міжшлуночкова перетинка: інтактна (норма) / дефект міжшлуночкової перетинки [?] мм. (те саме правило: «дефект» ≠ норма, напрямок шунта дослівно.)
- Відкрита артеріальна протока: не виявлена (норма) / «наявна, діаметр [?] мм».
- Легенева гіпертензія: відсутня (норма) / якщо систолічний тиск у ПШ підвищений АБО лікар назвав легеневу гіпертензію — заміни «відсутня» і відобрази у Висновку.
- Ліва безіменна вена та коронарний синус: за наявності диктовки додай їх розміри [?] мм.
- Якщо названо патологію клапанів/порожнин/функції — заміни відповідний дефолт і відобрази у Висновку.

⚠️ ВИСНОВОК (критично) — впиши замість [ВИСНОВОК]:
- НОРМА (нічого патологічного не диктувалось) → постав ДОСЛІВНО: «Порожнини серця не збільшені. Структура і функція клапанів не порушена. Невелика регургітація на тристулковому клапані та клапані легеневої артерії. Систолічна та діастолічна функція лівого шлуночку збережені (ФВ за Тейхольцем [?] %).»
- ФВ у висновку = ФВ у таблиці (те саме значення; якщо в таблиці [?] — і у висновку [?]).
- Якщо продиктовано БУДЬ-ЯКУ патологію (дефект, ВОВ, регургітація понад фізіологічну, дилатація, стеноз, порушення функції) — НЕ став норм-абзац; почни з переліку КОЖНОЇ знахідки (розмір + напрямок шунта дослівно).
- Висновок формуй з ФАКТИЧНИХ знахідок: КОЖНА продиктована патологія МАЄ бути у висновку (з розміром і напрямком шунта дослівно). Те, що є в тілі протоколу як знахідка, не може бути відсутнім у висновку, і навпаки.
- НЕ лишай у висновку норм-фразу, що суперечить знахідці: якщо є клапанна знахідка — прибери «функція клапанів не порушена»; якщо є структурна вада — прибери «структурної патології немає».
- НЕ додавай у висновок фізіологічну регургітацію (тристулковий/легеневий клапан) як «знахідку», якщо лікар її не диктував — це норма, а не діагноз.

Нічого, крім обраного HTML-фрагмента, не виводь.`;

// ── ШАБЛОН: Доплерографія вен нижніх кінцівок (формат Денисюк Роксоляни) ──
// Статичний порожній бланк венозного протоколу (= ШАБЛОН у промпті; тримати синхронно).
// Віддається напряму через /api/skeleton, щоб бланк ТОЧНО відповідав формі (skeleton-LLM не псує так/ні).
const VENOUS_BLANK_HTML = `<div style="font-family:'Times New Roman',Georgia,serif;font-size:13px;line-height:1.5;text-align:justify;color:#000">
<p style="margin:0">ПІБ</p>
<p style="margin:0 0 8px">Дата народження</p>
<p style="text-align:center;margin:0 0 8px"><u>Доплерографія вен нижніх кінцівок</u></p>
<p style="margin:0 0 8px">Глибокі вени прохідні на всьому проміжку, компресія їх просвіту повна, кровотік фазний, рефлюкс не визначається, клапани спроможні.</p>
<p style="margin:0 0 4px">Справа</p>
<p style="margin:0 0 4px">Велика підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СФС/по стовбуру/________ тривалість рефлюксу ________ сек,</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СФС ________ мм, в с/3 стегна ________ мм, в н/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 4px">Мала підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СПС/по стовбуру/________ тривалість рефлюксу ________ сек, впадає в: ПкВ/глибокі вени стегна/продовжується у вену Діжакоміні</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СПС ________ мм, в с/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 2px">Перфорантні вени</p>
<p style="margin:0 0 10px">________</p>
<p style="margin:0 0 4px">Зліва</p>
<p style="margin:0 0 4px">Велика підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СФС/по стовбуру/________ тривалість рефлюксу ________ сек,</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СФС ________ мм, в с/3 стегна ________ мм, в н/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 4px">Мала підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СПС/по стовбуру/________ тривалість рефлюксу ________ сек, впадає в: ПкВ/глибокі вени стегна/продовжується у вену Діжакоміні</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СПС ________ мм, в с/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 2px">Перфорантні вени</p>
<p style="margin:0 0 10px">________</p>
<p style="margin:0 0 8px">Дистальні відділи гомілкових артерій: кровотік магістральний/знижений/не визначається</p>
<p style="margin:0 0 4px">Висновок:</p>
<p style="margin:0 0 4px">Дата</p>
<p style="margin:0">Лікар</p>
</div>`;
const SYSTEM_PROMPT_DENYSIUK_VENOUS = `Ти — медичний редактор, що оформлює протоколи доплерографії вен нижніх кінцівок українською мовою у форматі лікаря Денисюк Роксоляни. Готовий протокол має ВИГЛЯДАТИ ТОЧНО як паперовий бланк лікаря: та сама структура, ті самі формулювання, ті самі варіанти через «/», ті самі підкреслені порожні поля «________».

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

ПРАВИЛА:
1. Поля пацієнта (ПІБ, Дата народження) і футер (Дата, Лікар) лиши ПОРОЖНІМИ — лікар впише вручну.
2. БЛАНК НЕ СПРОЩУЙ: відтворюй увесь текст форми ДОСЛІВНО, включно з варіантами «так/ні», «повна/неповна», «визначається/не визначається», «магістральний/знижений/не визначається» і підкресленнями «________». Нічого не прибирай, не перефразовуй і не переставляй.
3. ЧИСЛА: підставляй ЛИШЕ продиктовані числа на відповідне підкреслене місце (діаметри — у мм, тривалість рефлюксу — у сек). Нормалізуй: "сім" → "7", "три з половиною" → "3,5"; десятковий роздільник — кома. Якщо число НЕ названо — лиши підкреслення «________» порожнім (НЕ став [?], НЕ вигадуй).
4. ВАРІАНТИ через «/»: якщо лікар явно назвав варіант (напр. «компресія повна», «рефлюкс визначається», «кровотік магістральний») — познач ОБРАНИЙ варіант жирним <b>…</b>, а решту альтернатив лиши поряд як є. Якщо лікар цей пункт не згадав — лиши «варіант/варіант» без виділення (як на бланку).
5. СТОРОНА і ВЕНА: прив'язуй кожну знахідку до тієї СТОРОНИ (Справа/Зліва) і ВЕНИ (глибокі / велика підшкірна / мала підшкірна / перфорантні), яку назвав лікар. За неоднозначності нічого не виділяй; сторону чи вену НЕ вгадуй.
6. РЕФЛЮКС: якщо рефлюкс визначається — виділи <b>визначається</b> і обраний локус (<b>в ділянці СФС</b> / <b>по стовбуру</b> / впиши названий сегмент у підкреслення після «по стовбуру/»), і постав тривалість у «________ сек». Нема рефлюксу — виділи <b>не визначається</b>.
7. МАЛА ПІДШКІРНА — місце впадіння: якщо названо, виділи обране (<b>ПкВ</b> / <b>глибокі вени стегна</b> / <b>продовжується у вену Діжакоміні</b>); якщо ні — лиши всі варіанти.
8. «Інше»: впиши текст у підкреслення лише якщо лікар продиктував додаткове; інакше лиши підкреслення порожнім. Так само «Перфорантні вени» — заповнюй рядок лише за диктовки.
9. Сумнівне/нерозчуте СЛОВО познач [?] одразу після нього. ІГНОРУЙ поза-контекст (розмови з пацієнтом, команди «дихай», «не рухайся»).
10. ВИСНОВОК — після «Висновок:» згенеруй ПО СУТІ: НОРМА → «Ознак патологічного венозного рефлюксу та тромбозу глибоких і поверхневих вен нижніх кінцівок не виявлено.»; є знахідки → перелічи КОЖНУ продиктовану (сторона, вена, локалізація рефлюксу, тривалість, діаметри). Клас CEAP став ЛИШЕ якщо лікар назвав.

ФОРМАТ — ЛИШЕ HTML-фрагмент (без <html>/<head>/<body>, без markdown-обгорток і пояснень). Відтвори бланк ТОЧНО за шаблоном нижче: шрифт Times New Roman, текст вирівняний по ширині, заголовок по центру з підкресленням, порожні поля — підкресленнями «_».

ШАБЛОН (відтворюй ДОСЛІВНО; заповнюй/виділяй лише продиктоване):

<div style="font-family:'Times New Roman',Georgia,serif;font-size:13px;line-height:1.5;text-align:justify;color:#000">
<p style="margin:0">ПІБ</p>
<p style="margin:0 0 8px">Дата народження</p>
<p style="text-align:center;margin:0 0 8px"><u>Доплерографія вен нижніх кінцівок</u></p>
<p style="margin:0 0 8px">Глибокі вени прохідні на всьому проміжку, компресія їх просвіту повна, кровотік фазний, рефлюкс не визначається, клапани спроможні.</p>
<p style="margin:0 0 4px">Справа</p>
<p style="margin:0 0 4px">Велика підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СФС/по стовбуру/________ тривалість рефлюксу ________ сек,</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СФС ________ мм, в с/3 стегна ________ мм, в н/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 4px">Мала підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СПС/по стовбуру/________ тривалість рефлюксу ________ сек, впадає в: ПкВ/глибокі вени стегна/продовжується у вену Діжакоміні</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СПС ________ мм, в с/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 2px">Перфорантні вени</p>
<p style="margin:0 0 10px">________</p>
<p style="margin:0 0 4px">Зліва</p>
<p style="margin:0 0 4px">Велика підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СФС/по стовбуру/________ тривалість рефлюксу ________ сек,</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СФС ________ мм, в с/3 стегна ________ мм, в н/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 4px">Мала підшкірна вена прохідна: так/ні, компресія просвіту: повна/неповна, рефлюкс визначається/не визначається, рефлюкс: в ділянці СПС/по стовбуру/________ тривалість рефлюксу ________ сек, впадає в: ПкВ/глибокі вени стегна/продовжується у вену Діжакоміні</p>
<p style="margin:0 0 4px">Діаметри: в ділянці СПС ________ мм, в с/3 гомілки ________ мм</p>
<p style="margin:0 0 8px">Інше________</p>
<p style="margin:0 0 2px">Перфорантні вени</p>
<p style="margin:0 0 10px">________</p>
<p style="margin:0 0 8px">Дистальні відділи гомілкових артерій: кровотік магістральний/знижений/не визначається</p>
<p style="margin:0 0 4px">Висновок: [ВИСНОВОК — згенеруй за п.10; НЕ виводь цей дужковий текст]</p>
<p style="margin:0 0 4px">Дата</p>
<p style="margin:0">Лікар</p>
</div>

Нічого, крім цього HTML-фрагмента, не виводь.`;

// Вибір промпта за логіном Basic Auth. Для test2 — мультишаблон (черево/щитоподібна/дефолт);
// для test3 — дитяча ехокардіографія таблицями; для test5 — ветеринарні протоколи (ZOOLUX);
// test6 (Ольга Дебель) — УЗД ОЧП у форматі Ольги; test7 (Долгушина) — ЩЗ або ЕХОКГ НА ВИБІР (пікер у UI);
// для всіх інших (test, test4 і нові логіни) — стандартний SYSTEM_PROMPT.
// SYSTEM_PROMPT_TESTER4 (щитоподібна) наразі не призначений жодному логіну — лишено на майбутнє.
// Статичні бланки вет-ZOOLUX — щоб порожня форма підтягувалась МИТТЄВО (без 30–50с LLM-генерації).
// Згенеровано з шаблонів ШАБЛОН А/Б через ту саму expandZooTables-логіку (TNR + плоскі заголовки).
const VET_ZOOLUX_ABDOMEN_BLANK = `<div style="font-family:'Times New Roman', serif"><h2 style="font-family:'Times New Roman', serif;text-align:center">УЗД (експертне)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Сечовий міхур</h3>
<p><strong>Наповнення:</strong> [?]<br><strong>Стінка:</strong> не потовщена, [?] мм, рівна<br><strong>Вміст:</strong> анехогенний, однорідний<br><strong>Новоутворення:</strong> не візуалізуються</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Уретра</h3>
<p><strong>Проксимальний відділ уретри:</strong> не розширений<br><strong>Стінка уретри:</strong> не потовщена</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Нирки</h3>
<p><strong>Ліва нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Довжина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Кірковий шар (КШЛН) товщина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення КШ/Ао ліва нирка</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення К/Ао ліва нирка</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Права нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Довжина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Кірковий шар (КШПН) товщина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення КШ/Ао права нирка</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення К/Ао права нирка</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Селезінка</h3>
<p><strong>Розмір:</strong> не збільшена, товщина [?] мм<br><strong>Контури:</strong> рівні<br><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Утворення:</strong> не візуалізуються</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Печінка</h3>
<p><strong>Розмір:</strong> не збільшена<br><strong>Контур:</strong> рівний<br><strong>Вільний край:</strong> гострий<br><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Судинний малюнок:</strong> помірно виражений<br><strong>Утворення:</strong> не візуалізуються</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Жовчний міхур</h3>
<p><strong>Наповнення:</strong> помірно наповнений<br><strong>Форма:</strong> типова<br><strong>Вміст:</strong> однорідний анехогенний<br><strong>Стінка:</strong> не потовщена, рівна<br><strong>Новоутворення:</strong> не візуалізуються<br><strong>Міхурна протока:</strong> не розширена<br><strong>Холедох:</strong> не розширений</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Підшлункова залоза</h3>
<p><strong>Ехогенність:</strong> не змінена<br><strong>Ехоструктура:</strong> однорідна<br><strong>Контури:</strong> рівні<br><strong>Ліва доля, мм:</strong> [?]<br><strong>Включення:</strong> не візуалізуються<br><strong>Жирова тканина:</strong> не змінена</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Шлунково-кишковий тракт</h3>
<p><strong>Шлунок.</strong> Наповнення: [?]. Перистальтика: [?]. Стінка: не потовщена, тіло [?] мм, співвідношення шарів не змінено.</p>
<p><strong>12-ти пала кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>
<p><strong>Порожня кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>
<p><strong>Клубова кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?].</p>
<p><strong>Сліпа кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?].</p>
<p><strong>Ободова кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?]. Перистальтика: [?].</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Інше</h3>
<p><strong>Лімфатичні вузли:</strong> не змінені<br><strong>Вільна рідина:</strong> не візуалізується<br><strong>Вільний газ:</strong> не візуалізується (норма)</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Судини черевної порожнини</h3>
<p><strong>Аорта.</strong></p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення PV/Ao</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення CVC/Ao</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<p><strong>Висновок:</strong> На момент обстеження УЗ-ознак патології не виявлено</p>
<p><strong>Примітка:</strong> Висновок УЗД не є остаточним діагнозом та повинен бути інтерпретований лікарем з урахуванням анамнезу, клінічної картини та всіх інших методів діагностики.</p></div>`;
const VET_ZOOLUX_ECHO_BLANK = `<div style="font-family:'Times New Roman', serif"><h2 style="font-family:'Times New Roman', serif;text-align:center">ЕХО КГ (експертна)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Лівий шлуночок (Left ventricle)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Ідеальна вага</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">кг</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">МШП (VSd)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КДР (IVDd)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КДРн (LVDDn)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КСР (IVDs)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КСРн (LVSDn)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЗСЛШ (LVFWd)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ФС (FS) %</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">%</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">30,0 - 50,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КДО (EDV)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мл</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">КСО (ESV)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мл</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ФВ % (EF%)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">%</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення ЛШ/аорта у довгій вісі (LV/Ao long axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">MAPSE мжп</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">4,9 - 7,3</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">EPSS</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">S'</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Локальні зміни міокарду:</strong> не виявлено (норма)</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Ліве передсердя (LAD)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛП у довгій вісі (LAD long axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">LADn собаки</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">LADn коти</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0 - 12,7</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛП у короткій вісі (LAD short axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Об'єм ЛП нормалізований (LAVn)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Об'єм ЛП</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мл</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛВ (PV)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">1,5 - 4,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ПГЛА</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛВ/ПГЛА (PV/RBPA)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,5 - 1,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛП/Ао (LA/Ao short axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0 - 1,5</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ЛП/Ао у довгій вісі (LA/Ao long axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість у вушці лівого передсердя</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,30 - 0,90</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">М-режим ЛП діастола</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">М-режим ЛП систола</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">FS ЛП %</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">%</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Аорта (Aorta)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Діаметр аорти у короткій вісі (Ao short axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Діаметр кільця у довгій вісі (Ao long axis)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість потоку (Velocity)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Макс градієнт</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм рт.ст.</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Середній градієнт тиску (тільки для стенозу)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм.рт.ст.</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Оцінка виносного тракту:</strong> [?]</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Легенева артерія (Pulmonary artery)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Діаметр кільця клапана</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Ао/ЛА</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість потоку (Velocity)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Макс градієнт</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм рт.ст.</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Середній градієнт тиску (тільки для стенозу)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм.рт.ст.</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">VTI (тільки для стенозу)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">см</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Включення у стовбурі легеневої артерії:</strong> [?]</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Мітральний клапан (Mitral valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість мітральної регургітації</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">dP/dt</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм рт.ст.</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Пік Е</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Пік А</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Е/А</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0 - 2,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Праві відділи</h3>
<p><strong>Правий шлуночок (RVID):</strong> візуально не розширений</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Стінка правого шлуночка (RVW)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Ширина правого передсердя у довгій вісі</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Об'єм правого передсердя</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мл</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Довжина ПШ в апікальній проекції</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Ширина ПШ в довгій вісі</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">TAPSE</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">TAPSEn</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм/кг</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0 - 3,2</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Спадіння каудальної порожнистої вени</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">%</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Тристулковий клапан (Tricuspid valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість регургітації на клапані (TR)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Вроджені вади серця</h3>
<p><strong>ДМШП (VSD):</strong> не виявлено<br><strong>ДМПП (ASD):</strong> не виявлено</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Швидкість потоку на дефекті</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Оцінка порожнини перикарда</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Товщина перикарда</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Оцінка рідини в перикардіальній порожнині:</strong> рідини не виявлено (норма)</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Оцінка середостіння і паренхіми легень</h3>
<p><strong>Оцінка середостіння:</strong> новоутворень у середостінні не виявлено<br><strong>"Вологі легені" у точках:</strong> В-лінії відсутні (норма)</p>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Оцінка тиску наповнення</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">IVRT</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мс</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">37,0 - 60,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">E/IVRT</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">E'</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">м/с</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Е/Е'</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">0,0 - 12,0</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Індекс наповнення/викиду ЛШ (LVEIO)</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>

<h3 style="font-family:'Times New Roman', serif;font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px">Оцінка ступеня легеневої гіпертензії</h3>
<p><strong>Легенева гіпертензія по формі потоку:</strong> немає ознак легеневої гіпертензії (норма)</p>
<p><strong>Регургітація на клапані ЛА, м/с:</strong> Ранньодіастолічна [?]; Пізньодіастолічна [?]</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:'Times New Roman', serif">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Стовбур ЛА у короткій вісі</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Співвідношення стовбура ЛА/Ао у короткій вісі</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ПГЛА діастола М-режим</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ПГЛА систола М-режим</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">ПГЛАdn</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Індекс розтяжності ПГЛА</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">%</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Колабування КПВ:</strong> [?]</p>

<p><strong>Заключення:</strong> Камери серця не розширені, стінки міокарду не потовщені. Ознак діастолічної і систолічної дисфункції не виявлено. Клапанний апарат не змінений. Вроджених вад серця не виявлено.</p></div>`;

// ── Шаблони протоколів (іменований реєстр) ──
// Кожен шаблон = людська назва + system-промпт. Більшість лікарів залочені на свій шаблон за
// логіном (PROMPTS_BY_USER); окремі лікарі можуть перемикати власний НАБІР (TEMPLATE_CHOICES_BY_USER,
// напр. Долгушина: ЩЗ/ЕХОКГ). Нейтральні QA-акаунти (NEUTRAL_USERS) обирають БУДЬ-ЯКИЙ шаблон з UI.
const TEMPLATES = {
  default:         { label: "Стандарт (черевна порожнина)", prompt: SYSTEM_PROMPT },
  abdomen_thyroid: { label: "Черево + щитоподібна (мульти)", prompt: SYSTEM_PROMPT_TESTER2 },
  peds_echo:       { label: "Дитяча ехокардіографія", prompt: SYSTEM_PROMPT_TESTER3 },
  thyroid:         { label: "Щитоподібна залоза", prompt: SYSTEM_PROMPT_TESTER4 },
  vet_zoolux:         { label: "Ветеринарний (ZOOLUX)", prompt: SYSTEM_PROMPT_TESTER5 },
  vet_zoolux_abdomen: { label: "Ветеринарний УЗД ОЧП (ZOOLUX)", prompt: SYSTEM_PROMPT_VET_ZOOLUX_ABDOMEN, blank: VET_ZOOLUX_ABDOMEN_BLANK },
  vet_zoolux_echo:    { label: "Ветеринарний ЕХО КГ (ZOOLUX)", prompt: SYSTEM_PROMPT_VET_ZOOLUX_ECHO, blank: VET_ZOOLUX_ECHO_BLANK },
  levadna_abdomen:    { label: "Вет ОЧП (собака, самець)", prompt: SYSTEM_PROMPT_LEVADNA_ABDOMEN, blank: LEVADNA_ABDOMEN_BLANK },
  kravchenko_ct:      { label: "Вет КТ (все тіло)", prompt: SYSTEM_PROMPT_KRAVCHENKO_CT, blank: KRAVCHENKO_CT_BLANK },
  kravchenko_thorax:  { label: "РГ грудної порожнини (OVRU)", prompt: SYSTEM_PROMPT_KRAVCHENKO_THORAX, blank: KRAVCHENKO_THORAX_BLANK, brand: "ovru" },
  olga_abdomen:    { label: "УЗД ОЧП (формат Ольги)", prompt: SYSTEM_PROMPT_TESTER6 },
  dolhushyna_thyroid: { label: "Щитоподібна залоза (Долгушина)", prompt: SYSTEM_PROMPT_DOLHUSHYNA_THYROID, blank: DOLHUSHYNA_THYROID_BLANK },
  dolhushyna_echo:    { label: "ЕХОКГ (Долгушина)", prompt: SYSTEM_PROMPT_DOLHUSHYNA_ECHO, blank: DOLHUSHYNA_ECHO_BLANK },
  vasyl_abdomen:      { label: "Черевна порожнина (Головатий)", prompt: SYSTEM_PROMPT_VASYL_ABDOMEN },
  vasyl_thyroid:      { label: "Щитоподібна залоза (Головатий)", prompt: SYSTEM_PROMPT_VASYL_THYROID },
  vasyl_breast:       { label: "Молочні залози (Головатий)",       prompt: SYSTEM_PROMPT_VASYL_BREAST },
  vasyl_prostate:     { label: "Передміхурова залоза (Головатий)", prompt: SYSTEM_PROMPT_VASYL_PROSTATE },
  vasyl_scrotum:      { label: "Органи калитки (Головатий)",       prompt: SYSTEM_PROMPT_VASYL_SCROTUM },
  denysiuk_venous:    { label: "Доплерографія вен н/к (Денисюк)", prompt: SYSTEM_PROMPT_DENYSIUK_VENOUS, blank: VENOUS_BLANK_HTML },
};
// Логін Basic Auth → ключ шаблону. Це ПЕРВИННИЙ/дефолтний шаблон лікаря: береться, якщо UI не
// надіслав template (або надіслав недозволений). Логіни поза мапою → "default".
const PROMPTS_BY_USER = {
  test2: "vasyl_abdomen",   // Головатий Василь — дефолт черевна (може перемкнути на щитоподібну, див. нижче)
  test3: "peds_echo",       // дитяча ехокардіографія
  test5: "vet_zoolux_abdomen", // дефолт — УЗД ОЧП; ЕХО КГ обирається в пікері
  test9: "levadna_abdomen",  // вет ОЧП собака-самець (Ірина Левадна)
  test10: "kravchenko_thorax",   // дефолт — РГ грудної (OVRU, брендований); КТ у пікері (Катерина Кравченко)
  test6: "olga_abdomen",    // Ольга Дебель — УЗД ОЧП (формат Ольги)
  test7: "dolhushyna_thyroid", // Долгушина Альбіна — дефолт ЩЗ (може перемкнути на ЕХОКГ, див. нижче)
  test8: "denysiuk_venous",    // Денисюк Роксоляна — доплерографія вен нижніх кінцівок
};
// Логін → НАБІР шаблонів, які лікар може перемикати ВРУЧНУ в UI (підмножина TEMPLATES).
// Дає реальному лікарю випадайку вибору, не відкриваючи всі шаблони (на відміну від NEUTRAL_USERS).
// КОЖЕН тестер має тут СВІЙ набір — бачить лише власні протоколи (own-only гарантує mayUseTemplate +
// /api/trial). Пікер у UI зʼявляється, коли в наборі >1 ключа (canPick). Щоб дати лікарю вибір —
// просто додай ще його ключ(і) сюди (+ за потреби визнач новий промпт у TEMPLATES). Один ключ = без
// пікера, лише фіксований протокол (поведінка як раніше).
const TEMPLATE_CHOICES_BY_USER = {
  test2: ["vasyl_abdomen", "vasyl_thyroid", "vasyl_breast", "vasyl_prostate", "vasyl_scrotum"], // Головатий: черевна / щитоподібна / молочні залози / простата / калитка
  test3: ["peds_echo"],                              // Шипов: дитяча ехокардіографія (поки один формат)
  test5: ["vet_zoolux_abdomen", "vet_zoolux_echo"],  // ZOOLUX (вет): ОЧП або ЕХО КГ на вибір
  test9: ["levadna_abdomen"],              // Левадна (вет ОЧП): один формат
  test10: ["kravchenko_thorax", "kravchenko_ct"], // Кравченко: РГ грудної (OVRU) або КТ на вибір
  test6: ["olga_abdomen"],                           // Ольга Дебель: УЗД ОЧП (один формат)
  test7: ["dolhushyna_thyroid", "dolhushyna_echo"],  // Долгушина: ЩЗ або ЕХОКГ на вибір
  test8: ["denysiuk_venous"],                        // Денисюк: доплерографія вен (один формат)
};
// Бібліотека готових заключень лікаря (own-only: віддається лише власнику через /api/trial).
// Джерело — Word лікаря; нумерація приведена до унікальної 1..N (в оригіналі були повтори).
// Текст ДОСЛІВНИЙ (з пропусками «__ см» і варіантами «A/B?» — лікар доправляє в редагованому протоколі).
// Наразі ЛИШЕ ОЧП (черевна). Кардіо-ЕХО заключення притримані — заведемо, коли додамо ЕХО-протокол.
const CONCLUSIONS_BY_USER = {
  test9: [
    { n: 1, text: "дифузних змін в нирках, що характерні для хронічних нефропатій/геріатричних змін;" },
    { n: 2, text: "дифузних змін в нирках, що характерні для гострих процесів(гострий нефрит?); периренального/ретроперитонеального випоту;" },
    { n: 3, text: "наявності медулярного обідка в нирках, що може спостерігатися в нормі, а також при наступних патологіях: гострому тубулярному склерозі, піогранулематозному віскуліті, хронічному нефриті та гіперкальціємії;" },
    { n: 4, text: "осаду у сечовому міхурі(піурія/гематурія/кристалурія? – рекомендований ЗАС);" },
    { n: 5, text: "дилатації рогів матки рідким вмістом(піо-/гідро-/гемо-/мукометра?);" },
    { n: 6, text: "доброякісної гіперплазії передміхурової залози/не можна виключати простатит;" },
    { n: 7, text: "дифузно-вогнищевих змін селезінки, що можуть спостерігатися в нормі у цуценят віком до 1 року та після щеплення; також характерні для спленіту/нодулярної гіперплазії/екстрамедулярного гемопоезу/іншої неоплазії;" },
    { n: 8, text: "дифузних змін печінки, що характерні для хронічного гепатиту/вакуолярних гепатопатій(ліпідоз/стероїдна гепатопатія)/не виключена неоплазія, МТС;" },
    { n: 9, text: "дифузно візуалізуються гіпоехогенні включення різноманітних розмірів та форм, максимальний розмір" },
    { n: 10, text: "дифузних змін печінки, що характерні для гострого гепатиту/токсичного шоку/неопластичних змін/пасивного венозного застою;" },
    { n: 11, text: "стороннього тіла в шлунку без ознак розвитку механічної непрохідності;" },
    { n: 12, text: "стороннього тіла у кишці, що на момент обстеження спричинює механічну непрохідність ШКТ;" },
    { n: 13, text: "дифузних змін жирової клітковини, що характерні для запальних процесів/набряку/неопластичної інфільтрації;" },
    { n: 14, text: "локальних/дифузних змін стінки тонкого кишечника, що характерні для хронічних запальних процесів/неопластичних змін;" },
    { n: 15, text: "доброякісної гіперплазії передміхурової залози;" },
    { n: 16, text: "дифузно вогнищевих змін ПЗ, що характерні для ретенційних кіст/нодулярної гіперплазії/іншої неоплазії." },
    { n: 17, text: "дифузно візуалізуються гіпоехогенні округлі включення, діаметром до  см, їх контури нечіткі та нерівні, аваскулярні." },
    { n: 18, text: "співвідношення шарів порушене – потовщений м’язовий шар до  см, підслизовий шар – см." },
    { n: 19, text: "патологічних структурних змін ОЧП не виявлено." },
    { n: 20, text: "Вміст: помірна кількість гетерогенних кормових мас." },
    { n: 21, text: "дифузних змін підшлункової залози, що характерні для хронічного панкреатиту/геріатричних змін" },
    { n: 22, text: "позапечінкової обструкції жовчовивідних шляхів (безпосередня причина обструкції не візуалізується – набряк?)" },
    { n: 23, text: "візуалізується незначна/помірна/ значна кількість гіпоехогенного пристінкового  осаду." },
    { n: 24, text: "КМД стерта. Співвідношення коркового та мозкового шару в нормі. Корковий шар однорідний, ехогенність підвищена. Мозковий шар однорідний, ехогенність підвищена. Лоханка не змінена. Конкременти не візуалізуються. Сечовід не візуалізується. Судинний рисунок  виражений помірно. Новоутворення не візуалізуються." },
    { n: 25, text: "кістозної гіперплазії ендометрію, фолікулів/кіст у яєчниках." },
    { n: 26, text: "в дистальній частині візуалізується локальне потовщення стінки за рахунок додаткового анехогенного шару ( см) на межі слизового та підслизового шарів." },
    { n: 27, text: "локальних змін стінки клубової кишки, що характерні для лімфоїдних фолікулів (варіант норми)." },
    { n: 28, text: "в стінці візуалізуються гіпоехогенні овальні включення, довжиною до  см (лімфоїдні фолікули)." },
  ],
};
// Нейтральні тестові акаунти, яким дозволено перемикати БУДЬ-ЯКИЙ шаблон на льоту (з UI).
const NEUTRAL_USERS = new Set(["demo"]);

// Генерація (прев'ю /api/autofill + чистовик /api/protocol) доступна ВСІМ автентифікованим
// акаунтам, поки активний trial (trialState(user).expired === false). Demo = unlimited (ніколи не
// спливає). Прострочений trial → 403. Транскрипція аудіо й порожній бланк — завжди доступні всім.

// Чи дозволено цьому юзеру запросити саме цей шаблон (нейтральний — будь-який; решта — лише свій набір).
function mayUseTemplate(user, key) {
  const exists = Object.hasOwn(TEMPLATES, key); // не довіряй прото-ключам (__proto__/constructor)
  if (NEUTRAL_USERS.has(user)) return exists;
  return (TEMPLATE_CHOICES_BY_USER[user] || []).includes(key) && exists;
}

// Обрати system-промпт: honor-имо запитаний шаблон ЛИШЕ якщо він дозволений юзеру; інакше — залочений
// первинний (PROMPTS_BY_USER). Це серверна автoритетність: чужий шаблон з клієнта не підставити.
// Універсальний принцип — додається ПЕРЕД КОЖНИМ промптом (усі протоколи працюють так):
// шаблон = норма-основа; будь-яка частина лишається (норма) або замінюється диктовкою.
const TEMPLATE_PRINCIPLE = `ЗАГАЛЬНИЙ ПРИНЦИП (понад усе, діє для будь-якого протоколу нижче): ШАБЛОН — це ОСНОВА, яку показуємо лікарю (норма за замовчуванням або порожній бланк). БУДЬ-ЯКА його частина — слово, число, варіант, ціле речення, цілий орган чи розділ — ЛИШАЄТЬСЯ дослівно, якщо лікар про неї НЕ сказав, і ЗАМІНЮЄТЬСЯ тим, що лікар надиктував, якщо сказав (аж до згортання цілого органа до «<Орган>: не візуалізується / відсутній», коли лікар каже, що орган відсутній/не візуалізується). Шаблон ПОВНІСТЮ редагований диктовкою — у цьому його суть. Нічого не вигадуй понад продиктоване; неназване лишай нормою.

`;

function promptFor(user, requestedTemplate) {
  let base;
  if (requestedTemplate && mayUseTemplate(user, requestedTemplate)) base = TEMPLATES[requestedTemplate].prompt;
  else {
    const key = PROMPTS_BY_USER[user];
    base = (key && TEMPLATES[key] && TEMPLATES[key].prompt) || SYSTEM_PROMPT;
  }
  return TEMPLATE_PRINCIPLE + base;
}

// Які тестери сидять на цьому шаблоні (нік(и)) — для випадайки demo, щоб видно було
// «цей шаблон = протокол такого-то лікаря». Реверс PROMPTS_BY_USER (логіни поза мапою → default).
function testersForTemplate(key) {
  // лікар «на» шаблоні = його первинний (PROMPTS_BY_USER) АБО шаблон у його наборі вибору
  // (TEMPLATE_CHOICES_BY_USER) — інакше додаткові шаблони (напр. ЕХОКГ Долгушиної) показувались «не призначено».
  return Object.keys(NICKNAMES_BY_USER)
    .filter((u) => !NEUTRAL_USERS.has(u) &&
      ((PROMPTS_BY_USER[u] || "default") === key || (TEMPLATE_CHOICES_BY_USER[u] || []).includes(key)))
    .map(nickOf);
}

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

// Розгортання компактної розмітки таблиць ZOOLUX (<table class="zt">, голі <td>/<th>) у повні
// inline-стилі. Модель генерує легкий HTML (швидко, без обриву по токенах), а тут детерміновано
// підставляємо стилі — у фіналі повні inline-стилі (ідеальна вставка у Word). Для інших шаблонів
// no-op: вони не містять <table class="zt"> чи голих <td>/<th> (там стилі вже inline).
const ZOO_FONT = "'Times New Roman', serif";
const ZOO_TABLE = `border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px;font-family:${ZOO_FONT}`;
const ZOO_TD = 'border:1px solid #999;padding:4px 7px;vertical-align:top';
const ZOO_TH = 'border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5';
// Заголовки секцій ZOOLUX — звичайні чорні жирні (як у PDF лікаря), а не бірюзові ВЕЛИКІ з розрядкою.
const ZOO_H3 = `font-family:${ZOO_FONT};font-size:14px;font-weight:700;text-transform:none;letter-spacing:0;color:#000;margin:12px 0 6px`;
const ZOO_H2 = `font-family:${ZOO_FONT};text-align:center`;
function expandZooTables(html) {
  if (!html || html.indexOf('class="zt"') === -1) return html;
  const out = html
    .replace(/<table class="zt">/g, `<table style="${ZOO_TABLE}">`)
    .replace(/<th>/g, `<th style="${ZOO_TH}">`)
    .replace(/<td>/g, `<td style="${ZOO_TD}">`)
    .replace(/<h2>/g, `<h2 style="${ZOO_H2}">`)
    .replace(/<h3>/g, `<h3 style="${ZOO_H3}">`);
  // Єдиний шрифт усього протоколу — Times New Roman (in-app і в експорті Word/PDF).
  return `<div style="font-family:${ZOO_FONT}">${out}</div>`;
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
// Окрема модель для ФІНАЛЬНОГО протоколу (чистовий прохід) — Claude Sonnet 4.6.
// Живе прев'ю (/api/autofill) лишається на дешевій BEDROCK_MODEL (Nova).
// Якщо Claude на Bedrock не ввімкнено в акаунті → /api/protocol автоматично відкотиться на Nova.
const BEDROCK_MODEL_FINAL = process.env.BEDROCK_MODEL_FINAL || "us.anthropic.claude-sonnet-4-6";
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
  anthropic_empty: "Модель не повернула результат. Спробуйте ще раз.",
  anthropic_throw: "Помилка генерації протоколу. Спробуйте ще раз.",
  cli_timeout: "Не вдалося сформувати протокол за 3 хвилини (таймаут). Спробуйте ще раз.",
  cli_limit: "Можливо, вичерпано ліміт підписки Max — спробуйте пізніше.",
  cli_notfound: "Сервіс генерації недоступний на сервері. Зверніться до адміністратора.",
  cli_empty: "Не вдалося сформувати протокол. Спробуйте ще раз.",
  no_provider: "Генерація протоколу не налаштована на сервері.",
  unknown: "Невідома помилка формування протоколу.",
};

// Формування через AWS Bedrock (Converse). Повертає HTML або кидає ProviderError(code).
async function protocolViaBedrock(systemPrompt, raw, modelId) {
  let r;
  // Довгі бланки (напр. ветеринарне ЕХО КГ ZOOLUX) не вміщуються у 8000 токенів і обриваються.
  // Claude (Sonnet/фінал) має велику стелю — даємо запас; Nova лишаємо в її межах.
  const isClaude = /claude|anthropic/i.test(modelId || BEDROCK_MODEL);
  const maxTokens = isClaude ? 20000 : 8000;
  try {
    r = await bedrock.send(new ConverseCommand({
      modelId: modelId || BEDROCK_MODEL,
      system: [{ text: systemPrompt }],
      messages: [{ role: "user", content: [{ text: "--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw }] }],
      inferenceConfig: { maxTokens, temperature: 0 },
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
  return expandZooTables(stripFences(text));
}

// Формування через Anthropic API (Claude Opus 4.8). Стрімінг — щоб не впертись у таймаут.
async function protocolViaAnthropic(systemPrompt, raw) {
  let msg;
  try {
    const stream = anthropic.messages.stream({
      model: "claude-opus-4-8",
      max_tokens: 20000,
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
  return expandZooTables(stripFences(text));
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
      resolve(expandZooTables(stripFences(out)));
    });
    child.stdin.write(prompt);
    child.stdin.end();
  });
}

// Порожній БЛАНК шаблону — щоб лікар одразу бачив форму ще до диктовки.
// ДЕТЕРМІНІЗМ: ключ кешу = ключ-шаблону + ХЕШ повного промпта бланка. Зміна промпта → новий хеш →
// автоматично свіжий бланк (старий не «застряє»). Генерація фінальною моделлю (Sonnet) з відкатом на
// Nova, щоб бланк ніколи не падав. Persist на той самий volume, що й analytics.jsonl → той самий
// промпт дає той самий файл навіть після редеплою (нуль випадкових перегенерацій).
const skeletonCache = new Map();
const SKELETON_DIR = path.join(__dirname, "skeletons");
try { fs.mkdirSync(SKELETON_DIR, { recursive: true }); } catch (_) { /* створиться при першому записі */ }
const SKELETON_RAW = "(діагностичний бланк: лікар ще нічого не продиктував)";
const SKELETON_FORCE = "\n\n[РЕЖИМ ПОРОЖНЬОГО БЛАНКА] Лікар ще НІЧОГО не продиктував — це попередній бланк форми. Виведи ПОВНУ структуру цього протоколу: УСІ розділи, рядки, поля й таблиці шаблону. Кожне значення/число, яке зазвичай диктують, постав як [?]. НЕ пропускай жодного розділу (навіть якщо звичайні правила кажуть пропускати незгадане). Якісні дефолтні формулювання шаблону лишай як є. Нічого не вигадуй і не додавай поза шаблоном.";

// Ключ бланка: людський префікс (ключ-шаблону, для читабельності файлу) + хеш вмісту промпта.
// Хеш робить версійний дрейф структурно неможливим — інший промпт = інший ключ = інший файл.
function skeletonKeyFor(user, t) {
  const tplKey = (t && mayUseTemplate(user, t)) ? t : (PROMPTS_BY_USER[user] || "default");
  const promptText = promptFor(user, t) + SKELETON_FORCE;
  const hash = crypto.createHash("sha256").update(promptText).digest("hex").slice(0, 16);
  return { cacheKey: `${tplKey}.${hash}`, promptText };
}

app.get("/api/skeleton", async (req, res) => {
  const user = getAuthUser(req);
  const t = req.query.template;
  // Статичний бланк (детермінований, ТОЧНО як паперова форма) — якщо шаблон його визначає,
  // віддаємо напряму, без LLM (інакше skeleton-форс псує «так/ні» → «[?]/ні»).
  const tplKey = (t && mayUseTemplate(user, t)) ? t : (PROMPTS_BY_USER[user] || "default");
  if (TEMPLATES[tplKey] && TEMPLATES[tplKey].blank) {
    return res.json({ html: TEMPLATES[tplKey].blank, static: true });
  }
  if (!bedrock) return res.status(503).json({ error: "no_provider" });
  const { cacheKey, promptText } = skeletonKeyFor(user, t);
  // 1) гаряча пам'ять
  const mem = skeletonCache.get(cacheKey);
  if (mem) return res.json({ html: mem, cached: true });
  // 2) диск (persist між редеплоями)
  const file = path.join(SKELETON_DIR, cacheKey + ".html");
  try {
    const disk = fs.readFileSync(file, "utf8");
    skeletonCache.set(cacheKey, disk);
    return res.json({ html: disk, cached: true });
  } catch (_) { /* немає на диску — генеруємо нижче */ }
  // 3) генерація: Sonnet (якість) → відкат на Nova, щоб бланк ніколи не падав
  let html;
  try {
    html = await protocolViaBedrock(promptText, SKELETON_RAW, BEDROCK_MODEL_FINAL);
  } catch (_e1) {
    try {
      html = await protocolViaBedrock(promptText, SKELETON_RAW, BEDROCK_MODEL);
    } catch (e2) {
      return res.status(502).json({ error: (e2 && e2.code) || "unknown" });
    }
  }
  skeletonCache.set(cacheKey, html);
  try { fs.writeFileSync(file, html); } catch (_) { /* диск необов'язковий — пам'ять уже має значення */ }
  res.json({ html });
});

// Примусовий скид кешу бланків (пам'ять + диск). Бланк і так оновлюється авто (ключ за хешем промпта),
// але це дає миттєвий ручний скид — напр. перегенерувати після правки промпта без чекання, або для ревʼю.
// Захищено тим самим ADMIN_KEY. POST /api/admin/regen-skeletons?key=...[&template=<ключ>]
app.post("/api/admin/regen-skeletons", (req, res) => {
  if (!ADMIN_KEY_OK) return res.status(503).json({ ok: false, error: "ADMIN_KEY не налаштований" });
  if (String(req.query.key || "") !== ADMIN_KEY) return res.status(403).json({ ok: false, error: "forbidden" });
  const tpl = String(req.query.template || "").slice(0, 60);
  const prefix = tpl ? tpl + "." : null; // ключ файлу = "<шаблон>.<хеш>"
  let clearedMem = 0;
  for (const k of [...skeletonCache.keys()]) {
    if (!prefix || k.startsWith(prefix)) { skeletonCache.delete(k); clearedMem++; }
  }
  let clearedDisk = 0;
  try {
    for (const f of fs.readdirSync(SKELETON_DIR)) {
      if (!f.endsWith(".html")) continue;
      if (!prefix || f.startsWith(prefix)) {
        try { fs.unlinkSync(path.join(SKELETON_DIR, f)); clearedDisk++; } catch (_) {}
      }
    }
  } catch (_) { /* диру могли ще не створити */ }
  console.log(`[skeleton] regen ${tpl || "ALL"}: пам'ять ${clearedMem}, диск ${clearedDisk}`);
  res.json({ ok: true, template: tpl || "ALL", clearedFromMemory: clearedMem, clearedFromDisk: clearedDisk });
});

// Живе прев'ю заповнення шаблону ПІД ЧАС диктовки. Швидка/дешева модель (Nova).
// Best-effort: НЕ логуємо як generate_ok (щоб не накручувати лічильник протоколів),
// без ланцюга-резерву — це лише чернетка, чистовик дає /api/protocol (Sonnet) на стопі.
// Санітизація виводу LLM: моделі іноді додають РОЗДУМ/аналіз ПЕРЕД HTML або пояснення ПІСЛЯ нього
// (напр. «Аналізую диктовку: …» / «I need to carefully parse…»), попри інструкцію «виводь лише HTML».
// Відрізаємо все до першого блокового тега і хвіст після останнього закривного — у документ потрапляє
// ЛИШЕ чистий HTML-фрагмент. Діє для всіх шаблонів і провайдерів (Nova прев'ю / Sonnet чистовик).
function sanitizeProtocolHtml(html){
  if (typeof html !== "string") return html;
  let s = html.trim().replace(/^```(?:html)?\s*/i, "").replace(/\s*```$/, "").trim();
  const m = s.match(/<(?:div|p|h1|h2|h3|table|section|ul|ol)[\s>]/i);
  if (m && m.index > 0) s = s.slice(m.index);                 // відкинути преамбулу-роздум перед HTML
  const last = s.lastIndexOf(">");
  if (last !== -1 && last < s.length - 1) s = s.slice(0, last + 1);  // відкинути хвіст після HTML
  return s.trim();
}

app.post("/api/autofill", async (req, res) => {
  if (!bedrock) return res.status(503).json({ error: "no_provider" });
  const raw = (req.body && req.body.text || "").trim();
  if (!raw) return res.status(400).json({ error: "empty" });
  const user = getAuthUser(req);
  if (trialState(user).expired) return res.status(403).json({ trialExpired: true });
  const systemPrompt = promptFor(user, req.body && req.body.template);
  try {
    const html = sanitizeProtocolHtml(await protocolViaBedrock(systemPrompt, raw, BEDROCK_MODEL)); // Nova — швидке прев'ю
    res.json({ html });
  } catch (e) {
    res.status(502).json({ error: (e && e.code) || "unknown" });
  }
});

app.post("/api/protocol", async (req, res) => {
  const raw = (req.body && req.body.text || "").trim();
  if (!raw) {
    return res.status(400).json({ error: "Порожній текст диктовки." });
  }

  const user = getAuthUser(req);
  const uid = (req.body && req.body.uid) || "server";

  // Генерація З ТЕКСТУ (paste «Згенерувати з тексту») — лише demo (нейтральний QA).
  // Диктовка (fromText відсутній/false) доступна всім; гейт лише за trial нижче.
  if (req.body && req.body.fromText && !NEUTRAL_USERS.has(user)) {
    logEvent(uid, "generate_err", null, user, { stage: "generate", code: "text_gen_disabled" });
    return res.status(403).json({ error: "Генерація з тексту доступна лише на демо-акаунті.", genDisabled: true });
  }

  // Тестовий період вичерпано → блокуємо генерацію (серверна перевірка, обійти з клієнта не можна).
  const trial = trialState(user);
  if (trial.expired) {
    logEvent(uid, "generate_err", null, user, { stage: "generate", code: "trial_over" });
    return res.status(403).json({
      error: "Тестовий період (" + trial.limitDays + " " + trialDaysWord(trial.limitDays) + ") завершився. Зверніться до команди AkesoSystems, щоб продовжити доступ.",
      trialExpired: true,
    });
  }

  const systemPrompt = promptFor(user, req.body && req.body.template);

  // Ланцюг провайдерів: основний → резерв. Кожен збій логуємо з кодом; успіх після збою — fallback:true.
  // Фінал — ЗАВЖДИ сильна модель: Bedrock-Sonnet (якість, AWS-креди) → Anthropic-Opus (сильний резерв)
  // → Bedrock-Nova (останній рубіж, щоб генерація ніколи не падала) → CLI. Opus стоїть ДО Nova, бо на
  // довгих бланках Nova губить поля (нирки/петлі кишечника) — краще заплатити за Opus, ніж віддати брак.
  const chain = [];
  if (bedrock) chain.push({ provider: "bedrock", model: BEDROCK_MODEL_FINAL, run: (sp, r) => protocolViaBedrock(sp, r, BEDROCK_MODEL_FINAL) });
  if (anthropic) chain.push({ provider: "anthropic", model: "claude-opus-4-8", run: protocolViaAnthropic });
  if (bedrock && BEDROCK_MODEL_FINAL !== BEDROCK_MODEL) {
    chain.push({ provider: "bedrock", model: BEDROCK_MODEL, run: (sp, r) => protocolViaBedrock(sp, r, BEDROCK_MODEL) });
  }
  chain.push({ provider: "cli", model: "claude-cli-max", run: protocolViaCLI });

  let fallback = false;
  for (let i = 0; i < chain.length; i++) {
    const step = chain[i];
    const t0 = Date.now();
    try {
      const html = sanitizeProtocolHtml(await step.run(systemPrompt, raw));
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

// Запускаємо сервер лише при прямому виклику (`node server.js`). При require() з тесту
// сервер не слухає порт — доступні лише чисті функції (trialState тощо) для перевірки.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`УЗД МВП працює: http://localhost:${PORT}`);
  });
}

module.exports = { app, trialState, TRIAL_DAYS, DAY_MS };
