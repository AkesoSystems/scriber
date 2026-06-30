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
  test6:      "Ольга Дебель",
  test7:      "Долгушина Альбіна",
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
// База — TRIAL_DAYS (env, дефолт 14). Адмін може коригувати персонально через події у
// analytics.jsonl: "trial_reset" (рестарт відліку) і "trial_bonus" (value = +дні). Зберігати
// оверайди в аналітиці зручно — файл уже на volume, тож вони переживають редеплой без нового маунта.
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS) > 0 ? Number(process.env.TRIAL_DAYS) : 14;
const DAY_MS = 24 * 60 * 60 * 1000;

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

// Стан тестового періоду логіну з урахуванням адмін-оверайдів.
function trialState(user, rows) {
  rows = rows || readAnalyticsRows();
  // Останній reset для цього юзера «переводить годинник»: ранні протоколи й бонуси не рахуються.
  let resetAt = 0;
  for (const r of rows) {
    if (r.user === user && r.event === "trial_reset" && typeof r.t === "number" && r.t > resetAt) resetAt = r.t;
  }
  let firstAt = 0, bonusDays = 0;
  for (const r of rows) {
    if (r.user !== user || typeof r.t !== "number" || r.t < resetAt) continue;
    if (r.event === "generate_ok" && (!firstAt || r.t < firstAt)) firstAt = r.t;
    else if (r.event === "trial_bonus" && typeof r.value === "number") bonusDays += r.value;
  }
  const limitDays = Math.max(0, TRIAL_DAYS + bonusDays);
  if (!firstAt) return { started: false, expired: false, daysRemaining: limitDays, limitDays, bonusDays, firstAt: 0 };
  const remainingMs = limitDays * DAY_MS - (Date.now() - firstAt);
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
  res.json(Object.assign({ user, isNeutral, canPick, templates, primary }, trialState(user)));
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
    // Адмін-оверайди періоду — службові рядки; у статистику не йдуть (їх читає trialState).
    if (r.event === "trial_bonus" || r.event === "trial_reset") continue;
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
  const engagement = Object.keys(byUserDay).filter((user) => !NEUTRAL_USERS.has(user)).map((user) => {
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
    const ts = trialState(user, rows);
    return {
      user,
      lastActiveDay,
      daysSinceActive: lastActiveDay ? dayDiff(today, lastActiveDay) : null,
      protocols7d, protocols30d,
      activeDaysStreak: streak,
      protocolsTotal: protocols,
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
// ОДНА суцільна 4-колонкова таблиця з вбудованими жирними заголовками-рядками, значення
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

ФОРМАТ — лише HTML-фрагмент (без <html>, <head>, <body>, без markdown, без \`\`\`, без пояснень):
- Заголовок по центру: <h2 style="text-align:center">Ехокардіографічне обстеження</h2>.
- ОДНА таблиця <table style="border-collapse:collapse;width:100%;margin:0 0 14px">.
- Звичайна клітинка: <td style="border:1px solid #999;padding:5px 8px;vertical-align:top">; значення — у <em>.
- Заголовок-рядок (Праве передсердя, Тристулковий клапан тощо): <td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">.
- НЕ використовуй <h3>, не розбивай на кілька таблиць.

ВИКОРИСТАЙ РІВНО ТАКУ СТРУКТУРУ (підстав значення у місця з [?]; поля пацієнта лиши порожніми; якісні значення заміни лише за наявності патології в диктовці):

<h2 style="text-align:center">Ехокардіографічне обстеження</h2>

<p><strong>Дата :</strong><br>
<strong>Пацієнт:</strong><br>
<strong>Вік :</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Дата народження:</strong><br>
<strong>Стать:</strong><br>
<strong>Вага:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Зріст:</strong>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<strong>Площа поверхні тіла:</strong></p>

<table style="border-collapse:collapse;width:100%;margin:0 0 14px">
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Розташування передсердь</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Solitus</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Розташування серця</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Лівокардія</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Серце</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Двошлуночкове</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Передсердно-шлуночкове сполучення</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Конкордантне</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Шлуночково-артеріальне сполучення</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Конкордантне</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top">Хід магістральних судин</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Перехресний</em></td></tr>

<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Праве передсердя</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Ліве передсердя</td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Розмір</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>норма</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Розмір [?] мм</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>норма</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Порожнисті вени</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Впадають</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Легеневі вени</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Впадають всі</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Безіменна вена</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Наявна, діаметр [?]</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Додаткова ВПВ</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>немає</em></td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Міжпередсердна перетинка</td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Коронарний синус</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Не розширений</em></td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>інтактна</em></td></tr>

<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Тристулковий клапан</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Мітральний клапан</td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Діаметр</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Діаметр</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Швидкість</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] м/с</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Швидкість</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] м/с</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Недостатність</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>відсутня</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Недостатність</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>відсутня</em></td></tr>

<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Правий шлуночок</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Лівий шлуночок</td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Порожнина</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>не розширена</em></td><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Порожнина — норма, до верхівки доходить</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Скоротливість</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>добра</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Скоротливість</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Добра; ФВ = [?] %</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">До верхівки</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>доходить</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">КДР/КДО/КДІ</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм / [?] мл / [?] мл/м²</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">ТМШП/ТЗСЛШ</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм / [?] мм</em></td></tr>
<tr><td colspan="4" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Міжшлуночкова перетинка</strong> — <em>інтактна</em></td></tr>

<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Легенева артерія</td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Аорта</td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Клапан ЛА</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Клапан Ао</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Стовбур ЛА</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Синус Вальсальви</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Права гілка ЛА</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">ST-сполучення</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Ліва гілка ЛА</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм (Z,SD = [?]; N = [?] мм)</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Клапан Ао</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>тристулковий</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">ΔР max клапан</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм.рт.ст</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">ΔР max клапан</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм.рт.ст</em></td></tr>
<tr><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">недостатність</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>відсутня</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">недостатність</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>відсутня</em></td></tr>

<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Відкрита артеріальна протока</strong> — <em>відсутня</em></td><td colspan="2" style="border:1px solid #999;padding:5px 8px;text-align:center;background:#f0f0f0;font-weight:bold">Дуга аорти</td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Легенева гіпертензія</strong> — <em>відсутня</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">ΔР max</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>[?] мм.рт.ст</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Рідина в порожнині перикарду</strong> — <em>відсутня</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Дуга</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>лівостороння</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>В черевній аорті кровотік</strong> — <em>пульсуючий</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top">Коарктації аорти</td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>немає</em></td></tr>
<tr><td colspan="2" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Коронарні артерії</strong> — <em>без особливостей</em></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td><td style="border:1px solid #999;padding:5px 8px;vertical-align:top"></td></tr>

<tr><td colspan="4" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><em>Додаткові дані:</em> [за диктовкою; якщо нічого не продиктовано — лиши порожнім]</td></tr>
<tr><td colspan="4" style="border:1px solid #999;padding:5px 8px;vertical-align:top"><strong>Висновок:</strong> [сформулюй за фактичними знахідками; норм-варіант — Даних за структурну патологію серця немає]</td></tr>
</table>

<p><strong>Лікар-кардіолог дитячий Шипов Д.О.</strong></p>

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

Нічого, крім обраного HTML-фрагмента, не виводь.`;

// ── Окремі шаблони Головатого В. (test2): черево / щитоподібна — для пікера вибору. ──
// Форсуємо гілку того ж перевіреного мульти-промпта (TESTER2), щоб формат був 1-в-1, без дублювання.
const SYSTEM_PROMPT_VASYL_ABDOMEN = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН А (органи черевної порожнини), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;
const SYSTEM_PROMPT_VASYL_THYROID = "ВАЖЛИВО: ЗАВЖДИ використовуй ШАБЛОН Б (щитоподібна залоза), незалежно від змісту диктовки. Не обирай інший шаблон і не формуй суцільний опис.\n\n" + SYSTEM_PROMPT_TESTER2;

// ───────────── Промпт для test5: ВЕТЕРИНАРНІ протоколи (формат клініки ZOOLUX) ─────────────
// Два типи: УЗД (експертне) черевної порожнини і ЕХО КГ (експертна). Модель сама визначає тип;
// інше → дефолтний суцільний опис. Поля шапки порожні. Незгадане/сумнівне → [?]; колонки
// Норма/Відхилення лишаються "-" (їх рахує система клініки); висновок — по фактичних знахідках.
const SYSTEM_PROMPT_TESTER5 = `Ти — медичний редактор, що оформлює ВЕТЕРИНАРНІ протоколи УЗД у форматі клініки ZOOLUX українською мовою.

Тобі дають СИРИЙ текст диктовки лікаря (результат розпізнавання мовлення, можливі помилки розпізнавання).

КРОК 1 — ВИЗНАЧ ТИП ДОСЛІДЖЕННЯ з диктовки:
- Органи черевної порожнини (сечовий міхур, уретра, нирки, селезінка, печінка, жовчний міхур, підшлункова залоза, шлунок, кишечник, лімфовузли) → ШАБЛОН А «УЗД (експертне)».
- Серце / ехокардіографія (лівий/правий шлуночок, передсердя, клапани, аорта, легенева артерія, фракція, регургітація, перикард) → ШАБЛОН Б «ЕХО КГ (експертна)».
- Інше або незрозуміло → НЕ бери шаблон, а оформи суцільний опис: <h2> з назвою + абзаци <p> + фінальний <p> "Висновок:".

КРОК 2 — ПРАВИЛА ЗАПОВНЕННЯ:
0. ВІДТВОРИ ОБРАНИЙ ШАБЛОН ПОВНІСТЮ І ДОСЛІВНО: усі розділи (<h3>), усі рядки, усі параметри й УСІ рядки таблиць — навіть ті, яких лікар не згадав. НЕ скорочуй, НЕ об'єднуй, НЕ пропускай розділи й не перетворюй таблиці на абзаци. Незгадані значення стають [?], якісні норм-формулювання лишаються як є. Структура виходу = структура шаблону 1:1.
1. Поля шапки (Пацієнт, Власник, Контактна інформація, Призначив, Дослідження провів) лиши ПОРОЖНІМИ — їх заповнюють у системі клініки. НЕ вписуй кличку/власника/контакти навіть якщо продиктовано.
2. Підставляй ЛИШЕ продиктовані числа й факти. Числа нормалізуй, десятковий роздільник — кома ("три цілих вісім" → "3,8").
3. Незгадане значення → [?] на його місці (підсвітять). Колонки «Норма» і «Відхилення» ЗАПОВНЮЙ, якщо лікар їх продиктував: норму — як діапазон (напр. "30,0 - 50,0"), відхилення — зі стрілкою (вгору/підвищено → "▲29%", вниз/знижено → "▼33%", у межах норми → "норма"). Якщо лікар норму/відхилення НЕ назвав — лишай "-". НЕ вигадуй норми й відсотки самостійно.
4. Якісні норм-формулювання шаблону (не потовщена, рівна, однорідна, не змінена, не розширена, не візуалізуються тощо) — це дефолти; якщо лікар продиктував патологію — ЗАМІНИ формулювання на продиктоване. Додаткові продиктовані знахідки дописуй у відповідний розділ.
5. Сумнівне/нерозчуте слово познач [?] одразу після нього.
6. ІГНОРУЙ поза-контекст: розмови з власником, репліки до тварини, побутове — НЕ вписуй.
7. Висновок/Заключення формулюй ПО СУТІ протоколу: якщо є патологія — вкажи саме її (як перелік УЗ-ознак); якщо все в межах норми — нормальний висновок.

ФОРМАТ — лише HTML-фрагмент (без <html>/<head>/<body>, без markdown, без \`\`\`):
- <h2> — назва дослідження; <h3> — розділи (органи/блоки).
- Пари "параметр: значення" — <p> з <strong>Параметр:</strong> значення.
- Вимірювання — <table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px"> з рядком-заголовком Показник | Результат | Одиниця | Норма | Відхилення; клітинки style="border:1px solid #999;padding:4px 7px;vertical-align:top", заголовкові <th> додатково background:#dce9f5;text-align:left; значення в колонці Результат — <strong>.

═══════ ШАБЛОН А — УЗД (експертне) ═══════

<h2>УЗД (експертне)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3>Сечовий міхур</h3>
<p><strong>Наповнення:</strong> [?]<br><strong>Стінка:</strong> не потовщена, [?] мм, рівна<br><strong>Вміст:</strong> анехогенний, однорідний<br><strong>Новоутворення:</strong> не візуалізуються</p>

<h3>Уретра</h3>
<p><strong>Проксимальний відділ уретри:</strong> не розширений<br><strong>Стінка уретри:</strong> не потовщена</p>

<h3>Нирки</h3>
<p><strong>Ліва нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Довжина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Кірковий шар (КШЛН) товщина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
</table>
<p><strong>Права нирка.</strong> Форма: овальна. Контур: рівний. Межі: чіткі. Кортико-медулярна диференціація: збережена. Кірковий шар: ехогенність не змінена, структура однорідна. Мозковий шар: ехогенність не змінена, структура однорідна. Співвідношення шарів: не змінено. Судинний малюнок: помірний. Включення: не візуалізуються. Утворення: не візуалізуються. Миска: не розширена. Сечовід: не розширений.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Довжина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">Кірковий шар (КШПН) товщина</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">мм</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td><td style="border:1px solid #999;padding:4px 7px;vertical-align:top">-</td></tr>
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
<p><strong>Ободова кишка.</strong> Стінка: не потовщена, [?] мм, співвідношення шарів не змінено. Наповнення: [?].</p>

<h3>Інше</h3>
<p><strong>Лімфатичні вузли:</strong> не змінені<br><strong>Вільна рідина:</strong> не візуалізується<br><strong>Вільний газ:</strong> не візуалізується (норма)</p>

<h3>Судини черевної порожнини</h3>
<p><strong>Аорта.</strong> Співвідношення PV/Ao: -. Співвідношення CVC/Ao: -.</p>

<p><strong>Висновок:</strong> [сформулюй за фактичними знахідками як перелік УЗ-ознак; якщо патології немає — «На момент обстеження УЗ-ознак патології не виявлено»]</p>

═══════ ШАБЛОН Б — ЕХО КГ (експертна) ═══════

<h2>ЕХО КГ (експертна)</h2>
<p><strong>Пацієнт:</strong> <br><strong>Власник:</strong> <br><strong>Контактна інформація:</strong> <br><strong>Призначив:</strong> <br><strong>Дослідження провів:</strong> </p>

<h3>Лівий шлуночок (Left ventricle)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">МШП (VSd)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">КДР (IVDd)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">КСР (IVDs)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ЗСЛШ (LVFWd)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ФС (FS)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">%</td><td style="border:1px solid #999;padding:4px 7px">30,0 - 50,0</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ФВ (EF%)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">%</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
</table>
<p><strong>Локальні зміни міокарду:</strong> не виявлено (норма)</p>

<h3>Ліве передсердя (LAD)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ЛП у довгій вісі (LAD long axis)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ЛП у короткій вісі (LAD short axis)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">ЛП/Ао (LA/Ao short axis)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px"></td><td style="border:1px solid #999;padding:4px 7px">0,0 - 1,5</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
</table>

<h3>Аорта (Aorta)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Діаметр аорти у короткій вісі (Ao short axis)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Швидкість потоку (Velocity)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">м/с</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Макс градієнт</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм рт.ст.</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>

<h3>Легенева артерія (Pulmonary artery)</h3>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Діаметр кільця клапана</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Швидкість потоку (Velocity)</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">м/с</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Макс градієнт</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">мм рт.ст.</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
</table>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>

<h3>Мітральний клапан (Mitral valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені. <strong>Характеристика потоку:</strong> ламінарний.</p>
<table style="border-collapse:collapse;border:1px solid #999;width:100%;margin:0 0 10px">
<tr><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Показник</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Результат</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Одиниця</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Норма</th><th style="border:1px solid #999;padding:4px 7px;text-align:left;background:#dce9f5">Відхилення</th></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Пік Е</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">м/с</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Пік А</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px">м/с</td><td style="border:1px solid #999;padding:4px 7px">-</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
<tr><td style="border:1px solid #999;padding:4px 7px">Е/А</td><td style="border:1px solid #999;padding:4px 7px"><strong>[?]</strong></td><td style="border:1px solid #999;padding:4px 7px"></td><td style="border:1px solid #999;padding:4px 7px">0,0 - 2,0</td><td style="border:1px solid #999;padding:4px 7px">-</td></tr>
</table>

<h3>Праві відділи</h3>
<p><strong>Правий шлуночок (RVID):</strong> візуально не розширений</p>

<h3>Тристулковий клапан (Tricuspid valve)</h3>
<p><strong>Морфологія стулок клапана:</strong> не змінені</p>

<h3>Вроджені вади серця</h3>
<p><strong>ДМШП (VSD):</strong> не виявлено<br><strong>ДМПП (ASD):</strong> не виявлено</p>

<h3>Оцінка порожнини перикарда</h3>
<p><strong>Оцінка рідини в перикардіальній порожнині:</strong> рідини не виявлено (норма)</p>

<h3>Оцінка середостіння і паренхіми легень</h3>
<p><strong>Оцінка середостіння:</strong> новоутворень у середостінні не виявлено</p>

<p><strong>Заключення:</strong> [сформулюй за фактичними знахідками; норм-варіант — «Камери серця не розширені, стінки міокарду не потовщені. Ознак діастолічної і систолічної дисфункції не виявлено. Клапанний апарат не змінений. Вроджених вад серця не виявлено.»]</p>

Нічого, крім обраного HTML-фрагмента, не виводь.`;

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
<tr><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">Скоротливість</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">достатня, до верхівки доходить</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДО</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] мл</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">КДІ</td><td style="border:1px solid #999;padding:1px 5px;vertical-align:top">[?] м²</td></tr>
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

// Вибір промпта за логіном Basic Auth. Для test2 — мультишаблон (черево/щитоподібна/дефолт);
// для test3 — дитяча ехокардіографія таблицями; для test5 — ветеринарні протоколи (ZOOLUX);
// test6 (Ольга Дебель) — УЗД ОЧП у форматі Ольги; test7 (Долгушина) — ЩЗ або ЕХОКГ НА ВИБІР (пікер у UI);
// для всіх інших (test, test4 і нові логіни) — стандартний SYSTEM_PROMPT.
// SYSTEM_PROMPT_TESTER4 (щитоподібна) наразі не призначений жодному логіну — лишено на майбутнє.
// ── Шаблони протоколів (іменований реєстр) ──
// Кожен шаблон = людська назва + system-промпт. Більшість лікарів залочені на свій шаблон за
// логіном (PROMPTS_BY_USER); окремі лікарі можуть перемикати власний НАБІР (TEMPLATE_CHOICES_BY_USER,
// напр. Долгушина: ЩЗ/ЕХОКГ). Нейтральні QA-акаунти (NEUTRAL_USERS) обирають БУДЬ-ЯКИЙ шаблон з UI.
const TEMPLATES = {
  default:         { label: "Стандарт (черевна порожнина)", prompt: SYSTEM_PROMPT },
  abdomen_thyroid: { label: "Черево + щитоподібна (мульти)", prompt: SYSTEM_PROMPT_TESTER2 },
  peds_echo:       { label: "Дитяча ехокардіографія", prompt: SYSTEM_PROMPT_TESTER3 },
  thyroid:         { label: "Щитоподібна залоза", prompt: SYSTEM_PROMPT_TESTER4 },
  vet_zoolux:      { label: "Ветеринарний (ZOOLUX)", prompt: SYSTEM_PROMPT_TESTER5 },
  olga_abdomen:    { label: "УЗД ОЧП (формат Ольги)", prompt: SYSTEM_PROMPT_TESTER6 },
  dolhushyna_thyroid: { label: "Щитоподібна залоза (Долгушина)", prompt: SYSTEM_PROMPT_DOLHUSHYNA_THYROID },
  dolhushyna_echo:    { label: "ЕХОКГ (Долгушина)", prompt: SYSTEM_PROMPT_DOLHUSHYNA_ECHO },
  vasyl_abdomen:      { label: "Черевна порожнина (Головатий)", prompt: SYSTEM_PROMPT_VASYL_ABDOMEN },
  vasyl_thyroid:      { label: "Щитоподібна залоза (Головатий)", prompt: SYSTEM_PROMPT_VASYL_THYROID },
};
// Логін Basic Auth → ключ шаблону. Це ПЕРВИННИЙ/дефолтний шаблон лікаря: береться, якщо UI не
// надіслав template (або надіслав недозволений). Логіни поза мапою → "default".
const PROMPTS_BY_USER = {
  test2: "vasyl_abdomen",   // Головатий Василь — дефолт черевна (може перемкнути на щитоподібну, див. нижче)
  test3: "peds_echo",       // дитяча ехокардіографія
  test5: "vet_zoolux",      // ветеринарні протоколи ZOOLUX (УЗД ОЧП + ЕХО КГ)
  test6: "olga_abdomen",    // Ольга Дебель — УЗД ОЧП (формат Ольги)
  test7: "dolhushyna_thyroid", // Долгушина Альбіна — дефолт ЩЗ (може перемкнути на ЕХОКГ, див. нижче)
};
// Логін → НАБІР шаблонів, які лікар може перемикати ВРУЧНУ в UI (підмножина TEMPLATES).
// Дає реальному лікарю випадайку вибору, не відкриваючи всі шаблони (на відміну від NEUTRAL_USERS).
// КОЖЕН тестер має тут СВІЙ набір — бачить лише власні протоколи (own-only гарантує mayUseTemplate +
// /api/trial). Пікер у UI зʼявляється, коли в наборі >1 ключа (canPick). Щоб дати лікарю вибір —
// просто додай ще його ключ(і) сюди (+ за потреби визнач новий промпт у TEMPLATES). Один ключ = без
// пікера, лише фіксований протокол (поведінка як раніше).
const TEMPLATE_CHOICES_BY_USER = {
  test2: ["vasyl_abdomen", "vasyl_thyroid"],         // Головатий: черевна або щитоподібна на вибір
  test3: ["peds_echo"],                              // Шипов: дитяча ехокардіографія (поки один формат)
  test5: ["vet_zoolux"],                             // ZOOLUX (вет): один формат
  test6: ["olga_abdomen"],                           // Ольга Дебель: УЗД ОЧП (один формат)
  test7: ["dolhushyna_thyroid", "dolhushyna_echo"],  // Долгушина: ЩЗ або ЕХОКГ на вибір
};
// Нейтральні тестові акаунти, яким дозволено перемикати БУДЬ-ЯКИЙ шаблон на льоту (з UI).
const NEUTRAL_USERS = new Set(["demo"]);

// Генерація протоколу З ТЕКСТУ (прев'ю /api/autofill + чистовик /api/protocol) дозволена ЛИШЕ
// нейтральним QA-акаунтам (demo). Реальні логіни — заблоковані (серверна перевірка, з клієнта не
// обійти). Транскрипція аудіо й порожній бланк (/api/skeleton) лишаються доступними всім.
function mayGenerate(user) { return NEUTRAL_USERS.has(user); }

// Чи дозволено цьому юзеру запросити саме цей шаблон (нейтральний — будь-який; решта — лише свій набір).
function mayUseTemplate(user, key) {
  const exists = Object.hasOwn(TEMPLATES, key); // не довіряй прото-ключам (__proto__/constructor)
  if (NEUTRAL_USERS.has(user)) return exists;
  return (TEMPLATE_CHOICES_BY_USER[user] || []).includes(key) && exists;
}

// Обрати system-промпт: honor-имо запитаний шаблон ЛИШЕ якщо він дозволений юзеру; інакше — залочений
// первинний (PROMPTS_BY_USER). Це серверна автoритетність: чужий шаблон з клієнта не підставити.
function promptFor(user, requestedTemplate) {
  if (requestedTemplate && mayUseTemplate(user, requestedTemplate)) return TEMPLATES[requestedTemplate].prompt;
  const key = PROMPTS_BY_USER[user];
  return (key && TEMPLATES[key] && TEMPLATES[key].prompt) || SYSTEM_PROMPT;
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
async function protocolViaBedrock(systemPrompt, raw, modelId) {
  let r;
  try {
    r = await bedrock.send(new ConverseCommand({
      modelId: modelId || BEDROCK_MODEL,
      system: [{ text: systemPrompt }],
      messages: [{ role: "user", content: [{ text: "--- СИРИЙ ТЕКСТ ДИКТОВКИ ---\n" + raw }] }],
      inferenceConfig: { maxTokens: 8000, temperature: 0 },
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
  if (!bedrock) return res.status(503).json({ error: "no_provider" });
  const user = getAuthUser(req);
  const t = req.query.template;
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
app.post("/api/autofill", async (req, res) => {
  if (!bedrock) return res.status(503).json({ error: "no_provider" });
  const raw = (req.body && req.body.text || "").trim();
  if (!raw) return res.status(400).json({ error: "empty" });
  const user = getAuthUser(req);
  if (!mayGenerate(user)) return res.status(403).json({ error: "gen_disabled" });
  if (trialState(user).expired) return res.status(403).json({ trialExpired: true });
  const systemPrompt = promptFor(user, req.body && req.body.template);
  try {
    const html = await protocolViaBedrock(systemPrompt, raw, BEDROCK_MODEL); // Nova — швидке прев'ю
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

  // Генерація з тексту тимчасово дозволена лише на demo (нейтральний QA). Реальні логіни — блок.
  if (!mayGenerate(user)) {
    logEvent(uid, "generate_err", null, user, { stage: "generate", code: "gen_disabled" });
    return res.status(403).json({
      error: "Генерація протоколу тимчасово доступна лише на демо-акаунті. Зверніться до команди AkesoSystems.",
      genDisabled: true,
    });
  }

  // Тестовий період вичерпано → блокуємо генерацію (серверна перевірка, обійти з клієнта не можна).
  const trial = trialState(user);
  if (trial.expired) {
    logEvent(uid, "generate_err", null, user, { stage: "generate", code: "trial_over" });
    return res.status(403).json({
      error: "Тестовий період (14 днів) завершився. Зверніться до команди AkesoSystems, щоб продовжити доступ.",
      trialExpired: true,
    });
  }

  const systemPrompt = promptFor(user, req.body && req.body.template);

  // Ланцюг провайдерів: основний → резерв. Кожен збій логуємо з кодом; успіх після збою — fallback:true.
  // Фінальний протокол: спершу Claude Sonnet (якість), якщо нема доступу — відкат на Nova.
  const chain = [];
  if (bedrock) {
    chain.push({ provider: "bedrock", model: BEDROCK_MODEL_FINAL, run: (sp, r) => protocolViaBedrock(sp, r, BEDROCK_MODEL_FINAL) });
    if (BEDROCK_MODEL_FINAL !== BEDROCK_MODEL) {
      chain.push({ provider: "bedrock", model: BEDROCK_MODEL, run: (sp, r) => protocolViaBedrock(sp, r, BEDROCK_MODEL) });
    }
  }
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
