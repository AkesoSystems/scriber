#!/usr/bin/env node
// Read-only MCP server over Scriber's /api/stats endpoint.
// Lets an AI client pull live per-doctor analytics (including the raw per-recording
// log and per-user day-by-day dynamics) without manual copy-paste from the dashboard.
//
// It is a thin wrapper: it only GETs the same endpoint the dashboard uses. No writes,
// no PHI — the server already firewalls free text out of analytics.jsonl.
//
// Config via env (set these in the MCP client config, NOT committed):
//   SCRIBER_URL         e.g. https://scriber.akesosystems.com   (required)
//   SCRIBER_ADMIN_KEY   value of ADMIN_KEY on the server          (required)
//   SCRIBER_BASIC_USER  nginx basic-auth user (e.g. test)         (optional*)
//   SCRIBER_BASIC_PASS  nginx basic-auth password                 (optional*)
//   * required only if the site sits behind the nginx basic-auth gate (prod does).

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const URL_BASE = (process.env.SCRIBER_URL || "").replace(/\/+$/, "");
const ADMIN_KEY = process.env.SCRIBER_ADMIN_KEY || "";
const BASIC_USER = process.env.SCRIBER_BASIC_USER || "";
const BASIC_PASS = process.env.SCRIBER_BASIC_PASS || "";

if (!URL_BASE || !ADMIN_KEY) {
  console.error("[scriber-stats-mcp] SCRIBER_URL та SCRIBER_ADMIN_KEY обовʼязкові — задайте їх у конфізі MCP.");
  process.exit(1);
}

// GET /api/stats[?user=]; повертає розпарсений JSON або кидає зрозумілу помилку
// (а не мовчазний порожній результат) — щоб погані креди/ключ було видно одразу.
async function fetchStats(user) {
  const u = new URL(URL_BASE + "/api/stats");
  u.searchParams.set("key", ADMIN_KEY);
  if (user) u.searchParams.set("user", user);

  const headers = {};
  if (BASIC_USER || BASIC_PASS) {
    headers.Authorization = "Basic " + Buffer.from(`${BASIC_USER}:${BASIC_PASS}`).toString("base64");
  }

  const res = await fetch(u, { headers });
  const body = await res.text();
  if (!res.ok) {
    let hint = "";
    if (res.status === 401) hint = " (nginx basic-auth: перевірте SCRIBER_BASIC_USER/PASS)";
    else if (res.status === 403) hint = " (невірний SCRIBER_ADMIN_KEY)";
    else if (res.status === 503) hint = " (ADMIN_KEY на сервері не заданий/дефолтний — статистика вимкнена)";
    throw new Error(`/api/stats → HTTP ${res.status}${hint}: ${body.slice(0, 200)}`);
  }
  try { return JSON.parse(body); }
  catch { throw new Error(`/api/stats повернув не-JSON (можливо, гейт-сторінка): ${body.slice(0, 200)}`); }
}

function ok(obj) { return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] }; }
function fail(e) { return { content: [{ type: "text", text: "Помилка: " + e.message }], isError: true }; }

const server = new McpServer({ name: "scriber-stats", version: "1.0.0" });

server.registerTool(
  "scriber_stats",
  {
    title: "Scriber stats",
    description:
      "Стягнути аналітику Scriber (УЗД-транскрайбер). Без user — загальні агрегати + список лікарів (users/nicks). " +
      "З user (логін, напр. 'test2') — додає сирий журнал кожного запису (recordingsLog) і динаміку по днях (byUserDay). PHI-safe.",
    inputSchema: { user: z.string().optional().describe("Логін Basic Auth лікаря, напр. 'test2'. Пропустити — щоб отримати все.") },
  },
  async ({ user }) => {
    try { return ok(await fetchStats(user)); }
    catch (e) { return fail(e); }
  }
);

server.registerTool(
  "scriber_recordings",
  {
    title: "Scriber per-doctor recordings",
    description:
      "Стислий зріз по одному лікарю: нік, журнал кожного запису (час+тривалість/ms/код помилки) і динаміка по днях. " +
      "Відповідає на «кожен запис який записував лікар і скільки» без середніх.",
    inputSchema: { user: z.string().describe("Логін Basic Auth лікаря, напр. 'test2'.") },
  },
  async ({ user }) => {
    try {
      const d = await fetchStats(user);
      return ok({
        user,
        nick: (d.nicks && d.nicks[user]) || user,
        recordingsLog: d.recordingsLog || [],
        byDay: (d.byUserDay && d.byUserDay[user]) || {},
        totals: { protocols: d.protocolsGenerated, recordings: d.recordings, generateErrors: d.generateErrors },
      });
    } catch (e) { return fail(e); }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("[scriber-stats-mcp] запущено (stdio).");
