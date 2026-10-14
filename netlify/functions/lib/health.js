'use strict';
// Health journal helpers shared by save-schedule.js and ai-chat.js so the
// browser and the AI assistant write exactly the same, validated shape.
function cleanText(v, n = 300) { return String(v ?? '').slice(0, n); }
const isDate = k => /^\d{4}-\d{2}-\d{2}$/.test(String(k || ''));

function numOrNull(v, min, max, { int = false, decimals = 1 } = {}) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return int ? Math.round(n) : Math.round(n * 10 ** decimals) / 10 ** decimals;
}

function safeEntry(e) {
  e = e && typeof e === 'object' && !Array.isArray(e) ? e : {};
  return {
    sleep: numOrNull(e.sleep, 0, 24, { decimals: 1 }),
    mood: numOrNull(e.mood, 1, 5, { int: true }),
    water: numOrNull(e.water, 0, 30, { int: true }),        // glasses
    steps: numOrNull(e.steps, 0, 100000, { int: true }),
    workout: numOrNull(e.workout, 0, 600, { int: true }),   // minutes
    weight: numOrNull(e.weight, 20, 400, { decimals: 1 }),  // kg
    note: cleanText(e.note, 300)
  };
}

function safeHealthJournal(v) {
  const r = v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  const out = {};
  for (const k of Object.keys(r).slice(0, 800)) {
    if (!isDate(k)) continue;
    if (!r[k] || typeof r[k] !== 'object' || Array.isArray(r[k])) continue;
    out[k] = safeEntry(r[k]);
  }
  // keep the newest 400 days
  const keys = Object.keys(out).sort();
  if (keys.length > 400) for (const k of keys.slice(0, keys.length - 400)) delete out[k];
  return out;
}

const DEFAULT_GOALS = { sleep: 8, water: 8, steps: 8000, workout: 30 };
function safeHealthGoals(v) {
  const g = v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  return {
    sleep: numOrNull(g.sleep, 3, 14, { decimals: 1 }) ?? DEFAULT_GOALS.sleep,
    water: numOrNull(g.water, 1, 30, { int: true }) ?? DEFAULT_GOALS.water,
    steps: numOrNull(g.steps, 500, 60000, { int: true }) ?? DEFAULT_GOALS.steps,
    workout: numOrNull(g.workout, 0, 300, { int: true }) ?? DEFAULT_GOALS.workout
  };
}

function avg(list) { const v = list.filter(x => typeof x === 'number'); return v.length ? Math.round(v.reduce((a, b) => a + b, 0) / v.length * 10) / 10 : null; }

function summarize(journal, goals, days = 7, todayKey) {
  const keys = Object.keys(journal || {}).sort().reverse().filter(k => !todayKey || k <= todayKey).slice(0, days);
  const rows = keys.map(k => ({ date: k, ...journal[k] }));
  return {
    days: rows.length,
    avgSleep: avg(rows.map(r => r.sleep)), avgMood: avg(rows.map(r => r.mood)), avgWater: avg(rows.map(r => r.water)),
    avgSteps: avg(rows.map(r => r.steps)), avgWorkout: avg(rows.map(r => r.workout)),
    lastWeight: (rows.find(r => typeof r.weight === 'number') || {}).weight ?? null,
    goals, rows
  };
}

module.exports = { safeEntry, safeHealthJournal, safeHealthGoals, DEFAULT_GOALS, summarize, numOrNull, isDate };
