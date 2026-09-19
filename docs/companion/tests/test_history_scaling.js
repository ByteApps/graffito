#!/usr/bin/env node
// Pure-JS unit test for chain-scan.js's fullHistoryUntil — the cursor-aware
// pager viewer.html's IndexedDB memo uses (plans/PLAN-graffito-history-
// scaling.md, U6/U1). No browser, no IndexedDB here: that lives only in
// viewer.html and needs a real DOM (the companion-regtest e2e's playwright
// leg covers it end to end, against a real node). This covers the pure
// paging/stop-rule logic chain-scan.js owns, the same way
// test_chain_scan.js covers the decode logic — with a PAGE-AWARE fetch
// stub, unlike that file's (which never actually pages; its `/txs/chain`
// always answers empty).
//
// Run: node tests/test_history_scaling.js
"use strict";
const vm = require("vm");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "chain-scan.js"), "utf8");

const ADDR = "bcrt1ptestaddress";
const PAGE = 25; // esplora /txs/chain page size — must match chain-scan.js

// A synthetic confirmed history of `n` txs, NEWEST FIRST (txid `c<n>` is
// the newest, `c1` the oldest) — the order real esplora and server.py's
// shim both return from /address/A/txs and /address/A/txs/chain.
function confirmedTxs(n) {
  const out = [];
  for (let i = n; i >= 1; i--) {
    out.push({
      txid: `c${i}`, vin: [], vout: [],
      status: { confirmed: true, block_height: 1000 + i, block_time: 1700000000 + i },
    });
  }
  return out;
}

function mempoolTxs(n) {
  const out = [];
  for (let i = 1; i <= n; i++) out.push({ txid: `m${i}`, vin: [], vout: [], status: { confirmed: false } });
  return out;
}

// Page-aware fetch stub: /address/A/txs = mempool + first PAGE confirmed;
// /address/A/txs/chain?after_txid=T = the next PAGE confirmed after T.
// `counter.n` counts every call — the thing each assertion below is
// really checking (request COUNT, not elapsed time — regtest-hides-cost-
// bugs applies to a browser test suite exactly as much as a Rust one).
function makeFetch(confirmed, mempool, counter) {
  return async (url) => {
    counter.n++;
    const chainMatch = url.match(/\/txs\/chain\?after_txid=(\w+)/);
    let body;
    if (chainMatch) {
      const idx = confirmed.findIndex((t) => t.txid === chainMatch[1]);
      body = idx === -1 ? [] : confirmed.slice(idx + 1, idx + 1 + PAGE);
    } else if (url.endsWith("/txs")) {
      body = [...mempool, ...confirmed.slice(0, PAGE)];
    } else {
      throw new Error("unexpected url " + url);
    }
    return { ok: true, text: async () => JSON.stringify(body) };
  };
}

function freshCtx(confirmed, mempool, counter) {
  const ctx = { fetch: makeFetch(confirmed, mempool, counter), TextDecoder, console, process };
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  return ctx;
}

async function callFullHistoryUntil(ctx, knownArr) {
  return vm.runInContext(
    `fullHistoryUntil(${JSON.stringify("stub")}, ${JSON.stringify(ADDR)}, ` +
      `new Set(${JSON.stringify(knownArr)}), null)`,
    ctx
  );
}

async function run() {
  const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

  // --- Empty cursor: full walk, same page count fullHistory itself would
  // make (62 confirmed txs -> 1 initial + 2 chain pages = 3 requests). ---
  {
    const confirmed = confirmedTxs(62);
    const counter = { n: 0 };
    const ctx = freshCtx(confirmed, [], counter);
    const txs = await callFullHistoryUntil(ctx, []);
    assert(txs.length === 62, "empty cursor must return the whole history: got " + txs.length);
    assert(counter.n === 3, "empty cursor: expected 3 requests (1 + 2 chain pages), got " + counter.n);
  }
  console.log("PASS empty cursor walks the full history, same request count as fullHistory's own paging");

  // --- A quiet re-load: the cursor already covers ALL of page 1, so the
  // margin (6) is reseen immediately and zero /txs/chain calls happen —
  // this is the case the companion-regtest e2e's second-load assertion
  // exercises against a real server. ---
  {
    const confirmed = confirmedTxs(62);
    const known = confirmed.slice(0, PAGE).map((t) => t.txid);
    const counter = { n: 0 };
    const ctx = freshCtx(confirmed, [], counter);
    const txs = await callFullHistoryUntil(ctx, known);
    assert(counter.n === 1, "known tail: expected exactly 1 request (page 1 only), got " + counter.n);
    assert(txs.length === PAGE, "known tail: page 1's own txs, got " + txs.length);
  }
  console.log("PASS a cursor covering page 1 stops after the first request — no /txs/chain calls");

  // --- A handful of genuinely NEW confirmed txs sit ahead of an
  // otherwise-known tail: the walk must still stop within page 1 once it
  // re-sees the margin, not walk to the end of a 62-tx history for 3 new
  // notes. ---
  {
    const confirmed = confirmedTxs(62);
    const known = confirmed.slice(3).map((t) => t.txid); // all but the 3 newest
    const counter = { n: 0 };
    const ctx = freshCtx(confirmed, [], counter);
    const txs = await callFullHistoryUntil(ctx, known);
    assert(counter.n === 1,
      "3 new + known tail: page 1 alone already re-sees margin=6 known txids, got " + counter.n);
    assert(txs.some((t) => t.txid === "c62"), "the 3 new txs must be present in the result");
  }
  console.log("PASS a shallow set of new txs still stops within page 1 once the margin is re-seen");

  // --- A known set smaller than the reorg margin (here: 1 txid, deep in
  // the history) can never reach the margin — the walk must fall back to
  // a full walk rather than stop early and silently drop history. ---
  {
    const confirmed = confirmedTxs(40);
    const counter = { n: 0 };
    const ctx = freshCtx(confirmed, [], counter);
    const txs = await callFullHistoryUntil(ctx, ["c1"]);
    assert(txs.length === 40, "sub-margin known set must still walk the full history: got " + txs.length);
  }
  console.log("PASS a known set smaller than the reorg margin safely falls back to a full walk");

  // --- Mempool txs ride along on page 1 unconditionally, cursor or not —
  // this is what lets an unconfirmed -> confirmed transition surface with
  // no special-casing (U1's rule, ported here). ---
  {
    const confirmed = confirmedTxs(30);
    const mempool = mempoolTxs(2);
    const known = confirmed.slice(0, PAGE).map((t) => t.txid);
    const counter = { n: 0 };
    const ctx = freshCtx(confirmed, mempool, counter);
    const txs = await callFullHistoryUntil(ctx, known);
    assert(txs.filter((t) => !t.status.confirmed).length === 2,
      "mempool txs must ride along on page 1 unconditionally");
  }
  console.log("PASS mempool txs are always present on page 1, cursor or not");

  console.log("HISTORY SCALING (fullHistoryUntil) UNIT TESTS PASSED");

  // Mutation check performed by hand (not left in code, per the task):
  // temporarily changed the while-loop condition in fullHistoryUntil from
  // `(fullWalk || knownSeen < HISTORY_REORG_MARGIN)` to always `true`
  // (i.e. deleted the stop rule) and re-ran the "known tail" scenario
  // above — counter.n went from 1 to 3, walking the entire 62-tx history
  // every time instead of stopping after page 1. Confirms this suite
  // would catch a regression back to the old O(N) behavior. Reverted
  // immediately after.
}

run().catch((e) => { console.error("FAIL " + e.message); process.exit(1); });
