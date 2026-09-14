// Service worker: the master clock and bundle assembler.
//
// It owns t0. Every modality is stamped as ms-since-t0 on arrival here, so the
// timeline, rrweb stream, network (HAR), and frames are all aligned by
// construction — no post-hoc syncing. On stop it assembles the Capture Bundle
// (the exact shape ../analyze/pack.py consumes) and downloads it as a zip.
//
// v2: capture is GLOBAL, not pinned to one tab. The screen video comes from
// getDisplayMedia() in the offscreen document (follows the user across tabs and
// windows), and the CDP debugger + content script are attached to EVERY eligible
// tab — including tabs opened mid-recording. Every event is tagged with its source
// tab so the merged one-clock timeline stays disambiguable.
//
// Heavy third-party pieces are integration points, not reimplemented:
//   - rrweb runs in the content script (raw DOM stream)
//   - video is recorded in an offscreen document via MediaRecorder
//   - full request/response bodies come from the CDP Network domain (chrome.debugger)

import { redactHeaders, redactBody, redactUrl, scrubTokens, redactCtx } from "./redact.js";
import { makeZip } from "./zip.js";
import { downloadComplete } from "./download.js";
import { streamFiles, frameMeta } from "./bundle-streams.js";
import * as db from "./db.js";
import { bundleReadme, bundleClaudeMd, bundleAgentsMd, documentationSkill } from "./bundle-docs.js";
import { navActions } from "./nav-policy.js";
import { hostOnBlocklist } from "./blocklist.js";
import { recordingElapsed } from "./clock.js";
import { serializeSession, applySession } from "./session.js";
import { inCaptureScope } from "./capture-scope.js";
import { isStorageQuotaError } from "./write-failure.js";
import { isSameSite, isJsonMime, capResponseBody } from "./response-body.js";

let generation = crypto.randomUUID();
let commandTail = Promise.resolve();
function command(fn) {
  const result = commandTail.then(() => rehydrated).then(fn);
  commandTail = result.catch(() => {});
  return result;
}
const current = (g) => g === generation && state.recording && !state.arming;
const accepting = (g) => current(g) && !state.paused;

const state = {
  recording: false,
  arming: false, // picker open / countdown running, before capture goes live
  activeTabId: null, // the tab Start was pressed in — instrumented when we go live
  // What the user shared, used to scope capture/overlay to the recorded surface only:
  captureSurface: null, // "browser" (one tab) | "window" | "monitor" (whole screen)
  captureTabId: null, // for a tab share — the only tab in scope
  captureWindowId: null, // for a window share — the only window in scope
  paused: false, // EFFECTIVE pause (manual || auto) — what the recorder/overlay see
  manualPaused: false, // user pressed Pause
  autoPaused: false, // active tab is blocklisted → capture suspended automatically
  pauseReason: null, // "manual" | "blocklist" — drives the overlay copy
  pausedAccum: 0, // total ms spent paused so far (completed pauses)
  pauseStartedAt: 0, // wall-clock ms the current pause began (0 if not paused)
  t0: 0,
  tabIds: new Set(), // every tab we've attached the debugger + content script to
  tabs: new Map(), // tabId -> { id, url, title } legend for the bundle
  blocklist: [], // hostnames we never record on
  har: new Map(), // requestId -> partial HAR entry
  urls: new Set(),
  errors: [], // { t, where, message, stack } — surfaced into the bundle
  micActive: false, // is the mic actually being recorded? drives the overlay level meter
  micEndedEarly: false, // mic track ended mid-recording → narration is truncated
  storageFull: false, // an IndexedDB write hit the quota → capture is silently truncating
  // Re-share state: when the screen share dies mid-recording (user clicked
  // Chrome's "Stop sharing" or closed the shared window), the video track ends
  // but the mic + event/network capture keep going. We set awaitingReshare and
  // surface a Re-share button on the overlay; clicking it re-opens the picker
  // and the new video becomes a second segment of the same video.webm. The
  // segment offsets (ms since t0 at which each video segment's recorder
  // started) are reported by the offscreen doc at finalize and recorded in the
  // manifest so the analyze side can map events to segments and flag the gaps.
  awaitingReshare: false, // screen share died — overlay shows Re-share
  videoSegments: [], // [{ offsetMs }] — each video segment's start offset (ms since t0)
  // Frame METADATA only ({ t, file }) — the PNG bytes live in IndexedDB. This lets
  // the worker build manifest.frames without ever loading hundreds of screenshots
  // into memory (that bloat is exactly what the offscreen assembly now avoids).
  frames: [],
};

// The recording clock: ms since t0 with all PAUSED time removed, so event/frame
// timestamps stay aligned to video.webm (the MediaRecorder also excludes paused
// time). Before t0 is set (arming/countdown) it reads 0. Pure math lives in
// clock.js (unit-tested); this just feeds it the live state.
const now = () => recordingElapsed(Date.now(), state);

// Collect a runtime error into the bundle so failures are diagnosable from the
// exported zip (errors.json) instead of being trapped in a console we can't see —
// the offscreen doc and content script both report here.
function logError(where, info = {}) {
  // Error messages/stacks are machine-generated and can embed captured values —
  // a URL with ?token=…, a header dump, a secret-valued input in a DOM selector.
  // errors.json is part of the exported bundle, so scrub every string through
  // the canonical token/secret scrubbers BEFORE persisting (SYNTHESIS #11).
  const clean = (s) => (typeof s === "string" ? scrubTokens(redactUrl(s)) : s);
  const message = clean(info.message || String(info.error || info) || "unknown error");
  const stack = clean(info.stack || null);
  state.errors.push({ t: state.t0 ? now() : 0, where, message, stack });
  console.warn(`[capture-error] ${where}: ${message}`);
  persistSession();
}

// An IndexedDB write failed. The dangerous case is QuotaExceededError: once the
// quota is hit EVERY subsequent write (frames, timeline, rrweb, HAR) starts
// failing, so the recording keeps showing REC and the keepalive keeps the worker
// warm while it has quietly STOPPED persisting data — at export you'd get a
// silently-truncated bundle with no explanation. So the first time a write fails on
// quota, surface it loudly: flag it (lands in the manifest), log it (errors.json),
// and flip the badge so the user knows to finish and export now. Non-quota write
// blips (a transient tx abort) are left to the per-site catch — they self-heal.
function noteWriteFailure(where, e) {
  // isStorageQuotaError (write-failure.js) distinguishes a real full-disk
  // QuotaExceededError from Chrome's captureVisibleTab rate-limit message, which
  // also contains the word "quota" but is a harmless, self-healing throttle.
  if (isStorageQuotaError(e) && !state.storageFull) {
    state.storageFull = true;
    logError(where, {
      message:
        "browser storage is full — capture can no longer be saved and is being truncated; finish and export now",
      stack: e?.stack,
    });
    setBadge("!", "#c0392b");
  }
}

// Uncaught failures in the service worker itself.
self.addEventListener("error", (e) => logError("background", { message: e.message, stack: e.error?.stack }));
self.addEventListener("unhandledrejection", (e) =>
  logError("background", { message: e.reason?.message || String(e.reason), stack: e.reason?.stack })
);

// ---- crash recovery: persist the live recording so a worker restart survives ----
//
// The keepalive (offscreen.js) should stop the worker dying mid-recording, but it's
// not a guarantee — Chrome can still reclaim the worker under memory pressure or a
// crash. So the durable slice of `state` (t0, pause accounting, tab legend,
// blocklist, …) is mirrored to chrome.storage.local on every transition; the bulk
// streams (timeline, rrweb, frames, network) already live in IndexedDB. On a cold
// start, rehydrate() reads it back and resumes the recording instead of losing it.
const SESSION_KEY = "captureSession";
let persistTimer = null;

// Debounced — transitions can cluster (instrument several tabs, a burst of navs);
// one coalesced write per ~250ms is plenty (the keepalive keeps death rare, so this
// is a backstop, not a hot path).
let snapshotTail = Promise.resolve();

function commitSession() {
  clearTimeout(persistTimer);
  persistTimer = null;
  const rec = serializeSession(state);
  if (!rec) return snapshotTail;
  const snapshot = { ...rec, generation };
  const write = snapshotTail.then(() => chrome.storage.local.set({ [SESSION_KEY]: snapshot }));
  snapshotTail = write.catch(() => {});
  return write;
}

function persistSession() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    commitSession().catch((e) => {
      state.persistFailed = true;
      console.warn("[capture] session snapshot persist failed:", e?.message || e);
    });
  }, 250);
}

function clearPersistedSession() {
  clearTimeout(persistTimer);
  persistTimer = null;
  const clear = snapshotTail.then(() => chrome.storage.local.remove(SESSION_KEY));
  snapshotTail = clear.catch(() => {});
  return clear;
}

async function offscreenExists() {
  try {
    return !!(await chrome.offscreen.hasDocument?.());
  } catch {
    return false;
  }
}

// Commands (pause/finish/start/…) wait on this so they aren't dropped against a
// half-restored worker that woke specifically to handle them.
let resolveRehydrated;
const rehydrated = new Promise((r) => (resolveRehydrated = r));

// Runs once on every worker cold start. If a recording was live when the previous
// worker instance died, restore it. Two cases:
//   • offscreen doc still alive (worker-only death — the common case, e.g. Chrome
//     reclaimed the worker during a pause): re-attach debuggers, resume the frame
//     timer + overlay, and carry on. The video kept recording in the offscreen doc
//     the whole time, so nothing is lost.
//   • offscreen doc gone (e.g. the browser was restarted): the video pipeline can't
//     continue, but the structured capture is safe in IndexedDB — salvage it into a
//     (video-less) bundle so the recording still isn't lost, then clear.
async function rehydrate() {
  try {
    if (state.recording || state.arming) return; // a fresh session is already live here
    let rec;
    try {
      ({ [SESSION_KEY]: rec } = await chrome.storage.local.get(SESSION_KEY));
    } catch {
      return;
    }
    if (!rec || !rec.recording) return;

    const { unsavedTake, pendingExport } = await chrome.storage.local.get(["unsavedTake", "pendingExport"]);
    applySession(state, rec);
    generation = rec.generation || crypto.randomUUID();
    if (unsavedTake && pendingExport) {
      state.recording = false;
      state.stoppedDuration = pendingExport.manifest?.duration_ms ?? now();
      setBadge("!", "#c0392b");
      return;
    }
    // The in-memory HAR working copy is rebuilt from its IDB mirror.
    try {
      for (const e of await db.readAll("har")) state.har.set(e.requestId, e);
    } catch {}

    const media = await chrome.runtime.sendMessage({ type: "offscreen-status" }).catch(() => null);
    if (media?.live && media.t0 === state.t0) {
      for (const tabId of [...state.tabIds]) {
        // The debugger may have detached when the worker died; re-attach so network
        // resumes. Re-arm the content script too.
        await ensureDebuggerAttached(tabId);
        chrome.tabs.sendMessage(tabId, { type: "start", ...overlayClock() }).catch(() => {});
      }
      if (!state.paused) startFrameTimer();
      setBadge(state.paused ? "❚❚" : "REC", state.paused ? "#f39c12" : "#c0392b");
      broadcastOverlay();
      logError("worker-restart", { message: "service worker restarted mid-recording — state recovered, capture resumed" });
      persistSession();
    } else {
      // No video context to resume — finalise what we have so it isn't lost.
      logError("worker-restart", { message: "recording interrupted (no video context) — exporting recovered data" });
      state.stoppedDuration = now();
      state.recording = false;
      stopFrameTimer();
      await teardownTabs();
      await finalizeAndExport();
    }
  } finally {
    resolveRehydrated(); // unblock any queued commands regardless of outcome
  }
}

async function getSettings() {
  const { blocklist = [], micEnabled = true } = await chrome.storage.local.get(["blocklist", "micEnabled"]);
  // Exports always go to the browser's Downloads folder (bulletproof, no size limit,
  // no folder-picker / "Save as" dialog). The video Blob is written from the offscreen
  // doc via an object URL — see exportViaOffscreen / offscreen.js assembleAndSave.
  return { blocklist, micEnabled };
}

// Suffix-aware host match (so `1password.com` blocks `my.1password.com`) — see
// blocklist.js. The old exact-string check silently failed and let a sensitive
// tab through.
const hostBlocked = (url) => hostOnBlocklist(url, state.blocklist);

// Is this tab part of the surface the user is actually recording? Used to keep the
// overlay + annotation tools + instrumentation + frames off windows/tabs that aren't
// in video.webm (a window share must not light up the menu on another window). Pure
// decision lives in capture-scope.js; this feeds it the live capture context.
const inScope = (tab) =>
  inCaptureScope(tab, {
    surface: state.captureSurface,
    captureTabId: state.captureTabId,
    captureWindowId: state.captureWindowId,
  });

// ---- lifecycle -----------------------------------------------------------

// Pages where content scripts, captureVisibleTab, and the debugger all fail.
// We skip these tabs instead of half-attaching and logging noise.
const RESTRICTED = /^(chrome|edge|about|chrome-extension|devtools|view-source):|^https:\/\/chrome\.google\.com\/webstore/;

function isEligible(tab) {
  // Skip restricted pages AND the user's "Never record on" hosts — a blocklisted
  // host must not be instrumented at all (no debugger, no content script, no DOM /
  // clicks / frames), not merely have its network rows dropped from the HAR.
  return !!(tab && tab.url && !RESTRICTED.test(tab.url) && !hostBlocked(tab.url));
}

// The content script is registered for new page loads, but a tab opened BEFORE
// the extension loaded won't have it. Inject on demand so the first recording
// after install/reload still works.
async function ensureContentScript(tabId) {
  try {
    const res = await chrome.tabs.sendMessage(tabId, { type: "is-recording" });
    if (res) return true; // already there
  } catch {
    // no listener yet — fall through and inject
  }
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["src/lib/rrweb.min.js", "src/content.js"],
    });
    return true;
  } catch (e) {
    console.warn("content-script injection failed:", e);
    return false;
  }
}

// chrome.debugger calls normally resolve in a few ms, but a session left in a
// half-broken state (attach succeeded, then the target went away before the
// following command landed — exactly what a mid-navigation renderer swap can
// do) can leave attach/detach/sendCommand hanging far longer than that. Without
// a hard ceiling, Finish -> stop() -> teardownTabs() -> await detach() can block
// indefinitely, making the Finish button look unresponsive. Race every
// chrome.debugger call against this so a stuck one can never hold up the flow.
const DEBUGGER_CALL_TIMEOUT_MS = 1500;
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)),
  ]);
}

// Tabs we believe have a live, Network-enabled debugger session right now. Lets
// reattachTab() (called on EVERY navigation, including SPA pushState/query-param
// route changes) skip the chrome.debugger IPC round-trip in the common case
// instead of paying it on every click — cleared on onDetach, set on success below.
const debuggerAlive = new Set();

// How long to back off before retrying an attach for a tab that just detached.
// Without this, a tab whose debugger session won't stay up (seen on some
// Brave builds, which handle the CDP debugger banner differently than Chrome)
// causes onDetach -> attach -> onDetach -> attach... with no gap between
// attempts, pegging the service worker and starving every other message it
// needs to process (including the Finish-recording click).
const DEBUGGER_RETRY_COOLDOWN_MS = 3000;
const debuggerRetryAt = new Map(); // tabId -> timestamp of last attach attempt

const debuggerAttaching = new Map(); // tabId -> in-flight attach Promise, dedupes racing callers

// Make sure the CDP debugger is attached to a tab and its Network domain is live.
// No-ops immediately if we already believe the session is alive (the normal case
// on every navigation). If it's not, attach() + Network.enable re-establishes it,
// throttled per tab so a session that won't stay up doesn't thrash, and deduped so
// instrumentTab() and reattachTab() racing on the same tab don't both call attach().
// Logs to errors.json on failure so a dead session is never silent.
async function ensureDebuggerAttached(tabId) {
  const g = generation;
  if (debuggerAlive.has(tabId)) return;
  if (debuggerAttaching.has(tabId)) return debuggerAttaching.get(tabId);
  const lastAttempt = debuggerRetryAt.get(tabId) || 0;
  if (Date.now() - lastAttempt < DEBUGGER_RETRY_COOLDOWN_MS) return;
  debuggerRetryAt.set(tabId, Date.now());
  const attempt = (async () => {
    try {
      // Probe OUR existing CDP session first. Another extension's attachment
      // cannot pass sendCommand, so this never steals somebody else's debugger.
      const enabled = await withTimeout(
        chrome.debugger.sendCommand({ tabId }, "Network.enable"),
        DEBUGGER_CALL_TIMEOUT_MS, `Network probe(${tabId})`
      ).then(() => true, () => false);
      if (!enabled)
        await withTimeout(chrome.debugger.attach({ tabId }, "1.3"), DEBUGGER_CALL_TIMEOUT_MS, `debugger.attach(${tabId})`);
      await withTimeout(
        chrome.debugger.sendCommand({ tabId }, "Network.enable"),
        DEBUGGER_CALL_TIMEOUT_MS,
        `Network.enable(${tabId})`,
      );
      if (g !== generation || (!state.recording && !state.arming)) {
        await chrome.debugger.detach({ tabId }).catch(() => {});
        return;
      }
      debuggerAlive.add(tabId);
    } catch (e) {
      logError("debugger", { message: `attach failed on tab ${tabId}: ${e?.message || e}`, stack: e?.stack });
    } finally {
      debuggerAttaching.delete(tabId);
    }
  })();
  debuggerAttaching.set(tabId, attempt);
  return attempt;
}

// Attach the CDP debugger (for network) and the content script (for DOM/events)
// to one tab. Idempotent — safe to call again for a tab we already track.
async function instrumentTab(tabId) {
  const g = generation;
  if (!current(g) || state.tabIds.has(tabId)) return;
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!current(g) || !isEligible(tab)) return;
  // Don't instrument (or mount the overlay on) a tab outside the recorded surface — a
  // tab share captures only that tab; a window share only that window. Otherwise the
  // menu + capture would leak onto a window that isn't in video.webm.
  if (!inScope(tab)) return;
  state.tabIds.add(tabId);
  const tabUrl = redactUrl(tab.url);
  // A page title can carry a token (e.g. a "Reset password: <token>" page) and the
  // legend is exported, so scrub it before it lands in the manifest.
  state.tabs.set(tabId, { id: tabId, url: tabUrl, title: scrubTokens(tab.title || "") });
  state.urls.add(tabUrl);

  // CDP network capture (shows the per-tab "is being debugged" banner — by design).
  await ensureDebuggerAttached(tabId);

  if (!current(g)) return;
  const injected = await ensureContentScript(tabId);
  if (!current(g) || !state.tabIds.has(tabId)) return;
  // Carry the full clock so a tab that joins mid-recording renders its overlay in
  // the correct state (paused-aware elapsed clock, paused or live).
  if (injected)
    chrome.tabs.sendMessage(tabId, { type: "start", ...overlayClock() }).catch(() => {});
  persistSession(); // tab legend / tabIds changed
}

// Re-arm a tab AFTER A NAVIGATION. A full-page navigation (every click in a
// server-rendered app) tears down the content script — but the CDP debugger
// USUALLY stays attached to the tab, so network keeps recording while
// clicks/rrweb/frames silently die for the rest of the page's life. (This is
// the bug that lost ~4.5 min of a 6 min server-rendered session: only network
// survived.) The freshly-loaded content script is supposed to self-attach, but
// that single fire-and-forget check is unreliable; the worker stays alive
// throughout (the debugger keeps it warm), so we re-push capture from here on
// every navigation.
// The debugger session doesn't always survive, though (a cross-process/site-
// isolation swap on a real top-level navigation can drop it, same as the
// infobar-dismiss/onDetach case below) — so re-assert Network.enable here too,
// re-attaching first if needed, instead of assuming it's still alive.
async function reattachTab(tabId, tab) {
  const g = generation;
  if (!current(g) || !state.tabIds.has(tabId) || !inScope(tab)) return;
  // Keep the tab legend + URL set current as the user navigates.
  if (tab?.url) {
    const u = redactUrl(tab.url);
    state.urls.add(u);
    const info = state.tabs.get(tabId);
    if (info) info.url = u;
  }
  await ensureDebuggerAttached(tabId);
  if (!current(g)) return;
  const present = await ensureContentScript(tabId);
  if (!current(g) || !state.tabIds.has(tabId)) return;
  if (present)
    chrome.tabs.sendMessage(tabId, { type: "start", ...overlayClock() }).catch(() => {});
  if (tab?.url) persistSession(); // legend URL moved
}

async function uninstrumentTab(tabId) {
  if (!state.tabIds.has(tabId)) return;
  state.tabIds.delete(tabId);
  debuggerAlive.delete(tabId);
  debuggerRetryAt.delete(tabId);
  chrome.tabs.sendMessage(tabId, { type: "stop" }).catch(() => {});
  try {
    await withTimeout(chrome.debugger.detach({ tabId }), DEBUGGER_CALL_TIMEOUT_MS, `debugger.detach(${tabId})`);
  } catch {}
  persistSession(); // tabIds changed
}

const COUNTDOWN_SECONDS = 3;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function start(triggerTabId, task, purposes) {
  if (state.recording || state.arming) return { ok: false, error: "Already recording." };
  // Claim the lock SYNCHRONOUSLY, before any await — otherwise a second Start (double
  // click, or popup + overlay) slips through the guard during getSettings/clearAll and
  // opens a second picker + countdown, and the second clearAll wipes the first take.
  state.arming = true;

  // Loss guard: a previous take whose export FAILED is still sitting in IndexedDB.
  // Starting a new recording would clearAll() and wipe it. Refuse until the user
  // retries the export or explicitly discards it (the popup surfaces both).
  try {
    const { unsavedTake } = await chrome.storage.local.get("unsavedTake");
    if (unsavedTake) {
      state.arming = false;
      return { ok: false, error: "You have an unsaved recording. Retry its export or discard it first." };
    }
  } catch {}

  const { blocklist, micEnabled } = await getSettings();
  generation = crypto.randomUUID();
  state.stoppedDuration = null;
  await db.clearAll();
  state.frames = []; // fresh take → drop the previous take's frame metadata
  state.storageFull = false; // fresh take → reset the IDB-quota tripwire + frame cap
  state.micEndedEarly = false;
  frameCapLogged = false;
  // Reset any offscreen doc left over from a previous (possibly worker-killed) session
  // so a stale getDisplayMedia stream is released and we don't stack a second picker.
  await closeOffscreen();

  let activeTabId = triggerTabId;
  if (activeTabId == null) {
    const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTabId = active?.id;
  }

  // ARMING phase: the screen picker is up and a 3-2-1 countdown will run before
  // capture goes live. recording stays FALSE through all of it, so NOTHING is
  // recorded during the pre-roll — is-recording answers false, appendTimeline and
  // rrweb ingest drop, frames don't fire. t0 is set in goLive() at the END of the
  // countdown, so the clock starts exactly when capture does.
  Object.assign(state, {
    recording: false,
    arming: true,
    activeTabId,
    captureSurface: null,
    captureTabId: null,
    captureWindowId: null,
    paused: false,
    manualPaused: false,
    autoPaused: false,
    pauseReason: null,
    pausedAccum: 0,
    pauseStartedAt: 0,
    t0: 0,
    task: (task || "").slice(0, 500), // the user's stated goal — anchors the analysis
    purposes: Array.isArray(purposes) ? purposes.slice(0, 8) : [], // why they recorded — steers analysis
    tabIds: new Set(),
    tabs: new Map(),
    blocklist,
    har: new Map(),
    urls: new Set(),
    errors: [],
    videoEndedEarly: false, // set if the screen share stops on its own mid-recording
    awaitingReshare: false, // reset on a fresh take
    videoSegments: [], // reset on a fresh take
    micActive: false, // confirmed once the offscreen doc reports the mic track is live
  });

  setBadge("•••", "#f39c12"); // arming (amber) — distinct from REC
  // Open the screen picker in the offscreen doc. When the user finishes the picker,
  // offscreen replies `offscreen-armed`; runCountdownThenGo() then runs the 3-2-1
  // and goes live. If the offscreen layer is unavailable, go live data-only.
  const attempted = await startVideo(micEnabled);
  if (!attempted) runCountdownThenGo();
  return { ok: true, arming: true };
}

// Picker done → 3-2-1 countdown in the active tab → go live. The countdown is shown
// by the content script (injected if needed; it stays inert for capture because
// recording is still false). Bails at every step if stop()/cancel() raced us.
async function runCountdownThenGo() {
  const g = generation;
  if (!state.arming) return;
  const tabId = state.activeTabId;
  if (tabId != null) {
    await ensureContentScript(tabId);
    for (let n = COUNTDOWN_SECONDS; n >= 1; n--) {
      if (!state.arming || g !== generation) return;
      chrome.tabs.sendMessage(tabId, { type: "countdown", n }).catch(() => {});
      await sleep(1000);
    }
    chrome.tabs.sendMessage(tabId, { type: "countdown", n: 0 }).catch(() => {}); // clear it
  }
  if (!state.arming || g !== generation) return;
  await command(() => g === generation && state.arming ? goLive() : undefined);
}

// Capture actually begins here: set t0, flip recording on, instrument the active
// tab for real (mounts the pill, starts rrweb + listeners), and tell the offscreen
// recorder to start — all against the fresh t0. Other tabs are instrumented lazily
// when the user switches into them (tabs.onActivated), so we capture what they
// actually do, not every open tab. See nav-policy.js.
async function goLive() {
  if (!state.arming) return;
  const [active] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const tab = state.captureSurface === "browser"
    ? await chrome.tabs.get(state.captureTabId).catch(() => null)
    : active;
  state.activeTabId = tab?.id ?? null;

  // Prepare instrumentation BEFORE t0. No content recorder has been started yet.
  if (isEligible(tab) && inScope(tab)) {
    await ensureDebuggerAttached(tab.id);
    await ensureContentScript(tab.id);
  }
  state.recording = true;
  state.paused = false;
  state.manualPaused = false;
  state.autoPaused = false;
  state.pauseReason = null;
  state.pausedAccum = 0;
  state.pauseStartedAt = 0;
  state.t0 = Date.now();
  // arming keeps all intake closed while the indispensable snapshot commits.
  try {
    await commitSession();
  } catch (e) {
    state.recording = false;
    state.arming = false;
    await closeOffscreen();
    await teardownTabs();
    throw e;
  }
  state.arming = false;
  await updateAutoPause();
  await chrome.runtime.sendMessage({ type: "offscreen-go", clock: overlayClock() }).catch(() => {});
  if (tab?.id != null) await instrumentTab(tab.id);
  if (!state.tabIds.size)
    logError("golive", { message: "No verified browser surface available for structured capture." });
  if (!state.paused) {
    await captureFrame("recording started");
    startFrameTimer();
  }
  setBadge(state.paused ? "❚❚" : "REC");
  persistSession();
}

async function stop() {
  if (!state.recording) return;
  state.stoppedDuration = now();
  // Freeze media promptly, rather than recording debugger teardown/export time.
  await chrome.runtime.sendMessage({ type: "offscreen-pause", clock: overlayClock() }).catch(() => {});
  await commitSession();
  state.recording = false;
  stopFrameTimer();
  await chrome.storage.local.set({ unsavedTake: true });
  await teardownTabs();
  try {
    await finalizeAndExport();
  } catch (e) {
    await onExportFailure(null, e?.message || String(e), exportFilename());
  }
}

// Stop the overlay + detach the debugger on every tracked tab. (Stale tab ids — e.g.
// after a browser restart during salvage — just throw and are ignored.)
async function teardownTabs() {
  for (const tabId of state.tabIds) {
    chrome.tabs.sendMessage(tabId, { type: "stop" }).catch(() => {});
    try {
      await withTimeout(chrome.debugger.detach({ tabId }), DEBUGGER_CALL_TIMEOUT_MS, `debugger.detach(${tabId})`);
    } catch {}
  }
  state.tabIds.clear();
  // So a stale cooldown/alive flag from this session can't affect the next one.
  debuggerAlive.clear();
  debuggerRetryAt.clear();
  debuggerAttaching.clear();
}

function exportFilename() {
  const stamp = new Date(state.t0).toISOString().replace(/[:.]/g, "-");
  return `capture-${stamp}.zip`;
}

// Finalize the recording into a saved bundle. The video and the bulk streams
// (events.jsonl, frames) are far too big to move through a chrome.runtime message
// (hard 64MiB cap) or a base64 data: URL — that cap is exactly what silently lost a
// 17-min recording. So the zip is assembled and written WHERE the bytes already
// live:
//   • normal Finish → the OFFSCREEN document: it holds the video Blob, reads the
//     bulk streams from IndexedDB itself, zips, and writes via File System Access
//     (chosen folder) or an object-URL download — no size limit, nothing messaged.
//   • crash salvage (no offscreen doc) → the SERVICE WORKER assembles a video-less
//     bundle from IndexedDB and downloads it (bounded; no video, the big part).
// Either way the take is only cleared after the save is confirmed.
async function finalizeAndExport() {
  if (await offscreenExists()) {
    await exportViaOffscreen();
  } else {
    await salvageExport();
  }
}

// Normal Finish: the offscreen doc owns the bytes, so it does the assembly + save.
async function exportViaOffscreen() {
  const video = await finalizeVideo(); // { mic, micError, hasVideo } — NO bytes crossed
  if (video.micError && video.micError !== "mic not requested") {
    logError("offscreen-mic", { message: video.micError });
    // Mic was wanted but didn't record (grant likely revoked) — clear the fast-path
    // flag so the popup re-prompts next time instead of producing silent video again.
    chrome.storage.local.remove("micGrantedOnce").catch(() => {});
  }
  // Normal Finish: frame metadata + HAR are live in worker state, so we build the
  // manifest WITHOUT pulling any frame/video bytes into the worker (the whole point).
  const timeline = await db.readAll("timeline");
  const harEntries = [...state.har.values()];
  const manifest = buildManifest({
    hasVideo: video.hasVideo,
    narrationInVideo: video.mic,
    micError: video.micError,
    segmentOffsets: video.segmentOffsets,
    timeline,
    frameList: state.frames,
    harEntries,
  });
  const meta = metaFiles(manifest, timeline, state.errors);
  const filename = exportFilename();
  const res = await requestOffscreenSave(meta, filename, manifest.t0_wall);
  if (res.ok) {
    await onExportSuccess();
  } else {
    await onExportFailure(manifest, res.reason || "save-failed", filename);
  }
}

// Salvage path (offscreen doc gone, e.g. browser restart): no video pipeline to
// pull from, but the structured capture is safe in IndexedDB. Assemble a video-less
// bundle in the worker and download it. The worker has no URL.createObjectURL, so it
// uses a base64 data: URL — fine here because without the video the bundle is small.
async function salvageExport() {
  const filename = exportFilename();
  let manifest = null;
  try {
    // After a worker restart, state may be empty — source everything from IndexedDB.
    const timeline = await db.readAll("timeline");
    const rrweb = await db.readAll("rrweb");
    const frames = await db.readAll("frames");
    const harEntries = state.har.size ? [...state.har.values()] : await db.readAll("har");
    manifest = buildManifest({
      hasVideo: false,
      narrationInVideo: false,
      micError: "no video context (salvage)",
      segmentOffsets: [],
      timeline,
      frameList: frameMeta(frames),
      harEntries,
    });
    const files = [...metaFiles(manifest, timeline, state.errors), ...streamFiles(timeline, rrweb, frames, harEntries, manifest.t0_wall)];
    const bytes = new Uint8Array(await (await makeZip(files)).arrayBuffer());
    const url = `data:application/zip;base64,${base64FromBytes(bytes)}`;
    await downloadComplete({ url, filename, saveAs: false });
    await onExportSuccess();
  } catch (e) {
    await onExportFailure(manifest || { _filename: filename }, "salvage-download-failed: " + (e?.message || e), filename);
  }
}

// The take saved cleanly — now it's safe to drop it and the recovery snapshot.
async function onExportSuccess() {
  await db.clearAll();
  state.frames = [];
  clearPersistedSession();
  await chrome.storage.local.remove(["unsavedTake", "pendingExport", "lastExportFailed"]).catch(() => {});
  setBadge("");
}

// The save FAILED. Do NOT clear anything — the recording stays in IndexedDB so it can
// be retried or discarded deliberately. Mark it (badge + storage) so the next Start is
// blocked from wiping it and the popup can surface a Retry/Discard banner. `pendingExport`
// carries the already-built manifest so a retry (even after a worker restart) can
// rebuild the bundle from IndexedDB without re-deriving worker state.
async function onExportFailure(manifest, reason, filename) {
  logError("export", { message: `bundle export failed (${reason}) — recording kept for retry` });
  await chrome.storage.local
    .set({
      unsavedTake: true,
      pendingExport: { manifest, filename },
      lastExportFailed: { reason, filename, at: Date.now() },
    })
    .catch(() => {});
  setBadge("!", "#c0392b");
}

// Ask the offscreen doc to assemble (its video Blob + the bulk streams it reads from
// IndexedDB + these small meta files) and download. Resolves { ok, reason }.
function requestOffscreenSave(metaFiles, filename, t0Wall) {
  return new Promise((resolve) => {
    const listener = (msg) => {
      if (msg.type === "offscreen-save-done") {
        chrome.runtime.onMessage.removeListener(listener);
        clearTimeout(timer);
        resolve({ ok: !!msg.ok, reason: msg.reason || null });
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    // sendMessage validates its argument SYNCHRONOUSLY, so an oversized payload
    // throws here rather than rejecting — inside this executor that became an
    // unhandled rejection of the returned promise, and the take was lost with no
    // onExportFailure and no retry state. Resolve a failure instead; the caller
    // then keeps the recording for a retry.
    try {
      chrome.runtime.sendMessage({ type: "offscreen-save", metaFiles, filename, t0Wall }).catch(() => {});
    } catch (e) {
      chrome.runtime.onMessage.removeListener(listener);
      logError("export", { message: "offscreen-save could not be sent: " + (e?.message || e) });
      return resolve({ ok: false, reason: "save-send-failed" });
    }
    // Zipping + writing a large bundle can take a while; allow generously before
    // giving up (a timeout is treated as a failure → the take is kept for retry).
    const timer = setTimeout(() => {
      chrome.runtime.onMessage.removeListener(listener);
      resolve({ ok: false, reason: "offscreen-timeout" });
    }, 120000);
  });
}

// Retry a previously-failed export. The recording is still in IndexedDB; rebuild the
// bundle from the stored manifest + the streams and download it. (The offscreen doc /
// video are typically gone by now, so this produces the structured bundle without
// video — better than losing everything. If video survived, a fresh Finish is better.)
async function retryExport() {
  let pending;
  try {
    ({ pendingExport: pending } = await chrome.storage.local.get("pendingExport"));
  } catch {}
  if (!pending) {
    // Nothing recorded as pending but the flag may be stale — clear it.
    await chrome.storage.local.remove(["unsavedTake", "lastExportFailed"]).catch(() => {});
    setBadge("");
    return { ok: false, error: "Nothing to retry." };
  }
  let { manifest, filename } = pending;
  try {
    // Idempotent finalize preserves already-finalized media in the offscreen doc.
    if (await offscreenExists()) {
      await exportViaOffscreen();
      const { unsavedTake } = await chrome.storage.local.get("unsavedTake");
      return unsavedTake ? { ok: false, error: "Save failed; recording retained." } : { ok: true };
    }
    if (!manifest) {
      await salvageExport();
      const { unsavedTake } = await chrome.storage.local.get("unsavedTake");
      return { ok: !unsavedTake };
    }
    // The media context really is gone: do not promise files that cannot be saved.
    manifest = {
      ...manifest, video: null, video_segments: [], narration_in_video: false,
      narration_error: "media context lost before retry", video_ended_early: true,
    };
    const rrweb = await db.readAll("rrweb");
    const frames = await db.readAll("frames");
    const timeline = await db.readAll("timeline");
    const harEntries = state.har.size ? [...state.har.values()] : await db.readAll("har");
    const files = [...metaFiles(manifest, timeline, state.errors), ...streamFiles(timeline, rrweb, frames, harEntries, manifest.t0_wall)];
    const bytes = new Uint8Array(await (await makeZip(files)).arrayBuffer());
    const url = `data:application/zip;base64,${base64FromBytes(bytes)}`;
    await chrome.downloads.download({ url, filename, saveAs: false });
    await onExportSuccess();
    return { ok: true };
  } catch (e) {
    logError("export-retry", { message: "retry export failed: " + (e?.message || e) });
    setBadge("!", "#c0392b");
    return { ok: false, error: "Retry failed — the recording is still kept." };
  }
}

// Deliberately throw away an unsaved take (the user chose Discard over Retry).
async function discardTake() {
  if (state.recording || state.arming) return { ok: false, error: "Finish or cancel the live take first." };
  generation = crypto.randomUUID();
  await closeOffscreen();
  await db.clearAll();
  state.frames = [];
  clearPersistedSession();
  await chrome.storage.local.remove(["unsavedTake", "pendingExport", "lastExportFailed"]).catch(() => {});
  setBadge("");
  return { ok: true };
}

// ---- overlay controls: pause / resume / restart / cancel -----------------
//
// These are the on-screen overlay's verbs (also reachable from the popup). The
// worker owns the semantics; the offscreen MediaRecorder is told to match so the
// video and the event/network streams pause, restart, and discard together.

// One pause engine. The effective pause is (manual OR auto-on-blocklisted-tab);
// when it flips we pause/resume the MediaRecorder, the frame timer, and the
// event/rrweb intake in lockstep, and book the paused duration into pausedAccum so
// the recording clock excludes it. Manual and auto are independent inputs: leaving
// a blocklisted tab clears the AUTO pause but never overrides a manual one.
function applyPause() {
  if (!state.recording) return;
  const effective = state.manualPaused || state.autoPaused;
  if (effective === state.paused) {
    // No transition, but the REASON may have changed (e.g. user hit Pause while
    // already auto-paused on a blocklisted tab) — keep the overlay copy honest.
    const reason = state.manualPaused ? "manual" : state.autoPaused ? "blocklist" : null;
    if (reason !== state.pauseReason) {
      state.pauseReason = reason;
      broadcastOverlay();
    }
    return;
  }
  state.paused = effective;
  if (effective) {
    state.pauseStartedAt = Date.now(); // start metering paused time
    state.pauseReason = state.manualPaused ? "manual" : "blocklist";
    stopFrameTimer();
    chrome.runtime.sendMessage({ type: "offscreen-pause", clock: overlayClock() }).catch(() => {});
    setBadge("❚❚", "#f39c12"); // amber = paused
    // A blocklist auto-pause happens on a tab with NO overlay (it's uninstrumented),
    // so the on-page pill can't say why. The icon tooltip carries the reason.
    chrome.action.setTitle({
      title: state.autoPaused ? "Paused — on a blocklisted site (not recording)" : "Recording paused",
    });
  } else {
    state.pausedAccum += Date.now() - state.pauseStartedAt; // bank this pause
    state.pauseStartedAt = 0;
    state.pauseReason = null;
    startFrameTimer();
    chrome.runtime.sendMessage({ type: "offscreen-resume", clock: overlayClock() }).catch(() => {});
    setBadge("REC");
    chrome.action.setTitle({ title: "Recording" });
  }
  broadcastOverlay();
  persistSession(); // pause state + accounting must survive a worker restart
}

function pause() {
  if (!state.recording) return;
  state.manualPaused = true;
  applyPause();
}

function resume() {
  if (!state.recording) return;
  state.manualPaused = false;
  applyPause();
}

// Auto-pause when the user is looking at a blocklisted tab, auto-resume when they
// leave. Called on tab switch / window focus / navigation. The active tab of the
// last-focused window is the one the screen video is showing, so that's what
// gates capture.
let pauseCheck = 0;
async function updateAutoPause() {
  const g = generation, check = ++pauseCheck;
  if (!state.recording) return;
  // Unknown window/tab identity cannot safely be inferred from the Start tab.
  let blocked = state.captureSurface === "window" && state.captureWindowId == null;
  try {
    let tabs;
    if (state.captureSurface === "browser") {
      tabs = [await chrome.tabs.get(state.captureTabId)];
    } else if (state.captureSurface === "window" && state.captureWindowId != null) {
      tabs = await chrome.tabs.query({ active: true, windowId: state.captureWindowId });
    } else {
      // Monitor capture can show more than the focused Chrome window. Conservatively
      // pause if any visible Chrome window has an active blocklisted tab.
      tabs = await chrome.tabs.query({ active: true });
      const windows = await chrome.windows.getAll();
      const visible = new Set(windows.filter((w) => w.state !== "minimized").map((w) => w.id));
      tabs = tabs.filter((t) => visible.has(t.windowId));
    }
    blocked ||= tabs.some((t) => t?.url && hostBlocked(t.url));
  } catch {
    blocked = true;
  }
  if (g !== generation || check !== pauseCheck || !state.recording) return;
  if (blocked !== state.autoPaused) {
    state.autoPaused = blocked;
    applyPause();
  }
}

// Restart: throw away everything captured so far and begin a fresh take WITHOUT
// re-prompting the screen picker. The same tabs stay instrumented (their content
// scripts keep recording) and the offscreen doc reuses the live screen/mic
// streams; we just reset t0 and clear the buffers, so the new take is clean.
async function restart() {
  if (!state.recording) return;
  state.arming = true;
  generation = crypto.randomUUID();
  stopFrameTimer();
  await chrome.runtime.sendMessage({ type: "offscreen-pause", clock: overlayClock() }).catch(() => {});
  await db.clearAll();
  state.t0 = Date.now();
  state.paused = false;
  state.manualPaused = false;
  state.autoPaused = false;
  state.pauseReason = null;
  state.pausedAccum = 0; // fresh take → fresh clock, no banked pause time
  state.pauseStartedAt = 0;
  state.har = new Map(); // db.clearAll() above already wiped the frames store
  state.frames = []; // and the frame metadata mirror
  state.errors = [];
  state.videoEndedEarly = false;
  state.awaitingReshare = false; // Restart discards the dead take entirely
  state.videoSegments = []; // new take → fresh segment list
  // Reseed the URL set from the still-instrumented tabs' current pages.
  state.urls = new Set();
  for (const info of state.tabs.values()) if (info.url) state.urls.add(info.url);
  state.stoppedDuration = null;
  state.storageFull = false;
  frameCapLogged = false;
  await commitSession();
  state.arming = false;
  await updateAutoPause();
  await chrome.runtime.sendMessage({ type: "offscreen-restart", clock: overlayClock() }).catch(() => {});
  if (!state.paused) startFrameTimer();
  for (const tabId of state.tabIds)
    await chrome.tabs.sendMessage(tabId, { type: "restart", ...overlayClock() }).catch(() => {});
  await captureFrame("recording restarted");
  setBadge("REC");
  broadcastOverlay(); // new t0 resets every overlay's elapsed clock
  persistSession(); // fresh take → persist the new t0 / cleared accounting
}

// Re-share: the screen share died (Chrome's "Stop sharing" or a closed window)
// and the user clicked Re-share on the overlay. Re-arm the screen picker in the
// offscreen doc — the new video becomes a second segment of the same video.webm,
// the mic stays continuous, and the recording clock does NOT reset (events keep
// their timestamps; the manifest's video_segments declares the gap). Idempotent
// guard: ignore if we're not actually awaiting (e.g. a stale overlay click).
async function reshare() {
  if (!state.recording || !state.awaitingReshare) return;
  // Stamp the recording-clock offset at which this new segment begins. The
  // offscreen doc uses this for the segment it's about to seal; the worker
  // records it in videoSegments on reshare-armed.
  await ensureOffscreen();
  chrome.runtime.sendMessage({ type: "offscreen-reshare", clock: overlayClock() }).catch(() => {});
}

// Re-anchor capture/overlay scope to the currently-active tab after a re-share.
// A re-share may pick a different surface kind (tab vs window vs monitor); the
// tab the user is on now is the proxy for the new share (same heuristic as
// goLive). Pure async so the reshare-armed handler can await it before broadcasting.
async function applyCaptureSurface() {
  const g = generation;
  for (const id of [...state.tabIds]) {
    const tab = await chrome.tabs.get(id).catch(() => null);
    if (!current(g)) return;
    if (!inScope(tab)) await uninstrumentTab(id);
  }
  await updateAutoPause();
  if (state.captureTabId != null) await instrumentTab(state.captureTabId);
}

// Cancel: stop recording and discard — no bundle, no download. Tears down the
// overlay in every tab, detaches debuggers, and drops the in-progress video.
async function cancel() {
  if (!state.recording && !state.arming) return;
  generation = crypto.randomUUID();
  // If we're still arming (picker/countdown), abort it: clearing the flag makes
  // runCountdownThenGo() bail, and we clear any countdown number from the tab.
  if (state.arming && state.activeTabId != null) {
    chrome.tabs.sendMessage(state.activeTabId, { type: "countdown", n: 0 }).catch(() => {});
  }
  state.recording = false;
  state.arming = false;
  state.paused = false;
  state.manualPaused = false;
  state.autoPaused = false;
  state.pauseReason = null;
  state.pauseStartedAt = 0;
  stopFrameTimer();
  for (const tabId of state.tabIds) {
    chrome.tabs.sendMessage(tabId, { type: "stop" }).catch(() => {}); // removes overlay + listeners
    try {
      await withTimeout(chrome.debugger.detach({ tabId }), DEBUGGER_CALL_TIMEOUT_MS, `debugger.detach(${tabId})`);
    } catch {}
  }
  state.tabIds.clear();
  debuggerAlive.clear();
  debuggerRetryAt.clear();
  debuggerAttaching.clear();
  await closeOffscreen(); // also abort a pending picker before a subsequent Start
  await db.clearAll();
  state.frames = [];
  clearPersistedSession(); // nothing to recover — drop the crash-recovery snapshot
  await chrome.storage.local.remove(["unsavedTake", "pendingExport", "lastExportFailed"]).catch(() => {});
  setBadge("");
}

// btoa can't take a Uint8Array and chokes on huge strings, so encode in chunks.
function base64FromBytes(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function setBadge(text, color = "#c0392b") {
  chrome.action.setBadgeText({ text });
  if (text) chrome.action.setBadgeBackgroundColor({ color });
}

// Push the live recording state to every instrumented tab so each tab's overlay
// stays in sync regardless of which one is focused (worker is the source of
// truth). t0 lets each overlay run the same elapsed-time clock.
function broadcastOverlay() {
  const payload = { type: "overlay-state", state: overlayClock() };
  for (const tabId of state.tabIds) chrome.tabs.sendMessage(tabId, payload).catch(() => {});
}

// The clock snapshot every overlay needs to render the same paused-aware elapsed
// time locally: t0 + banked pause time + (if paused) when this pause began. The
// overlay computes elapsed = now - t0 - pausedAccum - ongoingPause, matching now()
// here and the video's own timeline.
function overlayClock() {
  return {
    recording: state.recording && !state.arming,
    generation,
    paused: state.paused,
    pauseReason: state.pauseReason,
    t0: state.t0,
    pausedAccum: state.pausedAccum,
    pauseStartedAt: state.pauseStartedAt,
    micActive: state.micActive, // overlay shows the level meter only when the mic is live
    reshare: !!state.awaitingReshare, // overlay shows Re-share when the screen share died
  };
}

// Follow the user across tabs: instrument any tab that starts loading a real URL
// while we're recording (covers brand-new tabs and navigations to eligible pages),
// re-arm the content script after each navigation, and drop tabs as they close.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // The active tab navigating to/from a blocklisted URL flips the auto-pause (the
  // user typed a sensitive URL into the tab they're already on, or navigated away).
  if (state.recording && changeInfo.url && tab?.active) await updateAutoPause();
  // A tracked tab that navigates INTO a blocklisted host must be torn down — detach
  // the debugger and stop the content script so nothing more is captured there.
  if (state.recording && state.tabIds.has(tabId) && tab?.url && hostBlocked(tab.url)) {
    uninstrumentTab(tabId);
    return;
  }
  const actions = navActions(changeInfo, {
    recording: state.recording,
    eligible: isEligible(tab),
    tracked: state.tabIds.has(tabId),
    active: !!tab?.active,
  });
  // "reattach": a tracked tab finished (re)loading / changed URL — re-arm the
  // content-script capture a navigation tears down. The debugger is left
  // attached. Fix for capture dying after the first navigation on server-
  // rendered apps (see nav-policy.js).
  if (actions.includes("reattach")) reattachTab(tabId, tab);
  // "emitnav": an in-place URL change (SPA pushState/replaceState or a hash change).
  // content.js only emits a nav on popstate, so without this the timeline loses the
  // route change. appendTimeline redacts the URL; reattach already updated the
  // legend/urls set. Grab a frame too, mirroring the click/nav frame trigger.
  if (actions.includes("emitnav") && tab?.url) {
    appendTimeline({ kind: "nav", url: tab.url, tab: tabId });
    captureFrame("nav");
  }
  // "instrument": the active tab finished loading and isn't tracked yet (e.g. the
  // recording tab navigated off a chrome:// page). Tabs the user switches into
  // are instrumented in onActivated below.
  if (actions.includes("instrument")) instrumentTab(tabId);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  if (state.recording) uninstrumentTab(tabId);
});
// Lazily instrument the tab the user switches INTO — this is how capture follows
// them across tabs while leaving untouched tabs alone. Also grab a frame:
// captureVisibleTab shoots the active tab, so we get a shot of the tab they just
// moved to (the periodic timer would otherwise miss the switch instant).
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  if (!state.recording) return;
  // Switching INTO a blocklisted tab auto-pauses everything (and out auto-resumes)
  // BEFORE we instrument or shoot a frame, so nothing from it is captured.
  const g = generation;
  await updateAutoPause();
  if (!current(g)) return;
  await instrumentTab(tabId);
  if (!accepting(g)) return;
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!accepting(g) || !isEligible(tab) || !inScope(tab)) return;
  appendTimeline({ kind: "tab-activated", tab: tabId });
  captureFrame("tab-activated");
});
// Switching browser windows (or to a window whose active tab is blocklisted) must
// re-evaluate the auto-pause too — the screen video follows the focused window.
chrome.windows.onFocusChanged.addListener(() => {
  if (state.recording) updateAutoPause();
});

// ---- frames --------------------------------------------------------------

// Grab a screenshot on a fixed cadence (not only on clicks/navs). Frame capture
// used to be triggered solely by content-script events, so when the content
// script died on a navigation the visual record died with it — leaving the
// "interesting" later states (error toasts, filtered views) with no frames even
// though the page was plainly visible. A timer makes visual coverage independent
// of the DOM event stream. The full-screen video is still the ground truth; this
// keeps the timeline navigable. 3s × ~6 min ≈ 120 frames ≈ ~16 MB (PNG).
const FRAME_INTERVAL_MS = 3000;
// Sanity ceiling on frame count. At 3s/frame this is ~5 hours of recording; frames
// are the biggest IndexedDB consumer (~130 KB PNG each), so this bounds runaway disk
// use on a forgotten-running capture. The full-screen video is still the ground
// truth past this point — we just stop minting new screenshots and say so once.
const FRAME_CAP = 6000;
let frameTimer = null;
let frameCapLogged = false;

function startFrameTimer() {
  stopFrameTimer();
  frameTimer = setInterval(() => captureFrame("interval"), FRAME_INTERVAL_MS);
}
function stopFrameTimer() {
  if (frameTimer) clearInterval(frameTimer);
  frameTimer = null;
}

async function captureFrame(reason = "") {
  const g = generation;
  if (!accepting(g)) return;
  if (state.frames.length >= FRAME_CAP) {
    if (!frameCapLogged) {
      frameCapLogged = true;
      logError("frame-cap", { message: `frame cap (${FRAME_CAP}) reached — relying on video.webm for the rest; structured capture continues` });
    }
    return;
  }
  // Two separate operations live here — the screenshot and the IndexedDB write — and
  // they fail for DIFFERENT reasons, so they get SEPARATE try blocks. Folding them
  // together is the bug this split fixes: captureVisibleTab's ~2/sec rate-limit error
  // ("...MAX_CAPTURE_VISIBLE_TAB_CALLS_PER_SECOND quota.") used to fall into the same
  // catch as the IDB write and route through noteWriteFailure, which misread its
  // "quota" wording as a full disk — a self-healing throttle tripping the fatal
  // truncation alarm. The screenshot failure must NOT reach noteWriteFailure.
  let dataUrl;
  try {
    // captureVisibleTab shoots the active tab of the focused window. Only shoot the
    // surface we're recording: skip a focused tab/window outside the captured scope
    // (e.g. a window share while another window is focused — its frame wouldn't match
    // video.webm), and skip a blocklisted host the user switched into.
    const [active] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!accepting(g) || !isEligible(active) || !inScope(active)) return;
    dataUrl = await chrome.tabs.captureVisibleTab(active.windowId, { format: "png" });
    const [after] = await chrome.tabs.query({ active: true, windowId: active.windowId });
    if (!accepting(g) || after?.id !== active.id || !isEligible(after) || !inScope(after)) return;
  } catch (e) {
    // captureVisibleTab can fail on chrome:// pages etc., or hit Chrome's ~2/sec rate
    // limit when an event frame lands next to a timer frame — both non-fatal and
    // self-healing. No storage was touched, so this is NEVER a storage-full case;
    // swallow it (the full-screen video stays the ground truth for these moments).
    console.debug("frame capture skipped:", reason, e?.message);
    return;
  }
  const t = now();
  const file = `frames/${String(t).padStart(10, "0")}.png`;
  try {
    // Frames are written straight to IndexedDB (not held in worker memory): a
    // 30-min capture is hundreds of PNGs, and — more importantly — if the worker is
    // ever torn down, in-memory frames would vanish. IDB survives a worker restart.
    await db.append("frames", { t, file, dataUrl });
    if (current(g)) state.frames.push({ t, file }); // only committed, current-generation frames
  } catch (e) {
    // A STORAGE QuotaExceededError here means IndexedDB is full and the whole capture
    // is now silently truncating — surface that loudly (noteWriteFailure classifies it).
    noteWriteFailure("frame-write", e);
    console.debug("frame write skipped:", reason, e?.message);
  }
}

// ---- network (CDP -> HAR) ------------------------------------------------

// Response-body capture caps (D1). Bodies land in network.har + the pack's API table,
// so they're bounded: keep up to RESP_BODY_CAP of a (redacted) body; above
// RESP_BODY_HARD_MAX omit it entirely rather than spend CPU/memory redacting a huge
// payload just to truncate it.
const RESP_BODY_CAP = 32 * 1024;
const RESP_BODY_HARD_MAX = 1024 * 1024;

// If the CDP session drops mid-recording — the "being debugged" infobar dismissed,
// another DevTools client taking the tab, a renderer crash/process swap — this is
// the ONLY signal we get. Without it, onEvent just stops firing for that tab: no
// exception, nothing in errors.json, HAR silently goes dead for the rest of the
// recording while video/frames/rrweb keep going fine. Log it and re-attach so
// capture self-heals instead of degrading invisibly.
chrome.debugger.onDetach.addListener((source, reason) => {
  const tabId = source.tabId;
  if (tabId == null || !state.tabIds.has(tabId)) return;
  debuggerAlive.delete(tabId);
  logError("debugger", { message: `debugger detached from tab ${tabId}: ${reason || "unknown reason"}` });
  if (!state.recording) return;
  // Don't drop the tab from state.tabIds here — it stays "tracked" (video/frames/
  // rrweb for it keep going); only the debugger session is down. Retry now
  // (cooldown + dedup guarded above), and reattachTab() will retry again on the
  // tab's next navigation if this attempt lands inside the cooldown window.
  ensureDebuggerAttached(tabId);
});

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  // Pause suspends ALL capture, network included. Without the `state.paused` guard the
  // tracked tabs' requests kept landing in network.har while the user had stepped
  // off-record during a pause (a privacy leak), and that network-without-content
  // signature also tripped check_coverage's false CAPTURE GAP warning. Now network
  // stops in lockstep with events/frames/rrweb when paused.
  const g = generation;
  if (!accepting(g) || !state.tabIds.has(source.tabId)) return;
  const requestKey = JSON.stringify([source.tabId, source.sessionId || "", params.requestId]);

  if (method === "Network.requestWillBeSent") {
    const { request, requestId, timestamp } = params;
    if (hostBlocked(request.url)) return;
    const reqUrl = redactUrl(request.url); // host/path intact; only secrets in the query masked
    state.urls.add(reqUrl);
    const entry = {
      requestId: requestKey, // target/session-scoped IDB key; stripped on export
      _tab: source.tabId,
      _t: now(),
      startedDateTime: new Date().toISOString(),
      _start: timestamp,
      // CDP timestamps are WALL clock, but the bundle's one clock (recordingElapsed
      // in clock.js) EXCLUDES paused time. Computing entry.time later as
      // (responseTs - _start) counted paused wall-time as request latency — a
      // request spanning a pause reported minutes of "latency" that the video-
      // aligned clock disagrees with (SYNTHESIS bug #2). Freeze the one-clock
      // reading at request start here, and measure duration on the SAME clock at
      // responseReceived/loadingFinished, so pause time never inflates entry.time.
      _t0Clock: now(),
      request: {
        method: request.method,
        url: reqUrl,
        headers: redactHeaders(toHeaderArray(request.headers)),
        postData: request.postData
          ? { mimeType: "application/json", text: redactBody(request.postData) }
          : undefined,
      },
      response: {},
      // Same-SITE check for D1 response-body capture: documentURL is the initiating
      // page, so this is accurate per-request (api.foo.com under app.foo.com = true,
      // a third party = false). `_`-prefixed → stripped from the exported HAR.
      _sameSite: isSameSite(request.url, params.documentURL),
    };
    state.har.set(requestKey, entry);
    db.put("har", entry).catch((e) => noteWriteFailure("har-write", e)); // mirror to IDB so network survives a worker restart
  }

  if (method === "Network.responseReceived") {
    const entry = state.har.get(requestKey);
    if (!entry) return;
    const r = params.response;
    entry.response = {
      status: r.status,
      statusText: r.statusText,
      headers: redactHeaders(toHeaderArray(r.headers)),
      content: { mimeType: r.mimeType },
    };
    // One-clock duration: never (wallTs - _start), which counts paused time
    // (the CDP clock and the recording clock diverge by pausedAccum). Using the
    // frozen _t0Clock reading keeps entry.time consistent with the video clock.
    entry.time = Math.max(0, Math.round(now() - (entry._t0Clock ?? entry._t ?? 0)));
    // Only same-site JSON responses get their body fetched on loadingFinished — the
    // app's own API data model, not third-party/HTML/binary. (`_`-prefixed → stripped.)
    entry._wantBody = entry._sameSite && isJsonMime(r.mimeType);
    db.put("har", entry).catch((e) => noteWriteFailure("har-write", e)); // upsert the now-complete entry
    // Also surface the request as a timeline event for the merged view.
    appendTimeline({
      kind: "network",
      method: entry.request.method,
      url: entry.request.url,
      status: r.status,
      ms: entry.time,
      tab: entry._tab,
    });
  }

  // loadingFinished is the canonical point at which the response body is retrievable
  // (D1). Fetch it only for the same-site JSON we flagged, redact it through the same
  // redactBody() used for request bodies, then size-cap. Redact BEFORE capping so the
  // JSON-aware field-name redaction runs on valid JSON (capping first would break the
  // parse and silently fall back to the weaker regex path). getResponseBody legitimately
  // fails for 304s / redirects / cached / streamed responses — swallow it and leave the
  // body unset (the pack renders "—").
  if (method === "Network.loadingFinished") {
    const entry = state.har.get(requestKey);
    if (!entry || !entry._wantBody) return;
    try {
      const { body, base64Encoded } = await chrome.debugger.sendCommand(
        source,
        "Network.getResponseBody",
        { requestId: params.requestId }
      );
      if (!accepting(g) || state.har.get(requestKey) !== entry || base64Encoded) return;
      entry.response.content =
        entry.response.content && typeof entry.response.content === "object"
          ? entry.response.content
          : {};
      entry.response.content.size = body.length;
      entry.response.content.text =
        body.length > RESP_BODY_HARD_MAX
          ? `‹response body omitted: ${body.length} bytes›`
          : capResponseBody(redactBody(body), RESP_BODY_CAP);
      db.put("har", entry).catch((e) => noteWriteFailure("har-write", e));
    } catch {
      /* body evicted / 304 / redirect — leave content.text unset */
    }
  }
});

function toHeaderArray(headers = {}) {
  return Object.entries(headers).map(([name, value]) => ({ name, value: String(value) }));
}

// Token-scrub a serialized rrweb node (DOM snapshot or mutation). Stringify →
// scrubTokens → parse catches a JWT/bearer anywhere in the tree (img src, href,
// inline text), where a per-field rule wouldn't reach. If (de)serialization
// fails, the node is DROPPED — never returned raw: the pre-v2 fallback could
// persist an unredacted node (with an embedded secret) into events.jsonl, which
// is the exact leak this chokepoint exists to prevent. One lost node of DOM
// diff is a recoverable rendering gap; a leaked token is not.
function scrubNode(node) {
  try {
    return JSON.parse(scrubTokens(JSON.stringify(node)));
  } catch {
    return { rrweb: "‹node dropped: scrub failed›" };
  }
}

// ---- timeline + rrweb from content script --------------------------------

async function appendTimeline(event) {
  if (!accepting(generation)) return;
  // Single chokepoint: any event carrying a URL gets it scrubbed before disk, so a
  // token in a query string can't ride into the timeline (nav + network events).
  if (event.url) event = { ...event, url: redactUrl(event.url) };
  // describe() copies a link's raw href + an aria-labelledby–derived name/section
  // into ctx — any of which can carry a token. Scrub all three at this one
  // chokepoint, else a secret in an <a href="…?token=…"> or a labelledby-referenced
  // node leaks into timeline.json. (content.js also drops ctx.name on secret inputs.)
  if (event.ctx) event = { ...event, ctx: redactCtx(event.ctx) };
  // Guard the write: an IndexedDB quota failure here would otherwise throw up into
  // whatever message handler called us. Swallow it like the other write sites, but
  // surface a quota exhaustion (capture is truncating) instead of dropping silently.
  try {
    await db.append("timeline", { ...event, t: now() });
  } catch (e) {
    noteWriteFailure("timeline-write", e);
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Offscreen pages only have chrome.runtime. The worker owns downloads and
  // acknowledges completion, while the Blob URL remains alive in its creator.
  if (msg.type === "download-blob") {
    if (sender.url !== chrome.runtime.getURL("src/offscreen.html")) return;
    if (typeof msg.url !== "string" || !msg.url.startsWith(`blob:${chrome.runtime.getURL("")}`)) {
      sendResponse({ ok: false, reason: "invalid Blob origin" });
      return;
    }
    downloadComplete({ url: msg.url, filename: msg.filename, saveAs: false })
      .then(() => sendResponse({ ok: true }),
            (e) => sendResponse({ ok: false, reason: e?.message || String(e) }));
    return true;
  }
  if (msg.type === "media-clock") {
    sendResponse(overlayClock());
    return;
  }
  if (msg.type === "timeline-event" || msg.type === "rrweb-event") {
    if (!accepting(generation) || msg.generation !== generation ||
        !state.tabIds.has(sender.tab?.id) || hostBlocked(sender.tab?.url || "")) return;
  }
  if (msg.type === "is-recording") {
    // A content script asking on load whether it should be capturing. Answer
    // PER TAB: only tabs we've instrumented (the recording tab + ones the user
    // has entered) record. A tab the user never switched into stays inert — so
    // we don't snapshot the DOM of a password-manager / chat tab just because
    // it was open. paused + t0 ride along for the overlay clock.
    const tabId = sender.tab?.id;
    const tracked = tabId != null && state.tabIds.has(tabId);
    sendResponse({ ...overlayClock(), recording: current(generation) && tracked });
    return true;
  }
  if (msg.type === "timeline-event") {
    // Tag every event with its source tab so the merged one-clock timeline stays
    // disambiguable across tabs. The content script doesn't know its own tabId;
    // the worker reads it from the message sender.
    const tabId = sender.tab?.id;
    const e = { ...msg.event, tab: tabId };
    appendTimeline(e);
    if (e.kind === "nav" && tabId != null) {
      const navUrl = redactUrl(e.url);
      state.urls.add(navUrl);
      const info = state.tabs.get(tabId);
      if (info) info.url = navUrl; // keep the tab legend current as the user navigates
    }
    // Grab a frame at the precise moment of a click, navigation, or annotation.
    // For annotations the frame is the point — it captures the screen with the
    // user's drawn highlight / selected-element box still painted on it, so the
    // analyst sees exactly what was marked. The periodic frame timer covers
    // everything in between (including idle dwell), so we no longer take a frame on
    // every hover — that just competed with the timer for Chrome's ~2/sec
    // captureVisibleTab quota.
    if (e.kind === "click" || e.kind === "nav" || e.kind === "annotation:select" || e.kind === "annotation:draw") {
      captureFrame(e.kind);
    }
  }
  if (msg.type === "rrweb-event") {
    // rrweb serializes the live DOM — including attribute values like <img src> and
    // <a href> that can carry a token in their query string (?jwt=…). That stream
    // (events.jsonl) bypasses the URL/body scrubbers, so scrub the whole serialized
    // node for token shapes here. Same net as redactBody; lockstep with the
    // validator's TOKEN_RE.
    if (state.recording && !state.paused)
      db.append("rrweb", { t: now(), node: scrubNode(msg.node), tab: sender.tab?.id }).catch((e) => noteWriteFailure("rrweb-write", e));
  }
  if (msg.type === "capture-error") {
    logError(msg.where || "unknown", { message: msg.message, stack: msg.stack });
  }
  // Heartbeat from the offscreen document so the MV3 service worker isn't torn down
  // mid-recording (especially while paused, when nothing else wakes it). Receiving
  // the message is the point — it resets the worker's idle timer; no work needed.
  if (msg.type === "keepalive") {
    return; // handled — keeps the worker warm
  }
  // The captured screen/window share ended on its own (user closed the window or hit
  // Chrome's "Stop sharing"). Record it; the rest of the capture (events, mic) keeps
  // going, but the manifest should reflect that video stopped early. Surface a
  // Re-share button on the overlay so the user can recover by picking a new screen
  // — the new video becomes a second segment of the same video.webm.
  if (msg.type === "video-track-ended") {
    state.videoEndedEarly = true;
    state.awaitingReshare = true;
    logError("offscreen-video", { message: "screen share ended mid-recording — Re-share available" });
    broadcastOverlay(); // overlay shows the Re-share button
  }
  // The offscreen doc's reshare picker failed or was cancelled. Stay in the
  // awaiting state so the user can try Re-share again; don't fail the recording.
  if (msg.type === "reshare-failed") {
    logError("offscreen-video", { message: "re-share picker failed or cancelled — video remains stopped, Re-share still available" });
    // awaitingReshare stays true; the overlay keeps the button armed.
  }
  // The offscreen doc's reshare succeeded: a fresh video track is live and a new
  // recorder segment has started. Clear the awaiting state, record the segment's
  // start offset (the worker passed it to offscreen-reshare so it's on the
  // recording clock), and update the capture surface in case the user picked a
  // different window/tab this time.
  if (msg.type === "reshare-armed") {
    state.awaitingReshare = false;
    state.videoEndedEarly = false; // video is live again — the take no longer ends early
    state.videoSegments.push({ offsetMs: msg.offsetMs || 0 });
    if (msg.surface) state.captureSurface = msg.surface;
    state.captureTabId = Number.isInteger(msg.tabId) ? msg.tabId : null;
    state.captureWindowId = null;
    // Re-scope capture/overlay to the new shared surface. A re-share may have
    // picked a different surface kind (tab vs window vs monitor); update the
    // scope anchors so capture/overlay match the new video. The onMessage
    // listener is NOT async (it can't be — it returns true selectively for
    // sendResponse paths), so fire-and-forget the async scope update and
    // broadcast once it's done.
    applyCaptureSurface().then(() => broadcastOverlay());
    return;
  }
  // The microphone track ended mid-recording (revoked / unplugged). Narration is
  // truncated from here; drop the level meter and flag the bundle so the analyst
  // knows the transcript stops short of the video.
  if (msg.type === "mic-track-ended") {
    state.micActive = false;
    state.micEndedEarly = true;
    logError("offscreen-mic", { message: "microphone ended mid-recording — narration truncated" });
    broadcastOverlay();
  }
  // The offscreen doc finished the screen picker (the user picked, or cancelled →
  // video:false). Run the countdown, then go live. Sent once per recording.
  if (msg.type === "offscreen-armed") {
    // Whether the mic track is actually live — set before goLive() sends the first
    // overlay clock, so each overlay knows to show (or hide) the level meter.
    state.micActive = !!msg.mic;
    // Mic was wanted but getUserMedia failed at arm time (stale grant, revoked,
    // OS-blocked). Log NOW so errors.json shows it even if the take is never
    // exported, and clear the grant flag so the next Start re-prompts instead of
    // silently producing another video-only take. Non-fatal: recording proceeds.
    if (!msg.mic && msg.micError && msg.micError !== "mic not requested") {
      logError("offscreen-mic", { message: `microphone not captured — recording is video-only (${msg.micError})` });
      chrome.storage.local.remove("micGrantedOnce").catch(() => {});
    }
    // What surface the user shared (tab/window/monitor) — set before goLive() so the
    // first tab is scoped correctly.
    if (!state.arming) return;
    state.captureSurface = msg.surface || null;
    state.captureTabId = Number.isInteger(msg.tabId) ? msg.tabId : null;
    state.captureWindowId = null;
    if (state.captureSurface === "window")
      logError("capture-scope", { message: "Chrome does not expose the picked OS-window identity; capture remains paused rather than recording the Start window by guess." });
    runCountdownThenGo();
  }
  // Live microphone loudness from the offscreen recorder (~12/sec). Fan it out to
  // every instrumented overlay so the focused tab's meter moves as the user talks.
  // Tiny payload; only while recording. Dropped if the mic isn't live.
  if (msg.type === "mic-level") {
    if (state.recording && state.micActive) {
      const payload = { type: "mic-level", level: msg.level };
      for (const tabId of state.tabIds) chrome.tabs.sendMessage(tabId, payload).catch(() => {});
    }
  }
  // Both the popup and the injected on-screen overlay drive the same verbs. Each
  // waits on `rehydrated` so a command that woke the worker isn't run against a
  // half-restored state — e.g. the first Pause after a crash recovery would
  // otherwise see recording=false and be dropped, and a Start would slip past the
  // "already recording" guard and wipe the recovered take.
  if (msg.type === "popup-command" || msg.type === "overlay-command") {
    const c = msg.command;
    if (c === "status") {
      rehydrated.then(() => sendResponse({
        recording: state.recording, paused: state.paused, arming: state.arming,
      }));
      return true;
    }
    const verbs = {
      start: () => start(msg.tabId, msg.task, msg.purposes),
      stop, finish: stop, pause, resume, restart, cancel, reshare,
      "retry-export": retryExport, "discard-take": discardTake,
    };
    if (!verbs[c]) {
      sendResponse({ ok: false, error: "Unknown command" });
      return;
    }
    command(verbs[c]).then(
      (result) => sendResponse(result ?? { ok: true }),
      (e) => sendResponse({ ok: false, error: e?.message || String(e) })
    );
    return true;
  }
});

// ---- offscreen video -----------------------------------------------------

// Tear down the offscreen doc (and with it any live screen/mic stream). Used at the
// start of a recording to clear an orphan left by a worker that was killed mid-arming
// — MV3 workers are ephemeral, and a stuck getDisplayMedia keeps the "sharing your
// screen" indicator lit with no way to stop it.
async function closeOffscreen() {
  try {
    if (await chrome.offscreen.hasDocument?.()) await chrome.offscreen.closeDocument();
  } catch {}
}

async function ensureOffscreen() {
  const has = await chrome.offscreen.hasDocument?.();
  if (has) return;
  await chrome.offscreen.createDocument({
    url: "src/offscreen.html",
    // DISPLAY_MEDIA lets the offscreen doc call getDisplayMedia() (screen) without a
    // user gesture; USER_MEDIA covers the separate microphone getUserMedia() stream.
    reasons: ["DISPLAY_MEDIA", "USER_MEDIA"],
    justification: "Record the chosen screen/window and the user's microphone narration via MediaRecorder.",
  });
}

// Kicks off whole-screen video. The offscreen document does the actual work: it
// calls getDisplayMedia() itself (Chrome's recommended MV3 path — a desktopCapture
// streamId minted in the worker is NOT consumable in offscreen). The screen
// picker therefore appears asynchronously inside offscreen,
// so we can't know here whether the user picked or cancelled — the real outcome
// (a video.webm, or none) is reported back at stop time and recorded in the
// manifest. Returns true to mean "video was attempted".
async function startVideo(withMic) {
  try {
    // Capture Handle is opt-in and only supported for browser-tab shares.
    // Do not guess identity when unavailable. This isolated-world configuration
    // is best-effort; unsupported pages remain out of structured-capture scope.
    const origin = chrome.runtime.getURL("").replace(/\/$/, "");
    for (const tab of await chrome.tabs.query({})) {
      if (!isEligible(tab)) continue;
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (handle, permittedOrigin) => {
          navigator.mediaDevices?.setCaptureHandleConfig?.({
            handle, exposeOrigin: true, permittedOrigins: [permittedOrigin],
          });
        },
        args: [`bac-tab:${tab.id}`, origin],
      }).catch(() => {});
    }
    await ensureOffscreen();
    chrome.runtime.sendMessage({ type: "offscreen-start", withMic })
      .catch((e) => logError("video", { message: "offscreen never got the start message: " + (e?.message || e) }));
    return true;
  } catch (e) {
    logError("video", { message: "video capture unavailable: " + (e?.message || e), stack: e?.stack });
    return false;
  }
}

// Stop the recorder and finalize the video Blob INSIDE the offscreen document — the
// bytes stay there (it'll zip + save them). Resolves with only the small status the
// worker needs for the manifest: { mic, micError, hasVideo, segmentOffsets }. No
// video bytes cross the message boundary (that handoff is exactly what the 64MiB
// cap broke). segmentOffsets is the list of recording-clock offsets (ms since t0)
// at which each video segment's recorder started — empty for a normal single-take
// recording, one entry per re-share. The manifest uses these to declare the gaps.
function finalizeVideo() {
  return new Promise((resolve) => {
    const listener = (msg) => {
      if (msg.type === "offscreen-finalized") {
        chrome.runtime.onMessage.removeListener(listener);
        clearTimeout(timer);
        resolve({
          mic: !!msg.mic,
          micError: msg.micError || null,
          hasVideo: !!msg.hasVideo,
          segmentOffsets: Array.isArray(msg.segmentOffsets) ? msg.segmentOffsets : [],
        });
      }
    };
    chrome.runtime.onMessage.addListener(listener);
    chrome.runtime.sendMessage({ type: "offscreen-finalize" }).catch(() => {});
    // Don't hang export if the offscreen doc never answers (proceed video-less).
    const timer = setTimeout(() => resolve({ mic: false, micError: "offscreen timed out", hasVideo: false, segmentOffsets: [] }), 8000);
  });
}

// ---- bundle assembly -----------------------------------------------------
//
// Assembly is split so the heavy streams never touch the worker on a normal Finish:
//   • buildManifest + metaFiles (here) produce the SMALL text files (manifest.json,
//     network.har, transcript, errors, README/CLAUDE/AGENTS) from worker state.
//   • the BULK files (timeline.json, events.jsonl, frames/*.png, video.webm) are
//     added by the offscreen doc from IndexedDB + its video Blob (bundle-streams.js).
// Inputs are passed in explicitly so the normal path can source frame metadata + HAR
// from worker state (no byte loads) while salvage/retry source them from IndexedDB.

function buildManifest({ hasVideo, narrationInVideo, micError, segmentOffsets, timeline, frameList, harEntries }) {
  const duration = state.stoppedDuration ?? now();
  return {
    bundle_version: "0.2",
    capture_id: `capture-${new Date(state.t0).toISOString()}`,
    t0_wall: new Date(state.t0).toISOString(),
    duration_ms: duration,
    sync_mode: "self_record",
    // The user's stated goal for this recording — the single best anchor for intent.
    task: state.task || null,
    // Why they recorded (skill / docs / ux / improve / general) — steers the analysis.
    purposes: state.purposes || [],
    // v2: video is a full screen/window recording that spans every tab; events
    // carry a `tab` id and this legend maps each id to its page.
    capture_scope: "all_tabs",
    // What the user shared in the picker ("browser" = one tab | "window" | "monitor").
    // Capture + overlay are scoped to this surface, so `tabs` lists only its tabs.
    capture_surface: state.captureSurface || null,
    tabs: [...state.tabs.values()],
    video: hasVideo ? "video.webm" : null,
    // True if the screen share stopped on its own before the user finished (closed
    // the shared window / hit "Stop sharing") AND was never re-shared — video.webm
    // ends early but the rest of the capture (events, network, mic) ran to the
    // end. If the user clicked Re-share and a later segment is live, this is
    // false; the gaps are described by `video_segments` instead. See errors.json.
    video_ended_early: !!state.videoEndedEarly,
    // The video segments that make up video.webm, with the recording-clock offset
    // (ms since t0) at which each segment's recorder started. Empty for a normal
    // single-take recording; one entry per re-share. Segment N+1's offset minus
    // segment N's offset is NOT contiguous video — the gap between them is the
    // period where the screen share was dead and the user hadn't yet re-shared
    // (events/network/mic still captured during the gap, video is missing). The
    // analyze side uses these offsets to flag the gaps and map events to segments.
    // NB: the offscreen doc already returns manifest-shaped [{offset_ms}] via
    // segmentOffsetsFor() — pass through directly, do NOT re-wrap.
    video_segments: Array.isArray(segmentOffsets) ? segmentOffsets : [],
    // True if IndexedDB hit its quota mid-recording — the structured streams
    // (timeline/events/frames/network) are TRUNCATED past that point. The video may
    // still be complete (it's held in the offscreen doc, not IDB). See errors.json.
    storage_full: !!state.storageFull,
    // Whether video.webm contains the user's microphone narration (mixed in on
    // the same clock). If true, transcribing video.webm yields t0-aligned cues.
    narration_in_video: hasVideo ? !!narrationInVideo : false,
    // When narration is absent, why — so the bundle self-diagnoses instead of the
    // reason being trapped in the offscreen document's console. null if narration
    // recorded fine.
    narration_error: narrationInVideo ? null : (micError || null),
    // True if the mic was recording but its track ended before the user finished —
    // narration exists but is TRUNCATED (transcript stops short of the video). See errors.json.
    narration_truncated: !!state.micEndedEarly,
    transcript: "transcript.vtt",
    browser: { name: "Chrome", version: navigator.userAgent.match(/Chrome\/([\d.]+)/)?.[1] || "?" },
    tool_versions: { extension: "0.2.0", rrweb: "2.0.0" },
    urls_visited: [...state.urls],
    redaction: {
      policy: "mask_secrets_and_auth",
      password_fields_masked: true,
      redacted_headers: ["Authorization", "Cookie", "Set-Cookie"],
      redacted_value_token: "‹redacted›",
      // network.har now carries response bodies, but only for same-site JSON
      // (the recorded app's own API), redacted like request bodies and size-capped.
      response_bodies: "same_site_json, redacted, capped 32KiB",
      // Redaction covers the STRUCTURED streams (timeline, network.har, DOM, URLs),
      // not the pixels: a secret visible on screen is visible in video.webm/frames.
      visual_streams_redacted: false,
    },
    frames: (frameList || []).map((f) => ({ t: f.t, file: f.file })),
    counts: {
      events: timeline.length,
      network: harEntries.length,
      frames: (frameList || []).length,
      errors: state.errors.length,
    },
  };
}

// The small, worker-built bundle files (everything except the bulk streams + video).
// Everything here is BOUNDED — it all crosses a chrome.runtime message to the
// offscreen doc, which is hard-capped at 64MiB. network.har is not bounded (one
// entry per request, for as long as the take runs), so it lives in streamFiles()
// and is read from IndexedDB on the far side instead. Keep it that way.
function metaFiles(manifest, timeline, errors) {
  return [
    { name: "manifest.json", data: JSON.stringify(manifest, null, 2) },
    { name: "transcript.vtt", data: buildTranscript(timeline, manifest.duration_ms) },
    { name: "errors.json", data: JSON.stringify(errors || [], null, 2) },
    { name: "README.md", data: bundleReadme(manifest) },
    // Self-driving instructions: the bundle alone is enough to analyze, with no
    // external pipeline. CLAUDE.md and AGENTS.md carry the same guidance for
    // Claude agents and the cross-agent AGENTS.md convention respectively.
    { name: "CLAUDE.md", data: bundleClaudeMd(manifest) },
    { name: "AGENTS.md", data: bundleAgentsMd(manifest) },
    // The documentation skill travels in every zip so an agent handed only the bundle
    // can produce illustrated docs (screenshots + highlights) with no external pipeline.
    { name: "agent-skills/documentation/SKILL.md", data: documentationSkill() },
  ];
}

// The extension captures narration timing as `speech` timeline events if a
// transcriber feeds them in; absent that, emit a stub the user replaces with a
// real transcript (Whisper, etc.). See README.
function buildTranscript(timeline, duration = state.stoppedDuration ?? now()) {
  const cues = timeline.filter((e) => e.kind === "speech");
  if (!cues.length)
    return (
      "WEBVTT\n\nNOTE No narration captured in this stream. The spoken audio is an Opus " +
      "track in video.webm (aligned to t0). To recover it WITHOUT this repo, see " +
      "CLAUDE.md / AGENTS.md in this bundle — they give the self-contained steps " +
      "(ffmpeg extract + a local ASR model). If you DO have the repo, " +
      "`python analyze/pack.py <bundle>` (or analyze/transcribe.py <bundle>) in the .venv " +
      "fills this automatically (one-time setup: install.sh / install.ps1).\n"
    );
  const fmt = (t) => {
    const s = Math.floor(t / 1000);
    return `${String(Math.floor(s / 3600)).padStart(2, "0")}:${String(Math.floor(s / 60) % 60).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}.${String(Math.floor(t) % 1000).padStart(3, "0")}`;
  };
  let out = "WEBVTT\n\n";
  cues.forEach((c, i) => {
    const next = Math.min(cues[i + 1]?.t ?? duration, duration);
    if (next > c.t) out += `${fmt(c.t)} --> ${fmt(next)}\n${c.text}\n\n`;
  });
  return out;
}

// bundleReadme, bundleClaudeMd, bundleAgentsMd are imported from ./bundle-docs.js
// (pure manifest→markdown functions, unit-tested in tests/test_bundle_docs.mjs).

// On every worker cold start, recover a recording that was live when a previous
// worker instance died (see rehydrate()). A no-op when nothing was recording.
rehydrate();
