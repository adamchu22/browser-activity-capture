// Content script: runs in the page, owns in-page capture.
//
//  - rrweb records the full DOM mutation stream (raw, → events.jsonl)
//  - DOM listeners produce the high-level timeline events (click/input/key/nav)
//  - password/secret fields are masked HERE, before the value ever leaves the page
//
// Timestamps are page-local (performance-based) but every event is stamped by
// the background worker on arrival against the one master clock (t0), so all
// modalities share a single timeline. See docs/02-design.md ("one clock").
//
// NOTE: content scripts are classic scripts, so the small redaction helpers
// below mirror src/redact.js (the canonical version used by the worker). Keep
// them in sync.

(() => {
  // The manifest injects this script on every page load AND the worker may
  // inject it on demand (for a tab opened before the extension loaded). Guard
  // against a second copy attaching a duplicate set of listeners — that's what
  // made every click/hover/nav fire twice. Same isolated world per tab, so this
  // window flag is shared across both injection paths.
  if (window.__bacContentLoaded) return;
  window.__bacContentLoaded = true;

  const SECRET_KEY_RE = /pass(word)?|secret|token|api[-_]?key|auth|ssn|card|cvv/i;
  const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  // Mirrors redact.js TOKEN_VALUE_RE — redact a JWT/bearer by value shape even
  // when it sits in a field whose name looks innocent.
  const TOKEN_VALUE_RE = new RegExp(
    [
      "eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}(?:\\.[A-Za-z0-9_-]+)?",
      "Bearer(?:\\s|%20|\\+)+[A-Za-z0-9._-]{12,}",
      "(?:AKIA|ASIA)[A-Z0-9]{16}",
      "[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
      "gh[posu]_[A-Za-z0-9]{36,}",
      "github_pat_[A-Za-z0-9_]{40,}",
      "AIza[A-Za-z0-9_-]{35}",
      "ya29\\.[A-Za-z0-9_-]{20,}",
      "xox[baprs]-[A-Za-z0-9-]{10,}",
      "sk-ant-[A-Za-z0-9_-]{20,}",
      "sk-[A-Za-z0-9]{32,}",
      "-----BEGIN(?:[A-Z ]+)?PRIVATE KEY-----[\\s\\S]*?-----END[A-Z ]*PRIVATE KEY-----",
      "-----BEGIN(?:[A-Z ]+)?PRIVATE KEY-----[\\s\\S]*",
    ].join("|"),
    "gi"
  );
  // Input-only: redact the entire pasted value, not just the PEM BEGIN marker.
  // Do not change scrubTokens/redactBody: HAR redaction retains its existing scope.
  const PEM_INPUT_RE = /-----BEGIN(?:[A-Z ]+)?PRIVATE KEY-----/i;
  const DWELL_MS = 500; // cursor must rest this long on an element to log a hover

  let recording = false;
  let captureGeneration = null;
  // Mirror of the recording's paused state at the top level. The overlay tracks
  // its own `paused` inside its IIFE (out of reach here), but the document click
  // handler needs it to gate ⌥-click instant-select — paused means off-record,
  // so no annotation should be captured then. Kept in sync from `overlay-state`.
  let capturePaused = false;
  let rrwebStop = null;

  // Send to the worker, but never throw. When the unpacked extension is reloaded,
  // the OLD content script keeps running in already-open tabs with a dead
  // `chrome.runtime` — any sendMessage then throws "Extension context invalidated"
  // (the four errors seen in chrome://extensions). Guard on the runtime id and
  // swallow the rest so a stale script goes quietly inert instead of spamming.
  let sendFailed = false; // surface the first dropped message, then stay quiet
  function safeSend(msg) {
    try {
      if (!chrome.runtime?.id) return; // context torn down (reload/update) — give up
      const sent = chrome.runtime.sendMessage(msg);
      // The callback form returns undefined; the promise form rejects ASYNCHRONOUSLY,
      // which the try/catch above cannot see — so it lands in the PAGE's console as an
      // "Uncaught (in promise)". Two real causes: the context torn down mid-call, and
      // an rrweb full-DOM snapshot of a heavy page exceeding sendMessage's hard 64MiB
      // cap. Swallow it so we don't spam the page, but report the first one — a
      // dropped snapshot leaves events.jsonl unreplayable and must not be invisible.
      // ponytail: drop-and-report, not chunk-and-reassemble. Split oversized rrweb
      // events across messages if this turns out to be common rather than rare.
      sent?.catch?.((err) => {
        if (sendFailed || msg.type === "capture-error") return; // never recurse
        sendFailed = true;
        reportError(`dropped a "${msg.type}" message: ${err?.message || err}`);
      });
    } catch {
      /* context invalidated mid-call — ignore */
    }
  }

  // Surface in-page failures into the bundle's errors.json (only while recording,
  // so we don't spam the worker with unrelated page errors).
  function reportError(message, stack) {
    if (!recording) return;
    safeSend({ type: "capture-error", where: "content", message, stack: stack || null });
  }
  window.addEventListener("error", (e) => reportError(e.message, e.error?.stack));
  window.addEventListener("unhandledrejection", (e) =>
    reportError(e.reason?.message || String(e.reason), e.reason?.stack)
  );

  function isSecretInput(el) {
    if (!el) return false;
    if (el.type === "password" || el.closest?.("[data-capture-secret]")) return true;
    const hay = `${el.name || ""} ${el.id || ""} ${el.autocomplete || ""}`;
    return SECRET_KEY_RE.test(hay);
  }

  function maskValue(fieldName, value) {
    if (value == null || value === "") return value;
    if (SECRET_KEY_RE.test(String(fieldName)) || PEM_INPUT_RE.test(String(value)))
      return "‹redacted:secret›";
    if (/email/i.test(String(fieldName)) || EMAIL_RE.test(String(value)))
      return "‹redacted:email›";
    return String(value).replace(TOKEN_VALUE_RE, "‹redacted:secret›");
  }

  // --- editable-text masking for rrweb (mirror of src/mask-text.js) ----------
  //
  // VERBATIM copy from src/mask-text.js (the tested module) — content.js is a
  // classic script and can't import. rrweb's maskAllInputs covers <input>/<textarea>
  // but NOT contenteditable / ARIA textboxes (Gmail, Slack, Notion), so free-form
  // text typed there would land in events.jsonl in the clear. Keep in sync.
  const EDITABLE_TEXT_SELECTOR =
    '[contenteditable]:not([contenteditable="false"]),[role="textbox"],[role="searchbox"]';
  function maskEditableText(text) {
    if (typeof text !== "string" || !text.trim()) return text;
    return "‹redacted›";
  }

  // --- unique selector (finder-style) -------------------------------------
  //
  // The old impl returned id / name / tag only, so real pages logged useless
  // "div", "svg", "span" selectors you can't replay. This builds the SHORTEST
  // selector that resolves to exactly one element: a unique id or test-id wins
  // outright; otherwise we climb the tree adding one token per level (preferring
  // id / test-id / name, falling back to :nth-of-type) until the path matches a
  // single node. Verified against the live DOM with querySelectorAll, so a
  // returned selector is guaranteed unique at capture time.

  const ID_OK_RE = /^[A-Za-z][\w-]*$/; // skip ids needing escapes / starting odd
  const TESTID_ATTRS = ["data-testid", "data-test-id", "data-test", "data-cy", "data-qa", "data-automation-id"];
  const MAX_DEPTH = 8; // cap the climb so deep DOMs stay cheap on every hover

  function cssEsc(s) {
    return window.CSS && CSS.escape ? CSS.escape(String(s)) : String(s).replace(/["\\]/g, "\\$&");
  }

  function isUnique(sel) {
    try {
      return document.querySelectorAll(sel).length === 1;
    } catch {
      return false; // malformed selector (exotic tag/attr) — treat as non-unique
    }
  }

  function attrToken(el) {
    for (const a of TESTID_ATTRS) {
      const v = el.getAttribute?.(a);
      if (v) return `[${a}="${cssEsc(v)}"]`;
    }
    return null;
  }

  function nthOfType(el) {
    const tag = (el.tagName || "*").toLowerCase();
    let i = 1;
    for (let sib = el.previousElementSibling; sib; sib = sib.previousElementSibling) {
      if (sib.tagName === el.tagName) i++;
    }
    return `${tag}:nth-of-type(${i})`;
  }

  // One level's most specific available token.
  function levelToken(el) {
    if (el.id && ID_OK_RE.test(el.id)) return `#${cssEsc(el.id)}`;
    const tag = (el.tagName || "*").toLowerCase();
    const attr = attrToken(el);
    if (attr) return tag + attr;
    if (el.name) return `${tag}[name="${cssEsc(el.name)}"]`;
    return nthOfType(el);
  }

  function selectorFor(el) {
    if (!el || el.nodeType !== 1) return el && el.tagName ? el.tagName.toLowerCase() : "?";
    if (el === document.body) return "body";

    // A unique id or test-id is the whole answer.
    if (el.id && ID_OK_RE.test(el.id)) {
      const s = `#${cssEsc(el.id)}`;
      if (isUnique(s)) return s;
    }
    const attr = attrToken(el);
    if (attr && isUnique(`${(el.tagName || "*").toLowerCase()}${attr}`)) {
      return `${el.tagName.toLowerCase()}${attr}`;
    }

    // Climb, prepending one token per level until the path is unique.
    const parts = [];
    let cur = el;
    for (let depth = 0; cur && cur.nodeType === 1 && cur !== document.body && depth < MAX_DEPTH; depth++) {
      parts.unshift(levelToken(cur));
      const candidate = parts.join(" > ");
      if (isUnique(candidate)) return candidate;
      cur = cur.parentElement;
    }
    // Anchor at body if we ran out of climb without a unique match.
    const anchored = "body > " + parts.join(" > ");
    if (isUnique(anchored)) return anchored;
    return parts.join(" > ") || (el.tagName ? el.tagName.toLowerCase() : "?");
  }

  function labelFor(el) {
    return (
      el.getAttribute?.("aria-label") ||
      el.textContent?.trim().slice(0, 40) ||
      el.getAttribute?.("placeholder") ||
      el.name ||
      ""
    );
  }

  // --- semantic context (what the element IS, for intent) -------------------
  //
  // A selector is for replay; this is for understanding. We capture the
  // accessible name, ARIA role, the section/landmark the element sits in, and
  // input/link/select specifics — so the analyst reads "click the 'Issue refund'
  // button in 'Order actions'" instead of "click div:nth-of-type(3)". Never reads
  // el.value, so it can't leak a typed secret.

  function accessibleName(el) {
    if (!el) return "";
    const aria = el.getAttribute?.("aria-label");
    if (aria) return aria.trim().slice(0, 80);
    const labelledby = el.getAttribute?.("aria-labelledby");
    if (labelledby) {
      const txt = labelledby
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim())
        .filter(Boolean)
        .join(" ");
      if (txt) return txt.slice(0, 80);
    }
    if (el.id) {
      const lab = document.querySelector(`label[for="${cssEsc(el.id)}"]`);
      if (lab?.textContent?.trim()) return lab.textContent.trim().slice(0, 80);
    }
    const closestLabel = el.closest?.("label");
    if (closestLabel?.textContent?.trim()) return closestLabel.textContent.trim().slice(0, 80);
    // textContent is a good name for buttons/links, but for a <select> it's just the
    // concatenated <option> text — skip it (the chosen option is in `selected`).
    if ((el.tagName || "").toLowerCase() !== "select") {
      const text = el.textContent?.trim();
      if (text) return text.slice(0, 80);
    }
    return (el.getAttribute?.("placeholder") || el.getAttribute?.("title") || el.getAttribute?.("alt") || "").slice(0, 80);
  }

  function roleOf(el) {
    const explicit = el.getAttribute?.("role");
    if (explicit) return explicit;
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "input") {
      const t = (el.getAttribute?.("type") || "text").toLowerCase();
      return { checkbox: "checkbox", radio: "radio", submit: "button", button: "button", range: "slider" }[t] || "textbox";
    }
    const map = {
      a: el.getAttribute?.("href") ? "link" : "",
      button: "button", select: "combobox", textarea: "textbox",
      h1: "heading", h2: "heading", h3: "heading", h4: "heading", h5: "heading", h6: "heading",
      nav: "navigation", main: "main",
    };
    return map[tag] || "";
  }

  // The section the element lives in: a labelled enclosing landmark, else the
  // nearest heading that precedes it in document order.
  function sectionFor(el) {
    const landmark = el.closest?.("[role], main, nav, header, footer, aside, section, form, dialog");
    if (landmark) {
      let label = landmark.getAttribute?.("aria-label") || "";
      if (!label) {
        const lid = landmark.getAttribute?.("aria-labelledby");
        if (lid) label = document.getElementById(lid)?.textContent?.trim() || "";
      }
      if (label) return label.slice(0, 80);
    }
    let node = el;
    for (let depth = 0; node && depth < 12; depth++) {
      for (let sib = node.previousElementSibling; sib; sib = sib.previousElementSibling) {
        const h = sib.matches?.("h1,h2,h3,h4,h5,h6") ? sib : sib.querySelector?.("h1,h2,h3,h4,h5,h6");
        if (h?.textContent?.trim()) return h.textContent.trim().slice(0, 80);
      }
      node = node.parentElement;
    }
    return "";
  }

  function describe(el) {
    if (!el || el.nodeType !== 1) return {};
    const tag = (el.tagName || "").toLowerCase();
    const d = { tag };
    const role = roleOf(el);
    if (role) d.role = role;
    // accessibleName() follows aria-labelledby to a referenced element's
    // textContent. On a SECRET field that reference can pull sensitive text into
    // ctx.name, so suppress the name entirely for secret inputs — the role/section
    // still give the analyst enough ("type into the secret field in 'Login'").
    const name = isSecretInput(el) ? "" : accessibleName(el);
    if (name) d.name = name;
    if (tag === "input" || tag === "textarea" || tag === "select") {
      const t = el.getAttribute?.("type");
      if (t) d.inputType = t;
    }
    if (tag === "a") {
      const href = el.getAttribute?.("href");
      if (href) d.href = href;
    }
    if (tag === "select" && el.options) {
      const opt = el.options[el.selectedIndex];
      if (opt?.textContent) d.selected = opt.textContent.trim().slice(0, 80);
    }
    const section = sectionFor(el);
    if (section) d.section = section;
    return d;
  }

  // Where on the page the pointer is — viewport pixel coords, a
  // resolution-independent percent, the viewport size, and the target's bounding
  // box. This is what lets an agent resolve "in this area" even when you click or
  // point at a spot with no obvious clickable element.
  function positionFor(x, y, el) {
    const vw = window.innerWidth || 0;
    const vh = window.innerHeight || 0;
    const r = el?.getBoundingClientRect?.();
    return {
      x: Math.round(x),
      y: Math.round(y),
      xpct: vw ? Math.round((x / vw) * 100) : null,
      ypct: vh ? Math.round((y / vh) * 100) : null,
      viewport: { w: vw, h: vh },
      rect: r ? { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) } : null,
    };
  }

  // Hand an event to the worker, which stamps it against t0 and buffers it.
  function emit(kind, payload) {
    if (!recording || capturePaused) return;
    safeSend({ type: "timeline-event", generation: captureGeneration, event: { kind, ...payload } });
  }
  function emitRaw(node) {
    if (!recording || capturePaused) return;
    safeSend({ type: "rrweb-event", generation: captureGeneration, node });
  }

  function onClick(e) {
    // ⌥-click (Alt+click) = instant Selector on the exact element under the cursor,
    // with no need to arm the Select tool first. It emits the SAME annotation:select
    // event a manual Select click would, so the user + agent align on that element.
    // We suppress the real click (capture-phase stopImmediatePropagation + preventDefault)
    // so marking a Delete button / link doesn't ALSO trigger it. Gated on an active,
    // non-paused recording and no annotation mode already running. (The fn key can't
    // be used — browsers never receive it; ⌥ is exposed as e.altKey.)
    if (e.altKey && recording && !capturePaused && !annotate.mode()) {
      e.preventDefault();
      e.stopImmediatePropagation();
      annotate.quickSelect(e.target);
      return;
    }
    // While an annotation tool is active, the catcher intercepts the click — don't
    // also log it as a workflow click (the event still bubbles to this document
    // listener, retargeted to our annotation host).
    if (annotate.mode()) return;
    const el = e.target;
    lastHoverSelector = null; // let a re-hover on the same element log again
    emit("click", { selector: selectorFor(el), label: labelFor(el), ctx: describe(el), ...positionFor(e.clientX, e.clientY, el) });
  }

  // Pointer dwell → `hover`. When the cursor rests on an element for DWELL_MS we
  // record where you are (selector + label + position) so narration like "and in
  // this area" resolves to a real element without a click. Deduped per element so
  // a slow drag across one box doesn't spam the timeline; secret fields are never
  // referenced even by hover.
  let dwellTimer = null;
  let lastMove = null;
  let lastHoverSelector = null;
  const moveOpts = { capture: true, passive: true };

  function onMove(e) {
    lastMove = { x: e.clientX, y: e.clientY };
    if (dwellTimer) clearTimeout(dwellTimer);
    dwellTimer = setTimeout(emitDwell, DWELL_MS);
  }

  function emitDwell() {
    if (!recording || !lastMove) return;
    if (annotate.mode()) return; // pointer is driving an annotation tool, not browsing
    const el = document.elementFromPoint(lastMove.x, lastMove.y);
    if (!el || isSecretInput(el)) return;
    const selector = selectorFor(el);
    if (selector === lastHoverSelector) return;
    lastHoverSelector = selector;
    emit("hover", { selector, label: labelFor(el), ctx: describe(el), ...positionFor(lastMove.x, lastMove.y, el) });
  }

  function onChange(e) {
    const el = e.target;
    if (!("value" in el)) return;
    // describe() never reads el.value, so it's safe even for secret fields — it
    // gives the field's label/role so "type into the 'Reason' box" is legible.
    const ctx = describe(el);
    if (isSecretInput(el)) {
      emit("input", { selector: selectorFor(el), value: "‹redacted:secret›", ctx });
    } else {
      emit("input", { selector: selectorFor(el), value: maskValue(el.name || el.id, el.value), ctx });
    }
  }

  let lastScrollAt = 0;
  function onScroll() {
    if (Date.now() - lastScrollAt < 150) return;
    lastScrollAt = Date.now();
    emit("scroll", { x: Math.round(window.scrollX), y: Math.round(window.scrollY) });
  }
  function onFocus() { emit("focus", { focused: true }); }
  function onBlur() { emit("focus", { focused: false }); }
  function onPopstate() { emit("nav", { url: location.href }); }

  function onKey(e) {
    // Only emit semantically meaningful keys, never raw keystrokes (those would
    // leak passwords typed character by character).
    if (["Enter", "Tab", "Escape"].includes(e.key)) emit("key", { key: e.key });
  }

  // --- on-screen recording overlay -----------------------------------------
  //
  // A single shadow-DOM pill the user sees while recording. The worker shows it
  // in EVERY instrumented tab and keeps it in sync (broadcastOverlay), so it's
  // present no matter which tab is focused. Styled deliberately unlike Chrome's
  // "<ext> is debugging this browser" bar: that bar's Cancel detaches the
  // debugger and kills network capture, whereas this Cancel discards the take
  // through the worker. Controls: Pause/Resume, Restart, Cancel, Finish.
  const overlay = (() => {
    let host = null;
    let els = {};
    let timer = null;
    let t0 = 0;
    let paused = false;
    let pauseReason = null; // "manual" | "blocklist"
    let pausedAccum = 0; // ms banked from completed pauses (from the worker)
    let pauseStartedAt = 0; // wall-clock ms the current pause began (0 if live)
    let micActive = false; // is the mic live? drives the level meter vs the muted glyph
    let reshare = false; // screen share died — show the Re-share button

    const fmt = (ms) => {
      const s = Math.max(0, Math.floor(ms / 1000));
      return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
    };
    // Elapsed RECORDING time = wall - t0 - banked pause - the pause in progress, so
    // the pill matches video.webm and never jumps forward when you resume.
    const elapsed = () => {
      const ongoing = paused && pauseStartedAt ? Date.now() - pauseStartedAt : 0;
      return Date.now() - t0 - pausedAccum - ongoing;
    };
    const tick = () => {
      if (els.time) els.time.textContent = fmt(elapsed());
    };
    const startTimer = () => {
      stopTimer();
      tick();
      timer = setInterval(tick, 1000);
    };
    const stopTimer = () => {
      if (timer) clearInterval(timer);
      timer = null;
    };

    const cmd = (command) => safeSend({ type: "overlay-command", command });

    // Destructive verbs need a deliberate second click: Restart wipes the
    // current take, Cancel discards the whole recording with no export.
    function wireDestructive(btn, command, label) {
      let armed = false;
      let t = null;
      btn.addEventListener("click", () => {
        if (armed) {
          clearTimeout(t);
          armed = false;
          btn.textContent = label;
          btn.classList.remove("armed");
          cmd(command);
          return;
        }
        armed = true;
        btn.textContent = "Sure?";
        btn.classList.add("armed");
        t = setTimeout(() => {
          armed = false;
          btn.textContent = label;
          btn.classList.remove("armed");
        }, 3000);
      });
    }

    function mount(meta) {
      if (host) return; // already shown
      t0 = meta?.t0 || Date.now();
      paused = !!meta?.paused;
      pauseReason = meta?.pauseReason || null;
      pausedAccum = meta?.pausedAccum || 0;
      pauseStartedAt = meta?.pauseStartedAt || 0;
      micActive = !!meta?.micActive;
      reshare = !!meta?.reshare;

      host = document.createElement("div");
      host.id = "__bac_overlay__";
      // Survive page CSS: isolate in a shadow root, pin above everything.
      host.style.cssText = "position:fixed;left:0;top:0;width:0;height:0;z-index:2147483647;";
      const shadow = host.attachShadow({ mode: "open" });
      shadow.innerHTML = `
        <style>
          .bar{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);
            display:flex;align-items:center;gap:10px;pointer-events:auto;
            font:13px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            background:#1c1c1e;color:#fff;padding:8px 12px;border-radius:9999px;
            box-shadow:0 6px 24px rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.12);
            user-select:none;cursor:grab;touch-action:none;}
          .bar.dragging{cursor:grabbing;}
          /* Collapsed: keep only the live read-outs (dot, timer, mic) + the toggle. */
          .bar.collapsed .sep,
          .bar.collapsed #select,.bar.collapsed #draw,.bar.collapsed #pause,
          .bar.collapsed #restart,.bar.collapsed #cancel,.bar.collapsed #finish,
          .bar.collapsed #reshare{display:none;}
          /* Re-share button: shown only when the screen share died mid-recording.
             Amber + bold so it reads as "action needed" without being as alarming
             as the red Finish. Pulses gently to draw the eye. */
          #reshare{display:none;background:#ff9f0a;color:#000;font-weight:600;}
          #reshare:hover{background:#ffb340;}
          .bar.reshare #reshare{display:inline-block;animation:reshare-pulse 1.6s infinite;}
          @keyframes reshare-pulse{0%,100%{box-shadow:0 0 0 0 rgba(255,159,10,.5)}
            50%{box-shadow:0 0 0 6px rgba(255,159,10,0)}}
          /* When the share is dead, tint the rec dot amber so the user sees the
             recording is still running but its video is paused. */
          .bar.reshare .dot{background:#ff9f0a;animation:none;}
          .bar.reshare .dot::after{content:"";position:absolute;}
          .dot{width:10px;height:10px;border-radius:50%;background:#ff3b30;
            box-shadow:0 0 0 0 rgba(255,59,48,.6);animation:pulse 1.4s infinite;}
          .dot.paused{background:#ff9f0a;animation:none;}
          @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,59,48,.6)}
            70%{box-shadow:0 0 0 7px rgba(255,59,48,0)}100%{box-shadow:0 0 0 0 rgba(255,59,48,0)}}
          .time{font-variant-numeric:tabular-nums;min-width:42px;text-align:center;opacity:.9;}
          .sep{width:1px;height:18px;background:rgba(255,255,255,.15);}
          /* Mic level meter — confirms the mic is actually hearing you while recording. */
          .mic{display:flex;align-items:center;gap:6px;}
          .mic-ico{position:relative;width:13px;height:13px;display:inline-flex;opacity:.85;}
          .mic-ico svg{width:13px;height:13px;}
          .mic-bars{display:flex;align-items:flex-end;gap:2px;height:14px;}
          .mic-bars i{width:3px;height:14px;border-radius:2px;background:#34c759;
            transform:scaleY(.12);transform-origin:bottom;transition:transform 90ms linear;}
          /* Mic off (narration not recorded): dim, slashed, no bars. */
          .mic.off{opacity:.55;}
          .mic.off .mic-bars{display:none;}
          .mic.off .mic-ico{opacity:.6;}
          .mic.off .mic-ico::after{content:"";position:absolute;left:-1px;top:5.5px;
            width:16px;height:1.5px;background:#ff9f0a;transform:rotate(-45deg);border-radius:1px;}
          button{font:inherit;color:#fff;background:transparent;border:0;cursor:pointer;
            padding:5px 9px;border-radius:7px;white-space:nowrap;}
          button:hover{background:rgba(255,255,255,.12);}
          button.primary{background:#ff3b30;font-weight:600;}
          button.primary:hover{background:#ff5147;}
          button.armed{background:#ff9f0a;color:#000;font-weight:600;}
          button.active{background:#0a84ff;color:#fff;font-weight:600;}
          button.active:hover{background:#3a9bff;}
          button:disabled{opacity:.4;cursor:default;}
          button:disabled:hover{background:transparent;}
          /* Collapse toggle — a chevron that flips when the bar is collapsed. */
          .toggle{display:inline-flex;align-items:center;padding:5px 6px;}
          .toggle svg{width:14px;height:14px;transition:transform 120ms ease;}
          .bar.collapsed .toggle svg{transform:rotate(180deg);}
        </style>
        <div class="bar" part="bar">
          <span class="dot" id="dot"></span>
          <span class="time" id="time">00:00</span>
          <span class="mic" id="mic" title="Microphone level">
            <span class="mic-ico"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0M12 18v3"/></svg></span>
            <span class="mic-bars" id="micBars"><i></i><i></i><i></i><i></i><i></i></span>
          </span>
          <button id="collapse" class="toggle" title="Hide the controls">
            <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
          </button>
          <span class="sep"></span>
          <button id="select" title="Pick an element you mean — or ⌥-click any element to mark it instantly">Select</button>
          <button id="draw" title="Draw on the screen">Draw</button>
          <span class="sep"></span>
          <button id="pause">Pause</button>
          <button id="restart">Restart</button>
          <button id="cancel">Cancel</button>
          <button id="reshare" title="The screen share stopped — pick a new screen to keep recording video">Re-share</button>
          <button id="finish" class="primary">Finish</button>
        </div>`;
      (document.documentElement || document.body).appendChild(host);

      els = {
        bar: shadow.querySelector(".bar"),
        dot: shadow.getElementById("dot"),
        time: shadow.getElementById("time"),
        mic: shadow.getElementById("mic"),
        micBars: shadow.getElementById("micBars"),
        collapse: shadow.getElementById("collapse"),
        select: shadow.getElementById("select"),
        draw: shadow.getElementById("draw"),
        pause: shadow.getElementById("pause"),
        restart: shadow.getElementById("restart"),
        cancel: shadow.getElementById("cancel"),
        reshare: shadow.getElementById("reshare"),
        finish: shadow.getElementById("finish"),
      };
      els.pause.addEventListener("click", () => cmd(paused ? "resume" : "pause"));
      els.finish.addEventListener("click", () => cmd("finish"));
      wireDestructive(els.restart, "restart", "Restart");
      wireDestructive(els.cancel, "cancel", "Cancel");
      els.reshare.addEventListener("click", () => cmd("reshare"));
      els.collapse.addEventListener("click", toggleCollapse);
      makeDraggable(els.bar);

      // The two annotation tools (Selector / Draw). Toggling one button enters
      // that mode; clicking it again (or pressing Esc, or switching to the other)
      // exits. annotate.onChange is the single sync point, so a mode exit it
      // triggers itself (Esc) repaints the buttons too.
      els.select.addEventListener("click", () => annotate.setMode("select"));
      els.draw.addEventListener("click", () => annotate.setMode("draw"));
      annotate.onChange = syncTools;

      applyPaused();
      applyMic();
      applyReshare();
      if (!paused) startTimer();
    }

    // Show the level meter when the mic is live; otherwise a dimmed, slashed glyph
    // so the user can see at a glance that narration isn't being recorded.
    function applyMic() {
      if (els.mic) els.mic.classList.toggle("off", !micActive);
    }

    // Toggle the Re-share button + amber dot state. When the screen share died
    // mid-recording, the rec dot goes amber (recording still running, video
    // paused) and the Re-share button appears + pulses to draw the eye. The
    // tools (Select/Draw) stay available — annotations are still useful while
    // the user decides whether to re-share.
    function applyReshare() {
      if (!els.bar) return;
      els.bar.classList.toggle("reshare", reshare);
    }

    // Drive the equalizer bars from a 0..1 loudness value (worker → us, ~12/sec).
    // Per-bar weights + a little jitter make it read as speech, not a flat block.
    const BAR_WEIGHTS = [0.55, 0.9, 1, 0.8, 0.6];
    function setMicLevel(level) {
      if (!els.micBars || !micActive) return;
      const lv = Math.max(0, Math.min(1, level || 0));
      const bars = els.micBars.children;
      for (let i = 0; i < bars.length; i++) {
        const jitter = lv > 0.04 ? 0.82 + Math.random() * 0.36 : 1;
        const h = Math.max(0.12, Math.min(1, lv * (BAR_WEIGHTS[i] || 0.7) * jitter));
        bars[i].style.transform = `scaleY(${h.toFixed(3)})`;
      }
    }

    // Collapse the pill down to just the live read-outs (rec dot, timer, mic
    // meter) and the toggle, hiding the tools/controls; click again to expand.
    function toggleCollapse() {
      const collapsed = els.bar.classList.toggle("collapsed");
      els.collapse.title = collapsed ? "Show the controls" : "Hide the controls";
      clampToViewport(); // width changed — keep it on-screen if it was dragged to an edge
    }

    // Pin the pill at a viewport coordinate, clamped so it can't leave the screen.
    function placeAt(left, top) {
      const r = els.bar.getBoundingClientRect();
      const maxL = Math.max(0, window.innerWidth - r.width);
      const maxT = Math.max(0, window.innerHeight - r.height);
      els.bar.style.left = Math.min(Math.max(0, left), maxL) + "px";
      els.bar.style.top = Math.min(Math.max(0, top), maxT) + "px";
    }
    // Re-clamp the current position. No-op until a drag has taken over placement
    // (before that the pill is still CSS-centered, transform: translateX(-50%)).
    function clampToViewport() {
      if (els.bar.style.transform !== "none") return;
      const r = els.bar.getBoundingClientRect();
      placeAt(r.left, r.top);
    }

    // Make the pill draggable from any non-button area. The first drag switches it
    // from CSS bottom-center to explicit left/top so it stays where the user drops it.
    function makeDraggable(bar) {
      let dragging = false, startX = 0, startY = 0, baseLeft = 0, baseTop = 0;
      bar.addEventListener("pointerdown", (e) => {
        if (e.button !== 0) return;            // left button only
        if (e.target.closest("button")) return; // let the controls handle their own clicks
        const r = bar.getBoundingClientRect();
        bar.style.left = r.left + "px";
        bar.style.top = r.top + "px";
        bar.style.bottom = "auto";
        bar.style.transform = "none";
        baseLeft = r.left; baseTop = r.top;
        startX = e.clientX; startY = e.clientY;
        dragging = true;
        bar.classList.add("dragging");
        bar.setPointerCapture?.(e.pointerId);
        e.preventDefault();
      });
      bar.addEventListener("pointermove", (e) => {
        if (!dragging) return;
        placeAt(baseLeft + (e.clientX - startX), baseTop + (e.clientY - startY));
      });
      const end = (e) => {
        if (!dragging) return;
        dragging = false;
        bar.classList.remove("dragging");
        bar.releasePointerCapture?.(e.pointerId);
      };
      bar.addEventListener("pointerup", end);
      bar.addEventListener("pointercancel", end);
    }

    // Reflect the active annotation mode on the tool buttons.
    function syncTools() {
      if (!els.select) return;
      const mode = annotate.mode();
      els.select.classList.toggle("active", mode === "select");
      els.draw.classList.toggle("active", mode === "draw");
    }

    function applyPaused() {
      if (!els.dot) return;
      els.dot.classList.toggle("paused", paused);
      const blocklist = paused && pauseReason === "blocklist";
      // A blocklist pause is automatic — the worker resumes it when the user leaves
      // the blocklisted tab, so don't offer a manual Resume that can't take effect.
      els.pause.textContent = blocklist ? "Blocked" : paused ? "Resume" : "Pause";
      els.pause.disabled = blocklist;
      els.pause.title = blocklist ? "Paused automatically — you're on a blocklisted site" : "";
      // Annotations are dropped while paused (the worker ignores events then), so
      // disable the tools and leave any active mode.
      els.select.disabled = paused;
      els.draw.disabled = paused;
      if (paused) annotate.exit();
    }

    // Reflect a worker state broadcast: unmount when recording ends, otherwise
    // sync t0 (resets on Restart), paused, and the elapsed clock.
    function update(s) {
      if (!s || !s.recording) {
        unmount();
        return;
      }
      if (!host) {
        mount(s);
        return;
      }
      if (s.t0 && s.t0 !== t0) t0 = s.t0; // Restart reset the clock
      paused = !!s.paused;
      pauseReason = s.pauseReason || null;
      pausedAccum = s.pausedAccum || 0;
      pauseStartedAt = s.pauseStartedAt || 0;
      micActive = !!s.micActive;
      reshare = !!s.reshare;
      applyPaused();
      applyMic();
      applyReshare();
      if (paused) {
        stopTimer();
        tick();
      } else {
        startTimer();
      }
    }

    function unmount() {
      stopTimer();
      host?.remove();
      host = null;
      els = {};
    }

    return { mount, update, unmount, setMicLevel };
  })();

  // --- annotation geometry (mirror of src/annotate-geom.js) -----------------
  //
  // VERBATIM copy of drawGeom from src/annotate-geom.js (the tested module). A
  // content script is a classic script and can't import the module, so we keep a
  // copy here — keep the two in sync (same arrangement as the redact.js helpers
  // above). Converts a viewport-pixel stroke into resolution-independent %-coords
  // + bounding box so pack.py can place the highlight on a frame of any size.
  function drawGeom(points, viewport) {
    const w = (viewport && viewport.w) || 0;
    const h = (viewport && viewport.h) || 0;
    const pct = (v, total) => (total ? Math.round((v / total) * 1000) / 10 : 0);
    const pts = (points || []).map((p) => ({ xpct: pct(p.x, w), ypct: pct(p.y, h) }));
    if (!pts.length) return { points: [], bbox: null, viewport: { w, h } };
    const xs = pts.map((p) => p.xpct);
    const ys = pts.map((p) => p.ypct);
    const minx = Math.min(...xs), maxx = Math.max(...xs);
    const miny = Math.min(...ys), maxy = Math.max(...ys);
    return {
      points: pts,
      bbox: { xpct: minx, ypct: miny, wpct: Math.round((maxx - minx) * 10) / 10, hpct: Math.round((maxy - miny) * 10) / 10 },
      viewport: { w, h },
    };
  }

  // --- annotation tools: Selector + Draw (Adam's headline ask) ---------------
  //
  // Two SEPARATE tools on the overlay, both usable mid-recording:
  //   • Selector — element pick that snaps to the DOM (reuses selectorFor() +
  //     describe()). Emits `annotation:select` so the user and the analyzing agent
  //     are aligned on the SAME element ("this button, not that one").
  //   • Draw — freeform highlight of an area/region (not element-bound). Emits
  //     `annotation:draw` (a %-coord stroke + bbox via drawGeom) so the agent gets
  //     "user circled here", not just video pixels.
  //
  // Visual layer: one shadow-DOM host (separate from the overlay pill), z-indexed
  // just below it so the pill stays clickable. A full-viewport "catcher" intercepts
  // pointer events ONLY while a mode is active (so a Select click doesn't also
  // navigate the page, and a Draw stroke doesn't select page text). Marks are drawn
  // on a <canvas> and fade after a few seconds — long enough to land in the video
  // and in the frame we grab at emit time, without permanently obscuring the page.
  const annotate = (() => {
    const Z = 2147483646; // one below the overlay pill (2147483647)
    const FADE_HOLD_MS = 3000; // keep a mark fully visible this long, then fade
    const FADE_MS = 500;
    const STROKE = "#ff3b30";
    const MAX_POINTS = 200; // cap a stroke's payload; long drags get sampled down

    let mode = null; // null | "select" | "draw"
    let host = null, shadow = null;
    let catcher = null, canvas = null, ctx = null, outline = null, hint = null;
    let dpr = 1;
    let drawing = false;
    let points = []; // current stroke, viewport-pixel
    let hovered = null; // element under cursor in select mode
    let fadeT = null, clearT = null;

    function ensureLayer() {
      if (host) return;
      host = document.createElement("div");
      host.id = "__bac_annotate__";
      host.style.cssText = `position:fixed;inset:0;z-index:${Z};pointer-events:none;`;
      shadow = host.attachShadow({ mode: "open" });
      shadow.innerHTML = `
        <style>
          .catcher{position:fixed;inset:0;pointer-events:none;}
          .catcher.on{pointer-events:auto;cursor:crosshair;}
          canvas{position:fixed;inset:0;width:100vw;height:100vh;pointer-events:none;
            transition:opacity ${FADE_MS}ms ease;}
          .outline{position:fixed;border:2px solid ${STROKE};border-radius:3px;
            background:rgba(255,59,48,.10);pointer-events:none;display:none;
            box-sizing:border-box;}
          .hint{position:fixed;bottom:64px;left:50%;transform:translateX(-50%);
            background:rgba(28,28,30,.92);color:#fff;display:none;white-space:nowrap;
            font:12px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            padding:6px 12px;border-radius:8px;pointer-events:none;}
        </style>
        <canvas class="ink" id="ink"></canvas>
        <div class="outline" id="outline"></div>
        <div class="catcher" id="catcher"></div>
        <div class="hint" id="hint"></div>`;
      (document.documentElement || document.body).appendChild(host);
      catcher = shadow.getElementById("catcher");
      canvas = shadow.getElementById("ink");
      outline = shadow.getElementById("outline");
      hint = shadow.getElementById("hint");
      ctx = canvas.getContext("2d");
      sizeCanvas();
      window.addEventListener("resize", sizeCanvas);
      catcher.addEventListener("mousemove", onMove);
      catcher.addEventListener("mousedown", onDown);
      catcher.addEventListener("mouseup", onUp);
      catcher.addEventListener("click", onPick, true);
      // Let the wheel still scroll the page so Select can reach off-screen elements.
      catcher.addEventListener("wheel", (e) => window.scrollBy(0, e.deltaY), { passive: true });
      document.addEventListener("keydown", onEsc, true);
    }

    function sizeCanvas() {
      if (!canvas) return;
      dpr = window.devicePixelRatio || 1;
      canvas.width = Math.round(window.innerWidth * dpr);
      canvas.height = Math.round(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); // draw in CSS pixels
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
    }

    // The page element under (x,y) — momentarily make the catcher transparent to
    // hit-testing so elementFromPoint returns the real page node, not our layer.
    function pageElAt(x, y) {
      const wasAuto = catcher.style.pointerEvents === "auto";
      catcher.style.pointerEvents = "none";
      let el = document.elementFromPoint(x, y);
      if (wasAuto) catcher.style.pointerEvents = "auto";
      if (el && (el.id === "__bac_annotate__" || el.id === "__bac_overlay__")) el = null;
      return el;
    }

    // --- fade: a single timer dims then clears the whole canvas after idle ----
    function holdFade() {
      if (fadeT) { clearTimeout(fadeT); fadeT = null; }
      if (clearT) { clearTimeout(clearT); clearT = null; }
      if (canvas) canvas.style.opacity = "1";
    }
    function scheduleFade() {
      holdFade();
      fadeT = setTimeout(() => {
        if (canvas) canvas.style.opacity = "0";
        clearT = setTimeout(clearInk, FADE_MS + 50);
      }, FADE_HOLD_MS);
    }
    function clearInk() {
      if (!ctx) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      canvas.style.opacity = "1";
    }

    // --- draw mode ------------------------------------------------------------
    function addPoint(x, y) {
      const prev = points[points.length - 1];
      points.push({ x, y });
      if (prev) {
        ctx.strokeStyle = STROKE;
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(x, y);
        ctx.stroke();
      }
    }
    function onDown(e) {
      if (mode !== "draw") return;
      holdFade();
      drawing = true;
      points = [];
      addPoint(e.clientX, e.clientY);
    }
    function onUp() {
      if (mode !== "draw" || !drawing) return;
      drawing = false;
      if (points.length > 1) {
        emit("annotation:draw", drawGeom(sample(points, MAX_POINTS), { w: window.innerWidth, h: window.innerHeight }));
      }
      points = [];
      scheduleFade();
    }

    // --- select mode ----------------------------------------------------------
    function showOutline(r) {
      outline.style.display = "block";
      outline.style.left = `${r.x}px`;
      outline.style.top = `${r.y}px`;
      outline.style.width = `${r.width}px`;
      outline.style.height = `${r.height}px`;
    }
    function hideOutline() {
      if (outline) outline.style.display = "none";
    }
    // Emit annotation:select for `el` and flash its box onto the canvas so the
    // confirmation lands in the video. Shared by the Select tool (onPick) and the
    // ⌥-click fast path (quickSelect).
    function markElement(el) {
      if (!el || el.nodeType !== 1) return;
      const r = el.getBoundingClientRect();
      emit("annotation:select", {
        selector: selectorFor(el),
        label: labelFor(el),
        ctx: describe(el),
        ...positionFor(r.x + r.width / 2, r.y + r.height / 2, el),
      });
      holdFade();
      ctx.strokeStyle = STROKE;
      ctx.lineWidth = 3;
      ctx.strokeRect(r.x, r.y, r.width, r.height);
      scheduleFade();
    }

    function onPick(e) {
      if (mode !== "select") return;
      // Don't let the pick double as a real page click / navigation.
      e.preventDefault();
      e.stopPropagation();
      // Resolve from the click point, not the cached hover — the wheel handler scrolls
      // without firing onMove, so `hovered` can be stale after a scroll.
      const el = pageElAt(e.clientX, e.clientY) || hovered;
      markElement(el);
    }

    // ⌥-click fast path: mark an element without arming the Select tool. The layer
    // may not exist yet (user never opened Select/Draw), so build it first; it stays
    // non-interactive (catcher pointer-events:none) since no mode is active.
    function quickSelect(el) {
      if (!el || el.nodeType !== 1) return;
      ensureLayer();
      markElement(el);
    }

    function onMove(e) {
      if (mode === "select") {
        const el = pageElAt(e.clientX, e.clientY);
        hovered = el;
        if (el) showOutline(el.getBoundingClientRect());
        else hideOutline();
      } else if (mode === "draw" && drawing) {
        addPoint(e.clientX, e.clientY);
      }
    }

    function onEsc(e) {
      if (e.key === "Escape" && mode) {
        e.stopPropagation();
        setMode(null);
      }
    }

    // Keep at most `max` points, evenly sampled, always keeping the last one.
    function sample(pts, max) {
      if (pts.length <= max) return pts;
      const step = pts.length / max;
      const out = [];
      for (let i = 0; i < max; i++) out.push(pts[Math.floor(i * step)]);
      out.push(pts[pts.length - 1]);
      return out;
    }

    // Enter `next`, or toggle off if it's already active. Switching modes resets
    // the other mode's transient state. onChange repaints the overlay buttons.
    function setMode(next) {
      const target = mode === next ? null : next;
      mode = target;
      drawing = false;
      points = [];
      hovered = null;
      if (mode) {
        ensureLayer();
        catcher.classList.add("on");
        catcher.style.pointerEvents = "auto";
        hint.textContent = mode === "select" ? "Click an element to mark it · Esc to exit" : "Drag to draw · Esc to exit";
        hint.style.display = "block";
      } else if (catcher) {
        catcher.classList.remove("on");
        catcher.style.pointerEvents = "none";
        hideOutline();
        if (hint) hint.style.display = "none";
      }
      try { annotate.onChange?.(); } catch {}
      return mode;
    }

    function exit() {
      if (mode) setMode(null);
    }

    // Remove the whole layer (on stop/cancel). Listeners die with the host.
    function teardown() {
      mode = null;
      drawing = false;
      points = [];
      hovered = null;
      holdFade();
      window.removeEventListener("resize", sizeCanvas);
      document.removeEventListener("keydown", onEsc, true);
      host?.remove();
      host = shadow = catcher = canvas = ctx = outline = hint = null;
    }

    return { setMode, exit, teardown, quickSelect, mode: () => mode, onChange: null };
  })();

  // --- pre-recording countdown ----------------------------------------------
  //
  // A big 3-2-1 shown in the active tab AFTER the screen picker, BEFORE capture
  // goes live (the worker holds recording=false until it finishes, then sets t0).
  // Driven entirely by the worker via `countdown` messages: n>=1 shows the number,
  // n=0 clears it. Shadow-DOM isolated, non-interactive (pointer-events:none).
  // Countdown caption strings, kept inline (content scripts don't load i18n.js).
  // Mirrors cdBold/cdSmall in i18n.js — update both together. `uiLang` tracks the
  // popup's language choice (chrome.storage `lang`), defaulting to English.
  const CD_STRINGS = {
    en: { bold: "Say out loud what you're about to do.", small: "Your narration gives the AI the most context." },
    es: { bold: "Di en voz alta lo que vas a hacer.", small: "Tu narración le da a la IA el máximo contexto." },
    pt: { bold: "Diga em voz alta o que você vai fazer.", small: "Sua narração dá à IA o máximo de contexto." },
  };
  let uiLang = "en";
  try {
    chrome.storage?.local?.get(["lang"], ({ lang }) => {
      if (CD_STRINGS[lang]) uiLang = lang;
    });
    chrome.storage?.onChanged?.addListener((changes, area) => {
      if (area === "local" && changes.lang && CD_STRINGS[changes.lang.newValue]) uiLang = changes.lang.newValue;
    });
  } catch {}

  const countdown = (() => {
    let host = null, numEl = null;

    function ensure() {
      if (host) return;
      host = document.createElement("div");
      host.id = "__bac_countdown__";
      host.style.cssText =
        "position:fixed;inset:0;z-index:2147483647;pointer-events:none;" +
        "display:flex;flex-direction:column;align-items:center;justify-content:center;gap:22px;";
      const sh = host.attachShadow({ mode: "open" });
      // The caption nudges the user to speak their intent during the pre-roll —
      // spoken narration is the richest context the AI gets, so we prompt for it
      // here rather than relying on the (now optional) typed task field.
      sh.innerHTML = `
        <style>
          .num{font:560 92px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            color:#fff;width:172px;height:172px;border-radius:50%;display:flex;
            align-items:center;justify-content:center;background:rgba(10,10,11,.86);
            box-shadow:inset 0 1px 0 rgba(255,255,255,.12),0 0 0 4px rgba(255,77,77,.14),
            0 10px 50px rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1);}
          .num.tick{animation:pop .9s cubic-bezier(0.32,0.72,0,1);}
          @keyframes pop{0%{transform:scale(.6);opacity:0}
            30%{transform:scale(1);opacity:1}100%{transform:scale(1);opacity:1}}
          .cap{max-width:420px;text-align:center;padding:12px 20px;border-radius:16px;
            background:rgba(10,10,11,.86);border:1px solid rgba(255,255,255,.1);
            box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 10px 40px rgba(0,0,0,.45);
            font:500 15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            color:rgba(255,255,255,.92);animation:rise .6s cubic-bezier(0.32,0.72,0,1) both;}
          .cap b{font-weight:600;color:#ff7a7a;}
          .cap small{display:block;margin-top:4px;font-size:12px;color:rgba(255,255,255,.5);font-weight:400;}
          @keyframes rise{0%{transform:translateY(14px);opacity:0}100%{transform:translateY(0);opacity:1}}
        </style>
        <div class="num" id="num"></div>
        <div class="cap"><b>${(CD_STRINGS[uiLang] || CD_STRINGS.en).bold}</b><small>${(CD_STRINGS[uiLang] || CD_STRINGS.en).small}</small></div>`;
      (document.documentElement || document.body).appendChild(host);
      numEl = sh.getElementById("num");
    }

    function show(n) {
      if (n >= 1) {
        ensure();
        numEl.textContent = String(n);
        // Restart the pop animation on each tick.
        numEl.classList.remove("tick");
        void numEl.offsetWidth;
        numEl.classList.add("tick");
      } else {
        remove();
      }
    }

    function remove() {
      host?.remove();
      host = null;
      numEl = null;
    }

    return { show, remove };
  })();

  // rrweb: full DOM recording. Loaded from src/lib/rrweb.min.js (see README for
  // how to vendor it). Guarded so the extension still loads without it. record()
  // emits a full DOM snapshot once up front, then incremental mutations — so it
  // must be (re)started whenever a fresh, replayable stream is needed.
  function startRrweb() {
    if (window.rrweb?.record) {
      rrwebStop = window.rrweb.record({
        emit: emitRaw,
        maskAllInputs: true, // belt-and-suspenders with our own masking
        maskInputOptions: { password: true },
        // maskAllInputs misses rich editors (contenteditable / role=textbox), so
        // free-form text typed into Gmail/Slack/Notion would serialize verbatim.
        // Mask text inside any editable region — on the snapshot and on every
        // typing mutation (rrweb re-tests via closest() per characterData change).
        maskTextSelector: EDITABLE_TEXT_SELECTOR + ",[data-capture-secret]",
        maskTextFn: maskEditableText,
      });
    }
  }

  // Restart: the worker wiped the buffers for a fresh take. Re-emit the full
  // rrweb snapshot + current URL (the cleared events.jsonl has no base snapshot
  // otherwise) so the new take replays from scratch. Listeners + overlay stay.
  function restartCapture() {
    if (!recording) return;
    rrwebStop?.();
    rrwebStop = null;
    emit("nav", { url: location.href });
    startRrweb();
  }

  function startCapture(meta) {
    captureGeneration = meta?.generation ?? captureGeneration;
    capturePaused = !!meta?.paused;
    if (recording) {
      overlay.update({ recording: true, ...(meta || {}) });
      return;
    }
    recording = true;
    capturePaused = !!(meta && meta.paused);
    overlay.mount(meta);
    emit("nav", { url: location.href });
    startRrweb();

    document.addEventListener("click", onClick, true);
    document.addEventListener("input", onChange, true);
    document.addEventListener("change", onChange, true);
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("mousemove", onMove, moveOpts);
    window.addEventListener("popstate", onPopstate);
  }

  function stopCapture() {
    recording = false;
    capturePaused = false;
    rrwebStop?.();
    rrwebStop = null;
    document.removeEventListener("click", onClick, true);
    document.removeEventListener("input", onChange, true);
    document.removeEventListener("change", onChange, true);
    window.removeEventListener("scroll", onScroll);
    window.removeEventListener("focus", onFocus);
    window.removeEventListener("blur", onBlur);
    window.removeEventListener("popstate", onPopstate);
    document.removeEventListener("keydown", onKey, true);
    document.removeEventListener("mousemove", onMove, moveOpts);
    if (dwellTimer) clearTimeout(dwellTimer);
    dwellTimer = null;
    lastHoverSelector = null;
    annotate.teardown();
    countdown.remove(); // clear any lingering pre-roll number
    overlay.unmount();
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // The full paused-aware clock rides along so a tab joining mid-recording shows
    // the right elapsed time (t0, pausedAccum, pauseStartedAt, pauseReason).
    if (msg.type === "start") startCapture(msg);
    if (msg.type === "stop") stopCapture();
    if (msg.type === "restart") {
      captureGeneration = msg.generation ?? captureGeneration;
      capturePaused = !!msg.paused;
      restartCapture();
    }
    // Pre-roll countdown pushed by the worker (n=3..1, then 0 to clear) — shown
    // before capture goes live, while recording is still false.
    if (msg.type === "countdown") countdown.show(msg.n);
    // Worker pushes live state to every tab so all overlays stay in sync
    // (pause/resume, Restart's new t0) regardless of which tab is focused.
    if (msg.type === "overlay-state") {
      capturePaused = !!(msg.state && msg.state.paused);
      captureGeneration = msg.state?.generation ?? captureGeneration;
      overlay.update(msg.state);
    }
    // Live mic loudness (~12/sec) → animate the overlay's level meter.
    if (msg.type === "mic-level") overlay.setMicLevel(msg.level);
    // The worker pings this (via tabs.sendMessage) to check we're already here
    // before injecting a second copy. Answer so it skips re-injection.
    if (msg.type === "is-recording") {
      sendResponse(true);
      return true;
    }
  });

  // If a recording is already in progress when this frame loads (full nav, new
  // page, SPA route), ask the worker so we attach immediately — and show the
  // overlay in the correct state (right elapsed clock, paused or live).
  //
  // This MUST be robust: on a full-page navigation the old content script is
  // destroyed and this brand-new one is the only thing that knows to start
  // recording again. A single fire-and-forget check is fragile — if the worker
  // is momentarily unreachable (waking up, busy) the message is lost and capture
  // silently dies for the rest of the page's life. So retry on transient
  // failure, and stop as soon as we get a definitive answer. The worker ALSO
  // re-pushes `start` on navigation (background.js reattachTab); startCapture is
  // idempotent, so whichever lands first wins and the other is a no-op.
  function selfAttach(attempt = 0) {
    let replied = false;
    const again = () => {
      if (attempt < 5) setTimeout(() => selfAttach(attempt + 1), 300);
    };
    if (!chrome.runtime?.id) return; // context torn down (reload) — don't retry
    try {
      chrome.runtime.sendMessage({ type: "is-recording" }, (res) => {
        replied = true;
        if (chrome.runtime.lastError) return again(); // worker unreachable — retry
        if (res?.recording) startCapture(res); // res carries the full clock
        // res.recording === false is a definitive "not recording" — stop retrying.
      });
    } catch {
      return again();
    }
    // Callback never fired (worker asleep mid-navigation) — retry.
    setTimeout(() => {
      if (!replied) again();
    }, 400);
  }
  selfAttach();
})();
