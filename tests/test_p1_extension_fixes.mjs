// Regression tests for the extension-side P1 fixes (2026-09-13 branch).
// Each test extracts the fixed function from source and mutation-probes it:
// reverting the fix must fail the test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const read = (name) => readFileSync(new URL(`../extension/src/${name}`, import.meta.url), "utf8");
const background = read("background.js");
const redact = read("redact.js");
const content = read("content.js");
const streams = read("bundle-streams.js");

function loadCtx(source, extra = "") {
  const ctx = vm.createContext({ console });
  vm.runInNewContext(source + "\n" + extra, ctx);
  return ctx;
}

test("scrubNode drops the node on scrub failure — never returns it raw", () => {
  // Extract scrubNode + scrubTokens from background.js source.
  const fn = background.match(/function scrubNode\(node\) \{[\s\S]*?\n\}/)[0];
  const redactMod = redact.match(/export const REDACTED[\s\S]*?export function scrubTokens\(text\) \{[\s\S]*?\n\}/)[0]
    .replace(/export /g, "");
  const ctx = vm.createContext({});
  vm.runInNewContext(redactMod + "\n" + fn + "\nglobalThis.scrubNode = scrubNode;", ctx);
  const cyc = {};
  cyc.self = cyc; // JSON.stringify throws → scrub fails
  ctx.cycSelf = cyc;
  const out = vm.runInContext("scrubNode(cycSelf)", ctx);
  assert.ok(!out || !out.self, "a cyclic node must NOT round-trip raw");
  assert.equal(JSON.stringify(out), '{"rrweb":"‹node dropped: scrub failed›"}');
  // and the happy path still scrubs
  const clean = vm.runInContext(
    'scrubNode({ src: "https://x/img.png?jwt=eyJabcdef.ghijklmn.sig" })', ctx);
  assert.ok(!JSON.stringify(clean).includes("eyJabcdef"), "happy path still token-scrubs");
});

test("PEM redaction removes the FULL key block, not just the BEGIN marker", () => {
  function regexFrom(source) {
    const decl = source.match(/const TOKEN_VALUE_RE = new RegExp\([\s\S]*?\n\s*\);/);
    return vm.runInNewContext(decl[0] + "\nTOKEN_VALUE_RE", vm.createContext({}));
  }
  const re = regexFrom(redact);
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
  const scrubbed = pem.replace(re, "‹redacted:secret›");
  assert.ok(!scrubbed.includes("MIIEowIBAAKCAQEA"), "key material must not survive");
  assert.ok(!scrubbed.match(/BEGIN.*PRIVATE KEY/), "the marker must not survive");
  // unterminated PEM → redact to end
  const open = "notes: -----BEGIN PRIVATE KEY-----\nMIIEow";
  assert.ok(!open.replace(regexFrom(redact), "‹redacted:secret›").includes("MIIEow"));
  // content.js mirror stays in lockstep (drift contract)
  assert.equal(regexFrom(content).source, re.source);
});

test("HAR export strips the internal _t0Clock bookkeeping field", () => {
  // The streamFiles strip-list must include _t0Clock, else the frozen one-clock
  // reading leaks into network.har as a confusing underscore field.
  const decl = streams.match(/entries: \(har \|\| \[\]\)\.map\(\(\{[^}]+\}\) => e\)/)[0];
  const fields = decl.match(/\{(.+)\}/)[1].split(",").map((s) => s.trim());
  assert.ok(fields.includes("_t0Clock"), "export strip-list must drop _t0Clock");
});

test("logError scrubs message and stack before persisting", () => {
  // Extract the fixed logError shape: message/stack pass through scrubTokens+redactUrl.
  const fn = background.match(/function logError\(where, info = \{\}\) \{[\s\S]*?\n\}/)[0];
  assert.ok(/scrubTokens\(redactUrl\(s\)\)/.test(fn),
    "logError must scrub via scrubTokens(redactUrl(…)) before persisting");
  // and the redaction imports exist
  assert.match(background, /import \{[^}]*redactUrl[^}]*\} from "\.\/redact\.js"/);
});