// Turn the bulk IndexedDB capture streams into Capture-Bundle file entries.
//
// These streams (the rrweb DOM log, the merged timeline, the HAR, and the frame
// PNGs) are the BIG part of a bundle — a long recording's events.jsonl + frames
// can be tens of MB, and network.har grows with every request made. They must never
// be shipped through chrome.runtime.sendMessage (hard-capped at 64MiB) or
// base64-inflated into a data: URL. So the assembly that touches them
// reads straight from IndexedDB in whichever context owns the destination:
//   - normal export: the OFFSCREEN document (it already holds the video Blob and can
//     createWritable()/createObjectURL at any size);
//   - crash salvage: the SERVICE WORKER (no offscreen doc to lean on).
// Both call these pure helpers, so the two sites can't drift. No chrome.* here —
// unit-tested in tests/test_bundle_streams.mjs.

// data: URL ("data:image/png;base64,AAAA…") -> the raw bytes. Used for the frame
// PNGs, which are stored in IndexedDB as data URLs from captureVisibleTab.
export function dataUrlToBytes(dataUrl) {
  const b64 = (dataUrl || "").split(",")[1] || "";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Project a frame's IndexedDB record down to the manifest's {t, file} shape without
// carrying the (large) dataUrl — so the worker can build manifest.frames from the
// frame metadata alone, never loading the image bytes into the service worker.
export function frameMeta(frames) {
  return (frames || []).map((f) => ({ t: f.t, file: f.file }));
}

// The bulk streams as bundle files. `timeline`/`rrweb`/`frames`/`har` are the raw
// IndexedDB records (each may carry an autoincrement `seq` key, stripped here).
// Frames become real PNG bytes under their stored `file` name (e.g. frames/…png).
//
// network.har belongs HERE, not with the worker's small meta files: a per-body cap
// bounds each entry but nothing bounds the entry COUNT, so a chatty app over a long
// take pushed the meta payload past sendMessage's 64MiB cap and killed the export
// outright. Assembled from IndexedDB in whichever context owns the destination, like
// every other unbounded stream. `_`-prefixed fields are worker bookkeeping and the
// requestId is the store's key — neither belongs in an exported HAR.
export function streamFiles(timeline, rrweb, frames, har, t0Wall) {
  const tl = (timeline || []).map(({ seq, ...e }) => e);
  const rr = (rrweb || []).map(({ seq, ...e }) => e);
  const log = {
    version: "1.2",
    creator: { name: "browser-activity-capture", version: "0.1.0" },
    comment: `t0_wall=${t0Wall}. Auth headers and cookies redacted before write.`,
    // HAR permits custom underscore fields. Keep the recording clock and source
    // tab: wall-clock subtraction cannot reconstruct pauses.
    entries: (har || []).map(({ seq, _start, _sameSite, _wantBody, _t0Clock, requestId, ...e }) => e),
  };
  const files = [
    { name: "timeline.json", data: JSON.stringify(tl, null, 2) },
    { name: "events.jsonl", data: rr.map((e) => JSON.stringify(e)).join("\n") },
    { name: "network.har", data: JSON.stringify({ log }, null, 2) },
  ];
  for (const f of frames || []) {
    files.push({ name: f.file, data: dataUrlToBytes(f.dataUrl) });
  }
  return files;
}
