// ============================================================================
//  DASHBOARD – máy chủ giám sát và điều khiển
//  Chạy:  node dashboard/server.js   (hoặc npm run dashboard)   rồi mở  http://localhost:3000
//
//  1) GIÁM SÁT – chỉ đọc nhật ký do các thành phần tự ghi:
//       logs/pdp_decisions.csv, logs/pep_events.csv, logs/device_<ID>.csv, logs/pdp_inbox.jsonl
//  2) ĐIỀU KHIỂN – bật/tắt PDP, PEP, từng thiết bị; cấp lại credential; sửa chính sách.
//       Chỉ chạy được đúng các chương trình có sẵn của dự án (không nhận lệnh tùy ý),
//       mọi tham số đều được kiểm tra với devices.json / policies.json.
//       Chỉ lắng nghe 127.0.0.1 và từ chối yêu cầu đến từ trang web khác (kiểm tra Origin).
//  Dashboard KHÔNG đọc secret.json hay credential.json của thiết bị.
// ============================================================================
import http from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync, statSync, openSync, readSync, closeSync, readdirSync } from "node:fs";
import { join, extname } from "node:path";

const PORT = 3000;
const PUBLIC = "dashboard/public";
const HISTORY_MIN = 30;
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
mkdirSync("logs", { recursive: true });

// ---------------------------------------------------------------- Trạng thái giám sát
const devices = {};
const events = [];
let policies = {}, profiles = {};
const clients = new Set();
const health = { pdp: false, pep: false };
let inbox = null;

function loadConfig() {
  try { policies = readJson("config/policies.json"); } catch { policies = {}; }
  try { profiles = readJson("config/devices.json"); } catch { profiles = {}; }
  for (const id of deviceIds())
    devices[id] ??= { id, status: "idle", topic: "", sessionUntil: 0, proveMs: null, authMs: null, msgs: 0, last: 0, note: profiles[id].mo_ta || "" };
}
const deviceIds = () => Object.keys(profiles).filter((k) => !k.startsWith("_")).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
const topicNames = () => Object.keys(policies).filter((k) => !k.startsWith("_"));
const dev = (id) => (devices[id] ??= { id, status: "idle", topic: "", sessionUntil: 0, proveMs: null, authMs: null, msgs: 0, last: 0, note: "" });

// ---------------------------------------------------------------- Đọc log kiểu "tail -f"
const offsets = new Map();
function readNewLines(file) {
  if (!existsSync(file)) return [];
  const size = statSync(file).size;
  let off = offsets.get(file) ?? 0;
  if (size < off) off = 0;
  if (size === off) return [];
  const buf = Buffer.alloc(size - off);
  const fd = openSync(file, "r"); readSync(fd, buf, 0, buf.length, off); closeSync(fd);
  const text = buf.toString("utf8");
  const lastNl = text.lastIndexOf("\n");
  if (lastNl < 0) return [];
  offsets.set(file, off + Buffer.byteLength(text.slice(0, lastNl + 1)));
  return text.slice(0, lastNl).split(/\r?\n/).filter((l) => l && !l.startsWith("time,"));
}

function parsePdp(line) {
  const [time, resource, decision, reason, verifyMs] = line.split(",");
  return { src: "PDP", time: Date.parse(time), kind: decision, topic: resource, reason, verifyMs: verifyMs ? Number(verifyMs) : null };
}
function parsePep(line) {
  const p = line.split(",");
  const [time, clientId, kind, topic] = p;
  return { src: "PEP", time: Date.parse(time), device: clientId.split("-")[0], clientId, kind, topic, detail: p.slice(4).join(",") };
}
function parseDevice(line) {
  const [time, device, topic, kind, proveMs, authMs] = line.split(",");
  return { src: device, time: Date.parse(time), device, kind, topic, proveMs: proveMs ? Number(proveMs) : null, authMs: authMs ? Number(authMs) : null };
}
function summarizeInbox(line) {
  try {
    const e = JSON.parse(line), r = e.received || {};
    return { time: Date.parse(e.time), decision: e.decision, reason: e.reason, verifyMs: e.verify_ms ?? null,
      fields: Object.keys(r), bytes: Buffer.byteLength(JSON.stringify(r)), resource: r.resource, nonce: String(r.nonce ?? ""),
      sessionTag: String(r.sessionTag ?? ""), proof: r.proof ? { A: r.proof.pi_a?.[0], B: r.proof.pi_b?.[0]?.[0], C: r.proof.pi_c?.[0] } : null,
      publicSignals: e.publicSignals };
  } catch { return null; }
}

function apply(ev) {
  if (!ev.device || !/^D\d+$/.test(ev.device)) return null;
  const d = dev(ev.device);
  d.last = ev.time;
  switch (ev.kind) {
    case "AUTH_OK":          Object.assign(d, { status: "connected", topic: ev.topic, proveMs: ev.proveMs, authMs: ev.authMs }); break;
    case "CONNECT_ALLOW": {  const ttl = Number((ev.detail.match(/(\d+)s/) || [])[1] || 0);
                             Object.assign(d, { status: "connected", topic: ev.topic, sessionUntil: ev.time + ttl * 1000 }); break; }
    case "CONNECT_DENY":     Object.assign(d, { status: "denied", topic: ev.topic || d.topic, sessionUntil: 0, reason: ev.detail }); break;
    case "AUTH_DENY":        Object.assign(d, { status: "denied", topic: ev.topic, proveMs: ev.proveMs }); break;
    case "PROOF_FAIL":       Object.assign(d, { status: "nopolicy", topic: ev.topic, sessionUntil: 0 }); break;
    case "SESSION_EXPIRED":
    case "SESSION_END":      Object.assign(d, { status: "reauth", sessionUntil: 0 }); break;
    case "PUBLISH_DENY":     Object.assign(d, { status: "violation", sessionUntil: 0 }); break;
    case "DISCONNECT":       if (d.status === "connected") Object.assign(d, { status: "offline", sessionUntil: 0 }); break;
    case "PUBLISH_OK":       d.msgs++; break;
    case "CHALLENGE_ERR":
    case "PEP_UNREACHABLE":  Object.assign(d, { status: "unreachable", sessionUntil: 0 }); break;
  }
  return d;
}

function broadcast(msg) {
  const data = `data: ${JSON.stringify(msg)}\n\n`;
  for (const res of clients) res.write(data);
}

function poll(initial = false) {
  const batch = [];
  for (const l of readNewLines("logs/pdp_decisions.csv")) batch.push(parsePdp(l));
  for (const l of readNewLines("logs/pep_events.csv")) batch.push(parsePep(l));
  for (const f of readdirSync("logs").filter((f) => /^device_.*\.csv$/.test(f)))
    for (const l of readNewLines(join("logs", f))) batch.push(parseDevice(l));
  batch.sort((a, b) => a.time - b.time);
  const inLines = readNewLines("logs/pdp_inbox.jsonl");
  if (inLines.length) { const last = summarizeInbox(inLines.at(-1));
    if (last && (!initial || last.time > Date.now() - HISTORY_MIN * 60000)) { inbox = last; if (!initial) broadcast({ type: "inbox", inbox }); } }
  const since = Date.now() - HISTORY_MIN * 60000;
  for (const ev of batch) {
    if (initial && ev.time < since) continue;
    const d = apply(ev);
    events.push(ev); if (events.length > 300) events.shift();
    if (!initial) broadcast({ type: "event", ev, device: d });
  }
}

async function ping(url) { try { await fetch(url, { signal: AbortSignal.timeout(800) }); return true; } catch { return false; } }
async function checkHealth() {
  const [pdp, pep] = await Promise.all([ping("http://127.0.0.1:8081/health"), ping("http://127.0.0.1:8080/")]);
  if (pdp !== health.pdp || pep !== health.pep) { Object.assign(health, { pdp, pep }); broadcast({ type: "health", health }); }
}
let polSig = "";
function checkPolicies() {
  try { const s = readFileSync("config/policies.json", "utf8"); if (s !== polSig) { polSig = s; policies = JSON.parse(s); broadcast({ type: "policies", policies }); } } catch {}
}

// ---------------------------------------------------------------- ĐIỀU KHIỂN: quản lý tiến trình
const procs = new Map();     // key -> { key, kind, child, pid, startedAt, meta }
const plogs = new Map();     // key -> [{ t, line }]  (300 dòng gần nhất của mỗi tiến trình)
const ANSI = /\x1b\[[0-9;]*m/g;
const procList = () => [...procs.values()].map(({ key, kind, pid, startedAt, meta }) => ({ key, kind, pid, startedAt, meta }));

function pushLog(key, line) {
  const t = Date.now(), arr = plogs.get(key) ?? [];
  arr.push({ t, line }); if (arr.length > 300) arr.shift(); plogs.set(key, arr);
  broadcast({ type: "plog", key, t, line });
}
function startProc(key, kind, args, env = {}, meta = {}) {
  if (procs.has(key)) throw new Error(`${key} đang chạy`);
  const child = spawn(process.execPath, args, { cwd: process.cwd(), env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const p = { key, kind, child, pid: child.pid, startedAt: Date.now(), meta };
  procs.set(key, p);
  pushLog(key, `▶ node ${args.join(" ")}${Object.keys(env).length ? `   (${Object.entries(env).map(([k, v]) => `${k}=${v}`).join(" ")})` : ""}`);
  for (const stream of [child.stdout, child.stderr]) {
    let buf = "";
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      buf += chunk; const lines = buf.split(/\r?\n/); buf = lines.pop();
      for (const l of lines) if (l.trim()) pushLog(key, l.replace(ANSI, ""));
    });
  }
  child.on("exit", (code, signal) => {
    if (procs.get(key) === p) procs.delete(key);
    pushLog(key, `■ tiến trình kết thúc${signal ? ` (dừng bởi dashboard)` : ` (mã thoát ${code})`}`);
    broadcast({ type: "procs", procs: procList() });
  });
  broadcast({ type: "procs", procs: procList() });
  return p;
}
function stopProc(key) {
  const p = procs.get(key);
  if (!p) throw new Error(`${key} không do dashboard bật hoặc đã dừng`);
  p.child.kill();
}
const stopAll = () => { for (const p of procs.values()) p.child.kill(); };
process.on("SIGINT", () => { stopAll(); process.exit(0); });
process.on("exit", stopAll);

function issuedAt() {
  let t = 0;
  for (const id of deviceIds()) { const f = `data/devices/${id}/credential.json`; if (existsSync(f)) t = Math.max(t, statSync(f).mtimeMs); }
  return t || null;     // chỉ đọc thời điểm tệp được ghi, không đọc nội dung credential
}
const meta = () => ({ ids: deviceIds(), topics: topicNames(),
  profiles: Object.fromEntries(deviceIds().map((id) => [id, { mo_ta: profiles[id].mo_ta || "", dtype: profiles[id].dtype }])), issuedAt: issuedAt() });

// ---------------------------------------------------------------- API điều khiển
const int = (v, lo, hi, name) => { const n = Number(v); if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(`${name} phải là số nguyên từ ${lo} đến ${hi}`); return n; };

async function handleApi(path, body) {
  switch (path) {
    case "/api/pdp":
      if (body.action === "start") {
        if (await ping("http://127.0.0.1:8081/health")) throw new Error("PDP đang chạy ở nơi khác (terminal). Hãy tắt bản đó trước.");
        startProc("pdp", "pdp", ["pdp/pdp.js"]); return { ok: true, msg: "Đã bật PDP" };
      }
      stopProc("pdp"); return { ok: true, msg: "Đã tắt PDP" };
    case "/api/pep":
      if (body.action === "start") {
        if (await ping("http://127.0.0.1:8080/")) throw new Error("PEP đang chạy ở nơi khác (terminal). Hãy tắt bản đó trước.");
        const s = int(body.session ?? 0, 0, 3600, "Thời hạn phiên");
        startProc("pep", "pep", ["pep/pep.js"], s ? { MAX_SESSION: String(s) } : {}, { session: s });
        return { ok: true, msg: `Đã bật PEP${s ? `, phiên tối đa ${s} s` : ", phiên theo chính sách"}` };
      }
      stopProc("pep"); return { ok: true, msg: "Đã tắt PEP" };
    case "/api/device": {
      const id = String(body.id);
      if (!deviceIds().includes(id)) throw new Error("Thiết bị không có trong hồ sơ MDM");
      if (body.action === "start") {
        if (!topicNames().includes(body.topic)) throw new Error("Topic không tồn tại");
        if (!["pub", "sub"].includes(body.mode)) throw new Error("Vai trò phải là gửi hoặc nhận");
        const period = int(body.period ?? 2, 1, 60, "Chu kỳ gửi");
        startProc(`dev:${id}`, "device", ["device/device.js", id, body.topic, body.mode, String(period)], {}, { id, topic: body.topic, mode: body.mode });
        return { ok: true, msg: `Đã bật ${id} – ${body.mode === "pub" ? "gửi vào" : "nhận từ"} ${body.topic}` };
      }
      stopProc(`dev:${id}`); return { ok: true, msg: `Đã dừng ${id}` };
    }
    case "/api/issue":
      if (procs.has("issuer")) throw new Error("Issuer đang chạy");
      startProc("issuer", "issuer", ["issuer/issue.js"]); return { ok: true, msg: "Issuer đang cấp lại credential cho D1–D7" };
    case "/api/policy": {
      const r = String(body.resource);
      const pol = readJson("config/policies.json");
      if (!pol[r] || r.startsWith("_")) throw new Error("Topic không tồn tại");
      const types = (Array.isArray(body.allowedTypes) ? body.allowedTypes : []).map((x) => int(x, 1, 4, "Loại thiết bị"));
      if (!types.length || types.length > 3) throw new Error("Chọn từ 1 đến 3 loại thiết bị");
      const next = { minFw: int(body.minFw, 0, 65535, "minFw"), minSec: int(body.minSec, 0, 255, "minSec"),
        allowedTypes: [...types, types.at(-1), types.at(-1)].slice(0, 3), ttl: int(body.ttl, 5, 3600, "Thời hạn phiên") };
      const old = JSON.stringify(pol[r]);
      pol[r] = next;
      writeFileSync("config/policies.json", JSON.stringify(pol, null, 2));
      appendFileSync("logs/policy_changes.csv", `${new Date().toISOString()},${r},all,${old.replace(/,/g, ";")},${JSON.stringify(next).replace(/,/g, ";")}\n`);
      pushLog("policy", `${r}: ${old}  →  ${JSON.stringify(next)}`);
      checkPolicies();
      return { ok: true, msg: `Đã cập nhật chính sách ${r}. PDP áp dụng ở lần chứng minh kế tiếp.` };
    }
    case "/api/stopall": stopAll(); return { ok: true, msg: "Đã dừng mọi tiến trình do dashboard bật" };
  }
  throw new Error("API không tồn tại");
}

// ---------------------------------------------------------------- Máy chủ web
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };
const sameOrigin = (req) => { const o = req.headers.origin; return !o || o === `http://localhost:${PORT}` || o === `http://127.0.0.1:${PORT}`; };

http.createServer((req, res) => {
  if (req.url === "/events") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    res.write(`data: ${JSON.stringify({ type: "snapshot", devices, events: events.slice(-150), policies, health, inbox, now: Date.now(),
      procs: procList(), plogs: Object.fromEntries([...plogs].map(([k, v]) => [k, v.slice(-200)])), meta: meta() })}\n\n`);
    clients.add(res);
    req.on("close", () => clients.delete(res));
    return;
  }
  if (req.url.startsWith("/api/")) {
    const reply = (code, obj) => { res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify(obj)); };
    if (req.method !== "POST" || !sameOrigin(req) || !String(req.headers["content-type"]).startsWith("application/json")) return reply(403, { ok: false, msg: "Từ chối yêu cầu" });
    let raw = ""; req.on("data", (c) => { raw += c; if (raw.length > 10000) req.destroy(); });
    req.on("end", async () => {
      try { reply(200, await handleApi(req.url, raw ? JSON.parse(raw) : {})); }
      catch (e) { reply(400, { ok: false, msg: e.message }); }
    });
    return;
  }
  const file = join(PUBLIC, req.url === "/" ? "index.html" : req.url.split("?")[0].split("#")[0].replace(/\.\./g, ""));
  if (!existsSync(file) || !statSync(file).isFile()) { res.writeHead(404); return res.end("Không tìm thấy"); }
  res.writeHead(200, { "Content-Type": MIME[extname(file)] || "application/octet-stream" });
  res.end(readFileSync(file));
}).listen(PORT, "127.0.0.1", () => {
  loadConfig(); poll(true); checkHealth(); checkPolicies();
  setInterval(() => poll(false), 400);
  setInterval(checkHealth, 1500);
  setInterval(checkPolicies, 1500);
  setInterval(() => { for (const res of clients) res.write(": ping\n\n"); }, 15000);
  console.log(`[Dashboard] Mở trình duyệt: http://localhost:${PORT}`);
  console.log("[Dashboard] Có thể bật/tắt PDP, PEP và thiết bị ngay trên giao diện. Ctrl+C để thoát (dừng luôn các tiến trình đã bật).");
});
