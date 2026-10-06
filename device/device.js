// ============================================================================
//  GIAI ĐOẠN 5 – CHƯƠNG TRÌNH THIẾT BỊ CHẠY LIÊN TỤC (Prover)
//  Chạy:  node device/device.js <ID> <topic> <pub|sub> [chu_kỳ_giây]
//   vd:   node device/device.js D1 factory/temperature pub 2   (cảm biến gửi dữ liệu)
//         node device/device.js D5 factory/temperature sub     (gateway nhận dữ liệu)
//  Vòng đời: xin nonce -> tạo proof -> CONNECT -> làm việc -> hết phiên -> chứng minh lại
//  Nếu không còn đạt chính sách: không tạo được proof -> mất quyền, thử lại sau 10 s
// ============================================================================
import mqtt from "mqtt";
import { appendFileSync, mkdirSync, existsSync } from "node:fs";
import { loadDevice, createProof } from "../lib/prover.js";

const [id = "D1", topic = "factory/temperature", mode = "pub", periodArg = "2"] = process.argv.slice(2);
const PEP_HTTP = "http://127.0.0.1:8080", BROKER = "mqtt://127.0.0.1:1883";
const PERIOD = Number(periodArg) * 1000, RETRY = 10000;
const dev = loadDevice(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hhmmss = () => new Date().toLocaleTimeString("vi-VN");

mkdirSync("logs", { recursive: true });
const LOG = `logs/device_${id}.csv`;
if (!existsSync(LOG)) appendFileSync(LOG, "time,device,topic,event,prove_ms,auth_ms\n");
const log = (event, proveMs = "", authMs = "", note = "") => {
  appendFileSync(LOG, `${new Date().toISOString()},${id},${topic},${event},${proveMs},${authMs}\n`);
  console.log(`[${hhmmss()}] [${id}] ${event.padEnd(14)} ${note}`);
};

// Giá trị cảm biến giả lập theo loại tài nguyên
const reading = () => topic.includes("temperature") ? { temp_C: +(25 + Math.random() * 5).toFixed(2) }
  : topic.includes("humidity") ? { humidity_pct: +(50 + Math.random() * 20).toFixed(1) }
  : { frame: Math.floor(Math.random() * 1e6) };

// Một lần xác thực: xin nonce -> proof -> CONNECT. Trả về client hoặc null
let lastFail = "";
async function authenticate(round) {
  lastFail = "";
  const t0 = performance.now();
  let ch;
  try {
    ch = await (await fetch(PEP_HTTP + "/challenge", { method: "POST",
      headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resource: topic }) })).json();
  } catch { log("PEP_UNREACHABLE", "", "", "không gọi được PEP"); return null; }
  if (ch.error) { log("CHALLENGE_ERR", "", "", ch.error); return null; }

  let p;
  const [l, e] = [console.log, console.error]; console.log = console.error = () => {};
  try { p = await createProof(dev, ch); } catch { p = null; } finally { console.log = l; console.error = e; }
  if (!p) { lastFail = "PROOF_FAIL"; log("PROOF_FAIL", "", "", "không còn đạt chính sách -> không tạo được proof"); return null; }

  const password = JSON.stringify({ resource: topic, nonce: ch.nonce, proof: p.proof, sessionTag: p.sessionTag });
  const client = await new Promise((resolve) => {
    const c = mqtt.connect(BROKER, { clientId: `${id}-r${round}`, username: "zkp-proof", password,
      reconnectPeriod: 0, connectTimeout: 5000 });
    c.once("connect", () => resolve(c));
    c.once("error", () => { c.end(true); resolve(null); });
    c.once("close", () => resolve(null));
  });
  const authMs = (performance.now() - t0).toFixed(0);
  if (!client) { lastFail = "AUTH_DENY"; log("AUTH_DENY", p.proveMs.toFixed(0), authMs, "PEP/PDP từ chối"); return null; }
  log("AUTH_OK", p.proveMs.toFixed(0), authMs, `được cấp quyền ${mode === "pub" ? "gửi vào" : "đọc"} ${topic} (prove ${p.proveMs.toFixed(0)} ms, tổng ${authMs} ms)`);
  return client;
}

// Một phiên làm việc: chạy đến khi PEP ngắt
async function work(client) {
  return new Promise(async (resolve) => {
    let timer = null;
    client.once("close", () => { clearInterval(timer); resolve(); });
    if (mode === "sub") {
      client.on("message", (t, msg) => console.log(`[${hhmmss()}] [${id}]   nhận ${t}: ${msg}`));
      try { await client.subscribeAsync(topic, { qos: 0 }); } catch { log("SUB_DENY"); client.end(true); }
    } else {
      const send = () => { const v = { device: id, ...reading(), t: Date.now() };
        client.publish(topic, JSON.stringify(v)); console.log(`[${hhmmss()}] [${id}]   gửi ${JSON.stringify(v)}`); };
      send(); timer = setInterval(send, PERIOD);
    }
  });
}

console.log(`Thiết bị ${id} | tài nguyên ${topic} | chế độ ${mode === "pub" ? "GỬI dữ liệu" : "NHẬN dữ liệu"} | nhật ký ${LOG}`);
let denyStreak = 0;
for (let round = 1; ; round++) {
  const client = await authenticate(round);
  if (!client) {
    // AUTH_DENY lần đầu: có thể chính sách vừa đổi giữa lúc xin nonce và lúc verify -> xin nonce mới ngay
    // Các trường hợp khác (không tạo được proof, bị từ chối liên tiếp): thử lại sau 10 s
    denyStreak = lastFail === "AUTH_DENY" ? denyStreak + 1 : 0;
    await sleep(denyStreak === 1 ? 500 : RETRY);
    continue;
  }
  denyStreak = 0;
  await work(client);
  log("SESSION_END", "", "", "PEP ngắt phiên -> chứng minh lại");
  await sleep(500);
}