// ============================================================================
//  KIỂM TRA GIAI ĐOẠN 4: thiết bị kết nối MQTT qua PEP
//  Cần PDP (cửa sổ 1) và PEP (cửa sổ 2) đang chạy.
//  Chạy:  node scripts/test_pep.js D1 factory/temperature
// ============================================================================
import mqtt from "mqtt";
import { loadDevice, createProof } from "../lib/prover.js";

const PEP_HTTP = "http://127.0.0.1:8080", BROKER = "mqtt://127.0.0.1:1883";
const [id = "D1", resource = "factory/temperature"] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Lưu ý MQTT 3.1.1: có password thì BẮT BUỘC có username. username chỉ là nhãn, không dùng để xác thực.
const tryConnect = (label, password) => new Promise((resolve) => {
  const c = mqtt.connect(BROKER, { clientId: `${id}-${label}`, username: password ? "zkp-proof" : undefined,
    password, reconnectPeriod: 0, connectTimeout: 5000 });
  c.once("connect", () => { console.log(`  ${label.padEnd(26)} -> KẾT NỐI ĐƯỢC`); resolve(c); });
  c.once("error", (e) => { console.log(`  ${label.padEnd(26)} -> BỊ TỪ CHỐI (${e.message})`); c.end(true); resolve(null); });
  c.once("close", () => resolve(null));
});

// A. Không có proof
console.log("A. Kết nối không kèm proof:");
await tryConnect("no-proof", undefined);

// B. Luồng chuẩn: xin thử thách qua PEP -> tạo proof -> CONNECT
console.log(`\nB. ${id} xin truy cập ${resource}:`);
const ch = await (await fetch(PEP_HTTP + "/challenge", { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resource }) })).json();
let p;
try { p = await createProof(loadDevice(id), ch); }
catch { console.log(`  ${id} không tạo được proof -> không thể kết nối. Kết thúc.`); process.exit(0); }
const password = JSON.stringify({ resource, nonce: ch.nonce, proof: p.proof, sessionTag: p.sessionTag });
console.log(`  Proof tạo trong ${p.proveMs.toFixed(0)} ms, gói CONNECT mang ${password.length} byte`);
const c = await tryConnect("connect-with-proof", password);
if (!c) process.exit(0);

// C. Publish đúng topic
await c.publishAsync(resource, JSON.stringify({ device: id, value: 27.5, t: Date.now() }), { qos: 1 });
console.log(`  publish vào ${resource.padEnd(21)} -> ĐƯỢC CHẤP NHẬN`);

// D. Subscribe sai topic
try {
  await c.subscribeAsync("factory/admin", { qos: 1 });
  console.log(`  subscribe factory/admin       -> được chấp nhận (lỗi!)`);
} catch (e) { console.log(`  subscribe factory/admin       -> BỊ TỪ CHỐI (SUBACK ${e.packet?.granted?.[0] ?? "lỗi"})`); }

// E. Dùng lại đúng gói CONNECT đó (phát lại)
console.log("\nE. Kẻ tấn công bắt được gói CONNECT và gửi lại:");
await tryConnect("replay-connect", password);

// F. Publish sai topic -> PEP cắt kết nối
console.log("\nF. Publish sang topic không được cấp:");
let closed = false; c.on("close", () => (closed = true));
c.publish("factory/admin", "bat may", { qos: 0 });
await sleep(800);
console.log(`  publish vào factory/admin      -> ${closed ? "BỊ CHẶN, PEP ngắt kết nối" : "không bị chặn (lỗi!)"}`);
c.end(true);

// G. Hết hạn phiên -> PEP tự ngắt, thiết bị phải chứng minh lại (xác thực liên tục)
console.log("\nG. Kết nối mới rồi chờ hết hạn phiên:");
const chG = await (await fetch(PEP_HTTP + "/challenge", { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify({ resource }) })).json();
const pG = await createProof(loadDevice(id), chG);
const cG = await tryConnect("session-test", JSON.stringify({ resource, nonce: chG.nonce, proof: pG.proof, sessionTag: pG.sessionTag }));
if (cG) {
  const tStart = Date.now();
  const closedAfter = await new Promise((r) => { cG.once("close", () => r((Date.now() - tStart) / 1000)); setTimeout(() => r(null), 70000); });
  console.log(closedAfter ? `  PEP ngắt phiên sau ${closedAfter.toFixed(1)} s -> thiết bị phải xin nonce mới và chứng minh lại`
                          : "  Chưa bị ngắt sau 70 s (hãy chạy PEP với MAX_SESSION nhỏ, ví dụ 10)");
  cG.end(true);
}
process.exit(0);