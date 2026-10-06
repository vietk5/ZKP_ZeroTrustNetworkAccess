// ============================================================================
//  KIỂM TRA GIAI ĐOẠN 3: đóng vai thiết bị gọi thẳng PDP (chưa có PEP)
//  Chạy (khi PDP đang chạy ở cửa sổ khác):
//     node scripts/test_pdp.js D1 factory/temperature
// ============================================================================
import { loadDevice, createProof } from "../lib/prover.js";

const PDP = "http://127.0.0.1:8081";
const [id = "D1", resource = "factory/temperature"] = process.argv.slice(2);
const post = async (path, body) => (await fetch(PDP + path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
const show = (label, obj) => console.log(`${label.padEnd(44)} -> ${JSON.stringify(obj)}`);

const dev = loadDevice(id);

// 1) Xin thử thách
const ch = await post("/challenge", { resource });
if (ch.error) { show("Xin thử thách", ch); process.exit(0); }
console.log(`[${id}] Nhận thử thách cho ${resource}: nonce=${ch.nonce.slice(0, 12)}…, now=${ch.now}, ` +
  `chính sách fw≥${ch.minFw}, sec≥${ch.minSec}, dtype∈[${ch.allowedTypes}]`);

// 2) Tạo proof
let p;
try { p = await createProof(dev, ch); }
catch { console.log(`[${id}] Không tạo được proof -> không gửi gì cho PDP (thiết bị không đạt chính sách)`); process.exit(0); }
console.log(`[${id}] Tạo proof xong trong ${p.proveMs.toFixed(0)} ms`);

// 3) Gửi proof: chỉ gồm resource, nonce, proof, sessionTag
const msg = { resource, nonce: ch.nonce, proof: p.proof, sessionTag: p.sessionTag };
console.log(`[${id}] Gửi PDP ${Buffer.byteLength(JSON.stringify(msg))} byte, các trường: ${Object.keys(msg).join(", ")}`);
show("① Gửi proof hợp lệ", await post("/verify", msg));

// 4) Các phép thử tấn công
show("② Gửi lại y hệt (phát lại)", await post("/verify", msg));
const ch2 = await post("/challenge", { resource });
show("③ Proof cũ + nonce mới", await post("/verify", { ...msg, nonce: ch2.nonce }));
const other = resource === "factory/camera" ? "factory/temperature" : "factory/camera";
const ch3 = await post("/challenge", { resource: other });
show(`④ Proof cũ dùng cho ${other}`, await post("/verify", { ...msg, resource: other, nonce: ch3.nonce }));
process.exit(0);