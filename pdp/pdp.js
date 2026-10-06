// ============================================================================
//  GIAI ĐOẠN 3 – PDP (Policy Decision Point) = Policy Engine + Policy Administrator
//  Chạy:  node pdp/pdp.js         (port 8081)
//
//  PDP giữ 3 thứ:
//    - config/policies.json          chính sách theo từng tài nguyên - điều kiện để có thể truy cập vào các kênh dữ liệu
//    - data/public/issuer_public.json khóa công khai Issuer (Ax, Ay)
//    - build/verification_key.json    verification key Groth16
//
//  API:
//    POST /challenge { resource }                         -> nonce, now, tham số chính sách
//    POST /verify    { resource, nonce, proof, sessionTag } -> ALLOW / DENY
// ============================================================================
import http from "node:http";
import * as snarkjs from "snarkjs";
import { randomBytes } from "node:crypto";
import { readFileSync, appendFileSync, mkdirSync, existsSync } from "node:fs";

const PORT = 8081;
const NONCE_TTL = 60;                 // nonce chỉ sống 60 giây
const vkey = JSON.parse(readFileSync("build/verification_key.json"));
const issuer = JSON.parse(readFileSync("data/public/issuer_public.json"));
const loadPolicies = () => JSON.parse(readFileSync("config/policies.json")); // đọc lại mỗi lần -> đổi chính sách có hiệu lực ngay

const pending = new Map();            // nonce -> { resource, now, expiresAt }  (nonce đã cấp, chưa dùng)
const usedTags = new Set();           // sessionTag đã chấp nhận (chống dùng lại)
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

mkdirSync("logs", { recursive: true });
const LOG = "logs/pdp_decisions.csv";
if (!existsSync(LOG)) appendFileSync(LOG, "time,resource,decision,reason,verify_ms,sessionTag_prefix\n");
const log = (resource, decision, reason, ms = "", tag = "") => {
  appendFileSync(LOG, `${new Date().toISOString()},${resource},${decision},${reason},${ms},${String(tag).slice(0, 12)}\n`);
  console.log(`[PDP] ${decision.padEnd(5)} ${resource.padEnd(20)} ${reason}${ms !== "" ? `  (verify ${ms} ms)` : ""}`);
};

// ---- Bước 1: cấp thử thách (nonce) cho một tài nguyên ----
function challenge({ resource }) {
  const policy = loadPolicies()[resource];
  if (!policy) return { status: 404, body: { error: "UNKNOWN_RESOURCE" } };
  const nonce = (BigInt("0x" + randomBytes(31).toString("hex")) % FIELD_P).toString();
  const now = Math.floor(Date.now() / 1000);
  pending.set(nonce, { resource, now, expiresAt: now + NONCE_TTL });
  // Trả về đúng các public input thiết bị cần để tạo proof 
  return { status: 200, body: { resource, nonce, now, Ax: issuer.Ax, Ay: issuer.Ay,
    minFw: policy.minFw, minSec: policy.minSec, allowedTypes: policy.allowedTypes, nonceTtl: NONCE_TTL } };
}

// ---- Bước 2: kiểm tra proof và ra quyết định ----
async function verify({ resource, nonce, proof, sessionTag }) {
  const deny = (reason, ms, tag) => { log(resource ?? "?", "DENY", reason, ms, tag); return { status: 200, body: { decision: "DENY", reason } }; };

  if (!resource || !nonce || !proof || !sessionTag) return deny("BAD_REQUEST");
  // (a) Nonce phải do chính PDP cấp và CHƯA dùng: xóa ngay khi đọc -> mỗi nonce chỉ dùng 1 lần (SR5)
  const ch = pending.get(nonce);
  pending.delete(nonce);
  if (!ch) return deny("NONCE_UNKNOWN_OR_USED");
  if (Math.floor(Date.now() / 1000) > ch.expiresAt) return deny("NONCE_EXPIRED");
  // (b) Nonce được cấp cho tài nguyên nào thì chỉ dùng cho tài nguyên đó
  if (ch.resource !== resource) return deny("RESOURCE_MISMATCH");
  const policy = loadPolicies()[resource];
  if (!policy) return deny("UNKNOWN_RESOURCE");
  // (c) PDP TỰ DỰNG LẠI public input từ dữ liệu của mình, không tin số liệu thiết bị gửi (SR6)
  //     Thứ tự: [sessionTag, Ax, Ay, minFw, minSec, allowedTypes[0..2], now, nonce]
  const publicSignals = [String(sessionTag), issuer.Ax, issuer.Ay, String(policy.minFw), String(policy.minSec),
    ...policy.allowedTypes.map(String), String(ch.now), String(nonce)];
  // (d) Kiểm tra proof Groth16: e(A,B) = e(α,β)·e(L,γ)·e(C,δ)
  const t0 = performance.now();
  let ok = false;
  try { ok = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { ok = false; }
  const ms = (performance.now() - t0).toFixed(1);
  if (!ok) return deny("PROOF_INVALID", ms, sessionTag);
  // (e) sessionTag đã dùng thì từ chối (lớp phòng thủ bổ sung chống phát lại)
  if (usedTags.has(String(sessionTag))) return deny("TAG_REUSED", ms, sessionTag);
  usedTags.add(String(sessionTag));

  log(resource, "ALLOW", "OK", ms, sessionTag);
  return { status: 200, body: { decision: "ALLOW", resource, sessionTtl: policy.ttl,
    sessionExpiresAt: Math.floor(Date.now() / 1000) + policy.ttl } };
}

// Dọn nonce hết hạn mỗi 30 giây
setInterval(() => { const t = Math.floor(Date.now() / 1000); for (const [n, c] of pending) if (t > c.expiresAt) pending.delete(n); }, 30000);

http.createServer(async (req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", async () => {
    let out = { status: 404, body: { error: "NOT_FOUND" } };
    try {
      const body = raw ? JSON.parse(raw) : {};
      if (req.method === "POST" && req.url === "/challenge") out = challenge(body);
      else if (req.method === "POST" && req.url === "/verify") out = await verify(body);
      else if (req.method === "GET" && req.url === "/health") out = { status: 200, body: { ok: true, pendingNonces: pending.size } };
    } catch (e) { out = { status: 400, body: { error: "BAD_JSON" } }; }
    res.writeHead(out.status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(out.body));
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log(`[PDP] Đang chạy tại http://127.0.0.1:${PORT}`);
  console.log(`[PDP] Tài nguyên được bảo vệ: ${Object.keys(loadPolicies()).filter((k) => !k.startsWith("_")).join(", ")}`);
  console.log(`[PDP] Nhật ký quyết định: ${LOG}`);
});