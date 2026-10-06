// ============================================================================
//  GIAI ĐOẠN 2b – ISSUER (MDM): ký credential cho thiết bị
//  Chạy:  node issuer/issue.js
//  Đầu vào : data/enroll/<ID>.json      (pk_dev do thiết bị gửi lên)
//            config/devices.json        (thuộc tính MDM đo được: fw, sec, dtype)
//  Xử lý   : C = Poseidon(pk_dev, fw, sec, dtype, exp)
//            sigma = EdDSA-Poseidon(sk_Issuer, C) = (R8x, R8y, S)
//  Đầu ra  : data/devices/<ID>/credential.json  (trả về cho thiết bị)
//            data/public/issuer_public.json     (khóa công khai, giao cho PDP)
//  Issuer KHÔNG BAO GIỜ thấy sk_dev.
// ============================================================================
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";

const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const toStr = (x) => F.toObject(x).toString();

mkdirSync("data/issuer", { recursive: true });
mkdirSync("data/public", { recursive: true });

// ---- 1) Khóa Issuer: chỉ sinh một lần, các lần sau nạp lại ----
const privPath = "data/issuer/issuer_private.json";
let issuerPriv;
if (existsSync(privPath)) {
  issuerPriv = Buffer.from(JSON.parse(readFileSync(privPath)).privateKey, "hex");
  console.log("Đã nạp khóa bí mật Issuer có sẵn.");
} else {
  issuerPriv = randomBytes(32);
  writeFileSync(privPath, JSON.stringify({ privateKey: issuerPriv.toString("hex"),
    _canh_bao: "KHÓA BÍ MẬT CỦA ISSUER – không bao giờ gửi cho PDP hay thiết bị" }, null, 2));
  console.log("Đã sinh khóa bí mật Issuer mới.");
}
const [Ax, Ay] = eddsa.prv2pub(issuerPriv);
writeFileSync("data/public/issuer_public.json", JSON.stringify({ Ax: toStr(Ax), Ay: toStr(Ay) }, null, 2));
console.log(`Khóa công khai Issuer (giao cho PDP):\n  Ax = ${toStr(Ax)}\n  Ay = ${toStr(Ay)}\n`);

// ---- 2) Ký credential cho từng yêu cầu đăng ký ----
const profiles = JSON.parse(readFileSync("config/devices.json"));
const now = Math.floor(Date.now() / 1000);
const rows = [];

for (const file of readdirSync("data/enroll").filter((f) => f.endsWith(".json"))) {
  const { deviceId: id, pk_dev } = JSON.parse(readFileSync(`data/enroll/${file}`));
  const d = profiles[id];
  if (!d) { console.log(`${id}: không có trong hồ sơ MDM -> TỪ CHỐI cấp credential`); continue; }

  const exp = now + d.validHours * 3600;                            // hạn credential
  const C = poseidon([BigInt(pk_dev), d.fw, d.sec, d.dtype, exp]);  // commitment
  const sig = eddsa.signPoseidon(issuerPriv, C);                    // chữ ký Issuer
  if (!eddsa.verifyPoseidon(C, sig, [Ax, Ay])) throw new Error(`Chữ ký của ${id} lỗi`);

  mkdirSync(`data/devices/${id}`, { recursive: true });
  writeFileSync(`data/devices/${id}/credential.json`, JSON.stringify({
    deviceId: id, fw: d.fw, sec: d.sec, dtype: d.dtype, exp,
    R8x: toStr(sig.R8[0]), R8y: toStr(sig.R8[1]), S: sig.S.toString(), issuedAt: now,
  }, null, 2));
  rows.push({ id, fw: d.fw, sec: d.sec, dtype: d.dtype,
    het_han: new Date(exp * 1000).toLocaleString("vi-VN"), C: toStr(C).slice(0, 12) + "…" });
}

console.table(rows);
console.log("Đã trả credential về data/devices/<ID>/credential.json");
process.exit(0);