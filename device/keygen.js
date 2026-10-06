// ============================================================================
//  GIAI ĐOẠN 2a – THIẾT BỊ TỰ SINH KHÓA (enrollment request)
//  Chạy:  node device/keygen.js D1      (hoặc: node device/keygen.js all)
//  - Thiết bị tự sinh sk_dev ngay trên máy mình, KHÔNG gửi đi đâu
//  - Tính pk_dev = Poseidon(sk_dev) và tạo yêu cầu đăng ký gửi cho Issuer
//  (Thực tế: sk_dev sinh và cất trong chip bảo mật TPM / Secure Element)
// ============================================================================
import { buildPoseidon } from "circomlibjs";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";

const poseidon = await buildPoseidon();
const F = poseidon.F;
const arg = process.argv[2] || "D1";
const ids = arg === "all"
  ? Object.keys(JSON.parse(readFileSync("config/devices.json"))).filter((k) => !k.startsWith("_"))
  : [arg];

mkdirSync("data/enroll", { recursive: true });
for (const id of ids) {
  const dir = `data/devices/${id}`;
  mkdirSync(dir, { recursive: true });
  const secretPath = `${dir}/secret.json`;
  if (existsSync(secretPath)) { console.log(`${id}: đã có khóa, bỏ qua (xóa ${secretPath} nếu muốn sinh lại)`); continue; }

  // Khóa bí mật: số ngẫu nhiên 248 bit (< p của trường BN254)
  const sk_dev = BigInt("0x" + randomBytes(31).toString("hex"));
  const pk_dev = F.toObject(poseidon([sk_dev])).toString();

  // 1) Bí mật: chỉ nằm trên thiết bị
  writeFileSync(secretPath, JSON.stringify({ deviceId: id, sk_dev: sk_dev.toString(),
    _canh_bao: "KHÓA BÍ MẬT CỦA THIẾT BỊ – không bao giờ rời khỏi thiết bị" }, null, 2));
  // 2) Yêu cầu đăng ký: chỉ chứa pk_dev, gửi cho Issuer
  writeFileSync(`data/enroll/${id}.json`, JSON.stringify({ deviceId: id, pk_dev }, null, 2));
  console.log(`${id}: đã sinh sk_dev (giữ lại) và gửi pk_dev = ${pk_dev.slice(0, 16)}… cho Issuer`);
}
process.exit(0);