// ============================================================================
//  KIỂM TRA NHANH CUỐI GIAI ĐOẠN 2: tạo proof thật từ credential rồi verify
//  Chạy:  node scripts/test_proof.js D1
//  Chính sách thử: tài nguyên factory/temperature (Bảng 2.13 Chương 2)
//     minFw = 300, minSec = 3, allowedTypes = [1, 4, 4]
//  (Ở Giai đoạn 3, PDP mới là bên cấp nonce/now và giữ chính sách.
//   Script này tự đóng cả hai vai chỉ để thử "khuôn" của Giai đoạn 1.)
// ============================================================================
import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

const id = process.argv[2] || "D1";
const secret = JSON.parse(readFileSync(`data/devices/${id}/secret.json`));        // do thiết bị tự sinh
const cred = JSON.parse(readFileSync(`data/devices/${id}/credential.json`));   // do Issuer ký
const issuer = JSON.parse(readFileSync("data/public/issuer_public.json"));
const vkey = JSON.parse(readFileSync("build/verification_key.json"));
const WASM = "build/device_posture_js/device_posture.wasm";
const ZKEY = "build/device_posture.zkey";

// --- Phần PDP sẽ cấp: chính sách + now + nonce ---
const policy = { minFw: 300, minSec: 3, allowedTypes: [1, 4, 4] };
const now = Math.floor(Date.now() / 1000);
const nonce = BigInt("0x" + randomBytes(31).toString("hex")).toString();

// --- Đầu vào của mạch: private (từ credential) + public (từ PDP) ---
const input = {
  sk_dev: secret.sk_dev, fw: cred.fw, sec: cred.sec, dtype: cred.dtype, exp: cred.exp,
  R8x: cred.R8x, R8y: cred.R8y, S: cred.S,
  Ax: issuer.Ax, Ay: issuer.Ay,
  minFw: policy.minFw, minSec: policy.minSec, allowedTypes: policy.allowedTypes,
  now, nonce,
};

console.log(`Thiết bị ${id}: fw=${cred.fw}, sec=${cred.sec}, dtype=${cred.dtype}, ` +
  `còn hạn=${cred.exp >= now}  |  Chính sách: fw≥${policy.minFw}, sec≥${policy.minSec}, dtype∈[${policy.allowedTypes}]`);

let proof, publicSignals;
const t0 = performance.now();
try {
  ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY));
} catch (e) {
  console.log(`\n✗ ${id} KHÔNG tạo được proof (${((performance.now() - t0)).toFixed(0)} ms).`);
  console.log(`  Lý do: dữ liệu bí mật không thỏa ít nhất một ràng buộc của mạch.`);
  console.log(`  Chi tiết: ${String(e.message || e).split("\n")[0]}`);
  process.exit(0);
}
const tProve = performance.now() - t0;

const t1 = performance.now();
const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
const tVerify = performance.now() - t1;

const proofBytes = Buffer.byteLength(JSON.stringify(proof));
console.log(`\n✓ ${id} tạo được proof trong ${tProve.toFixed(0)} ms (kích thước JSON ${proofBytes} byte)`);
console.log(`  Verify: ${ok ? "HỢP LỆ" : "KHÔNG HỢP LỆ"} (${tVerify.toFixed(1)} ms)`);

console.log(`\n  Thứ tự publicSignals (10 giá trị PDP nhìn thấy):`);
const names = ["sessionTag", "Ax", "Ay", "minFw", "minSec", "allowedTypes[0]", "allowedTypes[1]", "allowedTypes[2]", "now", "nonce"];
publicSignals.forEach((v, i) => console.log(`   [${i}] ${names[i].padEnd(16)} = ${v.length > 20 ? v.slice(0, 20) + "…" : v}`));
console.log(`\n  Không có fw, sec, dtype, exp, sk_dev hay chữ ký trong publicSignals và proof.`);

// Thử giả mạo: hạ minFw trong publicSignals xuống 100 rồi verify lại (SR6)
const forged = [...publicSignals]; forged[3] = "100";
const okForged = await snarkjs.groth16.verify(vkey, forged, proof);
console.log(`\n  Thử sửa minFw = 100 trong publicSignals rồi verify lại: ${okForged ? "HỢP LỆ (lỗi!)" : "KHÔNG HỢP LỆ – bị phát hiện"}`);
process.exit(0);