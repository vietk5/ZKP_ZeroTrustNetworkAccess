// Hàm dùng chung phía THIẾT BỊ: ghép bí mật + credential + thử thách của PDP -> proof
import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";

const WASM = "build/device_posture_js/device_posture.wasm";
const ZKEY = "build/device_posture.zkey";

export function loadDevice(id) {
  return {
    secret: JSON.parse(readFileSync(`data/devices/${id}/secret.json`)),         // tự sinh
    cred: JSON.parse(readFileSync(`data/devices/${id}/credential.json`)),      // Issuer ký
  };
}

// Trả về { proof, sessionTag, proveMs } hoặc ném lỗi nếu thiết bị không thỏa chính sách
export async function createProof({ secret, cred }, ch) {
  const input = {
    // private – chỉ thiết bị biết
    sk_dev: secret.sk_dev, fw: cred.fw, sec: cred.sec, dtype: cred.dtype, exp: cred.exp,
    R8x: cred.R8x, R8y: cred.R8y, S: cred.S,
    // public – lấy nguyên từ thử thách của PDP
    Ax: ch.Ax, Ay: ch.Ay, minFw: ch.minFw, minSec: ch.minSec, allowedTypes: ch.allowedTypes,
    now: ch.now, nonce: ch.nonce,
  };
  const t0 = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, sessionTag: publicSignals[0], proveMs: performance.now() - t0 };
}