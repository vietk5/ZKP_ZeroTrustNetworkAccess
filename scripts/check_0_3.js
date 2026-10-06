// ============================================================================
//  KIỂM TRA TỔNG THỂ GIAI ĐOẠN 0 → 3 (chạy lại bất cứ lúc nào)
//  Chạy:  node scripts/check_0_3.js
//  Script tự bật PDP (nếu chưa chạy), kiểm tra từng giai đoạn, in bảng ĐẠT/LỖI
//  và lưu kết quả vào results/check_0_3.csv
// ============================================================================
import * as snarkjs from "snarkjs";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import { spawn } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { loadDevice, createProof } from "../lib/prover.js";

const results = [];
const check = (stage, name, ok, detail = "") => {
  results.push({ stage, name, ok, detail });
  console.log(`  ${ok ? "✔ ĐẠT" : "✘ LỖI"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const readJson = (p) => JSON.parse(readFileSync(p));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- Giai đoạn 0
console.log("\n=== GIAI ĐOẠN 0 – Môi trường ===");
const nodeMajor = Number(process.versions.node.split(".")[0]);
check(0, `Node.js ≥ 20`, nodeMajor >= 20, `v${process.versions.node}`);
const want = { snarkjs: "0.7.6", circomlib: "2.0.5", circomlibjs: "0.1.7", aedes: "1.2.0", mqtt: "5.16.0" };
for (const [pkg, v] of Object.entries(want)) {
  const got = existsSync(`node_modules/${pkg}/package.json`) ? readJson(`node_modules/${pkg}/package.json`).version : "chưa cài";
  check(0, `Thư viện ${pkg} = ${v}`, got === v, got);
}

// ---------------------------------------------------------------- Giai đoạn 1
console.log("\n=== GIAI ĐOẠN 1 – Mạch và trusted setup ===");
const files = { r1cs: "build/device_posture.r1cs", wasm: "build/device_posture_js/device_posture.wasm",
  zkey: "build/device_posture.zkey", vkey: "build/verification_key.json", ptau: "build/pot14_final.ptau" };
for (const [k, f] of Object.entries(files))
  check(1, `Có file ${f}`, existsSync(f), existsSync(f) ? `${statSync(f).size.toLocaleString("vi-VN")} byte` : "thiếu");
const info = await snarkjs.r1cs.info(files.r1cs);
check(1, "Mạch: 9.986 ràng buộc, 9 public, 8 private, 1 output",
  info.nConstraints === 9986 && info.nPubInputs === 9 && info.nPrvInputs === 8 && info.nOutputs === 1,
  `${info.nConstraints} / ${info.nPubInputs} / ${info.nPrvInputs} / ${info.nOutputs}`);
const vkey = readJson(files.vkey);
check(1, "Verification key: groth16, bn128, nPublic = 10, IC = 11 điểm",
  vkey.protocol === "groth16" && vkey.curve === "bn128" && vkey.nPublic === 10 && vkey.IC.length === 11,
  `${vkey.protocol}, ${vkey.curve}, ${vkey.nPublic}, ${vkey.IC.length}`);
process.stdout.write("  … đang kiểm tra zkey khớp mạch và ptau (mất vài giây)\r");
const t0 = performance.now();
const zkOk = await snarkjs.zKey.verifyFromR1cs(files.r1cs, files.ptau, files.zkey);
process.stdout.write(" ".repeat(70) + "\r");
check(1, "zkey sinh đúng từ mạch này và ptau này (ZKey Ok)", zkOk, `${((performance.now() - t0) / 1000).toFixed(1)} s`);

// ---------------------------------------------------------------- Giai đoạn 2
console.log("\n=== GIAI ĐOẠN 2 – Thiết bị tự sinh khóa, Issuer ký credential ===");
const eddsa = await buildEddsa(), poseidon = await buildPoseidon(), F = poseidon.F;
const issuer = readJson("data/public/issuer_public.json");
const profiles = readJson("config/devices.json");
const ids = Object.keys(profiles).filter((k) => !k.startsWith("_"));
const nowS = Math.floor(Date.now() / 1000);
const expiredWarn = [];
for (const id of ids) {
  const enroll = readJson(`data/enroll/${id}.json`);
  const { secret, cred } = loadDevice(id);
  const pk = F.toObject(poseidon([BigInt(secret.sk_dev)])).toString();
  const C = poseidon([BigInt(enroll.pk_dev), cred.fw, cred.sec, cred.dtype, cred.exp]);
  const sigOk = eddsa.verifyPoseidon(C, { R8: [F.e(cred.R8x), F.e(cred.R8y)], S: BigInt(cred.S) }, [F.e(issuer.Ax), F.e(issuer.Ay)]);
  const onlyPk = Object.keys(enroll).sort().join(",") === "deviceId,pk_dev";
  const noSkInCred = !("sk_dev" in cred);
  const p = profiles[id];
  const attrsOk = cred.fw === p.fw && cred.sec === p.sec && cred.dtype === p.dtype;
  const expOk = cred.exp === cred.issuedAt + p.validHours * 3600;          // hạn đúng theo hồ sơ
  if (p.validHours > 0 && cred.exp < nowS) expiredWarn.push(id);
  check(2, `${id}: pk_dev khớp sk_dev, yêu cầu đăng ký chỉ có pk_dev, credential không chứa sk_dev, chữ ký Issuer hợp lệ, thuộc tính và hạn đúng hồ sơ`,
    pk === enroll.pk_dev && onlyPk && noSkInCred && sigOk && attrsOk && expOk,
    `pk ${pk === enroll.pk_dev ? "khớp" : "SAI"}, chữ ký ${sigOk ? "hợp lệ" : "SAI"}, hạn ${cred.exp > nowS ? "còn" : "hết"}`);
}
if (expiredWarn.length) console.log(`  ⚠ Credential của ${expiredWarn.join(", ")} đã quá hạn 24 giờ – đây là cơ chế thu hồi đang hoạt động.\n    Muốn các thiết bị này được ALLOW trở lại: chạy  node issuer/issue.js  để MDM cấp lại credential.`);

// ---------------------------------------------------------------- Giai đoạn 3
console.log("\n=== GIAI ĐOẠN 3 – PDP ===");
const PDP = "http://127.0.0.1:8081";
const post = async (path, body) => (await fetch(PDP + path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();
let pdpProc = null;
const healthy = async () => { try { return (await (await fetch(PDP + "/health")).json()).ok; } catch { return false; } };
if (!(await healthy())) {
  pdpProc = spawn(process.execPath, ["pdp/pdp.js"], { stdio: "ignore" });
  for (let i = 0; i < 50 && !(await healthy()); i++) await sleep(200);
}
check(3, "PDP đang chạy và trả lời /health", await healthy(), pdpProc ? "script tự bật PDP" : "dùng PDP đang chạy sẵn");

// Tạo proof nhưng tắt dòng ERROR của bộ tính witness cho gọn màn hình
const quietProof = async (dev, ch) => {
  const [l, e] = [console.log, console.error]; console.log = console.error = () => {};
  try { return await createProof(dev, ch); } catch { return null; } finally { console.log = l; console.error = e; }
};

// 3a) Ma trận D1–D7 × 4 tài nguyên: kết quả thật so với kỳ vọng tính từ thuộc tính
console.log("\n  Ma trận quyết định (kỳ vọng = tính trực tiếp từ thuộc tính và chính sách):");
const policies = readJson("config/policies.json");
const resources = Object.keys(policies).filter((k) => !k.startsWith("_"));
const matrix = [];
let proveTimes = [];
for (const id of ids) {
  const dev = loadDevice(id); const c = dev.cred; const row = { thiet_bi: id };
  for (const r of resources) {
    const pol = policies[r];
    const expected = c.fw >= pol.minFw && c.sec >= pol.minSec && pol.allowedTypes.includes(c.dtype) && c.exp >= Math.floor(Date.now() / 1000) ? "ALLOW" : "DENY";
    const ch = await post("/challenge", { resource: r });
    const p = await quietProof(dev, ch);
    let actual = "DENY";
    if (p) { proveTimes.push(p.proveMs); actual = (await post("/verify", { resource: r, nonce: ch.nonce, proof: p.proof, sessionTag: p.sessionTag })).decision; }
    row[r.replace("factory/", "")] = actual === expected ? actual : `${actual}≠${expected}`;
    results.push({ stage: 3, name: `Ma trận ${id} × ${r}`, ok: actual === expected, detail: `kỳ vọng ${expected}, thực tế ${actual}` });
  }
  matrix.push(row);
}
console.table(matrix);
const mOk = results.filter((x) => x.name.startsWith("Ma trận")).every((x) => x.ok);
check(3, `Ma trận ${ids.length}×${resources.length} = ${ids.length * resources.length} ca khớp kỳ vọng`, mOk,
  `${results.filter((x) => x.name.startsWith("Ma trận") && x.ok).length}/${ids.length * resources.length} ca; prove trung bình ${(proveTimes.reduce((a, b) => a + b, 0) / proveTimes.length).toFixed(0)} ms`);

// 3b) Các phép thử tấn công với D1 trên factory/temperature
console.log("\n  Các phép thử tấn công (D1, factory/temperature):");
const R = "factory/temperature", dev1 = loadDevice("D1");
const ch1 = await post("/challenge", { resource: R });
const p1 = await quietProof(dev1, ch1);
const msg = { resource: R, nonce: ch1.nonce, proof: p1.proof, sessionTag: p1.sessionTag };
const tests = [];
tests.push(["Proof hợp lệ được ALLOW", "ALLOW", (await post("/verify", msg)).decision]);
tests.push(["Phát lại y hệt bị chặn (nonce đã dùng)", "NONCE_UNKNOWN_OR_USED", (await post("/verify", msg)).reason]);
const ch2 = await post("/challenge", { resource: R });
tests.push(["Proof cũ + nonce mới bị chặn", "PROOF_INVALID", (await post("/verify", { ...msg, nonce: ch2.nonce })).reason]);
const ch3 = await post("/challenge", { resource: "factory/camera" });
tests.push(["Proof temperature dùng cho camera bị chặn", "PROOF_INVALID", (await post("/verify", { ...msg, resource: "factory/camera", nonce: ch3.nonce })).reason]);
const ch4 = await post("/challenge", { resource: R });
const p4 = await quietProof(dev1, ch4);
const bad = JSON.parse(JSON.stringify(p4.proof)); bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
tests.push(["Proof bị sửa 1 số bị chặn", "PROOF_INVALID", (await post("/verify", { resource: R, nonce: ch4.nonce, proof: bad, sessionTag: p4.sessionTag })).reason]);
const ch5 = await post("/challenge", { resource: R });
const p5 = await quietProof(dev1, ch5);
tests.push(["sessionTag giả bị chặn", "PROOF_INVALID", (await post("/verify", { resource: R, nonce: ch5.nonce, proof: p5.proof, sessionTag: "12345" })).reason]);
const ch6 = await post("/challenge", { resource: R });
tests.push(["Nonce xin cho temperature dùng cho humidity bị chặn", "RESOURCE_MISMATCH", (await post("/verify", { ...msg, resource: "factory/humidity", nonce: ch6.nonce })).reason]);
tests.push(["Nonce tự bịa bị chặn", "NONCE_UNKNOWN_OR_USED", (await post("/verify", { ...msg, nonce: "999" })).reason]);
tests.push(["Xin thử thách cho tài nguyên không tồn tại bị từ chối", "UNKNOWN_RESOURCE", (await post("/challenge", { resource: "factory/khong-co" })).error]);
for (const [name, exp, got] of tests) check(3, name, got === exp, got);

// 3c) Nhật ký PDP không chứa thuộc tính
const logTxt = readFileSync("logs/pdp_decisions.csv", "utf8");
const header = logTxt.split("\n")[0];
check(3, "Nhật ký PDP không có cột fw, sec, dtype, exp, sk_dev", !/fw|sec|dtype|exp|sk_dev/i.test(header), header);

if (pdpProc) pdpProc.kill();

// ---------------------------------------------------------------- Tổng kết
const pass = results.filter((r) => r.ok).length;
console.log(`\n=== TỔNG KẾT: ${pass}/${results.length} mục ĐẠT ${pass === results.length ? "✔" : "✘"} ===`);
for (const s of [0, 1, 2, 3]) {
  const rs = results.filter((r) => r.stage === s);
  console.log(`  Giai đoạn ${s}: ${rs.filter((r) => r.ok).length}/${rs.length}`);
}
mkdirSync("results", { recursive: true });
writeFileSync("results/check_0_3.csv", "stage,check,ok,detail\n" +
  results.map((r) => `${r.stage},"${r.name}",${r.ok},"${String(r.detail).replace(/"/g, "'")}"`).join("\n"));
console.log("  Chi tiết: results/check_0_3.csv");
process.exit(pass === results.length ? 0 : 1);