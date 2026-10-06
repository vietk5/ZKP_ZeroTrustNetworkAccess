// ============================================================================
//  GIAI ĐOẠN 4 – PEP (Policy Enforcement Point) gắn vào MQTT broker
//  Chạy:  node pep/pep.js        (MQTT: 127.0.0.1:1883, HTTP thử thách: 127.0.0.1:8080)
//  Biến môi trường tùy chọn: MAX_SESSION=30  -> giới hạn phiên 30 s để demo nhanh
//
//  Thiết bị KHÔNG nói chuyện trực tiếp với PDP. Mọi thứ đi qua PEP:
//   ① HTTP POST /challenge {resource}      -> PEP chuyển cho PDP, trả nonce về thiết bị
//   ② MQTT CONNECT, password = {resource, nonce, proof, sessionTag}
//        -> PEP hỏi PDP /verify -> ALLOW: mở phiên | DENY: từ chối kết nối (CONNACK 5)
//   ③ Mỗi PUBLISH / SUBSCRIBE: chỉ được đúng topic đã chứng minh, còn trong hạn phiên
//   ④ Hết hạn phiên -> PEP chủ động ngắt, thiết bị phải chứng minh lại (xác thực liên tục)
// ============================================================================
import { createServer } from "node:net";
import http from "node:http";
import { Aedes } from "aedes";
import { appendFileSync, mkdirSync, existsSync } from "node:fs";

const PDP = "http://127.0.0.1:8081";
const MQTT_PORT = 1883, HTTP_PORT = 8080;
const MAX_SESSION = Number(process.env.MAX_SESSION || 0);   // 0 = theo ttl của chính sách

mkdirSync("logs", { recursive: true });
const LOG = "logs/pep_events.csv";
if (!existsSync(LOG)) appendFileSync(LOG, "time,clientId,event,topic,detail\n");
const log = (cid, event, topic = "", detail = "") => {
  appendFileSync(LOG, `${new Date().toISOString()},${cid},${event},${topic},${detail}\n`);
  console.log(`[PEP] ${String(cid).padEnd(12)} ${event.padEnd(16)} ${topic.padEnd(20)} ${detail}`);
};
const pdpPost = async (path, body) => (await fetch(PDP + path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })).json();

const aedes = await Aedes.createBroker();

// ---- ② Xác thực khi kết nối: hỏi PDP ----
aedes.authenticate = async (client, username, password, done) => {
  let req;
  try { req = JSON.parse(password?.toString() || ""); } catch { req = null; }
  if (!req?.resource || !req?.proof) {
    log(client.id, "CONNECT_DENY", "", "không có proof");
    const e = new Error("no proof"); e.returnCode = 5; return done(e, false);
  }
  let d;
  try { d = await pdpPost("/verify", req); } catch { d = { decision: "DENY", reason: "PDP_UNREACHABLE" }; }
  if (d.decision !== "ALLOW") {
    log(client.id, "CONNECT_DENY", req.resource, d.reason);
    const e = new Error(d.reason); e.returnCode = 5; return done(e, false);
  }
  const ttl = MAX_SESSION > 0 ? Math.min(d.sessionTtl, MAX_SESSION) : d.sessionTtl;
  client.ztna = { resource: req.resource, expiresAt: Date.now() + ttl * 1000 };
  // ④ Hết hạn phiên -> ngắt, buộc chứng minh lại
  client.ztna.timer = setTimeout(() => { log(client.id, "SESSION_EXPIRED", req.resource, `sau ${ttl}s`); client.close(); }, ttl * 1000);
  log(client.id, "CONNECT_ALLOW", req.resource, `phiên ${ttl}s`);
  done(null, true);
};

// ---- ③ Kiểm soát từng thao tác: chỉ đúng topic đã được cấp quyền ----
const allowed = (client, topic) => client?.ztna && Date.now() < client.ztna.expiresAt && topic === client.ztna.resource;

aedes.authorizePublish = (client, packet, done) => {
  if (!client) return done(null);                       // bản tin nội bộ của broker
  if (!allowed(client, packet.topic)) {
    log(client.id, "PUBLISH_DENY", packet.topic, `chỉ được phép ${client.ztna?.resource}`);
    return done(new Error("not authorized"));           // Aedes sẽ ngắt kết nối vi phạm
  }
  done(null);
};
aedes.authorizeSubscribe = (client, sub, done) => {
  if (!allowed(client, sub.topic)) {
    log(client.id, "SUBSCRIBE_DENY", sub.topic, `chỉ được phép ${client.ztna?.resource}`);
    return done(null, null);                            
  }
  log(client.id, "SUBSCRIBE_OK", sub.topic);
  done(null, sub);
};

aedes.on("publish", (packet, client) => { if (client) log(client.id, "PUBLISH_OK", packet.topic, packet.payload.toString().slice(0, 40)); });
aedes.on("clientDisconnect", (client) => { clearTimeout(client.ztna?.timer); if (client.ztna) log(client.id, "DISCONNECT", client.ztna.resource); });

createServer(aedes.handle).listen(MQTT_PORT, "127.0.0.1", () =>
  console.log(`[PEP] MQTT broker + PEP tại mqtt://127.0.0.1:${MQTT_PORT}`));

// ---- ① Cổng xin thử thách: thiết bị gọi PEP, PEP chuyển cho PDP ----
http.createServer((req, res) => {
  let raw = ""; req.on("data", (c) => (raw += c));
  req.on("end", async () => {
    let out = { error: "NOT_FOUND" }, code = 404;
    if (req.method === "POST" && req.url === "/challenge") {
      try { out = await pdpPost("/challenge", JSON.parse(raw || "{}")); code = out.error ? 404 : 200; }
      catch { out = { error: "PDP_UNREACHABLE" }; code = 502; }
    }
    res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(out));
  });
}).listen(HTTP_PORT, "127.0.0.1", () => {
  console.log(`[PEP] Cổng thử thách tại http://127.0.0.1:${HTTP_PORT}/challenge`);
  console.log(`[PEP] Nhật ký: ${LOG}${MAX_SESSION ? `  |  giới hạn phiên ${MAX_SESSION}s` : ""}`);
});