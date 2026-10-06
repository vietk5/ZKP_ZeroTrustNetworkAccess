// ============================================================================
//  DASHBOARD – phía trình duyệt: nhận sự kiện qua SSE, vẽ sơ đồ, bảng, nhật ký
// ============================================================================
const SVGNS = "http://www.w3.org/2000/svg";
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
const TYPE_NAME = { 1: "cảm biến nhiệt", 2: "cảm biến ẩm", 3: "camera", 4: "gateway" };
const STATUS = {
  connected: "Đang kết nối", denied: "Bị từ chối", nopolicy: "Không đạt chính sách", reauth: "Đang chứng minh lại",
  violation: "Vi phạm, bị ngắt", unreachable: "Không gọi được PEP/PDP", offline: "Đã ngắt", idle: "Chưa hoạt động",
};
// Nhãn ngắn dùng trong sơ đồ (ô thiết bị hẹp)
const SHORT = { connected: "Đang kết nối", denied: "Bị từ chối", nopolicy: "Không đạt", reauth: "Chứng minh lại",
  violation: "Vi phạm", unreachable: "Mất PDP/PEP", offline: "Đã ngắt", idle: "Chưa hoạt động" };
const REASON = {
  NONCE_UNKNOWN_OR_USED: "nonce đã dùng hoặc không do PDP cấp (phát lại)", PROOF_INVALID: "proof không hợp lệ",
  RESOURCE_MISMATCH: "nonce xin cho tài nguyên khác", NONCE_EXPIRED: "nonce hết hạn", TAG_REUSED: "sessionTag đã dùng",
  BAD_REQUEST: "thiếu dữ liệu", UNKNOWN_RESOURCE: "tài nguyên không tồn tại", PDP_UNREACHABLE: "không gọi được PDP", OK: "đủ 5 lớp kiểm tra",
};

let devices = {}, policies = {}, events = [];
// Trạng thái hiển thị: phiên "đang kết nối" mà đã quá hạn lâu (log cũ) thì coi như đã ngắt
const effStatus = (d) => (d.status === "connected" && d.sessionUntil && d.sessionUntil < Date.now() - 3000 ? "offline" : d.status);

// ---------------------------------------------------------------- Bố cục sơ đồ (toạ độ trong viewBox 1200×440)
const L = { devX: 40, devW: 200, devH: 36, devY0: 96, devGap: 46, gateX: 470, gateW: 60, gateY: 84, gateH: 336,
            pdpX: 610, pdpY: 14, pdpW: 190, pdpH: 52, topX: 850, topW: 320, topH: 58, topY0: 112, topGap: 76 };
const svg = document.getElementById("mimic");
const el = (tag, attrs = {}, parent = svg) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); parent.appendChild(e); return e; };
const devY = (i) => L.devY0 + i * L.devGap + L.devH / 2;
const topY = (j) => L.topY0 + j * L.topGap + L.topH / 2;
let devIndex = {}, topicIndex = {};
const layers = {};

function drawStatic() {
  svg.innerHTML = "";
  layers.pipes = el("g"); layers.links = el("g"); layers.nodes = el("g"); layers.dots = el("g");
  const ids = Object.keys(devices).sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
  const topics = Object.keys(policies).filter((k) => !k.startsWith("_"));
  devIndex = Object.fromEntries(ids.map((id, i) => [id, i]));
  topicIndex = Object.fromEntries(topics.map((t, j) => [t, j]));

  // Issuer (MDM) và đường cấp credential
  const iss = el("g", { class: "node" }, layers.nodes);
  el("rect", { x: L.devX, y: 14, width: L.devW, height: 52 }, iss);
  el("text", { x: L.devX + 12, y: 37, "font-size": 16, "font-weight": 600 }, iss).textContent = "Issuer (MDM)";
  el("text", { x: L.devX + 12, y: 56, class: "sub" }, iss).textContent = "ký credential, hạn 24 giờ";
  el("path", { class: "pipe cred", d: `M${L.devX + L.devW + 14} 40 H${L.devX + L.devW + 40} V${devY(ids.length - 1)}` }, layers.pipes);

  // Cổng PEP
  const gate = el("g", { class: "gate", id: "gate" }, layers.nodes);
  el("rect", { class: "body", x: L.gateX, y: L.gateY, width: L.gateW, height: L.gateH }, gate);
  const gt = el("text", { x: L.gateX + L.gateW / 2, y: L.gateY + L.gateH / 2, "text-anchor": "middle", "font-size": 15, "font-weight": 600,
    transform: `rotate(-90 ${L.gateX + L.gateW / 2} ${L.gateY + L.gateH / 2})` }, gate);
  gt.textContent = "PEP – cổng kiểm soát";

  // PDP và đường hỏi ý kiến
  const pdp = el("g", { class: "node pdp", id: "pdp" }, layers.nodes);
  el("rect", { x: L.pdpX, y: L.pdpY, width: L.pdpW, height: L.pdpH }, pdp);
  el("text", { x: L.pdpX + 12, y: L.pdpY + 22, "font-size": 16, "font-weight": 600 }, pdp).textContent = "PDP";
  el("text", { x: L.pdpX + 12, y: L.pdpY + 41, class: "sub" }, pdp).textContent = "kiểm tra proof Groth16";
  el("path", { class: "pipe", id: "p-gate-pdp", d: `M${L.gateX + L.gateW / 2} ${L.gateY} V${L.pdpY + L.pdpH / 2} H${L.pdpX}` }, layers.pipes);

  // Broker và các topic
  el("rect", { class: "broker-box", x: L.topX - 22, y: L.topY0 - 34, width: L.topW + 40, height: topics.length * L.topGap + 26 }, layers.pipes);
  el("text", { class: "broker-label", x: L.topX - 10, y: L.topY0 - 14 }, layers.pipes).textContent = "Broker MQTT – tài nguyên được bảo vệ";
  topics.forEach((t, j) => {
    const g = el("g", { class: "node topic", id: `topic-${j}` }, layers.nodes);
    const p = policies[t], types = [...new Set(p.allowedTypes)].map((x) => TYPE_NAME[x] || x).join(", ");
    el("rect", { x: L.topX, y: L.topY0 + j * L.topGap, width: L.topW, height: L.topH }, g);
    el("text", { x: L.topX + 12, y: L.topY0 + j * L.topGap + 23, "font-size": 15, "font-weight": 600 }, g).textContent = t;
    el("text", { class: "pol", x: L.topX + 12, y: L.topY0 + j * L.topGap + 43 }, g).textContent = `fw ≥ ${p.minFw}, an toàn ≥ ${p.minSec}, ${types}`;
  });

  // Thiết bị và ống nối vào cổng
  ids.forEach((id, i) => {
    el("path", { class: "pipe", id: `p-dev-${id}`, d: `M${L.devX + L.devW} ${devY(i)} H${L.gateX}` }, layers.pipes);
    const g = el("g", { class: "node clickable", id: `node-${id}`, tabindex: 0, role: "button", "aria-label": `Điều khiển ${id}` }, layers.nodes);
    g.addEventListener("click", () => window.focusDevice?.(id));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); window.focusDevice?.(id); } });
    el("rect", { x: L.devX, y: L.devY0 + i * L.devGap, width: L.devW, height: L.devH }, g);
    el("text", { x: L.devX + 12, y: L.devY0 + i * L.devGap + 24, "font-size": 16, "font-weight": 600 }, g).textContent = id;
    el("text", { class: "sub", x: L.devX + 50, y: L.devY0 + i * L.devGap + 23, id: `node-st-${id}` }, g).textContent = SHORT.idle;
  });
}

const linkPath = (id, topic) => {
  const y1 = devY(devIndex[id]), y2 = topY(topicIndex[topic]), x1 = L.gateX + L.gateW, x2 = L.topX;
  return `M${x1} ${y1} C${x1 + 150} ${y1}, ${x2 - 150} ${y2}, ${x2} ${y2}`;
};

const linkPathRev = (id, topic) => {
  const y1 = devY(devIndex[id]), y2 = topY(topicIndex[topic]), x1 = L.gateX + L.gateW, x2 = L.topX;
  return `M${x2} ${y2} C${x2 - 150} ${y2}, ${x1 + 150} ${y1}, ${x1} ${y1}`;
};

function drawDynamic() {
  layers.links.innerHTML = "";
  const now = Date.now(), active = new Set();
  for (const d of Object.values(devices)) {
    const node = document.getElementById(`node-${d.id}`);
    if (!node) continue;
    const st = effStatus(d);
    node.setAttribute("class", `node clickable ${st}${window.isRunning?.(d.id) ? " running" : ""}`);
    document.getElementById(`node-st-${d.id}`).textContent = SHORT[st] || st;
    if (d.topic in topicIndex && (st === "connected" || st === "reauth")) {
      const live = st === "connected" && (!d.sessionUntil || d.sessionUntil > now);
      el("path", { class: `link ${live ? "allow" : "warn"}`, d: linkPath(d.id, d.topic) }, layers.links);
      if (live) active.add(d.topic);
    }
  }
  for (const [t, j] of Object.entries(topicIndex)) document.getElementById(`topic-${j}`).setAttribute("class", `node topic${active.has(t) ? " active" : ""}`);
}

// ---------------------------------------------------------------- Chuyển động: chấm chạy theo đường ống
function runDot(d, cls, ms) {
  return new Promise((resolve) => {
    if (reduceMotion) return resolve();
    const p = el("path", { d, fill: "none", stroke: "none" }, layers.dots);
    const c = el("circle", { class: `dot ${cls}`, r: 6 }, layers.dots);
    const len = p.getTotalLength(), t0 = performance.now();
    (function step(t) {
      const k = Math.min(1, (t - t0) / ms), pt = p.getPointAtLength(len * k);
      c.setAttribute("cx", pt.x); c.setAttribute("cy", pt.y);
      if (k < 1) requestAnimationFrame(step); else { p.remove(); c.remove(); resolve(); }
    })(t0);
  });
}
const flash = (id, cls, ms = 900) => { const g = document.getElementById(id); if (!g) return; g.classList.add(cls); setTimeout(() => g.classList.remove(cls), ms); };
const gatePdp = `M${L.gateX + L.gateW / 2} ${L.gateY} V${L.pdpY + L.pdpH / 2} H${L.pdpX}`;
const pdpGate = `M${L.pdpX} ${L.pdpY + L.pdpH / 2} H${L.gateX + L.gateW / 2} V${L.gateY}`;

async function animate(ev) {
  if (!ev.device || !(ev.device in devIndex)) {
    if (ev.src === "PDP") flash("pdp", ev.kind === "ALLOW" ? "flash-allow" : "flash-deny");
    return;
  }
  const devPipe = `M${L.devX + L.devW} ${devY(devIndex[ev.device])} H${L.gateX}`;
  if (ev.kind === "CONNECT_ALLOW" || ev.kind === "CONNECT_DENY") {
    const ok = ev.kind === "CONNECT_ALLOW";
    await runDot(devPipe, "ask", 380);                 // ② thiết bị gửi proof tới PEP
    await runDot(gatePdp, "ask", 300);                 // PEP hỏi PDP
    await runDot(pdpGate, ok ? "allow" : "deny", 300); // PDP trả quyết định
    flash("gate", ok ? "flash-allow" : "flash-deny");
    if (ok && ev.topic in topicIndex) runDot(linkPath(ev.device, ev.topic), "allow", 500);
  } else if (ev.kind === "PUBLISH_OK" && ev.topic in topicIndex) {
    await runDot(devPipe, "flow", 300);
    await runDot(linkPath(ev.device, ev.topic), "flow", 450);
    // Broker chuyển bản tin tới các thiết bị đang đăng ký nhận topic này
    for (const sub of window.subscribersOf?.(ev.topic, ev.device) || []) {
      if (!(sub in devIndex)) continue;
      runDot(linkPathRev(sub, ev.topic), "flow", 450).then(() => runDot(`M${L.gateX} ${devY(devIndex[sub])} H${L.devX + L.devW}`, "flow", 300));
    }
  } else if (ev.kind === "PUBLISH_DENY" || ev.kind === "SUBSCRIBE_DENY") {
    await runDot(devPipe, "deny", 300); flash("gate", "flash-deny");
  }
}

// ---------------------------------------------------------------- Bảng thiết bị: xem control.js (renderDevices)
const fmtMs = (v) => (v == null ? "–" : `${Math.round(v).toLocaleString("vi-VN")} ms`);

// ---------------------------------------------------------------- Nhật ký sự kiện
const showPub = document.getElementById("show-pub");
function describe(ev) {
  const r = (x) => REASON[x] || x || "";
  switch (ev.kind) {
    case "ALLOW":           return ["allow", `Cho phép truy cập <b>${ev.topic}</b> <small>(${r(ev.reason)}, verify ${ev.verifyMs} ms)</small>`];
    case "DENY":            return ["deny", `Từ chối <b>${ev.topic}</b>: ${r(ev.reason)}${ev.verifyMs ? ` <small>(verify ${ev.verifyMs} ms)</small>` : ""}`];
    case "CONNECT_ALLOW":   return ["allow", `${ev.device} được kết nối <b>${ev.topic}</b> <small>(${ev.detail})</small>`];
    case "CONNECT_DENY":    return ["deny", `${ev.device} bị từ chối kết nối${ev.topic ? ` <b>${ev.topic}</b>` : ""}: ${r(ev.detail)}`];
    case "PUBLISH_OK":      return ["flow", `${ev.device} gửi vào <b>${ev.topic}</b> <small>${ev.detail}</small>`];
    case "PUBLISH_DENY":    return ["deny", `${ev.device} gửi sai topic <b>${ev.topic}</b>, bị ngắt kết nối`];
    case "SUBSCRIBE_OK":    return ["allow", `${ev.device} đăng ký nhận <b>${ev.topic}</b>`];
    case "SUBSCRIBE_DENY":  return ["deny", `${ev.device} đăng ký sai topic <b>${ev.topic}</b>, bị từ chối`];
    case "SESSION_EXPIRED": return ["warn", `Phiên của ${ev.device} hết hạn, phải chứng minh lại`];
    case "DISCONNECT":      return ["", `${ev.device} ngắt kết nối`];
    case "AUTH_OK":         return ["allow", `Tạo proof ${fmtMs(ev.proveMs)}, kết nối xong sau ${fmtMs(ev.authMs)}`];
    case "AUTH_DENY":       return ["deny", `Proof đã gửi nhưng bị từ chối`];
    case "PROOF_FAIL":      return ["deny", `Không tạo được proof cho <b>${ev.topic}</b>: không đạt chính sách`];
    case "SESSION_END":     return ["warn", `Bị ngắt phiên, xin nonce mới để chứng minh lại`];
    case "CHALLENGE_ERR":   return ["deny", `Không xin được nonce: PDP không phản hồi`];
    case "PEP_UNREACHABLE": return ["deny", `Không gọi được PEP`];
    default:                return ["", `${ev.kind} ${ev.topic || ""}`];
  }
}
function evItem(ev, fresh) {
  const [cls, html] = describe(ev);
  const t = new Date(ev.time).toLocaleTimeString("vi-VN", { hour12: false });
  return `<li class="${cls}${fresh ? " fresh" : ""}"><span class="t">${t}</span><span class="src">${ev.src}</span><span class="msg">${html}</span></li>`;
}
function renderEvents(freshCount = 0) {
  const list = document.getElementById("ev-list");
  const shown = events.filter((e) => showPub.checked || e.kind !== "PUBLISH_OK").slice(-120).reverse();
  list.innerHTML = shown.length ? shown.map((e, i) => evItem(e, i < freshCount)).join("")
    : `<li class="empty">Chưa có sự kiện. Bấm <b>Bật PDP, PEP và D1, D5, D6</b> ở bảng điều khiển phía trên để bắt đầu.</li>`;
}
showPub.addEventListener("change", () => renderEvents());

// ---------------------------------------------------------------- Đèn trạng thái, đồng hồ
function setHealth(h) {
  for (const [k, id] of [["pdp", "lamp-pdp"], ["pep", "lamp-pep"]]) {
    const lamp = document.getElementById(id);
    lamp.classList.toggle("up", h[k]); lamp.classList.toggle("down", !h[k]);
    lamp.title = h[k] ? "Đang chạy" : "Không phản hồi";
  }
  document.getElementById("pdp")?.classList.toggle("down", !h.pdp);
}
setInterval(() => {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString("vi-VN", { hour12: false });
  renderDevices(); drawDynamic();
}, 250);

// ---------------------------------------------------------------- Kết nối SSE
const es = new EventSource("/events");
es.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  window.onCtl?.(msg);
  if (msg.type === "snapshot") {
    devices = msg.devices; policies = msg.policies; events = msg.events;
    drawStatic(); drawDynamic(); renderDevices(); renderEvents(); setHealth(msg.health); renderInbox(msg.inbox);
  } else if (msg.type === "event") {
    if (msg.device) {
      if (msg.ev.kind === "CONNECT_ALLOW") msg.device.sessionTotal = Math.max(1, msg.device.sessionUntil - msg.ev.time) / 1000;
      else if (devices[msg.device.id]?.sessionTotal) msg.device.sessionTotal = devices[msg.device.id].sessionTotal;
      devices[msg.device.id] = msg.device;
    }
    events.push(msg.ev); if (events.length > 300) events.shift();
    renderEvents(showPub.checked || msg.ev.kind !== "PUBLISH_OK" ? 1 : 0);
    animate(msg.ev);
  } else if (msg.type === "inbox") renderInbox(msg.inbox);
  else if (msg.type === "health") setHealth(msg.health);
  else if (msg.type === "policies") { policies = msg.policies; drawStatic(); drawDynamic(); }
};
es.onerror = () => { document.getElementById("lamp-pdp").title = "Mất kết nối tới dashboard"; };

// ---------------------------------------------------------------- Bảng "PDP thấy gì, không thấy gì"
const PUB_NAMES = [
  ["sessionTag", "Thiết bị tính trong mạch, gửi kèm proof"], ["Ax", "PDP tự điền: khóa công khai Issuer"], ["Ay", "PDP tự điền: khóa công khai Issuer"],
  ["minFw", "PDP tự điền: chính sách"], ["minSec", "PDP tự điền: chính sách"], ["allowedTypes[0]", "PDP tự điền: chính sách"],
  ["allowedTypes[1]", "PDP tự điền: chính sách"], ["allowedTypes[2]", "PDP tự điền: chính sách"], ["now", "PDP tự điền: lúc cấp nonce"], ["nonce", "PDP tự điền: đã cấp trước đó"],
];
const HIDDEN = [["sk_dev", "khóa bí mật thiết bị"], ["fw", "phiên bản firmware"], ["sec", "mức an toàn"], ["dtype", "loại thiết bị"],
  ["exp", "hạn credential"], ["R8x, R8y, S", "chữ ký Issuer"], ["pk_dev", "định danh thiết bị"], ["deviceId", "tên thiết bị"]];
const cut = (v, n = 18) => { v = String(v ?? ""); return v.length > n ? `${v.slice(0, n)}…` : v; };
document.getElementById("zk-hidden").innerHTML = HIDDEN.map(([k, d]) => `<li><span><b>${k}</b> <small>${d}</small></span><span class="mask" aria-label="ẩn">● ● ● ●</span></li>`).join("");

function renderInbox(x) {
  if (!x) { document.getElementById("zk-claim").textContent = "Khi một thiết bị gửi proof, nội dung PDP nhận được sẽ hiện ở đây."; return; }
  const ok = x.decision === "ALLOW";
  document.getElementById("zk-meta").innerHTML = `${new Date(x.time).toLocaleTimeString("vi-VN", { hour12: false })} <b class="${ok ? "allow" : "deny"}">${ok ? "ALLOW" : "DENY"}</b> ${ok ? "" : REASON[x.reason] || x.reason}${x.verifyMs ? ` <span>verify ${x.verifyMs} ms</span>` : ""}`;
  document.getElementById("zk-recv").innerHTML =
    `<dt>Các trường</dt><dd>${x.fields.join(", ")} <small>(${x.bytes} byte, không có trường thuộc tính nào)</small></dd>` +
    `<dt>resource</dt><dd>${x.resource ?? ""}</dd><dt>nonce</dt><dd><code>${cut(x.nonce, 30)}</code></dd>` +
    `<dt>sessionTag</dt><dd><code>${cut(x.sessionTag, 30)}</code></dd>` +
    (x.proof ? `<dt>proof π</dt><dd><code>A = ${cut(x.proof.A, 14)}</code>, <code>B = ${cut(x.proof.B, 14)}</code>, <code>C = ${cut(x.proof.C, 14)}</code> <small>(3 điểm trên đường cong)</small></dd>` : "");
  const ps = x.publicSignals || [];
  document.getElementById("zk-pub").innerHTML = ps.length ? ps.map((v, i) => `<tr class="${i === 0 ? "dev" : ""}"><td>${i}</td><td>${PUB_NAMES[i][0]}</td><td><code>${cut(v, 22)}</code></td><td class="src">${PUB_NAMES[i][1]}</td></tr>`).join("")
    : `<tr><td colspan="4" class="src">PDP từ chối trước khi dựng public input (${REASON[x.reason] || x.reason}).</td></tr>`;
  const claim = document.getElementById("zk-claim");
  claim.className = `zk-claim ${ok ? "allow" : "deny"}`;
  if (ps.length) {
    const types = [...new Set(ps.slice(5, 8))].map((t) => TYPE_NAME[t] || t).join(" hoặc ");
    claim.innerHTML = ok
      ? `Có một thiết bị giữ credential do Issuer ký, với firmware ≥ <b>${ps[3]}</b>, mức an toàn ≥ <b>${ps[4]}</b>, loại là <b>${types}</b>, credential còn hạn, và thiết bị nắm khóa bí mật gắn với credential đó. PDP không biết đó là thiết bị nào, cũng không biết các giá trị thật.`
      : `Proof không chứng minh được điều kiện của <b>${x.resource}</b>. PDP chỉ biết yêu cầu này không hợp lệ, không biết vì sao về phía thiết bị.`;
  } else claim.innerHTML = `Yêu cầu bị loại ở bước kiểm tra nonce, PDP chưa cần kiểm tra proof.`;
}
