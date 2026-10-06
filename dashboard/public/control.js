// ============================================================================
//  DASHBOARD – phần ĐIỀU KHIỂN: bật/tắt PDP, PEP, thiết bị; chính sách; nhật ký tiến trình
//  Mọi thao tác gọi API của dashboard/server.js; trạng thái thật luôn lấy lại từ máy chủ qua SSE.
// ============================================================================
let procs = [], meta = { ids: [], topics: [], profiles: {}, issuedAt: null };
const plogs = {};
let health = { pdp: false, pep: false };
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const proc = (key) => procs.find((p) => p.key === key);
window.isRunning = (id) => !!proc(`dev:${id}`);
// Thiết bị đang NHẬN dữ liệu trên topic (để vẽ bản tin đi từ broker tới người nhận)
window.subscribersOf = (topic, publisher) => procs.filter((p) => p.kind === "device" && p.meta.mode === "sub" && p.meta.topic === topic && p.meta.id !== publisher
  && effStatus(devices[p.meta.id] || {}) === "connected").map((p) => p.meta.id);

// ---------------------------------------------------------------- Gọi API
let toastTimer;
function toast(msg, bad = false) {
  const t = $("toast"); t.textContent = msg; t.className = `toast show${bad ? " bad" : ""}`;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = "toast"), 5000);
}
async function api(path, body = {}) {
  try {
    const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json(); toast(j.msg, !j.ok); return j.ok;
  } catch { toast("Không gọi được máy chủ dashboard", true); return false; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (cond, ms = 6000) => { for (let t = 0; t < ms && !cond(); t += 200) await sleep(200); return cond(); };

// ---------------------------------------------------------------- Bảng điều khiển hệ thống
const ago = (t) => { const s = Math.round((Date.now() - t) / 1000); return s < 60 ? `${s} giây` : `${Math.floor(s / 60)} phút`; };
function renderUnits() {
  for (const k of ["pdp", "pep"]) {
    const p = proc(k), up = health[k], unit = $(`unit-${k}`), btn = $(`btn-${k}`);
    unit.classList.toggle("on", up); unit.classList.toggle("ext", up && !p);
    let st = "Đã tắt";
    if (p && up) st = `Đang chạy, PID ${p.pid}, được ${ago(p.startedAt)}${k === "pep" ? (p.meta.session ? `, phiên ${p.meta.session} s` : ", phiên theo chính sách") : ""}`;
    else if (p) st = "Đang khởi động…";
    else if (up) st = "Đang chạy từ terminal (dashboard không tắt được bản này)";
    $(`st-${k}`).textContent = st;
    btn.textContent = p ? `Tắt ${k.toUpperCase()}` : `Bật ${k.toUpperCase()}`;
    btn.classList.toggle("danger", !!p);
    btn.disabled = up && !p;
  }
  $("pep-session").disabled = !!proc("pep");
  const iss = proc("issuer");
  $("unit-iss").classList.toggle("on", !!meta.issuedAt && Date.now() < meta.issuedAt + 24 * 3600e3);
  if (iss) $("st-iss").textContent = "Đang cấp credential…";
  else if (meta.issuedAt) {
    const left = meta.issuedAt + 24 * 3600e3 - Date.now();
    $("st-iss").textContent = left > 0 ? `Cấp lúc ${new Date(meta.issuedAt).toLocaleString("vi-VN", { hour12: false })}, còn ${Math.floor(left / 3600e3)} giờ ${Math.floor((left % 3600e3) / 60e3)} phút`
      : "Credential đã quá 24 giờ – hãy cấp lại";
  } else $("st-iss").textContent = "Chưa cấp credential";
  $("btn-iss").disabled = !!iss;
}
$("btn-pdp").onclick = () => api("/api/pdp", { action: proc("pdp") ? "stop" : "start" });
$("btn-pep").onclick = () => api("/api/pep", { action: proc("pep") ? "stop" : "start", session: Number($("pep-session").value) });
$("btn-iss").onclick = () => api("/api/issue");
$("btn-stopall").onclick = () => api("/api/stopall");

// Mặc định hợp lý cho từng thiết bị: cảm biến gửi vào topic của nó, gateway nhận dữ liệu nhiệt độ
const DEFAULT_TOPIC = { 1: "factory/temperature", 2: "factory/humidity", 3: "factory/camera", 4: "factory/temperature" };
const defaults = (id) => { const t = meta.profiles[id]?.dtype; return { topic: DEFAULT_TOPIC[t] || meta.topics[0], mode: t === 4 ? "sub" : "pub" }; };
async function ensureCore() {
  if (!health.pdp && !proc("pdp")) { await api("/api/pdp", { action: "start" }); await waitFor(() => health.pdp); }
  if (!health.pep && !proc("pep")) { await api("/api/pep", { action: "start", session: Number($("pep-session").value) }); await waitFor(() => health.pep); }
}
async function startDevices(ids) {
  await ensureCore();
  for (const id of ids) if (!proc(`dev:${id}`)) {
    const sel = rowSel(id);
    await api("/api/device", { action: "start", id, topic: sel.topic.value, mode: sel.mode.value });
    await sleep(250);
  }
}
$("btn-demo").onclick = () => startDevices(["D1", "D5", "D6"].filter((id) => meta.ids.includes(id)));
$("btn-alldev").onclick = () => startDevices(meta.ids);

// ---------------------------------------------------------------- Bảng thiết bị (dựng một lần, cập nhật từng ô)
const rows = {};
const rowSel = (id) => ({ topic: rows[id].querySelector(".sel-topic"), mode: rows[id].querySelector(".sel-mode") });
function buildDeviceRows() {
  const body = $("dev-body"); body.innerHTML = "";
  for (const id of meta.ids) {
    const d = defaults(id), tr = document.createElement("tr");
    tr.id = `row-${id}`;
    tr.innerHTML = `<td class="id" title="${esc(meta.profiles[id]?.mo_ta || "")}">${id}<small>${esc(meta.profiles[id]?.mo_ta || "")}</small></td>
      <td class="c-state"></td>
      <td><select class="sel-topic" aria-label="Topic của ${id}">${meta.topics.map((t) => `<option ${t === d.topic ? "selected" : ""}>${t}</option>`).join("")}</select></td>
      <td><select class="sel-mode" aria-label="Vai trò của ${id}"><option value="pub" ${d.mode === "pub" ? "selected" : ""}>Gửi dữ liệu</option><option value="sub" ${d.mode === "sub" ? "selected" : ""}>Nhận dữ liệu</option></select></td>
      <td class="c-sess"></td><td class="num c-prove"></td><td class="num c-msgs"></td>
      <td><button class="btn small c-btn" type="button">Bật</button></td>`;
    tr.querySelector(".c-btn").onclick = () => {
      if (proc(`dev:${id}`)) return api("/api/device", { action: "stop", id });
      if (!health.pep) return toast("Hãy bật PDP và PEP trước khi bật thiết bị", true);
      const s = rowSel(id); api("/api/device", { action: "start", id, topic: s.topic.value, mode: s.mode.value });
    };
    body.appendChild(tr); rows[id] = tr;
  }
}
function renderDevices() {
  if (!meta.ids.length) return;
  if (Object.keys(rows).length !== meta.ids.length) buildDeviceRows();
  const now = Date.now();
  for (const id of meta.ids) {
    const tr = rows[id], d = devices[id] || { status: "idle" }, p = proc(`dev:${id}`);
    const st = effStatus(d);
    const stHtml = `<span class="state ${st}">${STATUS[st] || st}</span>${p ? "" : (st !== "idle" ? `<small class="stopped">tiến trình đã dừng</small>` : "")}`;
    if (tr._st !== stHtml) { tr.querySelector(".c-state").innerHTML = stHtml; tr._st = stHtml; }
    let sess = "–";
    if (d.status === "connected" && d.sessionUntil > now) {
      const left = (d.sessionUntil - now) / 1000, total = d.sessionTotal || left;
      sess = `<div class="sess"><div class="track"><div class="fill" style="width:${Math.max(0, Math.min(100, (left / total) * 100))}%"></div></div><span>${Math.ceil(left)} s</span></div>`;
    }
    tr.querySelector(".c-sess").innerHTML = sess;
    tr.querySelector(".c-prove").textContent = fmtMs(d.proveMs);
    tr.querySelector(".c-msgs").textContent = d.msgs || 0;
    const btn = tr.querySelector(".c-btn");
    btn.textContent = p ? "Dừng" : "Bật"; btn.classList.toggle("danger", !!p);
    const s = rowSel(id);
    s.topic.disabled = s.mode.disabled = !!p;
    if (p) { s.topic.value = p.meta.topic; s.mode.value = p.meta.mode; }
    tr.classList.toggle("running", !!p);
  }
  renderUnits();
}
window.focusDevice = (id) => {
  const tr = rows[id]; if (!tr) return;
  tr.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
  tr.classList.remove("focus"); void tr.offsetWidth; tr.classList.add("focus");
  tr.querySelector(proc(`dev:${id}`) ? ".c-btn" : ".sel-topic").focus({ preventScroll: true });
  setLogTab("dev", id);
};

// ---------------------------------------------------------------- Chính sách
const TYPES = [[1, "Cảm biến nhiệt"], [2, "Cảm biến ẩm"], [3, "Camera"], [4, "Gateway"]];
let polSig = "";
function renderPolicies() {
  const sig = JSON.stringify(policies); if (sig === polSig) return; polSig = sig;
  $("pol-body").innerHTML = Object.keys(policies).filter((k) => !k.startsWith("_")).map((t) => {
    const p = policies[t], set = new Set(p.allowedTypes), key = t.replace(/\W/g, "_");
    return `<tr data-topic="${esc(t)}"><td class="id">${esc(t)}</td>
      <td><input type="number" class="in-fw" min="0" max="65535" value="${p.minFw}" aria-label="Firmware tối thiểu của ${esc(t)}"></td>
      <td><input type="number" class="in-sec" min="0" max="255" value="${p.minSec}" aria-label="Mức an toàn tối thiểu của ${esc(t)}"></td>
      <td class="types">${TYPES.map(([v, n]) => `<label><input type="checkbox" value="${v}" ${set.has(v) ? "checked" : ""}> ${n}</label>`).join("")}</td>
      <td><input type="number" class="in-ttl" min="5" max="3600" value="${p.ttl}" aria-label="Thời hạn phiên của ${esc(t)}"></td>
      <td><button class="btn small" type="button" id="apply-${key}">Áp dụng</button></td></tr>`;
  }).join("");
  for (const tr of $("pol-body").querySelectorAll("tr")) tr.querySelector("button").onclick = () => {
    const types = [...tr.querySelectorAll(".types input:checked")].map((x) => Number(x.value));
    api("/api/policy", { resource: tr.dataset.topic, minFw: Number(tr.querySelector(".in-fw").value), minSec: Number(tr.querySelector(".in-sec").value),
      allowedTypes: types, ttl: Number(tr.querySelector(".in-ttl").value) });
  };
}

// ---------------------------------------------------------------- Nhật ký: sự kiện + đầu ra từng tiến trình
let logTab = "events", logDev = null;
function setLogTab(tab, devId) {
  logTab = tab; if (devId) logDev = devId;
  for (const b of $("log-tabs").querySelectorAll("button")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
  $("ev-list").hidden = tab !== "events"; $("pub-toggle").hidden = tab !== "events";
  $("con").hidden = tab === "events"; $("log-dev").hidden = tab !== "dev";
  if (tab === "dev") { if (!logDev) logDev = meta.ids[0]; $("log-dev").value = logDev; }
  renderCon();
}
$("log-tabs").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) setLogTab(b.dataset.tab); });
$("log-dev").addEventListener("change", (e) => { logDev = e.target.value; renderCon(); });
const conKey = () => (logTab === "dev" ? `dev:${logDev}` : logTab);
const lineCls = (l) => (/DENY|FAIL|lỗi|Error|UNREACHABLE|không|kết thúc/i.test(l) ? "bad" : /ALLOW|AUTH_OK|OK|Đã|đang chạy|▶/i.test(l) ? "good" : "");
function renderCon() {
  if (logTab === "events") return;
  const con = $("con"), arr = plogs[conKey()] || [];
  const atBottom = con.scrollHeight - con.scrollTop - con.clientHeight < 30;
  con.innerHTML = arr.length ? arr.map((x) => `<span class="${lineCls(x.line)}"><i>${new Date(x.t).toLocaleTimeString("vi-VN", { hour12: false })}</i> ${esc(x.line)}</span>`).join("\n")
    : `<span class="muted">Chưa có đầu ra. Tiến trình bật từ dashboard sẽ hiện nội dung terminal của nó ở đây.</span>`;
  if (atBottom) con.scrollTop = con.scrollHeight;
}

// ---------------------------------------------------------------- Nhận dữ liệu từ máy chủ (gọi từ app.js)
window.onCtl = (msg) => {
  if (msg.type === "snapshot") {
    procs = msg.procs || []; meta = msg.meta || meta; health = msg.health || health;
    Object.assign(plogs, msg.plogs || {});
    $("log-dev").innerHTML = meta.ids.map((id) => `<option>${id}</option>`).join("");
    for (const k of Object.keys(rows)) delete rows[k];
    setTimeout(() => { renderDevices(); renderPolicies(); renderCon(); }, 0);
  } else if (msg.type === "procs") { procs = msg.procs; renderDevices(); }
  else if (msg.type === "health") { health = msg.health; renderUnits(); }
  else if (msg.type === "policies") { setTimeout(renderPolicies, 0); }
  else if (msg.type === "plog") {
    (plogs[msg.key] ??= []).push({ t: msg.t, line: msg.line }); if (plogs[msg.key].length > 300) plogs[msg.key].shift();
    if (msg.key === "issuer" && /Đã trả credential|credential.json/.test(msg.line)) meta.issuedAt = Date.now();
    if (msg.key === conKey()) renderCon();
  }
};
