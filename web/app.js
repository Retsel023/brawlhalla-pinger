"use strict";

const REGIONS = [
  { id: "us-e", name: "US East", code: "USE", hostname: "pingtest-atl.brawlhalla.com" },
  { id: "us-w", name: "US West", code: "USW", hostname: "pingtest-cal.brawlhalla.com" },
  { id: "eu", name: "Europe", code: "EU", hostname: "pingtest-ams.brawlhalla.com" },
  { id: "sea", name: "Southeast Asia", code: "SEA", hostname: "pingtest-sgp.brawlhalla.com" },
  { id: "aus", name: "Australia", code: "AUS", hostname: "pingtest-aus.brawlhalla.com" },
  { id: "brazil", name: "Brazil", code: "BR", hostname: "pingtest-brs.brawlhalla.com" },
  { id: "japan", name: "Japan", code: "JPN", hostname: "pingtest-jpn.brawlhalla.com" },
  { id: "middle-east", name: "Middle East", code: "ME", hostname: "pingtest-mde.brawlhalla.com" },
  { id: "southern-africa", name: "Southern Africa", code: "SAF", hostname: "pingtest-saf.brawlhalla.com" },
];

const $ = (id) => document.getElementById(id);
let state = null;
let busy = false;
let pollTimer;
let toastTimer;
let connected = false;
let polling = false;
let requestEpoch = 0;
let diagnosing = false;
let diagnosticReport = "";
let discovering = false;
const cards = new Map();

function setText(element, value) {
  if (element.textContent !== String(value)) element.textContent = value;
}

function isNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function number(value, digits = 0) {
  return isNumber(value) ? value.toFixed(digits) : "—";
}

function ms(value) {
  return isNumber(value) ? `${number(value, value < 1 ? 3 : value < 10 ? 1 : 0)} ms` : "—";
}

function quality(server) {
  if (server.enabled === false) return { label: "NOT SELECTED", color: "var(--muted)" };
  if (server.status === "error") return { label: "CHECK FAILED", color: "var(--poor)" };
  if (server.status === "refused") return { label: "PORT CLOSED", color: "var(--fair)" };
  if (server.status === "timeout") return { label: state && state.method === "tcp" ? "CONNECT TIMEOUT" : "NO REPLY", color: "var(--poor)" };
  if (!isNumber(server.latest_ms)) return { label: server.status === "idle" ? "WAITING" : "CHECKING", color: "var(--muted)" };
  if (server.latest_ms < 60) return { label: "EXCELLENT", color: "var(--excellent)" };
  if (server.latest_ms < 100) return { label: "GOOD", color: "var(--good)" };
  if (server.latest_ms <= 160) return { label: "FAIR", color: "var(--fair)" };
  return { label: "HIGH LATENCY", color: "var(--poor)" };
}

function buildCard(region) {
  const article = document.createElement("article");
  article.className = "server-card";
  article.dataset.region = region.id;
  article.setAttribute("aria-label", `${region.name} server`);
  article.innerHTML = `
    <button class="server-select" type="button" aria-label="Ping only ${region.name}" aria-pressed="false" disabled></button>
    <div class="card-header">
      <div class="region-title"><span class="region-badge">${region.code}</span><h3 class="region-name" style="margin:0">${region.name}</h3></div>
      <span class="best-badge" hidden><svg class="icon"><use href="#i-arrow"/></svg>BEST REGION</span>
    </div>
    <div class="hostname-row"><div class="hostname" title="${region.hostname}">${region.hostname}</div><button class="target-edit" type="button" aria-label="Change ${region.name} target" title="Change ping target">edit</button></div>
    <div class="card-reading">
      <div class="latency-reading"><span class="latency-value">—</span><span class="latency-unit">ms</span></div>
      <span class="quality-label"><i></i><span>CHECKING</span></span>
    </div>
    <div class="chart-wrap" role="img" aria-label="Waiting for latency samples"><svg class="sparkline" viewBox="0 0 320 48" preserveAspectRatio="none" aria-hidden="true"></svg><span class="chart-empty">Waiting for first reply</span></div>
    <div class="card-stats">
      <div class="stat-block"><span class="stat-label">AVERAGE</span><span class="stat-value"><span data-field="avg">—</span><span class="stat-unit">ms</span></span></div>
      <div class="stat-block"><span class="stat-label">JITTER</span><span class="stat-value"><span data-field="jitter">—</span><span class="stat-unit">ms</span></span></div>
      <div class="stat-block"><span class="stat-label" data-field="failure-label">CONNECT FAIL</span><span class="stat-value" data-field="loss-value"><span data-field="loss">—</span><span class="stat-unit">%</span></span></div>
    </div>
    <div class="card-detail"><span>MIN <b data-field="min">—</b><span> / MAX </span><b data-field="max">—</b><span> ms</span></span><span><b data-field="received">0</b> / <b data-field="sent">0</b> <span data-field="success-label">CONNECTED</span></span></div>`;
  const elements = {};
  for (const [key, selector] of Object.entries({
    reading: ".latency-value", quality: ".quality-label span", best: ".best-badge",
    chartWrap: ".chart-wrap", chart: ".sparkline", chartEmpty: ".chart-empty", hostname: ".hostname", edit: ".target-edit", select: ".server-select",
  })) elements[key] = article.querySelector(selector);
  article.querySelectorAll("[data-field]").forEach((element) => { elements[element.dataset.field] = element; });
  cards.set(region.id, { article, elements, chartSignature: "" });
  elements.edit.addEventListener("click", () => openTarget(region.id));
  elements.select.addEventListener("click", () => selectServer(region.id));
  $("server-grid").append(article);
}

function renderChart(card, server) {
  const history = Array.isArray(server.history) ? server.history.slice(-90) : [];
  const signature = JSON.stringify([history, server.status, server.enabled, state && state.method]);
  if (card.chartSignature === signature) return;
  card.chartSignature = signature;
  const values = history.filter((sample) => isNumber(sample.ms));
  const maximum = values.length ? Math.max(20, ...values.map((sample) => sample.ms)) : 100;
  const minimum = values.length ? Math.min(...values.map((sample) => sample.ms)) : 0;
  const span = Math.max(maximum - minimum, 24);
  const lower = Math.max(0, minimum - span * 0.4);
  const upper = maximum + span * 0.25;
  const y = (value) => 40 - ((value - lower) / (upper - lower)) * 32;
  // A fixed 90-probe window prevents the chart rescaling its time axis on every reply.
  const x = (index) => 3 + ((90 - history.length + index) / 89) * 314;
  const paths = [];
  const losses = [];
  let segment = [];
  history.forEach((sample, index) => {
    if (isNumber(sample.ms)) {
      segment.push([x(index), y(sample.ms)]);
    } else {
      if (segment.length) paths.push(segment);
      segment = [];
      losses.push(x(index));
    }
  });
  if (segment.length) paths.push(segment);
  const lineMarkup = paths.map((points) => {
    const line = points.map(([px, py], index) => `${index ? "L" : "M"}${px.toFixed(2)},${py.toFixed(2)}`).join(" ");
    const last = points[points.length - 1];
    return `<path class="chart-line" d="${line}"/><circle class="chart-dot" cx="${last[0].toFixed(2)}" cy="${last[1].toFixed(2)}" r="2.5"/>`;
  }).join("");
  const lossMarkup = losses.map((px) => `<path class="chart-loss" d="M${(px - 1.5).toFixed(2)},41 l3,3 m-3,0 l3,-3"/>`).join("");
  card.elements.chart.innerHTML = `<path class="chart-guide" d="M0 14H320 M0 31H320 M0 47H320"/>${lineMarkup}${lossMarkup}`;
  card.elements.chartEmpty.hidden = history.length > 0;
  const tcp = state && state.method === "tcp";
  setText(card.elements.chartEmpty, server.status === "error" ? "Unable to measure this region" : tcp ? "Waiting for first connection" : "Waiting for first reply");
  const chartDescription = history.length
    ? `Last ${history.length} ${tcp ? "TCP attempts" : "ICMP probes"}: ${values.length} ${tcp ? "successful connections" : "replies"}${values.length ? `, ${ms(Math.min(...values.map((sample) => sample.ms)))} minimum, ${ms(Math.max(...values.map((sample) => sample.ms)))} maximum` : ""}. Gaps indicate ${tcp ? "failed connections" : "lost ICMP replies"}.`
    : "Waiting for latency samples";
  card.elements.chartWrap.setAttribute("aria-label", `${chartDescription}${server.enabled === false ? " Saved results; this region is not being probed." : ""}`);
}

function getBest(servers) {
  return servers.filter((server) => server.status === "online" && isNumber(server.avg_ms))
    .sort((a, b) => a.avg_ms - b.avg_ms)[0] || null;
}

function showNotice(message) {
  setText($("notice-message"), message || "");
  $("notice").hidden = !message;
}

function render() {
  if (!state) return;
  const servers = state.servers || [];
  const activeServers = servers.filter((server) => server.enabled !== false);
  const selectedServer = servers.find((server) => server.id === state.selected_server);
  const allSelected = !selectedServer;
  const tcp = state.method === "tcp";
  const system = state.measurement_source && state.measurement_source.system;
  setText($("measurement-source"), tcp ? `TCP · ${state.tcp_port}` : system ? `${system.toUpperCase()} · ICMP` : "SYSTEM ICMP");
  setText($("measurement-note-title"), tcp ? `TCP connect latency · port ${state.tcp_port}` : "ICMP echo latency");
  setText($("source-description"), tcp ? `The ${system || "Python"} service measures TCP connection setup to port ${state.tcp_port}, excluding DNS. In-game UDP latency and packet loss may differ.` : `ICMP pings are sent by the computer running pinger.py${system ? ` (${system})` : ""}. Missing ICMP replies do not establish that a host is offline or that the game loses packets.`);
  setText($("online-label"), tcp ? "ENDPOINTS OPEN" : "REGIONS REPLYING");
  setText($("online-description"), tcp ? `Accepting TCP on port ${state.tcp_port}` : "Responding to ICMP echo");
  setText($("failure-label"), tcp ? "FAILED CONNECTIONS" : "ICMP PROBE LOSS");
  setText($("sort-failure-option"), tcp ? "Fewest failed connections" : "Lowest ICMP loss");
  setText($("chart-caption"), tcp ? "TCP CONNECT LATENCY · LAST 90 PROBES" : "ICMP ECHO LATENCY · LAST 90 PROBES");
  setText($("target-method-help"), tcp ? `The target needs an open TCP service on port ${state.tcp_port}. A game endpoint may only use UDP; you can select ICMP echo separately.` : "The target must answer ICMP echo requests. A working game server may filter them.");
  if (document.activeElement !== $("method-select")) $("method-select").value = tcp ? `tcp:${state.tcp_port}` : "icmp";
  const best = getBest(activeServers);
  const sent = activeServers.reduce((sum, server) => sum + server.sent, 0);
  const received = activeServers.reduce((sum, server) => sum + server.received, 0);
  setText($("best-label"), allSelected ? "BEST CONNECTION" : "SELECTED REGION");
  setText($("online-denominator"), `/ ${activeServers.length}`);
  setText($("probe-scope-description"), allSelected ? "All regions in parallel" : "One region at a time");
  setText($("selection-summary"), allSelected ? "Click a region to test it on its own" : `${selectedServer.name} only · other regions are not being probed`);
  $("all-servers-button").classList.toggle("is-active", allSelected);
  $("all-servers-button").setAttribute("aria-pressed", String(allSelected));
  const duration = Math.max(0, Math.floor(state.uptime_seconds || 0));
  const hours = Math.floor(duration / 3600);
  const minutes = Math.floor((duration % 3600) / 60);
  const seconds = duration % 60;
  setText($("session-duration"), `SESSION ${hours ? `${String(hours).padStart(2, "0")}:` : ""}${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`);
  $("session-state").className = `session-state ${state.running ? "is-running" : "is-paused"}`;
  setText($("session-label"), state.running ? allSelected ? "Live monitoring · all regions" : `Monitoring ${selectedServer.name}` : "Monitoring paused");
  setText($("best-region"), selectedServer ? selectedServer.name : best ? best.name : sent ? tcp ? "No connections" : "No replies" : "Checking");
  setText($("best-ping"), best ? ms(best.avg_ms) : "—");
  setText($("best-description"), selectedServer ? tcp ? `Session average · TCP ${state.tcp_port}` : "Session average · ICMP echo" : best ? tcp ? "Lowest average TCP connect time" : "Lowest average ICMP echo time" : state.running ? "Comparing all nine regions" : "Resume to measure your connection");
  setText($("online-count"), activeServers.filter((server) => server.status === "online").length);
  setText($("total-loss"), sent ? number(((sent - received) / sent) * 100, 1) : "—");
  setText($("packets-description"), sent ? `${received.toLocaleString()} of ${sent.toLocaleString()} ${tcp ? "connections succeeded" : "ICMP replies received"}` : tcp ? "Waiting for first connections" : "Waiting for first replies");
  setText($("interval-value"), state.interval);
  // Leave the interval picker alone while the user is choosing a value.
  if (document.activeElement !== $("interval-select")) $("interval-select").value = String(state.interval);
  $("toggle-button").classList.toggle("is-paused", !state.running);
  $("toggle-button").querySelector("use").setAttribute("href", state.running ? "#i-pause" : "#i-play");
  setText($("toggle-button").querySelector("span"), state.running ? "Pause test" : "Resume test");
  $("export-button").disabled = !sent;
  for (const server of servers) {
    const card = cards.get(server.id);
    if (!card) continue;
    const q = quality(server);
    setText(card.elements["failure-label"], tcp ? "CONNECT FAIL" : "ICMP LOSS");
    card.elements["failure-label"].title = tcp ? "Percentage of TCP connection attempts that failed" : "Percentage of ICMP probes without a reply";
    setText(card.elements["success-label"], tcp ? "CONNECTED" : "REPLIES");
    setText(card.elements.hostname, server.hostname);
    card.elements.hostname.title = server.hostname;
    card.elements.edit.title = server.is_custom ? "Change custom ping target" : "Change default ping target";
    card.elements.hostname.classList.toggle("custom-hostname", Boolean(server.is_custom));
    card.article.style.setProperty("--quality", q.color);
    card.article.classList.toggle("is-best", Boolean(best && best.id === server.id));
    card.article.classList.toggle("is-selected", server.id === state.selected_server);
    card.article.classList.toggle("is-inactive", server.enabled === false);
    card.article.classList.toggle("chart-stale", !state.running || server.enabled === false);
    card.elements.select.setAttribute("aria-pressed", String(server.id === state.selected_server));
    card.elements.best.hidden = !allSelected || !best || best.id !== server.id;
    const latest = server.status === "online" ? server.latest_ms : null;
    setText(card.elements.reading, number(latest, isNumber(latest) && latest < 1 ? 3 : isNumber(latest) && latest < 10 ? 1 : 0));
    setText(card.elements.quality, q.label);
    card.elements.quality.parentElement.title = server.enabled === false ? "Saved results. Click this region to probe it on its own." : server.error || (server.status === "timeout" ? tcp ? "TCP connection timed out" : "No ICMP reply before the timeout" : `${q.label.toLowerCase()} connection`);
    for (const [field, value] of Object.entries({ avg: server.avg_ms, jitter: server.jitter_ms, min: server.min_ms, max: server.max_ms })) {
      setText(card.elements[field], number(value, isNumber(value) && value < 1 ? 3 : field === "jitter" ? 1 : 0));
    }
    setText(card.elements.loss, server.sent ? number(server.loss, 1) : "—");
    card.elements["loss-value"].classList.toggle("has-loss", server.loss > 0);
    setText(card.elements.received, server.received);
    setText(card.elements.sent, server.sent);
    renderChart(card, server);
  }
  sortCards();
  const errors = activeServers.filter((server) => server.status === "error");
  const probeError = errors.length ? `${errors.length} region${errors.length === 1 ? "" : "s"} could not be checked. ${errors[0].name}: ${errors[0].error || "The system ping command failed."}` : null;
  const allTimeouts = activeServers.length > 0 && activeServers.every((server) => server.sent >= 2 && server.received === 0 && (server.status === "timeout" || server.status === "refused"));
  const targetName = selectedServer ? `${selectedServer.name} did not accept` : "None of the nine targets accepted";
  const echoName = selectedServer ? `${selectedServer.name} is not replying` : "None of the nine targets is replying";
  const noReplies = allTimeouts ? tcp ? `${targetName} a TCP connection on port ${state.tcp_port}. Check the connection for details or try another method. This is not a measurement of game packet loss.` : `${echoName} to ICMP echo. The hosts may still be reachable over TCP; select TCP port 443 to check. Missing ICMP replies do not establish that the game servers are offline.` : null;
  showNotice(state.capability && !state.capability.available ? state.capability.message : state.targets_config_error || probeError || noReplies);
}

function sortCards() {
  const mode = $("sort-select").value;
  const regionIndex = new Map(REGIONS.map((region, index) => [region.id, index]));
  const servers = state ? [...state.servers] : [...REGIONS];
  servers.sort((a, b) => {
    let comparison = 0;
    if (mode === "latency") comparison = (isNumber(a.avg_ms) && a.status === "online" ? a.avg_ms : Infinity) - (isNumber(b.avg_ms) && b.status === "online" ? b.avg_ms : Infinity);
    if (mode === "loss") comparison = (a.sent ? a.loss : Infinity) - (b.sent ? b.loss : Infinity);
    return (Number.isNaN(comparison) ? 0 : comparison) || regionIndex.get(a.id) - regionIndex.get(b.id);
  });
  servers.forEach((server, index) => {
    const card = cards.get(server.id);
    const container = $("server-grid");
    if (card && container.children[index] !== card.article) container.insertBefore(card.article, container.children[index] || null);
  });
}

async function request(path, options = {}, timeout = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(path, { ...options, signal: controller.signal, cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  } finally {
    clearTimeout(timer);
  }
}

function setBusy(value) {
  busy = value;
  $("toggle-button").disabled = value || !connected;
  $("reset-button").disabled = value || !connected;
  $("interval-select").disabled = value || !connected;
  $("method-select").disabled = value || !connected;
  $("all-servers-button").disabled = value || !connected;
  $("diagnose-button").disabled = diagnosing || !connected;
  $("notice-diagnose").disabled = diagnosing || !connected;
  $("discover-button").disabled = discovering || !connected;
  $("target-save").disabled = value || !connected;
  $("target-default").disabled = value || !connected || !$("target-region").value;
  cards.forEach((card) => {
    card.elements.edit.disabled = value || !connected;
    card.elements.select.disabled = value || !connected;
  });
}

async function poll() {
  if (busy || polling) {
    schedulePoll();
    return;
  }
  polling = true;
  const epoch = requestEpoch;
  try {
    const nextState = await request("/api/status");
    if (epoch !== requestEpoch) return;
    state = nextState;
    connected = true;
    render();
  } catch (error) {
    if (epoch !== requestEpoch) return;
    connected = false;
    $("session-state").className = "session-state is-offline";
    setText($("session-label"), "Service disconnected");
    showNotice("The local pinger service is unavailable. Start pinger.py (or use the launcher) on this computer, then leave it running. This page will reconnect automatically.");
  } finally {
    polling = false;
    setBusy(busy);
    schedulePoll();
  }
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(poll, document.hidden ? 2000 : 750);
}

async function control(action, extra = {}) {
  if (busy || !connected) return;
  clearTimeout(pollTimer);
  requestEpoch += 1;
  setBusy(true);
  try {
    state = await request("/api/control", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, ...extra }),
    });
    render();
    if (action === "reset") toast(state.running ? "Session cleared. Starting fresh." : "Session cleared. Resume when you're ready.");
    if (action === "interval") toast(`Probing every ${state.interval} second${state.interval === 1 ? "" : "s"}.`);
    if (action === "target") toast("Region target saved. Measurements cleared for that region.");
    if (action === "method") toast(`${state.method === "tcp" ? `TCP port ${state.tcp_port}` : "ICMP echo"} selected. Starting a fresh session.`);
    if (action === "select") toast(state.selected_server ? `Only ${state.servers.find((server) => server.id === state.selected_server).name} is selected.` : "All nine regions selected.");
    return true;
  } catch (error) {
    toast(error.name === "AbortError" ? "The service took too long to respond. Try again." : error.message);
    if (state) $("interval-select").value = String(state.interval);
    if (state) $("method-select").value = state.method === "tcp" ? `tcp:${state.tcp_port}` : "icmp";
    if (action === "target") {
      setText($("target-error"), error.message);
      $("target-error").hidden = false;
    }
    return false;
  } finally {
    setBusy(false);
    schedulePoll();
  }
}

function selectServer(id) {
  if ((id === "all" && !state?.selected_server) || state?.selected_server === id) return;
  control("select", { id });
}

function openTarget(regionId = "", observedIP) {
  if (busy || !connected) return;
  const server = state.servers.find((item) => item.id === regionId);
  $("target-region").value = regionId;
  $("target-hostname").value = observedIP || (server ? server.hostname : "");
  $("target-error").hidden = true;
  setBusy(busy);
  $("target-dialog").showModal();
  if (!regionId) $("target-region").focus();
  else $("target-hostname").focus();
}

async function discoverConnections() {
  if (discovering || !connected) return;
  discovering = true;
  setBusy(busy);
  setText($("discover-button"), "Finding connections…");
  setText($("discovery-message"), "Reading network connections owned by the running Brawlhalla process. No game memory or packet contents are read.");
  $("discovery-results").hidden = true;
  try {
    const result = await request("/api/connections", {}, 10000);
    setText($("discovery-message"), result.message);
    const container = $("discovery-results");
    container.replaceChildren();
    result.connections.forEach((connection) => {
      const row = document.createElement("div");
      row.className = "connection-row";
      const details = document.createElement("div");
      const address = document.createElement("strong");
      address.textContent = connection.ip.includes(":") ? `[${connection.ip}]:${connection.port}` : `${connection.ip}:${connection.port}`;
      const meta = document.createElement("span");
      meta.textContent = `${connection.protocol.toUpperCase()} · ${connection.process} · PID ${connection.pid}${connection.game_port ? " · game port range" : ""}`;
      details.append(address, meta);
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button diagnostic-button";
      button.textContent = "Use IP for a region";
      button.addEventListener("click", () => openTarget("", connection.ip));
      row.append(details, button);
      container.append(row);
    });
    container.hidden = !result.connections.length;
  } catch (error) {
    setText($("discovery-message"), error.name === "AbortError" ? "Connection discovery took too long. You can also run python3 connections.py from the terminal." : error.message);
  } finally {
    discovering = false;
    setText($("discover-button"), "Find game connections");
    setBusy(busy);
  }
}

function toast(message) {
  clearTimeout(toastTimer);
  setText($("toast"), message);
  $("toast").hidden = false;
  toastTimer = setTimeout(() => { $("toast").hidden = true; }, 3500);
}

function diagnosticText(report) {
  const tcp = report.method === "tcp";
  const region = REGIONS.find((item) => item.id === report.selected_server);
  const lines = ["Brawlhalla Pinger connection report", `Time: ${new Date(report.created_at * 1000).toISOString()}`, `System: ${report.system}`, `Scope: ${region ? region.name : "All nine regions"}`, `Method: ${tcp ? `TCP connect, port ${report.tcp_port} (DNS excluded)` : "ICMP echo"}`, ...(tcp ? [] : [`Ping executable: ${report.executable || "not found"}`]), "", report.summary.title, report.summary.message];
  report.checks.forEach((check) => {
    lines.push("", `${check.name} (${check.hostname})`, `Result: ${check.status}${isNumber(check.ms) ? `, ${check.ms} ms` : ""}`, `${tcp ? "Probe" : "Command"}: ${(check.command || []).map((arg) => JSON.stringify(arg)).join(" ")}`, `Total probe duration${tcp ? " (including DNS)" : ""}: ${number(check.elapsed_seconds, 2)} seconds`);
    if (!tcp) lines.push(`Exit code: ${check.returncode == null ? "unavailable" : check.returncode}`, `Process deadline reached: ${check.process_timed_out ? "yes" : "no"}`);
    if (check.error) lines.push(`Details: ${check.error}`);
    lines.push("Standard output:", check.stdout || "(empty)", "Standard error:", check.stderr || "(empty)");
  });
  return lines.join("\n");
}

async function diagnose() {
  if (diagnosing || !connected) return;
  const requestedMethod = state.method;
  const requestedPort = state.tcp_port;
  const requestedServer = state.selected_server;
  const targetDescription = requestedServer ? state.servers.find((server) => server.id === requestedServer).name : "all nine regional endpoints";
  diagnosing = true;
  setBusy(busy);
  const panel = $("diagnostics");
  panel.hidden = false;
  panel.setAttribute("aria-busy", "true");
  $("diagnostics-results").hidden = true;
  $("download-diagnostics").hidden = true;
  setText($("diagnostics-heading"), "Checking the connection…");
  setText($("diagnostics-message"), state.method === "tcp" ? `Connecting to Google and ${targetDescription} on TCP port ${state.tcp_port}. Timing excludes DNS lookup and TLS.` : `Testing this computer, Google, and ${targetDescription} using ICMP echo. This can take up to 10 seconds.`);
  panel.scrollIntoView({ block: "start", behavior: "auto" });
  try {
    const report = await request("/api/diagnose", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }, 20000);
    setText($("diagnostics-heading"), report.summary.title);
    setText($("diagnostics-message"), report.summary.message);
    const body = $("diagnostics-checks");
    body.replaceChildren();
    report.checks.forEach((check) => {
      const row = document.createElement("tr");
      const tcp = report.method === "tcp";
      const result = check.status === "online" ? tcp ? "Connected" : "Reply received" : check.status === "refused" ? "Port closed" : check.status === "timeout" ? tcp ? "Connect timed out" : "No ICMP reply" : "Probe error";
      const values = [check.kind === "reference" ? "Internet (Google)" : check.name, check.hostname, result, ms(check.ms)];
      values.forEach((value, index) => {
        const cell = document.createElement(index === 0 ? "th" : "td");
        if (index === 0) cell.scope = "row";
        if (index === 2) cell.className = check.status === "online" ? "check-success" : "check-failure";
        cell.textContent = value;
        row.append(cell);
      });
      body.append(row);
    });
    diagnosticReport = diagnosticText(report);
    setText($("diagnostics-raw"), diagnosticReport);
    $("diagnostics-results").hidden = false;
    $("download-diagnostics").hidden = false;
  } catch (error) {
    setText($("diagnostics-heading"), "Connection check could not finish");
    const diagnosticCommand = `python3 pinger.py --method ${requestedMethod}${requestedMethod === "tcp" ? ` --tcp-port ${requestedPort}` : ""} --diagnose`;
    setText($("diagnostics-message"), error.name === "AbortError" ? requestedServer ? "The selected region’s diagnostic request took too long. Try again, or check the Python terminal for errors." : `The diagnostic request took too long. Run ${diagnosticCommand} in the terminal to get the raw results.` : error.message);
  } finally {
    diagnosing = false;
    panel.setAttribute("aria-busy", "false");
    setBusy(busy);
  }
}

function downloadDiagnosticReport() {
  if (!diagnosticReport) return;
  const url = URL.createObjectURL(new Blob([diagnosticReport], { type: "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "brawlhalla-connection-report.txt";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportResults() {
  if (!state) return;
  const tcp = state.method === "tcp";
  const columns = ["region", "hostname", "method", "tcp_port", "probe_time_utc", "probe_latency_ms", "probe_result", "session_attempts", "session_successes", "session_failures", "session_failure_percent", "session_average_ms", "session_min_ms", "session_max_ms", "session_jitter_ms", "interval_seconds"];
  const rows = [columns];
  state.servers.filter((server) => server.enabled !== false).forEach((server) => {
    const samples = server.history.length ? server.history : [{ timestamp: null, ms: null }];
    samples.forEach((sample) => rows.push([
      server.name, server.hostname, tcp ? "tcp_connect" : "icmp_echo", tcp ? state.tcp_port : "", sample.timestamp ? new Date(sample.timestamp * 1000).toISOString() : "",
      sample.ms, sample.timestamp ? isNumber(sample.ms) ? tcp ? "connected" : "reply" : tcp ? "connection failed" : "no ICMP reply" : "not measured",
      server.sent, server.received, server.lost, server.loss, server.avg_ms, server.min_ms, server.max_ms, server.jitter_ms, state.interval,
    ]));
  });
  const csv = "\uFEFF" + rows.map((row) => row.map((value) => `"${String(value == null ? "" : value).replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `brawlhalla-${tcp ? `tcp-${state.tcp_port}` : "icmp"}-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("Results exported, including the last 90 probes per region.");
}

REGIONS.forEach(buildCard);
setBusy(false);
$("toggle-button").addEventListener("click", () => control(state && state.running ? "stop" : "start"));
$("reset-button").addEventListener("click", () => control("reset"));
$("all-servers-button").addEventListener("click", () => selectServer("all"));
$("interval-select").addEventListener("change", (event) => control("interval", { seconds: Number(event.target.value) }));
$("method-select").addEventListener("change", (event) => {
  const value = event.target.value;
  control("method", value === "icmp" ? { method: "icmp" } : { method: "tcp", port: Number(value.split(":")[1]) });
});
$("sort-select").addEventListener("change", sortCards);
$("export-button").addEventListener("click", exportResults);
$("diagnose-button").addEventListener("click", diagnose);
$("notice-diagnose").addEventListener("click", diagnose);
$("download-diagnostics").addEventListener("click", downloadDiagnosticReport);
$("discover-button").addEventListener("click", discoverConnections);
$("target-cancel").addEventListener("click", () => $("target-dialog").close());
$("target-region").addEventListener("change", () => setBusy(busy));
$("target-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("target-error").hidden = true;
  if (await control("target", { id: $("target-region").value, hostname: $("target-hostname").value.trim() })) $("target-dialog").close();
});
$("target-default").addEventListener("click", async () => {
  $("target-error").hidden = true;
  if (await control("target", { id: $("target-region").value, hostname: "" })) $("target-dialog").close();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !busy) {
    clearTimeout(pollTimer);
    poll();
  }
});
poll();
