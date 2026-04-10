/**
 * dashboard.js — NetWatch Frontend Logic
 * ========================================
 * This file:
 *   1. Reads the filter controls (time window, protocol, device)
 *   2. Fetches data from Flask API endpoints (/api/...)
 *   3. Renders / updates Plotly charts
 *   4. Populates the packet table
 *   5. Shows anomaly warnings
 *   6. Auto-refreshes everything every REFRESH_INTERVAL seconds
 *
 * Beginner tip: All the fetch() calls return Promises.
 * We use async/await to make the code read top-to-bottom.
 */

"use strict";

// ── How often to refresh the dashboard (milliseconds) ─────────────────────
const REFRESH_INTERVAL = 5000;   // 5 seconds

// ── Plotly dark theme config shared by all charts ─────────────────────────
const PLOTLY_LAYOUT_BASE = {
  paper_bgcolor: "transparent",
  plot_bgcolor:  "transparent",
  font:          { family: "'Share Tech Mono', monospace", color: "#e2eaf5", size: 11 },
  margin:        { t: 10, r: 10, b: 40, l: 50 },
  xaxis: {
    gridcolor:  "#1e2d45",
    linecolor:  "#1e2d45",
    tickcolor:  "#5a7090",
    tickfont:   { color: "#5a7090" },
    zeroline:   false,
  },
  yaxis: {
    gridcolor:  "#1e2d45",
    linecolor:  "#1e2d45",
    tickcolor:  "#5a7090",
    tickfont:   { color: "#5a7090" },
    zeroline:   false,
  },
  legend: { font: { color: "#5a7090" }, bgcolor: "transparent" },
  showlegend: false,
};

const PLOTLY_CONFIG = {
  responsive:       true,
  displayModeBar:   false,   // hide the Plotly toolbar
};

// ── Protocol → colour mapping ──────────────────────────────────────────────
const PROTO_COLORS = {
  TCP:   "#0ea5e9",
  UDP:   "#a78bfa",
  DNS:   "#10b981",
  HTTP:  "#f97316",
  HTTPS: "#34d399",
  SSH:   "#ef4444",
  FTP:   "#f59e0b",
  OTHER: "#64748b",
};

function protoColor(name) {
  return PROTO_COLORS[name] || "#64748b";
}

// ── Track whether charts have been created yet ────────────────────────────
let chartsInitialised = false;


// ══════════════════════════════════════════════════════════════════════════
// HELPER: Read current filter values from the UI
// ══════════════════════════════════════════════════════════════════════════
function getFilters() {
  return {
    hours:    parseFloat(document.getElementById("filter-hours").value)    || 1,
    protocol: document.getElementById("filter-protocol").value             || "",
    device:   document.getElementById("filter-device").value.trim()        || "",
    limit:    parseInt(document.getElementById("filter-limit").value, 10)  || 50,
  };
}


// ══════════════════════════════════════════════════════════════════════════
// HELPER: Build a query string from an object
// ══════════════════════════════════════════════════════════════════════════
function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== "" && v !== null && v !== undefined) p.set(k, v);
  }
  const s = p.toString();
  return s ? "?" + s : "";
}


// ══════════════════════════════════════════════════════════════════════════
// HELPER: Format bytes to a human-readable string
// ══════════════════════════════════════════════════════════════════════════
function fmtBytes(bytes) {
  if (bytes >= 1_048_576) return (bytes / 1_048_576).toFixed(1) + " MB";
  if (bytes >= 1_024)     return (bytes / 1_024).toFixed(1) + " KB";
  return bytes + " B";
}


// ══════════════════════════════════════════════════════════════════════════
// UPDATE: Summary stat cards
// ══════════════════════════════════════════════════════════════════════════
async function updateStats(filters) {
  const res  = await fetch("/api/stats" + qs({ hours: filters.hours }));
  const data = await res.json();

  document.getElementById("s-packets").textContent  = data.total_packets.toLocaleString();
  document.getElementById("s-mb").innerHTML         =
    data.total_mb + '<span class="stat-unit">MB</span>';
  document.getElementById("s-devices").textContent  = data.unique_devices;
  document.getElementById("s-proto").textContent    = data.top_protocol;
}


// ══════════════════════════════════════════════════════════════════════════
// CHART: Bandwidth line chart
// ══════════════════════════════════════════════════════════════════════════
async function updateBandwidth(filters) {
  const res  = await fetch("/api/bandwidth" + qs({
    hours: filters.hours, protocol: filters.protocol, device: filters.device
  }));
  const data = await res.json();

  const x = data.map(r => r.bucket);
  const y = data.map(r => r.total_bytes);

  const trace = {
    x, y,
    type:      "scatter",
    mode:      "lines+markers",
    fill:      "tozeroy",
    fillcolor: "rgba(14,165,233,.12)",
    line:      { color: "#0ea5e9", width: 2 },
    marker:    { color: "#0ea5e9", size: 4 },
    hovertemplate: "<b>%{x}</b><br>%{customdata}<extra></extra>",
    customdata: y.map(fmtBytes),
  };

  const layout = {
    ...PLOTLY_LAYOUT_BASE,
    yaxis: {
      ...PLOTLY_LAYOUT_BASE.yaxis,
      tickformat: ".2s",   // SI prefix: 1K, 1M, etc.
      title: { text: "Bytes", font: { color: "#5a7090", size: 10 } },
    },
    height: 220,
  };

  if (!chartsInitialised) {
    Plotly.newPlot("chart-bandwidth", [trace], layout, PLOTLY_CONFIG);
  } else {
    Plotly.react("chart-bandwidth", [trace], layout, PLOTLY_CONFIG);
  }
}


// ══════════════════════════════════════════════════════════════════════════
// CHART: Protocol bar chart
// ══════════════════════════════════════════════════════════════════════════
async function updateProtocolChart(filters) {
  const res  = await fetch("/api/protocols" + qs({ hours: filters.hours }));
  const data = await res.json();

  const protos = data.map(r => r.protocol);
  const bytes  = data.map(r => r.total_bytes);
  const colors = protos.map(protoColor);

  const trace = {
    x: protos, y: bytes,
    type:    "bar",
    marker:  { color: colors, opacity: 0.85 },
    hovertemplate: "<b>%{x}</b><br>%{customdata}<extra></extra>",
    customdata: bytes.map(fmtBytes),
  };

  const layout = {
    ...PLOTLY_LAYOUT_BASE,
    yaxis: { ...PLOTLY_LAYOUT_BASE.yaxis, tickformat: ".2s" },
    height: 220,
    bargap: 0.25,
  };

  if (!chartsInitialised) {
    Plotly.newPlot("chart-protocol", [trace], layout, PLOTLY_CONFIG);
  } else {
    Plotly.react("chart-protocol", [trace], layout, PLOTLY_CONFIG);
  }
}


// ══════════════════════════════════════════════════════════════════════════
// CHART: Devices pie chart + anomaly detection
// ══════════════════════════════════════════════════════════════════════════
async function updateDevicesChart(filters) {
  const res  = await fetch("/api/devices" + qs({
    hours: filters.hours, protocol: filters.protocol
  }));
  const data = await res.json();

  // Collect anomalous IPs for the banner
  const anomalous = data.filter(r => r.anomaly).map(r => r.ip);
  const banner    = document.getElementById("anomaly-banner");
  const bannerTxt = document.getElementById("anomaly-text");

  if (anomalous.length > 0) {
    bannerTxt.textContent =
      `Unusually high traffic from: ${anomalous.join(", ")} — investigate immediately.`;
    banner.classList.remove("d-none");
  } else {
    banner.classList.add("d-none");
  }

  // Top 10 devices for the pie
  const top    = data.slice(0, 10);
  const labels = top.map(r => r.ip);
  const values = top.map(r => r.total_bytes);
  const colors = top.map(r =>
    r.anomaly ? "#ef4444" : ["#0ea5e9","#10b981","#a78bfa","#f97316",
                              "#f59e0b","#34d399","#60a5fa","#e879f9",
                              "#fb923c","#4ade80"][top.indexOf(r) % 10]
  );

  const trace = {
    labels, values,
    type:      "pie",
    hole:      0.45,         // donut style
    marker:    { colors, line: { color: "#0a0d14", width: 2 } },
    textinfo:  "none",
    hovertemplate: "<b>%{label}</b><br>%{customdata}<br>%{percent}<extra></extra>",
    customdata: values.map(fmtBytes),
  };

  const layout = {
    ...PLOTLY_LAYOUT_BASE,
    height:     240,
    showlegend: true,
    legend: {
      font:        { color: "#5a7090", size: 10, family: "'Share Tech Mono', monospace" },
      bgcolor:     "transparent",
      orientation: "v",
      x: 1.02, y: 0.5,
    },
    margin: { t: 10, r: 140, b: 10, l: 10 },
  };

  if (!chartsInitialised) {
    Plotly.newPlot("chart-devices", [trace], layout, PLOTLY_CONFIG);
  } else {
    Plotly.react("chart-devices", [trace], layout, PLOTLY_CONFIG);
  }
}


// ══════════════════════════════════════════════════════════════════════════
// TABLE: Latest packets
// ══════════════════════════════════════════════════════════════════════════
async function updateTable(filters) {
  const res  = await fetch("/api/packets" + qs({
    hours: filters.hours, protocol: filters.protocol,
    device: filters.device, limit: filters.limit
  }));
  const data = await res.json();

  document.getElementById("packet-count-badge").textContent =
    data.length + " packets";

  const tbody = document.getElementById("packet-table-body");

  if (data.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="6" class="text-center text-muted py-3">No packets in this window.</td></tr>';
    return;
  }

  // Build table rows — using textContent to prevent XSS
  const rows = data.map(pkt => {
    const tr   = document.createElement("tr");
    const time = pkt.timestamp ? pkt.timestamp.slice(11, 19) : "–"; // HH:MM:SS
    const badgeClass = "proto-" + (pkt.protocol || "OTHER");

    tr.innerHTML = `
      <td style="color:var(--text-muted)">${time}</td>
      <td>${esc(pkt.src_ip)}</td>
      <td>${esc(pkt.dst_ip)}</td>
      <td><span class="proto-badge ${badgeClass}">${esc(pkt.protocol)}</span></td>
      <td style="color:var(--text-muted)">${fmtBytes(pkt.size || 0)}</td>
      <td style="color:var(--text-muted);max-width:120px;overflow:hidden;text-overflow:ellipsis"
          title="${esc(pkt.info || '')}">${esc(pkt.info || "")}</td>
    `;
    return tr;
  });

  tbody.replaceChildren(...rows);
}

/** Escape HTML special characters to prevent XSS */
function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}


// ══════════════════════════════════════════════════════════════════════════
// MAIN REFRESH FUNCTION — calls all updaters in parallel
// ══════════════════════════════════════════════════════════════════════════
async function refresh() {
  const filters = getFilters();

  try {
    // Run all API calls at the same time for speed
    await Promise.all([
      updateStats(filters),
      updateBandwidth(filters),
      updateProtocolChart(filters),
      updateDevicesChart(filters),
      updateTable(filters),
    ]);

    // Mark charts as created so next call uses react() instead of newPlot()
    chartsInitialised = true;

    // Update "last refreshed" timestamp
    document.getElementById("last-update").textContent =
      "Updated " + new Date().toLocaleTimeString();

  } catch (err) {
    console.warn("Refresh error:", err);
  }
}


// ══════════════════════════════════════════════════════════════════════════
// DOWNLOAD REPORT HELPER
// ══════════════════════════════════════════════════════════════════════════
function downloadReport(format) {
  const filters = getFilters();
  const url = `/download/${format}${qs({ hours: filters.hours })}`;
  window.open(url, "_blank");
}


// ══════════════════════════════════════════════════════════════════════════
// INIT: Run on page load
// ══════════════════════════════════════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {
  // Kick off the first refresh immediately
  refresh();

  // Then repeat every REFRESH_INTERVAL ms
  setInterval(refresh, REFRESH_INTERVAL);

  // Re-refresh immediately when any filter changes
  ["filter-hours", "filter-protocol", "filter-limit"].forEach(id => {
    document.getElementById(id).addEventListener("change", () => {
      chartsInitialised = false;   // force chart rebuild on filter change
      refresh();
    });
  });

  // Device input: refresh after user stops typing (debounce 600ms)
  let deviceTimer;
  document.getElementById("filter-device").addEventListener("input", () => {
    clearTimeout(deviceTimer);
    deviceTimer = setTimeout(() => {
      chartsInitialised = false;
      refresh();
    }, 600);
  });
});
