const state = { data: null };
const STATIC = document.documentElement.classList.contains("static");
const THEME_KEY = "pe_theme";
const SESSION_DB = "portfolio-engine";
const SESSION_STORE = "auth";
const SESSION_DAYS = 30;

function $(id) {
  return document.getElementById(id);
}

function man(value) {
  if (value == null || Number.isNaN(value)) return "—";
  const n = Number(value);
  return n.toLocaleString("ja-JP", { maximumFractionDigits: 1 }) + "万";
}

function yen(value) {
  if (value == null || Number.isNaN(value)) return "—";
  return "¥" + Math.round(Number(value)).toLocaleString("ja-JP");
}

function sharePct(value) {
  if (value == null || Number.isNaN(value)) return "—";
  return Number(value).toFixed(1) + "%";
}

function pct(value, digits = 1) {
  if (value == null || Number.isNaN(value)) return "—";
  const n = Number(value);
  const sign = n > 0 ? "+" : "";
  return sign + n.toFixed(digits) + "%";
}

const ALLOC_COLORS = {
  US_STOCK: "#3d7ab5",
  JP_STOCK: "#c4892a",
  FUND: "#8b919a",
  CASH: "#2f9d63",
  CFD: "#9a6ca3",
  home: "#c4892a",
  condo: "#c43c3c",
  bank: "#6b7280",
  own_sec: "#3d7ab5",
  kids_nisa: "#2f9d63",
  dc: "#8b8074",
  fa: "#3d7ab5",
  home_eq: "#c4892a",
  core: "#3d7ab5",
  us: "#2f9d63",
  jp_sat: "#c4892a",
  cash_buf: "#8b919a",
  gold: "#c43c3c",
};

const PAGE_TITLES = {
  home: "資産",
  holdings: "証券",
  household: "資産計画",
  kids: "子供",
  alerts: "警報",
  review: "AIレビュー",
};

function polar(cx, cy, r, angle) {
  const rad = ((angle - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
}

function allocationPie(items) {
  const slices = (items || []).filter((item) => Number(item.weight_pct) > 0);
  if (!slices.length) {
    return `<p class="empty">構成データがありません。</p>`;
  }
  const total = slices.reduce((sum, item) => sum + Number(item.weight_pct), 0) || 1;
  let angle = 0;
  const paths = slices.map((item) => {
    const share = (Number(item.weight_pct) / total) * 360;
    const start = angle;
    const end = angle + share;
    angle = end;
    const color = ALLOC_COLORS[item.id] || "#9a9a9a";
    if (end - start >= 359.99) {
      return `<circle cx="50" cy="50" r="48" fill="${color}"></circle>`;
    }
    const large = end - start > 180 ? 1 : 0;
    const [x1, y1] = polar(50, 50, 48, start);
    const [x2, y2] = polar(50, 50, 48, end);
    const d = `M 50 50 L ${x1.toFixed(3)} ${y1.toFixed(3)} A 48 48 0 ${large} 1 ${x2.toFixed(3)} ${y2.toFixed(3)} Z`;
    return `<path d="${d}" fill="${color}"></path>`;
  });
  const legend = slices
    .map((item) => {
      const color = ALLOC_COLORS[item.id] || "#9a9a9a";
      return `<div class="pie-legend-row">
        <span class="pie-swatch" style="background:${color}"></span>
        <span>${item.label}</span>
        <span class="pie-pct">${sharePct(item.weight_pct)}</span>
      </div>`;
    })
    .join("");
  return `<div class="pie-wrap">
    <svg class="pie" viewBox="0 0 100 100" role="img" aria-label="資産配分">${paths.join("")}</svg>
    <div class="pie-legend">${legend}</div>
  </div>`;
}

function toneClass(value) {
  if (value == null || Number.isNaN(value) || value === 0) return "";
  return value > 0 ? "up" : "down";
}

function signedYen(value) {
  if (value == null || Number.isNaN(value)) return "—";
  const n = Math.round(Number(value));
  const sign = n > 0 ? "+" : "";
  return sign + "¥" + n.toLocaleString("ja-JP");
}

function b64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function decryptPayload(password, envelope) {
  const salt = b64ToBytes(envelope.salt);
  const nonce = b64ToBytes(envelope.nonce);
  const data = b64ToBytes(envelope.data);
  const iterations = Number(envelope.iter) || 400000;
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}

async function loadEncryptedDashboard(password) {
  const response = await fetch("./dashboard.enc.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("暗号化データを取得できませんでした");
  }
  const envelope = await response.json();
  try {
    return await decryptPayload(password, envelope);
  } catch (_err) {
    throw new Error("パスワードが違います");
  }
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let body = {};
  try {
    body = await response.json();
  } catch (_err) {
    body = {};
  }
  if (!response.ok) {
    const detail = body.detail;
    const message =
      typeof detail === "string"
        ? detail
        : Array.isArray(detail)
          ? "入力を確認してください"
          : "リクエストに失敗しました";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

function showLogin(message) {
  $("login").classList.remove("hidden");
  $("app").classList.add("hidden");
  if (message) {
    $("login-error").hidden = false;
    $("login-error").textContent = message;
  }
}

function showApp() {
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
}

function setPage(name) {
  document.querySelectorAll(".page").forEach((el) => {
    el.classList.toggle("active", el.dataset.page === name);
  });
  document.querySelectorAll(".tabbar button").forEach((el) => {
    el.classList.toggle("active", el.dataset.nav === name);
  });
  const title = $("page-title");
  if (title) title.textContent = PAGE_TITLES[name] || "資産";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function currentTheme() {
  return localStorage.getItem(THEME_KEY) || "light";
}

function applyTheme(theme) {
  const next = theme || currentTheme();
  document.documentElement.dataset.theme = next;
  const dark =
    next === "dark" ||
    (next === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  const color = dark ? "#111111" : "#F5F6F8";
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", color);
  document.querySelectorAll("[data-theme-choice]").forEach((button) => {
    button.classList.toggle("active", button.dataset.themeChoice === next);
  });
}

function setTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
  applyTheme(theme);
}

function openSessionDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(SESSION_DB, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(SESSION_STORE)) {
        db.createObjectStore(SESSION_STORE);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function bytesToB64(bytes) {
  const arr = new Uint8Array(bytes);
  let text = "";
  for (let i = 0; i < arr.length; i += 1) text += String.fromCharCode(arr[i]);
  return btoa(text);
}

async function saveViewSession(password) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(password)
  );
  const db = await openSessionDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(SESSION_STORE, "readwrite");
    tx.objectStore(SESSION_STORE).put(
      {
        v: 1,
        token: bytesToB64(raw),
        iv: bytesToB64(iv),
        wrapped: bytesToB64(wrapped),
        expires: Date.now() + SESSION_DAYS * 86400 * 1000,
      },
      "view"
    );
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function loadViewSessionPassword() {
  try {
    const db = await openSessionDb();
    const record = await new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readonly");
      const req = tx.objectStore(SESSION_STORE).get("view");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    db.close();
    if (!record || record.expires < Date.now() || !record.token) return "";
    const key = await crypto.subtle.importKey(
      "raw",
      b64ToBytes(record.token),
      "AES-GCM",
      false,
      ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(record.iv) },
      key,
      b64ToBytes(record.wrapped)
    );
    return new TextDecoder().decode(plain);
  } catch (_err) {
    return "";
  }
}

async function clearViewSession() {
  try {
    sessionStorage.removeItem("pe_view_pw");
    localStorage.removeItem("pe_view_pw");
    const db = await openSessionDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(SESSION_STORE, "readwrite");
      tx.objectStore(SESSION_STORE).delete("view");
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch (_err) {
    sessionStorage.removeItem("pe_view_pw");
    localStorage.removeItem("pe_view_pw");
  }
}

function isJpQuoteSymbol(symbol, assetType) {
  const s = String(symbol || "").trim();
  if (!s) return false;
  if (String(assetType || "") === "JP_STOCK") return true;
  return /\.T$/i.test(s);
}

function yahooQuoteUrl(symbol, assetType) {
  const encoded = encodeURIComponent(symbol);
  if (isJpQuoteSymbol(symbol, assetType)) {
    return `https://finance.yahoo.co.jp/quote/${encoded}`;
  }
  return `https://finance.yahoo.com/quote/${encoded}`;
}

function looksLikePublicTicker(ticker) {
  return /^[A-Z0-9][A-Z0-9.-]{0,15}$/i.test(ticker) && !/[ _]/.test(ticker);
}

function getFinanceUrl(item) {
  if (!item || item.asset_type === "CASH") return "";
  const financeUrl = String(item.finance_url || "").trim();
  if (financeUrl) return financeUrl;
  const yahooSymbol = String(item.yahoo_symbol || "").trim();
  if (yahooSymbol) return yahooQuoteUrl(yahooSymbol, item.asset_type);
  const ticker = String(item.ticker || "").trim();
  const name = String(item.name || ticker);
  if (item.asset_type === "FUND") {
    return `https://finance.yahoo.co.jp/search?query=${encodeURIComponent(name || ticker)}`;
  }
  if (!ticker) return "";
  if (item.asset_type === "JP_STOCK" || /\.T$/i.test(ticker) || looksLikePublicTicker(ticker)) {
    return yahooQuoteUrl(ticker, item.asset_type);
  }
  return `https://finance.yahoo.com/lookup?s=${encodeURIComponent(ticker)}`;
}

function row(title, meta, right, rightClass = "") {
  return `<article class="row">
    <div>
      <strong>${title}</strong>
      <small>${meta || ""}</small>
    </div>
    <div class="right ${rightClass}">${right}</div>
  </article>`;
}

const ACTION_TYPE_LABELS = {
  REVIEW: "見直し",
  BUY_MORE_CANDIDATE: "買い増し候補",
  REDUCE_CANDIDATE: "減らし候補",
  HOLD: "継続",
  WATCH: "監視",
};

const AI_STATUS_LABELS = {
  OK: "順調",
  WATCH: "注視",
  ATTENTION: "要確認",
};

function compactEngineSnapshot(data) {
  const holdings = [...(data.holdings || [])]
    .sort((a, b) => (Number(b.market_value_jpy) || 0) - (Number(a.market_value_jpy) || 0))
    .slice(0, 12)
    .map((h) => ({
      ticker: h.ticker,
      name: h.name,
      asset_type: h.asset_type,
      account: h.account,
      market_value_jpy: h.market_value_jpy,
      portfolio_weight_pct: h.portfolio_weight_pct,
      unrealized_pnl_pct: h.unrealized_pnl_pct,
      daily_change_pct: h.daily_change_pct,
    }));
  const plan = data.plan || {};
  const kids = data.kids || {};
  return {
    generated_at: data.generated_at,
    headline: data.headline,
    portfolio: data.portfolio,
    allocation: data.allocation,
    accounts: data.accounts,
    alerts: data.alerts,
    plan: {
      target_pie: plan.target_pie,
      sleeves: plan.sleeves,
      gaps: plan.gaps,
      actions: plan.actions,
      next90: plan.next90,
      principles: plan.principles,
      buckets: plan.buckets,
      financial_pct: plan.financial_pct,
      real_estate_pct: plan.real_estate_pct,
    },
    kids: { total_man: kids.total_man, note: kids.note },
    holdings,
    sleeves: plan.sleeves,
  };
}

function formatReviewStamp(iso) {
  const raw = String(iso || "");
  const match = raw.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return "";
  return `${match[1]}/${match[2]}/${match[3]} ${match[4]}:${match[5]}`;
}

function manToYen(manValue) {
  if (manValue == null || Number.isNaN(Number(manValue))) return null;
  return Number(manValue) * 10000;
}

function formatShortJst(iso) {
  const raw = String(iso || "");
  const match = raw.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return "";
  return `${Number(match[2])}/${Number(match[3])} ${match[4]}:${match[5]}`;
}

function researchItems(data) {
  const research = data && data.research;
  if (!research) return [];
  const items = research.items || research.top_items || [];
  return items.filter((item) => item && (item.title || item.summary || item.url));
}

function allowedResearchUrls(data) {
  const urls = new Set();
  researchItems(data).forEach((item) => {
    if (item.url) urls.add(String(item.url));
    (item.additional_sources || []).forEach((extra) => {
      if (extra && extra.url) urls.add(String(extra.url));
    });
  });
  return urls;
}

function impactSign(impact) {
  const value = String(impact || "").toUpperCase();
  if (value === "POSITIVE") return "＋";
  if (value === "NEGATIVE") return "－";
  return "±";
}

function impactTags(item) {
  const blob = [
    item.category,
    item.title,
    ...(item.related_holdings || []),
    ...(item.related_tickers || []),
  ].join(" ");
  const upper = blob.toUpperCase();
  const tags = [];
  if (/VTI|MAGS|S&P|SP500|米国/.test(upper)) tags.push("米国株");
  if (/USD|円安|円高|為替|JPY/.test(upper)) tags.push("USD/JPY");
  if (/3288|日本株|日経|TOPIX/.test(upper)) tags.push("日本株");
  if (!tags.length && item.category) tags.push(item.category);
  const sign = impactSign(item.impact);
  return tags.map((tag) => `影響 ${tag} ${sign}`).join("   ");
}

function sourceCite(item, linkLabel = "記事を開く") {
  if (!item || !item.url) return "";
  const source = item.source || "出典";
  const when = formatShortJst(item.published_at);
  return `<div class="source-line">
    <span class="source-label">根拠</span>
    <span>${escapeHtml(source)}${when ? "・" + escapeHtml(when) : ""}</span>
    <a class="source-link" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(linkLabel)}</a>
  </div>`;
}

function topicCard(item, index) {
  const pf = item.reason || item.summary || "";
  return `<article class="topic-card">
    <p class="topic-index">${index + 1}. ${escapeHtml(item.title || "")}</p>
    <p class="topic-impact">${escapeHtml(impactTags(item))}</p>
    ${pf ? `<p class="topic-pf">${escapeHtml(pf)}</p>` : ""}
    ${sourceCite(item, "記事を読む")}
  </article>`;
}

function historyPoints(data) {
  return ((data.asset_history && data.asset_history.points) || []).filter(
    (item) => item && item.date && item.total_assets_jpy != null
  );
}

function rangeStart(range, lastDate) {
  const end = new Date(`${lastDate}T00:00:00+09:00`);
  if (Number.isNaN(end.getTime()) || range === "ALL") return null;
  const days = { "1M": 31, "3M": 93, "6M": 186, "1Y": 370 }[range];
  if (!days) return null;
  end.setDate(end.getDate() - days);
  return end.toISOString().slice(0, 10);
}

function filterHistory(points, range) {
  if (!points.length) return [];
  const start = rangeStart(range, points[points.length - 1].date);
  if (!start) return points;
  const filtered = points.filter((item) => String(item.date) >= start);
  return filtered.length ? filtered : points.slice(-2);
}

function defaultHistoryRange(points) {
  if (points.length < 2) return "ALL";
  const span = filterHistory(points, "3M");
  return span.length >= 2 ? "3M" : "ALL";
}

let chartRange = "";

function renderAssetChart(data) {
  const host = $("asset-chart");
  if (!host) return;
  const all = historyPoints(data);
  if (!chartRange) chartRange = defaultHistoryRange(all);
  document.querySelectorAll("#chart-ranges [data-range]").forEach((button) => {
    button.classList.toggle("active", button.dataset.range === chartRange);
  });
  const points = filterHistory(all, chartRange);
  const note = $("chart-note");
  if (note) note.textContent = (data.asset_history && data.asset_history.series_note) || "残高推移";
  const latest = points[points.length - 1];
  const first = points[0];
  const valueEl = $("chart-value");
  const deltaEl = $("chart-delta");
  if (valueEl) valueEl.textContent = latest ? yen(latest.total_assets_jpy) : "—";
  if (deltaEl) {
    if (latest && first && points.length >= 2) {
      const delta = latest.total_assets_jpy - first.total_assets_jpy;
      const pctValue = first.total_assets_jpy ? (delta / first.total_assets_jpy) * 100 : null;
      deltaEl.textContent = `${signedYen(delta)}  ${pct(pctValue, 1)}`;
      deltaEl.className = "hero-sub " + toneClass(delta);
    } else {
      deltaEl.textContent = "データ蓄積中";
      deltaEl.className = "hero-sub muted";
    }
  }
  if (points.length < 2) {
    host.innerHTML = `<p class="muted">履歴が少ないため、今日から残高を記録します。</p>`;
    return;
  }
  const values = points.map((item) => Number(item.total_assets_jpy));
  const min = Math.min(...values);
  const max = Math.max(...values);
  const pad = max === min ? Math.abs(max) * 0.02 || 1 : (max - min) * 0.08;
  const lo = min - pad;
  const hi = max + pad;
  const w = 320;
  const h = 132;
  const coords = points.map((item, index) => {
    const x = points.length === 1 ? w / 2 : (index / (points.length - 1)) * w;
    const y = h - ((Number(item.total_assets_jpy) - lo) / (hi - lo)) * h;
    return [x.toFixed(1), y.toFixed(1)];
  });
  const line = coords.map((pair, index) => `${index ? "L" : "M"} ${pair[0]} ${pair[1]}`).join(" ");
  const area = `M 0 ${h} ${line.replace(/^M/, "L")} L ${w} ${h} Z`;
  const firstLabel = points[0].date.slice(5).replace("-", "/");
  const lastLabel = points[points.length - 1].date.slice(5).replace("-", "/");
  host.innerHTML = `<svg class="history-svg" viewBox="0 0 ${w} ${h + 18}" role="img" aria-label="保有資産合計の残高推移">
    <path d="${area}" class="history-fill"></path>
    <path d="${line}" class="history-line" fill="none"></path>
    <text x="0" y="${h + 14}" class="history-axis">${escapeHtml(firstLabel)}</text>
    <text x="${w}" y="${h + 14}" text-anchor="end" class="history-axis">${escapeHtml(lastLabel)}</text>
  </svg>`;
}

function renderAiTeaser(data) {
  const lines = $("ai-teaser-lines");
  if (!lines) return;
  const analysis = data.analysis || {};
  const changes = (analysis.important_changes || []).filter(Boolean).length;
  const attention = ((analysis.priority_actions || []).filter((item) => String(item.severity || "").toUpperCase() === "HIGH").length)
    || (String((analysis.overall || {}).status || "").toUpperCase() === "ATTENTION" ? 1 : 0);
  const bits = [];
  if (changes) bits.push(`重要な変化 ${changes}件`);
  if (attention) bits.push(`要確認 ${attention}件`);
  if (!bits.length) bits.push(analysis.overall && analysis.overall.headline ? analysis.overall.headline : "今日の確認事項は AIレビュー で見られます。");
  lines.textContent = bits.join("  ·  ");
}

function renderReview(data) {
  const analysis = data.analysis || {};
  const overall = analysis.overall || {};
  const plan = data.plan || {};
  const items = researchItems(data);
  const highItems = items.filter((item) => String(item.importance || "").toUpperCase() === "HIGH");
  const allowed = allowedResearchUrls(data);
  const analyzedAt = formatReviewStamp(analysis.analyzed_at || (data.ai && data.ai.analyzed_at) || "");

  const agentEl = $("review-agent");
  if (agentEl) agentEl.textContent = (data.ai && data.ai.agent_name) || "Portfolio Manager";
  const asOf = $("review-as-of");
  if (asOf) asOf.textContent = analyzedAt;

  const overallEl = $("review-overall");
  if (overallEl) {
    const text = analysis.overall_review || [overall.headline, overall.summary].filter(Boolean).join("\n");
    overallEl.innerHTML = text
      ? `<p class="insight-body">${escapeHtml(text)}</p>`
      : `<p class="muted">レビューは次の更新で表示します。</p>`;
  }

  const changesEl = $("review-changes");
  const changesBlock = $("review-changes-block");
  if (changesEl) {
    const delta = data.daily_delta || {};
    const lines = (analysis.important_changes || []).filter(Boolean);
    const fallback = (delta.summary_lines || []).filter(Boolean).slice(0, 4);
    const rows = (lines.length ? lines : fallback).map((line) => row(escapeHtml(line), "", "")).join("");
    changesEl.innerHTML = rows || `<p class="muted">比較対象なし</p>`;
  }
  if (changesBlock) changesBlock.hidden = false;

  const portfolioEl = $("review-portfolio");
  if (portfolioEl) {
    const assessment = analysis.portfolio_assessment
      ? `<p class="insight-body">${escapeHtml(analysis.portfolio_assessment)}</p>`
      : "";
    portfolioEl.innerHTML = `
      ${assessment}
      <div class="list">${sleeveRows(plan.sleeves)}</div>
      <div class="list review-gaps">${homeGapRows(plan, analysis)}</div>
    `;
  }

  const marketEl = $("review-market");
  const marketBlock = $("review-market-block");
  if (marketEl) {
    const impact = analysis.market_impact
      ? `<p class="insight-body">${escapeHtml(analysis.market_impact)}</p>`
      : "";
    const news = (highItems.length ? highItems : items).slice(0, 3).map((item, index) => topicCard(item, index)).join("");
    marketEl.innerHTML = impact + news;
  }
  if (marketBlock) {
    marketBlock.hidden = !(analysis.market_impact || highItems.length || items.length);
  }

  const actionsEl = $("review-actions");
  if (actionsEl) actionsEl.innerHTML = homeActionRows(plan, analysis) || `<p class="muted">今日追加で動かす案件はありません。</p>`;

  const whyEl = $("review-why");
  const whyBlock = $("review-why-block");
  if (whyEl) {
    const risks = (analysis.risks || []).map((line) => row(escapeHtml(line), "リスク", "")).join("");
    const ops = (analysis.opportunities || []).map((line) => row(escapeHtml(line), "機会", "")).join("");
    const watch = (analysis.watch_items || []).map((line) => row(escapeHtml(line), "監視", "")).join("");
    const rationale = analysis.rationale ? `<p class="insight-body">${escapeHtml(analysis.rationale)}</p>` : "";
    whyEl.innerHTML = rationale + risks + ops + watch;
    if (whyBlock) whyBlock.hidden = !(rationale || risks || ops || watch);
  }

  const sourcesEl = $("review-sources");
  const sourcesBlock = $("review-sources-block");
  if (sourcesEl) {
    const cites = (analysis.citations || [])
      .filter((item) => item && item.url && allowed.has(String(item.url)))
      .map((item) => sourceCite(item))
      .join("");
    sourcesEl.innerHTML = cites;
    if (sourcesBlock) sourcesBlock.hidden = !cites;
  }

  const reanalyze = $("ai-reanalyze");
  if (reanalyze) {
    const ai = data.ai || {};
    reanalyze.hidden = STATIC ? !(ai.worker_url && ai.analysis_token) : false;
  }
}

function formatFreshnessStamp(iso) {
  const raw = String(iso || "");
  const match = raw.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
  if (!match) return "";
  return `${Number(match[2])}/${Number(match[3])} ${match[4]}:${match[5]}`;
}

function renderFreshness(data) {
  const el = $("freshness-lines");
  if (!el) return;
  const fresh = data.freshness || {};
  const market = formatFreshnessStamp(fresh.market_at || data.generated_at);
  const researchAt = formatFreshnessStamp(fresh.research_at);
  const analysisAt = formatFreshnessStamp(fresh.analysis_at);
  const lines = [];
  if (market) lines.push(`データ更新 ${market}`);
  if (fresh.research_status === "stale" && researchAt) {
    lines.push(`Research 前回成功 ${researchAt}`);
  } else if (researchAt) {
    lines.push(`Research ${researchAt}`);
  }
  if (fresh.analysis_status === "stale" && analysisAt) {
    lines.push(`AI分析 前回成功 ${analysisAt}`);
  } else if (analysisAt) {
    lines.push(`AI分析 ${analysisAt}`);
  }
  el.textContent = lines.join("\n");
}

function sleeveRows(sleeves) {
  return (sleeves || [])
    .map((item) =>
      row(
        escapeHtml(item.label || item.id),
        `いま ${sharePct(item.current_pct)}`,
        `目標 ${sharePct(item.target_pct)}`
      )
    )
    .join("");
}

function homeGapRows(plan, analysis) {
  const aiGaps = (analysis && analysis.gaps) || [];
  const engineGaps = plan.gaps || [];
  if (aiGaps.length) {
    return aiGaps
      .map((gap, index) => {
        const title = gap.title || engineGaps[index] || "ギャップ";
        const currentTarget = [gap.current, gap.target].filter(Boolean).join(" → ");
        const meta = [currentTarget, gap.reason].filter(Boolean).join(" · ");
        return row(escapeHtml(title), escapeHtml(meta), "");
      })
      .join("");
  }
  return engineGaps.map((line) => row(escapeHtml(line), "", "")).join("");
}

function homeActionRows(plan, analysis) {
  const actions = ((analysis && analysis.priority_actions) || []).slice(0, 3);
  if (actions.length) {
    return actions
      .map((item) => {
        const tag = ACTION_TYPE_LABELS[item.action_type] || item.action_type || "";
        const ticker = item.ticker ? String(item.ticker) : "";
        const status = item.status === "NEW" ? "NEW" : item.status === "CONTINUING" ? "継続" : "";
        const right = [status, tag, ticker].filter(Boolean).join(" · ");
        return row(escapeHtml(item.title || ""), escapeHtml(item.reason || ""), escapeHtml(right));
      })
      .join("");
  }
  return (plan.actions || [])
    .slice(0, 3)
    .map((item) => row(escapeHtml(item.title), escapeHtml(item.detail || ""), ""))
    .join("");
}

function homeNextRows(plan, analysis) {
  const lines = (analysis && analysis.next_90_days) || [];
  if (lines.length) {
    return lines.map((line) => row(escapeHtml(line), "", "")).join("");
  }
  return (plan.next90 || []).map((line) => row(escapeHtml(line), "", "")).join("");
}

async function reanalyze() {
  const button = $("ai-reanalyze");
  const ai = (state.data && state.data.ai) || {};
  if (button) {
    button.disabled = true;
    button.textContent = "分析中";
  }
  try {
    if (!STATIC) {
      const result = await api("/api/analyze", { method: "POST" });
      if (!result.ok) {
        alert(result.message || "再分析できませんでした");
        return;
      }
      await loadDashboard();
      return;
    }
    if (!ai.worker_url || !ai.analysis_token) {
      alert("次回データ更新時に再分析されます。");
      return;
    }
    const endpoint = String(ai.worker_url).replace(/\/$/, "") + "/analyze";
    const response = await fetch(endpoint, {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + ai.analysis_token,
      },
      body: JSON.stringify({ engine: compactEngineSnapshot(state.data) }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.analysis) {
      throw new Error(body.message || "再分析に失敗しました");
    }
    state.data.analysis = body.analysis;
    state.data.ai = { ...(state.data.ai || {}), status: "ready", stale: false };
    render(state.data);
  } catch (err) {
    if (err.status === 401) showLogin("再ログインしてください");
    else alert(err.message || "再分析に失敗しました");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "再分析";
    }
  }
}

function tvCandidates(ticker) {
  const t = String(ticker || "").trim();
  if (!t) return [];
  if (t === "JPY=X" || t === "USDJPY=X") return ["FX_IDC:USDJPY"];
  if (t.endsWith("=X")) return [`FX_IDC:${t.slice(0, -2)}`];
  if (t.endsWith(".T")) return [`TSE:${t.slice(0, -2)}`];
  if (t.endsWith("-USD")) {
    const base = t.replace(/-USD$/, "");
    return [`BITSTAMP:${base}USD`, `COINBASE:${base}USD`, `BINANCE:${base}USDT`];
  }
  return ["CBOE", "AMEX", "NASDAQ", "NYSEARCA", "NYSE", "BATS", "OTC"].map((ex) => `${ex}:${t}`);
}

function quoteFromClose(close, changePct, changeAbs) {
  const price = Number(close);
  if (!Number.isFinite(price) || price <= 0) return null;
  let previousClose = NaN;
  if (changeAbs != null && Number.isFinite(Number(changeAbs))) {
    previousClose = price - Number(changeAbs);
  } else if (changePct != null && Number.isFinite(Number(changePct)) && Number(changePct) > -100) {
    previousClose = price / (1 + Number(changePct) / 100);
  }
  if (!Number.isFinite(previousClose) || previousClose <= 0) previousClose = price;
  return { price, previousClose };
}

function parseYahooChart(body) {
  const meta = body && body.chart && body.chart.result && body.chart.result[0] && body.chart.result[0].meta;
  if (!meta || meta.regularMarketPrice == null) return null;
  return {
    price: Number(meta.regularMarketPrice),
    previousClose: Number(meta.chartPreviousClose || meta.previousClose || meta.regularMarketPrice),
  };
}

async function fetchTradingViewQuotes(tickers) {
  const unique = [...new Set(tickers.filter(Boolean))];
  const tvTickers = [];
  unique.forEach((ticker) => {
    tvCandidates(ticker).forEach((symbol) => tvTickers.push(symbol));
  });
  if (!tvTickers.length) return new Map();
  const response = await fetch("https://scanner.tradingview.com/global/scan", {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    headers: { "Content-Type": "text/plain" },
    body: JSON.stringify({
      symbols: { tickers: tvTickers, query: { types: [] } },
      columns: ["close", "change", "change_abs"],
      range: [0, tvTickers.length],
    }),
  });
  if (!response.ok) throw new Error("quotes");
  const body = await response.json();
  const rowsBySymbol = new Map((body.data || []).map((row) => [row.s, row]));
  const out = new Map();
  unique.forEach((ticker) => {
    tvCandidates(ticker).some((symbol) => {
      const row = rowsBySymbol.get(symbol);
      if (!row) return false;
      const quote = quoteFromClose((row.d || [])[0], (row.d || [])[1], (row.d || [])[2]);
      if (!quote) return false;
      out.set(ticker, quote);
      return true;
    });
  });
  return out;
}

async function fetchYahooViaReader(ticker) {
  const yahooUrl = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(
    ticker
  )}?interval=1d&range=5d`;
  const response = await fetch(`https://r.jina.ai/${yahooUrl}`, {
    cache: "no-store",
    credentials: "omit",
  });
  if (!response.ok) throw new Error(ticker);
  const text = await response.text();
  const start = text.indexOf('{"chart"');
  if (start < 0) throw new Error(ticker);
  let depth = 0;
  let end = -1;
  for (let i = start; i < text.length; i += 1) {
    if (text[i] === "{") depth += 1;
    else if (text[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  const quote = parseYahooChart(JSON.parse(text.slice(start, end)));
  if (!quote) throw new Error(ticker);
  return quote;
}

async function fetchUsdJpyFallback() {
  const response = await fetch("https://api.frankfurter.dev/v1/latest?base=USD&symbols=JPY", {
    cache: "no-store",
    credentials: "omit",
  });
  if (!response.ok) throw new Error("fx");
  const body = await response.json();
  const rate = body && body.rates && Number(body.rates.JPY);
  if (!rate) throw new Error("fx");
  return { price: rate, previousClose: rate };
}

function holdingFx(item, usdJpy) {
  const ccy = String(item && item.currency ? item.currency : "").toUpperCase();
  const asset = String(item && item.asset_type ? item.asset_type : "");
  if (ccy === "USD" || asset === "US_STOCK") return Number(usdJpy) || 0;
  if (ccy === "JPY" || asset === "JP_STOCK" || asset === "FUND" || asset === "CASH") return 1;
  const ticker = String(item && item.ticker ? item.ticker : "");
  if (ticker && !/\.T$/i.test(ticker) && /^[A-Z0-9.-]+$/i.test(ticker)) {
    return Number(usdJpy) || 0;
  }
  return 1;
}

function applyLiveQuote(item, quote, usdJpy, prevUsdJpy) {
  const quantity = Number(item.quantity);
  const divisor = Number(item.price_divisor) || 1;
  const avgCost = Number(item.avg_cost) || 0;
  const prevValue = Number(item.market_value_jpy);
  const oldPrice = Number(item.current_price);
  const fx = holdingFx(item, usdJpy);
  if (!fx) return false;
  let marketValueJpy = null;
  if (Number.isFinite(prevValue) && prevValue > 0 && Number.isFinite(oldPrice) && oldPrice > 0) {
    marketValueJpy = prevValue * (quote.price / oldPrice);
    const oldFx = holdingFx(item, prevUsdJpy || fx);
    if (oldFx && oldFx !== fx) marketValueJpy *= fx / oldFx;
  } else if (Number.isFinite(quantity) && quantity !== 0) {
    marketValueJpy = ((quantity * quote.price) / divisor) * fx;
  }
  if (marketValueJpy == null || !Number.isFinite(marketValueJpy)) return false;
  if (Number.isFinite(prevValue) && prevValue > 1000 && marketValueJpy < prevValue * 0.2) {
    return false;
  }
  const hasQty = Number.isFinite(quantity) && quantity !== 0;
  const localValue = hasQty ? (quantity * quote.price) / divisor : marketValueJpy / (fx || 1);
  const costLocal = hasQty ? (quantity * avgCost) / divisor : null;
  const costJpy = item.cost_basis_jpy != null ? Number(item.cost_basis_jpy) : costLocal != null ? costLocal * fx : null;
  const prevLocal = hasQty
    ? (quantity * quote.previousClose) / divisor
    : quote.price
      ? localValue * (quote.previousClose / quote.price)
      : localValue;
  const dailyJpy = (localValue - prevLocal) * fx;
  item.current_price = quote.price;
  item.market_value_jpy = marketValueJpy;
  if (costJpy != null && Number.isFinite(costJpy)) {
    item.unrealized_pnl = marketValueJpy - costJpy;
    item.unrealized_pnl_jpy = item.unrealized_pnl;
    item.unrealized_pnl_pct = costJpy ? ((marketValueJpy - costJpy) / costJpy) * 100 : null;
  }
  item.daily_change_pct =
    quote.previousClose ? ((quote.price - quote.previousClose) / quote.previousClose) * 100 : null;
  item.daily_change_jpy = dailyJpy;
  item.price_status = "OK";
  return true;
}

async function refreshLiveQuotes() {
  const data = state.data;
  if (!data || !data.holdings) {
    throw new Error("表示データがありません");
  }
  const liveable = (data.holdings || []).filter(
    (item) => item.asset_type !== "CASH" && item.price_status !== "MANUAL" && item.ticker
  );
  const tickers = liveable.map((item) => item.ticker);
  let quotes = new Map();
  try {
    quotes = await fetchTradingViewQuotes(["JPY=X", ...tickers]);
  } catch (_err) {
    quotes = new Map();
  }
  const missing = ["JPY=X", ...tickers].filter((ticker) => !quotes.has(ticker));
  if (missing.length) {
    const extras = await Promise.allSettled(
      missing.map(async (ticker) => {
        if (ticker === "JPY=X") {
          quotes.set(ticker, await fetchUsdJpyFallback());
          return;
        }
        quotes.set(ticker, await fetchYahooViaReader(ticker));
      })
    );
    extras.forEach((result, index) => {
      if (result.status === "rejected") quotes.delete(missing[index]);
    });
  }
  let usdJpy = Number((quotes.get("JPY=X") && quotes.get("JPY=X").price) || 0);
  if (!usdJpy) usdJpy = Number((data.headline && data.headline.usd_jpy) || (data.fx && data.fx.USD) || 0);
  if (!usdJpy) throw new Error("為替を取得できませんでした");
  const prevUsdJpy = Number((data.headline && data.headline.usd_jpy) || (data.fx && data.fx.USD) || usdJpy);
  let failed = 0;
  liveable.forEach((item) => {
    const quote = quotes.get(item.ticker);
    if (!quote || !applyLiveQuote(item, quote, usdJpy, prevUsdJpy)) {
      failed += 1;
    }
  });
  if (liveable.length && failed === liveable.length) {
    throw new Error("株価を取得できませんでした。通信環境を確認してください。");
  }
  const holdings = data.holdings || [];
  const market = holdings.reduce((sum, item) => sum + (Number(item.market_value_jpy) || 0), 0);
  const pnl = holdings.reduce(
    (sum, item) => sum + (Number(item.unrealized_pnl_jpy ?? item.unrealized_pnl) || 0),
    0
  );
  const daily = holdings.reduce((sum, item) => sum + (Number(item.daily_change_jpy) || 0), 0);
  const cost = market - pnl;
  data.portfolio = data.portfolio || {};
  data.portfolio.market_value = market;
  data.portfolio.unrealized_pnl = pnl;
  data.portfolio.unrealized_pnl_pct = cost ? (pnl / cost) * 100 : null;
  data.portfolio.daily_change = daily;
  data.portfolio.daily_change_pct = market - daily ? (daily / (market - daily)) * 100 : null;
  if (data.headline) {
    data.headline.usd_jpy = usdJpy;
    data.headline.daily_change_jpy = daily;
    data.headline.daily_change_pct = data.portfolio.daily_change_pct;
    data.headline.unrealized_pnl_jpy = pnl;
    data.headline.unrealized_pnl_pct = data.portfolio.unrealized_pnl_pct;
  }
  if (data.fx) data.fx.USD = usdJpy;
  data.generated_at =
    new Date().toLocaleString("sv-SE", { timeZone: "Asia/Tokyo" }).replace(" ", "T") + "+09:00";
  render(data);
}

async function refreshPrices() {
  const button = $("holdings-refresh") || $("refresh");
  if (button) {
    button.disabled = true;
    button.textContent = "更新中";
  }
  try {
    if (STATIC) {
      await refreshLiveQuotes();
    } else {
      await api("/api/refresh", { method: "POST" });
      await loadDashboard();
    }
  } catch (err) {
    if (err.status === 401) showLogin("再ログインしてください");
    else alert(err.message || "更新に失敗しました");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "更新";
    }
  }
}

function render(data) {
  state.data = data;
  const h = data.headline || {};
  const plan = data.plan || {};
  const household = (data.household && data.household.totals) || {};
  $("as-of").textContent = (data.generated_at || "").replace("T", " ").slice(0, 16);
  const totalYen = manToYen(household.assets_man != null ? household.assets_man : plan.total_assets_man);
  if ($("net-worth")) $("net-worth").textContent = yen(totalYen);
  const defs = $("hero-defs");
  if (defs) {
    defs.textContent = [
      household.financial_man != null ? `金融 ${man(household.financial_man)}` : "",
      h.net_worth_man != null ? `純資産 ${man(h.net_worth_man)}` : "",
    ]
      .filter(Boolean)
      .join("  ·  ");
  }

  const daily = `${signedYen(h.daily_change_jpy)}  ${pct(h.daily_change_pct, 2)}  USD/JPY ${
    h.usd_jpy != null ? Number(h.usd_jpy).toFixed(2) : "—"
  }`;
  if ($("daily")) {
    $("daily").textContent = daily;
    $("daily").className = "hero-sub " + toneClass(h.daily_change_jpy);
  }

  const sleevePie = (plan.sleeves || []).map((item) => ({
    id: item.id,
    label: item.label,
    weight_pct: item.current_pct,
  }));
  $("alloc-chart").innerHTML = allocationPie(sleevePie.length ? sleevePie : data.allocation);

  const p = data.portfolio || {};
  $("sec-value").textContent = yen(p.market_value);
  $("sec-pnl").textContent = `${signedYen(p.unrealized_pnl)}  ${pct(p.unrealized_pnl_pct)}`;
  $("sec-pnl").className = "hero-sub " + toneClass(p.unrealized_pnl);

  $("holdings").innerHTML = (data.holdings || [])
    .map((item) => {
      const dailyPct = item.price_status === "MANUAL" ? "—" : pct(item.daily_change_pct, 2);
      const url = getFinanceUrl(item);
      const name = escapeHtml(item.name || item.ticker || "");
      const ticker = escapeHtml(item.ticker || "");
      const title = url
        ? `<a class="holding-name" href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${name}</a>`
        : `<strong>${name}</strong>`;
      const custody = item.custody_label || item.tax_account_label || "";
      const broker = item.broker_label || "";
      const meta = [broker, custody].filter(Boolean).join(" · ");
      return `<article class="holding-card">
      <div>
        ${title}
        <small class="holding-ticker">${ticker}</small>
        <small>${escapeHtml(meta)}</small>
      </div>
      <div class="holding-metrics">
        <div><span>評価額</span><strong>${yen(item.market_value_jpy)}</strong></div>
        <div><span>損益</span><strong class="${toneClass(item.unrealized_pnl_jpy ?? item.unrealized_pnl)}">${signedYen(item.unrealized_pnl_jpy ?? item.unrealized_pnl)} ${pct(item.unrealized_pnl_pct)}</strong></div>
        <div><span>前日比</span><strong class="${toneClass(item.daily_change_pct)}">${dailyPct}</strong></div>
        <div><span>構成比</span><strong>${sharePct(item.portfolio_weight_pct)}</strong></div>
      </div>
    </article>`;
    })
    .join("");

  $("plan-sub").textContent = plan.subtitle || "";
  $("plan-rate").textContent = plan.rate_note || "";
  $("plan-disclaimer").textContent = plan.disclaimer || "";
  $("plan-goal-note").textContent = plan.goal_note || "";
  $("plan-stats").innerHTML = [
    ["総資産", man(plan.total_assets_man)],
    ["金融", `${man(h.financial_man)}（${sharePct(plan.financial_pct)}）`],
    ["不動産", `${man(plan.real_estate_man)}（${sharePct(plan.real_estate_pct)}）`],
    ["純資産", man(h.net_worth_man)],
  ]
    .map(
      ([label, value]) =>
        `<article><p class="muted">${label}</p><p>${value}</p></article>`
    )
    .join("");
  $("plan-gross-pie").innerHTML = allocationPie(plan.gross_pie);
  $("plan-net-pie").innerHTML = allocationPie(plan.net_pie);
  $("plan-target-pie").innerHTML = allocationPie(plan.target_pie);
  if ($("plan-sleeves")) $("plan-sleeves").innerHTML = sleeveRows(plan.sleeves);
  const sleeveNote = $("plan-sleeve-note");
  if (sleeveNote) {
    sleeveNote.textContent = plan.sleeve_note || "";
    sleeveNote.hidden = !plan.sleeve_note;
  }
  $("plan-buckets").innerHTML = (plan.buckets || [])
    .map((item) => row(item.name, item.detail, item.size))
    .join("");
  $("plan-principles-list").innerHTML = (plan.principles || [])
    .map((line) => `<div>${line}</div>`)
    .join("");
  const gapRows = (plan.gaps || []).map((line) => row(line, "", "")).join("");
  const actionRows = (plan.actions || [])
    .slice(0, 3)
    .map((item) => row(item.title, item.detail, ""))
    .join("");
  $("plan-gaps").innerHTML = gapRows;
  $("plan-actions").innerHTML = actionRows;
  renderFreshness(data);
  renderAssetChart(data);
  renderAiTeaser(data);
  renderReview(data);
  if ($("home-gaps")) $("home-gaps").innerHTML = homeGapRows(plan, data.analysis);
  $("plan-events").innerHTML = (plan.events || [])
    .map((item) => row(item.event, item.note, item.when))
    .join("");
  $("plan-goals").innerHTML = (plan.goals || [])
    .map((item) => {
      const status = item.met ? "達成" : "未達";
      return row(
        `${item.year}　${item.label}`,
        `いま ${man(item.current_man)}`,
        status,
        item.met ? "up" : ""
      );
    })
    .join("");
  $("plan-next").innerHTML = (plan.next90 || [])
    .map((line) => row(line, "", ""))
    .join("");

  $("kids-note").textContent = (data.kids && data.kids.note) || "";
  $("kids").innerHTML = ((data.kids && data.kids.children) || [])
    .map((child) => {
      const plan = child.plan || {};
      return `<article class="kid-card">
        <h3>${child.name}　${man(child.total_man)}</h3>
        <div class="plan">
          <div>ジュニアNISA　${man(child.nisa_man)}　<small class="muted">${child.nisa_note || ""}</small></div>
          <div>ゆうちょ　${man(child.yucho_man)}</div>
          <div>推奨 現金　${man(plan.cash)}（${plan.cash_pct}%）</div>
          <div>推奨 変動国債　${man(plan.jgb)}</div>
        </div>
      </article>`;
    })
    .join("");

  const alerts = data.alerts || [];
  $("alerts").innerHTML = alerts.length
    ? alerts
        .map((a) => row(a.name || a.ticker, a.alert_type, a.message || ""))
        .join("")
    : `<p class="empty">いま警報はありません。</p>`;
}

async function loadDashboard() {
  const data = await api("/api/dashboard");
  render(data);
  showApp();
}

async function openStatic(password, persist = true) {
  const data = await loadEncryptedDashboard(password);
  if (persist) await saveViewSession(password);
  sessionStorage.removeItem("pe_view_pw");
  localStorage.removeItem("pe_view_pw");
  render(data);
  showApp();
}

async function bootStatic() {
  const saved = await loadViewSessionPassword();
  if (!saved) {
    showLogin();
    return;
  }
  try {
    await openStatic(saved, false);
  } catch (err) {
    await clearViewSession();
    showLogin(err.message);
  }
}

async function boot() {
  if (STATIC) {
    await bootStatic();
    return;
  }
  try {
    const session = await api("/api/session");
    if (!session.ok) {
      showLogin();
      return;
    }
    await loadDashboard();
  } catch (err) {
    showLogin(err.message);
  }
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").hidden = true;
  const secret = ($("password") && $("password").value) || "";
  try {
    if (STATIC) {
      await openStatic(secret, true);
      return;
    }
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password: secret, pin: secret }),
    });
    await loadDashboard();
  } catch (err) {
    showLogin(err.message);
  }
});

$("refresh").addEventListener("click", () => {
  refreshPrices();
});

if ($("holdings-refresh")) {
  $("holdings-refresh").addEventListener("click", () => {
    refreshPrices();
  });
}

if ($("ai-reanalyze")) {
  $("ai-reanalyze").addEventListener("click", () => {
    reanalyze();
  });
}

if ($("ai-review")) {
  $("ai-review").addEventListener("click", () => setPage("review"));
}

if ($("topics-more")) {
  $("topics-more").addEventListener("click", () => setPage("review"));
}

document.querySelectorAll("#chart-ranges [data-range]").forEach((button) => {
  button.addEventListener("click", () => {
    chartRange = button.dataset.range || "3M";
    if (state.data) renderAssetChart(state.data);
  });
});

document.querySelectorAll("[data-back]").forEach((button) => {
  button.addEventListener("click", () => setPage(button.dataset.back || "home"));
});

document.querySelectorAll(".tabbar button").forEach((button) => {
  button.addEventListener("click", () => setPage(button.dataset.nav));
});

document.querySelectorAll("[data-theme-choice]").forEach((button) => {
  button.addEventListener("click", () => setTheme(button.dataset.themeChoice));
});
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (currentTheme() === "system") applyTheme("system");
});
applyTheme(currentTheme());

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register(STATIC ? "./sw.js" : "/sw.js");
}

boot();
