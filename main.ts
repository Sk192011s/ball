import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// ====== Environment Variables ======
const MATCH_API_BASE = Deno.env.get("MATCH_API_BASE") || "";
const ROOM_API_BASE = Deno.env.get("ROOM_API_BASE") || "";
const API_REFERER = Deno.env.get("API_REFERER") || "";
const API_USER_AGENT = Deno.env.get("API_USER_AGENT") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// ====== SECURITY: Rate Limiter ======
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60_000; // 1 minute
const RATE_LIMIT_MAX = 60; // max 60 requests per minute per IP
const BLOCK_THRESHOLD = 200; // block if > 200 requests in window
const blockedIPs = new Map<string, number>(); // IP -> block expiry time

function getClientIP(req: Request): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-real-ip") ||
    "unknown"
  );
}

function isRateLimited(ip: string): { limited: boolean; blocked: boolean } {
  const now = Date.now();

  // Check if IP is blocked
  const blockExpiry = blockedIPs.get(ip);
  if (blockExpiry && now < blockExpiry) {
    return { limited: true, blocked: true };
  } else if (blockExpiry) {
    blockedIPs.delete(ip);
  }

  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return { limited: false, blocked: false };
  }

  entry.count++;

  // Auto-block if way too many requests (bot behavior)
  if (entry.count > BLOCK_THRESHOLD) {
    blockedIPs.set(ip, now + 10 * 60_000); // Block for 10 minutes
    return { limited: true, blocked: true };
  }

  if (entry.count > RATE_LIMIT_MAX) {
    return { limited: true, blocked: false };
  }

  return { limited: false, blocked: false };
}

// Clean up stale entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetTime) rateLimitMap.delete(ip);
  }
  for (const [ip, expiry] of blockedIPs) {
    if (now > expiry) blockedIPs.delete(ip);
  }
}, 5 * 60_000);

// ====== SECURITY: Suspicious Request Detection ======
function isSuspiciousRequest(req: Request): boolean {
  const ua = req.headers.get("user-agent") || "";
  const url = new URL(req.url);

  // Block empty user agents (common in bots/scripts)
  if (!ua || ua.length < 10) return true;

  // Block known malicious bot patterns
  const botPatterns = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i,
    /dirbuster/i, /gobuster/i, /wfuzz/i, /hydra/i,
    /burpsuite/i, /nessus/i, /openvas/i, /acunetix/i,
    /zgrab/i, /nuclei/i, /httpx/i, /crawl.*bot/i,
    /python-requests/i, /go-http-client/i, /curl\//i,
    /wget\//i, /scrapy/i, /phantomjs/i, /headless/i,
  ];
  if (botPatterns.some(p => p.test(ua))) return true;

  // Block path traversal attempts
  const path = url.pathname;
  if (path.includes("..") || path.includes("//") || path.includes("\\")) return true;

  // Block common vulnerability probing paths
  const maliciousPaths = [
    /\.env/i, /\.git/i, /wp-admin/i, /wp-login/i,
    /phpmyadmin/i, /admin/i, /\.php/i, /\.asp/i,
    /shell/i, /eval/i, /exec/i, /config/i,
    /\.sql/i, /backup/i, /\.bak/i, /\.log/i,
  ];
  if (maliciousPaths.some(p => p.test(path))) return true;

  // Block SQL injection patterns in query strings
  const query = url.search;
  const sqlPatterns = [
    /union.*select/i, /or\s+1\s*=\s*1/i, /drop\s+table/i,
    /insert\s+into/i, /delete\s+from/i, /script>/i,
    /<iframe/i, /javascript:/i, /onerror/i, /onload/i,
  ];
  if (sqlPatterns.some(p => p.test(query))) return true;

  return false;
}

// ====== SECURITY: Response Headers ======
function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy":
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; " +
      "img-src * data:; " +
      "media-src *; " +
      "connect-src 'self';",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  };
}

serve(async (req) => {
  const url = new URL(req.url);
  const clientIP = getClientIP(req);

  // --- SECURITY: Rate Limiting ---
  const { limited, blocked } = isRateLimited(clientIP);
  if (blocked) {
    return new Response(
      JSON.stringify({ error: "Blocked: Too many requests. Try again later." }),
      {
        status: 403,
        headers: { "Content-Type": "application/json", "Retry-After": "600", ...securityHeaders() },
      }
    );
  }
  if (limited) {
    return new Response(
      JSON.stringify({ error: "Rate limit exceeded. Please slow down." }),
      {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "60", ...securityHeaders() },
      }
    );
  }

  // --- SECURITY: Suspicious Request Detection ---
  if (isSuspiciousRequest(req)) {
    // Return 404 to not reveal we detected them
    return new Response("Not Found", { status: 404, headers: securityHeaders() });
  }

  // --- SECURITY: Method validation ---
  if (req.method !== "GET") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET", ...securityHeaders() },
    });
  }

  // --- 1. API ROUTE (Backend) ---
  if (url.pathname === "/api/matches") {
    try {
      const getVNDate = (offset: number) => {
        const d = new Date();
        d.setDate(d.getDate() + offset);
        return new Intl.DateTimeFormat("en-CA", {
          timeZone: "Asia/Ho_Chi_Minh",
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
        })
          .format(d)
          .replace(/-/g, "");
      };

      const dates = [getVNDate(-1), getVNDate(0), getVNDate(1)];

      let allMatches: any[] = [];
      for (const d of dates) {
        const matches = await fetchMatches(d);
        allMatches = allMatches.concat(matches);
      }

      allMatches.sort((a, b) => {
        if (a.match_status === "live" && b.match_status !== "live") return -1;
        if (a.match_status !== "live" && b.match_status === "live") return 1;
        if (a.match_status === "upcoming" && b.match_status === "finished") return -1;
        if (a.match_status === "finished" && b.match_status === "upcoming") return 1;
        return 0;
      });

      return new Response(JSON.stringify(allMatches), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=30",
          ...securityHeaders(),
        },
      });
    } catch (e: any) {
      return new Response(JSON.stringify({ error: "Service temporarily unavailable" }), {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          ...securityHeaders(),
        },
      });
    }
  }

  // --- 2. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    return new Response(getHTML(), {
      headers: { "Content-Type": "text/html; charset=utf-8", ...securityHeaders() },
    });
  }

  return new Response("Not Found", { status: 404, headers: securityHeaders() });
});

// ====== FRONTEND HTML — PREMIUM BRIGHT UI ======
function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>⚽ Soco All Sports Live</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }

    body {
      background: #0b0f1a;
      color: #f1f5f9;
      font-family: 'Inter', 'Padauk', sans-serif;
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* Ambient background glow */
    body::before {
      content: '';
      position: fixed;
      top: -40%;
      left: -20%;
      width: 80%;
      height: 80%;
      background: radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 60%);
      pointer-events: none;
      z-index: 0;
    }
    body::after {
      content: '';
      position: fixed;
      bottom: -30%;
      right: -20%;
      width: 70%;
      height: 70%;
      background: radial-gradient(circle, rgba(250,204,21,0.06) 0%, transparent 60%);
      pointer-events: none;
      z-index: 0;
    }

    .app-container {
      position: relative;
      z-index: 1;
    }

    /* ===== HEADER ===== */
    .premium-header {
      background: linear-gradient(135deg, rgba(15,23,42,0.95) 0%, rgba(30,41,59,0.9) 100%);
      border-bottom: 1px solid rgba(255,255,255,0.06);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      position: sticky;
      top: 0;
      z-index: 40;
    }
    .header-title {
      background: linear-gradient(135deg, #facc15, #f59e0b, #fbbf24);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-weight: 900;
      letter-spacing: -0.5px;
    }
    .header-subtitle {
      color: #64748b;
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    /* ===== LIVE DOT ===== */
    .live-dot {
      width: 8px; height: 8px;
      background: #ef4444;
      border-radius: 50%;
      display: inline-block;
      animation: pulse-dot 1s ease-in-out infinite;
      box-shadow: 0 0 8px rgba(239,68,68,0.6), 0 0 20px rgba(239,68,68,0.3);
    }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.7); }
    }

    /* ===== CARDS ===== */
    .card {
      background: linear-gradient(145deg, rgba(30,41,59,0.7), rgba(15,23,42,0.8));
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 20px;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    }
    .card:hover {
      border-color: rgba(255,255,255,0.12);
      transform: translateY(-2px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    }
    .card-live {
      border-color: rgba(239,68,68,0.2);
      box-shadow: 0 0 30px rgba(239,68,68,0.06);
    }
    .card-live::before {
      background: linear-gradient(90deg, transparent, rgba(239,68,68,0.3), transparent);
    }
    .card-live:hover {
      border-color: rgba(239,68,68,0.35);
      box-shadow: 0 0 40px rgba(239,68,68,0.1);
    }

    /* ===== TEAM LOGOS ===== */
    .team-logo {
      width: 48px; height: 48px;
      border-radius: 50%;
      object-fit: contain;
      background: rgba(255,255,255,0.03);
      padding: 5px;
      border: 2px solid rgba(255,255,255,0.08);
      transition: all 0.3s;
    }
    .card:hover .team-logo {
      border-color: rgba(250,204,21,0.2);
    }
    .team-logo-fallback {
      width: 48px; height: 48px;
      border-radius: 50%;
      background: linear-gradient(135deg, #1e293b, #334155);
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
      border: 2px solid rgba(255,255,255,0.08);
    }

    /* ===== BUTTONS ===== */
    .btn-hd {
      background: linear-gradient(135deg, #ef4444, #dc2626);
      box-shadow: 0 4px 15px rgba(239,68,68,0.25);
      position: relative;
      overflow: hidden;
    }
    .btn-hd::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
      transition: left 0.5s;
    }
    .btn-hd:hover::before { left: 100%; }
    .btn-hd:hover { box-shadow: 0 6px 25px rgba(239,68,68,0.4); transform: translateY(-1px); }
    .btn-hd:active { transform: translateY(0); }

    .btn-sd {
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      box-shadow: 0 4px 15px rgba(99,102,241,0.25);
      position: relative;
      overflow: hidden;
    }
    .btn-sd::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent);
      transition: left 0.5s;
    }
    .btn-sd:hover::before { left: 100%; }
    .btn-sd:hover { box-shadow: 0 6px 25px rgba(99,102,241,0.4); transform: translateY(-1px); }
    .btn-sd:active { transform: translateY(0); }

    /* ===== SCORE BOX ===== */
    .score-box {
      background: rgba(0,0,0,0.5);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 14px;
      padding: 6px 16px;
      min-width: 80px;
    }

    /* ===== LEAGUE BADGE ===== */
    .league-badge {
      background: linear-gradient(135deg, rgba(250,204,21,0.08), rgba(245,158,11,0.05));
      border: 1px solid rgba(250,204,21,0.15);
      border-radius: 24px;
      padding: 4px 12px;
      font-weight: 600;
    }

    /* ===== TABS ===== */
    .tab-btn {
      padding: 10px 22px;
      border-radius: 24px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      border: 1px solid transparent;
      letter-spacing: 0.3px;
      white-space: nowrap;
    }
    .tab-btn.active {
      background: linear-gradient(135deg, #facc15, #f59e0b);
      color: #0f172a;
      box-shadow: 0 4px 20px rgba(250,204,21,0.3), 0 0 0 1px rgba(250,204,21,0.5);
    }
    .tab-btn:not(.active) {
      background: rgba(255,255,255,0.04);
      color: #94a3b8;
      border-color: rgba(255,255,255,0.08);
    }
    .tab-btn:not(.active):hover {
      background: rgba(255,255,255,0.08);
      color: #e2e8f0;
      border-color: rgba(255,255,255,0.15);
    }

    /* ===== STAT PILLS ===== */
    .stat-pill {
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 16px;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .stat-indicator {
      width: 6px; height: 6px;
      border-radius: 50%;
      display: inline-block;
    }

    /* ===== LOADING ===== */
    .loading-spinner {
      width: 44px; height: 44px;
      border: 3px solid rgba(255,255,255,0.06);
      border-top-color: #facc15;
      border-right-color: rgba(250,204,21,0.3);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ===== PLAYER ===== */
    .player-wrapper {
      border-radius: 20px;
      overflow: hidden;
      border: 2px solid rgba(250,204,21,0.2);
      box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 40px rgba(250,204,21,0.05);
    }
    .close-btn {
      background: linear-gradient(135deg, #1e293b, #0f172a);
      border-top: 1px solid rgba(255,255,255,0.06);
      transition: all 0.2s;
    }
    .close-btn:hover {
      background: linear-gradient(135deg, #dc2626, #991b1b);
    }

    /* ===== SCROLLBAR ===== */
    ::-webkit-scrollbar { width: 3px; height: 3px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

    /* ===== PAGE LOAD ANIMATION ===== */
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .fade-up { animation: fadeUp 0.5s ease-out forwards; }
    .fade-up-delay-1 { animation-delay: 0.1s; opacity: 0; }
    .fade-up-delay-2 { animation-delay: 0.2s; opacity: 0; }
    .fade-up-delay-3 { animation-delay: 0.3s; opacity: 0; }

    /* ===== NO MATCHES ===== */
    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }
    .empty-state-icon {
      font-size: 48px;
      margin-bottom: 16px;
      opacity: 0.5;
    }

    /* ===== MATCH DIVIDER ===== */
    .match-divider {
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.04), transparent);
    }

    /* ===== STATUS BADGES ===== */
    .status-live {
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.2);
      color: #fca5a5;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .status-ft {
      background: rgba(100,116,139,0.1);
      border: 1px solid rgba(100,116,139,0.2);
      color: #94a3b8;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 600;
    }
    .status-upcoming {
      background: rgba(52,211,153,0.08);
      border: 1px solid rgba(52,211,153,0.2);
      color: #6ee7b7;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 600;
    }

    /* ===== FOOTER SPACING ===== */
    .bottom-safe { height: 100px; }
  </style>
</head>
<body>
  <div class="app-container">

    <!-- Premium Header -->
    <div class="premium-header">
      <div class="max-w-md mx-auto px-5 py-4">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="header-title text-xl">⚽ All Sports Live</h1>
            <p class="header-subtitle mt-0.5">Premium Sports Streaming</p>
          </div>
          <div class="text-right">
            <div class="text-[10px] text-slate-500 font-medium">Myanmar Time</div>
            <div id="clock" class="text-sm font-bold text-slate-300 font-mono tracking-wide">--:--</div>
          </div>
        </div>
      </div>
    </div>

    <div class="max-w-md mx-auto px-4 pt-5 pb-4">

      <!-- Filter Tabs -->
      <div class="flex gap-2 mb-4 overflow-x-auto pb-1 fade-up fade-up-delay-1" id="tabs">
        <button class="tab-btn active" onclick="filterMatches('all')">All Matches</button>
        <button class="tab-btn" onclick="filterMatches('live')">🔴 Live</button>
        <button class="tab-btn" onclick="filterMatches('upcoming')">⏳ Upcoming</button>
        <button class="tab-btn" onclick="filterMatches('finished')">✅ Finished</button>
      </div>

      <!-- Stats Bar -->
      <div class="flex gap-2 justify-center mb-5 fade-up fade-up-delay-2" id="stats-bar">
        <span class="stat-pill text-slate-400">
          <span class="stat-indicator" style="background:#64748b;"></span>
          <span id="stat-total">Total: —</span>
        </span>
        <span class="stat-pill text-red-400">
          <span class="stat-indicator" style="background:#ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5);"></span>
          <span id="stat-live">Live: —</span>
        </span>
        <span class="stat-pill text-indigo-400">
          <span class="stat-indicator" style="background:#6366f1;"></span>
          <span id="stat-upcoming">Soon: —</span>
        </span>
      </div>

      <!-- Video Player -->
      <div id="player-container" class="hidden sticky top-[68px] z-50 mb-5 player-wrapper">
        <div class="bg-black relative">
          <video id="video" controls class="w-full aspect-video" autoplay playsinline></video>
        </div>
        <button onclick="closePlayer()" class="close-btn w-full text-white text-xs font-bold py-3.5 flex items-center justify-center gap-2">
          ✕ ပိတ်မည် (Close Player)
        </button>
      </div>

      <!-- Loading -->
      <div id="loading" class="flex flex-col items-center py-20 fade-up fade-up-delay-3">
        <div class="loading-spinner mb-4"></div>
        <span class="text-slate-500 text-sm font-medium">Loading matches...</span>
      </div>

      <!-- Match List -->
      <div id="match-list" class="space-y-3"></div>

      <div class="bottom-safe"></div>
    </div>
  </div>

  <script>
    let allData = [];
    let currentFilter = 'all';
    let currentHls = null;

    // Live clock
    function updateClock() {
      const now = new Date();
      const mmTime = now.toLocaleTimeString('en-US', {
        timeZone: 'Asia/Yangon',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
      });
      document.getElementById('clock').textContent = mmTime;
    }
    updateClock();
    setInterval(updateClock, 1000);

    async function load() {
      try {
        const res = await fetch('/api/matches');
        if (!res.ok) throw new Error('Server error');
        const data = await res.json();
        if (data.error) throw new Error(data.error);
        allData = data;
        document.getElementById('loading').style.display = 'none';
        updateStats();
        renderMatches();
      } catch (e) {
        document.getElementById('loading').innerHTML =
          '<div class="empty-state"><div class="empty-state-icon">⚠️</div><div class="text-red-400 text-sm font-medium">' + e.message + '</div><div class="text-slate-600 text-xs mt-2">Pull to refresh or try again later</div></div>';
      }
    }

    function updateStats() {
      const live = allData.filter(m => m.match_status === 'live').length;
      const upcoming = allData.filter(m => m.match_status === 'upcoming').length;
      document.getElementById('stat-total').textContent = 'Total: ' + allData.length;
      document.getElementById('stat-live').textContent = 'Live: ' + live;
      document.getElementById('stat-upcoming').textContent = 'Soon: ' + upcoming;
    }

    function filterMatches(type) {
      currentFilter = type;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      renderMatches();
    }

    function getLogoHTML(url, teamName) {
      if (url) {
        return '<img src="' + url + '" alt="" class="team-logo" loading="lazy" onerror="this.style.display=\\'none\\';this.nextElementSibling.style.display=\\'flex\\';">' +
               '<div class="team-logo-fallback" style="display:none;">⚽</div>';
      }
      return '<div class="team-logo-fallback">⚽</div>';
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    function renderMatches() {
      const list = document.getElementById('match-list');
      let filtered = allData;
      if (currentFilter !== 'all') {
        filtered = allData.filter(m => m.match_status === currentFilter);
      }

      if (filtered.length === 0) {
        list.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📭</div><div class="text-slate-500 text-sm font-medium">ပွဲစဉ်များ မရှိသေးပါ</div><div class="text-slate-600 text-xs mt-1">No matches found</div></div>';
        return;
      }

      let html = '';
      filtered.forEach((m, idx) => {
        const isLive = m.match_status === 'live';
        const isFinished = m.match_status === 'finished';
        const cardClass = isLive ? 'card card-live' : 'card';

        let statusHTML = '';
        if (isLive) {
          statusHTML = '<span class="status-live"><span class="live-dot"></span>LIVE ' + escapeHtml(m.match_time || '') + '</span>';
        } else if (isFinished) {
          statusHTML = '<span class="status-ft">FT</span>';
        } else {
          statusHTML = '<span class="status-upcoming">' + escapeHtml(m.match_time) + '</span>';
        }

        let btns = '';
        if (m.servers && m.servers.length > 0) {
          m.servers.forEach(s => {
            const isHD = s.name.includes('HD');
            const cls = isHD ? 'btn-hd' : 'btn-sd';
            const label = isHD ? '▶ HD' : '▶ SD';
            btns += '<button onclick="play(\\'' + encodeURIComponent(s.stream_url) + '\\')" class="' + cls + ' text-white text-[11px] px-5 py-2 rounded-full font-bold transition-all">' + label + '</button>';
          });
        } else if (isLive) {
          btns = '<span class="text-[11px] text-amber-400/70 font-medium">⏳ Stream loading...</span>';
        } else if (isFinished) {
          btns = '<span class="text-[11px] text-slate-600 font-medium">Match ended</span>';
        } else {
          btns = '<span class="text-[11px] text-slate-600 font-medium">Not started yet</span>';
        }

        const homeLogo = getLogoHTML(m.home_team_logo, m.home_team_name);
        const awayLogo = getLogoHTML(m.away_team_logo, m.away_team_name);

        const scoreDisplay = m.match_score
          ? '<div class="score-box text-center"><span class="text-xl font-black tracking-wider" style="color:#facc15; text-shadow: 0 0 20px rgba(250,204,21,0.3);">' + escapeHtml(m.match_score) + '</span></div>'
          : '<div class="score-box text-center"><span class="text-sm font-bold text-slate-500">VS</span></div>';

        html += '<div class="' + cardClass + ' p-5" style="animation: fadeUp 0.4s ease-out ' + (idx * 0.05) + 's both;">' +
          '<div class="flex justify-between items-center mb-4">' +
            '<span class="league-badge text-[10px] text-amber-400/90 truncate max-w-[60%]">' + escapeHtml(m.league_name) + '</span>' +
            statusHTML +
          '</div>' +
          '<div class="flex items-center justify-between">' +
            '<div class="flex flex-col items-center w-[30%] gap-2">' +
              homeLogo +
              '<span class="text-[11px] font-semibold text-center leading-tight text-slate-200 line-clamp-2 w-full">' + escapeHtml(m.home_team_name) + '</span>' +
            '</div>' +
            '<div class="w-[30%] flex justify-center">' +
              scoreDisplay +
            '</div>' +
            '<div class="flex flex-col items-center w-[30%] gap-2">' +
              awayLogo +
              '<span class="text-[11px] font-semibold text-center leading-tight text-slate-200 line-clamp-2 w-full">' + escapeHtml(m.away_team_name) + '</span>' +
            '</div>' +
          '</div>' +
          '<div class="text-center mt-4 pt-3 border-t border-white/[0.04] flex gap-2.5 justify-center">' +
            btns +
          '</div>' +
        '</div>';
      });
      list.innerHTML = html;
    }

    function play(encodedUrl) {
      const url = decodeURIComponent(encodedUrl);
      document.getElementById('player-container').classList.remove('hidden');
      const vid = document.getElementById('video');

      if (currentHls) {
        currentHls.destroy();
        currentHls = null;
      }

      if (Hls.isSupported()) {
        const hls = new Hls({
          enableWorker: true,
          lowLatencyMode: true,
          maxBufferLength: 30,
          maxMaxBufferLength: 60,
        });
        currentHls = hls;
        hls.loadSource(url);
        hls.attachMedia(vid);
        hls.on(Hls.Events.MANIFEST_PARSED, () => vid.play());
        hls.on(Hls.Events.ERROR, (event, data) => {
          if (data.fatal) {
            console.error('HLS fatal error:', data.type);
            if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
              hls.startLoad();
            } else {
              hls.destroy();
            }
          }
        });
      } else if (vid.canPlayType('application/vnd.apple.mpegurl')) {
        vid.src = url;
        vid.play();
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function closePlayer() {
      const vid = document.getElementById('video');
      vid.pause();
      vid.removeAttribute('src');
      vid.load();
      if (currentHls) {
        currentHls.destroy();
        currentHls = null;
      }
      document.getElementById('player-container').classList.add('hidden');
    }

    // Initial load
    load();
    // Auto-refresh every 60 seconds
    setInterval(load, 60000);
  </script>
</body>
</html>`;
}

// ====== BACKEND LOGIC ======

async function fetchServerURL(roomNum: any) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout

    const res = await fetch(`${ROOM_API_BASE}/room/${roomNum}/detail.json`, {
      headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const txt = await res.text();
    const m = txt.match(/detail\((.*)\)/);
    if (m) {
      const js = JSON.parse(m[1]);
      if (js.code === 200 && js.data && js.data.stream) {
        return { m3u8: js.data.stream.m3u8, hdM3u8: js.data.stream.hdM3u8 };
      }
    }
  } catch (_e) {
    /* ignore */
  }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string) {
  // Validate date format (YYYYMMDD)
  if (!/^\d{8}$/.test(date)) return [];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

    const res = await fetch(`${MATCH_API_BASE}/match/matches_${date}.json`, {
      headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const txt = await res.text();
    const m = txt.match(/matches_\d+\((.*)\)/);
    if (!m) return [];

    const js = JSON.parse(m[1]);
    if (js.code !== 200) return [];

    const now = Date.now();
    const results = [];

    for (const it of js.data) {
      const mt = it.matchTime;

      // Basic data validation
      if (!mt || typeof mt !== "number") continue;

      let status: string;
      if (now >= mt && now <= mt + 3 * 60 * 60 * 1000) status = "live";
      else if (now > mt + 3 * 60 * 60 * 1000) status = "finished";
      else status = "upcoming";

      const servers: any[] = [];
      if (status === "live" && it.anchors) {
        // Limit concurrent server fetches to prevent abuse
        const anchorSlice = it.anchors.slice(0, 3); // Max 3 servers per match
        for (const a of anchorSlice) {
          const room = a.anchor?.roomNum;
          if (!room) continue;
          const { m3u8, hdM3u8 } = await fetchServerURL(room);
          if (m3u8) servers.push({ name: "Soco SD", stream_url: m3u8 });
          if (hdM3u8) servers.push({ name: "Soco HD", stream_url: hdM3u8 });
        }
      }

      const homeLogo = it.homeLogo || it.hostLogo || it.homeIcon || it.hostIcon || null;
      const awayLogo = it.awayLogo || it.guestLogo || it.awayIcon || it.guestIcon || null;

      results.push({
        match_time: new Date(mt).toLocaleTimeString("en-US", {
          timeZone: "Asia/Yangon",
          hour: "2-digit",
          minute: "2-digit",
          hour12: true,
        }),
        match_status: status,
        home_team_name: String(it.homeName || it.hostName || "Home").slice(0, 50),
        away_team_name: String(it.awayName || it.guestName || "Away").slice(0, 50),
        home_team_logo: homeLogo,
        away_team_logo: awayLogo,
        league_name: String(it.leagueName || it.subCateName || "Unknown League").slice(0, 80),
        match_score:
          it.homeScore !== undefined && it.homeScore !== null
            ? `${it.homeScore} - ${it.awayScore}`
            : null,
        servers,
      });
    }
    return results;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
