import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// ====== Environment Variables ======
const MATCH_API_BASE = Deno.env.get("MATCH_API_BASE") || "";
const ROOM_API_BASE = Deno.env.get("ROOM_API_BASE") || "";
const API_REFERER = Deno.env.get("API_REFERER") || "";
const API_USER_AGENT =
  Deno.env.get("API_USER_AGENT") ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// ====== Developer Contact Info ======
const DEV_CONTACT_URL =
  Deno.env.get("DEV_CONTACT_URL") || "https://t.me/yourusername";
const DEV_PROFILE_IMG =
  Deno.env.get("DEV_PROFILE_IMG") ||
  "https://ui-avatars.com/api/?name=Dev&background=d97706&color=fff&size=128";
const DEV_DISPLAY_NAME = Deno.env.get("DEV_DISPLAY_NAME") || "Developer";

// ====== Customizable Site Subtitle ======
const SITE_SUBTITLE =
  Deno.env.get("SITE_SUBTITLE") || "Premium Sports Streaming";

// ====== SECURITY: Origin/Referer validation ======
const ALLOWED_ORIGINS: string[] = (() => {
  const raw = Deno.env.get("ALLOWED_ORIGINS") || "";
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
})();

function isAllowedOrigin(req: Request): boolean {
  if (ALLOWED_ORIGINS.length === 0) return true;
  const origin = req.headers.get("origin") || "";
  const referer = req.headers.get("referer") || "";

  for (const allowed of ALLOWED_ORIGINS) {
    if (origin === allowed) return true;
    if (referer.startsWith(allowed)) return true;
  }
  if (!origin && !referer) return true;
  return false;
}

// ====== Daily Visitor Tracking ======
const dailyVisitors = new Map<string, Set<string>>();

function getTodayDateKey(): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Yangon",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function trackVisitor(ip: string): void {
  const today = getTodayDateKey();
  if (!dailyVisitors.has(today)) dailyVisitors.set(today, new Set());
  dailyVisitors.get(today)!.add(ip);

  const keys = Array.from(dailyVisitors.keys()).sort();
  while (keys.length > 7) {
    const oldest = keys.shift()!;
    dailyVisitors.delete(oldest);
  }
}

function getVisitorStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const [date, ips] of dailyVisitors) {
    stats[date] = ips.size;
  }
  return stats;
}

// ====== PERFORMANCE: API Response Cache ======
interface CacheEntry {
  data: any;
  expires: number;
}

const apiCache = new Map<string, CacheEntry>();
const API_CACHE_TTL = 30_000; 

function getCachedResponse(key: string): any | null {
  const entry = apiCache.get(key);
  if (entry && Date.now() < entry.expires) return entry.data;
  if (entry) apiCache.delete(key);
  return null;
}

function setCachedResponse(key: string, data: any, ttl: number = API_CACHE_TTL): void {
  apiCache.set(key, { data, expires: Date.now() + ttl });
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of apiCache) {
    if (now > entry.expires) apiCache.delete(key);
  }
}, 60_000);

// ====== SECURITY: Rate Limiter ======
// Increased heavily to support single users loading 50+ images per page load
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60_000; 
const RATE_LIMIT_MAX = 600; // Allow 600 requests per minute per IP
const BLOCK_THRESHOLD = 1500; 
const blockedIPs = new Map<string, number>();
const BLOCK_DURATION = 10 * 60_000; 

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
  if (entry.count > BLOCK_THRESHOLD) {
    blockedIPs.set(ip, now + BLOCK_DURATION);
    return { limited: true, blocked: true };
  }
  if (entry.count > RATE_LIMIT_MAX) {
    return { limited: true, blocked: false };
  }
  return { limited: false, blocked: false };
}

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

  if (!ua || ua.length < 10) return true;

  const botPatterns = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i,
    /gobuster/i, /wfuzz/i, /hydra/i, /burpsuite/i, /nessus/i,
    /nuclei/i, /scrapy/i, /zgrab/i,
  ];
  if (botPatterns.some((p) => p.test(ua))) return true;

  const path = url.pathname;
  if (path.includes("..") || path.includes("//") || path.includes("\\")) return true;

  const maliciousPaths = [
    /\.env/i, /\.git/i, /wp-admin/i, /wp-login/i, /phpmyadmin/i,
    /\/admin\b/i, /\.php$/i, /shell/i, /eval\(/i, /\.sql$/i,
  ];
  if (maliciousPaths.some((p) => p.test(path))) return true;

  if (req.url.length > 4096) return true;

  return false;
}

// ====== SECURITY: Response Headers ======
function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store",
  };
}

// ====== SECURITY: Sanitize URL ======
function sanitizeUrl(url: string | null | undefined): string | null {
  if (!url || typeof url !== "string") return null;
  let trimmed = url.trim();
  // Handle protocol-relative URLs (fixes missing logos)
  if (trimmed.startsWith("//")) trimmed = "https:" + trimmed;
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed.replace(/[<>"'`\s]/g, "");
  }
  return null;
}

// ====== SECURITY: Sanitize plain text ======
function sanitizeText(text: string | null | undefined, maxLen: number): string {
  if (!text || typeof text !== "string") return "";
  return text
    .replace(/<[^>]*>/g, "")
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[&<>"']/g, (c) => {
      const map: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;" };
      return map[c] || c;
    })
    .trim()
    .slice(0, maxLen);
}

// ====== Logo Proxy Cache ======
const logoProxyCache = new Map<string, { data: Uint8Array; contentType: string; expires: number }>();
const LOGO_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const LOGO_CACHE_MAX_SIZE = 1000;

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of logoProxyCache) {
    if (now > entry.expires) logoProxyCache.delete(key);
  }
}, 5 * 60_000);

async function fetchLogoViaProxy(logoUrl: string): Promise<{ data: Uint8Array; contentType: string } | null> {
  if (!sanitizeUrl(logoUrl)) return null;

  const cached = logoProxyCache.get(logoUrl);
  if (cached && Date.now() < cached.expires) {
    return { data: cached.data, contentType: cached.contentType };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(logoUrl, {
      headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER, Accept: "image/*,*/*;q=0.8" },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;

    let contentType = res.headers.get("content-type") || "";
    // Reject HTML/JSON but accept unclassified or image types (fixes missing logos for upcoming matches)
    if (contentType.includes("text/html") || contentType.includes("application/json")) return null;
    
    const finalContentType = contentType.includes("image/") ? contentType : "image/png";

    const arrayBuf = await res.arrayBuffer();
    const data = new Uint8Array(arrayBuf);

    if (data.length > 2 * 1024 * 1024) return { data, contentType: finalContentType };

    if (logoProxyCache.size >= LOGO_CACHE_MAX_SIZE) {
      const keys = Array.from(logoProxyCache.keys());
      logoProxyCache.delete(keys[0]); 
    }

    logoProxyCache.set(logoUrl, { data, contentType: finalContentType, expires: Date.now() + LOGO_CACHE_TTL });

    return { data, contentType: finalContentType };
  } catch (_e) {
    return null;
  }
}

const DEV_STATS_KEY = Deno.env.get("DEV_STATS_KEY") || crypto.randomUUID();
if (!Deno.env.get("DEV_STATS_KEY")) {
  console.log(`[SECURITY] Auto-generated DEV_STATS_KEY: ${DEV_STATS_KEY}`);
}

serve(async (req) => {
  const url = new URL(req.url);
  const clientIP = getClientIP(req);

  // ====== Rate limiting ======
  const { limited, blocked } = isRateLimited(clientIP);
  if (blocked || limited) {
    // FIX: Show HTML for main page instead of raw JSON
    if (url.pathname === "/" || req.headers.get("accept")?.includes("text/html")) {
      return new Response(`
        <!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Please Wait</title><style>body{font-family:sans-serif;text-align:center;padding:50px 20px;background:#f8fafc;color:#1e293b;} 
        .box{background:#fff;padding:30px;border-radius:15px;box-shadow:0 4px 6px rgba(0,0,0,0.1);display:inline-block;}
        </style></head><body><div class="box"><h2>Too Many Requests</h2>
        <p>သင့်ဘက်မှ Request အရေအတွက်များလွန်းနေပါသည်။<br>ခဏစောင့်ပြီးမှ (သို့) 1 မိနစ်ခန့်အကြာမှ ပြန်လည် Refresh လုပ်ပေးပါ။</p>
        </div><script>setTimeout(()=>location.reload(), 30000);</script></body></html>
      `, {
        status: 429,
        headers: { "Content-Type": "text/html; charset=utf-8", "Retry-After": "60", ...securityHeaders() },
      });
    }
    return new Response(JSON.stringify({ error: "Rate limit exceeded. Please wait a minute." }), {
      status: 429,
      headers: { "Content-Type": "application/json", "Retry-After": "60", ...securityHeaders() },
    });
  }

  if (isSuspiciousRequest(req)) {
    return new Response("Not Found", { status: 404, headers: securityHeaders() });
  }

  if (req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET", ...securityHeaders() } });
  }

  // --- 1. API ROUTE: Matches ---
  if (url.pathname === "/api/matches") {
    if (!isAllowedOrigin(req)) return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403, headers: { "Content-Type": "application/json", ...securityHeaders() } });

    try {
      const cacheKey = "matches_all";
      const cached = getCachedResponse(cacheKey);
      if (cached) {
        return new Response(JSON.stringify(cached), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=30", ...securityHeaders() } });
      }

      const getVNDate = (offset: number) => {
        const d = new Date(); d.setDate(d.getDate() + offset);
        return new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Ho_Chi_Minh", year: "numeric", month: "2-digit", day: "2-digit" }).format(d).replace(/-/g, "");
      };
      const dates = [getVNDate(-1), getVNDate(0), getVNDate(1)];
      const allResults = await Promise.allSettled(dates.map((d) => fetchMatches(d)));

      let allMatches: any[] = [];
      for (const result of allResults) {
        if (result.status === "fulfilled") allMatches = allMatches.concat(result.value);
      }

      allMatches = allMatches.filter((m: any) => m.match_status !== "finished");
      allMatches.sort((a, b) => {
        if (a.match_status === "live" && b.match_status !== "live") return -1;
        if (a.match_status !== "live" && b.match_status === "live") return 1;
        return 0;
      });

      setCachedResponse(cacheKey, allMatches, API_CACHE_TTL);
      return new Response(JSON.stringify(allMatches), { headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=30", ...securityHeaders() } });
    } catch (_e) {
      return new Response(JSON.stringify({ error: "Service temporarily unavailable" }), { status: 500, headers: { "Content-Type": "application/json", ...securityHeaders() } });
    }
  }

  // --- 2. API ROUTE: Logo Proxy ---
  if (url.pathname === "/api/logo-proxy") {
    if (!isAllowedOrigin(req)) return new Response("Forbidden", { status: 403, headers: securityHeaders() });
    
    const logoUrl = url.searchParams.get("url");
    const sanitized = sanitizeUrl(logoUrl);
    if (!sanitized) return new Response("Bad Request", { status: 400, headers: securityHeaders() });

    const result = await fetchLogoViaProxy(sanitized);
    if (!result) {
      const transparentPng = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, 0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
      return new Response(transparentPng, { status: 200, headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=60", ...securityHeaders() } });
    }

    return new Response(result.data, { status: 200, headers: { "Content-Type": result.contentType, "Cache-Control": "public, max-age=300", ...securityHeaders() } });
  }

  // --- 3. API ROUTE: Stats ---
  if (url.pathname === "/api/stats") {
    if (url.searchParams.get("key") !== DEV_STATS_KEY) return new Response("Unauthorized", { status: 401 });
    return new Response(JSON.stringify(getVisitorStats()), { headers: { "Content-Type": "application/json" } });
  }

  // --- 4. FRONTEND UI ---
  if (url.pathname === "/") {
    trackVisitor(clientIP);
    return new Response(getHTML(), { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=60", ...securityHeaders() } });
  }

  return new Response("Not Found", { status: 404, headers: securityHeaders() });
});

function getHTML(): string {
  const safeDevUrl = sanitizeUrl(DEV_CONTACT_URL) || "#";
  const safeDevImg = sanitizeUrl(DEV_PROFILE_IMG) || "";
  const safeDevName = sanitizeText(DEV_DISPLAY_NAME, 50) || "Developer";
  const safeSubtitle = sanitizeText(SITE_SUBTITLE, 100) || "Premium Sports Streaming";

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>All Sports Live</title>
  <script src="https://cdn.tailwindcss.com"><\/script>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body { background: #f1f5f9; color: #1e293b; font-family: 'Inter', 'Padauk', sans-serif; margin: 0; min-height: 100vh; overflow-x: hidden; }
    .bg-animated { position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 0; background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 25%, #f8fafc 50%, #e2e8f0 75%, #f1f5f9 100%); background-size: 400% 400%; animation: gradientShift 20s ease infinite; }
    @keyframes gradientShift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
    .app-container { position: relative; z-index: 1; }
    .premium-header { background: rgba(255, 255, 255, 0.85); border-bottom: 1px solid rgba(0,0,0,0.06); backdrop-filter: blur(20px); position: sticky; top: 0; z-index: 40; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .header-title { background: linear-gradient(135deg, #d97706, #b45309, #d97706); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 900; letter-spacing: -0.5px; }
    .header-subtitle { color: #94a3b8; font-size: 11px; font-weight: 500; letter-spacing: 2px; text-transform: uppercase; }
    .dev-contact-link { display: flex; align-items: center; gap: 8px; padding: 4px 12px; border-radius: 24px; background: rgba(217,119,6,0.08); border: 1px solid rgba(217,119,6,0.15); text-decoration: none; }
    .dev-avatar { width: 28px; height: 28px; border-radius: 50%; object-fit: cover; }
    .dev-name { font-size: 11px; font-weight: 700; color: #b45309; }
    .live-dot { width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block; animation: pulse-dot 1s infinite; }
    @keyframes pulse-dot { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.7); } }
    .card { background: rgba(255, 255, 255, 0.75); border: 1px solid rgba(0,0,0,0.06); border-radius: 20px; backdrop-filter: blur(12px); box-shadow: 0 2px 12px rgba(0,0,0,0.04); overflow: hidden; }
    .card-live { border-color: rgba(239,68,68,0.2); box-shadow: 0 2px 12px rgba(239,68,68,0.06); }
    .card-watching { border-color: rgba(217,119,6,0.4) !important; box-shadow: 0 0 0 2px rgba(217,119,6,0.1) !important; }
    .team-logo { width: 52px; height: 52px; border-radius: 50%; object-fit: contain; background: rgba(0,0,0,0.03); padding: 5px; border: 2px solid rgba(0,0,0,0.06); }
    .team-logo-fallback { width: 52px; height: 52px; border-radius: 50%; background: rgba(0,0,0,0.04); display: flex; align-items: center; justify-content: center; font-size: 20px; border: 2px solid rgba(0,0,0,0.06); }
    .btn-hd { background: linear-gradient(135deg, #ef4444, #dc2626); box-shadow: 0 4px 12px rgba(239,68,68,0.25); }
    .btn-sd { background: linear-gradient(135deg, #6366f1, #4f46e5); box-shadow: 0 4px 12px rgba(99,102,241,0.25); }
    .score-box { background: rgba(15,23,42,0.06); border: 1px solid rgba(0,0,0,0.06); border-radius: 14px; padding: 6px 16px; min-width: 80px; text-align: center;}
    .league-badge { background: rgba(217,119,6,0.08); border: 1px solid rgba(217,119,6,0.15); border-radius: 24px; padding: 4px 12px; font-weight: 600; }
    .tab-btn { padding: 10px 22px; border-radius: 24px; font-size: 12px; font-weight: 700; cursor: pointer; border: 1px solid transparent; white-space: nowrap; background: rgba(255,255,255,0.7); color: #64748b; border-color: rgba(0,0,0,0.06); }
    .tab-btn.active { background: linear-gradient(135deg, #d97706, #b45309); color: #ffffff; }
    .stat-pill { background: rgba(255,255,255,0.7); border: 1px solid rgba(0,0,0,0.06); border-radius: 16px; padding: 8px 16px; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; color: #64748b; }
    .stat-indicator { width: 6px; height: 6px; border-radius: 50%; }
    .player-wrapper { border-radius: 20px; overflow: hidden; border: 2px solid rgba(217,119,6,0.3); box-shadow: 0 16px 48px rgba(0,0,0,0.12); }
    .now-watching-bar { background: linear-gradient(135deg, #1e293b, #0f172a); padding: 10px 16px; display: flex; align-items: center; gap: 10px; }
    .now-watching-bar .nw-dot { width: 8px; height: 8px; background: #ef4444; border-radius: 50%; animation: pulse-dot 1s infinite; }
    .now-watching-bar .nw-label { font-size: 10px; font-weight: 700; color: #facc15; text-transform: uppercase; }
    .now-watching-bar .nw-match { font-size: 12px; font-weight: 600; color: #e2e8f0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .now-watching-bar .nw-league { font-size: 10px; color: #94a3b8; margin-left: auto; }
    .close-btn { background: linear-gradient(135deg, #1e293b, #0f172a); border-top: 1px solid rgba(255,255,255,0.06); color: #ffffff; }
    .status-live { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25); color: #dc2626; border-radius: 20px; padding: 3px 10px; font-size: 10px; font-weight: 700; display: inline-flex; align-items: center; gap: 5px; }
    .status-upcoming { background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); color: #059669; border-radius: 20px; padding: 3px 10px; font-size: 10px; font-weight: 600; }
    .empty-state { text-align: center; padding: 60px 20px; }
    .player-error { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.9); display: flex; flex-direction: column; align-items: center; justify-content: center; color: #fff; font-size: 13px; z-index: 10; padding: 20px; text-align: center; }
    .player-error-btn { margin-top: 14px; background: #d97706; color: #fff; padding: 8px 24px; border-radius: 20px; font-weight: 700; }
    .player-error-tips { margin-top: 10px; font-size: 11px; color: #94a3b8; max-width: 300px; line-height: 1.8; }
    .player-loading { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 5; }
    .loading-spinner { width: 44px; height: 44px; border: 3px solid rgba(255,255,255,0.3); border-top-color: #facc15; border-radius: 50%; animation: spin 0.7s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .day-separator { display: flex; align-items: center; gap: 12px; margin: 16px 0 10px 0; }
    .day-separator-line { flex: 1; height: 1px; background: rgba(0,0,0,0.06); }
    .day-separator-label { font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 4px 14px; border-radius: 20px; }
    .day-today { background: rgba(99,102,241,0.1); color: #4f46e5; border: 1px solid rgba(99,102,241,0.2); }
    .day-tomorrow { background: rgba(16,185,129,0.08); color: #059669; border: 1px solid rgba(16,185,129,0.2); }
    .countdown-text { font-size: 10px; color: #059669; font-weight: 600; margin-top: 2px; }
    .search-bar { background: rgba(255,255,255,0.8); border: 1px solid rgba(0,0,0,0.08); border-radius: 16px; padding: 10px 16px; font-size: 13px; width: 100%; outline: none; box-shadow: 0 1px 3px rgba(0,0,0,0.03); }
    .search-bar:focus { border-color: rgba(217,119,6,0.35); background: rgba(255,255,255,0.95); box-shadow: 0 0 0 3px rgba(217,119,6,0.08); }
    .refresh-indicator { position: fixed; top: 68px; left: 50%; transform: translateX(-50%) translateY(-50px); background: rgba(217,119,6,0.95); color: white; padding: 6px 16px; border-radius: 20px; font-size: 11px; font-weight: 700; z-index: 50; transition: transform 0.3s ease; pointer-events: none; opacity: 0; }
    .refresh-indicator.visible { transform: translateX(-50%) translateY(10px); opacity: 1; }
    .last-updated { font-size: 10px; color: #94a3b8; text-align: center; margin-top: 4px; }
    .score-text { color: #d97706; text-shadow: none; font-size: 1.25rem; font-weight: 900; }
  </style>
</head>
<body>
  <div class="bg-animated"></div>
  <div class="app-container">
    <!-- Refresh Indicator FIX -->
    <div id="refresh-indicator" class="refresh-indicator">Updating data...</div>

    <div class="premium-header">
      <div class="max-w-md mx-auto px-5 py-4">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="header-title text-xl">All Sports Live</h1>
            <p class="header-subtitle mt-0.5">${safeSubtitle}</p>
          </div>
          <a href="${safeDevUrl}" target="_blank" class="dev-contact-link">
            <img src="${safeDevImg}" class="dev-avatar" onerror="this.style.display='none'">
            <span class="dev-name">${safeDevName}</span>
          </a>
        </div>
      </div>
    </div>

    <div class="max-w-md mx-auto px-4 pt-5 pb-24">
      <div class="mb-4">
        <input type="text" id="search-input" class="search-bar" placeholder="Search teams or leagues..." autocomplete="off">
      </div>

      <div class="flex gap-2 mb-4 overflow-x-auto pb-1" id="tabs">
        <button class="tab-btn active" data-filter="all">All Matches</button>
        <button class="tab-btn" data-filter="live">Live Now</button>
        <button class="tab-btn" data-filter="upcoming">Upcoming</button>
      </div>

      <div class="flex gap-2 justify-center mb-2" id="stats-bar">
        <span class="stat-pill"><span class="stat-indicator" style="background:#94a3b8;"></span><span id="stat-total">Total: —</span></span>
        <span class="stat-pill"><span class="stat-indicator" style="background:#ef4444;"></span><span id="stat-live">Live: —</span></span>
        <span class="stat-pill"><span class="stat-indicator" style="background:#10b981;"></span><span id="stat-upcoming">Soon: —</span></span>
      </div>

      <div class="last-updated mb-4" id="last-updated"></div>

      <div id="player-container" class="hidden sticky top-[68px] z-50 mb-5 player-wrapper">
        <div id="now-watching-bar" class="now-watching-bar hidden">
          <span class="nw-dot"></span><span class="nw-label">Watching</span>
          <span class="nw-match" id="nw-match-text">—</span>
          <span class="nw-league" id="nw-league-text"></span>
        </div>
        <div class="bg-black relative" id="player-inner">
          <video id="video" controls class="w-full aspect-video" autoplay playsinline></video>
          <div id="player-loading" class="player-loading hidden"><div class="loading-spinner"></div></div>
        </div>
        <button id="close-player-btn" class="close-btn w-full text-xs font-bold py-3.5 flex items-center justify-center gap-2">✕ Close Player</button>
      </div>

      <div id="loading" class="text-center py-10 text-slate-500 text-sm font-medium">Loading Matches...</div>
      <div id="match-list" class="space-y-3"></div>
    </div>
  </div>

  <script>
    "use strict";
    var allData = [];
    var currentFilter = "all";
    var searchQuery = "";
    var currentHls = null;
    var currentStreamUrl = null;
    var currentWatchingMatch = null;
    var isFirstLoad = true;
    var lastUpdateTime = null;
    var countdownIntervalId = null;
    var isLoadingData = false;
    var logoCache = {};

    function escapeHtml(str) {
      if (!str) return "";
      var div = document.createElement("div"); div.textContent = str; return div.innerHTML;
    }

    function proxiedLogoUrl(url) {
      if (!url) return null;
      return "/api/logo-proxy?url=" + encodeURIComponent(url);
    }

    document.getElementById("search-input").addEventListener("input", function(e) {
      searchQuery = e.target.value.trim().toLowerCase().replace(/[<>'"]/g, "");
      renderMatches();
    });

    document.getElementById("tabs").addEventListener("click", function(e) {
      var btn = e.target.closest(".tab-btn");
      if (!btn) return;
      currentFilter = btn.getAttribute("data-filter");
      document.querySelectorAll(".tab-btn").forEach(function(b) { b.classList.remove("active"); });
      btn.classList.add("active");
      renderMatches();
    });

    document.getElementById("close-player-btn").addEventListener("click", closePlayer);

    // FIX: Updating Box Logic
    function showRefreshIndicator() { document.getElementById("refresh-indicator").classList.add("visible"); }
    function hideRefreshIndicator() { document.getElementById("refresh-indicator").classList.remove("visible"); }

    async function load() {
      if (isLoadingData) return;
      isLoadingData = true;

      // Show indicator while fetching (except first load)
      if (!isFirstLoad) showRefreshIndicator();

      try {
        var res = await fetch("/api/matches");
        if (!res.ok) throw new Error("Server Error or Rate Limited");
        var data = await res.json();
        
        allData = data;
        if (isFirstLoad) {
          document.getElementById("loading").style.display = "none";
          isFirstLoad = false;
        }

        lastUpdateTime = new Date();
        updateLastUpdatedText();
        updateStats();
        renderMatches();
        startCountdowns();
      } catch (e) {
        if (isFirstLoad) {
          document.getElementById("loading").innerHTML = '<div class="empty-state"><div class="text-red-500">Failed to load matches. Please refresh the page.</div></div>';
        }
      } finally {
        isLoadingData = false;
        // Hide indicator firmly after load
        if (!isFirstLoad) setTimeout(hideRefreshIndicator, 1000); 
      }
    }

    function updateLastUpdatedText() {
      if (!lastUpdateTime) return;
      var diffSec = Math.floor((new Date() - lastUpdateTime) / 1000);
      document.getElementById("last-updated").textContent = diffSec < 10 ? "Updated just now" : (diffSec < 60 ? "Updated " + diffSec + "s ago" : "Updated " + Math.floor(diffSec / 60) + "m ago");
    }
    setInterval(updateLastUpdatedText, 10000);

    function updateStats() {
      var live = allData.filter(function(m) { return m.match_status === "live"; }).length;
      var upcoming = allData.filter(function(m) { return m.match_status === "upcoming"; }).length;
      document.getElementById("stat-total").textContent = "Total: " + allData.length;
      document.getElementById("stat-live").textContent = "Live: " + live;
      document.getElementById("stat-upcoming").textContent = "Soon: " + upcoming;
    }

    // FIX: Simplified reliable logo element creation
    function createLogoElement(url) {
      var proxyUrl = proxiedLogoUrl(url);
      if (!proxyUrl || logoCache[url] === "fail") {
        var fb = document.createElement("div"); fb.className = "team-logo-fallback"; fb.textContent = "⚽"; return fb;
      }
      var img = document.createElement("img");
      img.className = "team-logo"; img.loading = "lazy"; img.src = proxyUrl;
      img.onerror = function() { logoCache[url] = "fail"; img.replaceWith(createLogoElement(null)); };
      img.onload = function() { logoCache[url] = "ok"; };
      return img;
    }

    function parseMatchTimeToDate(m) {
      if (!m.match_time) return null;
      var parts = m.match_time.match(/(\\d{1,2}):(\\d{2})\\s*(AM|PM)/i);
      if (!parts) return null;
      var h = parseInt(parts[1]), min = parseInt(parts[2]), ampm = parts[3].toUpperCase();
      if (ampm === "PM" && h !== 12) h += 12;
      if (ampm === "AM" && h === 12) h = 0;

      var d = new Date();
      if (m.match_day === "Tomorrow") d.setDate(d.getDate() + 1);
      else if (m.match_day === "Yesterday") d.setDate(d.getDate() - 1);
      else if (m.match_day && m.match_day.match(/^\\d{4}-\\d{2}-\\d{2}$/)) d = new Date(m.match_day + "T00:00:00");
      d.setHours(h, min, 0, 0); return d;
    }

    function formatCountdown(diffMs) {
      if (diffMs <= 0) return null;
      var s = Math.floor(diffMs / 1000), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
      return h > 0 ? (h + "h " + m + "m") : (m + "m " + (s % 60) + "s");
    }

    function startCountdowns() {
      if (countdownIntervalId) clearInterval(countdownIntervalId);
      countdownIntervalId = setInterval(function() {
        var now = Date.now();
        document.querySelectorAll("[data-match-time-ms]").forEach(function(el) {
          var ms = parseInt(el.getAttribute("data-match-time-ms"));
          var diff = ms - now;
          el.textContent = diff > 0 ? "Starts in " + formatCountdown(diff) : "Starting soon...";
        });
      }, 1000);
    }

    function renderMatches() {
      var list = document.getElementById("match-list");
      var filtered = currentFilter === "all" ? allData : allData.filter(function(m) { return m.match_status === currentFilter; });
      if (searchQuery) filtered = filtered.filter(function(m) { return ((m.home_team_name||"")+" "+(m.away_team_name||"")+" "+(m.league_name||"")).toLowerCase().includes(searchQuery); });

      if (filtered.length === 0) { list.innerHTML = '<div class="empty-state text-slate-500 text-sm">No matches found</div>'; return; }

      list.innerHTML = "";
      var lastDay = null;

      filtered.forEach(function(m) {
        var isLive = m.match_status === "live";
        var matchDay = m.match_day || "Today";
        if (matchDay !== lastDay) {
          lastDay = matchDay;
          var sep = document.createElement("div"); sep.className = "day-separator";
          sep.innerHTML = '<div class="day-separator-line"></div><span class="day-separator-label ' + (matchDay==="Today"?"day-today":matchDay==="Tomorrow"?"day-tomorrow":"bg-slate-200 text-slate-500") + '">' + escapeHtml(matchDay) + '</span><div class="day-separator-line"></div>';
          list.appendChild(sep);
        }

        var card = document.createElement("div");
        card.className = "card p-5 mb-3" + (isLive ? " card-live" : "");

        var header = '<div class="flex justify-between items-center mb-4"><span class="league-badge text-[10px] text-amber-700 truncate max-w-[60%]">' + escapeHtml(m.league_name || "Unknown") + '</span>' +
                     (isLive ? '<span class="status-live"><span class="live-dot"></span>LIVE ' + escapeHtml(m.match_time) + '</span>' : '<span class="status-upcoming">' + (m.match_day !== "Today" ? m.match_day + " · " : "") + escapeHtml(m.match_time) + '</span>') + '</div>';
        
        var teamsRow = document.createElement("div"); teamsRow.className = "flex items-center justify-between";
        var homeDiv = document.createElement("div"); homeDiv.className = "flex flex-col items-center w-[30%] gap-2";
        homeDiv.appendChild(createLogoElement(m.home_team_logo));
        homeDiv.innerHTML += '<span class="text-[11px] font-semibold text-center leading-tight text-slate-600 line-clamp-2 w-full">' + escapeHtml(m.home_team_name) + '</span>';
        
        var scoreDiv = document.createElement("div"); scoreDiv.className = "w-[30%] flex flex-col items-center justify-center";
        scoreDiv.innerHTML = '<div class="score-box">' + (m.match_score ? '<span class="score-text">' + m.match_score + '</span>' : '<span class="text-sm font-bold text-slate-400">VS</span>') + '</div>';
        
        if (!isLive && m.match_status === "upcoming") {
          var dateObj = parseMatchTimeToDate(m);
          if (dateObj) scoreDiv.innerHTML += '<div class="countdown-text mt-1" data-match-time-ms="' + dateObj.getTime() + '"></div>';
        }

        var awayDiv = document.createElement("div"); awayDiv.className = "flex flex-col items-center w-[30%] gap-2";
        awayDiv.appendChild(createLogoElement(m.away_team_logo));
        awayDiv.innerHTML += '<span class="text-[11px] font-semibold text-center leading-tight text-slate-600 line-clamp-2 w-full">' + escapeHtml(m.away_team_name) + '</span>';

        teamsRow.append(homeDiv, scoreDiv, awayDiv);

        var btns = document.createElement("div"); btns.className = "text-center mt-4 pt-3 border-t border-black/[0.04] flex gap-2.5 justify-center flex-wrap";
        if (m.servers && m.servers.length > 0) {
          m.servers.forEach(function(s) {
            var btn = document.createElement("button");
            btn.className = (s.name.includes("HD") ? "btn-hd" : "btn-sd") + " text-white text-[11px] px-5 py-2 rounded-full font-bold";
            btn.textContent = s.name.includes("HD") ? "▶ HD" : "▶ SD";
            btn.onclick = function() { play(s.stream_url, m); };
            btns.appendChild(btn);
          });
        } else {
          btns.innerHTML = '<span class="text-[11px] font-medium text-slate-400">' + (isLive ? 'Stream loading...' : 'Not started yet') + '</span>';
        }

        card.innerHTML = header;
        card.appendChild(teamsRow); card.appendChild(btns);
        list.appendChild(card);
      });
    }

    function showPlayerError(msg) {
      document.querySelectorAll(".player-error").forEach(e=>e.remove());
      var overlay = document.createElement("div"); overlay.className = "player-error";
      overlay.innerHTML = '<div style="font-weight:bold;margin-bottom:10px;">' + escapeHtml(msg) + '</div><div class="player-error-tips">💡 VPN ဖွင့်ကြည့်ပါ<br>💡 အခြား Server ပြောင်းကြည့်ပါ</div>';
      if(currentStreamUrl) {
         var btn = document.createElement("button"); btn.className="player-error-btn"; btn.textContent="ပြန်ကြိုးစားမည်";
         btn.onclick = function(){ play(currentStreamUrl, currentWatchingMatch); }; overlay.appendChild(btn);
      }
      document.getElementById("player-inner").appendChild(overlay);
    }

    function play(url, match) {
      if (!url) return;
      currentStreamUrl = url; currentWatchingMatch = match;
      document.getElementById("player-container").classList.remove("hidden");
      document.querySelectorAll(".player-error").forEach(e=>e.remove());
      document.getElementById("player-loading").classList.remove("hidden");
      
      document.getElementById("now-watching-bar").classList.remove("hidden");
      document.getElementById("nw-match-text").textContent = (match.home_team_name||"") + " vs " + (match.away_team_name||"");
      document.getElementById("nw-league-text").textContent = match.league_name||"";

      var vid = document.getElementById("video");
      if (currentHls) { currentHls.destroy(); currentHls = null; }
      vid.removeAttribute("src"); vid.load();

      if (typeof Hls !== "undefined" && Hls.isSupported()) {
        currentHls = new Hls({ maxBufferLength: 30, maxMaxBufferLength: 60 });
        currentHls.loadSource(url); currentHls.attachMedia(vid);
        currentHls.on(Hls.Events.MANIFEST_PARSED, function() { document.getElementById("player-loading").classList.add("hidden"); vid.play().catch(e=>e); });
        currentHls.on(Hls.Events.ERROR, function(e, d) {
          if (d.fatal) {
            document.getElementById("player-loading").classList.add("hidden");
            if (d.type === Hls.ErrorTypes.NETWORK_ERROR) { currentHls.startLoad(); setTimeout(()=> { if(vid.paused) showPlayerError("Stream ချိတ်ဆက်မှု မအောင်မြင်ပါ။"); }, 5000); }
            else { showPlayerError("Stream ကြည့်ရှု၍ မရနိုင်သေးပါ။"); currentHls.destroy(); }
          }
        });
      } else if (vid.canPlayType("application/vnd.apple.mpegurl")) {
        vid.src = url; 
        vid.onloadeddata = function() { document.getElementById("player-loading").classList.add("hidden"); vid.play().catch(e=>e); };
        vid.onerror = function() { document.getElementById("player-loading").classList.add("hidden"); showPlayerError("Stream ကြည့်ရှု၍ မရနိုင်သေးပါ။"); };
      }
      window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function closePlayer() {
      var vid = document.getElementById("video"); vid.pause(); vid.removeAttribute("src"); vid.load();
      if (currentHls) { currentHls.destroy(); currentHls = null; }
      document.getElementById("player-container").classList.add("hidden");
      document.querySelectorAll(".player-error").forEach(e=>e.remove());
    }

    load();
    setInterval(load, 60000);
  <\/script>
</body>
</html>`;
}

// ====== BACKEND LOGIC ======
async function fetchServerURL(roomNum: any) {
  try {
    const roomStr = String(roomNum);
    if (!/^[a-zA-Z0-9_-]+$/.test(roomStr)) return { m3u8: null, hdM3u8: null };
    const cacheKey = `room_${roomStr}`;
    const cached = getCachedResponse(cacheKey);
    if (cached) return cached;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${ROOM_API_BASE}/room/${roomStr}/detail.json`, { headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER }, signal: controller.signal });
    clearTimeout(timeout);

    const txt = await res.text();
    const m = txt.match(/detail\((.*)\)/);
    if (m) {
      const js = JSON.parse(m[1]);
      if (js.code === 200 && js.data && js.data.stream) {
        const result = { m3u8: sanitizeUrl(js.data.stream.m3u8), hdM3u8: sanitizeUrl(js.data.stream.hdM3u8) };
        setCachedResponse(cacheKey, result, 60_000);
        return result;
      }
    }
  } catch (_e) { }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string) {
  if (!/^\d{8}$/.test(date)) return [];
  const dateCacheKey = `matches_date_${date}`;
  const cached = getCachedResponse(dateCacheKey);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(`${MATCH_API_BASE}/match/matches_${date}.json`, { headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER }, signal: controller.signal });
    clearTimeout(timeout);

    const txt = await res.text();
    const m = txt.match(/matches_\d+\((.*)\)/);
    if (!m) return [];

    const js = JSON.parse(m[1]);
    if (js.code !== 200) return [];

    const now = Date.now();
    const roomFetchPromises: { index: number; promise: Promise<{ m3u8: string | null; hdM3u8: string | null }> }[] = [];
    const prelimResults: any[] = [];

    for (const it of js.data) {
      const mt = it.matchTime;
      if (!mt || typeof mt !== "number") continue;

      let status: string;
      if (now >= mt && now <= mt + 3 * 60 * 60 * 1000) status = "live";
      else if (now > mt + 3 * 60 * 60 * 1000) status = "finished";
      else status = "upcoming";

      const homeLogo = sanitizeUrl(it.homeLogo || it.hostLogo || it.homeIcon || it.hostIcon);
      const awayLogo = sanitizeUrl(it.awayLogo || it.guestLogo || it.awayIcon || it.guestIcon);
      const homeTeamName = sanitizeText(it.homeName || it.hostName || "Home", 50);
      const awayTeamName = sanitizeText(it.awayName || it.guestName || "Away", 50);
      const leagueName = sanitizeText(it.leagueName || it.subCateName || "Unknown League", 80);

      let matchScore: string | null = null;
      if (it.homeScore !== undefined && it.homeScore !== null) {
        const hs = String(it.homeScore).replace(/[^0-9]/g, "").slice(0, 3);
        const as = String(it.awayScore).replace(/[^0-9]/g, "").slice(0, 3);
        matchScore = `${hs} - ${as}`;
      }

      const matchDateStr = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Yangon", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(mt));
      const todayDateStr = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Yangon", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
      const tomorrowD = new Date(); tomorrowD.setDate(tomorrowD.getDate() + 1);
      const tomorrowDateStr = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Yangon", year: "numeric", month: "2-digit", day: "2-digit" }).format(tomorrowD);
      const yesterdayD = new Date(); yesterdayD.setDate(yesterdayD.getDate() - 1);
      const yesterdayDateStr = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Yangon", year: "numeric", month: "2-digit", day: "2-digit" }).format(yesterdayD);

      let matchDay: string;
      if (matchDateStr === todayDateStr) matchDay = "Today";
      else if (matchDateStr === tomorrowDateStr) matchDay = "Tomorrow";
      else if (matchDateStr === yesterdayDateStr) matchDay = "Yesterday";
      else matchDay = matchDateStr;

      const entryIndex = prelimResults.length;
      prelimResults.push({
        match_time: new Date(mt).toLocaleTimeString("en-US", { timeZone: "Asia/Yangon", hour: "2-digit", minute: "2-digit", hour12: true }),
        match_day: matchDay,
        match_status: status,
        home_team_name: homeTeamName,
        away_team_name: awayTeamName,
        home_team_logo: homeLogo,
        away_team_logo: awayLogo,
        league_name: leagueName,
        match_score: matchScore,
        servers: [] as any[],
      });

      if (status === "live" && it.anchors) {
        for (const a of it.anchors.slice(0, 3)) {
          if (a.anchor?.roomNum) roomFetchPromises.push({ index: entryIndex, promise: fetchServerURL(a.anchor.roomNum) });
        }
      }
    }

    const roomResults = await Promise.allSettled(roomFetchPromises.map((r) => r.promise));
    for (let i = 0; i < roomFetchPromises.length; i++) {
      if (roomResults[i].status === "fulfilled") {
        const { m3u8, hdM3u8 } = (roomResults[i] as PromiseFulfilledResult<any>).value;
        const idx = roomFetchPromises[i].index;
        if (m3u8) prelimResults[idx].servers.push({ name: "Soco SD", stream_url: m3u8 });
        if (hdM3u8) prelimResults[idx].servers.push({ name: "Soco HD", stream_url: hdM3u8 });
      }
    }

    setCachedResponse(dateCacheKey, prelimResults, 30_000);
    return prelimResults;
  } catch (e) {
    return [];
  }
}
