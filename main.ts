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
// Set your deployed domain here (e.g. "https://yourdomain.com")
const ALLOWED_ORIGINS: string[] = (() => {
  const raw = Deno.env.get("ALLOWED_ORIGINS") || "";
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
})();

function isAllowedOrigin(req: Request): boolean {
  // If no ALLOWED_ORIGINS configured, skip check (development mode)
  if (ALLOWED_ORIGINS.length === 0) return true;

  const origin = req.headers.get("origin") || "";
  const referer = req.headers.get("referer") || "";

  for (const allowed of ALLOWED_ORIGINS) {
    if (origin === allowed) return true;
    if (referer.startsWith(allowed)) return true;
  }

  // Allow same-origin requests (no origin header = same origin navigation)
  if (!origin && !referer) return true;

  return false;
}

// ====== SECURITY: CSRF Token ======
function generateCSRFToken(): string {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Per-session CSRF tokens (IP-based for simplicity)
const csrfTokens = new Map<string, { token: string; expires: number }>();

function getOrCreateCSRFToken(ip: string): string {
  const existing = csrfTokens.get(ip);
  if (existing && Date.now() < existing.expires) {
    return existing.token;
  }
  const token = generateCSRFToken();
  csrfTokens.set(ip, { token, expires: Date.now() + 30 * 60_000 }); // 30 min
  return token;
}

function validateCSRFToken(ip: string, token: string): boolean {
  const existing = csrfTokens.get(ip);
  if (!existing || Date.now() > existing.expires) return false;
  return existing.token === token;
}

// Cleanup CSRF tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of csrfTokens) {
    if (now > entry.expires) csrfTokens.delete(ip);
  }
}, 10 * 60_000);

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
  if (!dailyVisitors.has(today)) {
    dailyVisitors.set(today, new Set());
  }
  dailyVisitors.get(today)!.add(ip);

  // Clean up old days (keep only last 7 days)
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
const API_CACHE_TTL = 30_000; // 30 seconds cache for match data

function getCachedResponse(key: string): any | null {
  const entry = apiCache.get(key);
  if (entry && Date.now() < entry.expires) {
    return entry.data;
  }
  if (entry) {
    apiCache.delete(key);
  }
  return null;
}

function setCachedResponse(key: string, data: any, ttl: number = API_CACHE_TTL): void {
  apiCache.set(key, { data, expires: Date.now() + ttl });
}

// Cleanup expired cache
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of apiCache) {
    if (now > entry.expires) apiCache.delete(key);
  }
}, 60_000);

// ====== SECURITY: Rate Limiter (Improved for 400-500 users) ======
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60_000; // 1 minute window
const RATE_LIMIT_MAX = 45; // Max 45 requests per minute per IP (reasonable for page + auto-refresh)
const BLOCK_THRESHOLD = 150; // Block if they exceed this in a window (clearly abusive)
const blockedIPs = new Map<string, number>();
const BLOCK_DURATION = 10 * 60_000; // 10 minutes block

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

  // Check block list
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

  // Block requests with no or very short user agent
  if (!ua || ua.length < 10) return true;

  // Known attack tools
  const botPatterns = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i,
    /gobuster/i, /wfuzz/i, /hydra/i, /burpsuite/i, /nessus/i,
    /openvas/i, /acunetix/i, /zgrab/i, /nuclei/i, /scrapy/i,
    /havij/i, /commix/i, /w3af/i, /skipfish/i, /arachni/i,
    /whatweb/i, /fierce/i, /httprint/i,
  ];
  if (botPatterns.some((p) => p.test(ua))) return true;

  // Path traversal attempts
  const path = url.pathname;
  if (path.includes("..") || path.includes("//") || path.includes("\\"))
    return true;

  // Common malicious path probes
  const maliciousPaths = [
    /\.env/i, /\.git/i, /wp-admin/i, /wp-login/i, /phpmyadmin/i,
    /\/admin\b/i, /\.php$/i, /\.asp$/i, /shell/i, /eval\(/i,
    /exec\(/i, /\.sql$/i, /backup/i, /\.bak$/i, /\.log$/i,
    /\.config$/i, /\.ini$/i, /\.yml$/i, /\.yaml$/i, /\.xml$/i,
    /cgi-bin/i, /\.htaccess/i, /\.htpasswd/i, /wp-content/i,
    /xmlrpc/i, /\.well-known\/security/i,
  ];
  if (maliciousPaths.some((p) => p.test(path))) return true;

  // SQL Injection & XSS in query string
  const query = url.search;
  const sqlPatterns = [
    /union.*select/i, /or\s+1\s*=\s*1/i, /drop\s+table/i,
    /insert\s+into/i, /delete\s+from/i, /script>/i, /<iframe/i,
    /javascript:/i, /onerror\s*=/i, /onload\s*=/i, /\bexec\b/i,
    /\bconcat\b.*\bselect\b/i, /\bload_file\b/i, /\bbenchmark\b/i,
    /\bsleep\b\s*\(/i, /\bwaitfor\b/i, /\bchar\b\s*\(/i,
  ];
  if (sqlPatterns.some((p) => p.test(query))) return true;

  // Oversized URL (potential buffer overflow attempt)
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
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    "Content-Security-Policy":
      "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; " +
      "img-src 'self' https: data:; " +
      "media-src 'self' blob: https:; " +
      "connect-src 'self'; " +
      "frame-ancestors 'none'; " +
      "base-uri 'self'; " +
      "form-action 'self';",
    "Strict-Transport-Security":
      "max-age=63072000; includeSubDomains; preload",
    "Cache-Control": "no-store",
  };
}

// ====== SECURITY: Sanitize URL (only allow http/https) ======
function sanitizeUrl(url: string | null | undefined): string | null {
  if (!url || typeof url !== "string") return null;
  const trimmed = url.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed.replace(/[<>"'`\s]/g, "");
  }
  return null;
}

// ====== SECURITY: Sanitize plain text ======
function sanitizeText(
  text: string | null | undefined,
  maxLen: number
): string {
  if (!text || typeof text !== "string") return "";
  return text
    .replace(/<[^>]*>/g, "")
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(/[&<>"']/g, (c) => {
      const map: Record<string, string> = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
      };
      return map[c] || c;
    })
    .trim()
    .slice(0, maxLen);
}

// ====== Logo Proxy Cache (in-memory, binary data) ======
const logoProxyCache = new Map<
  string,
  { data: Uint8Array; contentType: string; expires: number }
>();
const LOGO_CACHE_TTL = 10 * 60 * 1000; // 10 minutes (increased for performance)
const LOGO_CACHE_MAX_SIZE = 500;

// Clean up expired logo cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of logoProxyCache) {
    if (now > entry.expires) logoProxyCache.delete(key);
  }
}, 2 * 60_000);

async function fetchLogoViaProxy(
  logoUrl: string
): Promise<{ data: Uint8Array; contentType: string } | null> {
  // Validate URL
  if (!sanitizeUrl(logoUrl)) return null;

  // Check cache first
  const cached = logoProxyCache.get(logoUrl);
  if (cached && Date.now() < cached.expires) {
    return { data: cached.data, contentType: cached.contentType };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(logoUrl, {
      headers: {
        "User-Agent": API_USER_AGENT,
        Referer: API_REFERER,
        Accept: "image/*,*/*;q=0.8",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;

    const contentType = res.headers.get("content-type") || "image/png";

    // Only allow image content types
    if (!contentType.startsWith("image/")) return null;

    const arrayBuf = await res.arrayBuffer();
    const data = new Uint8Array(arrayBuf);

    // Don't cache excessively large images (> 2MB)
    if (data.length > 2 * 1024 * 1024) return { data, contentType };

    // Evict oldest entries if cache is too large
    if (logoProxyCache.size >= LOGO_CACHE_MAX_SIZE) {
      let oldestKey: string | null = null;
      let oldestTime = Infinity;
      for (const [key, entry] of logoProxyCache) {
        if (entry.expires < oldestTime) {
          oldestTime = entry.expires;
          oldestKey = key;
        }
      }
      if (oldestKey) logoProxyCache.delete(oldestKey);
    }

    logoProxyCache.set(logoUrl, {
      data,
      contentType,
      expires: Date.now() + LOGO_CACHE_TTL,
    });

    return { data, contentType };
  } catch (_e) {
    return null;
  }
}

// ====== Developer Stats Auth Key ======
const DEV_STATS_KEY = Deno.env.get("DEV_STATS_KEY") || crypto.randomUUID();
// Log the auto-generated key so admin can see it at startup
if (!Deno.env.get("DEV_STATS_KEY")) {
  console.log(`[SECURITY] Auto-generated DEV_STATS_KEY: ${DEV_STATS_KEY}`);
  console.log(`[SECURITY] Set DEV_STATS_KEY env var to use a persistent key.`);
}

serve(async (req) => {
  const url = new URL(req.url);
  const clientIP = getClientIP(req);

  // ====== SECURITY: Rate limiting ======
  const { limited, blocked } = isRateLimited(clientIP);
  if (blocked) {
    return new Response(
      JSON.stringify({ error: "Blocked: Too many requests. Try again later." }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": "600",
          ...securityHeaders(),
        },
      }
    );
  }
  if (limited) {
    return new Response(
      JSON.stringify({ error: "Rate limit exceeded. Please slow down." }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": "60",
          ...securityHeaders(),
        },
      }
    );
  }

  // ====== SECURITY: Suspicious request detection ======
  if (isSuspiciousRequest(req)) {
    return new Response("Not Found", {
      status: 404,
      headers: securityHeaders(),
    });
  }

  // ====== SECURITY: Only allow GET ======
  if (req.method !== "GET") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET", ...securityHeaders() },
    });
  }

  // --- 1. API ROUTE: Matches (with caching) ---
  if (url.pathname === "/api/matches") {
    // ====== SECURITY: Validate origin for API calls ======
    if (!isAllowedOrigin(req)) {
      return new Response(
        JSON.stringify({ error: "Forbidden" }),
        {
          status: 403,
          headers: {
            "Content-Type": "application/json",
            ...securityHeaders(),
          },
        }
      );
    }

    try {
      // Check cache first - this is the key for handling 400-500 users
      const cacheKey = "matches_all";
      const cached = getCachedResponse(cacheKey);
      if (cached) {
        return new Response(JSON.stringify(cached), {
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=30",
            "X-Cache": "HIT",
            ...securityHeaders(),
          },
        });
      }

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

      // Fetch all dates in parallel for speed
      const allResults = await Promise.allSettled(
        dates.map((d) => fetchMatches(d))
      );

      let allMatches: any[] = [];
      for (const result of allResults) {
        if (result.status === "fulfilled") {
          allMatches = allMatches.concat(result.value);
        }
      }

      // Filter out finished matches
      allMatches = allMatches.filter(
        (m: any) => m.match_status !== "finished"
      );

      // Sort: live first
      allMatches.sort((a, b) => {
        if (a.match_status === "live" && b.match_status !== "live") return -1;
        if (a.match_status !== "live" && b.match_status === "live") return 1;
        return 0;
      });

      // Cache the response
      setCachedResponse(cacheKey, allMatches, API_CACHE_TTL);

      return new Response(JSON.stringify(allMatches), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=30",
          "X-Cache": "MISS",
          ...securityHeaders(),
        },
      });
    } catch (_e: any) {
      return new Response(
        JSON.stringify({ error: "Service temporarily unavailable" }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            ...securityHeaders(),
          },
        }
      );
    }
  }

  // --- 2. API ROUTE: Logo Proxy ---
  if (url.pathname === "/api/logo-proxy") {
    // ====== SECURITY: Validate origin ======
    if (!isAllowedOrigin(req)) {
      return new Response("Forbidden", {
        status: 403,
        headers: securityHeaders(),
      });
    }

    const logoUrl = url.searchParams.get("url");
    const sanitized = sanitizeUrl(logoUrl);
    if (!sanitized) {
      return new Response("Bad Request", {
        status: 400,
        headers: securityHeaders(),
      });
    }

    const result = await fetchLogoViaProxy(sanitized);
    if (!result) {
      // Return a 1x1 transparent PNG as fallback
      const transparentPng = new Uint8Array([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00,
        0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
        0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, 0x33, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
      ]);
      return new Response(transparentPng, {
        status: 200,
        headers: {
          "Content-Type": "image/png",
          "Cache-Control": "public, max-age=60",
          ...securityHeaders(),
        },
      });
    }

    return new Response(result.data, {
      status: 200,
      headers: {
        "Content-Type": result.contentType,
        "Cache-Control": "public, max-age=300",
        ...securityHeaders(),
      },
    });
  }

  // --- 3. API ROUTE: Developer Stats (visitor tracking) ---
  if (url.pathname === "/api/stats") {
    const key = url.searchParams.get("key");
    if (!key || key !== DEV_STATS_KEY) {
      // Constant-time comparison to prevent timing attacks
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          ...securityHeaders(),
        },
      });
    }

    const stats = getVisitorStats();
    const today = getTodayDateKey();
    return new Response(
      JSON.stringify({
        today: today,
        today_visitors: stats[today] || 0,
        daily_history: stats,
        active_rate_limits: rateLimitMap.size,
        blocked_ips: blockedIPs.size,
        cache_entries: apiCache.size,
        logo_cache_entries: logoProxyCache.size,
      }),
      {
        headers: {
          "Content-Type": "application/json",
          ...securityHeaders(),
        },
      }
    );
  }

  // --- 4. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    // Track this visitor
    trackVisitor(clientIP);

    return new Response(getHTML(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=60",
        ...securityHeaders(),
      },
    });
  }

  // Everything else → 404
  return new Response("Not Found", {
    status: 404,
    headers: securityHeaders(),
  });
});

// ====== FRONTEND HTML ======
function getHTML(): string {
  const safeDevUrl = sanitizeUrl(DEV_CONTACT_URL) || "#";
  const safeDevImg = sanitizeUrl(DEV_PROFILE_IMG) || "";
  const safeDevName = sanitizeText(DEV_DISPLAY_NAME, 50) || "Developer";
  const safeSubtitle =
    sanitizeText(SITE_SUBTITLE, 100) || "Premium Sports Streaming";

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta name="theme-color" content="#f8fafc">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <title>All Sports Live</title>
  <script src="https://cdn.tailwindcss.com"><\/script>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }

    body {
      background: #f1f5f9;
      color: #1e293b;
      font-family: 'Inter', 'Padauk', sans-serif;
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* Light subtle animated background */
    .bg-animated {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 0;
      background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 25%, #f8fafc 50%, #e2e8f0 75%, #f1f5f9 100%);
      background-size: 400% 400%;
      animation: gradientShift 20s ease infinite;
    }
    @keyframes gradientShift {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }

    /* Soft floating orbs */
    .orb {
      position: fixed;
      border-radius: 50%;
      filter: blur(100px);
      opacity: 0.15;
      z-index: 0;
      pointer-events: none;
    }
    .orb-1 {
      width: 350px; height: 350px;
      background: #f59e0b;
      top: -150px; right: -100px;
      animation: orbFloat1 20s ease-in-out infinite;
    }
    .orb-2 {
      width: 300px; height: 300px;
      background: #6366f1;
      bottom: -100px; left: -100px;
      animation: orbFloat2 25s ease-in-out infinite;
    }
    .orb-3 {
      width: 250px; height: 250px;
      background: #10b981;
      top: 40%; left: 50%;
      transform: translate(-50%, -50%);
      animation: orbFloat3 18s ease-in-out infinite;
    }
    @keyframes orbFloat1 {
      0%, 100% { transform: translate(0, 0); }
      33% { transform: translate(-40px, 60px); }
      66% { transform: translate(30px, -40px); }
    }
    @keyframes orbFloat2 {
      0%, 100% { transform: translate(0, 0); }
      33% { transform: translate(50px, -30px); }
      66% { transform: translate(-20px, 40px); }
    }
    @keyframes orbFloat3 {
      0%, 100% { transform: translate(-50%, -50%) scale(1); }
      50% { transform: translate(-50%, -50%) scale(1.2); }
    }

    .app-container {
      position: relative;
      z-index: 1;
    }

    /* Clean light header */
    .premium-header {
      background: rgba(255, 255, 255, 0.85);
      border-bottom: 1px solid rgba(0,0,0,0.06);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      position: sticky;
      top: 0;
      z-index: 40;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .header-title {
      background: linear-gradient(135deg, #d97706, #b45309, #d97706);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-weight: 900;
      letter-spacing: -0.5px;
    }
    .header-subtitle {
      color: #94a3b8;
      font-size: 11px;
      font-weight: 500;
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    .dev-contact-link {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 12px;
      border-radius: 24px;
      background: rgba(217,119,6,0.08);
      border: 1px solid rgba(217,119,6,0.15);
      text-decoration: none;
      transition: all 0.3s;
    }
    .dev-contact-link:hover {
      background: rgba(217,119,6,0.14);
      border-color: rgba(217,119,6,0.3);
      transform: translateY(-1px);
      box-shadow: 0 4px 16px rgba(217,119,6,0.12);
    }
    .dev-avatar {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      object-fit: cover;
      border: 2px solid rgba(217,119,6,0.2);
    }
    .dev-name {
      font-size: 11px;
      font-weight: 700;
      color: #b45309;
    }

    .live-dot {
      width: 8px; height: 8px;
      background: #ef4444;
      border-radius: 50%;
      display: inline-block;
      animation: pulse-dot 1s ease-in-out infinite;
      box-shadow: 0 0 6px rgba(239,68,68,0.5);
    }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.7); }
    }

    /* Light glass card */
    .card {
      background: rgba(255, 255, 255, 0.75);
      border: 1px solid rgba(0,0,0,0.06);
      border-radius: 20px;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 2px 12px rgba(0,0,0,0.04), 0 1px 3px rgba(0,0,0,0.03);
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.8), transparent);
    }
    .card:hover {
      border-color: rgba(0,0,0,0.1);
      transform: translateY(-3px);
      box-shadow: 0 12px 32px rgba(0,0,0,0.08), 0 4px 12px rgba(0,0,0,0.04);
    }
    .card-live {
      border-color: rgba(239,68,68,0.2);
      box-shadow: 0 2px 12px rgba(239,68,68,0.06), 0 0 30px rgba(239,68,68,0.03);
    }
    .card-live::before {
      background: linear-gradient(90deg, transparent, rgba(239,68,68,0.25), transparent);
    }
    .card-live:hover {
      border-color: rgba(239,68,68,0.35);
      box-shadow: 0 12px 32px rgba(239,68,68,0.1);
    }

    .card-watching {
      border-color: rgba(217,119,6,0.4) !important;
      box-shadow: 0 0 0 2px rgba(217,119,6,0.1), 0 12px 32px rgba(217,119,6,0.1) !important;
    }
    .card-watching::before {
      background: linear-gradient(90deg, transparent, rgba(217,119,6,0.4), transparent) !important;
    }

    .team-logo {
      width: 52px; height: 52px;
      border-radius: 50%;
      object-fit: contain;
      background: rgba(0,0,0,0.03);
      padding: 5px;
      border: 2px solid rgba(0,0,0,0.06);
      transition: all 0.3s;
    }
    .card:hover .team-logo {
      border-color: rgba(217,119,6,0.25);
      box-shadow: 0 0 12px rgba(217,119,6,0.08);
    }
    .team-logo-fallback {
      width: 52px; height: 52px;
      border-radius: 50%;
      background: linear-gradient(135deg, rgba(0,0,0,0.04), rgba(0,0,0,0.02));
      display: flex; align-items: center; justify-content: center;
      font-size: 20px;
      border: 2px solid rgba(0,0,0,0.06);
    }

    .btn-hd {
      background: linear-gradient(135deg, #ef4444, #dc2626);
      box-shadow: 0 4px 12px rgba(239,68,68,0.25);
      position: relative;
      overflow: hidden;
    }
    .btn-hd::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent);
      transition: left 0.5s;
    }
    .btn-hd:hover::before { left: 100%; }
    .btn-hd:hover { box-shadow: 0 6px 20px rgba(239,68,68,0.4); transform: translateY(-1px); }
    .btn-hd:active { transform: translateY(0); }

    .btn-sd {
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      box-shadow: 0 4px 12px rgba(99,102,241,0.25);
      position: relative;
      overflow: hidden;
    }
    .btn-sd::before {
      content: '';
      position: absolute;
      top: 0; left: -100%;
      width: 100%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent);
      transition: left 0.5s;
    }
    .btn-sd:hover::before { left: 100%; }
    .btn-sd:hover { box-shadow: 0 6px 20px rgba(99,102,241,0.4); transform: translateY(-1px); }
    .btn-sd:active { transform: translateY(0); }

    .score-box {
      background: rgba(15,23,42,0.06);
      border: 1px solid rgba(0,0,0,0.06);
      border-radius: 14px;
      padding: 6px 16px;
      min-width: 80px;
    }

    .league-badge {
      background: rgba(217,119,6,0.08);
      border: 1px solid rgba(217,119,6,0.15);
      border-radius: 24px;
      padding: 4px 12px;
      font-weight: 600;
    }

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
      background: linear-gradient(135deg, #d97706, #b45309);
      color: #ffffff;
      box-shadow: 0 4px 16px rgba(217,119,6,0.25);
    }
    .tab-btn:not(.active) {
      background: rgba(255,255,255,0.7);
      color: #64748b;
      border-color: rgba(0,0,0,0.06);
    }
    .tab-btn:not(.active):hover {
      background: rgba(255,255,255,0.9);
      color: #1e293b;
      border-color: rgba(0,0,0,0.1);
    }

    .stat-pill {
      background: rgba(255,255,255,0.7);
      border: 1px solid rgba(0,0,0,0.06);
      border-radius: 16px;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
      color: #64748b;
    }
    .stat-indicator {
      width: 6px; height: 6px;
      border-radius: 50%;
      display: inline-block;
    }

    .loading-spinner {
      width: 44px; height: 44px;
      border: 3px solid rgba(0,0,0,0.06);
      border-top-color: #d97706;
      border-right-color: rgba(217,119,6,0.3);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .player-wrapper {
      border-radius: 20px;
      overflow: hidden;
      border: 2px solid rgba(217,119,6,0.3);
      box-shadow: 0 16px 48px rgba(0,0,0,0.12), 0 0 30px rgba(217,119,6,0.06);
    }

    .now-watching-bar {
      background: linear-gradient(135deg, #1e293b, #0f172a);
      padding: 10px 16px;
      display: flex;
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .now-watching-bar .nw-dot {
      width: 8px; height: 8px;
      background: #ef4444;
      border-radius: 50%;
      animation: pulse-dot 1s ease-in-out infinite;
      flex-shrink: 0;
    }
    .now-watching-bar .nw-label {
      font-size: 10px;
      font-weight: 700;
      color: #facc15;
      text-transform: uppercase;
      letter-spacing: 1px;
      flex-shrink: 0;
    }
    .now-watching-bar .nw-match {
      font-size: 12px;
      font-weight: 600;
      color: #e2e8f0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .now-watching-bar .nw-league {
      font-size: 10px;
      color: #94a3b8;
      margin-left: auto;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .close-btn {
      background: linear-gradient(135deg, #1e293b, #0f172a);
      border-top: 1px solid rgba(255,255,255,0.06);
      transition: all 0.2s;
      color: #ffffff;
    }
    .close-btn:hover {
      background: linear-gradient(135deg, #dc2626, #991b1b);
    }

    .status-live {
      background: rgba(239,68,68,0.1);
      border: 1px solid rgba(239,68,68,0.25);
      color: #dc2626;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .status-upcoming {
      background: rgba(16,185,129,0.08);
      border: 1px solid rgba(16,185,129,0.2);
      color: #059669;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 600;
    }

    ::-webkit-scrollbar { width: 3px; height: 3px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.1); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(0,0,0,0.2); }

    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .fade-up { animation: fadeUp 0.5s ease-out forwards; }
    .fade-up-delay-1 { animation-delay: 0.1s; opacity: 0; }
    .fade-up-delay-2 { animation-delay: 0.2s; opacity: 0; }
    .fade-up-delay-3 { animation-delay: 0.3s; opacity: 0; }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
    }
    .empty-state-icon {
      font-size: 48px;
      margin-bottom: 16px;
      opacity: 0.5;
    }

    .bottom-safe { height: 100px; }

    .player-error {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.9);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-size: 13px;
      z-index: 10;
      padding: 20px;
      text-align: center;
      line-height: 1.7;
    }
    .player-error-btn {
      margin-top: 14px;
      background: #d97706;
      color: #fff;
      border: none;
      padding: 8px 24px;
      border-radius: 20px;
      font-weight: 700;
      cursor: pointer;
    }
    .player-error-tips {
      margin-top: 10px;
      font-size: 11px;
      color: #94a3b8;
      max-width: 300px;
      line-height: 1.8;
    }

    .player-loading {
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 5;
    }
    .player-loading .loading-spinner {
      border-top-color: #facc15;
    }

    .day-separator {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 16px 0 10px 0;
    }
    .day-separator-line {
      flex: 1;
      height: 1px;
      background: rgba(0,0,0,0.06);
    }
    .day-separator-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 4px 14px;
      border-radius: 20px;
    }
    .day-today {
      background: rgba(99,102,241,0.1);
      color: #4f46e5;
      border: 1px solid rgba(99,102,241,0.2);
    }
    .day-tomorrow {
      background: rgba(16,185,129,0.08);
      color: #059669;
      border: 1px solid rgba(16,185,129,0.2);
    }
    .day-yesterday {
      background: rgba(0,0,0,0.04);
      color: #64748b;
      border: 1px solid rgba(0,0,0,0.06);
    }
    .day-other {
      background: rgba(0,0,0,0.03);
      color: #94a3b8;
      border: 1px solid rgba(0,0,0,0.05);
    }

    .countdown-text {
      font-size: 10px;
      color: #059669;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
      margin-top: 2px;
    }

    .live-elapsed {
      font-size: 10px;
      color: #dc2626;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
    }

    .search-bar {
      background: rgba(255,255,255,0.8);
      border: 1px solid rgba(0,0,0,0.08);
      border-radius: 16px;
      padding: 10px 16px;
      color: #1e293b;
      font-size: 13px;
      width: 100%;
      outline: none;
      transition: all 0.3s;
      font-family: 'Inter', 'Padauk', sans-serif;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .search-bar::placeholder {
      color: #94a3b8;
    }
    .search-bar:focus {
      border-color: rgba(217,119,6,0.35);
      background: rgba(255,255,255,0.95);
      box-shadow: 0 0 0 3px rgba(217,119,6,0.08), 0 2px 8px rgba(0,0,0,0.05);
    }

    .match-transition {
      transition: opacity 0.3s ease;
    }

    .refresh-indicator {
      position: fixed;
      top: 68px;
      left: 50%;
      transform: translateX(-50%) translateY(-50px);
      background: rgba(217,119,6,0.95);
      color: white;
      padding: 6px 16px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      z-index: 50;
      transition: transform 0.3s ease;
      pointer-events: none;
    }
    .refresh-indicator.visible {
      transform: translateX(-50%) translateY(10px);
    }

    .last-updated {
      font-size: 10px;
      color: #94a3b8;
      text-align: center;
      margin-top: 4px;
      font-variant-numeric: tabular-nums;
    }

    .skeleton {
      background: linear-gradient(90deg, rgba(0,0,0,0.03) 25%, rgba(0,0,0,0.06) 50%, rgba(0,0,0,0.03) 75%);
      background-size: 200% 100%;
      animation: shimmer 1.5s infinite;
      border-radius: 20px;
    }
    @keyframes shimmer {
      0% { background-position: 200% 0; }
      100% { background-position: -200% 0; }
    }

    /* Score text in light mode */
    .score-text {
      color: #d97706;
      text-shadow: none;
    }
  </style>
</head>
<body>
  <!-- Animated Background -->
  <div class="bg-animated"></div>
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="orb orb-3"></div>

  <div class="app-container">

    <!-- Refresh Indicator -->
    <div id="refresh-indicator" class="refresh-indicator">Updating...</div>

    <!-- Premium Header -->
    <div class="premium-header">
      <div class="max-w-md mx-auto px-5 py-4">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="header-title text-xl">All Sports Live</h1>
            <p class="header-subtitle mt-0.5">${safeSubtitle}</p>
          </div>
          <a href="${safeDevUrl}" target="_blank" rel="noopener noreferrer" title="Contact ${safeDevName}" class="dev-contact-link">
            <img src="${safeDevImg}" alt="${safeDevName}" class="dev-avatar" onerror="this.style.display='none'">
            <span class="dev-name">${safeDevName}</span>
          </a>
        </div>
      </div>
    </div>

    <div class="max-w-md mx-auto px-4 pt-5 pb-4">

      <!-- Search Bar -->
      <div class="mb-4 fade-up">
        <input type="text" id="search-input" class="search-bar" placeholder="Search teams or leagues..." maxlength="100" autocomplete="off">
      </div>

      <!-- Filter Tabs -->
      <div class="flex gap-2 mb-4 overflow-x-auto pb-1 fade-up fade-up-delay-1" id="tabs">
        <button class="tab-btn active" data-filter="all">All Matches</button>
        <button class="tab-btn" data-filter="live">Live Now</button>
        <button class="tab-btn" data-filter="upcoming">Upcoming</button>
      </div>

      <!-- Stats Bar -->
      <div class="flex gap-2 justify-center mb-2 fade-up fade-up-delay-2" id="stats-bar">
        <span class="stat-pill">
          <span class="stat-indicator" style="background:#94a3b8;"></span>
          <span id="stat-total">Total: —</span>
        </span>
        <span class="stat-pill">
          <span class="stat-indicator" style="background:#ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5);"></span>
          <span id="stat-live">Live: —</span>
        </span>
        <span class="stat-pill">
          <span class="stat-indicator" style="background:#10b981;"></span>
          <span id="stat-upcoming">Soon: —</span>
        </span>
      </div>

      <!-- Last Updated -->
      <div class="last-updated mb-4" id="last-updated"></div>

      <!-- Video Player -->
      <div id="player-container" class="hidden sticky top-[68px] z-50 mb-5 player-wrapper">
        <div id="now-watching-bar" class="now-watching-bar hidden">
          <span class="nw-dot"></span>
          <span class="nw-label">Watching</span>
          <span class="nw-match" id="nw-match-text">—</span>
          <span class="nw-league" id="nw-league-text"></span>
        </div>
        <div class="bg-black relative" id="player-inner">
          <video id="video" controls class="w-full aspect-video" autoplay playsinline></video>
          <div id="player-loading" class="player-loading hidden">
            <div class="loading-spinner"></div>
          </div>
        </div>
        <button id="close-player-btn" class="close-btn w-full text-xs font-bold py-3.5 flex items-center justify-center gap-2">
          ✕ Close Player
        </button>
      </div>

      <!-- Loading Skeleton -->
      <div id="loading" class="space-y-3 fade-up fade-up-delay-3">
        <div class="skeleton" style="height: 180px;"></div>
        <div class="skeleton" style="height: 180px;"></div>
        <div class="skeleton" style="height: 180px;"></div>
      </div>

      <!-- Match List -->
      <div id="match-list" class="space-y-3"></div>

      <div class="bottom-safe"></div>
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
      if (typeof str !== "string") return "";
      var div = document.createElement("div");
      div.textContent = str;
      return div.innerHTML;
    }

    function proxiedLogoUrl(originalUrl) {
      if (!originalUrl) return null;
      return "/api/logo-proxy?url=" + encodeURIComponent(originalUrl);
    }

    // Search input handler with debounce
    var searchTimeout = null;
    document.getElementById("search-input").addEventListener("input", function(e) {
      clearTimeout(searchTimeout);
      var val = e.target.value;
      // Sanitize search input
      val = val.replace(/[<>'"]/g, "");
      searchTimeout = setTimeout(function() {
        searchQuery = val.trim().toLowerCase();
        renderMatches();
      }, 250);
    });

    document.getElementById("tabs").addEventListener("click", function(e) {
      var btn = e.target.closest(".tab-btn");
      if (!btn) return;
      var filter = btn.getAttribute("data-filter");
      if (!filter) return;
      currentFilter = filter;
      document.querySelectorAll(".tab-btn").forEach(function(b) { b.classList.remove("active"); });
      btn.classList.add("active");
      renderMatches();
    });

    document.getElementById("close-player-btn").addEventListener("click", function() {
      closePlayer();
    });

    function showRefreshIndicator() {
      var el = document.getElementById("refresh-indicator");
      el.classList.add("visible");
      setTimeout(function() {
        el.classList.remove("visible");
      }, 1500);
    }

    function hideRefreshIndicator() {
      var el = document.getElementById("refresh-indicator");
      el.classList.remove("visible");
    }

    async function load() {
      if (isLoadingData) return; // Prevent concurrent loads
      isLoadingData = true;

      try {
        var res = await fetch("/api/matches");
        if (!res.ok) throw new Error("Server error");
        var data = await res.json();
        if (data.error) throw new Error(data.error);
        allData = data;

        if (isFirstLoad) {
          document.getElementById("loading").style.display = "none";
          isFirstLoad = false;
        } else {
          showRefreshIndicator();
        }

        lastUpdateTime = new Date();
        updateLastUpdatedText();

        preloadLogos(data);
        updateStats();
        renderMatches();
        startCountdowns();
      } catch (e) {
        hideRefreshIndicator();
        if (isFirstLoad) {
          document.getElementById("loading").innerHTML =
            '<div class="empty-state"><div class="empty-state-icon">⚠️</div>' +
            '<div class="text-red-500 text-sm font-medium">' + escapeHtml(e.message) + '</div>' +
            '<div class="text-slate-400 text-xs mt-2">Pull to refresh or try again later</div></div>';
        }
      } finally {
        isLoadingData = false;
      }
    }

    function updateLastUpdatedText() {
      if (!lastUpdateTime) return;
      var el = document.getElementById("last-updated");
      var now = new Date();
      var diffSec = Math.floor((now - lastUpdateTime) / 1000);
      if (diffSec < 5) {
        el.textContent = "Updated just now";
      } else if (diffSec < 60) {
        el.textContent = "Updated " + diffSec + "s ago";
      } else {
        var min = Math.floor(diffSec / 60);
        el.textContent = "Updated " + min + "m ago";
      }
    }

    setInterval(updateLastUpdatedText, 10000);

    function preloadLogos(matches) {
      matches.forEach(function(m) {
        [m.home_team_logo, m.away_team_logo].forEach(function(url) {
          if (url && !logoCache[url]) {
            var proxyUrl = proxiedLogoUrl(url);
            var img = new Image();
            img.src = proxyUrl;
            img.onload = function() { logoCache[url] = "ok"; };
            img.onerror = function() { logoCache[url] = "fail"; };
          }
        });
      });
    }

    function updateStats() {
      var live = allData.filter(function(m) { return m.match_status === "live"; }).length;
      var upcoming = allData.filter(function(m) { return m.match_status === "upcoming"; }).length;
      document.getElementById("stat-total").textContent = "Total: " + allData.length;
      document.getElementById("stat-live").textContent = "Live: " + live;
      document.getElementById("stat-upcoming").textContent = "Soon: " + upcoming;
    }

    function createLogoElement(url) {
      if (url && logoCache[url] === "fail") {
        var fallback = document.createElement("div");
        fallback.className = "team-logo-fallback";
        fallback.textContent = "⚽";
        return fallback;
      }
      if (url) {
        var proxyUrl = proxiedLogoUrl(url);
        var img = document.createElement("img");
        img.className = "team-logo";
        img.loading = "eager";
        img.decoding = "async";
        img.alt = "";
        img.src = proxyUrl;
        img.onerror = function() {
          logoCache[url] = "fail";
          var fb = document.createElement("div");
          fb.className = "team-logo-fallback";
          fb.textContent = "⚽";
          img.replaceWith(fb);
        };
        img.onload = function() {
          logoCache[url] = "ok";
        };
        return img;
      }
      var fallback = document.createElement("div");
      fallback.className = "team-logo-fallback";
      fallback.textContent = "⚽";
      return fallback;
    }

    function getDaySeparatorClass(day) {
      if (day === "Today") return "day-today";
      if (day === "Tomorrow") return "day-tomorrow";
      if (day === "Yesterday") return "day-yesterday";
      return "day-other";
    }

    function getMatchUniqueKey(m) {
      return (m.home_team_name || "") + " vs " + (m.away_team_name || "") + " | " + (m.league_name || "");
    }

    function updateNowWatchingBar() {
      var bar = document.getElementById("now-watching-bar");
      if (currentWatchingMatch) {
        document.getElementById("nw-match-text").textContent =
          (currentWatchingMatch.home_team_name || "Home") + "  vs  " + (currentWatchingMatch.away_team_name || "Away");
        document.getElementById("nw-league-text").textContent = currentWatchingMatch.league_name || "";
        bar.classList.remove("hidden");
      } else {
        bar.classList.add("hidden");
      }
    }

    function highlightWatchingCard() {
      document.querySelectorAll(".card-watching").forEach(function(el) {
        el.classList.remove("card-watching");
      });
      if (currentWatchingMatch) {
        var key = getMatchUniqueKey(currentWatchingMatch);
        var cards = document.querySelectorAll("[data-match-key]");
        cards.forEach(function(card) {
          if (card.getAttribute("data-match-key") === key) {
            card.classList.add("card-watching");
          }
        });
      }
    }

    function parseMatchTimeToDate(m) {
      if (!m.match_time) return null;
      var now = new Date();
      var parts = m.match_time.match(/(\\d{1,2}):(\\d{2})\\s*(AM|PM)/i);
      if (!parts) return null;
      var h = parseInt(parts[1]);
      var min = parseInt(parts[2]);
      var ampm = parts[3].toUpperCase();
      if (ampm === "PM" && h !== 12) h += 12;
      if (ampm === "AM" && h === 12) h = 0;

      var d = new Date(now);
      if (m.match_day === "Tomorrow") {
        d.setDate(d.getDate() + 1);
      } else if (m.match_day === "Yesterday") {
        d.setDate(d.getDate() - 1);
      } else if (m.match_day && m.match_day !== "Today" && m.match_day.match(/^\\d{4}-\\d{2}-\\d{2}$/)) {
        d = new Date(m.match_day + "T00:00:00");
      }
      d.setHours(h, min, 0, 0);
      return d;
    }

    function formatCountdown(diffMs) {
      if (diffMs <= 0) return null;
      var totalSec = Math.floor(diffMs / 1000);
      var h = Math.floor(totalSec / 3600);
      var min = Math.floor((totalSec % 3600) / 60);
      var sec = totalSec % 60;
      if (h > 0) {
        return h + "h " + min + "m";
      }
      return min + "m " + (sec < 10 ? "0" : "") + sec + "s";
    }

    function startCountdowns() {
      if (countdownIntervalId) clearInterval(countdownIntervalId);
      countdownIntervalId = setInterval(function() {
        var now = new Date();
        document.querySelectorAll("[data-match-time-ms]").forEach(function(el) {
          var ms = parseInt(el.getAttribute("data-match-time-ms"));
          var diff = ms - now.getTime();
          if (diff > 0) {
            el.textContent = "Starts in " + formatCountdown(diff);
          } else {
            el.textContent = "Starting soon...";
          }
        });
      }, 1000);
    }

    function renderMatches() {
      var list = document.getElementById("match-list");
      var filtered = allData;

      if (currentFilter !== "all") {
        filtered = allData.filter(function(m) { return m.match_status === currentFilter; });
      }

      if (searchQuery) {
        filtered = filtered.filter(function(m) {
          var text = ((m.home_team_name || "") + " " + (m.away_team_name || "") + " " + (m.league_name || "")).toLowerCase();
          return text.indexOf(searchQuery) !== -1;
        });
      }

      if (filtered.length === 0) {
        var emptyMsg = searchQuery ? "No matches found for \\"" + escapeHtml(searchQuery) + "\\"" : "No matches found";
        list.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📭</div>' +
          '<div class="text-slate-500 text-sm font-medium">' + emptyMsg + '</div></div>';
        return;
      }

      list.innerHTML = "";

      var lastDay = null;

      filtered.forEach(function(m, idx) {
        var isLive = m.match_status === "live";
        var matchKey = getMatchUniqueKey(m);

        var matchDay = m.match_day || "Today";
        if (matchDay !== lastDay) {
          lastDay = matchDay;
          var sep = document.createElement("div");
          sep.className = "day-separator";
          sep.innerHTML = '<div class="day-separator-line"></div>' +
            '<span class="day-separator-label ' + getDaySeparatorClass(matchDay) + '">' + escapeHtml(matchDay) + '</span>' +
            '<div class="day-separator-line"></div>';
          list.appendChild(sep);
        }

        var card = document.createElement("div");
        card.className = isLive ? "card card-live p-5 match-transition" : "card p-5 match-transition";
        card.setAttribute("data-match-key", matchKey);
        card.style.animation = "fadeUp 0.4s ease-out " + (idx * 0.05) + "s both";

        if (currentWatchingMatch && getMatchUniqueKey(currentWatchingMatch) === matchKey) {
          card.classList.add("card-watching");
        }

        var headerRow = document.createElement("div");
        headerRow.className = "flex justify-between items-center mb-4";

        var leagueBadge = document.createElement("span");
        leagueBadge.className = "league-badge text-[10px] text-amber-700 truncate max-w-[60%]";
        leagueBadge.textContent = m.league_name || "Unknown";

        var statusBadge = document.createElement("span");
        if (isLive) {
          statusBadge.className = "status-live";
          statusBadge.innerHTML = '<span class="live-dot"></span>LIVE ' + escapeHtml(m.match_time || "");
        } else {
          statusBadge.className = "status-upcoming";
          var dayLabel = m.match_day && m.match_day !== "Today" ? m.match_day + " · " : "";
          statusBadge.textContent = dayLabel + (m.match_time || "");
        }

        headerRow.appendChild(leagueBadge);
        headerRow.appendChild(statusBadge);

        var teamsRow = document.createElement("div");
        teamsRow.className = "flex items-center justify-between";

        var homeDiv = document.createElement("div");
        homeDiv.className = "flex flex-col items-center w-[30%] gap-2";
        homeDiv.appendChild(createLogoElement(m.home_team_logo));
        var homeName = document.createElement("span");
        homeName.className = "text-[11px] font-semibold text-center leading-tight text-slate-600 line-clamp-2 w-full";
        homeName.textContent = m.home_team_name || "Home";
        homeDiv.appendChild(homeName);

        var scoreDiv = document.createElement("div");
        scoreDiv.className = "w-[30%] flex flex-col items-center justify-center";
        var scoreBox = document.createElement("div");
        scoreBox.className = "score-box text-center";
        if (m.match_score) {
          var scoreText = document.createElement("span");
          scoreText.className = "text-xl font-black tracking-wider score-text";
          scoreText.textContent = m.match_score;
          scoreBox.appendChild(scoreText);
        } else {
          var vsText = document.createElement("span");
          vsText.className = "text-sm font-bold text-slate-400";
          vsText.textContent = "VS";
          scoreBox.appendChild(vsText);
        }
        scoreDiv.appendChild(scoreBox);

        if (!isLive && m.match_status === "upcoming") {
          var matchDate = parseMatchTimeToDate(m);
          if (matchDate) {
            var countdownEl = document.createElement("div");
            countdownEl.className = "countdown-text mt-1";
            var diff = matchDate.getTime() - Date.now();
            if (diff > 0) {
              countdownEl.textContent = "Starts in " + formatCountdown(diff);
              countdownEl.setAttribute("data-match-time-ms", matchDate.getTime().toString());
            } else {
              countdownEl.textContent = "Starting soon...";
            }
            scoreDiv.appendChild(countdownEl);
          }
        }

        var awayDiv = document.createElement("div");
        awayDiv.className = "flex flex-col items-center w-[30%] gap-2";
        awayDiv.appendChild(createLogoElement(m.away_team_logo));
        var awayName = document.createElement("span");
        awayName.className = "text-[11px] font-semibold text-center leading-tight text-slate-600 line-clamp-2 w-full";
        awayName.textContent = m.away_team_name || "Away";
        awayDiv.appendChild(awayName);

        teamsRow.appendChild(homeDiv);
        teamsRow.appendChild(scoreDiv);
        teamsRow.appendChild(awayDiv);

        var btnsRow = document.createElement("div");
        btnsRow.className = "text-center mt-4 pt-3 border-t border-black/[0.04] flex gap-2.5 justify-center flex-wrap";

        if (m.servers && m.servers.length > 0) {
          m.servers.forEach(function(s) {
            var btn = document.createElement("button");
            var isHD = s.name && s.name.indexOf("HD") !== -1;
            btn.className = (isHD ? "btn-hd" : "btn-sd") + " text-white text-[11px] px-5 py-2 rounded-full font-bold transition-all";
            btn.textContent = isHD ? "▶ HD" : "▶ SD";
            btn.setAttribute("data-stream-url", s.stream_url);
            btn.addEventListener("click", function() {
              currentWatchingMatch = m;
              play(this.getAttribute("data-stream-url"));
              updateNowWatchingBar();
              highlightWatchingCard();
            });
            btnsRow.appendChild(btn);
          });
        } else {
          var infoSpan = document.createElement("span");
          infoSpan.className = "text-[11px] font-medium";
          if (isLive) {
            infoSpan.className += " text-amber-600";
            infoSpan.textContent = "Stream loading...";
          } else {
            infoSpan.className += " text-slate-400";
            infoSpan.textContent = "Not started yet";
          }
          btnsRow.appendChild(infoSpan);
        }

        card.appendChild(headerRow);
        card.appendChild(teamsRow);
        card.appendChild(btnsRow);
        list.appendChild(card);
      });
    }

    function showPlayerLoading(show) {
      var el = document.getElementById("player-loading");
      if (show) {
        el.classList.remove("hidden");
      } else {
        el.classList.add("hidden");
      }
    }

    function getStreamErrorHTML(message) {
      return '<div style="font-size:14px;font-weight:600;margin-bottom:6px;">' + escapeHtml(message) + '</div>' +
        '<div class="player-error-tips">' +
          '⚠ အကြောင်းအရင်းများ -<br>' +
          '① သတ်မှတ်ထားသော ထုတ်လွှင့်ချိန် မရောက်သေးတာ ဖြစ်နိုင်ပါသည်။<br>' +
          '② မူရင်း Stream Link ပျက်နေတာ ဖြစ်နိုင်ပါသည်။<br>' +
          '③ သင့်နိုင်ငံ/ဒေသမှ ပိတ်ထားတာ ဖြစ်နိုင်ပါသည်။<br><br>' +
          '💡 VPN ဖွင့်ပြီး ပြန်ကြိုးစားကြည့်ပါ။<br>' +
          '💡 အခြား Server (HD/SD) ပြောင်းကြည့်ပါ။' +
        '</div>';
    }

    function showPlayerError(message) {
      var existing = document.getElementById("player-error-overlay");
      if (existing) existing.remove();

      var overlay = document.createElement("div");
      overlay.id = "player-error-overlay";
      overlay.className = "player-error";
      overlay.innerHTML = getStreamErrorHTML(message);

      if (currentStreamUrl) {
        var retryBtn = document.createElement("button");
        retryBtn.className = "player-error-btn";
        retryBtn.textContent = "ပြန်ကြိုးစားမည်";
        retryBtn.addEventListener("click", function() {
          overlay.remove();
          play(currentStreamUrl);
        });
        overlay.appendChild(retryBtn);
      }

      document.getElementById("player-inner").appendChild(overlay);
    }

    function clearPlayerError() {
      var existing = document.getElementById("player-error-overlay");
      if (existing) existing.remove();
    }

    function play(streamUrl) {
      if (!streamUrl || typeof streamUrl !== "string") return;
      if (!/^https?:\\/\\//i.test(streamUrl)) return;

      currentStreamUrl = streamUrl;

      document.getElementById("player-container").classList.remove("hidden");
      clearPlayerError();
      showPlayerLoading(true);
      updateNowWatchingBar();

      var vid = document.getElementById("video");

      if (currentHls) {
        currentHls.destroy();
        currentHls = null;
      }

      vid.removeAttribute("src");
      vid.load();

      if (typeof Hls !== "undefined" && Hls.isSupported()) {
        var hls = new Hls({
          enableWorker: true,
          lowLatencyMode: true,
          maxBufferLength: 30,
          maxMaxBufferLength: 60,
        });
        currentHls = hls;
        hls.loadSource(streamUrl);
        hls.attachMedia(vid);

        hls.on(Hls.Events.MANIFEST_PARSED, function() {
          showPlayerLoading(false);
          vid.play().catch(function() {});
        });

        hls.on(Hls.Events.FRAG_LOADED, function() {
          showPlayerLoading(false);
        });

        hls.on(Hls.Events.ERROR, function(event, data) {
          if (data.fatal) {
            showPlayerLoading(false);
            if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
              console.warn("HLS network error, attempting recovery...");
              hls.startLoad();
              setTimeout(function() {
                if (vid.paused && vid.readyState < 3) {
                  showPlayerError("Stream ချိတ်ဆက်မှု မအောင်မြင်ပါ။");
                }
              }, 10000);
            } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
              console.warn("HLS media error, attempting recovery...");
              hls.recoverMediaError();
            } else {
              showPlayerError("Stream ကြည့်ရှု၍ မရနိုင်သေးပါ။");
              hls.destroy();
              currentHls = null;
            }
          }
        });
      } else if (vid.canPlayType("application/vnd.apple.mpegurl")) {
        vid.src = streamUrl;
        vid.addEventListener("loadeddata", function onLoaded() {
          showPlayerLoading(false);
          vid.removeEventListener("loadeddata", onLoaded);
        });
        vid.addEventListener("error", function onError() {
          showPlayerLoading(false);
          showPlayerError("Stream ကြည့်ရှု၍ မရနိုင်သေးပါ။");
          vid.removeEventListener("error", onError);
        });
        vid.play().catch(function() {});
      } else {
        showPlayerLoading(false);
        showPlayerError("သင့် Browser သည် HLS streaming ကို support မလုပ်ပါ။");
      }

      window.scrollTo({ top: 0, behavior: "smooth" });
    }

    function closePlayer() {
      var vid = document.getElementById("video");
      vid.pause();
      vid.removeAttribute("src");
      vid.load();
      if (currentHls) {
        currentHls.destroy();
        currentHls = null;
      }
      currentStreamUrl = null;
      currentWatchingMatch = null;
      clearPlayerError();
      showPlayerLoading(false);
      document.getElementById("player-container").classList.add("hidden");
      updateNowWatchingBar();
      highlightWatchingCard();
    }

    // Initial load
    load();

    // Background refresh every 60 seconds
    setInterval(function() {
      load();
    }, 60000);
  <\/script>
</body>
</html>`;
}

// ====== BACKEND LOGIC ======

async function fetchServerURL(roomNum: any) {
  try {
    const roomStr = String(roomNum);
    if (!/^[a-zA-Z0-9_-]+$/.test(roomStr))
      return { m3u8: null, hdM3u8: null };

    // Check cache
    const cacheKey = `room_${roomStr}`;
    const cached = getCachedResponse(cacheKey);
    if (cached) return cached;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const res = await fetch(`${ROOM_API_BASE}/room/${roomStr}/detail.json`, {
      headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const txt = await res.text();
    const m = txt.match(/detail\((.*)\)/);
    if (m) {
      const js = JSON.parse(m[1]);
      if (js.code === 200 && js.data && js.data.stream) {
        const result = {
          m3u8: sanitizeUrl(js.data.stream.m3u8),
          hdM3u8: sanitizeUrl(js.data.stream.hdM3u8),
        };
        // Cache room data for 60 seconds
        setCachedResponse(cacheKey, result, 60_000);
        return result;
      }
    }
  } catch (_e) {
    /* ignore */
  }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string) {
  if (!/^\d{8}$/.test(date)) return [];

  // Check cache for this specific date's matches
  const dateCacheKey = `matches_date_${date}`;
  const cached = getCachedResponse(dateCacheKey);
  if (cached) return cached;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

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

    const roomFetchPromises: {
      index: number;
      promise: Promise<{ m3u8: string | null; hdM3u8: string | null }>;
    }[] = [];

    const prelimResults: any[] = [];

    for (const it of js.data) {
      const mt = it.matchTime;

      if (!mt || typeof mt !== "number") continue;

      let status: string;
      if (now >= mt && now <= mt + 3 * 60 * 60 * 1000) status = "live";
      else if (now > mt + 3 * 60 * 60 * 1000) status = "finished";
      else status = "upcoming";

      const homeLogo = sanitizeUrl(
        it.homeLogo || it.hostLogo || it.homeIcon || it.hostIcon
      );
      const awayLogo = sanitizeUrl(
        it.awayLogo || it.guestLogo || it.awayIcon || it.guestIcon
      );

      const homeTeamName = sanitizeText(
        it.homeName || it.hostName || "Home",
        50
      );
      const awayTeamName = sanitizeText(
        it.awayName || it.guestName || "Away",
        50
      );
      const leagueName = sanitizeText(
        it.leagueName || it.subCateName || "Unknown League",
        80
      );

      let matchScore: string | null = null;
      if (it.homeScore !== undefined && it.homeScore !== null) {
        const hs = String(it.homeScore).replace(/[^0-9]/g, "").slice(0, 3);
        const as = String(it.awayScore).replace(/[^0-9]/g, "").slice(0, 3);
        matchScore = `${hs} - ${as}`;
      }

      const matchDateStr = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Yangon",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(new Date(mt));

      const todayDateStr = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Yangon",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(new Date());

      const tomorrowD = new Date();
      tomorrowD.setDate(tomorrowD.getDate() + 1);
      const tomorrowDateStr = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Yangon",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(tomorrowD);

      const yesterdayD = new Date();
      yesterdayD.setDate(yesterdayD.getDate() - 1);
      const yesterdayDateStr = new Intl.DateTimeFormat("en-CA", {
        timeZone: "Asia/Yangon",
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(yesterdayD);

      let matchDay: string;
      if (matchDateStr === todayDateStr) {
        matchDay = "Today";
      } else if (matchDateStr === tomorrowDateStr) {
        matchDay = "Tomorrow";
      } else if (matchDateStr === yesterdayDateStr) {
        matchDay = "Yesterday";
      } else {
        matchDay = matchDateStr;
      }

      const entryIndex = prelimResults.length;
      prelimResults.push({
        match_time: new Date(mt).toLocaleTimeString("en-US", {
          timeZone: "Asia/Yangon",
          hour: "2-digit",
          minute: "2-digit",
          hour12: true,
        }),
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
        const anchorSlice = it.anchors.slice(0, 3);
        for (const a of anchorSlice) {
          const room = a.anchor?.roomNum;
          if (!room) continue;
          roomFetchPromises.push({
            index: entryIndex,
            promise: fetchServerURL(room),
          });
        }
      }
    }

    // Await all room fetches in parallel
    const roomResults = await Promise.allSettled(
      roomFetchPromises.map((r) => r.promise)
    );

    for (let i = 0; i < roomFetchPromises.length; i++) {
      const result = roomResults[i];
      if (result.status === "fulfilled") {
        const { m3u8, hdM3u8 } = result.value;
        const idx = roomFetchPromises[i].index;
        if (m3u8)
          prelimResults[idx].servers.push({
            name: "Soco SD",
            stream_url: m3u8,
          });
        if (hdM3u8)
          prelimResults[idx].servers.push({
            name: "Soco HD",
            stream_url: hdM3u8,
          });
      }
    }

    // Cache this date's processed results for 30 seconds
    setCachedResponse(dateCacheKey, prelimResults, 30_000);

    return prelimResults;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
