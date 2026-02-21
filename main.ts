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

// ====== SECURITY: Rate Limiter ======
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60_000;
const RATE_LIMIT_MAX = 60;
const BLOCK_THRESHOLD = 200;
const blockedIPs = new Map<string, number>();

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
    blockedIPs.set(ip, now + 10 * 60_000);
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

  if (!ua || ua.length < 10) return true;

  const botPatterns = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i,
    /gobuster/i, /wfuzz/i, /hydra/i, /burpsuite/i, /nessus/i,
    /openvas/i, /acunetix/i, /zgrab/i, /nuclei/i, /scrapy/i,
  ];
  if (botPatterns.some((p) => p.test(ua))) return true;

  const path = url.pathname;
  if (path.includes("..") || path.includes("//") || path.includes("\\"))
    return true;

  const maliciousPaths = [
    /\.env/i, /\.git/i, /wp-admin/i, /wp-login/i, /phpmyadmin/i,
    /\/admin\b/i, /\.php$/i, /\.asp$/i, /shell/i, /eval\(/i,
    /exec\(/i, /\.sql$/i, /backup/i, /\.bak$/i, /\.log$/i,
  ];
  if (maliciousPaths.some((p) => p.test(path))) return true;

  const query = url.search;
  const sqlPatterns = [
    /union.*select/i, /or\s+1\s*=\s*1/i, /drop\s+table/i,
    /insert\s+into/i, /delete\s+from/i, /script>/i, /<iframe/i,
    /javascript:/i, /onerror\s*=/i, /onload\s*=/i,
  ];
  if (sqlPatterns.some((p) => p.test(query))) return true;

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
      "img-src 'self' https: data:; " +
      "media-src 'self' blob: https:; " +
      "connect-src 'self' https:;",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
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
    .trim()
    .slice(0, maxLen);
}

// ====== Logo Proxy Cache (in-memory, binary data) ======
const logoProxyCache = new Map<
  string,
  { data: Uint8Array; contentType: string; expires: number }
>();
const LOGO_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const LOGO_CACHE_MAX_SIZE = 500; // max cached logos

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

    const contentType =
      res.headers.get("content-type") || "image/png";
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

serve(async (req) => {
  const url = new URL(req.url);
  const clientIP = getClientIP(req);

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

  if (isSuspiciousRequest(req)) {
    return new Response("Not Found", {
      status: 404,
      headers: securityHeaders(),
    });
  }

  if (req.method !== "GET") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET", ...securityHeaders() },
    });
  }

  // --- 1. API ROUTE: Matches ---
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
        if (a.match_status === "upcoming" && b.match_status === "finished")
          return -1;
        if (a.match_status === "finished" && b.match_status === "upcoming")
          return 1;
        return 0;
      });

      return new Response(JSON.stringify(allMatches), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=30",
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
        "Access-Control-Allow-Origin": "*",
        ...securityHeaders(),
      },
    });
  }

  // --- 3. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    return new Response(getHTML(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        ...securityHeaders(),
      },
    });
  }

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

    body {
      background: #f1f5f9;
      color: #1e293b;
      font-family: 'Inter', 'Padauk', sans-serif;
      margin: 0;
      min-height: 100vh;
      overflow-x: hidden;
    }

    .app-container {
      position: relative;
      z-index: 1;
    }

    .premium-header {
      background: linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(241,245,249,0.98) 100%);
      border-bottom: 1px solid rgba(0,0,0,0.06);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      position: sticky;
      top: 0;
      z-index: 40;
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
      background: linear-gradient(135deg, rgba(217,119,6,0.1), rgba(180,83,9,0.05));
      border: 1px solid rgba(217,119,6,0.2);
      text-decoration: none;
      transition: all 0.3s;
    }
    .dev-contact-link:hover {
      background: linear-gradient(135deg, rgba(217,119,6,0.18), rgba(180,83,9,0.1));
      border-color: rgba(217,119,6,0.35);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(217,119,6,0.15);
    }
    .dev-avatar {
      width: 28px;
      height: 28px;
      border-radius: 50%;
      object-fit: cover;
      border: 2px solid rgba(217,119,6,0.3);
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
      box-shadow: 0 0 8px rgba(239,68,68,0.6), 0 0 20px rgba(239,68,68,0.3);
    }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.7); }
    }

    .card {
      background: rgba(255,255,255,0.85);
      border: 1px solid rgba(0,0,0,0.06);
      border-radius: 20px;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .card:hover {
      border-color: rgba(0,0,0,0.1);
      transform: translateY(-2px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.08);
    }
    .card-live {
      border-color: rgba(239,68,68,0.2);
      box-shadow: 0 0 20px rgba(239,68,68,0.05);
    }
    .card-live:hover {
      border-color: rgba(239,68,68,0.35);
      box-shadow: 0 0 30px rgba(239,68,68,0.08);
    }

    /* Active card highlight when watching */
    .card-watching {
      border-color: rgba(217,119,6,0.5) !important;
      box-shadow: 0 0 0 2px rgba(217,119,6,0.15), 0 8px 32px rgba(217,119,6,0.12) !important;
    }

    .team-logo {
      width: 48px; height: 48px;
      border-radius: 50%;
      object-fit: contain;
      background: rgba(0,0,0,0.02);
      padding: 5px;
      border: 2px solid rgba(0,0,0,0.06);
      transition: all 0.3s;
    }
    .card:hover .team-logo {
      border-color: rgba(217,119,6,0.2);
    }
    .team-logo-fallback {
      width: 48px; height: 48px;
      border-radius: 50%;
      background: linear-gradient(135deg, #e2e8f0, #f1f5f9);
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
      border: 2px solid rgba(0,0,0,0.06);
    }

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
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
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
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s;
    }
    .btn-sd:hover::before { left: 100%; }
    .btn-sd:hover { box-shadow: 0 6px 25px rgba(99,102,241,0.4); transform: translateY(-1px); }
    .btn-sd:active { transform: translateY(0); }

    .score-box {
      background: rgba(15,23,42,0.9);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 14px;
      padding: 6px 16px;
      min-width: 80px;
    }

    .league-badge {
      background: linear-gradient(135deg, rgba(217,119,6,0.08), rgba(180,83,9,0.05));
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
      box-shadow: 0 4px 20px rgba(217,119,6,0.3);
    }
    .tab-btn:not(.active) {
      background: rgba(255,255,255,0.7);
      color: #64748b;
      border-color: rgba(0,0,0,0.08);
    }
    .tab-btn:not(.active):hover {
      background: rgba(255,255,255,0.9);
      color: #334155;
      border-color: rgba(0,0,0,0.12);
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
      border: 2px solid rgba(217,119,6,0.2);
      box-shadow: 0 20px 60px rgba(0,0,0,0.15);
    }

    /* Now-watching banner inside player */
    .now-watching-bar {
      background: linear-gradient(135deg, #0f172a, #1e293b);
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
      border: 1px solid rgba(239,68,68,0.2);
      color: #dc2626;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 700;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .status-ft {
      background: rgba(100,116,139,0.08);
      border: 1px solid rgba(100,116,139,0.15);
      color: #64748b;
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 10px;
      font-weight: 600;
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
      background: rgba(0,0,0,0.6);
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
      background: rgba(0,0,0,0.08);
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
      color: #6366f1;
      border: 1px solid rgba(99,102,241,0.2);
    }
    .day-tomorrow {
      background: rgba(16,185,129,0.1);
      color: #059669;
      border: 1px solid rgba(16,185,129,0.2);
    }
    .day-yesterday {
      background: rgba(100,116,139,0.08);
      color: #64748b;
      border: 1px solid rgba(100,116,139,0.15);
    }
    .day-other {
      background: rgba(0,0,0,0.04);
      color: #64748b;
      border: 1px solid rgba(0,0,0,0.08);
    }
  </style>
</head>
<body>
  <div class="app-container">

    <!-- Premium Header -->
    <div class="premium-header">
      <div class="max-w-md mx-auto px-5 py-4">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="header-title text-xl">All Sports Live</h1>
            <p class="header-subtitle mt-0.5">Premium Sports Streaming</p>
          </div>
          <a href="${safeDevUrl}" target="_blank" rel="noopener noreferrer" title="Contact ${safeDevName}" class="dev-contact-link">
            <img src="${safeDevImg}" alt="${safeDevName}" class="dev-avatar" onerror="this.style.display='none'">
            <span class="dev-name">${safeDevName}</span>
          </a>
        </div>
      </div>
    </div>

    <div class="max-w-md mx-auto px-4 pt-5 pb-4">

      <!-- Filter Tabs -->
      <div class="flex gap-2 mb-4 overflow-x-auto pb-1 fade-up fade-up-delay-1" id="tabs">
        <button class="tab-btn active" data-filter="all">All Matches</button>
        <button class="tab-btn" data-filter="live">Live</button>
        <button class="tab-btn" data-filter="upcoming">Upcoming</button>
        <button class="tab-btn" data-filter="finished">Finished</button>
      </div>

      <!-- Stats Bar -->
      <div class="flex gap-2 justify-center mb-5 fade-up fade-up-delay-2" id="stats-bar">
        <span class="stat-pill text-slate-500">
          <span class="stat-indicator" style="background:#64748b;"></span>
          <span id="stat-total">Total: —</span>
        </span>
        <span class="stat-pill text-red-500">
          <span class="stat-indicator" style="background:#ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5);"></span>
          <span id="stat-live">Live: —</span>
        </span>
        <span class="stat-pill text-indigo-500">
          <span class="stat-indicator" style="background:#6366f1;"></span>
          <span id="stat-upcoming">Soon: —</span>
        </span>
      </div>

      <!-- Video Player -->
      <div id="player-container" class="hidden sticky top-[68px] z-50 mb-5 player-wrapper">
        <!-- Now Watching Banner -->
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

      <!-- Loading -->
      <div id="loading" class="flex flex-col items-center py-20 fade-up fade-up-delay-3">
        <div class="loading-spinner mb-4"></div>
        <span class="text-slate-400 text-sm font-medium">Loading matches...</span>
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
    var currentHls = null;
    var currentStreamUrl = null;
    var currentWatchingMatch = null; // Track which match user is watching

    // ====== Logo cache to speed up repeated renders ======
    var logoCache = {};

    function escapeHtml(str) {
      if (typeof str !== "string") return "";
      var div = document.createElement("div");
      div.textContent = str;
      return div.innerHTML;
    }

    // ====== Convert original logo URL to proxied URL ======
    function proxiedLogoUrl(originalUrl) {
      if (!originalUrl) return null;
      return "/api/logo-proxy?url=" + encodeURIComponent(originalUrl);
    }

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

    async function load() {
      try {
        var res = await fetch("/api/matches");
        if (!res.ok) throw new Error("Server error");
        var data = await res.json();
        if (data.error) throw new Error(data.error);
        allData = data;
        document.getElementById("loading").style.display = "none";
        // Preload logo images into cache (via proxy)
        preloadLogos(data);
        updateStats();
        renderMatches();
      } catch (e) {
        document.getElementById("loading").innerHTML =
          '<div class="empty-state"><div class="empty-state-icon">⚠️</div>' +
          '<div class="text-red-500 text-sm font-medium">' + escapeHtml(e.message) + '</div>' +
          '<div class="text-slate-400 text-xs mt-2">Pull to refresh or try again later</div></div>';
      }
    }

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
      // If cached as failed, show fallback immediately
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
      // Remove previous highlights
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

    function renderMatches() {
      var list = document.getElementById("match-list");
      var filtered = allData;
      if (currentFilter !== "all") {
        filtered = allData.filter(function(m) { return m.match_status === currentFilter; });
      }

      if (filtered.length === 0) {
        list.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📭</div>' +
          '<div class="text-slate-400 text-sm font-medium">No matches found</div></div>';
        return;
      }

      list.innerHTML = "";

      var lastDay = null;

      filtered.forEach(function(m, idx) {
        var isLive = m.match_status === "live";
        var isFinished = m.match_status === "finished";
        var matchKey = getMatchUniqueKey(m);

        // Day separator
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
        card.className = isLive ? "card card-live p-5" : "card p-5";
        card.setAttribute("data-match-key", matchKey);
        card.style.animation = "fadeUp 0.4s ease-out " + (idx * 0.05) + "s both";

        // Highlight if currently watching this match
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
        } else if (isFinished) {
          statusBadge.className = "status-ft";
          var ftDayLabel = m.match_day && m.match_day !== "Today" ? m.match_day + " · " : "";
          statusBadge.textContent = ftDayLabel + "FT";
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
        homeName.className = "text-[11px] font-semibold text-center leading-tight text-slate-700 line-clamp-2 w-full";
        homeName.textContent = m.home_team_name || "Home";
        homeDiv.appendChild(homeName);

        var scoreDiv = document.createElement("div");
        scoreDiv.className = "w-[30%] flex justify-center";
        var scoreBox = document.createElement("div");
        scoreBox.className = "score-box text-center";
        if (m.match_score) {
          var scoreText = document.createElement("span");
          scoreText.className = "text-xl font-black tracking-wider";
          scoreText.style.cssText = "color:#facc15; text-shadow: 0 0 20px rgba(250,204,21,0.3);";
          scoreText.textContent = m.match_score;
          scoreBox.appendChild(scoreText);
        } else {
          var vsText = document.createElement("span");
          vsText.className = "text-sm font-bold text-slate-400";
          vsText.textContent = "VS";
          scoreBox.appendChild(vsText);
        }
        scoreDiv.appendChild(scoreBox);

        var awayDiv = document.createElement("div");
        awayDiv.className = "flex flex-col items-center w-[30%] gap-2";
        awayDiv.appendChild(createLogoElement(m.away_team_logo));
        var awayName = document.createElement("span");
        awayName.className = "text-[11px] font-semibold text-center leading-tight text-slate-700 line-clamp-2 w-full";
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
              // Set the match info for now-watching
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
            infoSpan.className += " text-amber-500";
            infoSpan.textContent = "Stream loading...";
          } else if (isFinished) {
            infoSpan.className += " text-slate-400";
            infoSpan.textContent = "Match ended";
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
        const m3u8 = sanitizeUrl(js.data.stream.m3u8);
        const hdM3u8 = sanitizeUrl(js.data.stream.hdM3u8);
        return { m3u8, hdM3u8 };
      }
    }
  } catch (_e) {
    /* ignore */
  }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string) {
  if (!/^\d{8}$/.test(date)) return [];

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
    const results = [];

    // Collect all live match anchor room fetches in parallel
    const roomFetchPromises: { index: number; promise: Promise<{ m3u8: string | null; hdM3u8: string | null }> }[] = [];

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

      // ---- Compute match_day label ----
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

      // Queue room fetches in parallel for live matches
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

    // Await all room fetches in parallel (big speed improvement)
    const roomResults = await Promise.allSettled(
      roomFetchPromises.map((r) => r.promise)
    );

    for (let i = 0; i < roomFetchPromises.length; i++) {
      const result = roomResults[i];
      if (result.status === "fulfilled") {
        const { m3u8, hdM3u8 } = result.value;
        const idx = roomFetchPromises[i].index;
        if (m3u8) prelimResults[idx].servers.push({ name: "Soco SD", stream_url: m3u8 });
        if (hdM3u8) prelimResults[idx].servers.push({ name: "Soco HD", stream_url: hdM3u8 });
      }
    }

    return prelimResults;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
