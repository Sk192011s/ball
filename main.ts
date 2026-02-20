import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// ====== Environment Variables ======
const MATCH_API_BASE = Deno.env.get("MATCH_API_BASE") || "";
const ROOM_API_BASE = Deno.env.get("ROOM_API_BASE") || "";
const API_REFERER = Deno.env.get("API_REFERER") || "";
const API_USER_AGENT =
  Deno.env.get("API_USER_AGENT") ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// ====== Developer Contact Info ======
const DEV_CONTACT_URL = Deno.env.get("DEV_CONTACT_URL") || "https://t.me/yourusername";
const DEV_PROFILE_IMG = Deno.env.get("DEV_PROFILE_IMG") || "https://ui-avatars.com/api/?name=Dev&background=d97706&color=fff&size=128";
const DEV_DISPLAY_NAME = Deno.env.get("DEV_DISPLAY_NAME") || "Developer";

// ====== SECURITY: Allowed stream domains (whitelist) ======
const ALLOWED_STREAM_DOMAINS: string[] = (() => {
  const envDomains = Deno.env.get("ALLOWED_STREAM_DOMAINS");
  if (envDomains) {
    return envDomains.split(",").map(d => d.trim().toLowerCase()).filter(Boolean);
  }
  return [];
})();

// ====== SECURITY: Rate Limiter ======
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 60_000;
const RATE_LIMIT_MAX = 60;
const BLOCK_THRESHOLD = 200;
const RATE_LIMIT_MAP_MAX_SIZE = 50_000; // Prevent memory exhaustion
const blockedIPs = new Map<string, number>();

function getClientIP(req: Request): string {
  // In production behind a trusted reverse proxy (e.g., Deno Deploy, Cloudflare),
  // cf-connecting-ip is set by Cloudflare and is trustworthy.
  // x-forwarded-for can be spoofed if not behind trusted proxy.
  // Prioritize cf-connecting-ip > x-real-ip > x-forwarded-for last entry
  const cfIP = req.headers.get("cf-connecting-ip");
  if (cfIP) return cfIP.trim();

  const realIP = req.headers.get("x-real-ip");
  if (realIP) return realIP.trim();

  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    // Use the LAST entry (closest to reverse proxy) to reduce spoofing risk
    // when behind a single trusted proxy. If behind multiple, adjust accordingly.
    const parts = xff.split(",").map(s => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }

  return "unknown";
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
    // Prevent memory exhaustion: if map is too large, clear old entries
    if (rateLimitMap.size >= RATE_LIMIT_MAP_MAX_SIZE) {
      const cutoff = now - RATE_LIMIT_WINDOW;
      for (const [key, val] of rateLimitMap) {
        if (val.resetTime < cutoff) rateLimitMap.delete(key);
      }
      // If still too large after cleanup, reject (defensive)
      if (rateLimitMap.size >= RATE_LIMIT_MAP_MAX_SIZE) {
        return { limited: true, blocked: false };
      }
    }
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
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i,
    /dirbuster/i, /gobuster/i, /wfuzz/i, /hydra/i,
    /burpsuite/i, /nessus/i, /openvas/i, /acunetix/i,
    /zgrab/i, /nuclei/i, /httpx/i, /crawl.*bot/i,
    /python-requests/i, /go-http-client/i, /curl\//i,
    /wget\//i, /scrapy/i, /phantomjs/i, /headless/i,
  ];
  if (botPatterns.some((p) => p.test(ua))) return true;

  const path = url.pathname;
  if (path.includes("..") || path.includes("//") || path.includes("\\"))
    return true;

  const maliciousPaths = [
    /\.env/i, /\.git/i, /wp-admin/i, /wp-login/i,
    /phpmyadmin/i, /admin/i, /\.php/i, /\.asp/i,
    /shell/i, /eval/i, /exec/i, /config/i,
    /\.sql/i, /backup/i, /\.bak/i, /\.log/i,
  ];
  if (maliciousPaths.some((p) => p.test(path))) return true;

  const query = url.search;
  const sqlPatterns = [
    /union.*select/i, /or\s+1\s*=\s*1/i, /drop\s+table/i,
    /insert\s+into/i, /delete\s+from/i, /script>/i,
    /<iframe/i, /javascript:/i, /onerror/i, /onload/i,
  ];
  if (sqlPatterns.some((p) => p.test(query))) return true;

  return false;
}

// ====== SECURITY: SSRF Prevention - Block internal/private IPs ======
function isInternalUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname.toLowerCase();

    // Block localhost variants
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "[::1]" ||
      hostname === "::1" ||
      hostname === "0.0.0.0"
    ) {
      return true;
    }

    // Block private IP ranges
    const privatePatterns = [
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,        // 10.0.0.0/8
      /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/, // 172.16.0.0/12
      /^192\.168\.\d{1,3}\.\d{1,3}$/,              // 192.168.0.0/16
      /^169\.254\.\d{1,3}\.\d{1,3}$/,              // Link-local
      /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/, // CGN 100.64.0.0/10
      /^0\.0\.0\.0$/,
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,         // 127.0.0.0/8
    ];
    if (privatePatterns.some(p => p.test(hostname))) return true;

    // Block .local, .internal, .corp, etc.
    if (
      hostname.endsWith(".local") ||
      hostname.endsWith(".internal") ||
      hostname.endsWith(".corp") ||
      hostname.endsWith(".lan") ||
      hostname.endsWith(".home")
    ) {
      return true;
    }

    // Block metadata endpoints (AWS, GCP, Azure)
    if (
      hostname === "169.254.169.254" ||
      hostname === "metadata.google.internal" ||
      hostname === "metadata.google.com"
    ) {
      return true;
    }

    // Block non-http(s) schemes
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return true;
    }

    return false;
  } catch {
    return true; // If URL parsing fails, treat as internal/unsafe
  }
}

// ====== SECURITY: Check if stream URL domain is allowed ======
function isAllowedStreamDomain(urlStr: string): boolean {
  // If no whitelist configured, allow all non-internal URLs (backward compat)
  if (ALLOWED_STREAM_DOMAINS.length === 0) return true;

  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname.toLowerCase();
    return ALLOWED_STREAM_DOMAINS.some(domain => {
      return hostname === domain || hostname.endsWith("." + domain);
    });
  } catch {
    return false;
  }
}

// ====== SECURITY: Response Headers ======
function securityHeaders(nonce?: string): Record<string, string> {
  const cspNonce = nonce || "";
  const scriptSrc = cspNonce
    ? `'nonce-${cspNonce}' https://cdn.tailwindcss.com https://cdn.jsdelivr.net`
    : "'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net";
  const styleSrc = cspNonce
    ? `'self' 'nonce-${cspNonce}' https://fonts.googleapis.com`
    : "'self' 'unsafe-inline' https://fonts.googleapis.com";

  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy":
      "default-src 'self'; " +
      `script-src ${scriptSrc}; ` +
      `style-src ${styleSrc}; ` +
      "font-src https://fonts.gstatic.com; " +
      "img-src 'self' https: data:; " +
      "media-src 'self' https: blob:; " +
      "connect-src 'self' https: blob:; " +
      "frame-ancestors 'none'; " +
      "base-uri 'self'; " +
      "form-action 'self';",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  };
}

// ====== SECURITY: Generate CSP Nonce ======
function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array)).replace(/[+/=]/g, "");
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
function sanitizeText(text: string | null | undefined, maxLen: number): string {
  if (!text || typeof text !== "string") return "";
  return text
    .replace(/<[^>]*>/g, "")
    .replace(/[\x00-\x1f\x7f]/g, "")
    .trim()
    .slice(0, maxLen);
}

// ====== Stream Proxy Route ======
async function handleStreamProxy(req: Request, url: URL): Promise<Response> {
  const streamUrl = url.searchParams.get("url");
  if (!streamUrl) {
    return new Response("Missing url parameter", { status: 400, headers: securityHeaders() });
  }

  if (!/^https?:\/\//i.test(streamUrl)) {
    return new Response("Invalid URL", { status: 400, headers: securityHeaders() });
  }

  // SSRF prevention: block internal/private URLs
  if (isInternalUrl(streamUrl)) {
    return new Response("Forbidden", { status: 403, headers: securityHeaders() });
  }

  // Domain whitelist check
  if (!isAllowedStreamDomain(streamUrl)) {
    return new Response("Forbidden: domain not allowed", { status: 403, headers: securityHeaders() });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const proxyRes = await fetch(streamUrl, {
      headers: {
        "User-Agent": API_USER_AGENT,
        Referer: API_REFERER,
      },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timeout);

    if (!proxyRes.ok) {
      return new Response("Stream unavailable", { status: 502, headers: securityHeaders() });
    }

    // Validate response size (prevent proxying huge files)
    const contentLength = proxyRes.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 50 * 1024 * 1024) {
      return new Response("Response too large", { status: 502, headers: securityHeaders() });
    }

    const contentType = proxyRes.headers.get("content-type") || "";
    const body = proxyRes.body;

    if (streamUrl.endsWith(".m3u8") || contentType.includes("mpegurl") || contentType.includes("m3u8")) {
      const text = await proxyRes.text();

      // Validate m3u8 content size
      if (text.length > 1024 * 1024) {
        return new Response("Playlist too large", { status: 502, headers: securityHeaders() });
      }

      const baseUrl = streamUrl.substring(0, streamUrl.lastIndexOf("/") + 1);

      const rewritten = text.split("\n").map((line: string) => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          let absoluteUrl: string;
          if (/^https?:\/\//i.test(trimmed)) {
            absoluteUrl = trimmed;
          } else {
            absoluteUrl = baseUrl + trimmed;
          }
          // Validate the resolved URL too
          if (isInternalUrl(absoluteUrl)) return "";
          return "/api/stream-proxy?url=" + encodeURIComponent(absoluteUrl);
        }
        return line;
      }).join("\n");

      return new Response(rewritten, {
        status: 200,
        headers: {
          "Content-Type": "application/vnd.apple.mpegurl",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-cache",
          ...securityHeaders(),
        },
      });
    }

    // For non-m3u8: only allow expected content types for stream segments
    const allowedTypes = [
      "video/mp2t", "video/", "application/octet-stream",
      "audio/", "application/vnd.apple.mpegurl", "binary/octet-stream",
    ];
    const isAllowedType = !contentType || allowedTypes.some(t => contentType.includes(t));
    if (!isAllowedType) {
      return new Response("Invalid content type", { status: 403, headers: securityHeaders() });
    }

    const resHeaders: Record<string, string> = {
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, max-age=10",
      ...securityHeaders(),
    };
    if (contentType) {
      resHeaders["Content-Type"] = contentType;
    } else if (streamUrl.endsWith(".ts")) {
      resHeaders["Content-Type"] = "video/mp2t";
    }

    return new Response(body, {
      status: 200,
      headers: resHeaders,
    });
  } catch (e: any) {
    console.warn("Stream proxy error:", e.message);
    return new Response("Stream error", { status: 502, headers: securityHeaders() });
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
    return new Response("Not Found", { status: 404, headers: securityHeaders() });
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

  // --- 2. API ROUTE: Stream Proxy ---
  if (url.pathname === "/api/stream-proxy") {
    return await handleStreamProxy(req, url);
  }

  // --- 3. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    const nonce = generateNonce();
    return new Response(getHTML(nonce), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        ...securityHeaders(nonce),
      },
    });
  }

  return new Response("Not Found", { status: 404, headers: securityHeaders() });
});

// ====== FRONTEND HTML ======
function getHTML(nonce: string): string {
  const safeDevUrl = sanitizeUrl(DEV_CONTACT_URL) || "#";
  const safeDevImg = sanitizeUrl(DEV_PROFILE_IMG) || "";
  const safeDevName = sanitizeText(DEV_DISPLAY_NAME, 50) || "Developer";

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>All Sports Live</title>
  <script nonce="${nonce}" src="https://cdn.tailwindcss.com"><\/script>
  <script nonce="${nonce}" src="https://cdn.jsdelivr.net/npm/hls.js@latest"><\/script>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style nonce="${nonce}">
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
      background: rgba(0,0,0,0.85);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-size: 14px;
      z-index: 10;
    }
    .player-error-btn {
      margin-top: 12px;
      background: #d97706;
      color: #fff;
      border: none;
      padding: 8px 24px;
      border-radius: 20px;
      font-weight: 700;
      cursor: pointer;
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

  <script nonce="${nonce}">
    "use strict";
    var allData = [];
    var currentFilter = "all";
    var currentHls = null;
    var currentStreamUrl = null;

    function escapeHtml(str) {
      if (typeof str !== "string") return "";
      var div = document.createElement("div");
      div.textContent = str;
      return div.innerHTML;
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
        updateStats();
        renderMatches();
      } catch (e) {
        document.getElementById("loading").innerHTML =
          '<div class="empty-state"><div class="empty-state-icon">⚠️</div>' +
          '<div class="text-red-500 text-sm font-medium">' + escapeHtml(e.message) + '</div>' +
          '<div class="text-slate-400 text-xs mt-2">Pull to refresh or try again later</div></div>';
      }
    }

    function updateStats() {
      var live = allData.filter(function(m) { return m.match_status === "live"; }).length;
      var upcoming = allData.filter(function(m) { return m.match_status === "upcoming"; }).length;
      document.getElementById("stat-total").textContent = "Total: " + allData.length;
      document.getElementById("stat-live").textContent = "Live: " + live;
      document.getElementById("stat-upcoming").textContent = "Soon: " + upcoming;
    }

    function createLogoElement(url) {
      if (url) {
        var img = document.createElement("img");
        img.className = "team-logo";
        img.loading = "lazy";
        img.alt = "";
        img.src = url;
        img.onerror = function() {
          var fallback = document.createElement("div");
          fallback.className = "team-logo-fallback";
          fallback.textContent = "⚽";
          img.replaceWith(fallback);
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
        card.style.animation = "fadeUp 0.4s ease-out " + (idx * 0.05) + "s both";

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
              play(this.getAttribute("data-stream-url"));
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

    function showPlayerError(message) {
      var existing = document.getElementById("player-error-overlay");
      if (existing) existing.remove();

      var overlay = document.createElement("div");
      overlay.id = "player-error-overlay";
      overlay.className = "player-error";

      var msgDiv = document.createElement("div");
      msgDiv.textContent = message;
      overlay.appendChild(msgDiv);

      if (currentStreamUrl) {
        var retryBtn = document.createElement("button");
        retryBtn.className = "player-error-btn";
        retryBtn.textContent = "Retry";
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

    function play(originalUrl) {
      if (!originalUrl || typeof originalUrl !== "string") return;
      if (!/^https?:\\/\\//i.test(originalUrl)) return;

      currentStreamUrl = originalUrl;

      var proxyUrl = "/api/stream-proxy?url=" + encodeURIComponent(originalUrl);

      document.getElementById("player-container").classList.remove("hidden");
      clearPlayerError();
      showPlayerLoading(true);

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
          xhrSetup: function(xhr, url) {
            if (url.indexOf("/api/stream-proxy") === -1 && /^https?:\\/\\//i.test(url)) {
              xhr.open("GET", "/api/stream-proxy?url=" + encodeURIComponent(url), true);
            }
          }
        });
        currentHls = hls;
        hls.loadSource(proxyUrl);
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
                  showPlayerError("Stream connection failed. Please try another server.");
                }
              }, 10000);
            } else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
              console.warn("HLS media error, attempting recovery...");
              hls.recoverMediaError();
            } else {
              showPlayerError("Stream unavailable. Please try another server.");
              hls.destroy();
              currentHls = null;
            }
          }
        });
      } else if (vid.canPlayType("application/vnd.apple.mpegurl")) {
        vid.src = proxyUrl;
        vid.addEventListener("loadeddata", function onLoaded() {
          showPlayerLoading(false);
          vid.removeEventListener("loadeddata", onLoaded);
        });
        vid.addEventListener("error", function onError() {
          showPlayerLoading(false);
          showPlayerError("Stream unavailable. Please try another server.");
          vid.removeEventListener("error", onError);
        });
        vid.play().catch(function() {});
      } else {
        showPlayerLoading(false);
        showPlayerError("Your browser does not support HLS streaming.");
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
      clearPlayerError();
      showPlayerLoading(false);
      document.getElementById("player-container").classList.add("hidden");
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

    const res = await fetch(`${ROOM_API_BASE}/room/${encodeURIComponent(roomStr)}/detail.json`, {
      headers: { "User-Agent": API_USER_AGENT, Referer: API_REFERER },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const txt = await res.text();

    // Limit response size to prevent abuse
    if (txt.length > 512 * 1024) return { m3u8: null, hdM3u8: null };

    const m = txt.match(/detail\((.*)\)/s);
    if (m) {
      let js: any;
      try {
        js = JSON.parse(m[1]);
      } catch {
        return { m3u8: null, hdM3u8: null };
      }
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

    // Limit response size
    if (txt.length > 5 * 1024 * 1024) return [];

    const m = txt.match(/matches_\d+\((.*)\)/s);
    if (!m) return [];

    let js: any;
    try {
      js = JSON.parse(m[1]);
    } catch {
      return [];
    }
    if (js.code !== 200) return [];

    const now = Date.now();
    const results = [];

    // Limit to reasonable number of matches to prevent DoS
    const matchData = Array.isArray(js.data) ? js.data.slice(0, 500) : [];

    for (const it of matchData) {
      const mt = it.matchTime;

      if (!mt || typeof mt !== "number") continue;

      // Sanity check: match time should be within reasonable range (±7 days)
      if (Math.abs(now - mt) > 7 * 24 * 60 * 60 * 1000) continue;

      let status: string;
      if (now >= mt && now <= mt + 3 * 60 * 60 * 1000) status = "live";
      else if (now > mt + 3 * 60 * 60 * 1000) status = "finished";
      else status = "upcoming";

      const servers: any[] = [];
      if (status === "live" && it.anchors) {
        const anchorSlice = Array.isArray(it.anchors) ? it.anchors.slice(0, 3) : [];
        for (const a of anchorSlice) {
          const room = a.anchor?.roomNum;
          if (!room) continue;
          const { m3u8, hdM3u8 } = await fetchServerURL(room);
          if (m3u8) servers.push({ name: "Soco SD", stream_url: m3u8 });
          if (hdM3u8) servers.push({ name: "Soco HD", stream_url: hdM3u8 });
        }
      }

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
        matchScore = hs + " - " + as;
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

      results.push({
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
        servers,
      });
    }
    return results;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
