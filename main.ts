import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

serve(async (req) => {
  const url = new URL(req.url);

  // --- 1. API ROUTE (Backend) ---
  if (url.pathname === "/api/matches") {
    try {
      const getVNDate = (offset: number) => {
        const d = new Date();
        d.setDate(d.getDate() + offset);
        return new Intl.DateTimeFormat("en-CA", {
          timeZone: "Asia/Ho_Chi_Minh",
          year: "numeric", month: "2-digit", day: "2-digit"
        }).format(d).replace(/-/g, "");
      };

      const dates = [getVNDate(-1), getVNDate(0), getVNDate(1)];
      const referer = "https://socolivev.co/";
      const agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

      let allMatches: any[] = [];
      for (const d of dates) {
        const matches = await fetchMatches(d, referer, agent);
        allMatches = allMatches.concat(matches);
      }

      allMatches.sort((a, b) => {
        if (a.match_status === 'live' && b.match_status !== 'live') return -1;
        if (a.match_status !== 'live' && b.match_status === 'live') return 1;
        if (a.match_status === 'upcoming' && b.match_status === 'finished') return -1;
        if (a.match_status === 'finished' && b.match_status === 'upcoming') return 1;
        return 0;
      });

      return new Response(JSON.stringify(allMatches), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    } catch (e: any) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }

  // --- 2. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    return new Response(getHTML(), {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }

  return new Response("Not Found", { status: 404 });
});

// ====== FRONTEND HTML ======
function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>⚽ Soco All Sports Live</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }
    body {
      background: linear-gradient(135deg, #0a0e1a 0%, #111827 50%, #0a0e1a 100%);
      color: #fff;
      font-family: 'Inter', 'Padauk', sans-serif;
      margin: 0;
      min-height: 100vh;
    }
    .live-dot {
      width: 7px; height: 7px;
      background: #ef4444;
      border-radius: 50%;
      display: inline-block;
      animation: pulse-dot 1.2s ease-in-out infinite;
      box-shadow: 0 0 6px #ef4444;
    }
    @keyframes pulse-dot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.8); }
    }
    .card {
      background: linear-gradient(145deg, rgba(30,41,59,0.9), rgba(15,23,42,0.95));
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 16px;
      backdrop-filter: blur(10px);
      transition: all 0.3s ease;
    }
    .card:hover { border-color: rgba(250,204,21,0.2); transform: translateY(-1px); }
    .card-live {
      border-color: rgba(239,68,68,0.3);
      box-shadow: 0 0 20px rgba(239,68,68,0.08);
    }
    .team-logo {
      width: 40px; height: 40px;
      border-radius: 50%;
      object-fit: contain;
      background: rgba(255,255,255,0.05);
      padding: 4px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .team-logo-fallback {
      width: 40px; height: 40px;
      border-radius: 50%;
      background: linear-gradient(135deg, #1e293b, #334155);
      display: flex; align-items: center; justify-content: center;
      font-size: 16px;
      border: 1px solid rgba(255,255,255,0.1);
    }
    .btn-hd {
      background: linear-gradient(135deg, #dc2626, #b91c1c);
      box-shadow: 0 2px 10px rgba(220,38,38,0.3);
    }
    .btn-hd:hover { box-shadow: 0 4px 15px rgba(220,38,38,0.5); }
    .btn-sd {
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      box-shadow: 0 2px 10px rgba(37,99,235,0.3);
    }
    .btn-sd:hover { box-shadow: 0 4px 15px rgba(37,99,235,0.5); }
    .score-box {
      background: rgba(0,0,0,0.4);
      border-radius: 10px;
      padding: 4px 12px;
      min-width: 70px;
    }
    .league-badge {
      background: rgba(250,204,21,0.1);
      border: 1px solid rgba(250,204,21,0.2);
      border-radius: 20px;
      padding: 2px 10px;
    }
    .tab-btn {
      padding: 8px 18px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      border: 1px solid transparent;
    }
    .tab-btn.active {
      background: linear-gradient(135deg, #facc15, #f59e0b);
      color: #000;
      box-shadow: 0 2px 15px rgba(250,204,21,0.3);
    }
    .tab-btn:not(.active) {
      background: rgba(255,255,255,0.05);
      color: #9ca3af;
      border-color: rgba(255,255,255,0.1);
    }
    .tab-btn:not(.active):hover { background: rgba(255,255,255,0.1); color: #fff; }
    .header-glow {
      text-shadow: 0 0 30px rgba(250,204,21,0.3);
    }
    .loading-spinner {
      width: 40px; height: 40px;
      border: 3px solid rgba(255,255,255,0.1);
      border-top-color: #facc15;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .player-wrapper {
      border-radius: 16px;
      overflow: hidden;
      border: 2px solid rgba(250,204,21,0.3);
      box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }
    .close-btn {
      background: linear-gradient(135deg, #dc2626, #991b1b);
      transition: all 0.2s;
    }
    .close-btn:hover { background: linear-gradient(135deg, #ef4444, #dc2626); }
    .stat-pill {
      background: rgba(255,255,255,0.05);
      border-radius: 12px;
      padding: 6px 14px;
      font-size: 11px;
    }
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 4px; }
  </style>
</head>
<body>
  <div class="max-w-md mx-auto px-4 pt-6 pb-28">

    <!-- Header -->
    <div class="text-center mb-6">
      <h1 class="text-2xl font-bold header-glow" style="color:#facc15;">⚽ All Sports Live</h1>
      <p class="text-gray-500 text-xs mt-1">Myanmar Time (UTC+6:30)</p>
    </div>

    <!-- Filter Tabs -->
    <div class="flex gap-2 mb-5 overflow-x-auto pb-1 justify-center" id="tabs">
      <button class="tab-btn active" onclick="filterMatches('all')">All</button>
      <button class="tab-btn" onclick="filterMatches('live')">🔴 Live</button>
      <button class="tab-btn" onclick="filterMatches('upcoming')">⏳ Upcoming</button>
      <button class="tab-btn" onclick="filterMatches('finished')">✅ Finished</button>
    </div>

    <!-- Stats Bar -->
    <div class="flex gap-2 justify-center mb-5" id="stats-bar">
      <span class="stat-pill text-gray-400" id="stat-total">Total: -</span>
      <span class="stat-pill text-red-400" id="stat-live">Live: -</span>
      <span class="stat-pill text-blue-400" id="stat-upcoming">Soon: -</span>
    </div>

    <!-- Video Player -->
    <div id="player-container" class="hidden sticky top-3 z-50 mb-5 player-wrapper">
      <div class="bg-black">
        <video id="video" controls class="w-full aspect-video" autoplay playsinline></video>
      </div>
      <button onclick="closePlayer()" class="close-btn w-full text-white text-xs font-bold py-3 flex items-center justify-center gap-2">
        ✕ ပိတ်မည် (Close Player)
      </button>
    </div>

    <!-- Loading -->
    <div id="loading" class="flex flex-col items-center py-16">
      <div class="loading-spinner mb-4"></div>
      <span class="text-gray-400 text-sm">Loading all sports...</span>
    </div>

    <!-- Match List -->
    <div id="match-list" class="space-y-3"></div>
  </div>

  <script>
    let allData = [];
    let currentFilter = 'all';
    let currentHls = null;

    async function load() {
      try {
        const res = await fetch('/api/matches');
        const data = await res.json();
        allData = data;
        document.getElementById('loading').style.display = 'none';
        updateStats();
        renderMatches();
      } catch (e) {
        document.getElementById('loading').innerHTML =
          '<div class="text-red-400 text-sm">⚠ Error: ' + e.message + '</div>';
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
        return '<img src="' + url + '" alt="' + teamName + '" class="team-logo" onerror="this.style.display=\\'none\\';this.nextElementSibling.style.display=\\'flex\\';">' +
               '<div class="team-logo-fallback" style="display:none;">⚽</div>';
      }
      return '<div class="team-logo-fallback">⚽</div>';
    }

    function renderMatches() {
      const list = document.getElementById('match-list');
      let filtered = allData;
      if (currentFilter !== 'all') {
        filtered = allData.filter(m => m.match_status === currentFilter);
      }

      if (filtered.length === 0) {
        list.innerHTML = '<div class="text-center text-gray-600 py-16">ပွဲစဉ်များ မရှိသေးပါ<br><span class="text-xs">No matches found</span></div>';
        return;
      }

      let html = '';
      filtered.forEach(m => {
        const isLive = m.match_status === 'live';
        const isFinished = m.match_status === 'finished';
        const cardClass = isLive ? 'card card-live' : 'card';

        let statusHTML = '';
        if (isLive) {
          statusHTML = '<span class="flex items-center gap-1.5 text-red-500 font-bold text-[10px]"><span class="live-dot"></span>LIVE ' + (m.match_time || '') + '</span>';
        } else if (isFinished) {
          statusHTML = '<span class="text-gray-500 text-[10px]">FT</span>';
        } else {
          statusHTML = '<span class="text-emerald-400 text-[10px] font-medium">' + m.match_time + '</span>';
        }

        let btns = '';
        if (m.servers && m.servers.length > 0) {
          m.servers.forEach(s => {
            const isHD = s.name.includes('HD');
            const cls = isHD ? 'btn-hd' : 'btn-sd';
            const label = isHD ? '▶ HD' : '▶ SD';
            btns += '<button onclick="play(\\'' + s.stream_url + '\\')" class="' + cls + ' text-white text-[10px] px-4 py-1.5 rounded-full font-bold transition-all">' + label + '</button>';
          });
        } else if (isLive) {
          btns = '<span class="text-[10px] text-yellow-500 animate-pulse">⏳ Stream loading...</span>';
        } else if (isFinished) {
          btns = '<span class="text-[10px] text-gray-600">Ended</span>';
        } else {
          btns = '<span class="text-[10px] text-gray-600">Not started</span>';
        }

        const homeLogo = getLogoHTML(m.home_team_logo, m.home_team_name);
        const awayLogo = getLogoHTML(m.away_team_logo, m.away_team_name);

        const scoreDisplay = m.match_score
          ? '<div class="score-box text-center"><span class="text-lg font-bold text-yellow-400 font-mono">' + m.match_score + '</span></div>'
          : '<div class="score-box text-center"><span class="text-sm font-bold text-gray-500">VS</span></div>';

        html += '<div class="' + cardClass + ' p-4">' +
          '<div class="flex justify-between items-center mb-3">' +
            '<span class="league-badge text-[10px] text-yellow-400 truncate max-w-[65%] font-semibold">' + m.league_name + '</span>' +
            statusHTML +
          '</div>' +
          '<div class="flex items-center justify-between">' +
            '<div class="flex flex-col items-center w-[30%] gap-1.5">' +
              homeLogo +
              '<span class="text-[11px] font-semibold text-center leading-tight truncate w-full">' + m.home_team_name + '</span>' +
            '</div>' +
            '<div class="w-[30%] flex justify-center">' +
              scoreDisplay +
            '</div>' +
            '<div class="flex flex-col items-center w-[30%] gap-1.5">' +
              awayLogo +
              '<span class="text-[11px] font-semibold text-center leading-tight truncate w-full">' + m.away_team_name + '</span>' +
            '</div>' +
          '</div>' +
          '<div class="text-center mt-3 pt-3 border-t border-white/5 flex gap-2 justify-center">' +
            btns +
          '</div>' +
        '</div>';
      });
      list.innerHTML = html;
    }

    function play(url) {
      document.getElementById('player-container').classList.remove('hidden');
      const vid = document.getElementById('video');

      // Destroy previous HLS instance
      if (currentHls) {
        currentHls.destroy();
        currentHls = null;
      }

      if (Hls.isSupported()) {
        const hls = new Hls({ enableWorker: true, lowLatencyMode: true });
        currentHls = hls;
        hls.loadSource(url);
        hls.attachMedia(vid);
        hls.on(Hls.Events.MANIFEST_PARSED, () => vid.play());
        hls.on(Hls.Events.ERROR, (event, data) => {
          if (data.fatal) {
            console.error('HLS fatal error:', data.type);
            hls.destroy();
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

    load();
    // Auto refresh every 60 seconds
    setInterval(load, 60000);
  </script>
</body>
</html>`;
}

// ====== BACKEND LOGIC ======

async function fetchServerURL(roomNum: any) {
  try {
    const res = await fetch(`https://json.vnres.co/room/${roomNum}/detail.json`, {
      headers: { "User-Agent": "Mozilla/5.0", "Referer": "https://socolivev.co/" }
    });
    const txt = await res.text();
    const m = txt.match(/detail\((.*)\)/);
    if (m) {
      const js = JSON.parse(m[1]);
      if (js.code === 200 && js.data && js.data.stream) {
        return { m3u8: js.data.stream.m3u8, hdM3u8: js.data.stream.hdM3u8 };
      }
    }
  } catch (_e) { /* ignore */ }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string, referer: string, agent: string) {
  try {
    const res = await fetch(`https://json.vnres.co/match/matches_${date}.json`, {
      headers: { "User-Agent": agent, "Referer": referer }
    });
    const txt = await res.text();
    const m = txt.match(/matches_\d+\((.*)\)/);
    if (!m) return [];

    const js = JSON.parse(m[1]);
    if (js.code !== 200) return [];

    const now = Date.now();
    const results = [];

    for (const it of js.data) {
      const mt = it.matchTime;
      let status: string;
      if (now >= mt && now <= mt + (3 * 60 * 60 * 1000)) status = "live";
      else if (now > mt + (3 * 60 * 60 * 1000)) status = "finished";
      else status = "upcoming";

      const servers: any[] = [];
      if (status === "live" && it.anchors) {
        for (const a of it.anchors) {
          const room = a.anchor.roomNum;
          const { m3u8, hdM3u8 } = await fetchServerURL(room);
          if (m3u8) servers.push({ name: "Soco SD", stream_url: m3u8 });
          if (hdM3u8) servers.push({ name: "Soco HD", stream_url: hdM3u8 });
        }
      }

      // ✅ Logo URLs ယူထားတယ် (API response ထဲက field names အမျိုးမျိုးကို စစ်ပေးတယ်)
      const homeLogo = it.homeLogo || it.hostLogo || it.homeIcon || it.hostIcon || null;
      const awayLogo = it.awayLogo || it.guestLogo || it.awayIcon || it.guestIcon || null;

      results.push({
        match_time: new Date(mt).toLocaleTimeString('en-US', {
          timeZone: 'Asia/Yangon',
          hour: '2-digit', minute: '2-digit', hour12: true
        }),
        match_status: status,
        home_team_name: it.homeName || it.hostName || "Home",
        away_team_name: it.awayName || it.guestName || "Away",
        home_team_logo: homeLogo,
        away_team_logo: awayLogo,
        league_name: it.leagueName || it.subCateName || "Unknown League",
        match_score: (it.homeScore !== undefined && it.homeScore !== null)
          ? `${it.homeScore} - ${it.awayScore}`
          : null,
        servers
      });
    }
    return results;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
