import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

serve(async (req) => {
  const url = new URL(req.url);

  // --- 1. API ROUTE (Backend) ---
  if (url.pathname === "/api/matches") {
    try {
      // Vietnam Time (UTC+7) အတိုင်း ရက်စွဲယူမယ် (Server Time မသုံးဘူး)
      const getVNDate = (offsetDays = 0) => {
        const d = new Date();
        d.setDate(d.getDate() + offsetDays);
        return new Intl.DateTimeFormat("en-CA", {
          timeZone: "Asia/Ho_Chi_Minh" // Socolive Server Timezone
        }).format(d).replace(/-/g, "");
      };

      const dates = [
        getVNDate(-1), // Yesterday
        getVNDate(0),  // Today
        getVNDate(1)   // Tomorrow
      ];

      let allMatches: any[] = [];
      
      // ၃ ရက်စာ ပတ်ပြီးဆွဲမယ်
      for (const date of dates) {
        const matches = await fetchMatches(date);
        allMatches = allMatches.concat(matches);
      }

      // Live ပွဲတွေ အပေါ်တင်မယ်၊ ပြီးရင် အချိန်နီးတာ စီမယ်
      allMatches.sort((a, b) => {
        if (a.match_status === 'live' && b.match_status !== 'live') return -1;
        if (a.match_status !== 'live' && b.match_status === 'live') return 1;
        return a.raw_time - b.raw_time;
      });

      return new Response(JSON.stringify(allMatches), {
        headers: { 
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*" 
        }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
  }

  // --- 2. FRONTEND ROUTE (HTML) ---
  if (url.pathname === "/") {
    return new Response(`
    <!DOCTYPE html>
    <html lang="my">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Soco Live</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
        <style>
            body { background: #0f172a; color: white; font-family: sans-serif; padding-bottom: 50px; }
            .live-dot { height: 8px; width: 8px; background-color: #ef4444; border-radius: 50%; display: inline-block; animation: blink 1s infinite; }
            @keyframes blink { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
            .glass { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); }
        </style>
    </head>
    <body class="max-w-md mx-auto p-4">
        
        <div class="flex justify-between items-center mb-6">
            <h1 class="text-xl font-bold text-green-400 flex items-center gap-2">
                ⚽ Soco Live <span class="text-xs text-gray-500 px-2 border border-gray-700 rounded">Myanmar</span>
            </h1>
            <button onclick="loadMatches()" class="text-sm text-blue-400">Refresh</button>
        </div>

        <!-- Player -->
        <div id="player-box" class="hidden sticky top-2 z-50 mb-4">
            <div class="bg-black rounded-lg overflow-hidden shadow-2xl border border-gray-700">
                <video id="video" controls class="w-full aspect-video" autoplay></video>
                <div class="bg-slate-900 p-2 flex justify-between items-center">
                    <span class="text-xs text-green-400 flex items-center gap-2"><span class="live-dot"></span> Live Stream</span>
                    <button onclick="closePlayer()" class="text-xs text-red-400 font-bold px-3 py-1 border border-red-900 rounded hover:bg-red-900/50">Close</button>
                </div>
            </div>
        </div>

        <!-- Loading -->
        <div id="loading" class="text-center py-10">
            <div class="inline-block w-6 h-6 border-2 border-t-transparent border-green-400 rounded-full animate-spin"></div>
            <p class="text-xs text-gray-500 mt-2">Loading Matches...</p>
        </div>

        <!-- List -->
        <div id="match-list" class="space-y-3"></div>

        <script>
            async function loadMatches() {
                const loader = document.getElementById('loading');
                const list = document.getElementById('match-list');
                loader.style.display = 'block';
                list.innerHTML = '';

                try {
                    const res = await fetch('/api/matches');
                    const data = await res.json();
                    loader.style.display = 'none';

                    if (data.error || data.length === 0) {
                        list.innerHTML = '<div class="text-center text-gray-500 text-sm py-10">ပွဲစဉ်များ မရှိသေးပါ (No Matches)</div>';
                        return;
                    }

                    data.forEach(m => {
                        const isLive = m.match_status === 'live';
                        const statusHtml = isLive 
                            ? '<span class="text-red-500 font-bold text-[10px] flex items-center gap-1"><span class="live-dot"></span> LIVE</span>' 
                            : '<span class="text-gray-500 text-[10px]">' + m.match_time_str + '</span>';
                        
                        const borderClass = isLive ? 'border-green-500/30' : 'border-white/5';
                        const score = m.match_score || 'VS';

                        let btns = '';
                        if (m.servers && m.servers.length > 0) {
                            m.servers.forEach(s => {
                                const label = s.name.includes('HD') ? 'HD' : 'SD';
                                const color = label === 'HD' ? 'bg-red-600' : 'bg-blue-600';
                                btns += \`<button onclick="play('\${s.stream_url}')" class="\${color} text-white text-[10px] px-3 py-1.5 rounded shadow font-bold hover:opacity-80 transition">\${label}</button>\`;
                            });
                        } else if (isLive) {
                            btns = '<span class="text-[10px] text-yellow-500 animate-pulse">Link ရှာနေဆဲ...</span>';
                        }

                        const html = \`
                            <div class="glass rounded-xl p-4 shadow-lg \${borderClass}">
                                <div class="flex justify-between items-center mb-3">
                                    <span class="text-[10px] text-gray-400 truncate max-w-[150px]">\${m.league_name}</span>
                                    \${statusHtml}
                                </div>
                                <div class="flex justify-between items-center text-center mb-3">
                                    <div class="w-1/3">
                                        <div class="font-bold text-sm truncate">\${m.home_team_name}</div>
                                    </div>
                                    <div class="w-1/3 text-xl font-mono font-bold text-yellow-400 px-2">\${score}</div>
                                    <div class="w-1/3">
                                        <div class="font-bold text-sm truncate">\${m.away_team_name}</div>
                                    </div>
                                </div>
                                <div class="flex justify-center gap-2 border-t border-white/5 pt-3">
                                    \${btns}
                                </div>
                            </div>
                        \`;
                        list.innerHTML += html;
                    });

                } catch (e) {
                    loader.innerHTML = '<div class="text-red-400 text-sm">Error loading data</div>';
                }
            }

            function play(url) {
                const box = document.getElementById('player-box');
                const vid = document.getElementById('video');
                box.classList.remove('hidden');
                window.scrollTo({ top: 0, behavior: 'smooth' });

                if (Hls.isSupported()) {
                    const hls = new Hls();
                    hls.loadSource(url);
                    hls.attachMedia(vid);
                    hls.on(Hls.Events.MANIFEST_PARSED, () => vid.play());
                } else if (vid.canPlayType('application/vnd.apple.mpegurl')) {
                    vid.src = url;
                    vid.play();
                }
            }

            function closePlayer() {
                const vid = document.getElementById('video');
                vid.pause();
                vid.src = "";
                document.getElementById('player-box').classList.add('hidden');
            }

            loadMatches();
        </script>
    </body>
    </html>
    `, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  return new Response("Not Found", { status: 404 });
});

// --- BACKEND LOGIC ---

// 1. Fetch Matches List
async function fetchMatches(date: string) {
  try {
    // Socolive JSON endpoint
    const res = await fetch(`https://json.vnres.co/match/matches_${date}.json`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Referer": "https://socolivev.co/",
        "Origin": "https://socolivev.co"
      }
    });

    const text = await res.text();
    // JSONP format: matches_20251125({...}) -> extract JSON
    const match = text.match(/matches_\d+\((.*)\)/);
    if (!match) return [];

    const json = JSON.parse(match[1]);
    if (json.code !== 200 || !json.data) return [];

    // Format Data
    const now = Date.now();
    const results = [];

    for (const item of json.data) {
      const matchTimeMs = item.matchTime;
      const matchEndTimeMs = matchTimeMs + (3 * 60 * 60 * 1000); // ~3 hours duration

      let status = "upcoming";
      if (now >= matchTimeMs && now <= matchEndTimeMs) status = "live";
      else if (now > matchEndTimeMs) status = "finished";

      // Live ချိန်မှသာ Link ရှာမယ်
      const servers = [];
      if (status === "live" && item.anchors) {
        for (const anchor of item.anchors) {
           const links = await fetchStreamLinks(anchor.anchor.roomNum);
           if (links.m3u8) servers.push({ name: "Soco SD", stream_url: links.m3u8 });
           if (links.hdM3u8) servers.push({ name: "Soco HD", stream_url: links.hdM3u8 });
        }
      }

      results.push({
        match_time: Math.floor(matchTimeMs / 1000),
        match_time_str: new Date(matchTimeMs).toLocaleTimeString('en-US', { timeZone: 'Asia/Yangon', hour: '2-digit', minute: '2-digit', hour12: true }),
        raw_time: matchTimeMs,
        match_status: status,
        home_team_name: item.homeName,
        away_team_name: item.awayName,
        league_name: item.leagueName,
        match_score: (item.homeScore !== undefined) ? `${item.homeScore} - ${item.awayScore}` : "VS",
        servers: servers
      });
    }
    return results;

  } catch (e) {
    console.error("Fetch Match Error:", e);
    return [];
  }
}

// 2. Fetch Stream Links (Detail API)
async function fetchStreamLinks(roomNum: any) {
  try {
    const res = await fetch(`https://json.vnres.co/room/${roomNum}/detail.json`, {
        headers: {
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://socolivev.co/"
        }
    });
    const text = await res.text();
    const match = text.match(/detail\((.*)\)/);
    if (match) {
      const json = JSON.parse(match[1]);
      if (json.data && json.data.stream) {
        return { 
            m3u8: json.data.stream.m3u8, 
            hdM3u8: json.data.stream.hdM3u8 
        };
      }
    }
  } catch (e) { /* ignore */ }
  return { m3u8: null, hdM3u8: null };
}
