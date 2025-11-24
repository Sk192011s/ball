import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

serve(async (req) => {
  const url = new URL(req.url);

  // --- 1. API ROUTE (Backend) ---
  if (url.pathname === "/api/matches") {
    try {
      // Timezone: Vietnam (UTC+7) for Socolive
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

      // Sort: Live first
      allMatches.sort((a, b) => (a.match_status === 'live' ? -1 : 1));

      return new Response(JSON.stringify(allMatches), {
        headers: { 
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*" 
        }
      });
    } catch (e: any) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }
  }

  // --- 2. FRONTEND UI (HTML) ---
  if (url.pathname === "/") {
    return new Response(`
    <!DOCTYPE html>
    <html lang="my">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Soco All Sports</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
        <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body { background: #0f172a; color: white; font-family: 'Padauk', sans-serif; padding-bottom: 50px; }
            .live-dot { width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block; animation: blink 1s infinite; }
            @keyframes blink { 50% { opacity: 0.4; } }
            .glass { background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255,255,255,0.1); }
        </style>
    </head>
    <body class="p-4 max-w-md mx-auto pb-24">
        <h1 class="text-xl font-bold text-center mb-6 text-yellow-400 flex items-center justify-center gap-2">
            🏆 All Sports Live <span class="text-xs text-gray-500">(MM Time)</span>
        </h1>

        <div id="player-container" class="hidden sticky top-2 z-50 mb-4 bg-black rounded-lg overflow-hidden border border-gray-600 shadow-2xl">
            <video id="video" controls class="w-full aspect-video" autoplay></video>
            <button onclick="closePlayer()" class="w-full bg-red-600 text-white text-xs font-bold py-3">ပိတ်မည် (Close)</button>
        </div>

        <div id="loading" class="text-center py-10 text-gray-400">
            <i class="fas fa-circle-notch fa-spin text-2xl mb-2"></i><br>
            Loading All Sports...
        </div>

        <div id="match-list" class="space-y-3"></div>

        <script>
            async function load() {
                try {
                    const res = await fetch('/api/matches');
                    const data = await res.json();
                    document.getElementById('loading').style.display = 'none';
                    const list = document.getElementById('match-list');
                    
                    if (data.length === 0) {
                        list.innerHTML = '<div class="text-center text-gray-500 py-10">လက်ရှိ ပွဲစဉ်များ မရှိသေးပါ (No Data Found)</div>';
                        return;
                    }

                    data.forEach(m => {
                        const isLive = m.match_status === 'live';
                        const statusBadge = isLive 
                            ? '<span class="text-red-500 font-bold text-[10px] flex items-center gap-1"><span class="live-dot"></span> LIVE</span>' 
                            : '<span class="text-gray-500 text-[10px]">' + m.match_time + '</span>';
                        
                        let btns = '';
                        if (m.servers.length > 0) {
                            m.servers.forEach(s => {
                                const label = s.name.includes('HD') ? 'HD' : 'SD';
                                const col = label === 'HD' ? 'bg-red-600' : 'bg-blue-600';
                                btns += \`<button onclick="play('\${s.stream_url}')" class="\${col} text-white text-[10px] px-3 py-1.5 rounded mr-2 shadow font-bold hover:opacity-80">\${label}</button>\`;
                            });
                        } else if (isLive) {
                            btns = '<span class="text-[10px] text-yellow-500 animate-pulse">Link...</span>';
                        } else {
                             btns = '<span class="text-[10px] text-gray-600">Upcoming</span>';
                        }

                        const html = \`
                            <div class="glass rounded-xl p-3 shadow-lg">
                                <div class="flex justify-between items-center mb-2">
                                    <span class="text-[10px] text-gray-400 truncate w-2/3 font-bold uppercase">\${m.league_name}</span>
                                    \${statusBadge}
                                </div>
                                <div class="flex justify-between items-center text-center">
                                    <div class="w-1/3 flex flex-col items-center">
                                        <span class="text-xs font-bold truncate w-full">\${m.home_team_name}</span>
                                    </div>
                                    <div class="w-1/3 text-xl font-bold text-yellow-400 font-mono">\${m.match_score || 'VS'}</div>
                                    <div class="w-1/3 flex flex-col items-center">
                                        <span class="text-xs font-bold truncate w-full">\${m.away_team_name}</span>
                                    </div>
                                </div>
                                <div class="text-center mt-3 pt-2 border-t border-white/5">
                                    \${btns}
                                </div>
                            </div>
                        \`;
                        list.innerHTML += html;
                    });
                } catch (e) {
                    document.getElementById('loading').innerText = "Error: " + e.message;
                }
            }

            function play(url) {
                document.getElementById('player-container').classList.remove('hidden');
                const vid = document.getElementById('video');
                if (Hls.isSupported()) {
                    const hls = new Hls();
                    hls.loadSource(url);
                    hls.attachMedia(vid);
                    hls.on(Hls.Events.MANIFEST_PARSED, () => vid.play());
                } else if (vid.canPlayType('application/vnd.apple.mpegurl')) {
                    vid.src = url;
                    vid.play();
                }
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }

            function closePlayer() {
                const vid = document.getElementById('video');
                vid.pause();
                vid.src = "";
                document.getElementById('player-container').classList.add('hidden');
            }

            load();
        </script>
    </body>
    </html>
    `, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  return new Response("Not Found", { status: 404 });
});

// --- BACKEND LOGIC (NO FILTER) ---

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
  } catch (e) { /* ignore */ }
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
      // NOTE: Filter removed to show ALL sports (Football, Basketball, etc.)
      // if (it.sportType !== 1) continue; 

      const mt = it.matchTime;
      let status;
      if (now >= mt && now <= mt + (3 * 60 * 60 * 1000)) status = "live";
      else if (now > mt + (3 * 60 * 60 * 1000)) status = "finished";
      else status = "upcoming";

      const servers = [];
      if (status === "live" && it.anchors) {
        for (const a of it.anchors) {
          const room = a.anchor.roomNum;
          const { m3u8, hdM3u8 } = await fetchServerURL(room);
          if (m3u8) servers.push({ name: "Soco SD", stream_url: m3u8 });
          if (hdM3u8) servers.push({ name: "Soco HD", stream_url: hdM3u8 });
        }
      }

      results.push({
        match_time: new Date(mt).toLocaleTimeString('en-US', { timeZone: 'Asia/Yangon', hour: '2-digit', minute: '2-digit', hour12: true }),
        match_status: status,
        home_team_name: it.homeName || it.hostName || "Home",
        away_team_name: it.awayName || it.guestName || "Away",
        league_name: it.leagueName || it.subCateName,
        match_score: (it.homeScore !== undefined) ? `${it.homeScore} - ${it.awayScore}` : null,
        servers
      });
    }
    return results;
  } catch (e) {
    console.warn(`matches ${date} error:`, e);
    return [];
  }
}
