import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

// --- 1. SERVER SETUP ---
Deno.serve(async (req) => {
  const url = new URL(req.url);

  // --- 2. API ROUTE (Backend Logic) ---
  // Frontend ကနေ /api/matches လို့ခေါ်ရင် ဒီအကွက်က အလုပ်လုပ်ပြီး Socolive ဆီက Data သွားယူမယ်
  if (url.pathname === "/api/matches") {
    try {
      const referer = "https://socolivev.co/";
      const agent = "Mozilla/5.0";

      // မနေ့က၊ ဒီနေ့၊ မနက်ဖြန် (၃ ရက်စာ)
      const dates = [
        formatDate(Date.now() - 86400000),
        formatDate(Date.now()),
        formatDate(Date.now() + 86400000),
      ];

      let allMatches: any[] = [];
      for (const d of dates) {
        const matches = await fetchMatches(d, referer, agent);
        allMatches = allMatches.concat(matches);
      }

      // Live ပွဲတွေကို အပေါ်ဆုံးတင်မယ်
      allMatches.sort((a, b) => (a.status === 'live' ? -1 : 1));

      return new Response(JSON.stringify(allMatches), {
        headers: { "Content-Type": "application/json" }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
  }

  // --- 3. FRONTEND ROUTE (HTML Page) ---
  // Web ကိုဖွင့်လိုက်ရင် ဒီ HTML ကို ပြမယ်
  if (url.pathname === "/") {
    const html = `
    <!DOCTYPE html>
    <html lang="my">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Deno Football Live</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
        <style>
            body { background-color: #0f172a; color: white; font-family: sans-serif; }
            .live-badge { animation: pulse 2s infinite; color: #ef4444; font-weight: bold; }
            @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
            .loader { border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 20px auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body class="p-4 max-w-md mx-auto pb-20">
        <h1 class="text-2xl font-bold text-center mb-4 text-green-400 flex items-center justify-center gap-2">
            ⚽ Deno Football Live
        </h1>

        <!-- Video Player -->
        <div id="player-container" class="hidden mb-6 bg-black rounded-lg overflow-hidden shadow-xl border border-slate-600 sticky top-2 z-50">
            <video id="video" controls class="w-full aspect-video" autoplay></video>
            <button onclick="closePlayer()" class="w-full bg-red-600 py-2 font-bold text-sm hover:bg-red-700">ပိတ်မည် (Close)</button>
        </div>

        <!-- Loading -->
        <div id="loading">
            <div class="loader"></div>
            <div class="text-center text-gray-400 text-sm">ပွဲစဉ်များကို ရှာနေပါသည်...</div>
        </div>

        <!-- Matches List -->
        <div id="match-list" class="space-y-3"></div>

        <script>
            async function loadMatches() {
                try {
                    // Deno Server ရဲ့ API ကို လှမ်းခေါ်မယ်
                    const res = await fetch('/api/matches');
                    const matches = await res.json();
                    
                    const container = document.getElementById('match-list');
                    document.getElementById('loading').style.display = 'none';
                    container.innerHTML = '';

                    if(matches.length === 0) {
                        container.innerHTML = '<div class="text-center text-gray-500 mt-10">ပွဲစဉ်များ မရှိသေးပါ</div>';
                        return;
                    }

                    matches.forEach(match => {
                        // Stream Buttons
                        let streamBtns = '';
                        if (match.streams && match.streams.length > 0) {
                            match.streams.forEach(s => {
                                streamBtns += \`<button onclick="playStream('\${s.url}')" class="bg-green-600 hover:bg-green-500 text-white text-[10px] px-3 py-1.5 rounded mr-2 mb-2 font-bold shadow">▶ \${s.label}</button>\`;
                            });
                        } else if (match.status === 'live') {
                            streamBtns = '<span class="text-xs text-gray-500 animate-pulse">လင့်ခ်ရှာနေဆဲ...</span>';
                        }

                        const statusText = match.status === 'live' ? 'LIVE' : (match.status === 'finished' ? 'FT' : match.time);
                        const statusClass = match.status === 'live' ? 'live-badge' : 'text-gray-400';
                        const borderClass = match.status === 'live' ? 'border-red-500/50' : 'border-slate-700';

                        const html = \`
                            <div class="bg-slate-800 rounded-xl p-4 shadow-lg border \${borderClass}">
                                <div class="text-[10px] text-gray-400 mb-3 flex justify-between uppercase tracking-wide font-bold">
                                    <span class="truncate w-2/3">\${match.league}</span>
                                    <span class="\${statusClass}">\${statusText}</span>
                                </div>
                                <div class="flex justify-between items-center mb-4">
                                    <div class="text-center w-1/3">
                                        <img src="\${match.home_icon}" class="w-10 h-10 mx-auto mb-2 bg-white/10 rounded-full p-1">
                                        <div class="text-xs font-bold truncate">\${match.home}</div>
                                    </div>
                                    <div class="text-2xl font-bold text-white w-1/3 text-center font-mono">
                                        \${match.score}
                                    </div>
                                    <div class="text-center w-1/3">
                                        <img src="\${match.away_icon}" class="w-10 h-10 mx-auto mb-2 bg-white/10 rounded-full p-1">
                                        <div class="text-xs font-bold truncate">\${match.away}</div>
                                    </div>
                                </div>
                                <div class="text-center border-t border-slate-700 pt-3">
                                    \${streamBtns}
                                </div>
                            </div>
                        \`;
                        container.innerHTML += html;
                    });

                } catch (e) {
                    document.getElementById('loading').innerHTML = "<div class='text-red-400 text-center'>Error loading matches</div>";
                    console.error(e);
                }
            }

            function playStream(url) {
                const container = document.getElementById('player-container');
                const video = document.getElementById('video');
                container.classList.remove('hidden');
                window.scrollTo({ top: 0, behavior: 'smooth' });

                if (Hls.isSupported()) {
                    const hls = new Hls();
                    hls.loadSource(url);
                    hls.attachMedia(video);
                    hls.on(Hls.Events.MANIFEST_PARSED, function() { video.play(); });
                } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                    video.src = url;
                    video.addEventListener('loadedmetadata', function() { video.play(); });
                }
            }

            function closePlayer() {
                const video = document.getElementById('video');
                video.pause();
                video.src = "";
                document.getElementById('player-container').classList.add('hidden');
            }

            loadMatches();
        </script>
    </body>
    </html>
    `;
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  return new Response("Not Found", { status: 404 });
});

// --- 4. HELPER FUNCTIONS (Backend Logic) ---

function formatDate(ms: number) {
  return new Date(ms).toISOString().split("T")[0].replace(/-/g, "");
}

async function fetchServerURL(roomNum: any) {
  try {
    const res = await fetch(`https://json.vnres.co/room/${roomNum}/detail.json`);
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
      headers: { referer, "user-agent": agent, origin: "https://json.vnres.co" }
    });
    const txt = await res.text();
    const m = txt.match(/matches_\d+\((.*)\)/);
    if (!m) return [];
    
    const js = JSON.parse(m[1]);
    if (js.code !== 200) return [];

    const now = Math.floor(Date.now() / 1000);
    const matchDur = 2.5 * 3600; // 2.5 hours
    const results = [];

    for (const it of js.data) {
      const mt = Math.floor(it.matchTime / 1000);
      let status;
      if (now >= mt && now <= mt + matchDur) status = "live";
      else if (now > mt + matchDur) status = "finished";
      else status = "upcoming";

      const servers = [];
      // Fetch stream links only if LIVE
      if (status === "live" && it.anchors) {
        for (const a of it.anchors) {
          const room = a.anchor.roomNum;
          const { m3u8, hdM3u8 } = await fetchServerURL(room);
          if (m3u8) servers.push({ label: "SD", url: m3u8 });
          if (hdM3u8) servers.push({ label: "HD", url: hdM3u8 });
        }
      }

      results.push({
        league: it.leagueName,
        home: it.homeName,
        away: it.awayName,
        home_icon: it.homeIcon,
        away_icon: it.awayIcon,
        score: (it.homeScore !== undefined) ? `${it.homeScore} - ${it.awayScore}` : "VS",
        time: new Date(it.matchTime).toLocaleTimeString('en-US', { timeZone: 'Asia/Yangon', hour: '2-digit', minute: '2-digit', hour12: true }),
        status: status,
        streams: servers
      });
    }
    return results;
  } catch (e) {
    console.error("Fetch error:", e);
    return [];
  }
}
