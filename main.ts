import { serve } from "https://deno.land/std@0.208.0/http/server.ts";

serve(async (req) => {
  const url = new URL(req.url);

  // --- API ROUTE ---
  if (url.pathname === "/api/matches") {
    try {
      // Manual Timezone Calculation (UTC+7) to be 100% sure
      const getVNDateString = (offsetDays = 0) => {
        const now = new Date();
        // Current UTC time + 7 hours + offset days
        const targetTime = new Date(now.getTime() + (7 * 60 * 60 * 1000) + (offsetDays * 24 * 60 * 60 * 1000));
        
        const y = targetTime.getUTCFullYear();
        const m = String(targetTime.getUTCMonth() + 1).padStart(2, '0');
        const d = String(targetTime.getUTCDate()).padStart(2, '0');
        return `${y}${m}${d}`;
      };

      // Get Yesterday, Today, Tomorrow
      const dates = [getVNDateString(-1), getVNDateString(0), getVNDateString(1)];
      
      let allMatches: any[] = [];
      let errors: string[] = [];

      for (const d of dates) {
        const result = await fetchMatches(d);
        if (result.length > 0) {
            allMatches = allMatches.concat(result);
        } else {
            errors.push(`No data for ${d}`);
        }
      }

      // Sort: Live matches first
      allMatches.sort((a, b) => (a.match_status === 'live' ? -1 : 1));

      return new Response(JSON.stringify(allMatches), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });

    } catch (e: any) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
  }

  // --- FRONTEND UI ---
  return new Response(`
    <!DOCTYPE html>
    <html lang="my">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Football Live MM</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
        <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body { background: #0f172a; color: white; font-family: 'Padauk', sans-serif; padding-bottom: 50px; }
            .live-dot { width: 8px; height: 8px; background: #ef4444; border-radius: 50%; display: inline-block; animation: blink 1s infinite; }
            @keyframes blink { 50% { opacity: 0.4; } }
            .loader { border: 3px solid #f3f3f3; border-top: 3px solid #3498db; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body class="max-w-md mx-auto p-4">
        <h1 class="text-xl font-bold text-center mb-6 text-green-400 flex justify-center items-center gap-2">
            ⚽ Football Live <span class="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">MM Time</span>
        </h1>

        <div id="player-box" class="hidden sticky top-2 z-50 mb-4 bg-black rounded-lg overflow-hidden border border-gray-600 shadow-2xl">
            <video id="video" controls class="w-full aspect-video" autoplay></video>
            <button onclick="closePlayer()" class="w-full bg-red-600 text-white text-xs font-bold py-3 hover:bg-red-700">ပိတ်မည် (Close Player)</button>
        </div>

        <div id="loading" class="text-center py-10">
            <div class="loader"></div>
            <p class="text-gray-400 text-sm mt-3">ပွဲစဉ်များကို ရှာဖွေနေပါသည်...</p>
        </div>
        
        <div id="match-list" class="space-y-3"></div>

        <script>
            async function load() {
                try {
                    const res = await fetch('/api/matches');
                    const data = await res.json();
                    document.getElementById('loading').style.display = 'none';
                    const list = document.getElementById('match-list');
                    
                    if (data.error) {
                        list.innerHTML = '<div class="text-center text-red-400">System Error: ' + data.error + '</div>';
                        return;
                    }

                    if (data.length === 0) {
                        list.innerHTML = '<div class="text-center text-gray-500 bg-slate-800 p-4 rounded-lg">လောလောဆယ် ဘောလုံးပွဲများ မရှိသေးပါ<br><span class="text-xs text-gray-600">(Server Time Check OK)</span></div>';
                        return;
                    }

                    data.forEach(m => {
                        const isLive = m.match_status === 'live';
                        const statusBadge = isLive 
                            ? '<span class="text-red-500 font-bold text-[10px] flex items-center gap-1 bg-red-500/10 px-2 py-1 rounded"><span class="live-dot"></span> LIVE</span>' 
                            : '<span class="text-gray-500 text-[10px] bg-slate-900 px-2 py-1 rounded">' + m.match_time + '</span>';
                        
                        const borderClass = isLive ? 'border-green-500/50 shadow-green-900/20' : 'border-white/5';
                        const bgClass = isLive ? 'bg-slate-800' : 'bg-slate-800/50';
                        
                        let btns = '';
                        if (m.servers.length > 0) {
                            m.servers.forEach(s => {
                                const label = s.name.includes('HD') ? 'HD' : 'SD';
                                const col = label === 'HD' ? 'bg-gradient-to-r from-red-600 to-red-500' : 'bg-gradient-to-r from-blue-600 to-blue-500';
                                btns += \`<button onclick="play('\${s.stream_url}')" class="\${col} text-white text-[10px] px-4 py-1.5 rounded shadow hover:opacity-90 mr-2 font-bold flex items-center gap-1"><i class="fas fa-play"></i> \${label}</button>\`;
                            });
                        } else if (isLive) {
                            btns = '<span class="text-[10px] text-yellow-500 animate-pulse">လင့်ခ်ရှာနေဆဲ...</span>';
                        } else {
                            btns = '<span class="text-[10px] text-gray-600">ပွဲမစသေးပါ</span>';
                        }

                        const html = \`
                            <div class="\${bgClass} border \${borderClass} rounded-xl p-4 shadow-lg transition hover:border-white/10">
                                <div class="flex justify-between items-center mb-3 border-b border-white/5 pb-2">
                                    <span class="text-[10px] text-gray-400 truncate w-2/3 font-bold uppercase tracking-wider">\${m.league_name}</span>
                                    \${statusBadge}
                                </div>
                                <div class="flex justify-between items-center text-center mb-4">
                                    <div class="w-1/3 flex flex-col items-center">
                                        <span class="text-xs font-bold truncate w-full">\${m.home_team_name}</span>
                                    </div>
                                    <div class="w-1/3 text-2xl font-bold text-yellow-400 font-mono tracking-widest">\${m.match_score || 'VS'}</div>
                                    <div class="w-1/3 flex flex-col items-center">
                                        <span class="text-xs font-bold truncate w-full">\${m.away_team_name}</span>
                                    </div>
                                </div>
                                <div class="text-center pt-1">
                                    \${btns}
                                </div>
                            </div>
                        \`;
                        list.innerHTML += html;
                    });
                } catch (e) {
                    document.getElementById('loading').innerHTML = "<div class='text-red-400 text-sm'>Connection Error!</div>";
                }
            }

            function play(url) {
                document.getElementById('player-box').classList.remove('hidden');
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
                document.getElementById('player-box').classList.add('hidden');
            }
            load();
        </script>
    </body>
    </html>
  `, { headers: { "Content-Type": "text/html; charset=utf-8" } });
});

// --- BACKEND LOGIC ---

async function fetchServerURL(roomNum: any) {
  try {
    const res = await fetch(`https://json.vnres.co/room/${roomNum}/detail.json`, {
        headers: { "User-Agent": "Mozilla/5.0", "Referer": "https://socolivev.co/" }
    });
    const txt = await res.text();
    
    // Smart Regex: Find first { and last }
    const start = txt.indexOf("{");
    const end = txt.lastIndexOf("}");
    if (start === -1 || end === -1) return { m3u8: null, hdM3u8: null };
    
    const jsonStr = txt.substring(start, end + 1);
    const js = JSON.parse(jsonStr);

    if (js.code === 200 && js.data && js.data.stream) {
       return { m3u8: js.data.stream.m3u8, hdM3u8: js.data.stream.hdM3u8 };
    }
  } catch (e) { /* ignore */ }
  return { m3u8: null, hdM3u8: null };
}

async function fetchMatches(date: string) {
  try {
    const res = await fetch(`https://json.vnres.co/match/matches_${date}.json`, {
      headers: { "User-Agent": "Mozilla/5.0", "Referer": "https://socolivev.co/" }
    });
    
    if (!res.ok) return []; // File not found or 403

    const txt = await res.text();
    
    // Smart Parse for matches list
    const start = txt.indexOf("{");
    const end = txt.lastIndexOf("}");
    if (start === -1 || end === -1) return [];

    const jsonStr = txt.substring(start, end + 1);
    const js = JSON.parse(jsonStr);
    
    if (js.code !== 200 || !js.data) return [];

    const now = Date.now();
    const results = [];

    for (const it of js.data) {
      // FILTER: Only Sport Type 1 (Football)
      if (it.sportType !== 1) continue;

      const mt = it.matchTime;
      let status = "upcoming";
      
      // Live Window: Match Start -> Match Start + 3 Hours
      if (now >= mt && now <= mt + (3 * 60 * 60 * 1000)) {
          status = "live";
      } else if (now > mt + (3 * 60 * 60 * 1000)) {
          status = "finished";
      }

      const servers = [];
      if (status === "live" && it.anchors) {
        for (const a of it.anchors) {
          const { m3u8, hdM3u8 } = await fetchServerURL(a.anchor.roomNum);
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
    console.log("Error fetching date:", date, e);
    return []; 
  }
}
