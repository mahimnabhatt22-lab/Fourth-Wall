// Asks TMDB for data on behalf of the page, so the secret token never reaches the browser.
// Put this file at  /api/tmdb.js  in your project (Vercel turns it into /api/tmdb).
// The page calls /api/tmdb?p=<tmdb path>&q=...&genre=...&country=...&kw=...&page=...
module.exports = async function handler(req, res) {
  const token = process.env.TMDB_TOKEN;      // the long "API Read Access Token" (eyJ...)
  const apiKey = process.env.TMDB_API_KEY;   // optional: the short API key, used only if no token is set
  if (!token && !apiKey) {
    return res.status(500).json({ error: "Set TMDB_TOKEN in Vercel (Settings > Environment Variables) and redeploy." });
  }

  const q = req.query || {};
  const p = String(q.p || q.endpoint || "").replace(/^\/+/, "");
  const allowed = /^(search\/(movie|keyword|person)|discover\/movie|trending\/movie\/(day|week)|movie\/(upcoming|now_playing|popular|top_rated)|movie\/\d+(\/(recommendations|similar))?|collection\/\d+)$/;
  if (!allowed.test(p)) return res.status(400).json({ error: "Not allowed" });

  const params = new URLSearchParams({ language: "en-US", include_adult: "false" });
  if (q.q) params.set("query", String(q.q).slice(0, 100));
  if (/^movie\/\d+$/.test(p)) params.set("append_to_response", "credits,keywords");
  if (p === "discover/movie") {
    params.set("sort_by", "popularity.desc");
    params.set("vote_count.gte", "150");
    params.set("primary_release_date.lte", new Date().toISOString().slice(0, 10));
    if (/^[\d|,]+$/.test(q.genre || "")) params.set("with_genres", q.genre);
    if (/^[\d|,]+$/.test(q.kw || "")) params.set("with_keywords", q.kw);
    if (/^[A-Z]{2}$/.test(q.country || "")) params.set("with_origin_country", q.country);
  }
  if (p === "movie/upcoming" || p === "movie/now_playing") params.set("region", "IN");
  const page = parseInt(q.page, 10);
  if (page >= 1 && page <= 5) params.set("page", String(page));

  const headers = { accept: "application/json" };
  if (token) headers.Authorization = "Bearer " + token; else params.set("api_key", apiKey);

  // Give up after 8s so a slow TMDB never hangs the page.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch("https://api.themoviedb.org/3/" + p + "?" + params, { headers, signal: ctrl.signal });
    let data = {};
    try { data = await r.json(); } catch (e) { data = {}; }

    if (!r.ok) {
      // Always give the page a simple { error } message, and never cache failures for long.
      res.setHeader("Cache-Control", "s-maxage=60");
      return res.status(r.status).json({
        error: data.status_message || data.error || ("TMDB error " + r.status),
        status: r.status
      });
    }

    res.setHeader("Cache-Control", "s-maxage=600, stale-while-revalidate=1200");
    return res.status(200).json(data);
  } catch (e) {
    return res.status(502).json({ error: e && e.name === "AbortError" ? "TMDB took too long to respond" : "Could not reach TMDB" });
  } finally {
    clearTimeout(timer);
  }
};
