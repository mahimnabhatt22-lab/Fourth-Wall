// Asks TMDB for movie & collection data on behalf of the page, so the secret token never reaches the browser.
module.exports = async function handler(req, res) {
  const token = process.env.TMDB_TOKEN;
  if (!token) return res.status(500).json({ error: "TMDB_TOKEN is not set in Vercel" });

  const p = String(req.query.p || "");
  const allowed = /^(search\/movie|search\/keyword|search\/person|discover\/movie|movie\/\d+|movie\/\d+\/recommendations|collection\/\d+)$/;
  if (!allowed.test(p)) return res.status(400).json({ error: "Not allowed" });

  const q = req.query, params = new URLSearchParams({ language: "en-US", include_adult: "false" });
  if (q.q) params.set("query", String(q.q).slice(0, 100));
  if (/^movie\/\d+$/.test(p)) params.set("append_to_response", "credits,keywords,release_dates");
  if (p === "discover/movie") {
    params.set("sort_by", "popularity.desc");
    params.set("vote_count.gte", "150");
    params.set("primary_release_date.lte", new Date().toISOString().slice(0, 10));
    if (/^[\d|,]+$/.test(q.genre || "")) params.set("with_genres", q.genre);
    if (/^[\d|,]+$/.test(q.kw || "")) params.set("with_keywords", q.kw);
    if (/^[A-Z]{2}$/.test(q.country || "")) params.set("with_origin_country", q.country);
  }
  const page = parseInt(q.page, 10);
  if (page >= 1 && page <= 5) params.set("page", String(page));

  try {
    const r = await fetch("https://api.themoviedb.org/3/" + p + "?" + params, {
      headers: { Authorization: "Bearer " + token, accept: "application/json" }
    });
    const data = await r.json();
    res.setHeader("Cache-Control", "s-maxage=3600");
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: "Could not reach TMDB" });
  }
};
