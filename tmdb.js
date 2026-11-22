// Asks TMDB for movie data on behalf of the page, so the secret token never reaches the browser.
module.exports = async function handler(req, res) {
  const token = process.env.TMDB_TOKEN;
  if (!token) return res.status(500).json({ error: "TMDB_TOKEN is not set in Vercel" });

  const p = String(req.query.p || "");
  const allowed = /^(search\/movie|movie\/upcoming|movie\/\d+)$/;
  if (!allowed.test(p)) return res.status(400).json({ error: "Not allowed" });

  const params = new URLSearchParams({ language: "en-US" });
  if (req.query.q) params.set("query", String(req.query.q).slice(0, 100));
  if (/^movie\/\d+$/.test(p)) params.set("append_to_response", "credits");
  if (p === "movie/upcoming") params.set("region", "IN");

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
