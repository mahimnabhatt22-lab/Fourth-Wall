export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();

  const apiKey = process.env.TMDB_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "TMDB_API_KEY is not configured on the server." });
  }

  try {
    const { endpoint = "", ...rest } = req.query || {};
    const cleanEndpoint = String(endpoint).replace(/^\/+/, "");
    if (!cleanEndpoint) {
      return res.status(400).json({ error: "Missing endpoint parameter." });
    }

    const url = new URL(`https://api.themoviedb.org/3/${cleanEndpoint}`);
    url.searchParams.set("api_key", apiKey);
    for (const [k, v] of Object.entries(rest)) {
      if (v !== undefined && v !== null && v !== "") {
        url.searchParams.set(k, Array.isArray(v) ? v[0] : String(v));
      }
    }

    const upstream = await fetch(url.toString(), {
      headers: { Accept: "application/json" }
    });
    const data = await upstream.json();
    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
    return res.status(upstream.status).json(data);
  } catch (err) {
    return res.status(502).json({ error: "Failed to reach TMDB upstream.", detail: String(err) });
  }
}
