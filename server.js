const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");

const app = express();

// Allow any browser to call this proxy (needed since it's public)
app.use(cors());
app.use(express.json());

// ── Simple rate limiter: max 60 requests per IP per minute ──
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const now = Date.now();
  const entry = hits.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) {
    hits.set(ip, { count: 1, start: now });
  } else {
    entry.count++;
    if (entry.count > 60) {
      return res.status(429).json({ error: "Too many requests — slow down" });
    }
    hits.set(ip, entry);
  }
  next();
});

const EXCHANGES = {
  bybit:    "https://api.bybit.com",
  binance:  "https://api.binance.com",
  okx:      "https://www.okx.com",
  kucoin:   "https://api.kucoin.com",
  coinbase: "https://api.coinbase.com",
};

app.all("/proxy/:exchange/*", async (req, res) => {
  const base = EXCHANGES[req.params.exchange];
  if (!base) return res.status(400).json({ error: "Unknown exchange" });

  const apiPath = "/" + req.params[0];
  const qs = new URLSearchParams(req.query).toString();
  const url = `${base}${apiPath}${qs ? "?" + qs : ""}`;

  try {
    const upstream = await fetch(url, {
      method: req.method,
      headers: {
        ...Object.fromEntries(
          Object.entries(req.headers).filter(([k]) =>
            /^(x-bapi|ok-access|kc-api|cb-access|x-mbx|content-type)/i.test(k)
          )
        ),
      },
      body: ["POST", "PUT", "DELETE"].includes(req.method)
        ? JSON.stringify(req.body)
        : undefined,
    });

    const text = await upstream.text();
    res.status(upstream.status);
    upstream.headers.forEach((v, k) => {
      if (!["content-encoding", "transfer-encoding"].includes(k)) res.setHeader(k, v);
    });
    res.send(text);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Proxy running on port ${PORT}`));
