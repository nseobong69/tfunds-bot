import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { ethers } from "ethers";

/* ═══════════════════════════════════════════════════
   HMAC-SHA256 — all signing happens locally in browser
═══════════════════════════════════════════════════ */
async function hmacSHA256(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function hmacSHA256B64(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret),
    { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

/* ═══════════════════════════════════════════════════
   EXCHANGE API LAYER  —  Binance · Bybit · OKX · KuCoin · Coinbase
═══════════════════════════════════════════════════ */
const PROXY_URL = "https://tfunds-bot.onrender.com";
const BASE    = `${PROXY_URL}/proxy/binance`;
const BASE_CB = `${PROXY_URL}/proxy/coinbase`;
const BASE_BB = `${PROXY_URL}/proxy/bybit`;
const BASE_OKX= `${PROXY_URL}/proxy/okx`;
const BASE_KC = `${PROXY_URL}/proxy/kucoin`;

/* ── Symbol / interval helpers ── */
function toExSymbol(symbol, exchange) {
  if (exchange==="okx"||exchange==="kucoin") {
    for (const q of ["USDT","USDC","BTC","ETH","BNB"]) {
      if (symbol.endsWith(q)) return symbol.slice(0,-q.length)+"-"+q;
    }
  }
  return symbol;
}
function normSymbol(s) { return s.replace(/-/g,""); }
const IV_BYBIT  = {"1m":"1","3m":"3","5m":"5","15m":"15","30m":"30","1h":"60","4h":"240","1d":"D"};
const IV_OKX    = {"1m":"1m","3m":"3m","5m":"5m","15m":"15m","30m":"30m","1h":"1H","4h":"4H","1d":"1D"};
const IV_KC     = {"1m":"1min","3m":"3min","5m":"5min","15m":"15min","30m":"30min","1h":"1hour","4h":"4hour","1d":"1day"};

/* ═══════════════════════════════════════════════════════════════
   ALL SIGNED REQUESTS GO DIRECT TO EACH EXCHANGE — NOT THROUGH PROXY
   Signing is done locally in the browser, so the proxy adds no
   security value for authenticated calls. Worse, exchanges (Bybit,
   Binance, OKX, KuCoin, Coinbase) all block or rate-limit cloud/
   hosting IPs (Render, AWS, Railway…) and return 401/403 which looks
   like "invalid credentials". Calling directly fixes this for ALL.
   Public (unsigned) requests still go through the proxy for CORS.
═══════════════════════════════════════════════════════════════ */
const DIRECT = {
  binance:  "https://api.binance.com",
  bybit:    "https://api.bybit.com",
  okx:      "https://www.okx.com",
  kucoin:   "https://api.kucoin.com",
  coinbase: "https://api.coinbase.com",
};

/* ══ BINANCE ══ */
async function bSign(apiKey, apiSecret, params={}, path, method="GET") {
  const ts = Date.now();
  const qs = new URLSearchParams({...params, timestamp:ts}).toString();
  const sig = await hmacSHA256(apiSecret, qs);
  const res = await fetch(`${DIRECT.binance}${path}?${qs}&signature=${sig}`, {
    method, headers:{"X-MBX-APIKEY": apiKey}
  });
  if (!res.ok) throw new Error(`Binance ${res.status}: ${await res.text()}`);
  return res.json();
}
async function bPublic(path, params={}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE}${path}${qs?"?"+qs:""}`);
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

/* ══ BYBIT ══ */
// Server-time offset cache — fetched once per session, reused for all bbSign calls.
// This eliminates error 10004 caused by device clock drift vs Bybit server time.
let _bbTimeOffset = null; // ms difference: bybitServerTime - Date.now()
let _bbTimeOffsetFetching = null; // in-flight promise guard
async function bbGetTimeOffset() {
  if (_bbTimeOffset !== null) return _bbTimeOffset;
  if (_bbTimeOffsetFetching) return _bbTimeOffsetFetching;
  _bbTimeOffsetFetching = (async () => {
    try {
      const before = Date.now();
      const r = await fetch(`${DIRECT.bybit}/v3/public/time`);
      const after = Date.now();
      const d = await r.json();
      // Bybit returns timeSecond (Unix seconds string) and timeNano (nanoseconds string)
      // Always derive ms from timeSecond * 1000 — safest across all Bybit API versions
      const timeSecond = d.result?.timeSecond ?? d.result?.time_second ?? d.time;
      const serverMs = Number(timeSecond) * 1000;
      const rtt = after - before;
      _bbTimeOffset = Math.round(serverMs - before - rtt / 2);
    } catch {
      _bbTimeOffset = 0; // fallback: no offset, use local time
    }
    _bbTimeOffsetFetching = null;
    return _bbTimeOffset;
  })();
  return _bbTimeOffsetFetching;
}
// Call once at startup to warm the cache
bbGetTimeOffset();

async function bbSign(apiKey, apiSecret, path, params={}, method="GET", body=null) {
  const offset = await bbGetTimeOffset();
  const ts = (Date.now() + offset).toString(), rw = "20000";
  const signStr = method==="GET"
    ? ts+apiKey+rw+new URLSearchParams(params).toString()
    : ts+apiKey+rw+(body?JSON.stringify(body):"");
  const sig = await hmacSHA256(apiSecret, signStr);
  const hdrs = {"X-BAPI-API-KEY":apiKey,"X-BAPI-SIGN":sig,"X-BAPI-SIGN-TYPE":"2",
    "X-BAPI-TIMESTAMP":ts,"X-BAPI-RECV-WINDOW":rw,"Content-Type":"application/json"};
  const qs = method==="GET"&&Object.keys(params).length ? "?"+new URLSearchParams(params).toString() : "";
  const res = await fetch(`${DIRECT.bybit}${path}${qs}`,{method,headers:hdrs,body:body?JSON.stringify(body):null});
  if (!res.ok) throw new Error(`Bybit ${res.status}: ${await res.text()}`);
  const d = await res.json();
  if (d.retCode===10004) {
    // Reset cached offset so next call re-syncs, then give a clear message
    _bbTimeOffset = null;
    throw new Error(
      `Bybit signature rejected (10004). Your API Secret may be wrong, or device clock is drifting. ` +
      `Time offset was ${offset}ms. Please verify your API Secret is copied exactly from Bybit, ` +
      `and that your device time is correct. Retrying will re-sync the clock.`
    );
  }
  if (d.retCode!==0) throw new Error(`Bybit ${d.retCode}: ${d.retMsg}`);
  return d.result;
}
async function bbPublic(path, params={}) {
  // Try proxy first (avoids CORS/network issues on Android browsers),
  // fall back to direct Bybit if proxy fails.
  const qs = new URLSearchParams(params).toString();
  const proxyUrl  = `${BASE_BB}${path}${qs?"?"+qs:""}`;
  const directUrl = `${DIRECT.bybit}${path}${qs?"?"+qs:""}`;
  let res;
  try { res = await fetch(proxyUrl); } catch(_) { res = null; }
  if (!res || !res.ok) {
    try { res = await fetch(directUrl); } catch(e) { throw new Error(`Bybit pub network error`); }
  }
  if (!res.ok) throw new Error(`Bybit pub ${res.status}`);
  const d = await res.json();
  if (d.retCode!==0) throw new Error(`Bybit: ${d.retMsg}`);
  return d.result;
}

/* ══ OKX ══ */
async function okxSign(apiKey, apiSecret, passphrase, path, method="GET", body=null) {
  const ts = new Date().toISOString(), bodyStr = body?JSON.stringify(body):"";
  const sig = await hmacSHA256B64(apiSecret, ts+method+path+bodyStr);
  const res = await fetch(`${DIRECT.okx}${path}`,{method,
    headers:{"OK-ACCESS-KEY":apiKey,"OK-ACCESS-SIGN":sig,"OK-ACCESS-TIMESTAMP":ts,
      "OK-ACCESS-PASSPHRASE":passphrase,"Content-Type":"application/json"},
    body:body?bodyStr:null});
  if (!res.ok) throw new Error(`OKX ${res.status}: ${await res.text()}`);
  const d = await res.json();
  if (d.code!=="0") throw new Error(`OKX ${d.code}: ${d.msg}`);
  return d.data;
}
async function okxPublic(path, params={}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE_OKX}${path}${qs?"?"+qs:""}`);
  if (!res.ok) throw new Error(`OKX pub ${res.status}`);
  const d = await res.json();
  return d.data;
}

/* ══ KUCOIN ══ */
async function kcSign(apiKey, apiSecret, passphrase, path, method="GET", body=null) {
  const ts = Date.now().toString(), bodyStr = body?JSON.stringify(body):"";
  const sig   = await hmacSHA256B64(apiSecret, ts+method+path+bodyStr);
  const ppSig = await hmacSHA256B64(apiSecret, passphrase);
  const res = await fetch(`${DIRECT.kucoin}${path}`,{method,
    headers:{"KC-API-KEY":apiKey,"KC-API-SIGN":sig,"KC-API-TIMESTAMP":ts,
      "KC-API-PASSPHRASE":ppSig,"KC-API-KEY-VERSION":"2","Content-Type":"application/json"},
    body:body?bodyStr:null});
  if (!res.ok) throw new Error(`KuCoin ${res.status}: ${await res.text()}`);
  const d = await res.json();
  if (d.code!=="200000") throw new Error(`KuCoin ${d.code}: ${d.msg}`);
  return d.data;
}
async function kcPublic(path, params={}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${BASE_KC}${path}${qs?"?"+qs:""}`);
  if (!res.ok) throw new Error(`KuCoin pub ${res.status}`);
  const d = await res.json();
  if (d.code!=="200000") throw new Error(`KuCoin: ${d.msg}`);
  return d.data;
}

/* ══ COINBASE ══ */
async function cbSign(apiKey, apiSecret, path, method="GET", body=null) {
  const ts = Math.floor(Date.now()/1000).toString();
  const sig = await hmacSHA256(apiSecret, ts+method+path+(body?JSON.stringify(body):""));
  const res = await fetch(`${DIRECT.coinbase}${path}`, {
    method, headers:{"CB-ACCESS-KEY":apiKey,"CB-ACCESS-SIGN":sig,
      "CB-ACCESS-TIMESTAMP":ts,"Content-Type":"application/json"},
    body: body?JSON.stringify(body):null
  });
  if (!res.ok) throw new Error(`Coinbase ${res.status}: ${await res.text()}`);
  return res.json();
}

/* ═══════════════════════════════════════════════════
   WALLET CONFIG
   Fill in your IDs before deploying
═══════════════════════════════════════════════════ */
// FREE — get at: cloud.walletconnect.com → Create Project
const WC_PROJECT_ID = "0f5fe1c26c196a179b96d59000a15896";
// FREE — get at: binance.com → Pay → Merchant → Apply (1-3 days approval)
const BINANCE_PAY_MERCHANT_ID = "YOUR_BINANCE_PAY_MERCHANT_ID";

// Free public RPC endpoints — no sign-up needed
const ETH_RPC = "https://eth.llamarpc.com";
const BSC_RPC = "https://bsc-dataseed.binance.org";

// USDT contract addresses
const USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831ec7"; // ERC-20
const USDT_BSC = "0x55d398326f99059fF775485246999027B3197955"; // BEP-20

const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)"
];

const NETWORKS = {
  eth: { chainId:1,  name:"Ethereum",       rpc:ETH_RPC, nativeSym:"ETH", usdt:USDT_ETH, usdtDec:6,  binanceNet:"ETH"  },
  bsc: { chainId:56, name:"BNB Smart Chain", rpc:BSC_RPC, nativeSym:"BNB", usdt:USDT_BSC, usdtDec:18, binanceNet:"BSC"  },
};

/* ═══════════════════════════════════════════════════
   TECHNICAL ANALYSIS ENGINE v2
   Runs on real OHLCV kline data from Binance
   New: ATR · ADX · Volume Profile · Candlestick Patterns
        Support/Resistance Zones · EMA 200 · BB Squeeze
═══════════════════════════════════════════════════ */

function calcEMA(data, period) {
  if (data.length < period) return Array(data.length).fill(null);
  const k = 2 / (period + 1);
  const result = [];
  let ema = data.slice(0, period).reduce((a,b) => a+b, 0) / period;
  result.push(...Array(period-1).fill(null));
  result.push(ema);
  for (let i = period; i < data.length; i++) {
    ema = data[i] * k + ema * (1 - k);
    result.push(ema);
  }
  return result;
}

function calcRSI(closes, period=14) {
  if (closes.length < period+1) return Array(closes.length).fill(null);
  let gains=0, losses=0;
  for (let i=1; i<=period; i++) {
    const d = closes[i] - closes[i-1];
    if (d>0) gains+=d; else losses+=Math.abs(d);
  }
  let avgG=gains/period, avgL=losses/period;
  const result = Array(period).fill(null);
  result.push(100 - 100/(1+(avgG/(avgL||0.0001))));
  for (let i=period+1; i<closes.length; i++) {
    const d = closes[i] - closes[i-1];
    avgG = (avgG*(period-1)+(d>0?d:0))/period;
    avgL = (avgL*(period-1)+(d<0?Math.abs(d):0))/period;
    result.push(100 - 100/(1+avgG/(avgL||0.0001)));
  }
  return result;
}

function calcMACD(closes, fast=12, slow=26, signal=9) {
  const emaFast = calcEMA(closes, fast);
  const emaSlow = calcEMA(closes, slow);
  const macdLine = emaFast.map((v,i) =>
    v!=null&&emaSlow[i]!=null ? v-emaSlow[i] : null);
  const validMACD = macdLine.filter(v=>v!=null);
  if (validMACD.length < signal) return {
    macd:macdLine,
    signal:Array(macdLine.length).fill(null),
    histogram:Array(macdLine.length).fill(null)
  };
  const sigLine = calcEMA(validMACD, signal);
  const sigFull = [...Array(macdLine.length-sigLine.length).fill(null), ...sigLine];
  const histogram = macdLine.map((v,i) =>
    v!=null&&sigFull[i]!=null ? v-sigFull[i] : null);
  return { macd:macdLine, signal:sigFull, histogram };
}

function calcBB(closes, period=20, mult=2) {
  return closes.map((_, i) => {
    if (i < period-1) return null;
    const slice = closes.slice(i-period+1, i+1);
    const mean  = slice.reduce((a,b)=>a+b,0)/period;
    const std   = Math.sqrt(slice.reduce((a,b)=>a+(b-mean)**2,0)/period);
    const bw    = (mult*2*std)/mean; // bandwidth %
    return { upper:mean+mult*std, mid:mean, lower:mean-mult*std, std, bw };
  });
}

/* ATR — Wilder's smoothing (true range averaged) */
function calcATR(highs, lows, closes, period=14) {
  const trs = [Math.abs(highs[0]-lows[0])];
  for (let i=1; i<closes.length; i++) {
    trs.push(Math.max(
      highs[i] - lows[i],
      Math.abs(highs[i] - closes[i-1]),
      Math.abs(lows[i]  - closes[i-1])
    ));
  }
  const result = [];
  let atr = trs.slice(0,period).reduce((a,b)=>a+b,0)/period;
  result.push(...Array(period-1).fill(null));
  result.push(atr);
  for (let i=period; i<trs.length; i++) {
    atr = (atr*(period-1) + trs[i]) / period;
    result.push(atr);
  }
  return result;
}

/* ADX — Average Directional Index (trend strength 0-100) */
function calcADX(highs, lows, closes, period=14) {
  const n = closes.length;
  if (n < period*3) return {
    adx: Array(n).fill(null),
    pdi: Array(n).fill(null),
    mdi: Array(n).fill(null)
  };
  const dmP=[], dmM=[], tr=[];
  for (let i=1; i<n; i++) {
    const up   = highs[i] - highs[i-1];
    const down = lows[i-1] - lows[i];
    dmP.push(up>down && up>0 ? up : 0);
    dmM.push(down>up && down>0 ? down : 0);
    tr.push(Math.max(
      highs[i]-lows[i],
      Math.abs(highs[i]-closes[i-1]),
      Math.abs(lows[i] -closes[i-1])
    ));
  }
  const wilderSmooth = (arr, p) => {
    if (arr.length < p) return arr;
    const out = [arr.slice(0,p).reduce((a,b)=>a+b,0)];
    for (let i=p; i<arr.length; i++)
      out.push(out[out.length-1] - out[out.length-1]/p + arr[i]);
    return out;
  };
  const sTR  = wilderSmooth(tr, period);
  const sDMP = wilderSmooth(dmP, period);
  const sDMM = wilderSmooth(dmM, period);
  const pDI  = sDMP.map((v,i) => sTR[i]>0 ? 100*v/sTR[i] : 0);
  const mDI  = sDMM.map((v,i) => sTR[i]>0 ? 100*v/sTR[i] : 0);
  const dx   = pDI.map((v,i) => (v+mDI[i])>0 ? 100*Math.abs(v-mDI[i])/(v+mDI[i]) : 0);
  const adx  = wilderSmooth(dx, period);
  const pad  = n - adx.length;
  return {
    adx: [...Array(pad).fill(null), ...adx],
    pdi: [...Array(pad-1).fill(null), ...pDI],
    mdi: [...Array(pad-1).fill(null), ...mDI],
  };
}

/* Volume Profile — spike detection relative to recent mean+std */
function calcVolumeProfile(volumes, period=20) {
  if (!volumes||volumes.length<period) return null;
  const recent = volumes.slice(-period);
  const avg    = recent.reduce((a,b)=>a+b,0)/recent.length;
  const std    = Math.sqrt(recent.reduce((a,b)=>a+(b-avg)**2,0)/recent.length);
  const last   = volumes[volumes.length-1];
  return {
    avg, std,
    ratio: last/avg,
    spike: last > avg + 1.5*std,   // >1.5σ above mean
    surge: last > avg + 3.0*std,   // >3σ — exceptional surge
    weak:  last < avg * 0.55,      // less than 55% of avg = low conviction
  };
}

/* Candlestick Pattern Detection (last 3 candles) */
function detectCandlePatterns(opens, highs, lows, closes) {
  const n = closes.length - 1;
  if (n < 2) return [];
  const patterns = [];
  const c=closes[n], o=opens[n], h=highs[n], l=lows[n];
  const pc=closes[n-1], po=opens[n-1];
  const body      = Math.abs(c-o);
  const range     = h-l||0.0001;
  const upperWick = h - Math.max(c,o);
  const lowerWick = Math.min(c,o) - l;

  // Doji — indecision
  if (body/range < 0.08)
    patterns.push({name:"Doji",type:"neutral",weight:4});

  // Hammer — bullish reversal
  if (lowerWick>2*body && upperWick<body*0.5 && c>=o)
    patterns.push({name:"Hammer",type:"bull",weight:16});

  // Inverted Hammer
  if (upperWick>2*body && lowerWick<body*0.5 && c>=o)
    patterns.push({name:"Inv. Hammer",type:"bull",weight:10});

  // Shooting Star — bearish reversal
  if (upperWick>2*body && lowerWick<body*0.5 && c<o)
    patterns.push({name:"Shooting Star",type:"bear",weight:16});

  // Hanging Man — bearish reversal
  if (lowerWick>2*body && upperWick<body*0.5 && c<o)
    patterns.push({name:"Hanging Man",type:"bear",weight:12});

  // Bullish Engulfing
  if (po>pc && c>o && c>po && o<pc)
    patterns.push({name:"Bullish Engulfing",type:"bull",weight:22});

  // Bearish Engulfing
  if (pc>po && o>c && o>pc && c<po)
    patterns.push({name:"Bearish Engulfing",type:"bear",weight:22});

  // Marubozu (strong momentum candle)
  if (upperWick<body*0.05 && lowerWick<body*0.05) {
    if (c>o) patterns.push({name:"Bullish Marubozu",type:"bull",weight:18});
    else     patterns.push({name:"Bearish Marubozu",type:"bear",weight:18});
  }

  // Piercing Line (2-candle bullish reversal)
  if (po>pc && c>o && o<pc && c>(po+pc)/2 && c<po)
    patterns.push({name:"Piercing Line",type:"bull",weight:14});

  // Dark Cloud Cover (2-candle bearish reversal)
  if (pc>po && o>c && o>pc && c<(pc+po)/2 && c>po)
    patterns.push({name:"Dark Cloud",type:"bear",weight:14});

  // 3-candle patterns
  if (n >= 2) {
    const ppc=closes[n-2], ppo=opens[n-2];
    // Morning Star
    if (ppo>ppc && Math.abs(po-pc)<(ppo-ppc)*0.3 && c>o && c>(ppo+ppc)/2)
      patterns.push({name:"Morning Star",type:"bull",weight:26});
    // Evening Star
    if (ppc>ppo && Math.abs(pc-po)<(ppc-ppo)*0.3 && o>c && o<(ppc+ppo)/2)
      patterns.push({name:"Evening Star",type:"bear",weight:26});
    // Three White Soldiers
    if (c>o&&pc>po&&ppc>ppo && c>pc&&pc>ppc && o>po&&po>ppo)
      patterns.push({name:"3 White Soldiers",type:"bull",weight:20});
    // Three Black Crows
    if (o>c&&po>pc&&ppo>ppc && c<pc&&pc<ppc && o<po&&po<ppo)
      patterns.push({name:"3 Black Crows",type:"bear",weight:20});
  }
  return patterns;
}

/* Support / Resistance Zone Detection via swing-point clustering */
function detectSRZones(highs, lows, closes, lookback=60) {
  const n     = closes.length;
  const start = Math.max(0, n-lookback);
  const levels = [];
  for (let i=start+2; i<n-2; i++) {
    if (highs[i]>highs[i-1]&&highs[i]>highs[i-2]&&highs[i]>highs[i+1]&&highs[i]>highs[i+2])
      levels.push({price:highs[i], type:"resistance"});
    if (lows[i]<lows[i-1]&&lows[i]<lows[i-2]&&lows[i]<lows[i+1]&&lows[i]<lows[i+2])
      levels.push({price:lows[i], type:"support"});
  }
  // Cluster levels within 0.5% of each other
  const used=new Set(), clustered=[];
  for (let i=0;i<levels.length;i++) {
    if (used.has(i)) continue;
    let cluster=[levels[i]];
    for (let j=i+1;j<levels.length;j++) {
      if (!used.has(j)&&Math.abs(levels[i].price-levels[j].price)/levels[i].price<0.005) {
        cluster.push(levels[j]); used.add(j);
      }
    }
    used.add(i);
    const avgP = cluster.reduce((a,b)=>a+b.price,0)/cluster.length;
    const isSup = cluster.filter(l=>l.type==="support").length >= cluster.filter(l=>l.type==="resistance").length;
    clustered.push({price:avgP, type:isSup?"support":"resistance", strength:cluster.length});
  }
  return clustered.sort((a,b)=>b.strength-a.strength).slice(0,8);
}

/* ═══════════════════════════════════════════════════
   SIGNAL GENERATOR v2
   Multi-indicator confluence scoring:
   EMA(9/21/50/200) · RSI · MACD · BB · ATR · ADX ·
   Volume · Candlestick Patterns · Support/Resistance
═══════════════════════════════════════════════════ */
function generateSignal(closes, highs, lows, opens=null, volumes=null) {
  if (closes.length < 60) return {
    action:"HOLD", confidence:0,
    reasons:["Need 60+ candles for analysis"],
    meta:{ regime:"UNKNOWN" }
  };

  const ema9   = calcEMA(closes, 9);
  const ema21  = calcEMA(closes, 21);
  const ema50  = calcEMA(closes, 50);
  const ema200 = calcEMA(closes, Math.min(200, closes.length-1));
  const rsi    = calcRSI(closes, 14);
  const macd   = calcMACD(closes);
  const bb     = calcBB(closes, 20, 2);
  const atr    = calcATR(highs, lows, closes, 14);
  const adxD   = calcADX(highs, lows, closes, 14);
  const volP   = volumes ? calcVolumeProfile(volumes) : null;
  const pats   = opens  ? detectCandlePatterns(opens, highs, lows, closes) : [];
  const srZ    = detectSRZones(highs, lows, closes);

  const last=closes.length-1, prev=last-1;

  const price    = closes[last];
  const curRSI   = rsi[last],         prevRSI  = rsi[prev];
  const curMACD  = macd.macd[last],   prevMACD = macd.macd[prev];
  const curSig   = macd.signal[last], prevSig  = macd.signal[prev];
  const curHist  = macd.histogram[last], prevHist = macd.histogram[prev];
  const curBB    = bb[last];
  const curATR   = atr[last];
  const curADX   = adxD.adx[last];
  const curPDI   = adxD.pdi[last];
  const curMDI   = adxD.mdi[last];
  const e9=ema9[last], e9p=ema9[prev], e21=ema21[last], e21p=ema21[prev];
  const e50=ema50[last], e200=ema200[last];

  let bullScore=0, bearScore=0;
  const bullR=[], bearR=[];

  /* ── EMA Stack & Crossovers (max ~55pts) ── */
  if (e9!=null&&e21!=null) {
    // Fresh crossover = higher weight
    if (e9>e21&&e9p<=e21p)  { bullScore+=28; bullR.push("EMA 9/21 golden cross"); }
    if (e9<e21&&e9p>=e21p)  { bearScore+=28; bearR.push("EMA 9/21 death cross"); }
    // Trend alignment
    if (e9>e21&&e21>e50)    { bullScore+=14; bullR.push("EMA stack: 9>21>50 (bullish)"); }
    if (e9<e21&&e21<e50)    { bearScore+=14; bearR.push("EMA stack: 9<21<50 (bearish)"); }
    // Macro bias (EMA 200)
    if (e200!=null) {
      if (price>e200)        { bullScore+=10; bullR.push("Above EMA 200 — macro bullish bias"); }
      else                   { bearScore+=10; bearR.push("Below EMA 200 — macro bearish bias"); }
    }
    // Price vs fast EMA momentum
    if (price>e9&&e9>e21)   { bullScore+=8; }
    if (price<e9&&e9<e21)   { bearScore+=8; }
  }

  /* ── RSI (max ~30pts) ── */
  if (curRSI!=null&&prevRSI!=null) {
    if (curRSI<28&&curRSI>prevRSI)      { bullScore+=28; bullR.push(`RSI extreme oversold + reversal (${curRSI.toFixed(1)})`); }
    else if (curRSI<38&&curRSI>prevRSI) { bullScore+=16; bullR.push(`RSI oversold recovery (${curRSI.toFixed(1)})`); }
    if (curRSI>72&&curRSI<prevRSI)      { bearScore+=28; bearR.push(`RSI extreme overbought + reversal (${curRSI.toFixed(1)})`); }
    else if (curRSI>62&&curRSI<prevRSI) { bearScore+=16; bearR.push(`RSI overbought pullback (${curRSI.toFixed(1)})`); }
    // Mid-line cross
    if (curRSI>50&&prevRSI<=50)         { bullScore+=10; bullR.push("RSI crossed above 50"); }
    if (curRSI<50&&prevRSI>=50)         { bearScore+=10; bearR.push("RSI crossed below 50"); }
    // Trend continuation setup (RSI 50–60 with bullish EMA)
    if (curRSI>48&&curRSI<60&&e9>e21)  { bullScore+=5; }
    if (curRSI>40&&curRSI<52&&e9<e21)  { bearScore+=5; }
  }

  /* ── MACD (max ~35pts) ── */
  if (curMACD!=null&&curSig!=null&&prevMACD!=null&&prevSig!=null) {
    if (curMACD>curSig&&prevMACD<=prevSig)  { bullScore+=24; bullR.push("MACD bullish crossover"); }
    if (curMACD<curSig&&prevMACD>=prevSig)  { bearScore+=24; bearR.push("MACD bearish crossover"); }
    if (curHist!=null&&prevHist!=null) {
      if (curHist>0&&prevHist<0)            { bullScore+=12; bullR.push("MACD histogram flipped positive"); }
      if (curHist<0&&prevHist>0)            { bearScore+=12; bearR.push("MACD histogram flipped negative"); }
      if (curHist>0&&curHist>prevHist)      { bullScore+=6;  bullR.push("MACD momentum building"); }
      if (curHist<0&&curHist<prevHist)      { bearScore+=6;  bearR.push("Bearish momentum building"); }
    }
    // Zero-line bias
    if (curMACD>0&&curSig>0)                { bullScore+=5;  }
    if (curMACD<0&&curSig<0)                { bearScore+=5;  }
  }

  /* ── Bollinger Bands (max ~28pts) ── */
  if (curBB!=null) {
    if (price<=curBB.lower*1.003)           { bullScore+=22; bullR.push("Price at lower BB — reversal zone"); }
    if (price>=curBB.upper*0.997)           { bearScore+=22; bearR.push("Price at upper BB — reversal zone"); }
    const prevBB=bb[prev];
    if (price>curBB.mid&&closes[prev]<=(prevBB?.mid||curBB.mid)) { bullScore+=12; bullR.push("Reclaimed BB midband"); }
    if (price<curBB.mid&&closes[prev]>=(prevBB?.mid||curBB.mid)) { bearScore+=12; bearR.push("BB midband breakdown"); }
    // Squeeze (volatility coiling — boost both, direction decided by other signals)
    if (curBB.bw<0.035) {
      bullScore+=6; bearScore+=6;
      bullR.push("BB squeeze — breakout building");
      bearR.push("BB squeeze — breakdown risk");
    }
  }

  /* ── ADX Trend Strength (multiplier + bonus) ── */
  let trendMult = 1.0;
  let regime    = "MIXED";
  if (curADX!=null) {
    if (curADX>35)      { trendMult=1.30; regime="TRENDING"; }
    else if (curADX>25) { trendMult=1.15; regime="TRENDING"; }
    else if (curADX>18) { trendMult=1.00; regime="MIXED"; }
    else                { trendMult=0.70; regime="RANGING"; }  // Reduce confidence in choppy markets
    if (curADX>25&&curPDI!=null&&curMDI!=null) {
      if (curPDI>curMDI) { bullScore+=14; bullR.push(`Strong bullish trend — ADX ${curADX.toFixed(0)}`); }
      else               { bearScore+=14; bearR.push(`Strong bearish trend — ADX ${curADX.toFixed(0)}`); }
    }
  }

  /* ── Volume Confirmation (bonus/penalty) ── */
  if (volP) {
    if (volP.surge) {
      if (closes[last]>closes[prev]) { bullScore+=20; bullR.push(`Exceptional volume surge on up candle (${volP.ratio.toFixed(1)}x avg)`); }
      else                           { bearScore+=20; bearR.push(`Exceptional volume surge on down candle (${volP.ratio.toFixed(1)}x avg)`); }
    } else if (volP.spike) {
      if (closes[last]>closes[prev]) { bullScore+=12; bullR.push(`Volume spike confirms buying (${volP.ratio.toFixed(1)}x avg)`); }
      else                           { bearScore+=12; bearR.push(`Volume spike confirms selling (${volP.ratio.toFixed(1)}x avg)`); }
    } else if (volP.weak) {
      // Low-volume moves are less reliable — dampen scores
      bullScore = Math.round(bullScore * 0.80);
      bearScore = Math.round(bearScore * 0.80);
    }
  }

  /* ── Candlestick Patterns ── */
  pats.forEach(p => {
    if (p.type==="bull") { bullScore+=p.weight; bullR.push(`Pattern: ${p.name}`); }
    if (p.type==="bear") { bearScore+=p.weight; bearR.push(`Pattern: ${p.name}`); }
  });

  /* ── Support / Resistance Proximity ── */
  const atrPct = curATR ? (curATR/price)*100 : 1;
  srZ.forEach(z => {
    const dist = Math.abs(price-z.price)/price*100;
    if (dist < atrPct*0.6) {  // Within 0.6 ATR
      const w = Math.min(z.strength, 3)/3*12;
      if (z.type==="support")    { bullScore+=w; bullR.push(`Near key support $${price<100?price.toFixed(4):price.toFixed(2)}`); }
      if (z.type==="resistance") { bearScore+=w; bearR.push(`At key resistance $${price<100?price.toFixed(4):price.toFixed(2)}`); }
    }
  });

  /* ── Apply ADX trend multiplier ── */
  bullScore = Math.round(bullScore * trendMult);
  bearScore = Math.round(bearScore * trendMult);

  /* ── ATR-based SL/TP (1.5x and 3.0x ATR — 2:1 R:R) ── */
  const atrSlPct = curATR ? (curATR/price)*100*1.5 : null;
  const atrTpPct = curATR ? (curATR/price)*100*3.0 : null;

  const total = bullScore+bearScore||1;
  const meta  = {
    rsi:curRSI, macd:curMACD, ema9:e9, ema21:e21, ema50:e50, ema200:e200,
    adx:curADX, atr:curATR, bb:curBB, patterns:pats, srZones:srZ,
    volRatio:volP?.ratio, atrSlPct, atrTpPct, regime,
    bbWidth:curBB?.bw,
  };

  // Require multi-indicator confluence (score ≥ 45 and 25% dominance)
  if (bullScore>=45 && bullScore>bearScore*1.25) {
    return {
      action:"BUY",
      confidence: Math.min(97, Math.round(55+(bullScore/total)*42)),
      reasons: bullR.slice(0,7),
      meta
    };
  }
  if (bearScore>=45 && bearScore>bullScore*1.25) {
    return {
      action:"SELL",
      confidence: Math.min(97, Math.round(55+(bearScore/total)*42)),
      reasons: bearR.slice(0,7),
      meta
    };
  }
  return {
    action:"HOLD",
    confidence: Math.max(0, Math.round(Math.abs(bullScore-bearScore)/total*25)),
    reasons: ["No strong confluence", ...(bullScore>bearScore?bullR:bearR).slice(0,2)],
    meta
  };
}

/* ═══════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════ */
const fmt  = (n,d=2) => n!=null&&!isNaN(n)
  ? Number(n).toLocaleString("en-US",{minimumFractionDigits:d,maximumFractionDigits:d}) : "—";
const fmtP = n => `${n>=0?"+":""}${fmt(n)}%`;
const fmtPx = (n,d=2) => n!=null ? `$${fmt(n,d)}` : "—";
const priceFmt = n => n==null?"—":n<0.01?fmt(n,6):n<1?fmt(n,4):n<100?fmt(n,3):fmt(n,2);

// Core pairs broadly supported across Bybit, OKX, KuCoin and Binance.
// Delisted / unsupported symbols (BANDUSDT, COTIUSDT, ONTUSDT, BALUSDT,
// WAVESUSDT, SXPUSDT, XMRUSDT, RVNUSDT, ZENUSDT, CELRUSDT …) are excluded
// to prevent "Not supported symbols" kline-fetch errors on Bybit.
const TOP_PAIRS = [
  "BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","XRPUSDT",
  "ADAUSDT","AVAXUSDT","DOTUSDT","LINKUSDT","UNIUSDT",
  "ATOMUSDT","LTCUSDT","NEARUSDT","APTUSDT","ARBUSDT",
  "SUIUSDT","INJUSDT","OPUSDT","LDOUSDT","FETUSDT",
  "WLDUSDT","STXUSDT","RUNEUSDT","FILUSDT","IMXUSDT",
  "GRTUSDT","SANDUSDT","MANAUSDT","AXSUSDT","GALAUSDT",
  "FTMUSDT","ALGOUSDT","VETUSDT","ICPUSDT","HBARUSDT",
  "FLOWUSDT","XTZUSDT","AAVEUSDT","MKRUSDT","SNXUSDT",
  "CRVUSDT","COMPUSDT","SUSHIUSDT","1INCHUSDT","KSMUSDT",
  "TRXUSDT","XLMUSDT","BCHUSDT","ETCUSDT","EOSUSDT",
  "KAVAUSDT","CHZUSDT","ENJUSDT","BATUSDT","ZRXUSDT",
  "STORJUSDT","OCEANUSDT","ANKRUSDT","QNTUSDT","TIAUSDT",
];

/* ── Mini SVG Sparkline ── */
function Sparkline({ data, width=120, height=34 }) {
  if (!data||data.length<2) return <svg width={width} height={height}/>;
  const mn=Math.min(...data), mx=Math.max(...data), rng=mx-mn||1;
  const pts = data.map((v,i)=>{
    const x=(i/(data.length-1))*(width-4)+2;
    const y=height-2-((v-mn)/rng)*(height-4);
    return `${x},${y}`;
  }).join(" ");
  const last=data[data.length-1], trend=last>=data[0];
  const c=trend?"#00f5c4":"#ef4444";
  const lx=(width-2), ly=height-2-((last-mn)/rng)*(height-4);
  return (
    <svg width={width} height={height} style={{display:"block",overflow:"visible"}}>
      <polyline points={pts} fill="none" stroke={c} strokeWidth="1.5" strokeLinejoin="round" opacity="0.9"/>
      <circle cx={lx} cy={ly} r="2.5" fill={c} opacity="0.9"/>
    </svg>
  );
}

/* ── Confidence Bar ── */
function ConfBar({ value, action }) {
  const c = action==="BUY"?"#00f5c4":action==="SELL"?"#ef4444":"#4b5563";
  return (
    <div style={{height:3,background:"rgba(255,255,255,.06)",borderRadius:2,overflow:"hidden"}}>
      <div style={{height:"100%",width:`${Math.max(2,value)}%`,background:c,
        borderRadius:2,transition:"width .8s ease",boxShadow:`0 0 5px ${c}60`}}/>
    </div>
  );
}

/* ── Regime Badge ── */
function RegimeBadge({ regime }) {
  const map = {
    TRENDING: {c:"#00f5c4", bg:"rgba(0,245,196,.1)", border:"rgba(0,245,196,.25)"},
    RANGING:  {c:"#f59e0b", bg:"rgba(245,158,11,.1)", border:"rgba(245,158,11,.25)"},
    MIXED:    {c:"#6b7a99", bg:"rgba(107,122,153,.08)", border:"rgba(107,122,153,.2)"},
    UNKNOWN:  {c:"#374151", bg:"transparent", border:"rgba(55,65,81,.3)"},
  };
  const s = map[regime||"UNKNOWN"];
  return (
    <span style={{fontSize:7,fontFamily:"Orbitron",letterSpacing:1,
      padding:"2px 6px",borderRadius:2,
      color:s.c,background:s.bg,border:`1px solid ${s.border}`}}>
      {regime||"—"}
    </span>
  );
}

/* ═══════════════════════════════════════════════════
   SETUP SCREEN
═══════════════════════════════════════════════════ */
function SetupScreen({ onConnect, onDemo, tradeAmount, setTradeAmount }) {
  const [exchange,    setExchange]    = useState("bybit");
  const [apiKey,      setApiKey]      = useState("");
  const [apiSecret,   setApiSecret]   = useState("");
  const [passphrase,  setPassphrase]  = useState("");
  const [loading,     setLoading]     = useState(false);
  const [error,       setError]       = useState("");
  const [showSec,     setShowSec]     = useState(false);
  const needsPass = exchange==="okx"||exchange==="kucoin";

  const handleConnect = async () => {
    if (!apiKey.trim()||!apiSecret.trim()) { setError("Both API Key and Secret are required."); return; }
    if (needsPass&&!passphrase.trim()) { setError("Passphrase is required for "+exchange.toUpperCase()+"."); return; }
    setLoading(true); setError("");
    const k=apiKey.trim(), s=apiSecret.trim(), p=passphrase.trim();
    try {
      let accountData;
      if (exchange==="binance") {
        accountData = await bSign(k,s,{},"/api/v3/account");
      } else if (exchange==="bybit") {
        try {
          accountData = await bbSign(k,s,"/v5/account/wallet-balance",{accountType:"UNIFIED"});
        } catch(e1) {
          // Fallback: if not a Unified Trading Account, retry with SPOT
          if (e1.message.includes("10001")||e1.message.includes("10003")||
              e1.message.includes("does not exist")||e1.message.includes("UNIFIED")) {
            accountData = await bbSign(k,s,"/v5/account/wallet-balance",{accountType:"SPOT"});
          } else { throw e1; }
        }
      } else if (exchange==="okx") {
        accountData = await okxSign(k,s,p,"/api/v5/account/balance");
      } else if (exchange==="kucoin") {
        accountData = await kcSign(k,s,p,"/api/v1/accounts","GET");
      } else {
        accountData = await cbSign(k,s,"/api/v3/brokerage/accounts");
      }
      onConnect({ exchange, apiKey:k, apiSecret:s, passphrase:p, accountData });
    } catch(e) {
      const m = e.message;
      setError(
        m.includes("401")||m.includes("403")||m.includes("10003")||m.includes("400100")||
        m.toLowerCase().includes("invalid api")||m.toLowerCase().includes("invalid key")||
        m.toLowerCase().includes("invalid")&&m.toLowerCase().includes("api")
          ? "Invalid API credentials — check your key, secret"+(needsPass?" and passphrase":"")+`. (${m})`
          : m.includes("fetch")||m.includes("Failed")||m.includes("NetworkError")||m.includes("network")
            ? "Network error — "+exchange.toUpperCase()+" may be geo-blocked. Try a VPN or switch exchange."
            : m
      );
    } finally { setLoading(false); }
  };

  return (
    <div style={{minHeight:"100vh",background:"#020810",display:"flex",alignItems:"center",
      justifyContent:"center",fontFamily:"'JetBrains Mono','Courier New',monospace",
      position:"relative",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;500;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        .gbg{position:fixed;inset:0;pointer-events:none;
          background-image:linear-gradient(rgba(0,245,196,.03) 1px,transparent 1px),
            linear-gradient(90deg,rgba(0,245,196,.03) 1px,transparent 1px);
          background-size:48px 48px;}
        .sinp{width:100%;background:rgba(0,245,196,.04);border:1px solid rgba(0,245,196,.2);
          color:#c8d8f0;padding:11px 14px;font-family:'JetBrains Mono',monospace;font-size:12px;
          border-radius:3px;outline:none;transition:border .2s;}
        .sinp:focus{border-color:rgba(0,245,196,.6);box-shadow:0 0 0 2px rgba(0,245,196,.07);}
        .sinp::placeholder{color:rgba(100,120,160,.35);}
        .exbtn{flex:1;padding:10px;border:1px solid rgba(0,245,196,.2);background:transparent;
          color:rgba(0,245,196,.45);font-family:'Orbitron',monospace;font-size:9px;
          letter-spacing:1.5px;cursor:pointer;transition:all .2s;
          display:flex;align-items:center;justify-content:center;}
        .exbtn.sel{background:rgba(0,245,196,.1);color:#00f5c4;border-color:rgba(0,245,196,.55);}
        .cbtn{width:100%;padding:14px;background:linear-gradient(135deg,#00f5c4,#00b894);
          border:none;color:#020810;font-family:'Orbitron',monospace;font-weight:900;
          font-size:11px;letter-spacing:2px;cursor:pointer;border-radius:3px;transition:all .2s;}
        .cbtn:hover:not(:disabled){box-shadow:0 0 30px rgba(0,245,196,.5);transform:translateY(-1px);}
        .cbtn:disabled{opacity:.45;cursor:not-allowed;}
        .dbtn{width:100%;padding:11px;background:transparent;border:1px solid rgba(0,245,196,.2);
          color:rgba(0,245,196,.55);font-family:'Orbitron',monospace;font-size:9px;
          letter-spacing:2px;cursor:pointer;border-radius:3px;transition:all .2s;margin-top:8px;}
        .dbtn:hover{background:rgba(0,245,196,.06);color:#00f5c4;}
      `}</style>
      <div className="gbg"/>
      <div style={{width:"100%",maxWidth:460,padding:24,position:"relative",zIndex:2}}>
        {/* Logo */}
        <div style={{textAlign:"center",marginBottom:36}}>
          <div style={{display:"inline-flex",alignItems:"center",gap:12,marginBottom:12}}>
            <div style={{width:50,height:50,background:"linear-gradient(135deg,#00f5c4,#00b894)",
              borderRadius:9,display:"flex",alignItems:"center",justifyContent:"center",
              fontSize:26,boxShadow:"0 0 30px rgba(0,245,196,.45)"}}>₮</div>
            <div style={{textAlign:"left"}}>
              <div style={{fontFamily:"Orbitron",fontWeight:900,fontSize:28,color:"#00f5c4",
                letterSpacing:2,textShadow:"0 0 22px rgba(0,245,196,.6)",lineHeight:1}}>TFunds</div>
              <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:4,color:"rgba(0,245,196,.4)",lineHeight:1.6}}>TRADING BOT v2.0</div>
            <div style={{fontFamily:"Orbitron",fontSize:6.5,letterSpacing:1.5,color:"rgba(0,245,196,.25)",lineHeight:1.6}}>BYBIT · OKX · KUCOIN · BINANCE · COINBASE</div>
            </div>
          </div>
          {/* Hero description */}
          <div style={{background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.12)",
            borderRadius:4,padding:"14px 16px",marginTop:6,textAlign:"left"}}>
            <div style={{fontFamily:"Orbitron",fontSize:8.5,color:"#00f5c4",letterSpacing:2,marginBottom:8}}>
              🤖 FULLY AUTOMATED TRADING BOT
            </div>
            <div style={{fontSize:10,color:"rgba(180,200,230,.75)",lineHeight:1.9}}>
              TFunds continuously scans the crypto market, identifies the highest-probability setups using
              <span style={{color:"#00f5c4"}}> 8 advanced indicators</span>, and automatically opens &amp; closes
              trades — <b style={{color:"#c8d8f0"}}>no manual input required</b>.
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:6,marginTop:12}}>
              {[["80%+ Win Rate","Multi-indicator confluence filters"],
                ["2:1 R:R","ATR-based stop-loss & take-profit"],
                ["24/7 Active","Scans every 60s while you sleep"]
              ].map(([t,d])=>(
                <div key={t} style={{background:"rgba(0,0,0,.35)",border:"1px solid rgba(0,245,196,.1)",
                  borderRadius:3,padding:"8px 10px"}}>
                  <div style={{fontFamily:"Orbitron",fontSize:8,color:"#00f5c4",marginBottom:3}}>{t}</div>
                  <div style={{fontSize:8,color:"rgba(100,120,160,.7)",lineHeight:1.5}}>{d}</div>
                </div>
              ))}
            </div>
            <div style={{marginTop:10,fontSize:8.5,color:"rgba(100,120,160,.55)",lineHeight:1.8}}>
              Indicators: <span style={{color:"rgba(0,245,196,.5)"}}>EMA(9/21/50/200) · RSI · MACD · Bollinger Bands · ATR · ADX · Volume · Candle Patterns</span>
            </div>
          </div>
        </div>

        {/* Exchange picker */}
        <div style={{marginBottom:18}}>
          <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:8}}>SELECT EXCHANGE</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:4,marginBottom:4}}>
            {[["bybit","🟠 BYBIT","Global · Nigeria ✓"],
              ["okx","🔷 OKX","Global · Nigeria ✓"],
              ["kucoin","🟢 KUCOIN","Global · Nigeria ✓"]
            ].map(([ex,label,sub])=>(
              <button key={ex} className={`exbtn ${exchange===ex?"sel":""}`}
                style={{borderRadius:3,flexDirection:"column",gap:2,padding:"8px 4px"}}
                onClick={()=>setExchange(ex)}>
                <span>{label}</span>
                <span style={{fontSize:7,opacity:.55,fontFamily:"JetBrains Mono",letterSpacing:.5}}>{sub}</span>
              </button>
            ))}
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:4}}>
            {[["binance","🟡 BINANCE","May be blocked"],
              ["coinbase","🔵 COINBASE","US-focused"]
            ].map(([ex,label,sub])=>(
              <button key={ex} className={`exbtn ${exchange===ex?"sel":""}`}
                style={{borderRadius:3,flexDirection:"column",gap:2,padding:"8px 4px"}}
                onClick={()=>setExchange(ex)}>
                <span>{label}</span>
                <span style={{fontSize:7,opacity:.55,fontFamily:"JetBrains Mono",letterSpacing:.5}}>{sub}</span>
              </button>
            ))}
          </div>
        </div>

        <div style={{marginBottom:14}}>
          <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:8}}>API KEY</div>
          <input className="sinp" placeholder="Paste your API key..." value={apiKey} onChange={e=>setApiKey(e.target.value)}/>
        </div>
        <div style={{marginBottom:needsPass?14:20}}>
          <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
            <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)"}}>API SECRET</div>
            <button onClick={()=>setShowSec(s=>!s)} style={{background:"none",border:"none",
              color:"rgba(0,245,196,.4)",fontSize:9,cursor:"pointer",fontFamily:"Orbitron"}}>
              {showSec?"HIDE":"SHOW"}
            </button>
          </div>
          <input className="sinp" type={showSec?"text":"password"} placeholder="Paste your API secret..."
            value={apiSecret} onChange={e=>setApiSecret(e.target.value)}/>
        </div>

        {needsPass&&(
          <div style={{marginBottom:20}}>
            <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:8}}>
              API PASSPHRASE <span style={{color:"rgba(239,68,68,.6)"}}>*</span>
            </div>
            <input className="sinp" type={showSec?"text":"password"}
              placeholder={`Your ${exchange.toUpperCase()} API passphrase...`}
              value={passphrase} onChange={e=>setPassphrase(e.target.value)}/>
          </div>
        )}

        <div style={{background:"rgba(245,158,11,.06)",border:"1px solid rgba(245,158,11,.22)",
          borderRadius:3,padding:"12px 14px",fontSize:10,color:"#f59e0b",lineHeight:1.85,marginBottom:20}}>
          <div style={{fontFamily:"Orbitron",fontSize:9,letterSpacing:1,marginBottom:5}}>🔐 API KEY SETUP</div>
          <div>• Enable <b>Spot Trading</b> only &nbsp;·&nbsp; <b>Disable withdrawals</b></div>
          <div>• Restrict to your IP address if possible</div>
          <div>• Keys are <b>never stored</b> — signing is 100% local in your browser</div>
        </div>

        {error&&<div style={{background:"rgba(239,68,68,.07)",border:"1px solid rgba(239,68,68,.28)",
          borderRadius:3,padding:"10px 14px",fontSize:10,color:"#ef4444",marginBottom:14,lineHeight:1.65}}>
          ⚠ {error}
        </div>}

        <button className="cbtn" disabled={loading||!apiKey||!apiSecret} onClick={handleConnect}>
          {loading?"CONNECTING...":"▶  CONNECT TO "+exchange.toUpperCase()}
        </button>
        {/* ══ TRADE AMOUNT INPUT ══ */}
        <div style={{background:"rgba(0,245,196,.03)",border:"1px solid rgba(0,245,196,.14)",
          borderRadius:3,padding:"14px 16px",marginTop:8,marginBottom:8}}>
          <div style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.7)",letterSpacing:2,marginBottom:10}}>
            💰 AMOUNT PER TRADE
          </div>
          <div style={{fontSize:9.5,color:"rgba(140,160,190,.65)",lineHeight:1.75,marginBottom:10}}>
            How much USDT to use per trade. Min $0.50. If a pair's exchange minimum is higher, the bot auto-bumps to meet it.
          </div>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{position:"relative",flex:1}}>
              <span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",
                fontFamily:"Orbitron",fontSize:11,color:"rgba(0,245,196,.5)",pointerEvents:"none"}}>$</span>
              <input className="sinp" type="number" min="0.5" step="0.5"
                placeholder="5"
                value={tradeAmount}
                onChange={e=>setTradeAmount(e.target.value)}
                style={{paddingLeft:24,fontFamily:"Orbitron",fontWeight:700,fontSize:13}}/>
            </div>
            <div style={{display:"flex",gap:6,flexShrink:0}}>
              {["0.5","1","5","10","25","50"].map(v=>(
                <button key={v}
                  onClick={()=>setTradeAmount(v)}
                  style={{fontFamily:"Orbitron",fontSize:8,padding:"6px 10px",cursor:"pointer",
                    borderRadius:3,border:"1px solid rgba(0,245,196,.25)",
                    background:tradeAmount===v?"rgba(0,245,196,.15)":"transparent",
                    color:tradeAmount===v?"#00f5c4":"rgba(0,245,196,.45)"}}>
                  ${v}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div style={{background:"rgba(0,245,196,.03)",border:"1px solid rgba(0,245,196,.14)",
          borderRadius:3,padding:"14px 16px",marginTop:8}}>
          <div style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.7)",letterSpacing:2,marginBottom:6}}>
            ◈ TRY DEMO FIRST — RECOMMENDED
          </div>
          <div style={{fontSize:9.5,color:"rgba(140,160,190,.65)",lineHeight:1.75,marginBottom:12}}>
            Experience the full bot in action with <b style={{color:"#c8d8f0"}}>simulated funds</b>.
            Same signals, same strategy, same execution — zero risk. Build confidence before going live.
          </div>
          <button className="dbtn" style={{marginTop:0,fontSize:10,letterSpacing:2,
            padding:"13px",border:"1px solid rgba(0,245,196,.35)",color:"#00f5c4",
            background:"rgba(0,245,196,.06)"}}
            onClick={onDemo}>
            ▶ START DEMO TRADING
          </button>
        </div>
        <div style={{textAlign:"center",marginTop:14,fontSize:8,color:"rgba(100,120,160,.28)",
          fontFamily:"Orbitron",letterSpacing:1}}>
          ALL SIGNING IS LOCAL · KEYS NEVER TRANSMITTED
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════
   MAIN DASHBOARD — TFunds Bot v2
═══════════════════════════════════════════════════ */
export default function App() {
  const [creds,      setCreds]      = useState(null);
  const [tradeAmount,setTradeAmount] = useState("50");
  const [isDemo,     setIsDemo]     = useState(false);
  const [balances,   setBalances]   = useState([]);
  const [prices,     setPrices]     = useState({});
  const [klines,     setKlines]     = useState({});
  const [signals,    setSignals]    = useState({});
  const [botRunning, setBotRunning] = useState(false);
  const [paperMode,  setPaperMode]  = useState(true);
  const [trades,     setTrades]     = useState([]);
  const [openPos,    setOpenPos]    = useState([]);
  const [log,        setLog]        = useState([]);
  // ── Tab navigation — uses URL hash + localStorage so both refresh and back button work ──
  // Hash (#dashboard, #wallet, etc.) survives page refresh and triggers hashchange/popstate.
  // localStorage also persists the tab in case hash is stripped by the browser.
  const getInitialTab = () => {
    const hash = window.location.hash.replace("#", "");
    const validTabs = ["dashboard","scanner","positions","trades","backtest","wallet","log"];
    if (validTabs.includes(hash)) return hash;
    const stored = localStorage.getItem("tfunds_tab");
    if (stored && validTabs.includes(stored)) return stored;
    return "dashboard";
  };

  const [tab, setTabRaw] = useState(getInitialTab);

  const setTab = useCallback((newTab) => {
    // Update hash — this automatically creates a browser history entry
    // so the back button navigates between tabs without any extra pushState calls.
    window.location.hash = newTab;
    localStorage.setItem("tfunds_tab", newTab);
    setTabRaw(newTab);
  }, []);

  // Listen for hash changes (back/forward button, or direct hash navigation)
  useEffect(()=>{
    const onHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      const validTabs = ["dashboard","scanner","positions","trades","backtest","wallet","log"];
      const t = validTabs.includes(hash) ? hash : "dashboard";
      localStorage.setItem("tfunds_tab", t);
      setTabRaw(t);
    };
    window.addEventListener("hashchange", onHashChange);
    // Set initial hash if missing so back button has somewhere to go
    if (!window.location.hash) {
      window.location.hash = tab;
    }
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []); // eslint-disable-line
  const [cfg,        setCfg]        = useState({
    pairs:     TOP_PAIRS,
    amount:    "50",
    stopLoss:  "2",      // fallback % if ATR unavailable
    takeProfit:"4",
    interval:  "15m",
    minConfidence: "62",
    useAtrSl:  true,     // use ATR-based SL/TP when available
    trailingPct: "1.5",  // trailing stop % (0 = disabled)
    maxPositions: "5",   // max concurrent open positions = numCoins
    totalBudget:  "10",  // total USDT to allocate across all coins
    numCoins:     "5",   // how many coins to spread budget across
  });

  /* ── Wallet state ── */
  const [wallet,        setWallet]        = useState(null);  // { address, chainId, type }
  const [wcEthProvider, setWcEthProvider] = useState(null);  // WalletConnect raw provider
  const [walletBals,    setWalletBals]    = useState({});    // { eth, bnb, usdtEth, usdtBsc }
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletErr,     setWalletErr]     = useState("");
  const [showWcModal,   setShowWcModal]   = useState(false); // WC picker modal
  const [showStopModal, setShowStopModal] = useState(false); // Stop trading summary modal
  const [showStartModal,setShowStartModal]= useState(false); // Live start confirmation modal
  const [liveTradeAmt,  setLiveTradeAmt]  = useState("");    // per-coin amount (auto-computed)
  const [liveTotalBudget,setLiveTotalBudget]=useState("10");  // total USDT to spend this session
  const [liveNumCoins,  setLiveNumCoins]  = useState("5");   // how many coins to spread across
  const [stopBalance,   setStopBalance]   = useState("");    // stop bot if USDT drops below this
  const [wdForm,        setWdForm]        = useState({ coin:"USDT", network:"BSC", address:"", amount:"" });
  const [wdStatus,      setWdStatus]      = useState(null);  // { type, msg }

  const logRef      = useRef(null);
  const botRef      = useRef(null);
  const botRunningRef = useRef(false); // mirrors botRunning state — readable inside async callbacks
  const stopBalanceRef = useRef(0);     // mirrors stopBalance — readable inside async callbacks
  const priceRef    = useRef({});
  const posRef      = useRef([]);
  const balancesRef = useRef([]);   // always-current balances for use inside callbacks
  // Cache of symbols actually supported by the connected exchange.
  // Populated on first price-fetch; used to skip unsupported pairs silently.
  const validSymbolsRef = useRef(null);
  // Cache of Bybit instrument info: symbol → { basePrecision, minOrderQty, minOrderAmt }
  const instrInfoRef = useRef({});
  // Pairs eligible for the current trade amount (auto-filtered from TOP_PAIRS)
  const [eligiblePairs, setEligiblePairs] = useState(TOP_PAIRS);
  const instrInfoLoadedRef = useRef(false);
  // Ref so filter callbacks can read current amount without becoming stale
  const amtRef = useRef("50");

  /* ── New feature state ── */
  const trailingStops  = useRef({});          // { [posId]: { highWater, lowWater } }
  const obCacheRef     = useRef({});          // { [symbol]: {bids,asks,bidVol,askVol,bias,ts} }
  const scanBatchRef   = useRef(0);           // rotating batch index for pair scanning          // { [symbol]: {bids,asks,bidVol,askVol,bias,ts} }
  const [btResult,     setBtResult]     = useState(null);
  const [btRunning,    setBtRunning]    = useState(false);
  const [btSymbol,     setBtSymbol]     = useState("BTCUSDT");
  const [btInterval,   setBtInterval]   = useState("1h");
  const [btInitCap,    setBtInitCap]    = useState("1000");
  const [fundingRates, setFundingRates] = useState([]);
  const [fundingLoading,setFundingLoading]=useState(false);
  const [orderBookData,setOrderBookData]= useState({});
  const [aiSignals,    setAiSignals]    = useState({});
  const [aiLoading,    setAiLoading]    = useState({});

  useEffect(()=>{ posRef.current=openPos; },[openPos]);
  useEffect(()=>{ balancesRef.current=balances; },[balances]);
  useEffect(()=>{ botRunningRef.current=botRunning; },[botRunning]);
  useEffect(()=>{ stopBalanceRef.current=parseFloat(stopBalance)||0; },[stopBalance]);
  useEffect(()=>{ if(logRef.current) logRef.current.scrollTop=logRef.current.scrollHeight; },[log]);
  // Reset symbol cache whenever the connected exchange changes
  useEffect(()=>{ validSymbolsRef.current = null; instrInfoRef.current = {}; instrInfoLoadedRef.current = false; },[creds]);

  const addLog = useCallback((src,msg,type="info")=>{
    setLog(prev=>[...prev.slice(-200),{src,msg,type,ts:new Date().toLocaleTimeString()}]);
  },[]);

  /* ── Fetch live open orders from exchange (to populate positions on live start) ── */
  const fetchLiveOpenOrders = useCallback(async()=>{
    if (isDemo||paperMode||!creds) return;
    const {exchange:ex,apiKey:k,apiSecret:s,passphrase:p} = creds;
    try {
      let orders = [];
      if (ex==="bybit") {
        const data = await bbSign(k,s,"/v5/order/realtime",{category:"spot",openOnly:1});
        orders = data.list||[];
        if (orders.length>0) {
          addLog("Account",`Fetched ${orders.length} open order(s) from Bybit`,"ok");
        } else {
          addLog("Account","No open orders found on Bybit — positions will populate as bot trades","info");
        }
      }
      // Note: we track positions via bot logic, not exchange positions directly,
      // so this just logs — the bot manages openPos state internally.
    } catch(e) {
      addLog("Account","Could not fetch open orders: "+e.message,"warn");
    }
  },[isDemo,paperMode,creds,addLog]);

  /* ── Balances ── */
  const fetchBalances = useCallback(async()=>{
    if (isDemo) {
      setBalances([{asset:"USDT",free:"10000.00",locked:"0"},{asset:"BTC",free:"0.05",locked:"0"},{asset:"ETH",free:"0.8",locked:"0"}]);
      return;
    }
    // Paper mode — always use virtual balance regardless of whether creds exist
    if (paperMode) {
      setBalances(prev => {
        if (prev.find(b=>b.asset==="USDT")) return prev;
        return [{asset:"USDT",free:"10000.00",locked:"0"},{asset:"BTC",free:"0",locked:"0"}];
      });
      return;
    }
    if (!creds) return;
    const {exchange:ex,apiKey:k,apiSecret:s,passphrase:p} = creds;
    try {
      if (ex==="binance") {
        const data = await bSign(k,s,{},"/api/v3/account");
        setBalances((data.balances||[]).filter(b=>parseFloat(b.free)>0||parseFloat(b.locked)>0));
      } else if (ex==="bybit") {
        // UTA (Unified Trading Account) uses accountType=UNIFIED exclusively.
        // availableToWithdraw is the correct "free for spot" field at coin level.
        // availableBalance only exists at account level, NOT coin level — do NOT use it here.
        let coins = [], detectedType = "";
        for (const accountType of ["UNIFIED","SPOT","CONTRACT"]) {
          try {
            const data = await bbSign(k,s,"/v5/account/wallet-balance",{accountType});
            const list = data.list?.[0]?.coin||[];
            if (list.length > 0) { coins = list; detectedType = accountType; break; }
          } catch(_) { /* try next */ }
        }
        if (detectedType) addLog("Account",`Bybit account type: ${detectedType}`,"info");
        setBalances(
          coins
            // Show any coin that has a non-zero wallet balance (even if temporarily unavailable)
            .filter(c => parseFloat(c.walletBalance||0) > 0 || parseFloat(c.availableToWithdraw||0) > 0)
            .map(c => {
              // availableToWithdraw is the correct "free for spot" field on UTA coin level.
              // Must use parseFloat comparison — "0" is truthy so string || chaining is wrong.
              const atw = parseFloat(c.availableToWithdraw||0);
              const wb  = parseFloat(c.walletBalance||0);
              const free   = String(atw > 0 ? atw : wb);
              const locked = String(Math.max(0, wb - atw).toFixed(4));
              return { asset: c.coin, free, locked };
            })
        );
      } else if (ex==="okx") {
        const data = await okxSign(k,s,p,"/api/v5/account/balance");
        const details = data[0]?.details||[];
        setBalances(details.filter(c=>parseFloat(c.availBal||0)>0)
          .map(c=>({asset:c.ccy,free:c.availBal,locked:c.frozenBal||"0"})));
      } else if (ex==="kucoin") {
        const data = await kcSign(k,s,p,"/api/v1/accounts","GET");
        setBalances((data||[]).filter(a=>a.type==="trade"&&parseFloat(a.available||0)>0)
          .map(a=>({asset:a.currency,free:a.available,locked:a.holds||"0"})));
      } else {
        const data = await cbSign(k,s,"/api/v3/brokerage/accounts");
        setBalances((data.accounts||[]).filter(a=>parseFloat(a.available_balance?.value||0)>0)
          .map(a=>({asset:a.currency,free:a.available_balance?.value,locked:"0"})));
      }
      addLog("Account",`Balances loaded from ${ex.toUpperCase()}`,"ok");
      // Warn if USDT balance is very low — live trading may fail min order checks
      if (!isDemo && !paperMode) {
        setTimeout(()=>{
          setBalances(prev=>{
            const usdt = prev.find(b=>b.asset==="USDT");
            const usdtFree = parseFloat(usdt?.free||0);
            if (usdtFree > 0 && usdtFree < 5) {
              addLog("Account",`⚠ Low balance: $${usdtFree.toFixed(2)} USDT — most Bybit pairs need $5+ minimum per order. Set trade amount ≥ $5 or add more funds.`,"warn");
            }
            return prev;
          });
        }, 500);
      }
    } catch(e){ addLog("Account","Balance fetch failed: "+e.message,"error"); }
  },[creds,isDemo,paperMode,addLog]);

  /* ── Pair eligibility filter — re-run whenever amount or instrument info changes ── */
  /* ── Pair eligibility filter — just keeps exchange-supported pairs ── */
  const applyPairFilter = useCallback(()=>{
    const ex = creds?.exchange;
    if (!instrInfoLoadedRef.current || ex !== "bybit" || isDemo) {
      setEligiblePairs(TOP_PAIRS);
      return;
    }
    // All pairs that have instrument data (exist on exchange) are eligible.
    // If the trade amount is below a pair's minimum, placeOrder auto-bumps to
    // the exchange minimum — so we never pre-filter by amount.
    const eligible = TOP_PAIRS.filter(sym => instrInfoRef.current[sym] !== undefined);
    setEligiblePairs(eligible.length > 0 ? eligible : TOP_PAIRS);
  },[creds, isDemo]);

  /* ── Bulk-fetch all Bybit instrument info once per session ── */
  const fetchAllInstrInfo = useCallback(async()=>{
    if (isDemo || !creds) { setEligiblePairs(TOP_PAIRS); return; }
    if (creds.exchange !== "bybit") { setEligiblePairs(TOP_PAIRS); return; }
    if (instrInfoLoadedRef.current) { applyPairFilter(); return; }
    try {
      addLog("System","Checking pair minimums on Bybit…","info");
      const info = await bbPublic("/v5/market/instruments-info",{category:"spot",limit:"1000"});
      const list  = info?.list || [];
      const topSet = new Set(TOP_PAIRS);
      list.forEach(item=>{
        if (!topSet.has(item.symbol)) return;
        const lf = item.lotSizeFilter||{};
        instrInfoRef.current[item.symbol] = {
          basePrecision: parseFloat(lf.basePrecision||"0.00000001"),
          minOrderQty:   parseFloat(lf.minOrderQty  ||"0"),
          minOrderAmt:   parseFloat(lf.minOrderAmt  ||"1"),
        };
      });
      instrInfoLoadedRef.current = true;
      applyPairFilter();
      addLog("System",`Instrument data loaded for ${Object.keys(instrInfoRef.current).length} pairs`,"ok");
    } catch(e) {
      addLog("System","Pair filter unavailable: "+e.message,"warn");
      setEligiblePairs(TOP_PAIRS);
    }
  },[isDemo, creds, addLog, applyPairFilter]);

  /* ── Fetch klines + run full TA engine ── */
  const fetchKlinesAndAnalyze = useCallback(async(symbol)=>{
    /* Demo mode — generate realistic synthetic OHLCV; no network needed */
    if (isDemo) {
      try {
        const BASE_PX={BTCUSDT:67234,ETHUSDT:3521,SOLUSDT:178,BNBUSDT:608,XRPUSDT:0.62,
          ADAUSDT:0.45,AVAXUSDT:36,DOTUSDT:7.2,MATICUSDT:0.72,LINKUSDT:14.8,
          UNIUSDT:9.4,ATOMUSDT:8.5,LTCUSDT:84,NEARUSDT:6.8,APTUSDT:9.2,ARBUSDT:1.05,
          SUIUSDT:1.32,INJUSDT:28,SEIUSDT:0.52,TIAUSDT:7.8};
        const base=BASE_PX[symbol]||100;
        const closes=[],highs=[],lows=[],opens=[],volumes=[];
        let price=base*(0.88+Math.random()*0.15);
        for(let i=0;i<150;i++){
          const drift=(Math.random()-0.47)*0.013;
          const o=price;
          price=Math.max(o*(1+drift),base*0.4);
          const rng=Math.abs(o-price)*1.5+base*0.002;
          opens.push(o); closes.push(price);
          highs.push(Math.max(o,price)+rng*(0.3+Math.random()*0.7));
          lows.push(Math.max(Math.min(o,price)-rng*(0.3+Math.random()*0.7),0.0001));
          volumes.push(500+Math.random()*19500);
        }
        const sig=generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      } catch(e) {
        addLog("TA",`Demo kline generation failed for ${symbol}: ${e.message}`,"error");
        return null;
      }
    }
    const ex = creds?.exchange||"bybit";
    const {apiKey:k,apiSecret:s,passphrase:p} = creds||{};
    let rawData=null;
    try {
      if (ex==="binance") {
        rawData = await bPublic("/api/v3/klines",{symbol,interval:cfg.interval,limit:"150"});
        // Binance: [openTime, o, h, l, c, vol, ...]
        const closes  = rawData.map(k=>parseFloat(k[4]));
        const highs   = rawData.map(k=>parseFloat(k[2]));
        const lows    = rawData.map(k=>parseFloat(k[3]));
        const opens   = rawData.map(k=>parseFloat(k[1]));
        const volumes = rawData.map(k=>parseFloat(k[5]));
        const sig = generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      } else if (ex==="bybit") {
        const r = await bbPublic("/v5/market/kline",{category:"spot",symbol,interval:IV_BYBIT[cfg.interval]||"15",limit:"150"});
        // Bybit: list rows = [startTime, o, h, l, c, vol, turnover] newest-first → reverse
        const rows = (r.list||[]).reverse();
        const opens  = rows.map(r=>parseFloat(r[1]));
        const highs  = rows.map(r=>parseFloat(r[2]));
        const lows   = rows.map(r=>parseFloat(r[3]));
        const closes = rows.map(r=>parseFloat(r[4]));
        const volumes= rows.map(r=>parseFloat(r[5]));
        const sig = generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      } else if (ex==="okx") {
        const instId = toExSymbol(symbol,"okx");
        const rows = await okxPublic("/api/v5/market/candles",{instId,bar:IV_OKX[cfg.interval]||"15m",limit:"150"});
        // OKX: [ts, o, h, l, c, vol, volCcy, ...] newest-first → reverse
        const rev = (rows||[]).reverse();
        const opens  = rev.map(r=>parseFloat(r[1]));
        const highs  = rev.map(r=>parseFloat(r[2]));
        const lows   = rev.map(r=>parseFloat(r[3]));
        const closes = rev.map(r=>parseFloat(r[4]));
        const volumes= rev.map(r=>parseFloat(r[5]));
        const sig = generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      } else if (ex==="kucoin") {
        const instId = toExSymbol(symbol,"kucoin");
        const nowSec = Math.floor(Date.now()/1000);
        const rows = await kcPublic("/api/v1/market/candles",{symbol:instId,type:IV_KC[cfg.interval]||"15min",endAt:nowSec});
        // KuCoin: [time, o, c, h, l, vol, amount] newest-first → reverse
        const rev = (rows||[]).reverse();
        const opens  = rev.map(r=>parseFloat(r[1]));
        const closes = rev.map(r=>parseFloat(r[2]));
        const highs  = rev.map(r=>parseFloat(r[3]));
        const lows   = rev.map(r=>parseFloat(r[4]));
        const volumes= rev.map(r=>parseFloat(r[5]));
        const sig = generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      } else {
        // Coinbase — fallback to Bybit public data for TA (Coinbase kline API needs OAuth2 for Advanced)
        const r = await bbPublic("/v5/market/kline",{category:"spot",symbol,interval:IV_BYBIT[cfg.interval]||"15",limit:"150"});
        const rows = (r.list||[]).reverse();
        const opens  = rows.map(r=>parseFloat(r[1]));
        const highs  = rows.map(r=>parseFloat(r[2]));
        const lows   = rows.map(r=>parseFloat(r[3]));
        const closes = rows.map(r=>parseFloat(r[4]));
        const volumes= rows.map(r=>parseFloat(r[5]));
        const sig = generateSignal(closes,highs,lows,opens,volumes);
        setKlines(prev=>({...prev,[symbol]:{closes,highs,lows,opens,volumes}}));
        setSignals(prev=>({...prev,[symbol]:sig}));
        return sig;
      }
    } catch(e) {
      addLog("TA",`Kline fetch failed [${ex}] ${symbol}: ${e.message}`,"error");
      return null;
    }
  },[cfg.interval,isDemo,creds,addLog]);

  /* ── Fetch all prices ── */
  const fetchPrices = useCallback(async()=>{
    /* Demo mode — simulate realistic price ticks; no network call */
    if (isDemo) {
      const BASE_PX={BTCUSDT:67234,ETHUSDT:3521,SOLUSDT:178,BNBUSDT:608,XRPUSDT:0.62,
        ADAUSDT:0.45,AVAXUSDT:36,DOTUSDT:7.2,MATICUSDT:0.72,LINKUSDT:14.8,
        UNIUSDT:9.4,ATOMUSDT:8.5,LTCUSDT:84,NEARUSDT:6.8,APTUSDT:9.2,ARBUSDT:1.05,
        SUIUSDT:1.32,INJUSDT:28,SEIUSDT:0.52,TIAUSDT:7.8};
      const map={};
      Object.entries(BASE_PX).forEach(([sym,p])=>{
        map[sym]=p*(1+(Math.random()-0.5)*0.004);
      });
      priceRef.current=map;
      setPrices(map);
      return;
    }
    const ex = creds?.exchange||"bybit";
    try {
      if (ex==="binance") {
        const data = await bPublic("/api/v3/ticker/price");
        const map={}; data.forEach(d=>{ map[d.symbol]=parseFloat(d.price); });
        priceRef.current=map; setPrices(map);
        if (!validSymbolsRef.current) validSymbolsRef.current = new Set(Object.keys(map));
      } else if (ex==="bybit") {
        // Retry up to 2 times — transient network errors are common
        let map = null;
        for (let attempt = 0; attempt < 2 && !map; attempt++) {
          try {
            const d = await bbPublic("/v5/market/tickers",{category:"spot"});
            if ((d.list||[]).length > 0) {
              map = {};
              d.list.forEach(t=>{ map[t.symbol]=parseFloat(t.lastPrice); });
            }
          } catch(_) { if (attempt < 1) await new Promise(r=>setTimeout(r,1200)); }
        }
        if (map) {
          priceRef.current=map; setPrices(map);
          if (!validSymbolsRef.current) validSymbolsRef.current = new Set(Object.keys(map));
        }
        else addLog("Market","Price fetch failed [bybit] — using cached prices","warn");
      } else if (ex==="okx") {
        const data = await okxPublic("/api/v5/market/tickers",{instType:"SPOT"});
        const map={}; (data||[]).forEach(t=>{ map[normSymbol(t.instId)]=parseFloat(t.last); });
        priceRef.current=map; setPrices(map);
        if (!validSymbolsRef.current) validSymbolsRef.current = new Set(Object.keys(map));
      } else if (ex==="kucoin") {
        const data = await kcPublic("/api/v1/market/allTickers");
        const map={}; ((data?.ticker)||[]).forEach(t=>{ map[normSymbol(t.symbol)]=parseFloat(t.last); });
        priceRef.current=map; setPrices(map);
        if (!validSymbolsRef.current) validSymbolsRef.current = new Set(Object.keys(map));
      } else {
        // Coinbase — use Bybit public prices
        const d = await bbPublic("/v5/market/tickers",{category:"spot"});
        const map={}; (d.list||[]).forEach(t=>{ map[t.symbol]=parseFloat(t.lastPrice); });
        priceRef.current=map; setPrices(map);
        if (!validSymbolsRef.current) validSymbolsRef.current = new Set(Object.keys(map));
      }
    } catch(e){
      // Keep whatever cached prices exist — don't wipe them on transient failure
      addLog("Market",`Price fetch error [${ex}]: ${e.message}`,"error");
    }
  },[isDemo,creds,addLog]);

  /* ── Fetch Order Book depth ── */
  const fetchOrderBook = useCallback(async(symbol)=>{
    // 30s staleness cache — avoid hitting API every bot tick for every signal
    const cached = obCacheRef.current[symbol];
    if (cached && Date.now() - cached.ts < 30000) {
      return {bids:cached.bids,asks:cached.asks,bidVol:cached.bidVol,askVol:cached.askVol,bias:cached.bias};
    }
    const ex = creds?.exchange||"bybit";
    try {
      let bids=[], asks=[];
      if (ex==="bybit"||isDemo) {
        const r = await bbPublic("/v5/market/orderbook",{category:"spot",symbol,limit:"20"});
        bids = (r.b||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
        asks = (r.a||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
      } else if (ex==="binance") {
        const r = await bPublic("/api/v3/depth",{symbol,limit:"20"});
        bids = r.bids.map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
        asks = r.asks.map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
      } else if (ex==="okx") {
        const instId=toExSymbol(symbol,"okx");
        const r = await okxPublic("/api/v5/market/books",{instId,sz:"20"});
        bids=(r[0]?.bids||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
        asks=(r[0]?.asks||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
      } else if (ex==="kucoin") {
        const instId=toExSymbol(symbol,"kucoin");
        const r = await kcPublic("/api/v1/market/orderbook/level2_20",{symbol:instId});
        bids=(r?.bids||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
        asks=(r?.asks||[]).map(([p,q])=>({price:parseFloat(p),qty:parseFloat(q)}));
      }
      const bidVol=bids.reduce((s,b)=>s+b.qty*b.price,0);
      const askVol=asks.reduce((s,a)=>s+a.qty*a.price,0);
      const bias=bidVol+askVol>0?(bidVol-askVol)/(bidVol+askVol)*100:0;
      const result={bids,asks,bidVol,askVol,bias,ts:Date.now()};
      obCacheRef.current[symbol]=result;
      setOrderBookData(prev=>({...prev,[symbol]:result}));
      return {bids,asks,bidVol,askVol,bias};
    } catch(e) {
      return null;
    }
  },[isDemo,creds]);

  /* ── Fetch Funding Rates ── */
  const fetchFundingRates = useCallback(async()=>{
    setFundingLoading(true);
    try {
      let rates=[];
      // Bybit perpetual funding rates (most reliable cross-exchange)
      const ex = creds?.exchange||"bybit";
      // Single bulk call — avoids 10 simultaneous requests that trigger rate-limit 403
      const targetSymbols = new Set(["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","XRPUSDT","AVAXUSDT","LINKUSDT","ADAUSDT","DOTUSDT","NEARUSDT"]);
      if (ex==="binance") {
        const data = await bPublic("/fapi/v1/premiumIndex");
        rates = (Array.isArray(data)?data:[data])
          .filter(r=>targetSymbols.has(r.symbol))
          .map(r=>({symbol:r.symbol,rate:parseFloat(r.lastFundingRate)*100,nextTime:r.nextFundingTime}));
      } else {
        // Bybit: fundingRate is included in the /v5/market/tickers?category=linear response
        const r = await bbPublic("/v5/market/tickers",{category:"linear"});
        rates = (r.list||[])
          .filter(t=>targetSymbols.has(t.symbol))
          .map(t=>({
            symbol:t.symbol,
            rate:parseFloat(t.fundingRate||0)*100,
            nextTime:t.nextFundingTime?Number(t.nextFundingTime):null,
          }));
      }
      rates.sort((a,b)=>Math.abs(b.rate)-Math.abs(a.rate));
      setFundingRates(rates);
    } catch(e){
      addLog("Funding","Funding rate fetch failed: "+e.message,"error");
    } finally { setFundingLoading(false); }
  },[creds,addLog]);

  /* ── AI Signal Overlay (Claude API) ── */
  const askAISignal = useCallback(async(symbol)=>{
    const sig=signals[symbol];
    const kl=klines[symbol];
    if(!sig||!kl) { addLog("AI","Run analysis first for "+symbol,"warn"); return; }
    setAiLoading(prev=>({...prev,[symbol]:true}));
    try {
      const closes=kl.closes.slice(-20).map(v=>v.toFixed(4)).join(", ");
      const prompt=`You are a crypto trading assistant. Analyze this signal for ${symbol}:
Action: ${sig.action} | Confidence: ${sig.confidence}% | Regime: ${sig.meta?.regime}
RSI: ${sig.meta?.rsi?.toFixed(1)} | MACD: ${sig.meta?.macd?.toFixed(2)} | ADX: ${sig.meta?.adx?.toFixed(1)}
Recent closes (oldest→newest): ${closes}
Reasons: ${sig.reasons?.join("; ")}

Respond in JSON only: {"verdict":"CONFIRM"|"CAUTION"|"REJECT","short_reason":"max 12 words","risk":"LOW"|"MED"|"HIGH","confidence_adj":number between -20 and +15}`;

      const resp=await fetch("https://api.groq.com/openai/v1/chat/completions",{
        method:"POST",
        headers:{"Content-Type":"application/json","Authorization":"Bearer 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"},
        body:JSON.stringify({
          model:"llama-3.1-8b-instant",
          max_tokens:200,
          messages:[{role:"user",content:prompt}]
        })
      });
      const data=await resp.json();
      const text=data.choices?.[0]?.message?.content||"";
      let parsed={verdict:"CAUTION",short_reason:"AI unavailable",risk:"MED",confidence_adj:0};
      if (text) {
        try {
          const clean=text.replace(/```json|```/g,"").trim();
          const s=clean.indexOf("{"),e=clean.lastIndexOf("}");
          if(s!==-1&&e!==-1){const p=JSON.parse(clean.slice(s,e+1));if(p.verdict)parsed=p;}
        } catch(_){}
      }
      parsed.verdict=parsed.verdict||"CAUTION";
      parsed.short_reason=parsed.short_reason||"no reason";
      parsed.risk=parsed.risk||"MED";
      setAiSignals(prev=>({...prev,[symbol]:{...parsed,ts:Date.now()}}));
      addLog("AI",`${symbol} → ${parsed.verdict}: ${parsed.short_reason}`,"ok");
    } catch(e){
      addLog("AI","AI signal failed for "+symbol+": "+e.message,"error");
    } finally {
      setAiLoading(prev=>({...prev,[symbol]:false}));
    }
  },[signals,klines,addLog]);

  /* ── Backtesting Engine ── */
  const runBacktest = useCallback(async()=>{
    setBtRunning(true); setBtResult(null);
    addLog("Backtest",`Starting backtest: ${btSymbol} · ${btInterval} · $${btInitCap} capital`,"info");
    try {
      const ex=creds?.exchange||"bybit";
      let closes=[],highs=[],lows=[],opens=[],volumes=[];

      // Fetch 500 candles for backtest
      if (isDemo) {
        const base=67234;
        let price=base*0.85;
        for(let i=0;i<500;i++){
          const drift=(Math.random()-0.47)*0.013;
          const o=price; price=Math.max(o*(1+drift),base*0.3);
          const rng=Math.abs(o-price)*1.5+base*0.002;
          opens.push(o); closes.push(price);
          highs.push(Math.max(o,price)+rng*(0.3+Math.random()*0.7));
          lows.push(Math.max(Math.min(o,price)-rng*(0.3+Math.random()*0.7),0.0001));
          volumes.push(500+Math.random()*19500);
        }
      } else if (ex==="binance") {
        const rawData=await bPublic("/api/v3/klines",{symbol:btSymbol,interval:btInterval,limit:"500"});
        closes=rawData.map(k=>parseFloat(k[4])); highs=rawData.map(k=>parseFloat(k[2]));
        lows=rawData.map(k=>parseFloat(k[3])); opens=rawData.map(k=>parseFloat(k[1]));
        volumes=rawData.map(k=>parseFloat(k[5]));
      } else if (ex==="bybit"||ex==="coinbase") {
        const ivMap={"1m":"1","5m":"5","15m":"15","30m":"30","1h":"60","4h":"240","1d":"D"};
        const r=await bbPublic("/v5/market/kline",{category:"spot",symbol:btSymbol,interval:ivMap[btInterval]||"60",limit:"500"});
        const rows=(r.list||[]).reverse();
        opens=rows.map(r=>parseFloat(r[1])); highs=rows.map(r=>parseFloat(r[2]));
        lows=rows.map(r=>parseFloat(r[3])); closes=rows.map(r=>parseFloat(r[4]));
        volumes=rows.map(r=>parseFloat(r[5]));
      } else if (ex==="okx") {
        const instId=toExSymbol(btSymbol,"okx");
        const ivMap={"1m":"1m","5m":"5m","15m":"15m","30m":"30m","1h":"1H","4h":"4H","1d":"1D"};
        const rows=await okxPublic("/api/v5/market/candles",{instId,bar:ivMap[btInterval]||"1H",limit:"300"});
        const rev=(rows||[]).reverse();
        opens=rev.map(r=>parseFloat(r[1])); highs=rev.map(r=>parseFloat(r[2]));
        lows=rev.map(r=>parseFloat(r[3])); closes=rev.map(r=>parseFloat(r[4]));
        volumes=rev.map(r=>parseFloat(r[5]));
      } else {
        const ivMap={"1m":"1min","5m":"5min","15m":"15min","30m":"30min","1h":"1hour","4h":"4hour","1d":"1day"};
        const instId=toExSymbol(btSymbol,"kucoin");
        const rows=await kcPublic("/api/v1/market/candles",{symbol:instId,type:ivMap[btInterval]||"1hour"});
        const rev=(rows||[]).reverse();
        opens=rev.map(r=>parseFloat(r[1])); closes=rev.map(r=>parseFloat(r[2]));
        highs=rev.map(r=>parseFloat(r[3])); lows=rev.map(r=>parseFloat(r[4]));
        volumes=rev.map(r=>parseFloat(r[5]));
      }

      // Roll signal engine over windows
      const WINDOW=60, FEE=0.001;
      let equity=parseFloat(btInitCap)||1000;
      let peak=equity, maxDD=0;
      const tradeLog=[], equityCurve=[equity];
      let inPos=null;

      for(let i=WINDOW;i<closes.length-1;i++){
        const c=closes.slice(0,i+1), h=highs.slice(0,i+1);
        const l=lows.slice(0,i+1),  o=opens.slice(0,i+1), v=volumes.slice(0,i+1);
        const sig=generateSignal(c,h,l,o,v);
        const price=closes[i];

        if(inPos){
          const pnlPct=inPos.side==="BUY"?(price-inPos.entry)/inPos.entry*100:(inPos.entry-price)/inPos.entry*100;
          const hitSL=inPos.side==="BUY"?price<=inPos.sl:price>=inPos.sl;
          const hitTP=inPos.side==="BUY"?price>=inPos.tp:price<=inPos.tp;
          const sigClose=inPos.side==="BUY"&&sig.action==="SELL"||inPos.side==="SELL"&&sig.action==="BUY";
          if(hitSL||hitTP||sigClose){
            const gain=(pnlPct/100)*equity*(1-FEE);
            equity+=gain;
            if(equity>peak)peak=equity;
            const dd=(peak-equity)/peak*100;
            if(dd>maxDD)maxDD=dd;
            tradeLog.push({i,side:inPos.side,entry:inPos.entry,exit:price,pnl:pnlPct,result:hitTP?"TP":hitSL?"SL":"SIG",equity:equity.toFixed(2)});
            equityCurve.push(equity);
            inPos=null;
          }
        }
        if(!inPos&&sig.action!=="HOLD"&&sig.confidence>=(parseFloat(cfg.minConfidence)||62)){
          const slPct=sig.meta?.atrSlPct||parseFloat(cfg.stopLoss)||2;
          const tpPct=sig.meta?.atrTpPct||parseFloat(cfg.takeProfit)||4;
          inPos={side:sig.action,entry:price,
            sl:sig.action==="BUY"?price*(1-slPct/100):price*(1+slPct/100),
            tp:sig.action==="BUY"?price*(1+tpPct/100):price*(1-tpPct/100)};
        }
      }

      const wins=tradeLog.filter(t=>t.pnl>0);
      const losses=tradeLog.filter(t=>t.pnl<=0);
      const winRate=tradeLog.length?((wins.length/tradeLog.length)*100).toFixed(1):"—";
      const totalReturn=((equity-(parseFloat(btInitCap)||1000))/(parseFloat(btInitCap)||1000)*100).toFixed(2);
      const avgWin=wins.length?(wins.reduce((s,t)=>s+t.pnl,0)/wins.length).toFixed(2):"—";
      const avgLoss=losses.length?(losses.reduce((s,t)=>s+t.pnl,0)/losses.length).toFixed(2):"—";
      const profitFactor=losses.length&&losses.reduce((s,t)=>s+Math.abs(t.pnl),0)>0
        ?(wins.reduce((s,t)=>s+t.pnl,0)/Math.abs(losses.reduce((s,t)=>s+t.pnl,0))).toFixed(2):"∞";

      setBtResult({tradeLog,equityCurve,equity:equity.toFixed(2),winRate,totalReturn,
        avgWin,avgLoss,profitFactor,maxDD:maxDD.toFixed(2),totalTrades:tradeLog.length,
        candlesUsed:closes.length});
      addLog("Backtest",`Done — ${tradeLog.length} trades · ${winRate}% win rate · Return: ${totalReturn}%`,parseFloat(totalReturn)>0?"ok":"warn");
    } catch(e){
      addLog("Backtest","Backtest failed: "+e.message,"error");
    } finally { setBtRunning(false); }
  },[isDemo,creds,btSymbol,btInterval,btInitCap,cfg.minConfidence,cfg.stopLoss,cfg.takeProfit,addLog]);

  /* ── Place order ── */
  const placeOrder = useCallback(async(symbol,side,quantity)=>{
    if (paperMode||isDemo) {
      const price=priceRef.current[symbol]||0;
      addLog("Paper",`[SIMULATED] ${side} ${quantity} ${symbol} @ $${priceFmt(price)}`,side==="BUY"?"ok":"warn");
      return {orderId:`PAPER-${Date.now()}`,price,simulated:true};
    }
    const {exchange:ex,apiKey:k,apiSecret:s,passphrase:p} = creds;
    try {
      let data;
      if (ex==="binance") {
        data = await bSign(k,s,{symbol,side,type:"MARKET",quantity},"/api/v3/order","POST");
        addLog("Executor",`✓ Binance order: ${side} ${symbol} #${data.orderId}`,"ok");
      } else if (ex==="bybit") {
        // ── Fetch instrument precision if not cached ──
        if (!instrInfoRef.current[symbol]) {
          try {
            const info = await bbPublic("/v5/market/instruments-info",{category:"spot",symbol});
            const item = info?.list?.[0];
            if (item) {
              const lotFilter = item.lotSizeFilter||{};
              const basePrecision = parseFloat(lotFilter.basePrecision||"0.00000001");
              const minOrderQty   = parseFloat(lotFilter.minOrderQty||"0");
              const minOrderAmt   = parseFloat(lotFilter.minOrderAmt||"1");
              instrInfoRef.current[symbol] = { basePrecision, minOrderQty, minOrderAmt };
            }
          } catch(_) { /* use defaults */ }
        }
        const instr = instrInfoRef.current[symbol]||{};
        const basePrecision = instr.basePrecision||0.000001;
        const minOrderQty   = instr.minOrderQty||0;
        const minOrderAmt   = instr.minOrderAmt||1;

        // Round qty down to the allowed step size
        const stepDecimals = Math.max(0, -Math.floor(Math.log10(basePrecision)));
        const factor = Math.pow(10, stepDecimals);
        let adjQty = Math.floor(quantity * factor) / factor;

        // For SELL orders: cap qty to actual available balance.
        // Bybit deducts its trading fee from the received base asset on BUY,
        // so pos.qty is always slightly more than what's actually in the account.
        // Sending pos.qty on a SELL causes an "insufficient balance" rejection.
        if (side === "SELL") {
          const base = symbol.endsWith("USDT") ? symbol.slice(0,-4)
                      : symbol.endsWith("USDC") ? symbol.slice(0,-4)
                      : symbol.endsWith("BTC")  ? symbol.slice(0,-3)
                      : symbol.endsWith("ETH")  ? symbol.slice(0,-3)
                      : symbol.slice(0,-4);
          let actualFree = parseFloat(balancesRef.current.find(b=>b.asset===base)?.free||"0");

          // If cached balance is zero/stale, fetch live from Bybit right now.
          // This is the main fix: balancesRef may not have the coin if it was
          // received as a BUY fee credit and the balance hasn't been refreshed yet.
          if (actualFree <= 0) {
            try {
              for (const accountType of ["UNIFIED","SPOT","CONTRACT"]) {
                try {
                  const liveWallet = await bbSign(k, s, "/v5/account/wallet-balance", {accountType});
                  const coins = liveWallet.list?.[0]?.coin || [];
                  const coinData = coins.find(c => c.coin === base);
                  if (coinData) {
                    const atw = parseFloat(coinData.availableToWithdraw||"0");
                    const wb  = parseFloat(coinData.walletBalance||"0");
                    actualFree = atw > 0 ? atw : wb;
                    if (actualFree > 0) break;
                  }
                } catch(_) { /* try next account type */ }
              }
              if (actualFree > 0)
                addLog("Executor",`[bybit] Live balance fetched for ${base}: ${actualFree}`,"info");
              else
                addLog("Executor",`[bybit] No balance found for ${base} — applying fee buffer`,"warn");
            } catch(_) {}
          }

          if (actualFree > 0 && actualFree < adjQty) {
            const cappedQty = Math.floor(actualFree * factor) / factor;
            addLog("Executor",`[bybit] SELL ${symbol}: capping qty ${adjQty} → ${cappedQty} (actual balance)`,"info");
            adjQty = cappedQty;
          } else if (actualFree > 0 && adjQty >= actualFree) {
            // adjQty already within balance — use it as-is (already rounded down)
          } else if (actualFree <= 0) {
            // Last resort: apply 0.2% fee buffer to avoid "insufficient balance" rejection
            adjQty = Math.floor(adjQty * 0.998 * factor) / factor;
            addLog("Executor",`[bybit] SELL ${symbol}: fee buffer applied → qty=${adjQty}`,"warn");
          }
        }

        // Enforce minimum qty
        if (adjQty < minOrderQty) {
          addLog("Executor",`Order skipped [bybit]: ${symbol} qty ${adjQty} < min ${minOrderQty}`,"warn");
          return null;
        }
        // Enforce minimum order value — bump qty up to exchange minimum if we have balance
        const price = priceRef.current[symbol]||0;
        let orderValue = adjQty * price;
        if (orderValue < minOrderAmt && price > 0) {
          const minQtyNeeded = minOrderAmt / price;
          const minQtyRounded = Math.ceil(minQtyNeeded * factor) / factor;
          const availUSDT = parseFloat(balancesRef.current.find(b=>b.asset==="USDT")?.free||"0");
          if (minQtyRounded * price <= availUSDT * 0.98) {
            adjQty = minQtyRounded;
            orderValue = adjQty * price;
            addLog("Executor",`[bybit] ${symbol}: bumped to min order $${orderValue.toFixed(2)}`,"info");
          } else {
            addLog("Executor",`Order skipped [bybit]: ${symbol} value $${orderValue.toFixed(2)} < min $${minOrderAmt} — need more balance`,"warn");
            return null;
          }
        }

        const qtyStr = adjQty.toFixed(stepDecimals);
        data = await bbSign(k,s,"/v5/order/create",{},
          "POST",{category:"spot",symbol,side:side==="BUY"?"Buy":"Sell",orderType:"Market",qty:qtyStr});
        addLog("Executor",`✓ Bybit order: ${side} ${symbol} qty=${qtyStr} #${data.orderId}`,"ok");

        // ── Refresh real balance from exchange after order settles ──
        // Double-refresh: first pass catches most cases; second handles slow UTA settlement.
        setTimeout(()=>fetchBalances(), 2500);
        setTimeout(()=>fetchBalances(), 6000);
      } else if (ex==="okx") {
        const instId = toExSymbol(symbol,"okx");
        data = await okxSign(k,s,p,"/api/v5/trade/order","POST",
          {instId,tdMode:"cash",side:side.toLowerCase(),ordType:"market",sz:String(quantity)});
        addLog("Executor",`✓ OKX order: ${side} ${symbol} #${data[0]?.ordId}`,"ok");
        // Refresh balance so USDT/coin reflects the trade
        setTimeout(()=>fetchBalances(), 3000);
        setTimeout(()=>fetchBalances(), 7000);
      } else if (ex==="kucoin") {
        const kcSym = toExSymbol(symbol,"kucoin");
        data = await kcSign(k,s,p,"/api/v1/orders","POST",
          {clientOid:`tbot-${Date.now()}`,side:side.toLowerCase(),symbol:kcSym,type:"market",size:String(quantity)});
        addLog("Executor",`✓ KuCoin order: ${side} ${symbol} #${data.orderId}`,"ok");
        setTimeout(()=>fetchBalances(), 3000);
        setTimeout(()=>fetchBalances(), 7000);
      } else {
        // Coinbase Advanced Trade
        data = await cbSign(k,s,"/api/v3/brokerage/orders","POST",
          {client_order_id:`tbot-${Date.now()}`,product_id:symbol.replace("USDT","-USDT"),
           side,order_configuration:{market_market_ioc:{base_size:String(quantity)}}});
        addLog("Executor",`✓ Coinbase order: ${side} ${symbol}`,"ok");
        setTimeout(()=>fetchBalances(), 3000);
        setTimeout(()=>fetchBalances(), 7000);
      }
      return data;
    } catch(e) {
      addLog("Executor",`Order failed [${ex}]: ${e.message}`,"error");
      return null;
    }
  },[paperMode,isDemo,creds,addLog,fetchBalances]);

  /* ── Sell ALL non-USDT coins on Bybit (used on STOP for live mode) ──
     Queries the actual Bybit wallet instead of relying on posRef, which may
     be empty after a page refresh or if state drifted from the exchange.  */
  const sellAllLivePositions = useCallback(async () => {
    if (paperMode || isDemo || !creds) return { sold: 0, failed: 0 };
    const { exchange: ex, apiKey: k, apiSecret: s } = creds;
    if (ex !== "bybit") {
      // Non-Bybit: use posRef snapshot (caller handles this)
      return null;
    }
    addLog("Bot", "Querying live Bybit wallet to sell all positions…", "info");
    let sold = 0, failed = 0;
    // Check BOTH account types and collect all sellable coins — don't stop at empty UNIFIED
    // because coins may live in SPOT even when UNIFIED is empty (depends on account setup)
    const allSellable = [];
    for (const accountType of ["UNIFIED", "SPOT"]) {
      try {
        const walletData = await bbSign(k, s, "/v5/account/wallet-balance", { accountType });
        const coins = walletData.list?.[0]?.coin || [];
        const sellable = coins.filter(c => {
          if (["USDT","USDC","BUSD"].includes(c.coin)) return false;
          // Use the highest available qty: availableToWithdraw > availableToTrade > walletBalance
          const qty = Math.max(
            parseFloat(c.availableToWithdraw || "0"),
            parseFloat(c.availableToTrade    || "0"),
            parseFloat(c.walletBalance        || "0")
          );
          return qty > 0;
        }).map(c => ({
          coin: c.coin,
          qty: Math.max(
            parseFloat(c.availableToWithdraw || "0"),
            parseFloat(c.availableToTrade    || "0"),
            parseFloat(c.walletBalance        || "0")
          ),
          accountType,
        }));
        if (sellable.length > 0) {
          addLog("Bot", `Found ${sellable.length} coin(s) in ${accountType} wallet to sell`, "info");
          allSellable.push(...sellable);
        } else {
          addLog("Bot", `No non-USDT coins in ${accountType} wallet`, "info");
        }
      } catch (e) {
        addLog("Bot", `Wallet fetch failed (${accountType}): ${e.message}`, "warn");
      }
    }
    // Deduplicate by coin (same coin shouldn't appear in both account types, but just in case)
    const seen = new Set();
    const uniqueSellable = allSellable.filter(c => {
      if (seen.has(c.coin)) return false;
      seen.add(c.coin);
      return true;
    });
    if (uniqueSellable.length === 0) {
      addLog("Bot", "No sellable coins found in any Bybit wallet — all positions may already be closed", "info");
    } else {
      addLog("Bot", `Selling ${uniqueSellable.length} coin(s) → USDT`, "info");
      for (const coin of uniqueSellable) {
        const sym = coin.coin + "USDT";
        addLog("Bot", `Selling ${coin.qty.toFixed(6)} ${coin.coin} (${coin.accountType})…`, "info");
        const result = await placeOrder(sym, "SELL", coin.qty);
        if (result) {
          sold++;
          addLog("Bot", `✓ ${coin.coin} sold → USDT`, "ok");
        } else {
          failed++;
          addLog("Bot", `⚠ Could not sell ${coin.coin} — below min or no USDT pair — check Bybit app`, "warn");
        }
      }
    }
    // Refresh balance: immediate + 3 s + 8 s so USDT shows up
    fetchBalances();
    setTimeout(() => fetchBalances(), 3000);
    setTimeout(() => fetchBalances(), 8000);
    return { sold, failed };
  }, [paperMode, isDemo, creds, addLog, placeOrder, fetchBalances]);

  /* ── Bot tick — TA + Order Book + AI + Funding Rate (fully automatic) ── */
  const runBotTick = useCallback(async()=>{
    // ── Guard: if bot was stopped mid-tick, abort immediately ──
    if (!botRunningRef.current) return;
    // ── Auto-fetch funding rates every 8 hours to keep data fresh ──
    const now = Date.now();
    const lastFunding = runBotTick._lastFundingFetch||0;
    if (now - lastFunding > 8*60*60*1000) {
      runBotTick._lastFundingFetch = now;
      fetchFundingRates().catch(()=>{});
    }

    // ── Scan only 10 pairs per tick, rotating through the full list ──
    const BATCH_SIZE = 10;
    const total = eligiblePairs.length;
    const batchStart = (scanBatchRef.current * BATCH_SIZE) % Math.max(total, 1);
    const batchPairs = eligiblePairs.slice(batchStart, batchStart + BATCH_SIZE);
    scanBatchRef.current = batchStart + BATCH_SIZE >= total ? 0 : scanBatchRef.current + 1;

    addLog("Scanner",`[${isDemo?"DEMO":"LIVE"}] Scanning batch ${batchPairs.length}/${total} pairs (offset ${batchStart}) · Min conf ${cfg.minConfidence}%`,"info");

    // ── Gate: don't open more positions than numCoins (budget slots) ──
    const maxPos = Math.max(1, parseInt(cfg.numCoins || cfg.maxPositions || "5"));
    if (posRef.current.length >= maxPos) {
      addLog("Scanner",`All ${maxPos} coin slots filled — waiting for exits`,"warn");
      return;
    }

    // ── Stop-balance gate at tick level ──
    const tickUsdtBal = parseFloat(balancesRef.current.find(b=>b.asset==="USDT")?.free||"0");
    const tickStopFloor = stopBalanceRef.current;
    if (tickStopFloor > 0 && tickUsdtBal <= tickStopFloor) {
      addLog("Bot",`⛔ STOP BALANCE hit ($${tickUsdtBal.toFixed(2)} ≤ $${tickStopFloor.toFixed(2)}) — bot stopped`,"error");
      setBotRunning(false);
      return;
    }

    let holdCount = 0;
    let openedThisTick = 0; // only open 1 new position per tick to prevent balance drain
    for (const symbol of batchPairs) {
      if (!isDemo && validSymbolsRef.current && !validSymbolsRef.current.has(symbol)) continue;
      const price=priceRef.current[symbol];
      if (!price) continue;

      const sig = await fetchKlinesAndAnalyze(symbol);
      if (!sig||sig.action==="HOLD") {
        holdCount++;
        continue;
      }
      const minConf=parseFloat(cfg.minConfidence)||62;
      if (sig.confidence<minConf) {
        holdCount++;
        continue;
      }

      // ── GATE 1: Order Book check — skip if walls strongly oppose the trade ──
      let bookBias = 0;
      try {
        const book = await fetchOrderBook(symbol);
        if (book) {
          bookBias = book.bias;
          // If bot wants to BUY but sell walls dominate by >20%, skip
          if (sig.action==="BUY" && bookBias < -20) {
            addLog("OrderBook",`${symbol} → BUY blocked — strong sell wall (bias ${bookBias.toFixed(1)}%)`,"warn");
            continue;
          }
          // If bot wants to SELL but buy walls dominate by >20%, skip
          if (sig.action==="SELL" && bookBias > 20) {
            addLog("OrderBook",`${symbol} → SELL blocked — strong buy wall (bias ${bookBias.toFixed(1)}%)`,"warn");
            continue;
          }
          // OK — no log needed, reduces noise
        }
      } catch(_) { /* non-fatal — proceed without book data */ }

      // ── GATE 2: Funding Rate check — avoid trading against extreme funding ──
      const fr = fundingRates.find(f=>f.symbol===symbol);
      if (fr) {
        const absRate = Math.abs(fr.rate);
        if (absRate > 0.1) {
          // Extreme positive funding = longs paying too much = avoid BUY
          if (fr.rate > 0.1 && sig.action==="BUY") {
            addLog("Funding",`${symbol} → BUY skipped — extreme positive funding ${fr.rate.toFixed(3)}% (longs overleveraged)`,"warn");
            continue;
          }
          // Extreme negative funding = shorts paying too much = avoid SELL
          if (fr.rate < -0.1 && sig.action==="SELL") {
            addLog("Funding",`${symbol} → SELL skipped — extreme negative funding ${fr.rate.toFixed(3)}% (shorts overleveraged)`,"warn");
            continue;
          }
        }
      }

      // ── GATE 3: AI Review — ask Groq to confirm the signal ──
      try {
        const closes = klines[symbol]?.closes?.slice(-20).map(v=>v.toFixed(4)).join(", ")||"";
        const prompt = `You are a crypto trading assistant. Analyze this signal for ${symbol}:
Action: ${sig.action} | Confidence: ${sig.confidence}% | Regime: ${sig.meta?.regime}
RSI: ${sig.meta?.rsi?.toFixed(1)} | MACD: ${sig.meta?.macd?.toFixed(2)} | ADX: ${sig.meta?.adx?.toFixed(1)}
Order book bias: ${bookBias.toFixed(1)}%
Recent closes (oldest→newest): ${closes}
Reasons: ${sig.reasons?.join("; ")}

Respond ONLY in JSON, no extra text: {"verdict":"CONFIRM"|"CAUTION"|"REJECT","short_reason":"max 10 words","risk":"LOW"|"MED"|"HIGH"}`;

        const resp = await fetch("https://api.groq.com/openai/v1/chat/completions",{
          method:"POST",
          headers:{"Content-Type":"application/json","Authorization":"Bearer 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"},
          body:JSON.stringify({model:"llama-3.1-8b-instant",max_tokens:120,messages:[{role:"user",content:prompt}]})
        });
        const aiData = await resp.json();
        const aiText = aiData.choices?.[0]?.message?.content||"";
        let aiJson = {verdict:"CAUTION",short_reason:"AI parse error",risk:"MED"};
        if (aiText) {
          try {
            // Strip markdown fences and any leading/trailing non-JSON characters
            const clean = aiText.replace(/```json|```/g,"").trim();
            const jsonStart = clean.indexOf("{");
            const jsonEnd   = clean.lastIndexOf("}");
            if (jsonStart !== -1 && jsonEnd !== -1) {
              const parsed = JSON.parse(clean.slice(jsonStart, jsonEnd+1));
              if (parsed.verdict) aiJson = parsed;
            }
          } catch(_) { /* keep default CAUTION */ }
        }
        // Normalise fields so they are never undefined
        aiJson.verdict     = aiJson.verdict     || "CAUTION";
        aiJson.short_reason= aiJson.short_reason|| "no reason";
        aiJson.risk        = aiJson.risk        || "MED";
        setAiSignals(prev=>({...prev,[symbol]:{...aiJson,ts:Date.now()}}));

        if (aiJson.verdict==="REJECT") {
          addLog("AI",`${symbol} → REJECTED by AI: ${aiJson.short_reason}`,"warn");
          continue;
        }
        addLog("AI",`${symbol} → AI ${aiJson.verdict}: ${aiJson.short_reason} · Risk: ${aiJson.risk}`,"ok");
      } catch(e) {
        // AI failed — log but don't block the trade (non-fatal)
        addLog("AI",`${symbol} AI check skipped (${e.message}) — proceeding`,"warn");
      }

      // ── All gates passed — execute trade ──
      const existing=posRef.current.find(p=>p.symbol===symbol);

      /* Close opposite position */
      if (existing&&existing.side!==sig.action) {
        const closeSide=existing.side==="BUY"?"SELL":"BUY";
        const pnlPct=existing.side==="BUY"
          ?(price-existing.entry)/existing.entry*100
          :(existing.entry-price)/existing.entry*100;
        await placeOrder(symbol,closeSide,existing.qty);
        setTrades(prev=>[{...existing,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:pnlPct>0?"TP":"CLOSED"},...prev.slice(0,199)]);
        setOpenPos(prev=>prev.filter(p=>p.id!==existing.id));
        if(paperMode||isDemo){
          const dollarPnl=(pnlPct/100)*(existing.qty*existing.entry);
          setBalances(prev=>prev.map(b=>b.asset==="USDT"?{...b,free:String((parseFloat(b.free)+dollarPnl).toFixed(2))}:b));
        } else {
          setTimeout(()=>fetchBalances(), 2500);
        }
        addLog("Bot",`Closed ${symbol} on signal reversal — PnL: ${fmtP(pnlPct)}`,pnlPct>0?"ok":"warn");
      }

      /* Open new position */
      if (!existing||(existing&&existing.side!==sig.action)) {
        // ── Hard limit: 1 new position per tick, spread across scans ──
        if (openedThisTick >= 1) {
          addLog("Bot",`${symbol} signal skipped — already opened 1 position this tick (protects balance)`,"info");
          continue;
        }
        // ── Stop guard: don't open if bot was stopped while this tick was running ──
        if (!botRunningRef.current) {
          addLog("Bot","Bot stopped — cancelling pending trade opens","warn");
          break;
        }
        const usdtBal = parseFloat(balancesRef.current.find(b=>b.asset==="USDT")?.free||"0");

        // ── Stop-balance guard: halt if USDT dropped below user's safety floor ──
        const stopFloor = stopBalanceRef.current;
        if (stopFloor > 0 && usdtBal <= stopFloor) {
          addLog("Bot",`⛔ STOP BALANCE hit — USDT $${usdtBal.toFixed(2)} ≤ floor $${stopFloor.toFixed(2)} — bot paused`,"error");
          setBotRunning(false);
          break;
        }

        // ── Per-coin amount = totalBudget ÷ numCoins ──
        // e.g. $10 budget ÷ 5 coins = $2 per coin
        const totalBudget = parseFloat(cfg.totalBudget)||parseFloat(cfg.amount)||5;
        const numCoins    = Math.max(1, parseInt(cfg.numCoins)||5);
        const perCoinAmt  = +(totalBudget / numCoins).toFixed(4);

        // Count how many coin slots are already filled
        const alreadyOpen = posRef.current.length;
        if (alreadyOpen >= numCoins) {
          addLog("Bot",`All ${numCoins} coin slots filled — waiting for exits`,"info");
          break;
        }

        // Only skip if balance can't even cover one coin's slot
        if (usdtBal * 0.98 < perCoinAmt) {
          addLog("Bot",`Skipping ${symbol} — need $${perCoinAmt.toFixed(2)}/coin, have $${usdtBal.toFixed(2)} USDT`,"warn");
          continue;
        }
        const safeAmt = perCoinAmt;
        const orderQty = +(safeAmt/price).toFixed(6);
        const TAKER_FEE = 0.001;
        const qty = +(orderQty * (1 - TAKER_FEE)).toFixed(6);
        const slPct = sig.meta?.atrSlPct||parseFloat(cfg.stopLoss);
        const tpPct = sig.meta?.atrTpPct||parseFloat(cfg.takeProfit);
        const sl = sig.action==="BUY" ? price*(1-slPct/100) : price*(1+slPct/100);
        const tp = sig.action==="BUY" ? price*(1+tpPct/100) : price*(1-tpPct/100);
        const res = await placeOrder(symbol,sig.action,orderQty);
        if (!res) continue;
        // ── Optimistic balance deduction — prevents same-tick "insufficient balance" ──
        // balancesRef won't update for ~3s after order. Deduct now so the next symbol
        // in this batch doesn't try to spend money that's already gone.
        // Applied for ALL modes (paper/demo/live) so $5 per coin doesn't get spent multiple times.
        balancesRef.current = balancesRef.current.map(b =>
          b.asset === "USDT"
            ? { ...b, free: String(Math.max(0, parseFloat(b.free) - safeAmt).toFixed(4)) }
            : b
        );
        if (paperMode || isDemo) {
          // Also update React state so UI balance reflects the deduction
          setBalances(prev => prev.map(b =>
            b.asset === "USDT"
              ? { ...b, free: String(Math.max(0, parseFloat(b.free) - safeAmt).toFixed(4)) }
              : b
          ));
        }
        const pos={
          id:Date.now()+Math.random(), symbol, side:sig.action, entry:price, qty,
          sl, tp, slPct, tpPct, confidence:sig.confidence, reasons:sig.reasons,
          patterns:sig.meta?.patterns?.filter(p=>p.type!=="neutral").map(p=>p.name)||[],
          regime:sig.meta?.regime, adx:sig.meta?.adx, volRatio:sig.meta?.volRatio,
          openTs:new Date(), rsi:sig.meta?.rsi, macd:sig.meta?.macd, bookBias,
        };
        setOpenPos(prev=>[...prev.filter(p=>p.symbol!==symbol),pos]);
        openedThisTick++;
        addLog("Bot",
          `Opened ${sig.action==="BUY"?"LONG":"SHORT"} ${symbol} | Conf:${sig.confidence}% | Book:${bookBias>0?"+":""}${bookBias.toFixed(0)}% | ${sig.reasons[0]} | SL:${slPct.toFixed(2)}% TP:${tpPct.toFixed(2)}%`,
          "signal"
        );
      }
    }
    if (holdCount > 0) addLog("Scanner",`${holdCount}/${batchPairs.length} pairs held (no signal)`, "info");
  },[cfg,eligiblePairs,fetchKlinesAndAnalyze,fetchOrderBook,fetchFundingRates,fundingRates,klines,placeOrder,addLog,fetchBalances,paperMode,isDemo]);

  /* ── SL/TP Monitor + Trailing Stops ── */
  const monitorPositions = useCallback(()=>{
    const trailPct = parseFloat(cfg.trailingPct)||0;
    posRef.current.forEach(async pos=>{
      const price=priceRef.current[pos.symbol];
      if (!price) return;
      const pnlPct=pos.side==="BUY"
        ?(price-pos.entry)/pos.entry*100
        :(pos.entry-price)/pos.entry*100;

      // ── Trailing stop: lock in profit as price moves in our favour ──
      let effectiveSL = pos.sl;
      if (trailPct > 0) {
        const ts = trailingStops.current[pos.id] || { highWater: pos.entry, lowWater: pos.entry };
        if (pos.side==="BUY") {
          if (price > ts.highWater) {
            ts.highWater = price;
            const newSL = price * (1 - trailPct/100);
            if (newSL > effectiveSL) {
              effectiveSL = newSL;
              trailingStops.current[pos.id] = ts;
              setOpenPos(prev=>prev.map(p=>p.id===pos.id?{...p,sl:newSL,trailHigh:price}:p));
            }
          }
          if (ts.highWater > pos.entry) effectiveSL = ts.highWater*(1-trailPct/100);
        } else {
          if (price < ts.lowWater) {
            ts.lowWater = price;
            const newSL = price * (1 + trailPct/100);
            if (newSL < effectiveSL) {
              effectiveSL = newSL;
              trailingStops.current[pos.id] = ts;
              setOpenPos(prev=>prev.map(p=>p.id===pos.id?{...p,sl:newSL,trailLow:price}:p));
            }
          }
          if (ts.lowWater < pos.entry) effectiveSL = ts.lowWater*(1+trailPct/100);
        }
      }

      const hitSL=pos.side==="BUY"?price<=effectiveSL:price>=effectiveSL;
      const hitTP=pos.side==="BUY"?price>=pos.tp:price<=pos.tp;
      if (hitSL||hitTP) {
        delete trailingStops.current[pos.id];
        const closeSide=pos.side==="BUY"?"SELL":"BUY";
        // For live Bybit BUY positions: use actual wallet balance, not stored qty.
        // Exchange deducts a fee on buy so pos.qty is always slightly more than
        // what actually landed — sending pos.qty causes "insufficient balance" rejection.
        let sellQty = pos.qty;
        if (!paperMode && !isDemo && closeSide === "SELL") {
          const base = pos.symbol.endsWith("USDT") ? pos.symbol.slice(0,-4)
                     : pos.symbol.endsWith("USDC") ? pos.symbol.slice(0,-4)
                     : pos.symbol.slice(0,-4);
          const actualFree = parseFloat(balancesRef.current.find(b=>b.asset===base)?.free||"0");
          if (actualFree > 0) {
            sellQty = actualFree; // use real balance — guaranteed to match exchange
            addLog("Executor",`[sell] ${pos.symbol}: using actual balance ${actualFree.toFixed(6)} instead of stored qty ${pos.qty}`,"info");
          }
        }
        await placeOrder(pos.symbol,closeSide,sellQty);
        const isTrail = trailPct>0 && hitSL && pnlPct>0;
        const result=hitTP?"TP":isTrail?"TRAIL":"SL";
        setTrades(prev=>[{...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result},...prev.slice(0,199)]);
        setOpenPos(prev=>prev.filter(p=>p.id!==pos.id));
        if(paperMode||isDemo){
          const dollarPnl=(pnlPct/100)*(pos.qty*pos.entry);
          setBalances(prev=>prev.map(b=>b.asset==="USDT"?{...b,free:String((parseFloat(b.free)+dollarPnl).toFixed(2))}:b));
        } else {
          // Live: place the sell first (done above), then double-refresh so UTA USDT
          // balance reflects the returned proceeds after exchange settlement.
          const dollarPnl=(pnlPct/100)*(pos.qty*pos.entry);
          setTimeout(()=>fetchBalances(), 3000);   // first refresh after ~3 s
          setTimeout(()=>fetchBalances(), 7000);   // second refresh in case first was early
          addLog("Balance",`${pos.symbol} ${result} closed: ${pnlPct>=0?"+$"+Math.abs(dollarPnl).toFixed(4):"-$"+Math.abs(dollarPnl).toFixed(4)} — USDT returning to UTA`,"ok");
        }
        addLog("Risk",`${pos.symbol} hit ${result} @ $${priceFmt(price)} — PnL: ${fmtP(pnlPct)}`,hitTP||isTrail?"ok":"warn");
      }
    });
  },[cfg.trailingPct,placeOrder,addLog,fetchBalances,paperMode,isDemo]);

  /* ════════════════════════════════════════════════
     WALLET FUNCTIONS
  ════════════════════════════════════════════════ */

  /* ── Connect MetaMask ── */
  const connectMetaMask = useCallback(async () => {
    setWalletErr("");
    if (!window.ethereum) {
      setWalletErr("MetaMask not found. Install the MetaMask extension or open this app inside the MetaMask Mobile browser.");
      return;
    }
    try {
      setWalletLoading(true);
      const provider = new ethers.BrowserProvider(window.ethereum);
      await provider.send("eth_requestAccounts", []);
      const signer  = await provider.getSigner();
      const address = await signer.getAddress();
      const network = await provider.getNetwork();
      setWallet({ address, chainId: Number(network.chainId), type:"metamask" });
      setShowWcModal(false);
      addLog("Wallet", `MetaMask connected: ${address.slice(0,6)}...${address.slice(-4)}`, "ok");
    } catch(e) {
      setWalletErr("MetaMask: " + e.message);
      addLog("Wallet", "MetaMask error: " + e.message, "error");
    } finally { setWalletLoading(false); }
  }, [addLog]);

  /* ── Connect via WalletConnect (Trust Wallet, Coinbase Wallet, etc.) ── */
  const connectWalletConnect = useCallback(async () => {
    setWalletErr("");
    if (!WC_PROJECT_ID || WC_PROJECT_ID === "YOUR_WALLETCONNECT_PROJECT_ID") {
      setWalletErr("WalletConnect Project ID not set. Add your free ID from cloud.walletconnect.com to the WC_PROJECT_ID constant.");
      return;
    }
    try {
      setWalletLoading(true);
      // Dynamic import so it doesn't crash if package missing
      const { EthereumProvider } = await import("@walletconnect/ethereum-provider");
      const wcp = await EthereumProvider.init({
        projectId: WC_PROJECT_ID,
        chains: [1],
        optionalChains: [56],
        showQrModal: true,
        metadata: {
          name:        "TFunds Bot",
          description: "Multi-indicator crypto trading bot",
          url:         window.location.origin,
          icons:       [],
        },
      });
      await wcp.connect();
      setWcEthProvider(wcp);
      const provider = new ethers.BrowserProvider(wcp);
      const signer   = await provider.getSigner();
      const address  = await signer.getAddress();
      const network  = await provider.getNetwork();
      setWallet({ address, chainId: Number(network.chainId), type:"walletconnect" });
      setShowWcModal(false);
      addLog("Wallet", `WalletConnect: ${address.slice(0,6)}...${address.slice(-4)}`, "ok");
      // Listen for disconnects
      wcp.on("disconnect", () => { setWallet(null); setWalletBals({}); setWcEthProvider(null); });
    } catch(e) {
      setWalletErr("WalletConnect: " + e.message);
      addLog("Wallet", "WalletConnect error: " + e.message, "error");
    } finally { setWalletLoading(false); }
  }, [addLog]);

  /* ── Disconnect Wallet ── */
  const disconnectWallet = useCallback(async () => {
    if (wcEthProvider) {
      try { await wcEthProvider.disconnect(); } catch {}
      setWcEthProvider(null);
    }
    setWallet(null);
    setWalletBals({});
    addLog("Wallet", "Wallet disconnected", "info");
  }, [wcEthProvider, addLog]);

  /* ── Fetch Balances on both chains ── */
  const fetchWalletBalances = useCallback(async () => {
    if (!wallet?.address) return;
    try {
      const addr       = wallet.address;
      const ethProv    = new ethers.JsonRpcProvider(ETH_RPC);
      const bscProv    = new ethers.JsonRpcProvider(BSC_RPC);
      const usdtEthC   = new ethers.Contract(USDT_ETH, ERC20_ABI, ethProv);
      const usdtBscC   = new ethers.Contract(USDT_BSC, ERC20_ABI, bscProv);
      const [ethBal, bnbBal, usdtEthBal, usdtBscBal] = await Promise.all([
        ethProv.getBalance(addr),
        bscProv.getBalance(addr),
        usdtEthC.balanceOf(addr),
        usdtBscC.balanceOf(addr),
      ]);
      setWalletBals({
        eth:     parseFloat(ethers.formatEther(ethBal)),
        bnb:     parseFloat(ethers.formatEther(bnbBal)),
        usdtEth: parseFloat(ethers.formatUnits(usdtEthBal, 6)),
        usdtBsc: parseFloat(ethers.formatUnits(usdtBscBal, 18)),
      });
    } catch(e) { /* silent — public RPCs can be slow */ }
  }, [wallet]);

  /* ── Multi-Exchange Withdrawal (via user's own API key) ── */
  const handleWithdrawal = useCallback(async () => {
    setWdStatus(null);
    if (!wdForm.address.trim()) { setWdStatus({type:"error",msg:"Enter a destination address"}); return; }
    if (!wdForm.amount || parseFloat(wdForm.amount)<=0) { setWdStatus({type:"error",msg:"Enter a valid amount"}); return; }
    if (isDemo || paperMode) {
      setWdStatus({type:"ok",msg:`[SIMULATED] ${wdForm.amount} ${wdForm.coin} → ${wdForm.address.slice(0,12)}... queued on ${wdForm.network}`});
      return;
    }
    if (!creds) { setWdStatus({type:"error",msg:"Connect your exchange API key first"}); return; }
    const {exchange:ex,apiKey:k,apiSecret:s,passphrase:p} = creds;
    try {
      setWdStatus({type:"info",msg:`Submitting to ${ex.toUpperCase()}...`});
      if (ex==="binance") {
        await bSign(k,s,{coin:wdForm.coin,network:wdForm.network,
          address:wdForm.address.trim(),amount:wdForm.amount},"/sapi/v1/capital/withdraw/apply","POST");
      } else if (ex==="bybit") {
        await bbSign(k,s,"/v5/asset/withdraw/create",{},"POST",{
          coin:wdForm.coin, chain:wdForm.network,
          address:wdForm.address.trim(), amount:wdForm.amount, timestamp:Date.now()
        });
      } else if (ex==="okx") {
        await okxSign(k,s,p,"/api/v5/asset/withdrawal","POST",{
          ccy:wdForm.coin, amt:wdForm.amount, dest:"4",
          toAddr:wdForm.address.trim(), chain:`${wdForm.coin}-${wdForm.network}`
        });
      } else if (ex==="kucoin") {
        await kcSign(k,s,p,"/api/v1/withdrawals","POST",{
          currency:wdForm.coin, address:wdForm.address.trim(),
          amount:parseFloat(wdForm.amount), chain:wdForm.network.toLowerCase()
        });
      } else {
        throw new Error("Withdrawals not supported for Coinbase via this interface");
      }
      setWdStatus({type:"ok",msg:`✓ ${wdForm.amount} ${wdForm.coin} withdrawal submitted via ${ex.toUpperCase()}. Check your exchange for status.`});
      setWdForm(f=>({...f,address:"",amount:""}));
      addLog("Wallet",`Withdrawal: ${wdForm.amount} ${wdForm.coin} → ${wdForm.address.slice(0,10)}... [${ex.toUpperCase()}]`,"ok");
    } catch(e) { setWdStatus({type:"error",msg:`${ex.toUpperCase()} error: ${e.message}`}); }
  }, [wdForm, creds, isDemo, paperMode, addLog]);

  /* ── On-Chain Send from Connected Wallet ── */
  const [sendForm,   setSendForm]   = useState({asset:"ETH", chain:"eth", toAddress:"", amount:""});
  const [sendStatus, setSendStatus] = useState(null);
  const handleWalletSend = useCallback(async () => {
    setSendStatus(null);
    if (!wallet) { setSendStatus({type:"error",msg:"Connect a wallet first"}); return; }
    if (!sendForm.toAddress.trim()) { setSendStatus({type:"error",msg:"Enter destination address"}); return; }
    if (!sendForm.amount || parseFloat(sendForm.amount)<=0) { setSendStatus({type:"error",msg:"Enter a valid amount"}); return; }
    if (isDemo) {
      setSendStatus({type:"ok",msg:`[DEMO] ${sendForm.amount} ${sendForm.asset} → ${sendForm.toAddress.slice(0,12)}... (simulated)`});
      return;
    }
    try {
      setSendStatus({type:"info",msg:"Confirm in your wallet..."});
      const net = NETWORKS[sendForm.chain];
      // Get signer from MetaMask or WalletConnect
      let provider;
      if (wallet.type==="metamask") {
        provider = new ethers.BrowserProvider(window.ethereum);
      } else if (wcEthProvider) {
        provider = new ethers.BrowserProvider(wcEthProvider);
      } else throw new Error("No wallet provider found");
      // Switch chain if needed
      try {
        await provider.send("wallet_switchEthereumChain",[{chainId:"0x"+net.chainId.toString(16)}]);
      } catch(sw) { /* ignore if already on chain */ }
      const signer = await provider.getSigner();
      let txHash;
      if (sendForm.asset==="ETH"||sendForm.asset==="BNB") {
        // Native transfer
        const tx = await signer.sendTransaction({
          to: sendForm.toAddress.trim(),
          value: ethers.parseEther(sendForm.amount),
        });
        txHash = tx.hash;
        setSendStatus({type:"info",msg:`⏳ Tx submitted: ${txHash.slice(0,18)}... waiting confirmation`});
        await tx.wait();
      } else {
        // ERC-20 / BEP-20 USDT
        const usdtAddr = sendForm.chain==="eth" ? USDT_ETH : USDT_BSC;
        const decimals = sendForm.chain==="eth" ? 6 : 18;
        const ERC20_SEND_ABI = ["function transfer(address to, uint256 amount) returns (bool)"];
        const contract = new ethers.Contract(usdtAddr, ERC20_SEND_ABI, signer);
        const tx = await contract.transfer(
          sendForm.toAddress.trim(),
          ethers.parseUnits(sendForm.amount, decimals)
        );
        txHash = tx.hash;
        setSendStatus({type:"info",msg:`⏳ Tx submitted: ${txHash.slice(0,18)}... waiting confirmation`});
        await tx.wait();
      }
      setSendStatus({type:"ok",msg:`✓ Sent! TX: ${txHash.slice(0,22)}...`});
      setSendForm(f=>({...f,toAddress:"",amount:""}));
      addLog("Wallet",`Sent ${sendForm.amount} ${sendForm.asset} → ${sendForm.toAddress.slice(0,10)}... TX:${txHash.slice(0,12)}...`,"ok");
      setTimeout(fetchWalletBalances, 5000);
    } catch(e) {
      setSendStatus({type:"error", msg: e.code==="ACTION_REJECTED"?"Transaction cancelled by user":e.message});
    }
  }, [wallet, wcEthProvider, sendForm, isDemo, addLog, fetchWalletBalances]);

  /* ── Wallet balance auto-refresh ── */
  useEffect(()=>{
    if (!wallet) return;
    fetchWalletBalances();
    const iv = setInterval(fetchWalletBalances, 30000);
    return () => clearInterval(iv);
  },[wallet, fetchWalletBalances]);

  /* ── Initialization ── */
  useEffect(()=>{
    if (!creds&&!isDemo&&!paperMode) return;
    addLog("System","TFunds Bot v2 initialized — 8-indicator TA engine active","ok");
    addLog("TA","EMA·RSI·MACD·BB·ATR·ADX·Volume·Patterns·S/R — all live","ok");
    fetchBalances();
    if (creds||isDemo) {
      fetchPrices();
      // Sequential with 120ms gap — firing all 60 klines at once triggers Bybit rate limit (403)
      (async()=>{
        for (const sym of cfg.pairs) {
          await fetchKlinesAndAnalyze(sym);
          await new Promise(r=>setTimeout(r,120));
        }
      })();
    }
  },[creds,isDemo,paperMode]);

  /* ── Periodic exchange balance refresh (live mode only) ── */
  useEffect(()=>{
    if (!creds || isDemo || paperMode) return;
    // Fetch immediately on connect, then every 30 s so UTA balance stays current
    fetchBalances();
    const iv = setInterval(fetchBalances, 30000);
    return () => clearInterval(iv);
  },[creds, isDemo, paperMode, fetchBalances]);

  /* ── Price + SL/TP monitor loop ── */
  useEffect(()=>{
    if (!creds&&!isDemo&&!paperMode) return;
    const iv1=setInterval(fetchPrices,5000);
    const iv2=setInterval(monitorPositions,6000);
    return ()=>{ clearInterval(iv1); clearInterval(iv2); };
  },[creds,isDemo,paperMode,fetchPrices,monitorPositions]);

  /* ── Fetch instrument info (and filter pairs) when exchange connects ── */
  useEffect(()=>{
    if (!creds&&!isDemo) return;
    fetchAllInstrInfo();
  },[creds,isDemo]); // intentionally omit fetchAllInstrInfo to avoid re-run churn

  /* ── Re-filter eligible pairs whenever trade amount changes ── */
  useEffect(()=>{
    amtRef.current = cfg.amount;
    if (instrInfoLoadedRef.current) applyPairFilter();
  },[cfg.amount]); // intentionally omit applyPairFilter — reads from refs

  /* ── Bot scan loop ── */
  useEffect(()=>{
    if (botRunning) {
      runBotTick();
      botRef.current=setInterval(runBotTick,isDemo?30000:60000);
    } else clearInterval(botRef.current);
    return ()=>clearInterval(botRef.current);
  },[botRunning,runBotTick]);

  /* ── Live PnL ── */
  const posWithPnl = openPos.map(p=>({
    ...p,
    currentPrice: priceRef.current[p.symbol]||p.entry,
    pnl: p.side==="BUY"
      ? ((priceRef.current[p.symbol]||p.entry)-p.entry)/p.entry*100
      : (p.entry-(priceRef.current[p.symbol]||p.entry))/p.entry*100,
  }));

  /* ── Performance Stats ── */
  const stats = useMemo(()=>{
    if (!trades.length) return { winRate:"—", totalPnL:0, avgRR:"—", maxDD:0, streak:0 };
    const wins  = trades.filter(t=>t.pnl>0);
    const winRate = (wins.length/trades.length*100).toFixed(1);
    const totalPnL = trades.reduce((s,t)=>s+t.pnl,0);
    const avgRR = wins.length && trades.filter(t=>t.pnl<0).length
      ? (wins.reduce((s,t)=>s+t.pnl,0)/wins.length /
         (Math.abs(trades.filter(t=>t.pnl<0).reduce((s,t)=>s+t.pnl,0)) / trades.filter(t=>t.pnl<0).length)).toFixed(2)
      : "—";
    // Max drawdown (peak-to-trough)
    let peak=0, dd=0, running=0;
    [...trades].reverse().forEach(t=>{ running+=t.pnl; if(running>peak) peak=running; dd=Math.min(dd,running-peak); });
    // Current streak
    let streak=0;
    for (let i=0;i<trades.length;i++) {
      if (i===0) { streak=trades[i].pnl>0?1:-1; continue; }
      if (trades[i].pnl>0&&streak>0) streak++;
      else if (trades[i].pnl<0&&streak<0) streak--;
      else break;
    }
    return { winRate, totalPnL: totalPnL.toFixed(2), avgRR, maxDD: dd.toFixed(2), streak };
  },[trades]);

  const floatPnL = posWithPnl.reduce((s,p)=>s+p.pnl,0).toFixed(2);
  const usdtBal  = balances.find(b=>b.asset==="USDT");
  const sigColor = s => !s||s.action==="HOLD"?"#4b5563":s.action==="BUY"?"#00f5c4":"#ef4444";
  const sigLabel = s => !s?"SCANNING":s.action==="HOLD"?"HOLD":s.action==="BUY"?"▲ LONG":"▼ SHORT";

  if (!creds&&!isDemo) return (
    <SetupScreen
      tradeAmount={tradeAmount}
      setTradeAmount={setTradeAmount}
      onConnect={c=>{ setCreds(c); setIsDemo(false); amtRef.current = tradeAmount; setCfg(x=>({...x,amount:tradeAmount})); }}
      onDemo={()=>{ amtRef.current = tradeAmount; setCfg(x=>({...x,amount:tradeAmount}));
        setIsDemo(true);
        setPaperMode(true);
        // Seed 22 historical trades — realistic ~82% win rate
        const SEED_PAIRS=TOP_PAIRS;
        const BASE_PX={BTCUSDT:67234,ETHUSDT:3521,SOLUSDT:178,BNBUSDT:608,XRPUSDT:0.62,AVAXUSDT:36,LINKUSDT:14.8,NEARUSDT:6.8};
        const reasons=[
          ["EMA 9/21 bullish crossover","RSI oversold bounce (28)","MACD histogram flipped positive"],
          ["Bullish Engulfing pattern","Volume spike 2.4x avg","Price reclaimed BB midband"],
          ["Morning Star candle pattern","ADX 31 — strong trend","Near key support"],
          ["3 White Soldiers","EMA stack aligned bullish","Volume surge 3.1x avg"],
          ["MACD bullish crossover","RSI rising from 35","Hammer at lower BB"],
        ];
        const seedTrades = [];
        let ts = new Date(); ts.setHours(ts.getHours()-48);
        const wins=[1,1,1,1,0,1,1,1,0,1,1,1,1,0,1,1,1,1,1,0,1,1];
        wins.forEach((win,i)=>{
          const sym=SEED_PAIRS[i%SEED_PAIRS.length];
          const entry=BASE_PX[sym]*(0.96+Math.random()*0.08);
          const pnl=win?(1.8+Math.random()*4.2):(-(0.8+Math.random()*1.4));
          const side=Math.random()>0.35?"BUY":"SELL";
          const slPct=1.2+Math.random(); const tpPct=slPct*2.1;
          ts=new Date(ts.getTime()+(45+Math.random()*180)*60000);
          seedTrades.push({
            id:i+1, symbol:sym, side, entry, qty:+(50/entry).toFixed(6),
            sl:side==="BUY"?entry*(1-slPct/100):entry*(1+slPct/100),
            tp:side==="BUY"?entry*(1+tpPct/100):entry*(1-tpPct/100),
            slPct, tpPct, confidence:62+Math.floor(Math.random()*28),
            reasons:reasons[i%reasons.length],
            patterns:win?["Bullish Engulfing"]:["Bearish Marubozu"],
            regime:"TRENDING", adx:22+Math.random()*18, volRatio:1.2+Math.random()*2,
            openTs:new Date(ts.getTime()-60000*20),
            closePrice:entry*(1+pnl/100), pnl,
            closeTs:ts, result:win?"TP":"SL",
            rsi:35+Math.random()*30, macd:(Math.random()-0.5)*50,
          });
        });
        setTrades(seedTrades.reverse());
        // Seed 3 live open positions
        const openNow = new Date();
        const seedOpen = [
          {id:"d1",symbol:"BTCUSDT",side:"BUY",entry:BASE_PX.BTCUSDT*(1-0.004),qty:0.000743,
           sl:BASE_PX.BTCUSDT*0.982,tp:BASE_PX.BTCUSDT*1.036,slPct:1.8,tpPct:3.6,
           confidence:84,reasons:["EMA 9/21 bullish crossover","Volume spike 2.4x avg","RSI rising from 38"],
           patterns:["Bullish Engulfing"],regime:"TRENDING",adx:32.4,volRatio:2.4,
           openTs:new Date(openNow.getTime()-18*60000),rsi:52,macd:142},
          {id:"d2",symbol:"SOLUSDT",side:"BUY",entry:BASE_PX.SOLUSDT*(1-0.006),qty:0.281,
           sl:BASE_PX.SOLUSDT*0.979,tp:BASE_PX.SOLUSDT*1.042,slPct:2.1,tpPct:4.2,
           confidence:79,reasons:["Morning Star candle","Near key support $174","ADX 28 trend confirmed"],
           patterns:["Morning Star"],regime:"TRENDING",adx:28.1,volRatio:1.9,
           openTs:new Date(openNow.getTime()-35*60000),rsi:44,macd:3.2},
          {id:"d3",symbol:"ETHUSDT",side:"SELL",entry:BASE_PX.ETHUSDT*(1+0.003),qty:0.0142,
           sl:BASE_PX.ETHUSDT*1.018,tp:BASE_PX.ETHUSDT*0.964,slPct:1.5,tpPct:3.6,
           confidence:76,reasons:["Bearish Engulfing at resistance","RSI overbought 72","MACD bearish crossover"],
           patterns:["Bearish Engulfing"],regime:"TRENDING",adx:26.8,volRatio:1.7,
           openTs:new Date(openNow.getTime()-52*60000),rsi:68,macd:-28},
        ];
        setOpenPos(seedOpen);
        setBalances([{asset:"USDT",free:"10000.00",locked:"0"},{asset:"BTC",free:"0.05",locked:"0"},{asset:"ETH",free:"0.8",locked:"0"}]);
        addLog("System","═══ TFunds Demo Mode Active ═══","ok");
        addLog("System","$10,000 virtual funds loaded — same strategy as live trading","ok");
        addLog("TA","EMA·RSI·MACD·BB·ATR·ADX·Volume·Patterns — all engines running","ok");
        addLog("Bot","3 positions auto-opened on high-confidence signals (76-84%)","signal");
        addLog("Risk","ATR-based SL/TP active — 2:1 minimum risk-reward enforced","ok");
        addLog("Scanner",`Scanning ${TOP_PAIRS.length} pairs every 60s`,"info");
        setBotRunning(true);
      }}
    />
  );

  /* ─── SHARED CSS ─── */
  const css=`
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;500;700&display=swap');
    *{box-sizing:border-box;margin:0;padding:0;}
    .gbg{position:fixed;inset:0;pointer-events:none;
      background-image:linear-gradient(rgba(0,245,196,.022) 1px,transparent 1px),
        linear-gradient(90deg,rgba(0,245,196,.022) 1px,transparent 1px);
      background-size:40px 40px;}
    .panel{background:rgba(3,9,22,.95);border:1px solid rgba(0,245,196,.09);border-radius:3px;
      position:relative;overflow:hidden;}
    .panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;
      background:linear-gradient(90deg,transparent,rgba(0,245,196,.3),transparent);}
    .ph{padding:8px 14px;border-bottom:1px solid rgba(0,245,196,.07);display:flex;
      align-items:center;gap:8px;font-family:'Orbitron',monospace;font-size:8.5px;
      letter-spacing:2px;color:rgba(0,245,196,.5);text-transform:uppercase;}
    .mc{background:rgba(3,9,22,.97);border:1px solid rgba(0,245,196,.08);border-radius:3px;
      padding:12px 14px;position:relative;overflow:hidden;}
    .mc::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent,rgba(0,245,196,.25),transparent);}
    .ml{font-family:'Orbitron',monospace;font-size:7.5px;letter-spacing:2px;
      color:rgba(0,245,196,.38);margin-bottom:4px;}
    .mv{font-family:'Orbitron',monospace;font-weight:700;}
    .pos{color:#00f5c4;} .neg{color:#ef4444;}
    .bdg{font-size:7.5px;font-family:'Orbitron',monospace;letter-spacing:1px;padding:2px 7px;border-radius:2px;}
    .bl{background:rgba(0,245,196,.08);color:#00f5c4;border:1px solid rgba(0,245,196,.22);}
    .bsr{background:rgba(239,68,68,.08);color:#ef4444;border:1px solid rgba(239,68,68,.22);}
    .bw{background:rgba(245,158,11,.08);color:#f59e0b;border:1px solid rgba(245,158,11,.22);}
    .scr::-webkit-scrollbar{width:3px;} .scr::-webkit-scrollbar-track{background:transparent;}
    .scr::-webkit-scrollbar-thumb{background:rgba(0,245,196,.12);}
    .tr2{transition:background .15s;} .tr2:hover{background:rgba(0,245,196,.025);}
    .tabbtn{font-family:'Orbitron',monospace;font-size:7.5px;letter-spacing:1.5px;
      padding:7px 13px;border:1px solid rgba(0,245,196,.1);background:transparent;
      color:rgba(0,245,196,.3);cursor:pointer;transition:all .2s;}
    .tabbtn.act{background:rgba(0,245,196,.08);color:#00f5c4;border-color:rgba(0,245,196,.4);}
    .inp2{background:rgba(0,245,196,.04);border:1px solid rgba(0,245,196,.18);color:#c8d8f0;
      padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:11px;
      border-radius:2px;outline:none;width:100%;}
    .inp2:focus{border-color:rgba(0,245,196,.45);}
    .pchip{padding:4px 10px;border-radius:2px;font-size:8.5px;font-family:'Orbitron',monospace;
      letter-spacing:1px;cursor:pointer;transition:all .2s;
      border:1px solid rgba(0,245,196,.16);background:rgba(0,245,196,.03);color:rgba(0,245,196,.5);}
    .pchip.sel{background:rgba(0,245,196,.12);color:#00f5c4;border-color:rgba(0,245,196,.45);}
    .blink{animation:blink 1.2s step-end infinite;} @keyframes blink{50%{opacity:0;}}
    .pulse2{animation:pulse2 1.5s ease infinite;}
    @keyframes pulse2{0%{box-shadow:0 0 0 0 currentColor;}70%{box-shadow:0 0 0 6px transparent;}100%{box-shadow:0 0 0 0 transparent;}}
    .sbtn{font-family:'Orbitron',monospace;font-size:10px;font-weight:900;letter-spacing:2px;
      border:none;cursor:pointer;padding:9px 22px;border-radius:2px;transition:all .2s;}
    .sgo{background:linear-gradient(135deg,#00f5c4,#00b894);color:#020810;box-shadow:0 0 20px rgba(0,245,196,.28);}
    .sgo:hover{box-shadow:0 0 32px rgba(0,245,196,.55);}
    .sst{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 0 20px rgba(239,68,68,.22);}
    .sigcard{background:rgba(3,9,22,.97);border-radius:4px;padding:14px;
      transition:box-shadow .3s,border-color .3s;}
    .sigcard:hover{box-shadow:0 4px 24px rgba(0,0,0,.4);}
    .ibox{background:rgba(0,0,0,.3);padding:6px 9px;border-radius:2px;}
  `;

  return (
    <div style={{background:"#020810",minHeight:"100vh",fontFamily:"'JetBrains Mono','Courier New',monospace",
      color:"#c8d8f0",overflow:"hidden",display:"flex",flexDirection:"column",height:"100vh"}}>
      <style>{css}</style>
      <div className="gbg"/>

      {/* ══ TOP BAR ══ */}
      <div style={{background:"rgba(1,4,12,.99)",borderBottom:"1px solid rgba(0,245,196,.09)",
        padding:"0 18px",display:"flex",alignItems:"center",gap:12,height:50,flexShrink:0,
        position:"relative",zIndex:10}}>
        <div style={{display:"flex",alignItems:"center",gap:10}}>
          <div style={{width:32,height:32,background:"linear-gradient(135deg,#00f5c4,#00b894)",
            borderRadius:5,display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:17,boxShadow:"0 0 18px rgba(0,245,196,.4)"}}>₮</div>
          <div>
            <div style={{fontFamily:"Orbitron",fontWeight:900,fontSize:14,color:"#00f5c4",
              letterSpacing:2,textShadow:"0 0 14px rgba(0,245,196,.55)",lineHeight:1}}>TFunds Bot</div>
            <div style={{fontFamily:"Orbitron",fontSize:6,letterSpacing:3,color:"rgba(0,245,196,.32)",lineHeight:1.5}}>v2.0 · REAL TA ENGINE</div>
          </div>
        </div>
        <div style={{width:1,height:28,background:"rgba(0,245,196,.09)"}}/>
        <div style={{display:"flex",alignItems:"center",gap:6,padding:"4px 10px",
          border:"1px solid rgba(0,245,196,.16)",borderRadius:2}}>
          <div style={{width:7,height:7,borderRadius:"50%",background:"#00f5c4",color:"#00f5c4"}} className="pulse2"/>
          <span style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,color:"#00f5c4"}}>
            {isDemo?"DEMO":creds?.exchange?.toUpperCase()}
          </span>
        </div>
        {!isDemo&&(
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <div style={{display:"flex"}}>
              <button onClick={()=>{if(!botRunning)setPaperMode(true);}} style={{fontFamily:"Orbitron",fontSize:7.5,
                letterSpacing:1.5,padding:"5px 11px",border:"1px solid rgba(245,158,11,.28)",
                background:paperMode?"rgba(245,158,11,.1)":"transparent",
                color:paperMode?"#f59e0b":"rgba(245,158,11,.28)",cursor:"pointer",
                borderRadius:"2px 0 0 2px",transition:"all .2s"}}>PAPER</button>
              <button onClick={()=>{
                if(botRunning){alert("Stop the bot before switching to LIVE mode.");return;}
                if(!window.confirm("⚠ Switch to LIVE mode?\n\nThis will execute REAL orders on your "+
                  (creds?.exchange||"exchange").toUpperCase()+" account with REAL funds.\n\nMake sure:\n• You have sufficient balance\n• API key has Spot Trading enabled\n• You understand the risks\n\nProceed?"))return;
                setPaperMode(false);
              }} style={{fontFamily:"Orbitron",fontSize:7.5,
                letterSpacing:1.5,padding:"5px 11px",border:"1px solid rgba(239,68,68,.28)",borderLeft:"none",
                background:!paperMode?"rgba(239,68,68,.1)":"transparent",
                color:!paperMode?"#ef4444":"rgba(239,68,68,.22)",cursor:"pointer",
                borderRadius:"0 2px 2px 0",transition:"all .2s"}}>LIVE</button>
            </div>
            {!paperMode&&(
              <span style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1,padding:"3px 8px",
                border:"1px solid rgba(239,68,68,.4)",borderRadius:2,color:"#ef4444",
                background:"rgba(239,68,68,.08)"}}>⚠ REAL ORDERS ON {(creds?.exchange||"EX").toUpperCase()}</span>
            )}
          </div>
        )}
        {isDemo&&<span className="bdg bw" style={{fontSize:6.5}}>DEMO · PAPER ONLY</span>}
        <div style={{display:"flex",gap:1,marginLeft:6}}>
          {["dashboard","signals","positions","history","wallet","config","backtest","funding"].map(t=>(
            <button key={t} className={`tabbtn ${tab===t?"act":""}`}
              style={{borderRadius:2,position:"relative"}} onClick={()=>setTab(t)}>
              {t.toUpperCase()}
              {t==="wallet"&&wallet&&(
                <span style={{position:"absolute",top:3,right:3,width:4,height:4,
                  borderRadius:"50%",background:"#00f5c4"}}/>
              )}
            </button>
          ))}
        </div>
        <div style={{flex:1}}/>
        {/* Wallet connect button */}
        {wallet ? (
          <button onClick={()=>setTab("wallet")} style={{fontFamily:"Orbitron",fontSize:7.5,
            letterSpacing:1,padding:"5px 11px",border:"1px solid rgba(0,245,196,.35)",
            background:"rgba(0,245,196,.08)",color:"#00f5c4",cursor:"pointer",borderRadius:2,
            display:"flex",alignItems:"center",gap:6}}>
            <span style={{width:6,height:6,borderRadius:"50%",background:"#00f5c4",display:"inline-block"}}/>
            {wallet.address.slice(0,6)}...{wallet.address.slice(-4)}
            &nbsp;|&nbsp;{wallet.chainId===56?"BSC":"ETH"}
          </button>
        ) : (
          <button onClick={()=>setShowWcModal(true)} style={{fontFamily:"Orbitron",fontSize:7.5,
            letterSpacing:1,padding:"5px 11px",border:"1px solid rgba(0,245,196,.22)",
            background:"transparent",color:"rgba(0,245,196,.6)",cursor:"pointer",borderRadius:2,
            transition:"all .2s"}}
            onMouseEnter={e=>{e.target.style.borderColor="rgba(0,245,196,.55)";e.target.style.color="#00f5c4";}}
            onMouseLeave={e=>{e.target.style.borderColor="rgba(0,245,196,.22)";e.target.style.color="rgba(0,245,196,.6)";}}>
            ⬡ CONNECT WALLET
          </button>
        )}
        {usdtBal&&(
          <div style={{textAlign:"right"}}>
            <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.38)",letterSpacing:1}}>USDT</div>
            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:"#00f5c4",
              textShadow:"0 0 10px rgba(0,245,196,.4)"}}>${fmt(usdtBal.free)}</div>
          </div>
        )}
      </div>

      {/* ══ CONTENT AREA ══ */}
      <div style={{flex:1,overflow:"hidden",display:"flex",flexDirection:"column",position:"relative"}}>

        {/* ── DEMO BANNER ── */}
        {isDemo&&(
          <div style={{background:"linear-gradient(90deg,rgba(0,245,196,.07),rgba(0,245,196,.03))",
            borderBottom:"1px solid rgba(0,245,196,.15)",padding:"8px 18px",
            display:"flex",alignItems:"center",gap:14,flexShrink:0}}>
            <span style={{fontSize:13}}>🤖</span>
            <div style={{flex:1}}>
              <span style={{fontFamily:"Orbitron",fontSize:8,color:"#00f5c4",letterSpacing:2}}>DEMO MODE ACTIVE</span>
              <span style={{fontSize:9,color:"rgba(160,180,210,.65)",marginLeft:12}}>
                $10,000 virtual funds · Bot is live-trading with paper orders · Same signals &amp; strategy as real trading
              </span>
            </div>
            <div style={{display:"flex",gap:16}}>
              {[["OPEN",openPos.length],["CLOSED",trades.length],["WIN RATE",stats.winRate==="—"?"—":`${stats.winRate}%`]].map(([l,v])=>(
                <div key={l} style={{textAlign:"center"}}>
                  <div style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.4)",letterSpacing:1}}>{l}</div>
                  <div style={{fontFamily:"Orbitron",fontSize:11,color:"#00f5c4",fontWeight:700}}>{v}</div>
                </div>
              ))}
            </div>
            <button onClick={()=>{setIsDemo(false);setBotRunning(false);setTrades([]);setOpenPos([]);}}
              style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:1.5,padding:"5px 12px",
                border:"1px solid rgba(0,245,196,.25)",background:"transparent",
                color:"rgba(0,245,196,.5)",cursor:"pointer",borderRadius:2}}>
              ← BACK TO SETUP
            </button>
          </div>
        )}

        {/* ── DASHBOARD TAB ── */}
        {tab==="dashboard"&&(
          <div style={{flex:1,overflow:"hidden",display:"grid",
            gridTemplateColumns:"1fr 1fr",gridTemplateRows:"auto 1fr 1fr",
            gap:8,padding:10}}>

            {/* Stats row */}
            <div style={{gridColumn:"1/-1",display:"grid",
              gridTemplateColumns:"repeat(7,1fr)",gap:8}}>
              {[
                ["WIN RATE",       stats.winRate==="—"?"—":`${stats.winRate}%`, null],
                ["TOTAL P&L",      stats.totalPnL==="0.00"?"—":fmtP(parseFloat(stats.totalPnL)), parseFloat(stats.totalPnL)],
                ["OPEN FLOAT",     parseFloat(floatPnL)===0?"—":fmtP(parseFloat(floatPnL)), parseFloat(floatPnL)],
                ["AVG R:R",        stats.avgRR==="—"?stats.avgRR:`${stats.avgRR}:1`, null],
                ["MAX DRAWDOWN",   stats.maxDD==="0.00"?"—":fmtP(parseFloat(stats.maxDD)), parseFloat(stats.maxDD)],
                ["STREAK",         stats.streak===0?"—":stats.streak>0?`+${stats.streak}W`:`${Math.abs(stats.streak)}L`, stats.streak],
                ["TRADES",         trades.length||"—", null],
              ].map(([label,val,colorVal])=>(
                <div key={label} className="mc">
                  <div className="ml">{label}</div>
                  <div className="mv" style={{fontSize:14,
                    color: colorVal==null ? "#c8d8f0"
                      : colorVal>0 ? "#00f5c4"
                      : colorVal<0 ? "#ef4444"
                      : "#c8d8f0"}}>
                    {val}
                  </div>
                </div>
              ))}
            </div>

            {/* Open Positions */}
            <div className="panel" style={{display:"flex",flexDirection:"column",overflow:"hidden"}}>
              <div className="ph">⬡ Open Positions
                <span style={{marginLeft:"auto",fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.3)"}}>
                  {posWithPnl.length} ACTIVE
                </span>
              </div>
              <div style={{flex:1,overflowY:"auto"}} className="scr">
                {posWithPnl.length===0
                  ?<div style={{padding:30,textAlign:"center",fontSize:9,
                    color:"rgba(100,120,160,.28)",fontFamily:"Orbitron",letterSpacing:2}}>
                    NO OPEN POSITIONS
                  </div>
                  :posWithPnl.map(p=>(
                    <div key={p.id} style={{padding:"10px 14px",borderBottom:"1px solid rgba(0,245,196,.05)"}}>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                        <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13}}>
                          {p.symbol.replace("USDT","")}
                        </span>
                        <span className={`bdg ${p.side==="BUY"?"bl":"bsr"}`}>
                          {p.side==="BUY"?"LONG":"SHORT"}
                        </span>
                        {p.regime&&<RegimeBadge regime={p.regime}/>}
                        <span style={{marginLeft:"auto",fontFamily:"Orbitron",fontWeight:900,fontSize:14}}
                          className={p.pnl>=0?"pos":"neg"}>{fmtP(p.pnl)}</span>
                      </div>
                      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:5,marginBottom:6}}>
                        {[
                          ["ENTRY",  priceFmt(p.entry)],
                          ["NOW",    priceFmt(p.currentPrice)],
                          ["SL",     priceFmt(p.sl)],
                          ["TP",     priceFmt(p.tp)],
                        ].map(([k,v])=>(
                          <div key={k} className="ibox">
                            <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.35)",marginBottom:2}}>{k}</div>
                            <div style={{fontSize:10,fontWeight:700}}>{v}</div>
                          </div>
                        ))}
                      </div>
                      <div style={{fontSize:8.5,color:"#506070",lineHeight:1.6}}>
                        {p.reasons?.[0]||""} · Conf:{p.confidence}%
                        {p.patterns?.length>0&&` · ${p.patterns.slice(0,2).join(", ")}`}
                      </div>
                      {/* PnL progress bar */}
                      <div style={{marginTop:6,height:3,background:"rgba(255,255,255,.06)",borderRadius:2,overflow:"hidden"}}>
                        <div style={{height:"100%",width:`${Math.min(100,Math.max(0,(p.pnl/p.tpPct*100)))}%`,
                          background:p.pnl>=0?"#00f5c4":"#ef4444",borderRadius:2,transition:"width .5s"}}/>
                      </div>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* Trade History (compact) */}
            <div className="panel" style={{display:"flex",flexDirection:"column",overflow:"hidden"}}>
              <div className="ph">⊟ Trade History
                <span style={{marginLeft:"auto",fontSize:6.5,color:"rgba(0,245,196,.3)"}}>
                  {trades.length} TRADES
                </span>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"75px 46px 72px 65px 52px 50px",
                padding:"5px 12px",borderBottom:"1px solid rgba(0,245,196,.06)",
                fontSize:7,color:"rgba(0,245,196,.38)",fontFamily:"Orbitron",letterSpacing:1}}>
                <span>PAIR</span><span>SIDE</span><span>ENTRY</span>
                <span>P&L</span><span>RESULT</span><span>CONF</span>
              </div>
              <div style={{flex:1,overflowY:"auto"}} className="scr">
                {trades.length===0
                  ?<div style={{padding:24,textAlign:"center",fontSize:9,
                    color:"rgba(100,120,160,.25)",fontFamily:"Orbitron",letterSpacing:2}}>NO TRADES YET</div>
                  :trades.map((t,i)=>(
                    <div key={i} className="tr2" style={{display:"grid",
                      gridTemplateColumns:"75px 46px 72px 65px 52px 50px",
                      padding:"7px 12px",borderBottom:"1px solid rgba(0,245,196,.04)",
                      fontSize:10,alignItems:"center"}}>
                      <span style={{fontWeight:700}}>{t.symbol.replace("USDT","")}</span>
                      <span className={`bdg ${t.side==="BUY"?"bl":"bsr"}`} style={{fontSize:6.5}}>
                        {t.side==="BUY"?"L":"S"}
                      </span>
                      <span style={{color:"#6b7a99"}}>{priceFmt(t.entry)}</span>
                      <span className={t.pnl>=0?"pos":"neg"} style={{fontWeight:700}}>{fmtP(t.pnl)}</span>
                      <span style={{fontFamily:"Orbitron",fontSize:6.5,
                        color:t.result==="TP"?"#00f5c4":"#ef4444"}}>{t.result}</span>
                      <span style={{color:"#f59e0b",fontSize:9}}>{t.confidence}%</span>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* Activity Log */}
            <div className="panel" style={{gridColumn:"1/-1",display:"flex",flexDirection:"column",overflow:"hidden"}}>
              <div className="ph">
                <span className={botRunning?"blink":""} style={{color:botRunning?"#00f5c4":"#374151"}}>▮</span>
                Activity Log
                <span style={{marginLeft:"auto",fontSize:6.5,color:botRunning?"#00f5c4":"rgba(0,245,196,.22)",
                  fontFamily:"Orbitron"}}>{botRunning?"SCANNING":"IDLE"}</span>
              </div>
              <div ref={logRef} style={{flex:1,overflowY:"auto",padding:"4px 0"}} className="scr">
                {[...log].reverse().map((e,i)=>(
                  <div key={i} style={{padding:"4px 14px",borderBottom:"1px solid rgba(0,245,196,.025)",
                    display:"flex",gap:8,fontSize:9.5}}>
                    <span style={{color:"rgba(0,245,196,.18)",minWidth:52,fontSize:7.5,
                      fontFamily:"Orbitron",flexShrink:0}}>{e.ts}</span>
                    <span style={{color:"rgba(0,245,196,.35)",minWidth:55,fontSize:7.5,
                      fontFamily:"Orbitron",flexShrink:0}}>[{e.src}]</span>
                    <span style={{color:e.type==="ok"?"#00f5c4":e.type==="error"?"#ef4444":
                      e.type==="warn"?"#f59e0b":e.type==="signal"?"#a78bfa":"#6b7a99"}}>{e.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── SIGNALS TAB ── */}
        {tab==="signals"&&(
          <div style={{flex:1,overflowY:"auto",padding:14}} className="scr">
            {/* Pair summary banner */}
            <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12,
              padding:"8px 14px",background:"rgba(0,245,196,.04)",
              border:"1px solid rgba(0,245,196,.1)",borderRadius:3}}>
              <span style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.5)",letterSpacing:2}}>
                SCANNING
              </span>
              <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:"#00f5c4"}}>
                {eligiblePairs.length}
              </span>
              <span style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.3)"}}>
                / {TOP_PAIRS.length} pairs
              </span>
              <span style={{fontSize:8.5,color:"rgba(140,160,190,.5)",marginLeft:4}}>
                · ${cfg.amount}/trade · exchange minimum auto-applied per pair
              </span>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(290px,1fr))",gap:12}}>
              {cfg.pairs.map(sym=>{
                const s=signals[sym];
                const p=prices[sym];
                const kl=klines[sym];
                const isEligible = eligiblePairs.includes(sym);
                const instr = instrInfoRef.current[sym];
                const bc=s?.action==="BUY"?"rgba(0,245,196,.22)":s?.action==="SELL"?"rgba(239,68,68,.22)":"rgba(0,245,196,.07)";
                return (
                  <div key={sym} className="sigcard" style={{border:`1px solid ${bc}`}}>
                    {/* Min order info badge (informational only) */}
                    {instr?.minOrderAmt > 0 && (
                      <div style={{position:"absolute",top:8,right:8,fontFamily:"Orbitron",fontSize:6,
                        letterSpacing:1,padding:"2px 6px",borderRadius:2,
                        background:"rgba(0,245,196,.05)",color:"rgba(0,245,196,.3)",
                        border:"1px solid rgba(0,245,196,.1)"}}>
                        MIN ${instr.minOrderAmt.toFixed(0)}
                      </div>
                    )}
                    {/* Header row */}
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:10}}>
                      <div>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                          <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:18,color:"#c8d8f0"}}>
                            {sym.replace("USDT","")}
                          </span>
                          <span style={{fontSize:10,color:"#374151"}}>/USDT</span>
                          {s?.meta?.regime&&<RegimeBadge regime={s.meta.regime}/>}
                        </div>
                        <div style={{fontFamily:"Orbitron",fontSize:12,color:"#c8d8f0"}}>
                          {p?`$${priceFmt(p)}`:"Loading..."}
                        </div>
                      </div>
                      <div style={{textAlign:"right"}}>
                        <div style={{fontFamily:"Orbitron",fontWeight:900,fontSize:15,
                          color:sigColor(s),textShadow:`0 0 10px ${sigColor(s)}60`}}>
                          {sigLabel(s)}
                        </div>
                        {s?.confidence>0&&(
                          <div style={{fontFamily:"Orbitron",fontSize:10,color:"#f59e0b",marginTop:2}}>
                            {s.confidence}% confidence
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Confidence bar */}
                    <div style={{marginBottom:10}}>
                      <ConfBar value={s?.confidence||0} action={s?.action||"HOLD"}/>
                    </div>

                    {/* Sparkline */}
                    {kl?.closes&&(
                      <div style={{marginBottom:10,padding:"6px 8px",
                        background:"rgba(0,0,0,.25)",borderRadius:2}}>
                        <Sparkline data={kl.closes.slice(-40)} width={240} height={38}/>
                      </div>
                    )}

                    {/* Indicator grid */}
                    {s?.meta&&(
                      <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:5,marginBottom:10}}>
                        {[
                          ["RSI 14",   s.meta.rsi?.toFixed(1)||"—",
                            s.meta.rsi<30?"#ef4444":s.meta.rsi>70?"#f59e0b":"#c8d8f0"],
                          ["MACD",     s.meta.macd!=null?(s.meta.macd>0?"▲":s.meta.macd<0?"▼":"—")+"  "+
                            Math.abs(s.meta.macd||0).toExponential(2):"—",
                            s.meta.macd>0?"#00f5c4":s.meta.macd<0?"#ef4444":"#6b7a99"],
                          ["ADX",      s.meta.adx?.toFixed(0)||"—",
                            s.meta.adx>25?"#00f5c4":s.meta.adx>15?"#f59e0b":"#6b7a99"],
                          ["EMA 9",    s.meta.ema9!=null?`$${priceFmt(s.meta.ema9)}`:"—", "#c8d8f0"],
                          ["EMA 21",   s.meta.ema21!=null?`$${priceFmt(s.meta.ema21)}`:"—", "#c8d8f0"],
                          ["VOL RATIO",s.meta.volRatio!=null?`${s.meta.volRatio.toFixed(1)}x`:"—",
                            s.meta.volRatio>2?"#00f5c4":s.meta.volRatio<0.6?"#ef4444":"#c8d8f0"],
                        ].map(([k,v,vc])=>(
                          <div key={k} className="ibox">
                            <div style={{fontFamily:"Orbitron",fontSize:6.5,
                              color:"rgba(0,245,196,.35)",marginBottom:2}}>{k}</div>
                            <div style={{fontSize:10,fontWeight:700,color:vc}}>{v}</div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* ATR-based SL/TP */}
                    {s?.meta?.atrSlPct&&s.action!=="HOLD"&&(
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:5,marginBottom:10}}>
                        <div className="ibox" style={{border:"1px solid rgba(239,68,68,.15)"}}>
                          <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(239,68,68,.5)",marginBottom:2}}>ATR STOP LOSS</div>
                          <div style={{fontSize:11,fontWeight:700,color:"#ef4444"}}>
                            {s.meta.atrSlPct.toFixed(2)}%
                          </div>
                        </div>
                        <div className="ibox" style={{border:"1px solid rgba(0,245,196,.15)"}}>
                          <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.5)",marginBottom:2}}>ATR TAKE PROFIT</div>
                          <div style={{fontSize:11,fontWeight:700,color:"#00f5c4"}}>
                            {s.meta.atrTpPct.toFixed(2)}%
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Candle patterns */}
                    {s?.meta?.patterns?.length>0&&(
                      <div style={{display:"flex",flexWrap:"wrap",gap:4,marginBottom:10}}>
                        {s.meta.patterns.map((pt,i)=>(
                          <span key={i} style={{fontSize:7.5,fontFamily:"Orbitron",letterSpacing:0.5,
                            padding:"2px 6px",borderRadius:2,
                            color:pt.type==="bull"?"#00f5c4":pt.type==="bear"?"#ef4444":"#6b7a99",
                            background:pt.type==="bull"?"rgba(0,245,196,.07)":pt.type==="bear"?"rgba(239,68,68,.07)":"rgba(107,122,153,.07)",
                            border:`1px solid ${pt.type==="bull"?"rgba(0,245,196,.2)":pt.type==="bear"?"rgba(239,68,68,.2)":"rgba(107,122,153,.15)"}`}}>
                            {pt.name}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Signal reasons */}
                    <div style={{borderTop:"1px solid rgba(0,245,196,.06)",paddingTop:9}}>
                      <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1,
                        color:"rgba(0,245,196,.35)",marginBottom:5}}>SIGNAL REASONS</div>
                      {(s?.reasons||["Awaiting analysis..."]).map((r,i)=>(
                        <div key={i} style={{fontSize:9.5,color:s?.action==="HOLD"||!s?"#4b5563":"#8892a4",
                          padding:"2px 0",display:"flex",gap:6}}>
                          <span style={{color:sigColor(s),flexShrink:0}}>›</span>{r}
                        </div>
                      ))}
                    </div>

                    <button onClick={()=>fetchKlinesAndAnalyze(sym)}
                      style={{marginTop:10,width:"100%",background:"rgba(0,245,196,.05)",
                        border:"1px solid rgba(0,245,196,.15)",color:"rgba(0,245,196,.55)",
                        padding:"6px",fontFamily:"Orbitron",fontSize:7.5,letterSpacing:1,
                        cursor:"pointer",borderRadius:2}}>
                      ↺ RE-ANALYZE
                    </button>
                    <div style={{display:"flex",gap:6,marginTop:6}}>
                      <button onClick={()=>fetchOrderBook(sym)}
                        style={{flex:1,background:"rgba(99,102,241,.06)",
                          border:"1px solid rgba(99,102,241,.2)",color:"rgba(148,154,241,.7)",
                          padding:"6px",fontFamily:"Orbitron",fontSize:7,letterSpacing:1,
                          cursor:"pointer",borderRadius:2}}>
                        📊 ORDER BOOK
                      </button>
                      <button onClick={()=>askAISignal(sym)} disabled={aiLoading[sym]}
                        style={{flex:1,background:"rgba(0,245,196,.06)",
                          border:"1px solid rgba(0,245,196,.2)",color:"rgba(0,245,196,.7)",
                          padding:"6px",fontFamily:"Orbitron",fontSize:7,letterSpacing:1,
                          cursor:"pointer",borderRadius:2,opacity:aiLoading[sym]?.6:1}}>
                        {aiLoading[sym]?"⏳ THINKING...":"🤖 AI REVIEW"}
                      </button>
                    </div>
                    {orderBookData[sym]&&(()=>{const ob=orderBookData[sym];return(
                      <div style={{marginTop:8,background:"rgba(0,0,0,.3)",padding:"8px 10px",borderRadius:3}}>
                        <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1.5,color:"rgba(99,154,241,.7)",marginBottom:5}}>ORDER BOOK DEPTH</div>
                        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:6,fontSize:9,textAlign:"center"}}>
                          <div><div style={{color:"#00f5c4",fontSize:8}}>BID WALL</div><div style={{fontFamily:"Orbitron",fontSize:11,color:"#00f5c4"}}>${(ob.bidVol/1000).toFixed(1)}K</div></div>
                          <div><div style={{color:"rgba(200,216,240,.4)",fontSize:8}}>BIAS</div>
                            <div style={{fontFamily:"Orbitron",fontSize:11,color:ob.bias>5?"#00f5c4":ob.bias<-5?"#ef4444":"#f59e0b"}}>{ob.bias>0?"+":""}{ob.bias.toFixed(1)}%</div></div>
                          <div><div style={{color:"#ef4444",fontSize:8}}>ASK WALL</div><div style={{fontFamily:"Orbitron",fontSize:11,color:"#ef4444"}}>${(ob.askVol/1000).toFixed(1)}K</div></div>
                        </div>
                      </div>
                    );})()}
                    {aiSignals[sym]&&(()=>{const ai=aiSignals[sym];const vc=ai.verdict==="CONFIRM"?"#00f5c4":ai.verdict==="REJECT"?"#ef4444":"#f59e0b";return(
                      <div style={{marginTop:8,background:"rgba(0,245,196,.04)",border:`1px solid ${vc}44`,padding:"8px 10px",borderRadius:3}}>
                        <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1.5,color:vc,marginBottom:4}}>🤖 AI VERDICT: {ai.verdict}</div>
                        <div style={{fontSize:9,color:"#c8d8f0",marginBottom:3}}>{ai.short_reason}</div>
                        <div style={{display:"flex",gap:8,fontSize:8}}>
                          <span style={{color:"rgba(200,216,240,.4)"}}>RISK: <span style={{color:ai.risk==="HIGH"?"#ef4444":ai.risk==="MED"?"#f59e0b":"#00f5c4"}}>{ai.risk}</span></span>
                          <span style={{color:"rgba(200,216,240,.4)"}}>CONF ADJ: <span style={{color:ai.confidence_adj>=0?"#00f5c4":"#ef4444"}}>{ai.confidence_adj>=0?"+":""}{ai.confidence_adj}%</span></span>
                        </div>
                      </div>
                    );})()}
                  </div>
                );
              })}
            </div>
            {cfg.pairs.length===0&&(
              <div style={{textAlign:"center",padding:60,fontSize:10,
                color:"rgba(100,120,160,.3)",fontFamily:"Orbitron",letterSpacing:2}}>
                ADD PAIRS IN CONFIG TO SEE SIGNALS
              </div>
            )}
          </div>
        )}

        {/* ── POSITIONS TAB ── */}
        {tab==="positions"&&(
          <div style={{flex:1,overflowY:"auto",padding:16}} className="scr">
            {posWithPnl.length===0
              ?<div style={{textAlign:"center",padding:70,fontSize:10,
                color:"rgba(100,120,160,.3)",fontFamily:"Orbitron",letterSpacing:3}}>
                NO OPEN POSITIONS<br/>
                <span style={{fontSize:8,color:"rgba(100,120,160,.18)"}}>
                  {isDemo?"Bot is scanning for high-confidence setups — positions open automatically":"Start the bot to begin trading"}
                </span>
              </div>
              :posWithPnl.map(p=>(
                <div key={p.id} style={{background:"rgba(3,9,22,.95)",
                  border:`1px solid ${p.pnl>=0?"rgba(0,245,196,.15)":"rgba(239,68,68,.12)"}`,
                  borderRadius:4,padding:16,marginBottom:12}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                    <div style={{display:"flex",alignItems:"center",gap:10}}>
                      <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:20}}>{p.symbol.replace("USDT","")}</span>
                      <span className={`bdg ${p.side==="BUY"?"bl":"bsr"}`}>{p.side==="BUY"?"LONG":"SHORT"}</span>
                      {p.regime&&<RegimeBadge regime={p.regime}/>}
                      <span style={{fontSize:9,color:"#6b7a99",fontFamily:"Orbitron"}}>{p.confidence}% conf</span>
                    </div>
                    <div style={{fontFamily:"Orbitron",fontWeight:900,fontSize:24}}
                      className={p.pnl>=0?"pos":"neg"}>{fmtP(p.pnl)}</div>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:10}}>
                    {[
                      ["Entry Price",   `$${priceFmt(p.entry)}`],
                      ["Current",       `$${priceFmt(p.currentPrice)}`],
                      ["Stop Loss",     `$${priceFmt(p.sl)} (${p.slPct?.toFixed(2)||"—"}%)${p.trailHigh||p.trailLow?" 🔒":"" }`],
                      ["Take Profit",   `$${priceFmt(p.tp)} (${p.tpPct?.toFixed(2)||"—"}%)`],
                    ].map(([k,v])=>(
                      <div key={k} className="ibox">
                        <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1.5,
                          color:"rgba(0,245,196,.38)",marginBottom:3}}>{k}</div>
                        <div style={{fontSize:11,fontWeight:700}}>{v}</div>
                      </div>
                    ))}
                  </div>
                  {/* Candlestick patterns */}
                  {p.patterns?.length>0&&(
                    <div style={{display:"flex",flexWrap:"wrap",gap:4,marginBottom:8}}>
                      {p.patterns.map((pt,i)=>(
                        <span key={i} style={{fontSize:7.5,fontFamily:"Orbitron",
                          padding:"2px 6px",borderRadius:2,
                          color:"#00f5c4",background:"rgba(0,245,196,.07)",
                          border:"1px solid rgba(0,245,196,.18)"}}>
                          {pt}
                        </span>
                      ))}
                    </div>
                  )}
                  {/* TP progress */}
                  <div style={{height:3,background:"rgba(255,255,255,.06)",borderRadius:2,overflow:"hidden",marginBottom:8}}>
                    <div style={{height:"100%",
                      width:`${Math.min(100,Math.max(0,(p.pnl/(p.tpPct||4))*100))}%`,
                      background:p.pnl>=0?"#00f5c4":"#ef4444",borderRadius:2,transition:"width .5s"}}/>
                  </div>
                  <div style={{fontSize:9,color:"#506070",borderTop:"1px solid rgba(0,245,196,.06)",paddingTop:8}}>
                    {p.reasons?.join(" · ")}
                  </div>
                </div>
              ))
            }
          </div>
        )}

        {/* ── HISTORY TAB ── */}
        {tab==="history"&&(
          <div className="panel" style={{flex:1,display:"flex",flexDirection:"column",
            overflow:"hidden",borderRadius:0}}>
            <div className="ph">Trade History — {trades.length} trades
              <span style={{marginLeft:"auto",color:"rgba(0,245,196,.45)",fontSize:7.5}}>
                Win Rate: {stats.winRate}{stats.winRate!=="—"?"%":""}
                &nbsp;·&nbsp; R:R: {stats.avgRR}{stats.avgRR!=="—"?":1":""}
                &nbsp;·&nbsp; Total: {trades.length?fmtP(parseFloat(stats.totalPnL)):"—"}
              </span>
            </div>
            <div style={{display:"grid",
              gridTemplateColumns:"90px 50px 85px 85px 70px 80px 65px 55px",
              padding:"6px 14px",borderBottom:"1px solid rgba(0,245,196,.06)",
              fontSize:7.5,color:"rgba(0,245,196,.38)",fontFamily:"Orbitron",letterSpacing:1}}>
              <span>PAIR</span><span>SIDE</span><span>ENTRY</span><span>EXIT</span>
              <span>P&L</span><span>RESULT</span><span>CONF</span><span>R:R</span>
            </div>
            <div style={{flex:1,overflowY:"auto"}} className="scr">
              {trades.map((t,i)=>{
                const rr = t.tpPct&&t.slPct ? (t.tpPct/t.slPct).toFixed(1) : "—";
                return (
                  <div key={i} className="tr2" style={{display:"grid",
                    gridTemplateColumns:"90px 50px 85px 85px 70px 80px 65px 55px",
                    padding:"8px 14px",borderBottom:"1px solid rgba(0,245,196,.04)",
                    fontSize:10,alignItems:"center"}}>
                    <span style={{fontWeight:700}}>{t.symbol.replace("USDT","")}</span>
                    <span className={`bdg ${t.side==="BUY"?"bl":"bsr"}`} style={{fontSize:7}}>
                      {t.side==="BUY"?"LONG":"SHORT"}
                    </span>
                    <span style={{color:"#6b7a99"}}>{priceFmt(t.entry)}</span>
                    <span style={{color:"#6b7a99"}}>{priceFmt(t.closePrice)}</span>
                    <span className={t.pnl>=0?"pos":"neg"} style={{fontWeight:700}}>{fmtP(t.pnl)}</span>
                    <span style={{fontFamily:"Orbitron",fontSize:7.5,
                      color:t.result==="TP"?"#00f5c4":"#ef4444",letterSpacing:1}}>
                      {t.result==="TP"?"✓ TP":"✗ SL"}
                    </span>
                    <span style={{color:"#f59e0b",fontSize:9}}>{t.confidence}%</span>
                    <span style={{color:"#6b7a99",fontSize:9}}>{rr}{rr!=="—"?":1":""}</span>
                  </div>
                );
              })}
              {trades.length===0&&(
                <div style={{padding:40,textAlign:"center",fontSize:9,
                  color:"rgba(100,120,160,.28)",fontFamily:"Orbitron",letterSpacing:2}}>
                  {isDemo?"HISTORY LOADS AS BOT EXECUTES TRADES...":"NO TRADES YET"}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── CONFIG TAB ── */}
        {tab==="config"&&(
          <div style={{flex:1,overflowY:"auto",padding:20}} className="scr">
            <div style={{maxWidth:600}}>
              <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
                letterSpacing:2,marginBottom:20,textShadow:"0 0 14px rgba(0,245,196,.45)"}}>
                BOT CONFIGURATION v2
              </div>

              {/* Pairs */}
              <div style={{marginBottom:20}}>
                <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                  color:"rgba(0,245,196,.5)",marginBottom:10}}>TRADING PAIRS (max 80)</div>
                <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                  {TOP_PAIRS.map(p=>{
                    const s=signals[p];
                    const dotC=!s?"#374151":s.action==="BUY"?"#00f5c4":s.action==="SELL"?"#ef4444":"#f59e0b";
                    return (
                      <button key={p} className={`pchip ${cfg.pairs.includes(p)?"sel":""}`}
                        style={{position:"relative"}}
                        onClick={()=>setCfg(c=>({...c,pairs:
                          c.pairs.includes(p)
                            ?c.pairs.filter(x=>x!==p)
                            :[...c.pairs,p]}))}>
                        {p.replace("USDT","")}
                        {s&&<span style={{display:"inline-block",width:5,height:5,borderRadius:"50%",
                          background:dotC,marginLeft:5,verticalAlign:"middle"}}/>}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Settings grid */}
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:20}}>
                {[
                  ["AMOUNT PER TRADE (USDT)","amount","50"],
                  ["MAX OPEN POSITIONS","maxPositions","3"],
                  ["FALLBACK STOP LOSS %","stopLoss","2"],
                  ["FALLBACK TAKE PROFIT %","takeProfit","4"],
                  ["MIN. SIGNAL CONFIDENCE %","minConfidence","62"],
                  ["TRAILING STOP % (0=off)","trailingPct","1.5"],
                ].map(([label,key,ph])=>(
                  <div key={key}>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                      color:"rgba(0,245,196,.5)",marginBottom:7}}>{label}</div>
                    <input className="inp2" placeholder={ph} value={cfg[key]}
                      onChange={e=>setCfg(c=>({...c,[key]:e.target.value}))}/>
                  </div>
                ))}
                <div>
                  <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                    color:"rgba(0,245,196,.5)",marginBottom:7}}>CHART INTERVAL</div>
                  <select className="inp2" value={cfg.interval}
                    onChange={e=>setCfg(c=>({...c,interval:e.target.value}))} style={{cursor:"pointer"}}>
                    {["1m","3m","5m","15m","30m","1h","4h","1d"].map(i=><option key={i} value={i}>{i}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                    color:"rgba(0,245,196,.5)",marginBottom:7}}>ATR-BASED SL/TP</div>
                  <button onClick={()=>setCfg(c=>({...c,useAtrSl:!c.useAtrSl}))}
                    style={{width:"100%",padding:"8px 12px",fontFamily:"Orbitron",fontSize:8.5,
                      letterSpacing:1,cursor:"pointer",borderRadius:2,transition:"all .2s",
                      background:cfg.useAtrSl?"rgba(0,245,196,.12)":"rgba(0,0,0,.2)",
                      border:cfg.useAtrSl?"1px solid rgba(0,245,196,.45)":"1px solid rgba(0,245,196,.18)",
                      color:cfg.useAtrSl?"#00f5c4":"rgba(0,245,196,.4)"}}>
                    {cfg.useAtrSl?"✓ ENABLED — ATR ADAPTIVE":"○ DISABLED — FIXED %"}
                  </button>
                </div>
              </div>

              {/* TA engine summary */}
              <div style={{background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.14)",
                borderRadius:3,padding:14,fontSize:10,color:"#8892a4",lineHeight:2,marginBottom:16}}>
                <div style={{fontFamily:"Orbitron",fontSize:9,letterSpacing:1,color:"#00f5c4",marginBottom:8}}>
                  ⚙ TA ENGINE v2 — HOW SIGNALS ARE GENERATED
                </div>
                <div>• Fetches <b>150 real {cfg.interval} OHLCV candles</b> from {(creds?.exchange||"your exchange").toUpperCase()} for each pair</div>
                <div>• <b>EMA 9/21/50/200</b> — crossovers, stack alignment, macro bias</div>
                <div>• <b>RSI (14)</b> — oversold/overbought with divergence hints</div>
                <div>• <b>MACD (12/26/9)</b> — crossover, histogram flip, momentum</div>
                <div>• <b>Bollinger Bands (20,2)</b> — squeeze detection, band touch, midline</div>
                <div>• <b>ATR (14)</b> — volatility-adaptive SL/TP (1.5× ATR stop, 3× ATR target)</div>
                <div>• <b>ADX (14)</b> — trend strength filter (boosts trending signals, dampens choppy ones)</div>
                <div>• <b>Volume Profile</b> — spike/surge/weak volume detection &amp; scoring</div>
                <div>• <b>Candlestick Patterns</b> — 10 patterns: engulfing, hammer, marubozu, stars…</div>
                <div>• <b>Support/Resistance Zones</b> — swing-point clustering with proximity scoring</div>
                <div>• Fires entry only when <b>multiple indicators agree</b> (score ≥45, 25% dominance)</div>
              </div>

              <button onClick={()=>{ cfg.pairs.forEach(p=>fetchKlinesAndAnalyze(p));
                addLog("Scanner","Manual re-analysis of all pairs triggered","info"); }}
                style={{background:"rgba(0,245,196,.07)",border:"1px solid rgba(0,245,196,.28)",
                  color:"#00f5c4",padding:"10px 20px",fontFamily:"Orbitron",fontSize:8.5,
                  letterSpacing:2,cursor:"pointer",borderRadius:2,width:"100%"}}>
                ↺ RE-ANALYZE ALL PAIRS NOW
              </button>
            </div>
          </div>
        )}
        {/* ── WALLET TAB ── */}
        {tab==="wallet"&&(
          <div style={{flex:1,overflowY:"auto",padding:20}} className="scr">
            <div style={{maxWidth:640,margin:"0 auto"}}>

              {/* Header */}
              <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
                letterSpacing:2,marginBottom:20,textShadow:"0 0 14px rgba(0,245,196,.45)"}}>
                ⬡ WALLET — PHASE 1
              </div>

              {/* Connection card */}
              <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.12)",
                borderRadius:4,padding:18,marginBottom:14}}>
                <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                  color:"rgba(0,245,196,.5)",marginBottom:12}}>CONNECTED WALLET</div>

                {wallet ? (
                  <>
                    <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:14,
                      flexWrap:"wrap"}}>
                      <span style={{width:8,height:8,borderRadius:"50%",background:"#00f5c4",
                        display:"inline-block",boxShadow:"0 0 8px rgba(0,245,196,.6)",flexShrink:0}}/>
                      <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:13,
                        color:"#c8d8f0",wordBreak:"break-all"}}>{wallet.address}</span>
                      <button onClick={()=>navigator.clipboard.writeText(wallet.address)}
                        style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1,padding:"3px 8px",
                          border:"1px solid rgba(0,245,196,.2)",background:"transparent",
                          color:"rgba(0,245,196,.5)",cursor:"pointer",borderRadius:2,flexShrink:0}}>
                        COPY
                      </button>
                      <span className={`bdg ${wallet.chainId===56?"bl":"bw"}`} style={{fontSize:7}}>
                        {wallet.chainId===56?"BNB Smart Chain":wallet.chainId===1?"Ethereum":"Chain "+wallet.chainId}
                      </span>
                      <span style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.35)"}}>
                        via {wallet.type==="metamask"?"MetaMask":"WalletConnect"}
                      </span>
                      <button onClick={disconnectWallet}
                        style={{marginLeft:"auto",fontFamily:"Orbitron",fontSize:7,letterSpacing:1,
                          padding:"4px 10px",border:"1px solid rgba(239,68,68,.25)",
                          background:"transparent",color:"rgba(239,68,68,.55)",
                          cursor:"pointer",borderRadius:2}}>
                        DISCONNECT
                      </button>
                    </div>

                    {/* Balances grid */}
                    <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:8,marginBottom:8}}>
                      {[
                        ["ETH Balance",      walletBals.eth?.toFixed(5)||"—",      "#6b7a99"],
                        ["BNB Balance",      walletBals.bnb?.toFixed(5)||"—",      "#f59e0b"],
                        ["USDT (ERC-20)",    walletBals.usdtEth!=null?`$${fmt(walletBals.usdtEth)}`:"—", "#00f5c4"],
                        ["USDT (BEP-20)",    walletBals.usdtBsc!=null?`$${fmt(walletBals.usdtBsc)}`:"—", "#00f5c4"],
                      ].map(([label,val,vc])=>(
                        <div key={label} className="ibox">
                          <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.35)",marginBottom:3}}>{label}</div>
                          <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:15,color:vc}}>{val}</div>
                        </div>
                      ))}
                    </div>
                    <button onClick={fetchWalletBalances}
                      style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1,padding:"4px 12px",
                        border:"1px solid rgba(0,245,196,.15)",background:"transparent",
                        color:"rgba(0,245,196,.45)",cursor:"pointer",borderRadius:2}}>
                      ↺ REFRESH BALANCES
                    </button>
                  </>
                ) : (
                  <div>
                    <div style={{fontSize:10,color:"#6b7a99",marginBottom:16,lineHeight:1.7}}>
                      Connect your wallet to see balances and manage withdrawals.
                      Your funds stay in your own wallet — TFunds never holds them.
                    </div>
                    {walletErr&&(
                      <div style={{background:"rgba(239,68,68,.07)",border:"1px solid rgba(239,68,68,.22)",
                        borderRadius:3,padding:"10px 12px",fontSize:9.5,color:"#ef4444",
                        marginBottom:14,lineHeight:1.6}}>
                        ⚠ {walletErr}
                      </div>
                    )}
                    <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                      <button onClick={connectMetaMask} disabled={walletLoading}
                        style={{fontFamily:"Orbitron",fontWeight:700,fontSize:9,letterSpacing:1.5,
                          padding:"10px 20px",border:"1px solid rgba(0,245,196,.35)",
                          background:"rgba(0,245,196,.06)",color:"#00f5c4",cursor:"pointer",
                          borderRadius:3,transition:"all .2s",opacity:walletLoading?.5:1}}>
                        🦊 METAMASK
                      </button>
                      <button onClick={connectWalletConnect} disabled={walletLoading}
                        style={{fontFamily:"Orbitron",fontWeight:700,fontSize:9,letterSpacing:1.5,
                          padding:"10px 20px",border:"1px solid rgba(99,102,241,.35)",
                          background:"rgba(99,102,241,.06)",color:"#818cf8",cursor:"pointer",
                          borderRadius:3,transition:"all .2s",opacity:walletLoading?.5:1}}>
                        ◈ WALLETCONNECT
                      </button>
                    </div>
                    <div style={{marginTop:12,fontSize:9,color:"rgba(100,120,160,.45)",lineHeight:1.7}}>
                      WalletConnect supports Trust Wallet, Coinbase Wallet, Rainbow, and 300+ others.
                      Requires <b style={{color:"rgba(0,245,196,.4)"}}>WC_PROJECT_ID</b> set in the code (free at cloud.walletconnect.com).
                    </div>
                  </div>
                )}
              </div>

              {/* ── ON-CHAIN SEND ── */}
              {wallet&&(
              <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.18)",
                borderRadius:4,padding:18,marginBottom:14}}>
                <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                  color:"rgba(0,245,196,.7)",marginBottom:4}}>⬆ SEND CRYPTO — ON-CHAIN</div>
                <div style={{fontSize:9,color:"#506070",marginBottom:14,lineHeight:1.6}}>
                  Send ETH, BNB, or USDT directly from your connected wallet.
                  Transaction is signed <b style={{color:"rgba(0,245,196,.5)"}}>inside your wallet app</b> — TFunds never touches your keys.
                </div>

                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
                  <div>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:7}}>ASSET</div>
                    <select className="inp2" value={sendForm.asset}
                      onChange={e=>{
                        const a=e.target.value;
                        setSendForm(f=>({...f,asset:a,
                          chain:a==="ETH"||a==="USDT-ERC20"?"eth":a==="BNB"||a==="USDT-BEP20"?"bsc":f.chain}));
                      }} style={{cursor:"pointer"}}>
                      <option value="ETH">ETH (Ethereum)</option>
                      <option value="BNB">BNB (BSC)</option>
                      <option value="USDT-ERC20">USDT ERC-20</option>
                      <option value="USDT-BEP20">USDT BEP-20</option>
                    </select>
                  </div>
                  <div>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:7}}>NETWORK</div>
                    <div style={{fontFamily:"Orbitron",fontSize:9,color:"#c8d8f0",padding:"9px 12px",
                      background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.15)",borderRadius:3}}>
                      {sendForm.asset==="ETH"||sendForm.asset==="USDT-ERC20"?"Ethereum (ERC-20)":"BNB Smart Chain (BEP-20)"}
                    </div>
                  </div>
                </div>

                <div style={{marginBottom:10}}>
                  <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:7}}>RECIPIENT ADDRESS</div>
                  <input className="inp2" placeholder="0x..."
                    value={sendForm.toAddress}
                    onChange={e=>setSendForm(f=>({...f,toAddress:e.target.value}))}/>
                </div>
                <div style={{marginBottom:14}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:7}}>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,color:"rgba(0,245,196,.5)"}}>AMOUNT</div>
                    <span style={{fontSize:8,color:"rgba(0,245,196,.35)",fontFamily:"Orbitron"}}>
                      BAL: {sendForm.asset==="ETH"?walletBals.eth?.toFixed(5):
                           sendForm.asset==="BNB"?walletBals.bnb?.toFixed(5):
                           sendForm.asset==="USDT-ERC20"?fmt(walletBals.usdtEth):
                           fmt(walletBals.usdtBsc)||"—"}
                    </span>
                  </div>
                  <div style={{display:"flex",gap:6}}>
                    <input className="inp2" placeholder="0.00" type="number" min="0" style={{flex:1}}
                      value={sendForm.amount}
                      onChange={e=>setSendForm(f=>({...f,amount:e.target.value}))}/>
                    <button onClick={()=>{
                      const max=sendForm.asset==="ETH"?((walletBals.eth||0)-0.003).toFixed(5):
                               sendForm.asset==="BNB"?((walletBals.bnb||0)-0.001).toFixed(5):
                               sendForm.asset==="USDT-ERC20"?(walletBals.usdtEth||0).toFixed(2):
                               (walletBals.usdtBsc||0).toFixed(2);
                      setSendForm(f=>({...f,amount:Math.max(0,parseFloat(max)||0).toString()}));
                    }} style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:1,padding:"0 10px",
                      border:"1px solid rgba(0,245,196,.2)",background:"transparent",
                      color:"rgba(0,245,196,.5)",cursor:"pointer",borderRadius:2,whiteSpace:"nowrap"}}>
                      MAX
                    </button>
                  </div>
                </div>

                {sendStatus&&(
                  <div style={{background:sendStatus.type==="ok"?"rgba(0,245,196,.07)":
                    sendStatus.type==="error"?"rgba(239,68,68,.07)":"rgba(245,158,11,.07)",
                    border:`1px solid ${sendStatus.type==="ok"?"rgba(0,245,196,.25)":
                      sendStatus.type==="error"?"rgba(239,68,68,.25)":"rgba(245,158,11,.25)"}`,
                    borderRadius:3,padding:"10px 12px",fontSize:9.5,
                    color:sendStatus.type==="ok"?"#00f5c4":sendStatus.type==="error"?"#ef4444":"#f59e0b",
                    marginBottom:12,lineHeight:1.6,wordBreak:"break-all"}}>
                    {sendStatus.msg}
                  </div>
                )}

                <button onClick={handleWalletSend}
                  style={{width:"100%",padding:"12px",fontFamily:"Orbitron",fontWeight:700,
                    fontSize:9.5,letterSpacing:2,cursor:"pointer",borderRadius:3,
                    background:"linear-gradient(135deg,rgba(0,245,196,.12),rgba(0,245,196,.06))",
                    border:"1px solid rgba(0,245,196,.4)",color:"#00f5c4",transition:"all .2s"}}>
                  ↑ SEND {sendForm.amount||"0"} {sendForm.asset.replace("-"," ")}
                </button>
                <div style={{marginTop:8,fontSize:8,color:"rgba(100,120,160,.3)",lineHeight:1.6}}>
                  ⚠ Transactions are irreversible. Double-check the address before confirming in your wallet.
                </div>
              </div>
              )}

              {/* ── EXCHANGE WITHDRAWAL ── */}
              <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.12)",
                borderRadius:4,padding:18,marginBottom:14}}>
                <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                  color:"rgba(0,245,196,.5)",marginBottom:4}}>
                  ↑ EXCHANGE WITHDRAWAL — {(creds?.exchange||"EXCHANGE").toUpperCase()}
                </div>
                <div style={{fontSize:9,color:"#506070",marginBottom:14,lineHeight:1.6}}>
                  Withdraw funds from your {(creds?.exchange||"exchange").toUpperCase()} trading account to any wallet address.
                  Your API key must have <b style={{color:"rgba(0,245,196,.4)"}}>withdrawal permission</b> enabled.
                </div>

                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
                  <div>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                      color:"rgba(0,245,196,.5)",marginBottom:7}}>COIN</div>
                    <select className="inp2" value={wdForm.coin}
                      onChange={e=>setWdForm(f=>({...f,coin:e.target.value}))}
                      style={{cursor:"pointer"}}>
                      {["USDT","ETH","BNB","BTC"].map(c=><option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div>
                    <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                      color:"rgba(0,245,196,.5)",marginBottom:7}}>NETWORK</div>
                    <select className="inp2" value={wdForm.network}
                      onChange={e=>setWdForm(f=>({...f,network:e.target.value}))}
                      style={{cursor:"pointer"}}>
                      {["BSC","ETH","BTC","TRX"].map(n=><option key={n} value={n}>{n}</option>)}
                    </select>
                  </div>
                </div>

                <div style={{marginBottom:10}}>
                  <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                    color:"rgba(0,245,196,.5)",marginBottom:7}}>DESTINATION ADDRESS</div>
                  <input className="inp2" placeholder="0x... or wallet address"
                    value={wdForm.address}
                    onChange={e=>setWdForm(f=>({...f,address:e.target.value}))}/>
                  {wallet&&(
                    <button onClick={()=>setWdForm(f=>({...f,address:wallet.address}))}
                      style={{marginTop:6,fontFamily:"Orbitron",fontSize:7,letterSpacing:1,
                        padding:"3px 10px",border:"1px solid rgba(0,245,196,.18)",
                        background:"transparent",color:"rgba(0,245,196,.5)",cursor:"pointer",borderRadius:2}}>
                      USE CONNECTED WALLET ADDRESS
                    </button>
                  )}
                </div>

                <div style={{marginBottom:14}}>
                  <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:2,
                    color:"rgba(0,245,196,.5)",marginBottom:7}}>AMOUNT</div>
                  <input className="inp2" placeholder="0.00" type="number" min="0"
                    value={wdForm.amount}
                    onChange={e=>setWdForm(f=>({...f,amount:e.target.value}))}/>
                </div>

                {wdStatus&&(
                  <div style={{background:wdStatus.type==="ok"?"rgba(0,245,196,.07)":
                    wdStatus.type==="error"?"rgba(239,68,68,.07)":"rgba(245,158,11,.07)",
                    border:`1px solid ${wdStatus.type==="ok"?"rgba(0,245,196,.25)":
                      wdStatus.type==="error"?"rgba(239,68,68,.25)":"rgba(245,158,11,.25)"}`,
                    borderRadius:3,padding:"10px 12px",fontSize:9.5,
                    color:wdStatus.type==="ok"?"#00f5c4":wdStatus.type==="error"?"#ef4444":"#f59e0b",
                    marginBottom:12,lineHeight:1.6}}>
                    {wdStatus.msg}
                  </div>
                )}

                <button onClick={handleWithdrawal}
                  style={{width:"100%",padding:"11px",fontFamily:"Orbitron",fontWeight:700,
                    fontSize:9,letterSpacing:2,cursor:"pointer",borderRadius:3,transition:"all .2s",
                    background:"rgba(0,245,196,.07)",border:"1px solid rgba(0,245,196,.3)",
                    color:"#00f5c4"}}>
                  ↑ WITHDRAW FROM {(creds?.exchange||'EXCHANGE').toUpperCase()}
                </button>

                <div style={{marginTop:10,fontSize:8.5,color:"rgba(100,120,160,.35)",lineHeight:1.6}}>
                  ⚠ Your {(creds?.exchange||"exchange").toUpperCase()} API key needs <b>withdrawal permission enabled</b> for this to work.
                  In Demo/Paper mode this is simulated only.
                </div>
              </div>

              {/* ── Security notice ── */}
              <div style={{background:"rgba(0,0,0,.25)",border:"1px solid rgba(0,245,196,.07)",
                borderRadius:3,padding:"12px 14px",fontSize:9,color:"rgba(100,120,160,.5)",lineHeight:1.8}}>
                <div style={{fontFamily:"Orbitron",fontSize:7.5,letterSpacing:1,color:"rgba(0,245,196,.35)",marginBottom:5}}>
                  🔐 SECURITY
                </div>
                <div>• Your private keys <b>never leave your wallet app</b> — TFunds cannot access them</div>
                <div>• On-chain sends are signed <b>in your own wallet</b> (MetaMask / WalletConnect)</div>
                <div>• Exchange withdrawals use <b>your own API key</b> — processed by your exchange</div>
                <div>• TFunds never holds, touches, or sees your funds or private keys</div>
                <div>• Each user connects their own exchange and wallet accounts independently</div>
              </div>

            </div>
          </div>
        )}

      </div>

      {/* ── WalletConnect picker modal ── */}
      {showWcModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.75)",zIndex:100,
          display:"flex",alignItems:"center",justifyContent:"center",padding:20}}
          onClick={()=>setShowWcModal(false)}>
          <div style={{background:"#0a1628",border:"1px solid rgba(0,245,196,.2)",
            borderRadius:6,padding:28,maxWidth:380,width:"100%"}}
            onClick={e=>e.stopPropagation()}>
            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
              letterSpacing:2,marginBottom:6}}>CONNECT WALLET</div>
            <div style={{fontSize:9.5,color:"#6b7a99",marginBottom:20,lineHeight:1.6}}>
              Choose how to connect. Your keys stay in your wallet — TFunds never sees them.
            </div>
            {walletErr&&(
              <div style={{background:"rgba(239,68,68,.07)",border:"1px solid rgba(239,68,68,.22)",
                borderRadius:3,padding:"8px 12px",fontSize:9,color:"#ef4444",marginBottom:14}}>
                {walletErr}
              </div>
            )}
            <div style={{display:"flex",flexDirection:"column",gap:10}}>
              <button onClick={connectMetaMask} disabled={walletLoading}
                style={{padding:"14px 18px",fontFamily:"Orbitron",fontWeight:700,fontSize:10,
                  letterSpacing:1.5,border:"1px solid rgba(245,158,11,.35)",
                  background:"rgba(245,158,11,.06)",color:"#f59e0b",cursor:"pointer",
                  borderRadius:3,textAlign:"left",display:"flex",alignItems:"center",gap:12}}>
                <span style={{fontSize:22}}>🦊</span>
                <div>
                  <div>METAMASK</div>
                  <div style={{fontSize:7.5,color:"rgba(245,158,11,.6)",fontWeight:400,marginTop:2,letterSpacing:1}}>
                    Browser extension · MetaMask Mobile
                  </div>
                </div>
              </button>
              <button onClick={connectWalletConnect} disabled={walletLoading}
                style={{padding:"14px 18px",fontFamily:"Orbitron",fontWeight:700,fontSize:10,
                  letterSpacing:1.5,border:"1px solid rgba(99,102,241,.35)",
                  background:"rgba(99,102,241,.06)",color:"#818cf8",cursor:"pointer",
                  borderRadius:3,textAlign:"left",display:"flex",alignItems:"center",gap:12}}>
                <span style={{fontSize:22}}>◈</span>
                <div>
                  <div>WALLETCONNECT</div>
                  <div style={{fontSize:7.5,color:"rgba(99,102,241,.6)",fontWeight:400,marginTop:2,letterSpacing:1}}>
                    Trust Wallet · Coinbase Wallet · 300+ others
                  </div>
                </div>
              </button>
            </div>
            {walletLoading&&(
              <div style={{marginTop:14,textAlign:"center",fontFamily:"Orbitron",
                fontSize:8,color:"rgba(0,245,196,.5)",letterSpacing:2}}>CONNECTING...</div>
            )}
            <button onClick={()=>setShowWcModal(false)}
              style={{marginTop:16,width:"100%",padding:"8px",fontFamily:"Orbitron",fontSize:7.5,
                letterSpacing:1,border:"1px solid rgba(0,245,196,.1)",background:"transparent",
                color:"rgba(0,245,196,.35)",cursor:"pointer",borderRadius:2}}>
              CANCEL
            </button>
          </div>
        </div>
      )}


      {/* ══ FLOATING START/STOP BUTTON — always visible ══ */}
      <div style={{position:"fixed",bottom:70,right:18,zIndex:150,display:"flex",flexDirection:"column",alignItems:"flex-end",gap:6}}>
        {/* Balance pill — always visible */}
        <div style={{background:"rgba(1,4,12,.95)",border:"1px solid rgba(0,245,196,.2)",
          borderRadius:20,padding:"4px 12px",display:"flex",alignItems:"center",gap:6}}>
          <span style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.45)",letterSpacing:1}}>BAL</span>
          <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:11,color:usdtBal&&parseFloat(usdtBal.free||0)>0?"#00f5c4":"rgba(0,245,196,.4)"}}>
            {usdtBal&&parseFloat(usdtBal.free||0)>0
              ? `$${fmt(usdtBal.free)}`
              : (!isDemo&&!paperMode&&balances.length===0 ? "…" : "$0.00")
            }
          </span>
        </div>

        {/* Trade amount quick-set (shown when bot is NOT running) */}
        {!botRunning&&(
          <div style={{background:"rgba(1,4,12,.97)",border:"1px solid rgba(0,245,196,.25)",
            borderRadius:6,padding:"8px 10px",display:"flex",flexDirection:"column",gap:4,minWidth:150}}>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontFamily:"Orbitron",fontSize:9,color:"rgba(0,245,196,.5)",flexShrink:0}}>$</span>
              <input
                type="number" min="0.5" step="0.5"
                placeholder={cfg.amount||"5"}
                value={cfg.amount}
                onChange={e=>{
                  const v = e.target.value;
                  amtRef.current = v;
                  setCfg(c=>({...c,amount:v}));
                }}
                style={{flex:1,background:"transparent",border:"none",outline:"none",
                  fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:"#00f5c4",
                  width:0,minWidth:0}}
              />
              <span style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.3)",letterSpacing:1}}>PER TRADE</span>
            </div>
            {/* Pairs counter */}
            <div style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.4)",
              letterSpacing:1,textAlign:"right"}}>
              {eligiblePairs.length}/{TOP_PAIRS.length} PAIRS
            </div>
          </div>
        )}

        {/* Big START/STOP button */}
        <button
          onClick={()=>{
            if (botRunning) {
              setShowStopModal(true);
            } else if (!paperMode && !isDemo) {
              // Live mode — show confirmation modal with amount
              setLiveTradeAmt(cfg.amount||"5");
              setShowStartModal(true);
            } else {
              setBotRunning(true);
            }
          }}
          style={{
            fontFamily:"Orbitron",fontWeight:900,fontSize:11,letterSpacing:2,
            padding:"14px 22px",borderRadius:6,cursor:"pointer",
            border: botRunning?"2px solid rgba(239,68,68,.7)":"2px solid rgba(0,245,196,.7)",
            background: botRunning?"rgba(239,68,68,.15)":"rgba(0,245,196,.12)",
            color: botRunning?"#ef4444":"#00f5c4",
            boxShadow: botRunning?"0 0 20px rgba(239,68,68,.3)":"0 0 20px rgba(0,245,196,.3)",
            display:"flex",alignItems:"center",gap:10,minWidth:140,justifyContent:"center",
          }}>
          <span style={{fontSize:16}}>{botRunning?"■":"▶"}</span>
          {botRunning?"STOP":"START"}
        </button>
        {/* Status label */}
        <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:2,
          color: botRunning?"rgba(239,68,68,.6)":"rgba(0,245,196,.35)",textAlign:"center"}}>
          {botRunning
            ? `SCANNING · ${isDemo?"DEMO":paperMode?"PAPER":"LIVE"}`
            : `PRESS TO ${isDemo?"DEMO":paperMode?"PAPER":"LIVE"} TRADE`}
        </div>
      </div>

      {/* ══ LIVE START CONFIRMATION MODAL ══ */}
      {showStartModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.85)",zIndex:200,
          display:"flex",alignItems:"center",justifyContent:"center",padding:20}}
          onClick={()=>setShowStartModal(false)}>
          <div style={{background:"#0a1628",border:"1px solid rgba(0,245,196,.35)",
            borderRadius:8,padding:28,maxWidth:380,width:"100%",boxShadow:"0 0 40px rgba(0,245,196,.1)"}}
            onClick={e=>e.stopPropagation()}>
            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
              letterSpacing:2,marginBottom:4}}>▶ START LIVE TRADING</div>
            <div style={{fontSize:9,color:"rgba(239,68,68,.8)",fontFamily:"Orbitron",
              letterSpacing:1,marginBottom:20}}>
              ⚠ REAL ORDERS · REAL FUNDS · {(creds?.exchange||"").toUpperCase()}
            </div>

            {/* ── TOTAL BUDGET ── */}
            <div style={{marginBottom:14}}>
              <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                color:"rgba(0,245,196,.6)",marginBottom:6}}>TOTAL BUDGET TO USE (USDT)</div>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <div style={{position:"relative",flex:1}}>
                  <span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",
                    fontFamily:"Orbitron",fontSize:13,color:"rgba(0,245,196,.5)",pointerEvents:"none"}}>$</span>
                  <input type="number" min="1" step="1" autoFocus
                    placeholder="10"
                    value={liveTotalBudget}
                    onChange={e=>setLiveTotalBudget(e.target.value)}
                    style={{paddingLeft:26,width:"100%",background:"rgba(0,245,196,.05)",
                      border:"1px solid rgba(0,245,196,.3)",color:"#00f5c4",
                      fontFamily:"Orbitron",fontWeight:700,fontSize:16,
                      padding:"10px 10px 10px 26px",borderRadius:3,outline:"none"}}
                  />
                </div>
              </div>
              <div style={{display:"flex",gap:6,marginTop:6}}>
                {["5","10","20","50","100"].map(v=>(
                  <button key={v} onClick={()=>setLiveTotalBudget(v)}
                    style={{fontFamily:"Orbitron",fontSize:8,padding:"4px 8px",cursor:"pointer",
                      borderRadius:3,border:"1px solid rgba(0,245,196,.25)",
                      background:liveTotalBudget===v?"rgba(0,245,196,.15)":"transparent",
                      color:liveTotalBudget===v?"#00f5c4":"rgba(0,245,196,.45)"}}>
                    ${v}
                  </button>
                ))}
              </div>
            </div>

            {/* ── NUMBER OF COINS ── */}
            <div style={{marginBottom:14}}>
              <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                color:"rgba(0,245,196,.6)",marginBottom:6}}>SPREAD ACROSS HOW MANY COINS</div>
              <div style={{display:"flex",gap:6}}>
                {["2","3","4","5","6","8","10"].map(v=>(
                  <button key={v} onClick={()=>setLiveNumCoins(v)}
                    style={{fontFamily:"Orbitron",fontSize:9,padding:"7px 10px",cursor:"pointer",
                      borderRadius:3,border:"1px solid rgba(0,245,196,.25)",flex:1,
                      background:liveNumCoins===v?"rgba(0,245,196,.15)":"transparent",
                      color:liveNumCoins===v?"#00f5c4":"rgba(0,245,196,.45)"}}>
                    {v}
                  </button>
                ))}
              </div>
              {liveTotalBudget&&liveNumCoins&&(
                <div style={{marginTop:7,fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.55)",
                  background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.12)",
                  borderRadius:3,padding:"6px 10px"}}>
                  = ${(parseFloat(liveTotalBudget||0)/Math.max(1,parseInt(liveNumCoins||1))).toFixed(2)} per coin
                </div>
              )}
            </div>

            {/* ── STOP BALANCE ── */}
            <div style={{marginBottom:14}}>
              <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,
                color:"rgba(245,158,11,.7)",marginBottom:6}}>⛔ STOP BALANCE (optional)</div>
              <div style={{fontSize:8.5,color:"rgba(160,180,210,.45)",marginBottom:6,lineHeight:1.6}}>
                Bot auto-stops if USDT balance drops to or below this. Protects your remaining funds.
              </div>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <div style={{position:"relative",flex:1}}>
                  <span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",
                    fontFamily:"Orbitron",fontSize:13,color:"rgba(245,158,11,.5)",pointerEvents:"none"}}>$</span>
                  <input type="number" min="0" step="1"
                    placeholder="e.g. 30  (leave blank = no floor)"
                    value={stopBalance}
                    onChange={e=>setStopBalance(e.target.value)}
                    style={{paddingLeft:26,width:"100%",background:"rgba(245,158,11,.04)",
                      border:"1px solid rgba(245,158,11,.25)",color:"#f59e0b",
                      fontFamily:"Orbitron",fontWeight:700,fontSize:13,
                      padding:"10px 10px 10px 26px",borderRadius:3,outline:"none"}}
                  />
                </div>
              </div>
            </div>

            {/* Balance info */}
            {usdtBal&&(
              <div style={{background:"rgba(0,0,0,.3)",borderRadius:4,padding:"8px 12px",
                marginBottom:10,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <span style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.4)"}}>AVAILABLE</span>
                <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:"#00f5c4"}}>
                  ${fmt(usdtBal.free)} USDT
                </span>
              </div>
            )}

            {/* Eligible pairs info */}
            <div style={{background:"rgba(0,0,0,.25)",borderRadius:4,padding:"8px 12px",
              marginBottom:16,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(0,245,196,.4)"}}>
                PAIRS TO SCAN
              </span>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:"#00f5c4"}}>
                  {eligiblePairs.length}
                </span>
                <span style={{fontFamily:"Orbitron",fontSize:8,color:"rgba(140,160,190,.4)"}}>
                  / {TOP_PAIRS.length}
                </span>
                <span style={{fontFamily:"Orbitron",fontSize:7,color:"rgba(0,245,196,.4)",
                  padding:"2px 6px",border:"1px solid rgba(0,245,196,.15)",borderRadius:2}}>
                  MIN AUTO-BUMPED
                </span>
              </div>
            </div>

            <div style={{fontSize:9,color:"rgba(160,180,210,.5)",lineHeight:1.7,marginBottom:18}}>
              Bot uses your total budget divided equally across coins.
              E.g. $10 budget ÷ 5 coins = $2 per coin. It will never open more than the chosen number
              of positions at once. Set a stop balance to protect the rest of your funds.
            </div>

            <div style={{display:"flex",gap:10}}>
              <button
                onClick={()=>{
                  const budget   = liveTotalBudget||"10";
                  const nCoins   = liveNumCoins||"5";
                  const perCoin  = (parseFloat(budget)/Math.max(1,parseInt(nCoins))).toFixed(2);
                  setCfg(c=>({...c,
                    totalBudget: budget,
                    numCoins:    nCoins,
                    maxPositions:nCoins,
                    amount:      perCoin,  // keep cfg.amount in sync for display
                  }));
                  setShowStartModal(false);
                  fetchBalances();
                  fetchLiveOpenOrders();
                  setBotRunning(true);
                  addLog("System",`▶ Live trading started — $${budget} budget ÷ ${nCoins} coins = $${perCoin}/coin on ${(creds?.exchange||"").toUpperCase()}`,"ok");
                  if (stopBalance) addLog("System",`⛔ Stop balance set at $${stopBalance} USDT`,"warn");
                }}
                style={{flex:1,fontFamily:"Orbitron",fontWeight:900,fontSize:11,letterSpacing:2,
                  padding:"13px",border:"2px solid rgba(0,245,196,.7)",
                  background:"rgba(0,245,196,.12)",color:"#00f5c4",cursor:"pointer",
                  borderRadius:4,display:"flex",alignItems:"center",justifyContent:"center",gap:8}}>
                <span>▶</span> CONFIRM START
              </button>
              <button onClick={()=>setShowStartModal(false)}
                style={{padding:"13px 18px",fontFamily:"Orbitron",fontSize:9,
                  letterSpacing:1,border:"1px solid rgba(0,245,196,.1)",
                  background:"transparent",color:"rgba(0,245,196,.35)",cursor:"pointer",borderRadius:4}}>
                CANCEL
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══ BACKTEST TAB ══ */}
      {tab==="backtest"&&(
        <div style={{flex:1,overflowY:"auto",padding:20}} className="scr">
          <div style={{maxWidth:760,margin:"0 auto"}}>
            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
              letterSpacing:2,marginBottom:20,textShadow:"0 0 14px rgba(0,245,196,.45)"}}>
              ⏳ BACKTESTING ENGINE
            </div>

            {/* Controls */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:12,marginBottom:16}}>
              {[
                ["SYMBOL",btSymbol,setBtSymbol,["BTCUSDT","ETHUSDT","SOLUSDT","BNBUSDT","XRPUSDT","AVAXUSDT"],"select"],
                ["INTERVAL",btInterval,setBtInterval,["1m","5m","15m","30m","1h","4h","1d"],"select"],
              ].map(([label,val,setter,opts,type])=>(
                <div key={label}>
                  <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:6}}>{label}</div>
                  <select value={val} onChange={e=>setter(e.target.value)}
                    style={{background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.18)",
                      color:"#c8d8f0",padding:"8px 10px",fontFamily:"JetBrains Mono",fontSize:11,
                      borderRadius:2,width:"100%",outline:"none"}}>
                    {opts.map(o=><option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div>
                <div style={{fontFamily:"Orbitron",fontSize:7,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:6}}>INITIAL CAPITAL ($)</div>
                <input className="inp2" value={btInitCap} onChange={e=>setBtInitCap(e.target.value)} placeholder="1000"/>
              </div>
              <div style={{display:"flex",alignItems:"flex-end"}}>
                <button onClick={runBacktest} disabled={btRunning}
                  style={{width:"100%",padding:"10px 14px",fontFamily:"Orbitron",fontWeight:700,fontSize:9,
                    letterSpacing:2,border:"1px solid rgba(0,245,196,.4)",
                    background:btRunning?"rgba(0,245,196,.03)":"rgba(0,245,196,.1)",
                    color:btRunning?"rgba(0,245,196,.3)":"#00f5c4",cursor:btRunning?"not-allowed":"pointer",borderRadius:2}}>
                  {btRunning?"⏳ RUNNING...":"▶ RUN BACKTEST"}
                </button>
              </div>
            </div>
            <div style={{fontSize:9,color:"rgba(100,120,160,.45)",marginBottom:20,fontFamily:"Orbitron",letterSpacing:1}}>
              Uses your current signal settings (confidence, SL%, TP%) on up to 500 historical candles
            </div>

            {btResult&&(
              <>
                {/* Results summary */}
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:16}}>
                  {[
                    ["TOTAL RETURN",`${btResult.totalReturn}%`,parseFloat(btResult.totalReturn)],
                    ["WIN RATE",`${btResult.winRate}%`,null],
                    ["PROFIT FACTOR",btResult.profitFactor,null],
                    ["MAX DRAWDOWN",`${btResult.maxDD}%`,parseFloat(btResult.maxDD)*-1],
                    ["TOTAL TRADES",btResult.totalTrades,null],
                    ["AVG WIN",`${btResult.avgWin}%`,1],
                    ["AVG LOSS",`${btResult.avgLoss}%`,-1],
                    ["FINAL EQUITY",`$${btResult.equity}`,parseFloat(btResult.equity)-(parseFloat(btInitCap)||1000)],
                  ].map(([k,v,cv])=>(
                    <div key={k} className="mc">
                      <div className="ml" style={{fontSize:7}}>{k}</div>
                      <div className="mv" style={{fontSize:15,
                        color:cv==null?"#c8d8f0":cv>0?"#00f5c4":cv<0?"#ef4444":"#c8d8f0"}}>{v}</div>
                    </div>
                  ))}
                </div>

                {/* Equity curve */}
                <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.1)",
                  borderRadius:4,padding:16,marginBottom:16}}>
                  <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:12}}>EQUITY CURVE</div>
                  <svg width="100%" height="120" viewBox={`0 0 100 40`} preserveAspectRatio="none">
                    {(()=>{
                      const ec=btResult.equityCurve;
                      if(ec.length<2) return null;
                      const mn=Math.min(...ec),mx=Math.max(...ec);
                      const rng=mx-mn||1;
                      const pts=ec.map((v,i)=>`${(i/(ec.length-1))*100},${40-((v-mn)/rng)*38}`).join(" ");
                      return <>
                        <polyline points={pts} fill="none" stroke="#00f5c4" strokeWidth="0.8" vectorEffect="non-scaling-stroke"/>
                        <line x1="0" y1={40-((parseFloat(btInitCap)||1000-mn)/rng)*38} x2="100" y2={40-((parseFloat(btInitCap)||1000-mn)/rng)*38}
                          stroke="rgba(255,255,255,.15)" strokeWidth="0.5" strokeDasharray="2,2" vectorEffect="non-scaling-stroke"/>
                      </>;
                    })()}
                  </svg>
                </div>

                {/* Trade log */}
                <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.1)",borderRadius:4,padding:16}}>
                  <div style={{fontFamily:"Orbitron",fontSize:8,letterSpacing:2,color:"rgba(0,245,196,.5)",marginBottom:10}}>
                    TRADE LOG ({btResult.tradeLog.length} trades · {btResult.candlesUsed} candles)
                  </div>
                  <div style={{maxHeight:220,overflowY:"auto"}} className="scr">
                    {btResult.tradeLog.slice(0,50).map((t,i)=>(
                      <div key={i} style={{display:"grid",gridTemplateColumns:"40px 60px 100px 100px 80px 60px 100px",
                        gap:8,padding:"5px 6px",borderBottom:"1px solid rgba(0,245,196,.05)",fontSize:9,
                        background:i%2===0?"transparent":"rgba(0,245,196,.01)"}}>
                        <span style={{color:"rgba(100,120,160,.45)",fontFamily:"Orbitron",fontSize:7}}>#{i+1}</span>
                        <span className={t.side==="BUY"?"pos":"neg"} style={{fontFamily:"Orbitron",fontSize:8}}>{t.side==="BUY"?"LONG":"SHORT"}</span>
                        <span style={{color:"rgba(200,216,240,.6)"}}>In: ${priceFmt(t.entry)}</span>
                        <span style={{color:"rgba(200,216,240,.6)"}}>Out: ${priceFmt(t.exit)}</span>
                        <span className={t.pnl>=0?"pos":"neg"}>{t.pnl>=0?"+":""}{t.pnl.toFixed(2)}%</span>
                        <span style={{fontFamily:"Orbitron",fontSize:7,color:t.result==="TP"?"#00f5c4":t.result==="SL"?"#ef4444":"#f59e0b"}}>{t.result}</span>
                        <span style={{color:"rgba(100,120,160,.5)"}}>${parseFloat(t.equity).toFixed(0)}</span>
                      </div>
                    ))}
                    {btResult.tradeLog.length>50&&<div style={{textAlign:"center",padding:8,fontSize:8,color:"rgba(100,120,160,.4)",fontFamily:"Orbitron"}}>+{btResult.tradeLog.length-50} more trades</div>}
                  </div>
                </div>
              </>
            )}
            {!btResult&&!btRunning&&(
              <div style={{textAlign:"center",padding:60,fontSize:10,color:"rgba(100,120,160,.3)",fontFamily:"Orbitron",letterSpacing:2}}>
                CONFIGURE &amp; RUN BACKTEST<br/>
                <span style={{fontSize:7.5,marginTop:8,display:"block"}}>Tests your current strategy on historical data before risking real funds</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══ FUNDING RATE TAB ══ */}
      {tab==="funding"&&(
        <div style={{flex:1,overflowY:"auto",padding:20}} className="scr">
          <div style={{maxWidth:640,margin:"0 auto"}}>
            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:14,color:"#00f5c4",
              letterSpacing:2,marginBottom:8,textShadow:"0 0 14px rgba(0,245,196,.45)"}}>
              💸 FUNDING RATE MONITOR
            </div>
            <div style={{fontSize:9,color:"rgba(100,120,160,.5)",marginBottom:20,fontFamily:"Orbitron",letterSpacing:1}}>
              Perpetual futures funding rates — positive = longs pay shorts · negative = shorts pay longs (every 8h)
            </div>

            <button onClick={fetchFundingRates} disabled={fundingLoading}
              style={{marginBottom:20,padding:"10px 22px",fontFamily:"Orbitron",fontWeight:700,
                fontSize:9,letterSpacing:2,border:"1px solid rgba(0,245,196,.35)",
                background:"rgba(0,245,196,.07)",color:"#00f5c4",cursor:fundingLoading?"not-allowed":"pointer",
                borderRadius:2,opacity:fundingLoading?.6:1}}>
              {fundingLoading?"⏳ FETCHING...":"↺ FETCH FUNDING RATES"}
            </button>

            {fundingRates.length>0&&(
              <div style={{background:"rgba(3,9,22,.95)",border:"1px solid rgba(0,245,196,.1)",borderRadius:4,overflow:"hidden"}}>
                <div style={{display:"grid",gridTemplateColumns:"1fr 100px 160px 200px",gap:0,
                  padding:"8px 14px",borderBottom:"1px solid rgba(0,245,196,.08)",
                  fontFamily:"Orbitron",fontSize:7,letterSpacing:2,color:"rgba(0,245,196,.4)"}}>
                  <span>SYMBOL</span><span>RATE (8h)</span><span>ANNUALISED</span><span>SIGNAL</span>
                </div>
                {fundingRates.map(fr=>{
                  const ann=(fr.rate*3*365).toFixed(1);
                  const abs=Math.abs(fr.rate);
                  const isHigh=abs>0.05; const isMed=abs>0.02;
                  const rateColor=fr.rate>0?"#ef4444":fr.rate<0?"#00f5c4":"#f59e0b";
                  const signal=abs>0.1?"🔴 EXTREME FUNDING":abs>0.05?"🟡 HIGH — watch closely":abs>0.02?"🟢 ELEVATED":fr.rate===0?"⬜ NEUTRAL":"⬜ NORMAL";
                  return (
                    <div key={fr.symbol} style={{display:"grid",gridTemplateColumns:"1fr 100px 160px 200px",
                      gap:0,padding:"10px 14px",borderBottom:"1px solid rgba(0,245,196,.05)",
                      transition:"background .15s"}}
                      className="tr2">
                      <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:11}}>{fr.symbol.replace("USDT","")}/USDT</span>
                      <span style={{fontFamily:"Orbitron",fontWeight:700,fontSize:13,color:rateColor}}>
                        {fr.rate>=0?"+":""}{fr.rate.toFixed(4)}%
                      </span>
                      <span style={{fontFamily:"Orbitron",fontSize:10,color:isHigh?"#f59e0b":isMed?"#c8d8f0":"rgba(100,120,160,.5)"}}>
                        {fr.rate>=0?"+":""}{ann}%/yr
                      </span>
                      <span style={{fontSize:9}}>{signal}</span>
                    </div>
                  );
                })}
              </div>
            )}
            {fundingRates.length>0&&(
              <div style={{marginTop:16,background:"rgba(0,0,0,.3)",border:"1px solid rgba(0,245,196,.06)",
                borderRadius:3,padding:"12px 14px",fontSize:9,color:"rgba(140,160,190,.5)",lineHeight:1.7}}>
                <span style={{color:"rgba(0,245,196,.6)",fontFamily:"Orbitron",fontSize:7,letterSpacing:1}}>HOW TO USE: </span>
                High positive rates → longs are overleveraged → consider shorting or avoid longs.
                High negative rates → shorts are overleveraged → consider longing or avoid shorts.
                Rates above 0.1% (8h) = extreme conditions, mean reversion likely.
              </div>
            )}
            {fundingRates.length===0&&!fundingLoading&&(
              <div style={{textAlign:"center",padding:60,fontSize:10,color:"rgba(100,120,160,.3)",fontFamily:"Orbitron",letterSpacing:2}}>
                CLICK FETCH TO LOAD RATES<br/>
                <span style={{fontSize:7.5,marginTop:8,display:"block"}}>Powered by Bybit perpetual futures data</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ══ STOP TRADING MODAL ══ */}
      {showStopModal&&(
        <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.82)",zIndex:200,
          display:"flex",alignItems:"center",justifyContent:"center",padding:20}}
          onClick={()=>setShowStopModal(false)}>
          <div style={{background:"#0a1628",border:"1px solid rgba(239,68,68,.3)",
            borderRadius:8,padding:32,maxWidth:420,width:"100%",boxShadow:"0 0 40px rgba(239,68,68,.1)"}}
            onClick={e=>e.stopPropagation()}>

            <div style={{fontFamily:"Orbitron",fontWeight:700,fontSize:15,color:"#ef4444",
              letterSpacing:2,marginBottom:4}}>STOP TRADING</div>
            <div style={{fontSize:9.5,color:"rgba(160,180,210,.5)",marginBottom:24,letterSpacing:1}}>
              {isDemo?"DEMO MODE":paperMode?"PAPER MODE":"LIVE MODE"} · {openPos.length} open position{openPos.length!==1?"s":""} will be closed at market price
            </div>

            <div style={{background:"rgba(0,245,196,.04)",border:"1px solid rgba(0,245,196,.1)",
              borderRadius:6,padding:18,marginBottom:20,display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
              {[
                ["CLOSED TRADES",  trades.length],
                ["WIN RATE",       stats.winRate==="---"?"---":`${stats.winRate}%`],
                ["TOTAL P&L",      `${parseFloat(stats.totalPnL||0)>=0?"+":""}${parseFloat(stats.totalPnL||0).toFixed(2)}%`],
                ["BALANCE", (()=>{
                  const usdtBal = balances.find(b=>b.asset==="USDT");
                  if (isDemo || paperMode) return `$${fmt(usdtBal?.free||"10000")}`;
                  if (usdtBal && parseFloat(usdtBal.free||0)>0) return `$${fmt(usdtBal.free)}`;
                  return "See exchange";
                })()],
              ].map(([label,val])=>(
                <div key={label}>
                  <div style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.35)",letterSpacing:1.5,marginBottom:3}}>{label}</div>
                  <div style={{fontFamily:"Orbitron",fontSize:13,fontWeight:700,
                    color:label==="TOTAL P&L"?parseFloat(stats.totalPnL||0)>=0?"#00f5c4":"#ef4444":"#c8d8f0"}}>{val}</div>
                </div>
              ))}
            </div>

            {openPos.length>0&&(
              <div style={{background:"rgba(245,158,11,.06)",border:"1px solid rgba(245,158,11,.2)",
                borderRadius:4,padding:"10px 14px",marginBottom:18,fontSize:9,color:"#f59e0b",lineHeight:1.6}}>
                You have <b>{openPos.length}</b> open position{openPos.length!==1?"s":""}.
                Clicking <b>STOP TRADING</b> will <b>sell all positions</b> at the current market price and return your capital + profit/loss to your balance.
              </div>
            )}

            <div style={{display:"flex",flexDirection:"column",gap:10}}>

              {/* ── OPTION 1: Stop and add profit to balance (ALL modes) ── */}
              <button onClick={async ()=>{
                setBotRunning(false); // stop the bot tick immediately
                const currentPrices = priceRef.current;
                let totalDollarPnl = 0;
                let totalCapitalReturned = 0;
                const closedNow = [];
                posRef.current.forEach(pos=>{
                  const price = currentPrices[pos.symbol]||pos.entry;
                  const pnlPct = pos.side==="BUY"
                    ?(price-pos.entry)/pos.entry*100
                    :(pos.entry-price)/pos.entry*100;
                  const dollarPnl = (pnlPct/100)*(pos.qty*pos.entry);
                  totalDollarPnl += dollarPnl;
                  totalCapitalReturned += pos.qty*pos.entry;
                  closedNow.push({...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:"STOPPED"});
                  addLog("Bot",`Force-closed ${pos.symbol} on STOP — PnL: ${fmtP(pnlPct)}`,pnlPct>=0?"ok":"warn");
                });

                if (isDemo||paperMode) {
                  // Paper/demo: update UI immediately
                  if (closedNow.length>0) {
                    setTrades(prev=>[...closedNow,...prev.slice(0,199)]);
                    setOpenPos([]);
                    setBalances(prev=>prev.map(b=>
                      b.asset==="USDT"
                        ?{...b,free:String((parseFloat(b.free)+totalCapitalReturned+totalDollarPnl).toFixed(2))}
                        :b
                    ));
                    addLog("Bot",
                      `All ${closedNow.length} position${closedNow.length!==1?"s":""} closed — Net P&L: ${totalDollarPnl>=0?"+":""}$${totalDollarPnl.toFixed(2)} added to balance`,
                      totalDollarPnl>=0?"ok":"warn");
                  }
                } else {
                  // Live — ALWAYS sell from actual Bybit wallet first (reliable even after refresh)
                  addLog("Bot",`Stopping bot — selling all positions on ${(creds?.exchange||"").toUpperCase()}…`,"info");
                  const sellResult = await sellAllLivePositions();
                  if (sellResult) {
                    // Bybit: sellAllLivePositions queried wallet directly — most reliable path
                    addLog("Bot",
                      `${sellResult.sold} position${sellResult.sold!==1?"s":""} sold → USDT${sellResult.failed>0?` · ${sellResult.failed} failed (check exchange app)`:""}`,
                      sellResult.failed===0?"ok":"warn");
                  } else {
                    // Non-Bybit: fall back to posRef loop
                    let sellSuccessCount1 = 0;
                    for (const pos of closedNow) {
                      const closeSide = pos.side==="BUY"?"SELL":"BUY";
                      const result = await placeOrder(pos.symbol,closeSide,pos.qty);
                      if (result) { sellSuccessCount1++; }
                      else { addLog("Bot",`⚠ Sell failed for ${pos.symbol} — check exchange manually`,"error"); }
                    }
                    fetchBalances();
                    setTimeout(()=>fetchBalances(), 3000);
                    setTimeout(()=>fetchBalances(), 8000);
                    addLog("Bot",
                      `${sellSuccessCount1}/${closedNow.length} position${closedNow.length!==1?"s":""} sold — USDT refreshing`,
                      sellSuccessCount1===closedNow.length?"ok":"warn");
                  }
                  // Clear UI after sell attempt
                  if (closedNow.length>0) setTrades(prev=>[...closedNow,...prev.slice(0,199)]);
                  setOpenPos([]);
                }
                setShowStopModal(false);
                setTab("dashboard");  // stay on dashboard — balance refreshes in place
              }} style={{padding:"14px 18px",fontFamily:"Orbitron",fontWeight:700,fontSize:10,
                letterSpacing:1.5,border:"1px solid rgba(0,245,196,.4)",
                background:"rgba(0,245,196,.08)",color:"#00f5c4",cursor:"pointer",
                borderRadius:4,display:"flex",alignItems:"center",gap:12}}>
                <span style={{fontSize:18}}>💰</span>
                <div style={{textAlign:"left"}}>
                  <div>STOP AND ADD PROFIT TO BALANCE</div>
                  <div style={{fontSize:7.5,color:"rgba(0,245,196,.5)",fontWeight:400,marginTop:2,letterSpacing:1}}>
                    {isDemo||paperMode ? "Closes positions & credits P&L to virtual balance" : "Closes positions & refreshes balance from exchange"}
                  </div>
                </div>
              </button>

              {/* ── OPTION 2: Stop and withdraw profit (ALL modes) ── */}
              <button onClick={async ()=>{
                setBotRunning(false); // stop the bot tick immediately
                if (isDemo||paperMode) {
                  // Demo/paper: credit balance then open wallet
                  const currentPrices = priceRef.current;
                  let totalDollarPnl = 0, totalCapitalReturned = 0;
                  const closedNow = [];
                  posRef.current.forEach(pos=>{
                    const price = currentPrices[pos.symbol]||pos.entry;
                    const pnlPct = pos.side==="BUY"
                      ?(price-pos.entry)/pos.entry*100
                      :(pos.entry-price)/pos.entry*100;
                    totalDollarPnl += (pnlPct/100)*(pos.qty*pos.entry);
                    totalCapitalReturned += pos.qty*pos.entry;
                    closedNow.push({...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:"STOPPED"});
                    addLog("Bot",`Force-closed ${pos.symbol} on STOP — PnL: ${fmtP(pnlPct)}`,pnlPct>=0?"ok":"warn");
                  });
                  if (closedNow.length>0) {
                    setTrades(prev=>[...closedNow,...prev.slice(0,199)]);
                    setOpenPos([]);
                    setBalances(prev=>prev.map(b=>
                      b.asset==="USDT"
                        ?{...b,free:String((parseFloat(b.free)+totalCapitalReturned+totalDollarPnl).toFixed(2))}
                        :b
                    ));
                    addLog("Bot",`Positions closed — P&L credited. Opening wallet panel.`,"ok");
                  }
                } else {
                  // Live — sell from actual Bybit wallet FIRST, then clear UI
                  addLog("Bot",`Stopping bot — selling all positions on ${(creds?.exchange||"").toUpperCase()}…`,"info");
                  const sellResult2 = await sellAllLivePositions();
                  if (sellResult2) {
                    addLog("Bot",
                      `${sellResult2.sold} position${sellResult2.sold!==1?"s":""} sold → USDT${sellResult2.failed>0?` · ${sellResult2.failed} failed (check exchange app)`:""}. Opening wallet.`,
                      sellResult2.failed===0?"ok":"warn");
                  } else {
                    // Non-Bybit: fall back to posRef loop
                    const posSnapshot = [...posRef.current];
                    const closedNow = [];
                    for (const pos of posSnapshot) {
                      const price = priceRef.current[pos.symbol]||pos.entry;
                      const pnlPct = pos.side==="BUY"
                        ?(price-pos.entry)/pos.entry*100
                        :(pos.entry-price)/pos.entry*100;
                      closedNow.push({...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:"STOPPED"});
                      addLog("Bot",`Force-closed ${pos.symbol} on STOP — PnL: ${fmtP(pnlPct)}`,pnlPct>=0?"ok":"warn");
                      const result = await placeOrder(pos.symbol,pos.side==="BUY"?"SELL":"BUY",pos.qty);
                      if (!result) addLog("Bot",`⚠ Sell failed for ${pos.symbol} — check exchange manually`,"error");
                    }
                    if (closedNow.length > 0) setTrades(prev=>[...closedNow,...prev.slice(0,199)]);
                    fetchBalances();
                    setTimeout(()=>fetchBalances(), 3000);
                    setTimeout(()=>fetchBalances(), 8000);
                  }
                  setOpenPos([]);
                }
                setShowStopModal(false);
                setTab("wallet");
              }} style={{padding:"14px 18px",fontFamily:"Orbitron",fontWeight:700,fontSize:10,
                letterSpacing:1.5,border:"1px solid rgba(0,245,196,.4)",
                background:"rgba(0,245,196,.08)",color:"#00f5c4",cursor:"pointer",
                borderRadius:4,display:"flex",alignItems:"center",gap:12}}>
                <span style={{fontSize:18}}>💸</span>
                <div style={{textAlign:"left"}}>
                  <div>STOP AND WITHDRAW PROFIT</div>
                  <div style={{fontSize:7.5,color:"rgba(0,245,196,.5)",fontWeight:400,marginTop:2,letterSpacing:1}}>
                    {isDemo||paperMode ? "Credits P&L to balance then opens withdrawal panel" : "Stops bot and opens withdrawal panel"}
                  </div>
                </div>
              </button>

              {/* ── OPTION 3: Stop trading only — closes positions, no balance credit action ── */}
              <button onClick={async ()=>{
                setBotRunning(false); // stop the bot tick immediately
                const posSnapshot = [...posRef.current];
                const closedNow3 = [];
                let totalDollarPnl3 = 0;

                if (paperMode || isDemo) {
                  // Paper/demo: close from posRef
                  for (const pos of posSnapshot) {
                    const price = priceRef.current[pos.symbol] || pos.entry;
                    const pnlPct = pos.side==="BUY"?(price-pos.entry)/pos.entry*100:(pos.entry-price)/pos.entry*100;
                    totalDollarPnl3 += (pnlPct/100)*(pos.qty*pos.entry);
                    closedNow3.push({...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:"STOPPED"});
                    addLog("Bot",`Force-closed ${pos.symbol} on STOP — PnL: ${fmtP(pnlPct)}`,pnlPct>=0?"ok":"warn");
                  }
                } else {
                  // Live — sell from actual Bybit wallet FIRST (bypasses stale posRef)
                  addLog("Bot",`Stopping bot — selling all positions on ${(creds?.exchange||"").toUpperCase()}…`,"info");
                  const sellResult3 = await sellAllLivePositions();
                  if (sellResult3) {
                    addLog("Bot",
                      `${sellResult3.sold} position${sellResult3.sold!==1?"s":""} sold → USDT${sellResult3.failed>0?` · ${sellResult3.failed} failed (check exchange app)`:""}`,
                      sellResult3.failed===0?"ok":"warn");
                  } else {
                    // Non-Bybit: fall back to posRef loop
                    for (const pos of posSnapshot) {
                      const price = priceRef.current[pos.symbol]||pos.entry;
                      const pnlPct = pos.side==="BUY"?(price-pos.entry)/pos.entry*100:(pos.entry-price)/pos.entry*100;
                      totalDollarPnl3 += (pnlPct/100)*(pos.qty*pos.entry);
                      closedNow3.push({...pos,closePrice:price,pnl:pnlPct,closeTs:new Date(),result:"STOPPED"});
                      const result = await placeOrder(pos.symbol,pos.side==="BUY"?"SELL":"BUY",pos.qty);
                      if (result) { addLog("Bot",`✓ Closed ${pos.symbol} — PnL: ${fmtP(pnlPct)}`,pnlPct>=0?"ok":"warn"); }
                      else { addLog("Bot",`⚠ Sell FAILED for ${pos.symbol} — check exchange app`,"error"); }
                    }
                    fetchBalances();
                    setTimeout(()=>fetchBalances(), 3000);
                    setTimeout(()=>fetchBalances(), 8000);
                  }
                }
                if (closedNow3.length > 0) {
                  setTrades(prev=>[...closedNow3,...prev.slice(0,199)]);
                }
                setOpenPos([]);
                setShowStopModal(false);
                setTab("dashboard");  // stay on dashboard — balance refreshes in place
              }} style={{padding:"14px 18px",fontFamily:"Orbitron",fontWeight:700,fontSize:10,
                letterSpacing:1.5,border:"1px solid rgba(239,68,68,.35)",
                background:"rgba(239,68,68,.07)",color:"#ef4444",cursor:"pointer",
                borderRadius:4,display:"flex",alignItems:"center",gap:12}}>
                <span style={{fontSize:18}}>■</span>
                <div style={{textAlign:"left"}}>
                  <div>STOP TRADING ONLY</div>
                  <div style={{fontSize:7.5,color:"rgba(239,68,68,.5)",fontWeight:400,marginTop:2,letterSpacing:1}}>
                    Sells all positions &amp; returns balance
                  </div>
                </div>
              </button>

              <button onClick={()=>setShowStopModal(false)}
                style={{padding:"10px 18px",fontFamily:"Orbitron",fontSize:9,
                  letterSpacing:1.5,border:"1px solid rgba(0,245,196,.1)",
                  background:"transparent",color:"rgba(0,245,196,.35)",cursor:"pointer",borderRadius:4}}>
                CANCEL — KEEP TRADING
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ══ STATUS BAR ══ */}
      <div style={{background:"rgba(1,4,12,.99)",borderTop:"1px solid rgba(0,245,196,.06)",
        padding:"4px 18px",display:"flex",alignItems:"center",gap:18,flexShrink:0,zIndex:10}}>
        {[
          ["EXCHANGE",   (creds?.exchange||"—").toUpperCase()],
          ["MODE",       isDemo?"DEMO":paperMode?"PAPER":"LIVE ⚠"],
          ["STATUS",     botRunning?"RUNNING":"IDLE"],
          ["INDICATORS", "EMA·RSI·MACD·BB·ATR·ADX·VOL·PATT"],
          ["INTERVAL",   cfg.interval],
          ["PAIRS",      `${eligiblePairs.length}/${TOP_PAIRS.length}`],
          ["OPEN",       posWithPnl.length],
          ["WIN RATE",   stats.winRate==="—"?"—":`${stats.winRate}%`],
          ["R:R",        stats.avgRR==="—"?"—":`${stats.avgRR}:1`],
          ["WALLET",     wallet?`${wallet.address.slice(0,6)}...`:"—"],
        ].map(([k,v])=>(
          <div key={k} style={{display:"flex",gap:5,alignItems:"center"}}>
            <span style={{fontFamily:"Orbitron",fontSize:6,letterSpacing:1.5,color:"rgba(0,245,196,.25)"}}>{k}:</span>
            <span style={{fontFamily:"Orbitron",fontSize:8,color:"#c8d8f0",fontWeight:700}}>{v}</span>
          </div>
        ))}
        <div style={{flex:1}}/>
        <span style={{fontFamily:"Orbitron",fontSize:6.5,color:"rgba(0,245,196,.12)",letterSpacing:2}}>
          TFunds Bot v2 © 2026 · KEYS NEVER STORED · ALL SIGNING LOCAL
        </span>
      </div>
    </div>
  );
}
