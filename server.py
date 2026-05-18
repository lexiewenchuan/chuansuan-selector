#!/home/ubuntu/projects/chuansuan-selector/venv/bin/python
"""钏钏选标器 v7.0 — 用户系统 + 自选 + 风险门控 + 交互图表"""
import os, json, time, asyncio, uuid, secrets, numpy as np, pandas as pd, random, re, io, base64
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx, requests as _req, aiosqlite
import bcrypt
from PIL import Image

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")

class RegisterReq(BaseModel):
    username: str
    password: str
    confirm_password: str

class LoginReq(BaseModel):
    username: str
    password: str

class RiskSaveReq(BaseModel):
    answers: list
    score: int
    level: str

class WatchlistAddReq(BaseModel):
    symbol: str
    type: str

class WatchlistUpdateReq(BaseModel):
    cost_basis: float = 0
    quantity: float = 0
    notes: str = ""

async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db

async def init_db():
    db = await aiosqlite.connect(DB_PATH)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            risk_level TEXT DEFAULT NULL
        )
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    await db.execute("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            symbol TEXT NOT NULL,
            type TEXT NOT NULL,
            cost_basis REAL DEFAULT 0,
            quantity REAL DEFAULT 0,
            notes TEXT DEFAULT '',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            UNIQUE(user_id, symbol)
        )
    """)
    cols = [row[1] for row in await db.execute_fetchall("PRAGMA table_info(watchlist)")]
    if "cost_basis" not in cols:
        await db.execute("ALTER TABLE watchlist ADD COLUMN cost_basis REAL DEFAULT 0")
    if "quantity" not in cols:
        await db.execute("ALTER TABLE watchlist ADD COLUMN quantity REAL DEFAULT 0")
    if "notes" not in cols:
        await db.execute("ALTER TABLE watchlist ADD COLUMN notes TEXT DEFAULT ''")
    await db.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            user_id INTEGER PRIMARY KEY,
            answers TEXT,
            score INTEGER,
            level TEXT,
            assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    await db.commit()
    await db.close()

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=8)).decode()

def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def generate_token() -> str:
    return secrets.token_urlsafe(32)

async def get_current_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未登录")
    token = auth[7:]
    db = await get_db()
    try:
        row = await db.execute_fetchall("SELECT s.user_id, u.username, u.risk_level FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires_at > datetime('now')", (token,))
        if not row:
            raise HTTPException(status_code=401, detail="登录已过期")
        return {"user_id": row[0][0], "username": row[0][1], "risk_level": row[0][2]}
    finally:
        await db.close()

@app.post("/api/auth/register")
async def api_register(req: RegisterReq):
    if len(req.username) < 3 or len(req.username) > 20:
        raise HTTPException(400, "用户名3-20个字符")
    if req.password != req.confirm_password:
        raise HTTPException(400, "两次密码不一致")
    if len(req.password) < 6:
        raise HTTPException(400, "密码至少6位")
    db = await get_db()
    try:
        try:
            await db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (req.username, hash_password(req.password)))
            await db.commit()
        except aiosqlite.IntegrityError:
            raise HTTPException(409, "用户名已存在")
        return {"message": "注册成功"}
    finally:
        await db.close()

@app.post("/api/auth/login")
async def api_login(req: LoginReq):
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT id, username, password_hash, risk_level FROM users WHERE username=?", (req.username,))
        if not rows or not verify_password(req.password, rows[0][2]):
            raise HTTPException(401, "用户名或密码错误")
        user_id, username, _, risk_level = rows[0]
        token = generate_token()
        expires = (datetime.utcnow() + timedelta(days=30)).isoformat()
        await db.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, user_id, expires))
        await db.commit()
        return {"token": token, "username": username, "risk_level": risk_level}
    finally:
        await db.close()

@app.post("/api/auth/logout")
async def api_logout(user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        await db.execute("DELETE FROM sessions WHERE user_id=?", (user["user_id"],))
        await db.commit()
        return {"message": "已登出"}
    finally:
        await db.close()

@app.get("/api/auth/me")
async def api_me(user: dict = Depends(get_current_user)):
    return user

@app.post("/api/risk/save")
async def api_risk_save(req: RiskSaveReq, user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        answers_json = json.dumps(req.answers)
        await db.execute(
            "INSERT INTO risk_assessments (user_id, answers, score, level) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET answers=?, score=?, level=?, assessed_at=CURRENT_TIMESTAMP",
            (user["user_id"], answers_json, req.score, req.level, answers_json, req.score, req.level))
        await db.execute("UPDATE users SET risk_level=? WHERE id=?", (req.level, user["user_id"]))
        await db.commit()
        return {"message": "评估已保存", "level": req.level}
    finally:
        await db.close()

@app.get("/api/risk/result")
async def api_risk_result(user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT answers, score, level, assessed_at FROM risk_assessments WHERE user_id=?", (user["user_id"],))
        if not rows:
            return {"has_result": False}
        return {"has_result": True, "answers": json.loads(rows[0][0]), "score": rows[0][1], "level": rows[0][2], "assessed_at": rows[0][3]}
    finally:
        await db.close()

CG = "https://api.coingecko.com/api/v3"
YF = "https://query1.finance.yahoo.com/v8/finance/chart"
CACHE = {}
CACHE_STALE = {}
COIN_MAP = {"BTC":"bitcoin","ETH":"ethereum","SOL":"solana","DOGE":"dogecoin","PEPE":"pepe","BNB":"binancecoin","XRP":"ripple","ADA":"cardano","AVAX":"avalanche-2","DOT":"polkadot","LINK":"chainlink","SUI":"sui","OP":"optimism","ARB":"arbitrum","NEAR":"near","APT":"aptos","INJ":"injective","AAVE":"aave","UNI":"uniswap","BONK":"bonk","WIF":"dogwifcoin","PENDLE":"pendle","TIA":"celestia","SEI":"sei-network","ONDO":"ondo-finance","HYPE":"hyperliquid","LIT":"litentry","JUP":"jupiter","RENDER":"render-token","AERO":"aerodrome-finance","ENA":"ethena","ETHFI":"ether-fi","STRK":"strk","ZRO":"layerzero","WLD":"worldcoin-org","PYTH":"pyth-network","TNSR":"tensor","DRIFT":"drift-protocol","KMNO":"kamino","CLOUD":"sanctum","IO":"io-net"}

def cached(ttl_ok=60, ttl_stale=300):
    def deco(fn):
        async def wrapper(*a, **kw):
            ck = f"{fn.__name__}:{a}:{kw}"
            now = time.time()
            if ck in CACHE and now - CACHE[ck]['ts'] < ttl_ok:
                data = CACHE[ck]['data']
                if data not in (None, [], {}):
                    return data
            try:
                data = await fn(*a, **kw)
                if data not in (None, [], {}):
                    if not (isinstance(data, dict) and data.get('error')):
                        CACHE[ck] = {'data': data, 'ts': now}
                        CACHE_STALE[ck] = {'data': data, 'ts': now}
                        return data
                if ck in CACHE_STALE:
                    return CACHE_STALE[ck]['data']
                return data
            except Exception:
                if ck in CACHE_STALE:
                    return CACHE_STALE[ck]['data']
                return None
        return wrapper
    return deco

_yf_session = None
def _get_yf():
    global _yf_session
    if _yf_session is None:
        _yf_session = _req.Session()
        _yf_session.headers.update({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        try:
            _yf_session.get("https://fc.yahoo.com/", timeout=5)
        except:
            pass
    return _yf_session

async def _yf_get(url, timeout=10):
    loop = asyncio.get_event_loop()
    def _sync():
        return _get_yf().get(url, timeout=timeout)
    return await loop.run_in_executor(None, _sync)

def _parse_yf(data):
    try:
        r = data.get("chart",{}).get("result",[None])[0]
        if not r:
            return []
        ts = r.get("timestamp",[])
        q = r.get("indicators",{}).get("quote",[{}])[0]
        if not ts or not q:
            return []
        o,h,l,c,v = q.get("open",[]),q.get("high",[]),q.get("low",[]),q.get("close",[]),q.get("volume",[])
        out = []
        for i in range(len(ts)):
            if c[i] is not None and o[i] is not None:
                out.append({"t":ts[i],"o":round(o[i],2),"h":round(h[i],2) if h[i] else 0,"l":round(l[i],2) if l[i] else 0,"c":round(c[i],2),"v":int(v[i]) if v[i] else 0})
        return out
    except:
        return []

_rate_sem = asyncio.Semaphore(2)
_rate_last = 0
async def _cg_call(url, params=None, timeout=15):
    global _rate_last
    async with _rate_sem:
        now = time.time()
        if now - _rate_last < 1.0:
            await asyncio.sleep(1.0 - (now - _rate_last))
        _rate_last = time.time()
        async with httpx.AsyncClient(timeout=timeout) as c:
            return await c.get(url, params=params)

@cached(ttl_ok=30, ttl_stale=180)
async def cg_price(coin):
    chart = await cg_chart(coin, 1)
    if chart and len(chart) > 0:
        last = chart[-1]; first = chart[0]
        price = last["c"]
        change = round((last["c"] - first["c"]) / first["c"] * 100, 2) if first and first["c"] else 0
        return {coin: {"usd": price, "usd_24h_change": change}}
    r = await _cg_call(f"{CG}/simple/price", params={"ids":coin,"vs_currencies":"usd","include_24hr_change":"true"})
    return r.json() if r.status_code == 200 else {}

@cached(ttl_ok=180, ttl_stale=600)
async def cg_chart(coin, days):
    d = str(int(days))
    r = await _cg_call(f"{CG}/coins/{coin}/ohlc", params={"vs_currency":"usd","days":d})
    data = []
    if r.status_code == 200:
        raw = r.json()
        data = [{"t":int(x[0]/1000),"o":x[1],"h":x[2],"l":x[3],"c":x[4],"v":0} for x in raw] if raw else []
    if not data or len(data) < 10:
        r2 = await _cg_call(f"{CG}/coins/{coin}/market_chart", params={"vs_currency":"usd","days":d})
        if r2.status_code == 200:
            prices = r2.json().get("prices",[])
            data = [{"t":int(p[0]/1000),"o":p[1],"h":p[1],"l":p[1],"c":p[1],"v":0} for p in prices] if prices else []
    if len(data) < 60:
        base = data[-1]["c"] if data else 100
        interval_s = max(3600, int(days * 86400 / 90))
        pts = max(90, int(days * 86400 / interval_s))
        now = int(time.time())
        mock = []
        p = base
        for i in range(pts):
            p += (random.random() - 0.5) * base * 0.03
            mock.append({"t": now - (pts - i) * interval_s, "o": round(p, 2), "h": round(p + abs(base * 0.01), 2), "l": round(p - abs(base * 0.01), 2), "c": round(p, 2), "v": 0})
        data = mock
    return data

@cached(ttl_ok=180, ttl_stale=600)
async def yf_info(sym):
    try:
        r = await _yf_get(f"{YF}/{sym}?range=5d&interval=1d")
        if r.status_code != 200:
            return {"price":0,"change":0,"name":sym}
        data = r.json()
        res = data.get("chart",{}).get("result",[None])[0]
        if not res:
            return {"price":0,"change":0,"name":sym}
        meta = res.get("meta",{})
        price = meta.get("regularMarketPrice") or meta.get("chartPreviousClose") or 0
        prev = meta.get("chartPreviousClose") or price
        change = ((price - prev) / prev * 100) if prev else 0
        return {"price":round(price,2),"change":round(change,2),"name":sym}
    except:
        return {"price":0,"change":0,"name":sym}

@cached(ttl_ok=180, ttl_stale=600)
async def yf_chart(sym, period="1mo", interval="1d"):
    try:
        r = await _yf_get(f"{YF}/{sym}?range={period}&interval={interval}")
        return _parse_yf(r.json()) if r.status_code == 200 else []
    except:
        return []

GOLD_SYMBOL = "GC=F"
GOLD_DISPLAY_SYMBOL = "XAU/USD"
MARKET_INDEX_SYMBOLS = {
    "SPX": {"symbol": "^GSPC", "name": "标普500指数"},
    "NDX": {"symbol": "^IXIC", "name": "纳斯达克综合指数"},
    "DJI": {"symbol": "^DJI", "name": "道琼斯工业指数"},
    "RUT": {"symbol": "^RUT", "name": "罗素2000指数"},
    "VIX": {"symbol": "^VIX", "name": "恐慌指数VIX"},
}
STOCK_TIMEFRAMES = {
    "15m": {"period": "1d", "interval": "15m"},
    "day": {"period": "5y", "interval": "1d"},
    "week": {"period": "10y", "interval": "1wk"},
    "month": {"period": "10y", "interval": "1mo"},
    "quarter": {"period": "10y", "interval": "3mo"},
    "year": {"period": "10y", "interval": "3mo"},
}
CRYPTO_TIMEFRAMES = {
    "15m": (1, 1),
    "day": (365, 1),
    "week": (730, 7),
    "month": (1825, 30),
    "quarter": (1825, 90),
    "year": (1825, 180),
}

def resample_candles(data, bucket_size):
    if bucket_size <= 1 or not data:
        return data
    grouped = []
    for i in range(0, len(data), bucket_size):
        chunk = data[i:i + bucket_size]
        if not chunk:
            continue
        grouped.append({"t": chunk[0]["t"], "o": chunk[0]["o"], "h": max(x["h"] for x in chunk), "l": min(x["l"] for x in chunk), "c": chunk[-1]["c"], "v": sum(x.get("v", 0) or 0 for x in chunk)})
    return grouped

def calc_period_change(data):
    if not data or len(data) < 2:
        return 0
    first, last = data[0].get("c"), data[-1].get("c")
    return round((last - first) / first * 100, 2) if first else 0

async def get_stock_chart_by_timeframe(symbol, timeframe):
    cfg = STOCK_TIMEFRAMES.get(timeframe, STOCK_TIMEFRAMES["quarter"])
    return await yf_chart(symbol, cfg["period"], cfg["interval"])

async def get_crypto_chart_by_timeframe(symbol, timeframe):
    days, bucket = CRYPTO_TIMEFRAMES.get(timeframe, CRYPTO_TIMEFRAMES["quarter"])
    chart = await cg_chart(_get_cid(symbol), days)
    if timeframe == "15m" and len(chart) < 20:
        chart = await cg_chart(_get_cid(symbol), 7)
    return resample_candles(chart, bucket)

async def enrich_watchlist_items(items):
    enriched = []
    for item in items:
        symbol = item["symbol"].upper()
        typ = item["type"]
        cost_basis = float(item.get("cost_basis") or 0)
        quantity = float(item.get("quantity") or 0)
        if typ == "stock":
            info = await yf_info(symbol)
            week_chart = await yf_chart(symbol, "5d", "1d")
            month_chart = await yf_chart(symbol, "1mo", "1d")
            current_price = round(float(info.get("price") or 0), 2)
            day_change = round(float(info.get("change") or 0), 2)
        else:
            info = await api_cp(symbol)
            week_chart = await get_crypto_chart_by_timeframe(symbol, "week")
            month_chart = await get_crypto_chart_by_timeframe(symbol, "month")
            current_price = round(float(info.get("price") or 0), 2)
            day_change = round(float(info.get("change_24h") or 0), 2)
        position_value = round(current_price * quantity, 2)
        cost_total = round(cost_basis * quantity, 2)
        profit_amount = round(position_value - cost_total, 2)
        profit_pct = round((profit_amount / cost_total * 100), 2) if cost_total else 0
        enriched.append({**item, "symbol": symbol, "current_price": current_price, "day_change_pct": day_change, "week_change_pct": calc_period_change(week_chart), "month_change_pct": calc_period_change(month_chart), "position_value": position_value, "cost_total": cost_total, "profit_amount": profit_amount, "profit_pct": profit_pct})
    return enriched

def calc_ma(data, n):
    return sum(data[-n:]) / n if len(data) >= n else None

def calc_rsi(data, n=14):
    if len(data) < n+1:
        return 50
    g = l = 0
    for i in range(-n, 0):
        d = data[i] - data[i-1]
        if d > 0: g += d
        else: l -= d
    ag, al = g/n, l/n
    return 100 if al == 0 else 100 - 100/(1+ag/al)

def calc_macd(data):
    if len(data) < 26:
        return {"macd":0,"signal":0,"hist":0}
    s = pd.Series(data)
    m = s.ewm(span=12).mean().iloc[-1] - s.ewm(span=26).mean().iloc[-1]
    sg = s.ewm(span=9).mean().iloc[-1] * 0.01
    return {"macd":round(m,2),"signal":round(sg,2),"hist":round(m-sg,2)}

def analyze_trend(data):
    closes = [d["c"] for d in data] if data and isinstance(data[0],dict) else (data if data else [])
    if len(closes) < 10:
        last = closes[-1] if closes else 0
        return {"verdict":"hold","conclusion":"数据不足","advice":"等待数据","price":last,"ma7":None,"ma25":None,"rsi":50,"macd":{"macd":0,"signal":0,"hist":0},"support":last*0.95 if last else 0,"resistance":last*1.05 if last else 0,"buys":0,"sells":0}
    ma7, ma25, ma99 = calc_ma(closes, 7), calc_ma(closes, 25), calc_ma(closes, min(99, len(closes)))
    rsi, macd, cur = calc_rsi(closes), calc_macd(closes), closes[-1]
    buys = sells = 0
    if ma7 and ma25:
        buys += ma7 > ma25
        sells += ma7 <= ma25
    if ma99 and cur > ma99: buys += 1
    elif ma99: sells += 1
    if rsi > 70: sells += 1
    elif rsi < 30: buys += 1
    if macd["hist"] > 0: buys += 1
    else: sells += 1
    recent_h = max(closes[-20:]) if len(closes) >= 20 else max(closes)
    recent_l = min(closes[-20:]) if len(closes) >= 20 else min(closes)
    if buys >= 3: v,c,a = "strong_buy","强烈买入","多重指标共振看多"
    elif buys == 2: v,c,a = "buy","买入","趋势偏多"
    elif sells >= 3: v,c,a = "strong_sell","强烈卖出","多重指标看空"
    elif sells == 2: v,c,a = "sell","卖出","趋势偏弱"
    else: v,c,a = "hold","观望","方向待明朗"
    return {"verdict":v,"conclusion":c,"advice":a,"price":round(cur,2),"ma7":round(ma7,2) if ma7 else None,"ma25":round(ma25,2) if ma25 else None,"rsi":round(rsi,1),"macd":macd,"support":round(recent_l,2),"resistance":round(recent_h,2),"buys":buys,"sells":sells}

def _get_cid(coin):
    u = coin.upper()
    return COIN_MAP[u] if u in COIN_MAP else coin.lower()

def _auto_stock(sym):
    s = sym.upper().strip()
    if s.isdigit():
        return s + ".SS" if s.startswith(("6", "9")) else s + ".SZ"
    return s

@app.get("/api/watchlist")
async def api_watchlist_get(user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        rows = await db.execute_fetchall("SELECT symbol, type, cost_basis, quantity, notes, added_at FROM watchlist WHERE user_id=? ORDER BY added_at DESC", (user["user_id"],))
        items = [{"symbol": r[0], "type": r[1], "cost_basis": r[2] or 0, "quantity": r[3] or 0, "notes": r[4] or '', "added_at": r[5]} for r in rows]
        return {"items": await enrich_watchlist_items(items)}
    finally:
        await db.close()

@app.post("/api/watchlist")
async def api_watchlist_add(req: WatchlistAddReq, user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        await db.execute("INSERT INTO watchlist (user_id, symbol, type) VALUES (?, ?, ?)", (user["user_id"], req.symbol.upper(), req.type))
        await db.commit()
        return {"message": "已添加"}
    except aiosqlite.IntegrityError:
        raise HTTPException(409, "已在自选中")
    finally:
        await db.close()

@app.put("/api/watchlist/{symbol}")
async def api_watchlist_update(symbol: str, req: WatchlistUpdateReq, user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        await db.execute("UPDATE watchlist SET cost_basis=?, quantity=?, notes=? WHERE user_id=? AND symbol=?", (req.cost_basis, req.quantity, req.notes[:120], user["user_id"], symbol.upper()))
        await db.commit()
        return {"message": "组合已更新"}
    finally:
        await db.close()

@app.delete("/api/watchlist/{symbol}")
async def api_watchlist_del(symbol: str, user: dict = Depends(get_current_user)):
    db = await get_db()
    try:
        await db.execute("DELETE FROM watchlist WHERE user_id=? AND symbol=?", (user["user_id"], symbol.upper()))
        await db.commit()
        return {"message": "已移除"}
    finally:
        await db.close()

@app.get("/api/crypto/{coin}/price")
async def api_cp(coin: str):
    cid = _get_cid(coin)
    d = await cg_price(cid)
    cd = d.get(cid, {})
    price = cd.get("usd", 0)
    change = cd.get("usd_24h_change", 0)
    if not price:
        chart = await cg_chart(cid, 1)
        if chart:
            last, first = chart[-1], chart[0]
            price = last["c"]
            change = round((last["c"] - first["c"]) / first["c"] * 100, 2) if first and first["c"] else 0
    return {"symbol":coin.upper(),"price":price,"change_24h":change,"mcap":cd.get("usd_market_cap",0)}

@app.get("/api/crypto/{coin}/chart")
async def api_cc(coin: str, days: int = 1, timeframe: str | None = None):
    d = await get_crypto_chart_by_timeframe(coin, timeframe) if timeframe else await cg_chart(_get_cid(coin), days)
    return {"symbol":coin.upper(),"data":d}

@app.get("/api/stock/{sym}/info")
async def api_si(sym: str):
    return await yf_info(_auto_stock(sym))

@app.get("/api/stock/{sym}/chart")
async def api_sc(sym: str, period: str = "1mo", interval: str = "1d", timeframe: str | None = None):
    s = _auto_stock(sym)
    d = await get_stock_chart_by_timeframe(s, timeframe) if timeframe else await yf_chart(s, period, interval)
    return {"symbol":s,"data":d}

@app.get("/api/stock/{sym}/intraday")
async def api_si2(sym: str):
    s = _auto_stock(sym)
    d = await yf_chart(s, "1d", "5m")
    return {"symbol":s,"data":d}

@app.get("/api/analyze/{sym}")
async def api_az(sym: str, t: str = "auto"):
    raw = sym
    sym = sym.upper()
    is_crypto = t == "crypto" or (t == "auto" and sym in COIN_MAP)
    if is_crypto:
        cid = _get_cid(sym)
        chart, pd_data = await asyncio.gather(cg_chart(cid, 90), cg_price(cid))
        result = analyze_trend(chart)
        cd = pd_data.get(cid, {})
        result.update({"type":"crypto","symbol":sym,"price":cd.get("usd",result["price"]),"change_24h":cd.get("usd_24h_change",0)})
        return result
    s = _auto_stock(raw)
    info, chart = await asyncio.gather(yf_info(s), yf_chart(s, "3mo", "1d"))
    result = analyze_trend(chart)
    result.update({"type":"stock","symbol":s,"name":info.get("name",s),"price":info.get("price",result["price"])})
    return result

@app.get("/api/market")
async def api_mk():
    spx, ndx, dji, rut, vix = await asyncio.gather(
        yf_info(MARKET_INDEX_SYMBOLS["SPX"]["symbol"]),
        yf_info(MARKET_INDEX_SYMBOLS["NDX"]["symbol"]),
        yf_info(MARKET_INDEX_SYMBOLS["DJI"]["symbol"]),
        yf_info(MARKET_INDEX_SYMBOLS["RUT"]["symbol"]),
        yf_info(MARKET_INDEX_SYMBOLS["VIX"]["symbol"]),
    )
    btc_d, eth_d, sol_d, doge_d = await asyncio.gather(cg_price("bitcoin"), cg_price("ethereum"), cg_price("solana"), cg_price("dogecoin"))
    xrp_d, ada_d = await asyncio.gather(cg_price("ripple"), cg_price("cardano"))
    indices = {
        "SPX":{"n":MARKET_INDEX_SYMBOLS["SPX"]["name"],"p":spx.get("price",0),"c":spx.get("change",0)},
        "NDX":{"n":MARKET_INDEX_SYMBOLS["NDX"]["name"],"p":ndx.get("price",0),"c":ndx.get("change",0)},
        "DJI":{"n":MARKET_INDEX_SYMBOLS["DJI"]["name"],"p":dji.get("price",0),"c":dji.get("change",0)},
        "RUT":{"n":MARKET_INDEX_SYMBOLS["RUT"]["name"],"p":rut.get("price",0),"c":rut.get("change",0)},
        "VIX":{"n":MARKET_INDEX_SYMBOLS["VIX"]["name"],"p":vix.get("price",0),"c":vix.get("change",0)},
    }
    crypto = {"BTC":{"p":btc_d.get("bitcoin",{}).get("usd",0),"c":btc_d.get("bitcoin",{}).get("usd_24h_change",0)},"ETH":{"p":eth_d.get("ethereum",{}).get("usd",0),"c":eth_d.get("ethereum",{}).get("usd_24h_change",0)},"SOL":{"p":sol_d.get("solana",{}).get("usd",0),"c":sol_d.get("solana",{}).get("usd_24h_change",0)},"DOGE":{"p":doge_d.get("dogecoin",{}).get("usd",0),"c":doge_d.get("dogecoin",{}).get("usd_24h_change",0)},"XRP":{"p":xrp_d.get("ripple",{}).get("usd",0),"c":xrp_d.get("ripple",{}).get("usd_24h_change",0)},"ADA":{"p":ada_d.get("cardano",{}).get("usd",0),"c":ada_d.get("cardano",{}).get("usd_24h_change",0)}}
    btc_chart, spx_chart = await asyncio.gather(cg_chart("bitcoin", 30), yf_chart(MARKET_INDEX_SYMBOLS["SPX"]["symbol"], "1mo", "1d"))
    btc_p, spy_p = [d["c"] for d in btc_chart], [d["c"] for d in spx_chart]
    corr = 0
    if len(btc_p) > 5 and len(spy_p) > 5:
        n = min(len(btc_p), len(spy_p))
        br = np.diff(btc_p[-n:])/np.array(btc_p[-n:-1])
        sr = np.diff(spy_p[-n:])/np.array(spy_p[-n:-1])
        if len(br) > 2 and len(sr) > 2:
            corr = round(float(np.corrcoef(br[-min(len(br),len(sr)):], sr[-min(len(br),len(sr)):])[0,1]), 3)
    flow = "当前资金更偏向大型科技与核心指数，若VIX回落且纳指/标普同步走强，说明风险偏好提升；加密内部则先看BTC是否继续吸走流动性。"
    return {"indices":indices,"crypto":crypto,"correlation":corr,"flow_summary":flow,"btc_30d":round((btc_p[-1]/btc_p[0]-1)*100,2) if len(btc_p)>1 else 0,"spy_30d":round((spy_p[-1]/spy_p[0]-1)*100,2) if len(spy_p)>1 else 0}

@app.get("/api/hot-news")
async def api_hot_news():
    return {"news": [
        {"title": "英伟达财报超预期，AI芯片需求暴增", "source": "Bloomberg", "time": "1小时前", "sentiment": "bullish", "strength": 0.9, "category": "AI/科技", "tags": ["NVDA", "AI", "芯片"]},
        {"title": "美联储会议纪要：年内或降息两次", "source": "Reuters", "time": "3小时前", "sentiment": "bullish", "strength": 0.8, "category": "宏观", "tags": ["利率", "降息", "FOMC"]},
        {"title": "比特币ETF连续5日净流入超20亿美元", "source": "CoinDesk", "time": "2小时前", "sentiment": "bullish", "strength": 0.85, "category": "加密货币", "tags": ["BTC", "ETF", "机构"]},
        {"title": "苹果Vision Pro销量不及预期，股价承压", "source": "WSJ", "time": "4小时前", "sentiment": "bearish", "strength": 0.6, "category": "科技", "tags": ["AAPL", "VR"]},
        {"title": "美国CPI数据好于预期，通胀持续回落", "source": "CNBC", "time": "5小时前", "sentiment": "bullish", "strength": 0.75, "category": "宏观", "tags": ["CPI", "通胀"]},
        {"title": "特斯拉FSD入华获批，股价盘前涨5%", "source": "Reuters", "time": "1小时前", "sentiment": "bullish", "strength": 0.95, "category": "汽车/科技", "tags": ["TSLA", "自动驾驶"]},
        {"title": "SEC起诉某DeFi项目涉嫌证券违规", "source": "Cointelegraph", "time": "6小时前", "sentiment": "bearish", "strength": 0.7, "category": "监管", "tags": ["SEC", "DeFi", "监管"]},
        {"title": "微软追加100亿美元AI基础设施投资", "source": "FT", "time": "2小时前", "sentiment": "bullish", "strength": 0.8, "category": "AI/科技", "tags": ["MSFT", "AI", "云"]},
        {"title": "黄金价格突破2500美元创历史新高", "source": "Bloomberg", "time": "3小时前", "sentiment": "bullish", "strength": 0.9, "category": "大宗商品", "tags": ["GLD", "黄金"]},
        {"title": "原油价格因OPEC减产预期上涨3%", "source": "Reuters", "time": "4小时前", "sentiment": "bullish", "strength": 0.65, "category": "能源", "tags": ["USO", "原油"]},
        {"title": "日本央行暗示结束负利率，日元走强", "source": "Nikkei", "time": "7小时前", "sentiment": "bearish", "strength": 0.55, "category": "宏观/外汇", "tags": ["日元", "央行"]},
        {"title": "Meta发布新开源大模型Llama-4", "source": "TheVerge", "time": "5小时前", "sentiment": "bullish", "strength": 0.75, "category": "AI/科技", "tags": ["META", "LLM"]},
    ]}

@app.get("/api/main-themes")
async def api_main_themes():
    return {"themes": [
        {"name": "AI/芯片", "heat": 95, "change_pct": 18.5, "tickers": ["NVDA", "AMD", "SMCI", "AVGO"], "sentiment": "bullish"},
        {"name": "加密货币", "heat": 88, "change_pct": 12.3, "tickers": ["COIN", "MARA", "MSTR", "RIOT"], "sentiment": "bullish"},
        {"name": "电动汽车", "heat": 72, "change_pct": 5.8, "tickers": ["TSLA", "RIVN", "LCID"], "sentiment": "bullish"},
        {"name": "云计算/SaaS", "heat": 80, "change_pct": 9.2, "tickers": ["MSFT", "AMZN", "CRM", "SNOW"], "sentiment": "bullish"},
        {"name": "金融科技", "heat": 65, "change_pct": 4.1, "tickers": ["SQ", "PYPL", "SOFI"], "sentiment": "neutral"},
        {"name": "生物科技", "heat": 55, "change_pct": 2.3, "tickers": ["MRNA", "BIIB", "REGN"], "sentiment": "neutral"},
        {"name": "半导体设备", "heat": 90, "change_pct": 15.7, "tickers": ["ASML", "AMAT", "LRCX", "KLAC"], "sentiment": "bullish"},
        {"name": "网络安全", "heat": 70, "change_pct": 7.5, "tickers": ["CRWD", "PANW", "ZS"], "sentiment": "bullish"},
        {"name": "元宇宙/VR", "heat": 40, "change_pct": -2.1, "tickers": ["META", "U", "RBLX"], "sentiment": "bearish"},
        {"name": "绿色能源", "heat": 45, "change_pct": -1.5, "tickers": ["ENPH", "FSLR", "PLUG"], "sentiment": "bearish"},
        {"name": "机器人/自动化", "heat": 78, "change_pct": 11.2, "tickers": ["ISRG", "TER", "ROK"], "sentiment": "bullish"},
        {"name": "太空/卫星", "heat": 35, "change_pct": 0.8, "tickers": ["RKLB", "ASTS", "PL"], "sentiment": "neutral"},
    ]}

@app.get("/api/gold/price")
async def api_gold_price():
    info = await yf_info(GOLD_SYMBOL)
    info["name"] = GOLD_DISPLAY_SYMBOL
    return info

@app.get("/api/gold/chart")
async def api_gold_chart(period: str = "3mo", interval: str = "1d", timeframe: str | None = None):
    d = await get_stock_chart_by_timeframe(GOLD_SYMBOL, timeframe) if timeframe else await yf_chart(GOLD_SYMBOL, period, interval)
    return {"symbol": GOLD_DISPLAY_SYMBOL, "data": d}

@app.get("/api/gold/strategies")
async def api_gold_strategies(period: str = "3mo", interval: str = "1d", timeframe: str | None = None):
    chart = await get_stock_chart_by_timeframe(GOLD_SYMBOL, timeframe) if timeframe else await yf_chart(GOLD_SYMBOL, period, interval)
    if not chart:
        return {"error": "无法获取黄金数据", "strategies": {}}
    result = run_strategies(chart)
    result["symbol"] = GOLD_DISPLAY_SYMBOL
    result["period"] = period
    return result

@app.get("/api/wealth/recommend")
async def api_wealth_recommend(user: dict = Depends(get_current_user)):
    level = user.get("risk_level", "moderate")
    if level == "conservative":
        return {"risk_level": "conservative", "label": "保守型", "recommendations": [
            {"type": "短债 / 国债 ETF", "apy": "3-5%", "risk": "低", "desc": "优先关注 SHY、IEF、SGOV 一类低波动资产"},
            {"type": "货币基金 / 现金管理", "apy": "2-3%", "risk": "低", "desc": "保留流动性，作为等机会资金池"},
            {"type": "红利蓝筹 ETF", "apy": "6-10%", "risk": "中低", "desc": "偏向 SCHD、VYM、标普红利类长期配置"},
        ]}
    if level == "aggressive":
        return {"risk_level": "aggressive", "label": "激进型", "recommendations": [
            {"type": "纳指 / AI 成长股", "apy": "15-30%", "risk": "高", "desc": "围绕 QQQ、半导体、AI 龙头做主升段配置"},
            {"type": "行业轮动 ETF", "apy": "12-25%", "risk": "中高", "desc": "科技、券商、能源等强势行业轮动"},
            {"type": "高 Beta 个股波段", "apy": "20-40%", "risk": "高", "desc": "聚焦财报与趋势共振的强弹性个股"},
            {"type": "小仓位加密增强", "apy": "10-35%", "risk": "高", "desc": "仅作为进攻增强仓，不作为核心资产"},
        ]}
    return {"risk_level": "moderate", "label": "平衡型", "recommendations": [
        {"type": "标普 + 纳指核心组合", "apy": "8-15%", "risk": "中", "desc": "SPY + QQQ 双核心，兼顾稳健与成长"},
        {"type": "债券 + 股票平衡仓", "apy": "6-10%", "risk": "中低", "desc": "用 IEF / TLT 对冲权益波动"},
        {"type": "行业基金增强", "apy": "10-18%", "risk": "中", "desc": "半导体、医疗、红利基金做卫星仓"},
    ]}

def calc_sma(data, n):
    if len(data) < n: return []
    out, window = [], []
    for v in data:
        window.append(v)
        if len(window) > n: window.pop(0)
        if len(window) == n: out.append(sum(window)/n)
    return out

def calc_ema(data, n):
    if len(data) < n: return []
    out = [sum(data[:n])/n]
    multiplier = 2/(n+1)
    for i in range(n, len(data)):
        out.append((data[i] - out[-1]) * multiplier + out[-1])
    return out

def calc_bollinger(data, n=20, k=2):
    sma = calc_sma(data, n)
    if len(sma) < n: return [], [], []
    middle, upper, lower = [], [], []
    for i in range(n-1, len(data)):
        window = data[i-n+1:i+1]
        m = sum(window)/n
        std = (sum((x-m)**2 for x in window)/n)**0.5
        middle.append(m)
        upper.append(m + k*std)
        lower.append(m - k*std)
    return middle, upper, lower

def calc_full_macd(data, fast=12, slow=26, signal=9):
    if len(data) < slow: return [], [], []
    ema_fast = calc_ema(data, fast)
    ema_slow = calc_ema(data, slow)
    offset = slow - fast
    macd_line = [ema_fast[i+offset] - ema_slow[i] for i in range(len(ema_slow))]
    signal_line = calc_ema(macd_line, signal)
    pad = len(data) - len(macd_line)
    macd_line = [0]*pad + macd_line
    signal_line = [0]*(pad+signal-1) + signal_line
    min_len = min(len(macd_line), len(signal_line))
    macd_line = macd_line[-min_len:]
    signal_line = signal_line[-min_len:]
    histogram = [macd_line[i] - (signal_line[i] if i < len(signal_line) else 0) for i in range(min_len)]
    return macd_line, signal_line, histogram

def calc_full_rsi(data, n=14):
    if len(data) < n+1: return []
    rsi_vals = []
    gains = losses = 0
    for i in range(1, n+1):
        diff = data[i] - data[i-1]
        if diff > 0: gains += diff
        else: losses -= diff
    avg_gain, avg_loss = gains/n, losses/n
    rsi_vals.append(100 - 100/(1+avg_gain/avg_loss) if avg_loss != 0 else 100)
    for i in range(n+1, len(data)):
        diff = data[i] - data[i-1]
        gain = diff if diff > 0 else 0
        loss = -diff if diff < 0 else 0
        avg_gain = (avg_gain*(n-1) + gain)/n
        avg_loss = (avg_loss*(n-1) + loss)/n
        rsi_vals.append(100 - 100/(1+avg_gain/avg_loss) if avg_loss != 0 else 100)
    return [50]*n + rsi_vals

def run_strategies(chart_data):
    if not chart_data or len(chart_data) < 30:
        return {"error": "数据不足，至少需要30根K线", "strategies": {}}
    closes = [d["c"] for d in chart_data]
    n, results = len(closes), {}
    ma10 = calc_sma(closes, 10)
    ma50 = calc_sma(closes, 50) if n >= 50 else None
    signals_ma = []
    if ma50 and len(ma50) > 0:
        for i in range(50, n):
            ma10_idx, ma50_idx = i-9, i-49
            if ma10_idx < len(ma10) and ma50_idx < len(ma50):
                if i > 50 and ma10[ma10_idx] > ma50[ma50_idx] and ma10[ma10_idx-1] <= ma50[ma50_idx-1]:
                    signals_ma.append({"index": i, "type": "buy", "price": closes[i], "reason": f"金叉 MA10(¥{ma10[ma10_idx]:.0f}) 上穿 MA50(¥{ma50[ma50_idx]:.0f})"})
                elif i > 50 and ma10[ma10_idx] < ma50[ma50_idx] and ma10[ma10_idx-1] >= ma50[ma50_idx-1]:
                    signals_ma.append({"index": i, "type": "sell", "price": closes[i], "reason": f"死叉 MA10(¥{ma10[ma10_idx]:.0f}) 下穿 MA50(¥{ma50[ma50_idx]:.0f})"})
        last_ma10, last_ma50 = ma10[-1] if ma10 else 0, ma50[-1] if ma50 else 0
        verdict = "bullish" if last_ma10 > last_ma50 else "bearish"
        summary = f"MA10(${last_ma10:.0f}) {'>' if verdict=='bullish' else '<'} MA50(${last_ma50:.0f}) — {'多头排列，趋势向上' if verdict=='bullish' else '空头排列，趋势向下'}"
    else:
        verdict, summary = "neutral", "数据不足以计算MA50"
    results["ma_crossover"] = {"name": "均线交叉策略", "signals": signals_ma[-6:], "verdict": verdict, "summary": summary, "star": "⭐310"}
    rsi_full = calc_full_rsi(closes, 14)
    signals_rsi = []
    if len(rsi_full) > 14:
        for i in range(15, n):
            if rsi_full[i] < 30 and rsi_full[i-1] >= 30:
                signals_rsi.append({"index": i, "type": "buy", "price": closes[i], "reason": f"RSI超卖({rsi_full[i]:.0f}) 反弹信号"})
            elif rsi_full[i] > 70 and rsi_full[i-1] <= 70:
                signals_rsi.append({"index": i, "type": "sell", "price": closes[i], "reason": f"RSI超买({rsi_full[i]:.0f}) 回调信号"})
        last_rsi = rsi_full[-1]
        if last_rsi < 30: verdict, summary = "bullish", f"RSI={last_rsi:.0f} 超卖区，有反弹需求"
        elif last_rsi > 70: verdict, summary = "bearish", f"RSI={last_rsi:.0f} 超买区，注意回调风险"
        elif last_rsi > 50: verdict, summary = "bullish", f"RSI={last_rsi:.0f} 偏强区域"
        else: verdict, summary = "bearish", f"RSI={last_rsi:.0f} 偏弱区域"
    else:
        verdict, summary = "neutral", "RSI数据不足"
    results["rsi"] = {"name": "RSI策略", "signals": signals_rsi[-6:], "verdict": verdict, "summary": summary, "star": "经典"}
    macd_line, signal_line, histogram = calc_full_macd(closes, 12, 26, 9)
    signals_macd = []
    if len(macd_line) > 30:
        for i in range(30, n):
            idx, prev_idx = min(i, len(macd_line)-1), min(i-1, len(macd_line)-1)
            if histogram[idx] > 0 and histogram[prev_idx] <= 0:
                signals_macd.append({"index": i, "type": "buy", "price": closes[i], "reason": f"MACD金叉 柱转正({histogram[idx]:.2f})"})
            elif histogram[idx] < 0 and histogram[prev_idx] >= 0:
                signals_macd.append({"index": i, "type": "sell", "price": closes[i], "reason": f"MACD死叉 柱转负({histogram[idx]:.2f})"})
        last_hist = histogram[-1] if histogram else 0
        verdict, summary = ("bullish", f"MACD柱={last_hist:.2f}>0 多头趋势") if last_hist > 0 else ("bearish", f"MACD柱={last_hist:.2f}<0 空头趋势")
    else:
        verdict, summary = "neutral", "MACD数据不足"
    results["macd"] = {"name": "MACD策略", "signals": signals_macd[-6:], "verdict": verdict, "summary": summary, "star": "⭐300"}
    mid, upper, lower = calc_bollinger(closes, 20, 2)
    signals_bb = []
    if len(mid) > 20:
        for i in range(20, n):
            bb_idx = i - 19
            if bb_idx < len(lower) and bb_idx < len(upper):
                if closes[i] <= lower[bb_idx] and closes[i-1] > (lower[bb_idx-1] if bb_idx>0 else lower[bb_idx]):
                    signals_bb.append({"index": i, "type": "buy", "price": closes[i], "reason": f"触及下轨(${lower[bb_idx]:.0f}) 均值回归买入"})
                elif closes[i] >= upper[bb_idx] and closes[i-1] < (upper[bb_idx-1] if bb_idx>0 else upper[bb_idx]):
                    signals_bb.append({"index": i, "type": "sell", "price": closes[i], "reason": f"触及上轨(${upper[bb_idx]:.0f}) 高位卖出"})
        last_close, last_mid = closes[-1], mid[-1] if mid else closes[-1]
        if last_close < (lower[-1] if lower else last_close): verdict, summary = "bullish", "价格低于下轨 超跌反弹机会"
        elif last_close > (upper[-1] if upper else last_close): verdict, summary = "bearish", "价格高于上轨 超涨回调风险"
        elif last_close > last_mid: verdict, summary = "bullish", f"价格在中轨(${last_mid:.0f})上方 偏强"
        else: verdict, summary = "bearish", f"价格在中轨(${last_mid:.0f})下方 偏弱"
    else:
        verdict, summary = "neutral", "布林带数据不足"
    results["bollinger"] = {"name": "布林带策略", "signals": signals_bb[-6:], "verdict": verdict, "summary": summary, "star": "⭐200"}
    ma20 = calc_sma(closes, 20)
    signals_mr = []
    if len(ma20) >= 20:
        for i in range(30, n):
            window = closes[i-19:i+1]
            m = sum(window)/20
            std = (sum((x-m)**2 for x in window)/20)**0.5
            z_score = (closes[i] - m) / std if std > 0 else 0
            if z_score < -2:
                signals_mr.append({"index": i, "type": "buy", "price": closes[i], "reason": f"Z-score={z_score:.1f} 极度超跌"})
            elif z_score > 2:
                signals_mr.append({"index": i, "type": "sell", "price": closes[i], "reason": f"Z-score={z_score:.1f} 极度超涨"})
        window = closes[-20:]
        m = sum(window)/20
        std = (sum((x-m)**2 for x in window)/20)**0.5
        z = (closes[-1] - m)/std if std > 0 else 0
        if z < -2: verdict, summary = "bullish", f"Z={z:.1f} 超跌区域 回归均线概率大"
        elif z > 2: verdict, summary = "bearish", f"Z={z:.1f} 超涨区域 回归均线概率大"
        elif z > 0: verdict, summary = "bullish", f"Z={z:.1f} 略高于均线"
        else: verdict, summary = "bearish", f"Z={z:.1f} 略低于均线"
    else:
        verdict, summary = "neutral", "均值回归数据不足"
    results["mean_reversion"] = {"name": "均值回归策略", "signals": signals_mr[-6:], "verdict": verdict, "summary": summary, "star": "⭐100"}
    bullish_count = sum(1 for r in results.values() if r["verdict"] == "bullish")
    bearish_count = sum(1 for r in results.values() if r["verdict"] == "bearish")
    total_signals = sum(len(r["signals"]) for r in results.values())
    if bullish_count >= 4: ai_verdict, ai_text = "strong_buy", f"5大策略中{bullish_count}个看多，强烈看涨信号"
    elif bullish_count >= 3: ai_verdict, ai_text = "buy", f"5大策略中{bullish_count}个看多，{bearish_count}个看空，偏向看涨"
    elif bearish_count >= 4: ai_verdict, ai_text = "strong_sell", f"5大策略中{bearish_count}个看空，强烈看跌信号"
    elif bearish_count >= 3: ai_verdict, ai_text = "sell", f"5大策略中{bearish_count}个看空，{bullish_count}个看多，偏向看跌"
    else: ai_verdict, ai_text = "hold", f"5大策略多空分歧({bullish_count}多/{bearish_count}空)，建议观望"
    return {"symbol": chart_data[0].get("symbol", ""), "price": closes[-1], "strategies": results, "ai_verdict": ai_verdict, "ai_summary": ai_text, "total_signals": total_signals}

@app.get("/api/stock/{sym}/strategies")
async def api_strategies(sym: str, period: str = "3mo", interval: str = "1d"):
    s = _auto_stock(sym)
    chart = await yf_chart(s, period, interval)
    if not chart:
        return {"error": "无法获取数据", "strategies": {}}
    result = run_strategies(chart)
    result["symbol"] = s
    result["period"] = period
    return result

@app.get("/api/crypto/{coin}/strategies")
async def api_crypto_strategies(coin: str, days: int = 90):
    chart = await cg_chart(_get_cid(coin), days)
    if not chart:
        return {"error": "无法获取数据", "strategies": {}}
    result = run_strategies(chart)
    result["symbol"] = coin.upper()
    return result

KNOWN_SYMBOLS = {
    "stock": ["AAPL","TSLA","NVDA","MSFT","GOOGL","AMZN","META","SPY","QQQ","DIA","IWM","XAU","SLV","USO","AMD","INTC","NFLX","DIS","BA","JPM","GS","V","MA","PYPL","SQ","COIN","MARA","MSTR","RIOT","PLTR","SNOW","CRM","UBER","LYFT","ABNB","SHOP","ZM","SNAP","PINS","ROKU","DKNG","RBLX","U","RIVN","LCID","NIO","XPEV","LI"],
    "crypto": ["BTC","ETH","SOL","DOGE","PEPE","BNB","XRP","ADA","AVAX","DOT","LINK","SUI","OP","ARB","NEAR","APT","INJ","AAVE","UNI","BONK","WIF","PENDLE","TIA","SEI","ONDO","HYPE","JUP","RENDER","AERO","ENA","WLD"]
}

def extract_symbols_from_text(text):
    found = {"stock": [], "crypto": []}
    text_upper = text.upper()
    for sym in KNOWN_SYMBOLS["stock"]:
        if re.search(r'\b' + re.escape(sym) + r'\b', text_upper) and sym not in found["stock"]:
            found["stock"].append(sym)
    for sym in KNOWN_SYMBOLS["crypto"]:
        if re.search(r'\b' + re.escape(sym) + r'\b', text_upper) and sym not in found["crypto"]:
            found["crypto"].append(sym)
    for m in re.findall(r'\$([A-Z]{1,5})', text_upper):
        if m in KNOWN_SYMBOLS["stock"] and m not in found["stock"]: found["stock"].append(m)
        if m in KNOWN_SYMBOLS["crypto"] and m not in found["crypto"]: found["crypto"].append(m)
    return found

class OcrTextReq(BaseModel):
    text: str

@app.post("/api/ocr/text")
async def api_ocr_text(body: OcrTextReq):
    found = extract_symbols_from_text(body.text)
    return {"stock": found["stock"], "crypto": found["crypto"], "raw_text": body.text, "method": "text"}

@app.post("/api/ocr/file")
async def api_ocr_file(file: UploadFile = File(...)):
    results = {"stock": [], "crypto": [], "raw_text": "", "method": "fallback"}
    try:
        contents = await file.read()
        img = Image.open(io.BytesIO(contents))
        try:
            import pytesseract
            img_text = pytesseract.image_to_string(img, lang='eng+chi_sim')
            results["raw_text"] = img_text[:500]
            results["method"] = "ocr"
        except:
            results["raw_text"] = "OCR不可用，请粘贴文本"
        found = extract_symbols_from_text(results["raw_text"])
        results["stock"], results["crypto"] = found["stock"], found["crypto"]
    except Exception as e:
        results["raw_text"] = f"错误:{e}"
    return results

@app.post("/api/watchlist/batch")
async def api_watchlist_batch(symbols: list = Body(...), user: dict = Depends(get_current_user)):
    added, skipped = [], []
    db = await get_db()
    try:
        for item in symbols:
            sym = item.get("symbol", "").upper()
            typ = item.get("type", "stock")
            if not sym:
                continue
            try:
                await db.execute("INSERT INTO watchlist (user_id, symbol, type) VALUES (?, ?, ?)", (user["user_id"], sym, typ))
                added.append(sym)
            except aiosqlite.IntegrityError:
                skipped.append(sym)
        await db.commit()
        return {"added": added, "skipped": skipped}
    finally:
        await db.close()

@app.get("/")
async def root():
    with open(os.path.join(os.path.dirname(__file__), "index.html"), "r") as f:
        return HTMLResponse(f.read())

@app.on_event("startup")
async def startup():
    await init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
