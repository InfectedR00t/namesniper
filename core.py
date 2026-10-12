"""Engine: database, Mojang API, Microsoft sign-in, scanner, scheduler and sniping."""
import asyncio
import base64
import itertools
import json
import re
import secrets
import sqlite3
import statistics
import string
import time
from collections import deque
from datetime import datetime, timezone

import aiohttp
import ntplib

from messages import t as msg

SERVICES = "https://api.minecraftservices.com"
BULK_URL = "https://api.mojang.com/profiles/minecraft"  # max 10 names per request
CHARSET = string.ascii_lowercase + string.digits + "_"
NAME_RE = re.compile(r"^[a-z0-9_]{3,16}$")

# Microsoft → Xbox Live → XSTS → Minecraft
MS_AUTH = "https://login.microsoftonline.com/consumers/oauth2/v2.0"
MS_SCOPE = "XboxLive.signin offline_access"
XBL_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MC_LOGIN = f"{SERVICES}/authentication/login_with_xbox"

NTP_SERVERS = ("time.cloudflare.com", "time.google.com", "pool.ntp.org")
PROBE_NAME = "notch"  # always taken; a claim on it is guaranteed to fail, so it is safe as a test

DEFAULTS = {
    "scan_enabled": False,
    "scan_length": 3,          # 0 = watchlist only
    "bulk_delay": 1.2,         # seconds between bulk requests
    "hold_days": 37,           # hold period between release and drop
    "auto_snipe": False,       # automatically queue a snipe for released names
    "watch_poll": 15.0,        # seconds between availability checks, per account
    "helpers_enabled": True,   # let other accounts help watch (they never claim)
    "window_before_min": 120,
    "window_after_min": 240,
    "offsets": "-50,30,120",   # ms around the exact drop time
    "watchlist": "",
    "webhook_url": "",         # Discord webhook for notifications (optional)
    "ms_client_id": "",        # client ID of your own (Mojang-approved) Azure app
    "fast_enabled": True,      # check favourites separately and often
    "fast_interval": 5.0,      # seconds between fast-lane checks
    "fast_auto": True,         # queue an exact snipe as soon as a favourite is released
    "spread_step_ms": 250,     # gap between claims when the drop time is a few seconds uncertain
    "spread_max": 12,          # max number of extra claims for that spread
    "hold_offset_s": 0.0,      # hold period correction, from calibration against NameMC
    # Discord notifications
    "discord_mention": "",     # Discord user ID (or &role ID) to ping on actionable notifications
    "dashboard_url": "http://127.0.0.1:8787",  # where namesniper is reachable with the tunnel open
    "tunnel_cmd": "",          # e.g. ssh -L 8787:127.0.0.1:8787 user@host; included in actionable notifications
    "notify_lead_min": 30,     # heads-up this many minutes before a snipe starts
    "n_result": True,          # claimed, lost, missed, error
    "n_token": True,           # renew token, link again
    "n_upcoming": True,        # heads-up before a snipe
    "n_problem": True,         # no account, clock not synchronised
    "n_fav": True,             # favourite released
    "n_released": False,       # all released names, bundled
    "n_retaken": True,         # name taken again, snipe dropped
    # Rate-limit protection. Mojang doesn't publish its limits; these are conservative estimates.
    "rl_bulk_per_10min": 540,  # bulk lookups per 10 minutes, scanner and fast lane together (per IP)
    "rl_checks_per_min": 20,   # availability checks per account per minute
    "rl_claims_per_min": 6,    # claim requests per account per minute
    "rl_cooldown_s": 60,       # pause after a 429 that has no Retry-After header
}

NOTIFY_KINDS = {"result": "n_result", "token": "n_token", "upcoming": "n_upcoming", "problem": "n_problem",
                "fav": "n_fav", "released": "n_released", "retaken": "n_retaken"}
COLORS = {"ok": 0x74C27A, "info": 0x62C8C2, "warn": 0xE5B53E, "error": 0xE0624F}

SCHEMA = """
CREATE TABLE IF NOT EXISTS names(
  name TEXT PRIMARY KEY, state TEXT, uuid TEXT,
  drop_lo REAL, drop_hi REAL, checked_at REAL);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY, label TEXT, token TEXT, exp REAL,
  has_profile INTEGER, profile_name TEXT, can_claim INTEGER DEFAULT 0,
  status TEXT DEFAULT 'unknown', checked_at REAL);
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY, name TEXT, mode TEXT, drop_at REAL,
  window_start REAL, window_end REAL, account_id INTEGER,
  status TEXT, result TEXT, created REAL);
CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY, target_id INTEGER, account_id INTEGER, idx INTEGER,
  sent REAL, ms REAL, status INTEGER, body TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, level TEXT, msg TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS notified(key TEXT PRIMARY KEY, ts REAL);
"""

MIGRATIONS = [
    ("targets", "pinned", "INTEGER"),
    ("accounts", "life", "REAL"),
    ("accounts", "locked", "INTEGER DEFAULT 0"),
    ("accounts", "refresh_token", "TEXT"),
    ("accounts", "probe", "TEXT"),
    ("names", "star", "INTEGER DEFAULT 0"),
    ("names", "rel_lo", "REAL"),     # release moment per the fast lane: between rel_lo and rel_hi
    ("names", "rel_hi", "REAL"),
    ("names", "calib", "REAL"),      # NameMC time minus our prediction, in seconds
    ("targets", "drop_end", "REAL"), # exact snipe with small uncertainty: drop between drop_at and drop_end
    ("targets", "claim_as", "TEXT"), # name with the desired capitalisation, as it is claimed
    ("accounts", "helper", "INTEGER DEFAULT 1"),  # may help watch other accounts' snipes
]


def fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def jwt_claims(token: str) -> dict:
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def jwt_exp(token: str):
    return jwt_claims(token).get("exp")


def jwt_life(token: str) -> float:
    c = jwt_claims(token)
    if c.get("exp") and c.get("iat"):
        return float(c["exp"] - c["iat"])
    return 86400.0


def ntp_query():
    """(offset, server) of the first NTP server that answers, or None."""
    c = ntplib.NTPClient()
    for host in NTP_SERVERS:
        try:
            return c.request(host, version=3, timeout=2).offset, host
        except Exception:
            continue
    return None


def need_until(t: dict) -> float:
    """Until when a token must be valid for this snipe."""
    return ((t.get("drop_end") or t["drop_at"]) + 60) if t["mode"] == "drop" else t["window_end"] + 300


def namemc(name: str) -> str:
    return f"https://namemc.com/search?q={name}"


def ago_span(sec: float) -> str:
    sec = int(abs(sec))
    h, m, s_ = sec // 3600, sec % 3600 // 60, sec % 60
    return f"{h}h {m}m" if h else f"{m}m {s_}s" if m else f"{s_}s"


def hold_secs(s: dict) -> float:
    return float(s["hold_days"]) * 86400 + float(s.get("hold_offset_s") or 0)


async def sleep_until(local_ts: float) -> None:
    """Sleep until local clock time, busy-waiting the last ~30 ms for precision."""
    while True:
        d = local_ts - time.time()
        if d <= 0:
            return
        if d > 0.03:
            await asyncio.sleep(d - 0.03)
        else:
            while time.time() < local_ts:
                pass
            return


class AuthError(Exception):
    pass


def retry_after(r) -> float | None:
    """Seconds from a Retry-After header, or None."""
    try:
        return max(1.0, float(r.headers.get("Retry-After")))
    except (TypeError, ValueError):
        return None


class Limiter:
    """Sliding-window limiter: at most n requests per `per` seconds for each key."""

    def __init__(self):
        self.hits: dict[str, deque] = {}

    def _window(self, key: str, per: float) -> tuple[deque, float]:
        q = self.hits.setdefault(key, deque())
        now = time.monotonic()
        while q and q[0] <= now - per:
            q.popleft()
        return q, now

    def used(self, key: str, per: float) -> int:
        return len(self._window(key, per)[0])

    def wait_time(self, key: str, n: int, per: float) -> float:
        q, now = self._window(key, per)
        return 0.0 if len(q) < n else q[0] + per - now

    def try_acquire(self, key: str, n: int, per: float) -> bool:
        q, now = self._window(key, per)
        if len(q) >= n:
            return False
        q.append(now)
        return True

    async def acquire(self, key: str, n: int, per: float):
        while not self.try_acquire(key, n, per):
            await asyncio.sleep(max(0.05, self.wait_time(key, n, per)))


class DB:
    def __init__(self, path: str):
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.c.row_factory = sqlite3.Row
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.executescript(SCHEMA)
        for table, col, decl in MIGRATIONS:
            if col not in {r[1] for r in self.c.execute(f"PRAGMA table_info({table})")}:
                self.c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    def q(self, sql, *a):
        return [dict(r) for r in self.c.execute(sql, a).fetchall()]

    def one(self, sql, *a):
        r = self.c.execute(sql, a).fetchone()
        return dict(r) if r else None

    def x(self, sql, *a):
        return self.c.execute(sql, a).lastrowid

    def n(self, sql, *a) -> int:
        """Execute and return the number of affected rows."""
        return self.c.execute(sql, a).rowcount


class Engine:
    def __init__(self, db_path: str = "sniper.db"):
        self.db = DB(db_path)
        self.session: aiohttp.ClientSession | None = None
        self.subs: set[asyncio.Queue] = set()
        self.ntp = 0.0
        self.ntp_info = {"ok": False, "server": None, "at": None}
        self.scan = {"running": False, "pos": 0, "total": 0, "round": 0, "wait_until": 0,
                     "started_at": None, "last_secs": None}
        self.slow = 0.0
        self.active: dict[int, asyncio.Task] = {}
        self.busy: set[int] = set()
        self.warned: set[int] = set()
        self.tasks: list[asyncio.Task] = []
        self.notified: set[tuple] = set()
        self.flows: dict[str, dict] = {}
        self.refreshing: set[int] = set()
        self.refresh_failed: set[int] = set()
        self.fast = {"running": False, "count": 0, "last": None}
        self.outbox: asyncio.Queue = asyncio.Queue()
        self.released_buf: list[tuple] = []
        self.limiter = Limiter()
        self.cool: dict[str, float] = {}  # limiter key -> paused until (after a 429)

    # ---------- lifecycle ----------
    async def start(self):
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=600),
            timeout=aiohttp.ClientTimeout(total=10),
        )
        await self.sync_ntp(quiet=True)
        self.db.x("UPDATE targets SET status='queued', account_id=NULL WHERE status='armed'")
        if self.ntp_info["ok"]:
            self.log(self.t("started", ms=self.ntp * 1000))
        else:
            self.log(self.t("started_nontp"), "warn")
        self.tasks = [
            asyncio.create_task(self.scanner()),
            asyncio.create_task(self.scheduler()),
            asyncio.create_task(self.ntp_loop()),
            asyncio.create_task(self.fast_scanner()),
            asyncio.create_task(self.sender()),
        ]

    async def stop(self):
        for t in self.tasks + list(self.active.values()):
            t.cancel()
        await self.session.close()

    def now(self) -> float:
        return time.time() + self.ntp

    # ---------- rate-limit protection ----------
    def cooling(self, key: str) -> float:
        """Seconds this key is still paused after a 429 (0 if not)."""
        return max(0.0, self.cool.get(key, 0) - time.time())

    def cool_down(self, key: str, r) -> float:
        """Pause a key after a 429, honouring Retry-After. Returns the pause in seconds."""
        wait = retry_after(r) or float(self.settings()["rl_cooldown_s"])
        self.cool[key] = max(self.cool.get(key, 0), time.time() + wait)
        return wait

    # ---------- messages and logging ----------
    def t(self, key: str, **kw) -> str:
        """Message text for a key."""
        return msg(key, **kw)

    def log(self, msg: str, level: str = "info"):
        ts = time.time()
        self.db.x("INSERT INTO events(ts,level,msg) VALUES(?,?,?)", ts, level, msg)
        ev = {"ts": ts, "level": level, "msg": msg}
        for q in list(self.subs):
            q.put_nowait(ev)
        print(f"[{fmt(ts)}] {level:5} {msg}", flush=True)

    # ---------- clock ----------
    async def sync_ntp(self, quiet: bool = False) -> dict:
        res = await asyncio.get_running_loop().run_in_executor(None, ntp_query)
        was_ok = self.ntp_info["ok"]
        if res:
            # If a later sync fails, keep the last known offset: it is usually still fine.
            self.ntp = res[0]
            self.ntp_info = {"ok": True, "server": res[1], "at": time.time()}
            if not quiet and not was_ok:
                self.log(self.t("ntp_ok", server=res[1], ms=self.ntp * 1000), "ok")
        else:
            self.ntp_info = {**self.ntp_info, "ok": False}
            if not quiet and was_ok:
                self.log(self.t("ntp_fail"), "warn")
        return self.ntp_info

    async def ntp_loop(self):
        while True:
            await asyncio.sleep(1800 if self.ntp_info["ok"] else 60)
            await self.sync_ntp()

    # ---------- settings ----------
    def settings(self) -> dict:
        s = dict(DEFAULTS)
        for r in self.db.q("SELECT key,value FROM settings"):
            s[r["key"]] = json.loads(r["value"])
        return s

    def save_settings(self, upd: dict):
        for k, v in upd.items():
            if k not in DEFAULTS:
                continue
            t = type(DEFAULTS[k])
            v = bool(v) if t is bool else t(v) if t in (int, float) else str(v)
            if k == "offsets":
                [int(x) for x in v.split(",") if x.strip()]  # validate
            if k == "ms_client_id":
                v = v.strip()
            if k == "fast_interval":
                v = max(2.0, v)
            if k in ("spread_step_ms", "spread_max"):
                v = max(1, v)
            if k == "discord_mention":
                v = v.strip().strip("<@>").replace("!", "")
                if v and not re.fullmatch(r"&?\d{15,22}", v):
                    raise ValueError(self.t("bad_mention"))
            if k in ("dashboard_url", "tunnel_cmd", "webhook_url"):
                v = v.strip()
            if k.startswith("rl_"):
                v = max(1, v)
            if k == "notify_lead_min":
                v = max(1, v)
            self.db.x("INSERT OR REPLACE INTO settings VALUES(?,?)", k, json.dumps(v))
        self.log(self.t("settings_saved"))

    # ---------- accounts ----------
    def add_account(self, label: str, token: str, locked: bool = False) -> int:
        token = token.strip().removeprefix("Bearer ").strip()
        return self.db.x(
            "INSERT INTO accounts(label,token,exp,life,locked) VALUES(?,?,?,?,?)",
            label.strip() or "account", token, jwt_exp(token), jwt_life(token), int(bool(locked)),
        )

    def set_token(self, aid: int, token: str, exp=None, life=None, refresh_token=None):
        """Store a new token. With refresh_token=None an existing link is kept."""
        token = token.strip().removeprefix("Bearer ").strip()
        exp = exp or jwt_exp(token)
        life = life or jwt_life(token)
        if refresh_token is None:
            self.db.x("UPDATE accounts SET token=?, exp=?, life=? WHERE id=?", token, exp, life, aid)
        else:
            self.db.x("UPDATE accounts SET token=?, exp=?, life=?, refresh_token=? WHERE id=?",
                      token, exp, life, refresh_token, aid)
        self.refresh_failed.discard(aid)
        self.db.x("DELETE FROM notified WHERE key LIKE 'tok-%'")

    def update_token(self, aid: int, token: str):
        self.set_token(aid, token)

    async def check_account(self, aid: int):
        # Status values (ready, cooldown, expired, unknown) are codes; the UI labels them.
        a = self.db.one("SELECT * FROM accounts WHERE id=?", aid)
        if not a:
            return
        if a["refresh_token"] and (not a["exp"] or a["exp"] < time.time() + 600):
            if await self.try_refresh(aid):
                a = self.db.one("SELECT * FROM accounts WHERE id=?", aid)
        h = auth(a["token"])
        hp, pn, can = None, None, 0
        try:
            if a["exp"] and a["exp"] < time.time():
                status = "expired"
            else:
                async with self.session.get(f"{SERVICES}/minecraft/profile", headers=h) as r:
                    if r.status == 401:
                        status = "expired"
                    elif r.status == 404:
                        status, hp, can = "ready", 0, 1
                    elif r.status == 200:
                        hp, pn = 1, (await r.json()).get("name")
                        async with self.session.get(f"{SERVICES}/minecraft/profile/namechange", headers=h) as r2:
                            d = await r2.json() if r2.status == 200 else {}
                        can = 1 if d.get("nameChangeAllowed") else 0
                        status = "ready" if can else "cooldown"
                    else:
                        status = f"HTTP {r.status}"
        except Exception as e:
            status = f"error: {type(e).__name__} {e}".strip()
        self.db.x(
            "UPDATE accounts SET has_profile=?,profile_name=?,can_claim=?,status=?,checked_at=? WHERE id=?",
            hp, pn, can, status, time.time(), aid,
        )

    def usable(self, a) -> str | None:
        """None if the account can claim right now, otherwise the reason."""
        if not a:
            return self.t("acc_gone")
        if a["id"] in self.busy:
            return self.t("acc_busy_other")
        if not a["can_claim"]:
            return self.t("acc_cant", status=a["status"])
        if a["exp"] and a["exp"] < time.time() + 300:
            return self.t("token_5min")
        if self.cooling(f"claim:{a['id']}"):
            return self.t("acc_cooling", s=self.cooling(f"claim:{a['id']}"))
        return None

    def pick_account(self):
        reserved = {r["pinned"] for r in self.db.q(
            "SELECT pinned FROM targets WHERE status='queued' AND pinned IS NOT NULL")}
        # Locked accounts are never picked automatically, only for snipes pinned to them
        for a in self.db.q("SELECT * FROM accounts WHERE can_claim=1 AND COALESCE(locked,0)=0 ORDER BY has_profile ASC, id"):
            if a["id"] not in reserved and self.usable(a) is None:
                return a
        return None

    def token_plan(self, t: dict) -> dict:
        """When must this snipe's token be renewed so it covers the whole window?"""
        start = t["window_start"]
        need = need_until(t)
        if t["pinned"]:
            accs = self.db.q("SELECT * FROM accounts WHERE id=?", t["pinned"])
        else:
            accs = self.db.q("SELECT * FROM accounts WHERE can_claim=1 AND COALESCE(locked,0)=0")
        if not accs:
            return {"ok": False, "label": None, "reason": "no_account"}
        linked = [a for a in accs if a["refresh_token"] and a["id"] not in self.refresh_failed]
        if linked:
            a = linked[0]
            return {"ok": True, "auto": True, "account_id": a["id"], "label": a["label"], "exp": a["exp"]}
        best = max(accs, key=lambda a: a["exp"] or 0)
        life = best["life"] or 86400.0
        earliest = need - life + 600
        latest = start - 600
        return {
            "ok": bool(best["exp"] and best["exp"] >= need),
            "account_id": best["id"], "label": best["label"], "exp": best["exp"],
            "earliest": earliest, "latest": latest, "need": need,
            "fits": earliest <= latest,
        }

    # ---------- notifications ----------
    def once(self, key: str) -> bool:
        """True the first time for this key (persists across restarts)."""
        return self.db.n("INSERT OR IGNORE INTO notified(key,ts) VALUES(?,?)", key, time.time()) == 1

    def build_message(self, title: str, desc: str = "", level: str = "info", action: str | None = None,
                      page: str | None = None, ping: bool = False, s: dict | None = None) -> dict:
        s = s or self.settings()
        embed = {"title": title[:256], "color": COLORS.get(level, COLORS["info"]),
                 "footer": {"text": "namesniper"}, "timestamp": datetime.now(timezone.utc).isoformat()}
        if desc:
            embed["description"] = desc[:4000]
        fields = []
        if action:
            fields.append({"name": self.t("f_what"), "value": action[:1024]})
        if action and s.get("tunnel_cmd"):
            fields.append({"name": self.t("f_tunnel"), "value": f"```{s['tunnel_cmd'][:1000]}```"})
        if fields:
            embed["fields"] = fields
        dash = (s.get("dashboard_url") or "").rstrip("/")
        if page and dash.startswith(("http://", "https://")):
            embed["url"] = f"{dash}/#{page}"
        msg = {"username": "namesniper", "embeds": [embed], "allowed_mentions": {"parse": []}}
        m = s.get("discord_mention", "")
        if ping and m:
            if m.startswith("&"):
                msg["content"], msg["allowed_mentions"] = f"<@&{m[1:]}>", {"roles": [m[1:]]}
            else:
                msg["content"], msg["allowed_mentions"] = f"<@{m}>", {"users": [m]}
        return msg

    def notify(self, kind: str, log_msg: str, level: str = "info", title: str | None = None, desc: str | None = None,
               action: str | None = None, page: str | None = None, ping: bool | None = None):
        """Log, and queue a Discord message if that kind is enabled. Never blocks."""
        self.log(log_msg, level)
        s = self.settings()
        if not s.get("webhook_url") or not s.get(NOTIFY_KINDS.get(kind, ""), True):
            return
        if ping is None:
            ping = bool(action) and level in ("warn", "error")
        self.outbox.put_nowait(self.build_message(title or log_msg, log_msg if desc is None else desc,
                                                  level, action, page, ping, s))

    async def post_webhook(self, payload: dict):
        """Send a message to Discord. Raises RuntimeError if Discord rejects it."""
        url = self.settings().get("webhook_url", "").strip()
        if not url:
            raise RuntimeError(self.t("need_webhook"))
        payload = json.loads(json.dumps(payload))
        for _ in range(4):
            async with self.session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 429:
                    d = await r.json(content_type=None) or {}
                    await asyncio.sleep(min(float(d.get("retry_after", 1)), 30))
                    continue
                if r.status == 400 and payload["embeds"][0].get("url"):
                    # Discord may reject a local link; send it as text instead
                    e = payload["embeds"][0]
                    e.setdefault("fields", []).append({"name": self.t("f_open"), "value": e.pop("url")})
                    continue
                if r.status >= 300:
                    raise RuntimeError(self.t("webhook_failed", detail=f"HTTP {r.status} {(await r.text())[:150]}"))
                return
        raise RuntimeError(self.t("webhook_failed", detail="rate limit"))

    async def sender(self):
        while True:
            payload = await self.outbox.get()
            try:
                await self.post_webhook(payload)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(self.t("notify_failed", detail=str(e) or type(e).__name__), "warn")
            await asyncio.sleep(0.5)

    async def send_test(self):
        payload = self.build_message(self.t("test_title"), self.t("test_notify"), "info",
                                     self.t("test_action"), "overview", ping=True)
        await self.post_webhook(payload)
        self.log(self.t("test_notify"))

    def upcoming_desc(self, t: dict) -> tuple[str, bool]:
        """Summary for the heads-up. Returns (text, has_problem)."""
        lines, bad = [], False
        if t["mode"] == "drop" and t.get("drop_end"):
            lines.append(self.t("d_spread", at=int(t["drop_at"]), end=int(t["drop_end"])))
        elif t["mode"] == "drop":
            lines.append(self.t("d_drop", at=int(t["drop_at"])))
        else:
            lines.append(self.t("d_watch", start=int(t["window_start"]), end=int(t["window_end"])))
        p = self.token_plan(t)
        if not p.get("label"):
            lines.append(self.t("d_noacc")); bad = True
        else:
            lines.append(self.t("d_acc" if t["pinned"] else "d_acc_auto", label=p["label"]))
            lines.append(self.t("d_tok_auto" if p.get("auto") else "d_tok_ok" if p["ok"] else "d_tok_bad"))
            bad = bad or not p["ok"]
            if not t["pinned"] and self.pick_account() is None:
                lines.append(self.t("d_noacc")); bad = True
        if t["mode"] == "drop" and not self.ntp_info["ok"]:
            lines.append(self.t("d_ntp")); bad = True
        row = self.db.one("SELECT drop_lo, drop_hi FROM names WHERE name=?", t["name"])
        if t["mode"] != "drop" and row and row["drop_lo"] and row["drop_hi"] - row["drop_lo"] > 60:
            lines.append(self.t("d_wide", u=ago_span(row["drop_hi"] - row["drop_lo"])))
        return "\n".join(lines), bad

    async def token_reminders(self):
        now = self.now()
        s = self.settings()
        lead = float(s["notify_lead_min"]) * 60
        for t in self.db.q("SELECT * FROM targets WHERE status='queued'"):
            p = self.token_plan(t)
            if not p["ok"] and p.get("label"):
                if now >= p["earliest"] and self.once(f"tok-open:{t['id']}"):
                    self.notify("token", self.t("renew_now", label=p["label"], name=t["name"],
                                                latest=fmt(p["latest"]), start=fmt(t["window_start"])), "warn",
                                title=self.t("ti_renew", label=p["label"]),
                                desc=self.t("d_renew", label=p["label"], name=t["name"], start=int(t["window_start"])),
                                action=self.t("a_renew", label=p["label"], latest=int(p["latest"])), page="accounts")
                if now >= p["latest"] - 3600 and self.once(f"tok-urgent:{t['id']}"):
                    self.notify("token", self.t("renew_urgent", label=p["label"], name=t["name"],
                                                start=fmt(t["window_start"])), "error",
                                title=self.t("ti_urgent", label=p["label"]),
                                desc=self.t("d_renew", label=p["label"], name=t["name"], start=int(t["window_start"])),
                                action=self.t("a_renew", label=p["label"], latest=int(p["latest"])), page="accounts")
            # heads-up
            start = t["drop_at"] if t["mode"] == "drop" else t["window_start"]
            if 0 < start - now <= lead and self.once(f"up:{t['id']}"):
                desc, bad = self.upcoming_desc(t)
                mins = max(1, round((start - now) / 60))
                row = self.db.one("SELECT drop_lo, drop_hi FROM names WHERE name=?", t["name"])
                wide = t["mode"] != "drop" and row and row["drop_lo"] and row["drop_hi"] - row["drop_lo"] > 60
                action = self.t("a_up_bad") if bad else self.t("a_up_wide", url=namemc(t["name"])) if wide else self.t("a_up_ok")
                self.notify("upcoming", self.t("ti_upcoming", name=t["name"], mins=mins), "warn" if bad else "info",
                            desc=desc, action=action, page="snipes", ping=True)
            # clock for exact snipes
            if t["mode"] == "drop" and not self.ntp_info["ok"] and t["drop_at"] - now < 2 * 3600 \
                    and self.once(f"ntp:{t['id']}"):
                self.notify("problem", self.t("ntp_fail"), "error", title=self.t("ti_ntp"),
                            desc=self.t("d_ntp_long", name=t["name"], at=int(t["drop_at"])),
                            action=self.t("a_ntp"), page="overview")

    def flush_released(self):
        """Report released names bundled, so a full scan doesn't flood you."""
        if not self.released_buf:
            return
        buf, self.released_buf = self.released_buf, []
        lines = [self.t("d_rel_line", name=n, lo=int(lo)) for n, lo, hi in buf[:20]]
        if len(buf) > 20:
            lines.append(self.t("d_rel_more", n=len(buf) - 20))
        title = self.t("ti_released1", name=buf[0][0]) if len(buf) == 1 else self.t("ti_released", n=len(buf))
        s = self.settings()
        if s.get("webhook_url") and s.get("n_released"):
            self.outbox.put_nowait(self.build_message(title, "\n".join(lines), "info",
                                                      self.t("a_released"), "names", False, s))

    def set_locked(self, aid: int, locked: bool):
        a = self.db.one("SELECT label FROM accounts WHERE id=?", aid)
        if not a:
            raise ValueError(self.t("acc_missing"))
        self.db.x("UPDATE accounts SET locked=? WHERE id=?", int(bool(locked)), aid)
        self.log(self.t("lock_on" if locked else "lock_off", label=a["label"]))

    def set_helper(self, aid: int, on: bool):
        a = self.db.one("SELECT label FROM accounts WHERE id=?", aid)
        if not a:
            raise ValueError(self.t("acc_missing"))
        self.db.x("UPDATE accounts SET helper=? WHERE id=?", int(bool(on)), aid)
        self.log(self.t("helper_on_acc" if on else "helper_off_acc", label=a["label"]))

    def check_pin(self, account_id):
        if account_id in (None, "", 0):
            return None
        a = self.db.one("SELECT id FROM accounts WHERE id=?", int(account_id))
        if not a:
            raise ValueError(self.t("pin_missing"))
        return a["id"]

    def set_target_account(self, tid: int, account_id):
        t = self.db.one("SELECT * FROM targets WHERE id=?", tid)
        if not t or t["status"] != "queued":
            raise ValueError(self.t("pin_only_queued"))
        pin = self.check_pin(account_id)
        self.db.x("UPDATE targets SET pinned=? WHERE id=?", pin, tid)
        self.warned.discard(tid)
        label = self.db.one("SELECT label FROM accounts WHERE id=?", pin)["label"] if pin else self.t("auto")
        self.log(self.t("pin_set", name=t["name"], label=label))

    # ---------- Microsoft sign-in ----------
    def client_id(self) -> str:
        cid = self.settings().get("ms_client_id", "").strip()
        if not cid:
            raise AuthError(self.t("no_client_id"))
        return cid

    async def ms_post(self, path: str, data: dict) -> tuple[int, dict]:
        async with self.session.post(f"{MS_AUTH}/{path}", data=data) as r:
            try:
                return r.status, await r.json(content_type=None)
            except Exception:
                return r.status, {}

    async def mc_from_ms(self, ms_access: str) -> tuple[str, float, float]:
        """Microsoft access token → Minecraft token. Returns (token, exp, lifetime)."""
        hdr = {"Accept": "application/json"}
        async with self.session.post(XBL_URL, headers=hdr, json={
            "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": f"d={ms_access}"},
            "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT",
        }) as r:
            if r.status != 200:
                raise AuthError(self.t("xbl_fail", status=r.status))
            d = await r.json(content_type=None)
            xbl, uhs = d["Token"], d["DisplayClaims"]["xui"][0]["uhs"]
        async with self.session.post(XSTS_URL, headers=hdr, json={
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl]},
            "RelyingParty": "rp://api.minecraftservices.com/", "TokenType": "JWT",
        }) as r:
            if r.status == 401:
                x = (await r.json(content_type=None) or {}).get("XErr")
                key = {2148916233: "xsts_noxbox", 2148916238: "xsts_child"}.get(x, "xsts_fail")
                raise AuthError(self.t(key, code=x))
            if r.status != 200:
                raise AuthError(self.t("xsts_fail", code=f"HTTP {r.status}"))
            xsts = (await r.json(content_type=None))["Token"]
        async with self.session.post(MC_LOGIN, headers=hdr, json={"identityToken": f"XBL3.0 x={uhs};{xsts}"}) as r:
            if r.status == 403:
                raise AuthError(self.t("mc_forbidden"))
            if r.status != 200:
                raise AuthError(self.t("mc_fail", status=r.status))
            d = await r.json(content_type=None)
        life = float(d.get("expires_in") or 86400)
        token = d["access_token"]
        return token, jwt_exp(token) or time.time() + life, life

    def flow_view(self, f: dict) -> dict:
        return {k: f[k] for k in ("id", "status", "code", "url", "expires", "msg", "account_id")}

    async def msa_start(self, label: str = "", locked: bool = False, aid: int | None = None) -> dict:
        """Start the device-code sign-in. The user enters the code at microsoft.com/link."""
        cid = self.client_id()
        if aid is not None and not self.db.one("SELECT id FROM accounts WHERE id=?", aid):
            raise ValueError(self.t("acc_missing"))
        st, d = await self.ms_post("devicecode", {"client_id": cid, "scope": MS_SCOPE})
        if st != 200:
            raise AuthError(self.t("ms_fail", detail=(d.get("error_description") or f"HTTP {st}").split("\r\n")[0][:200]))
        now = time.time()
        for k in [k for k, f in self.flows.items() if f["expires"] < now - 3600]:
            del self.flows[k]
        f = {"id": secrets.token_urlsafe(8), "status": "pending", "code": d["user_code"],
             "url": d.get("verification_uri", "https://www.microsoft.com/link"),
             "expires": now + float(d.get("expires_in", 900)), "msg": None, "account_id": aid}
        self.flows[f["id"]] = f
        f["task"] = asyncio.create_task(
            self._msa_poll(f, d["device_code"], int(d.get("interval", 5)), cid, label, locked, aid))
        return self.flow_view(f)

    def msa_flow(self, fid: str) -> dict:
        f = self.flows.get(fid)
        if not f:
            raise ValueError(self.t("flow_missing"))
        return self.flow_view(f)

    def msa_cancel(self, fid: str):
        f = self.flows.pop(fid, None)
        if f and f["status"] == "pending":
            f["task"].cancel()

    async def _msa_poll(self, f, device_code, interval, cid, label, locked, aid):
        try:
            d = None
            while time.time() < f["expires"]:
                await asyncio.sleep(interval)
                st, d = await self.ms_post("token", {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": cid, "device_code": device_code})
                if st == 200:
                    break
                err = d.get("error")
                if err == "authorization_pending":
                    continue
                if err == "slow_down":
                    interval += 5
                    continue
                if err == "expired_token":
                    raise AuthError(self.t("code_expired"))
                raise AuthError(self.t("ms_fail", detail=(d.get("error_description") or err or f"HTTP {st}").split("\r\n")[0][:200]))
            else:
                raise AuthError(self.t("code_expired"))
            token, exp, life = await self.mc_from_ms(d["access_token"])
            if aid is None:
                aid = self.add_account(label, token, locked)
            self.set_token(aid, token, exp, life, d.get("refresh_token") or "")
            await self.check_account(aid)
            acc = self.db.one("SELECT label FROM accounts WHERE id=?", aid)
            f.update(status="done", account_id=aid)
            self.log(self.t("msa_linked", label=acc["label"]), "ok")
        except asyncio.CancelledError:
            f["status"] = "cancelled"
        except Exception as e:
            f.update(status="error", msg=str(e) if isinstance(e, AuthError) else f"{type(e).__name__}: {e}")
            self.log(f["msg"], "warn")

    async def refresh_account(self, aid: int):
        """New Minecraft token via the stored Microsoft refresh token. Raises AuthError on failure."""
        a = self.db.one("SELECT * FROM accounts WHERE id=?", aid)
        if not a:
            raise ValueError(self.t("acc_missing"))
        if not a["refresh_token"]:
            raise AuthError(self.t("refresh_none"))
        cid = self.client_id()
        st, d = await self.ms_post("token", {"grant_type": "refresh_token", "client_id": cid,
                                             "refresh_token": a["refresh_token"], "scope": MS_SCOPE})
        if st != 200:
            raise AuthError(self.t("ms_fail", detail=(d.get("error_description") or d.get("error") or f"HTTP {st}").split("\r\n")[0][:200]))
        token, exp, life = await self.mc_from_ms(d["access_token"])
        # Microsoft rotates refresh tokens: always store the new one
        self.set_token(aid, token, exp, life, d.get("refresh_token") or a["refresh_token"])
        self.log(self.t("token_refreshed", label=a["label"], exp=fmt(exp)), "ok")

    async def try_refresh(self, aid: int) -> bool:
        """Renew without raising. Reports a failure once per account."""
        if aid in self.refreshing:
            return False
        self.refreshing.add(aid)
        try:
            await self.refresh_account(aid)
            return True
        except Exception as e:
            if aid not in self.refresh_failed:
                self.refresh_failed.add(aid)
                a = self.db.one("SELECT label FROM accounts WHERE id=?", aid)
                lbl = a["label"] if a else aid
                self.notify("token", self.t("refresh_fail", label=lbl, e=str(e).rstrip(".")), "error",
                            title=self.t("ti_relink", label=lbl), desc=str(e),
                            action=self.t("a_relink", label=lbl), page="accounts")
            return False
        finally:
            self.refreshing.discard(aid)

    async def auto_refresh(self):
        """Renew linked accounts in time so the token covers upcoming windows."""
        now = time.time()
        queued = self.db.q("SELECT * FROM targets WHERE status IN ('queued','armed')")
        for a in self.db.q("SELECT * FROM accounts WHERE refresh_token IS NOT NULL AND refresh_token != ''"):
            if a["id"] in self.refresh_failed:
                continue
            need = now + 3 * 3600
            for t in queued:
                mine = (t["account_id"] == a["id"]) if t["status"] == "armed" else \
                    (t["pinned"] == a["id"] or (not t["pinned"] and not a["locked"]))
                if mine and t["window_start"] < now + 3600:
                    need = max(need, need_until(t))
            issued = (a["exp"] or 0) - (a["life"] or 86400)
            # At most once per 30 min: a window longer than the token life is covered in parts
            if (not a["exp"] or a["exp"] < need) and issued < now - 1800:
                await self.try_refresh(a["id"])

    # ---------- test run ----------
    async def probe(self, aid: int) -> dict:
        """Test the full claim route on a name that is guaranteed taken. Never claims anything."""
        a = self.db.one("SELECT * FROM accounts WHERE id=?", aid)
        if not a:
            raise ValueError(self.t("acc_missing"))
        if aid in self.busy:
            raise ValueError(self.t("acc_busy"))
        if a["refresh_token"] and (not a["exp"] or a["exp"] < time.time() + 300):
            await self.try_refresh(aid)
            a = self.db.one("SELECT * FROM accounts WHERE id=?", aid)
        key, limit = f"claim:{aid}", int(self.settings()["rl_claims_per_min"])
        if self.cooling(key) or self.limiter.used(key, 60) + 3 > limit:
            raise ValueError(self.t("probe_throttled"))
        st = await self.availability(PROBE_NAME, a["token"], aid)
        if st == "AVAILABLE":
            raise ValueError(self.t("probe_unsafe"))
        if st in ("RATE_LIMITED", "THROTTLED"):
            raise ValueError(self.t("probe_throttled"))
        await self.warm(1, a["token"])
        results = []
        for _ in range(3):
            if not self.limiter.try_acquire(key, limit, 60):
                break
            t0 = time.perf_counter()
            if a["has_profile"]:
                req = self.session.put(f"{SERVICES}/minecraft/profile/name/{PROBE_NAME}",
                                       headers={**auth(a["token"]), "Content-Type": "application/json"})
            else:
                req = self.session.post(f"{SERVICES}/minecraft/profile", headers=auth(a["token"]),
                                        json={"profileName": PROBE_NAME})
            try:
                async with req as r:
                    body = (await r.text())[:160]
                    if r.status == 429:
                        self.cool_down(key, r)
                    results.append((r.status, (time.perf_counter() - t0) * 1000, body))
            except Exception as e:
                results.append((0, (time.perf_counter() - t0) * 1000, f"{type(e).__name__} {e}"[:160]))
            if self.cooling(key):
                break
            await asyncio.sleep(0.3)
        codes = [r[0] for r in results]
        ms = [r[1] for r in results if r[0]]
        # 400/403 means: token accepted and the route works, only the name was (rightly) refused
        p = {"at": time.time(), "ok": all(c in (400, 403) for c in codes), "status": codes[0],
             "codes": codes, "ms_min": min(ms) if ms else None,
             "ms_med": statistics.median(ms) if ms else None, "body": results[0][2], "check": st}
        self.db.x("UPDATE accounts SET probe=? WHERE id=?", json.dumps(p), aid)
        self.log(self.t("probe_done", label=a["label"], status="/".join(map(str, codes)), ms=p["ms_min"] or 0),
                 "ok" if p["ok"] else "warn")
        return p

    # ---------- Mojang API ----------
    async def bulk(self, chunk: list[str]):
        for attempt in range(5):
            # Scanner and fast lane share one budget, since Mojang limits per IP
            await self.limiter.acquire("bulk", int(self.settings()["rl_bulk_per_10min"]), 600)
            try:
                async with self.session.post(BULK_URL, json=chunk) as r:
                    if r.status == 429:
                        wait = retry_after(r) or 30 * (attempt + 1)
                        self.slow = min(self.slow + 0.5, 5.0)
                        self.log(self.t("bulk_rl", wait=wait, slow=self.slow), "warn")
                        self.scan["wait_until"] = time.time() + wait
                        await asyncio.sleep(wait)
                        self.scan["wait_until"] = 0
                        continue
                    if r.status != 200:
                        self.log(self.t("bulk_http", status=r.status), "warn")
                        await asyncio.sleep(10)
                        continue
                    return {p["name"].lower(): p["id"] for p in await r.json()}
            except Exception as e:
                self.log(self.t("bulk_err", detail=f"{type(e).__name__} {e}".strip()), "warn")
                await asyncio.sleep(10)
        return None

    async def availability(self, name: str, token: str, aid: int | None = None) -> str:
        """Availability check, within this account's check budget.
        THROTTLED: our own limiter held it back. RATE_LIMITED: Mojang returned 429 (or we're still pausing)."""
        key = f"chk:{aid if aid is not None else token[-16:]}"
        if self.cooling(key):
            return "RATE_LIMITED"
        if not self.limiter.try_acquire(key, int(self.settings()["rl_checks_per_min"]), 60):
            return "THROTTLED"
        url = f"{SERVICES}/minecraft/profile/name/{name}/available"
        async with self.session.get(url, headers=auth(token)) as r:
            if r.status == 429:
                self.cool_down(key, r)
                return "RATE_LIMITED"
            if r.status == 401:
                return "UNAUTHORIZED"
            if r.status != 200:
                return f"HTTP {r.status}"
            return (await r.json()).get("status", "?")

    async def check_name(self, name: str) -> str:
        acc = self.db.one("SELECT * FROM accounts WHERE status IN ('ready','cooldown') LIMIT 1")
        if acc:
            return await self.availability(name, acc["token"], acc["id"])
        found = await self.bulk([name])
        if found is None:
            return "UNKNOWN"
        return "DUPLICATE" if name in found else "NOT_IN_USE"

    async def warm(self, n: int, token: str):
        async def ping():
            async with self.session.get(f"{SERVICES}/minecraft/profile", headers=auth(token)) as r:
                await r.read()
        await asyncio.gather(*(ping() for _ in range(n)), return_exceptions=True)

    async def claim(self, name: str, acc: dict, idx: int, tid: int | None = None) -> bool:
        key = f"claim:{acc['id']}"
        if self.cooling(key):
            self.log(self.t("claim_cool", name=name, i=idx, s=self.cooling(key)), "warn")
            return False
        if not self.limiter.try_acquire(key, int(self.settings()["rl_claims_per_min"]), 60):
            self.log(self.t("claim_throttled", name=name, i=idx), "warn")
            return False
        h = auth(acc["token"])
        sent = self.now()
        t0 = time.perf_counter()
        if acc["has_profile"]:
            # Without an explicit Content-Type aiohttp sends application/octet-stream, which Mojang rejects (415)
            req = self.session.put(f"{SERVICES}/minecraft/profile/name/{name}", headers={**h, "Content-Type": "application/json"})
        else:
            req = self.session.post(f"{SERVICES}/minecraft/profile", headers=h, json={"profileName": name})
        status, body = 0, ""
        try:
            async with req as r:
                status, body = r.status, (await r.text())[:120]
                ms = (time.perf_counter() - t0) * 1000
                if r.status == 429:
                    self.log(self.t("claim_429", label=acc["label"], s=self.cool_down(key, r)), "warn")
                self.log(self.t("claim_try", name=name, i=idx, status=r.status, ms=ms, body=body),
                         "ok" if r.status == 200 else "info")
                return r.status == 200
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000
            body = f"{type(e).__name__} {e}"[:120]
            self.log(self.t("claim_err", name=name, i=idx, e=e), "error")
            return False
        finally:
            if tid is not None:
                self.db.x("INSERT INTO attempts(target_id,account_id,idx,sent,ms,status,body) VALUES(?,?,?,?,?,?,?)",
                          tid, acc["id"], idx, sent, ms, status, body)

    # ---------- scanner ----------
    def scan_list(self, s: dict) -> list[str]:
        n = int(s["scan_length"])
        names = ["".join(p) for p in itertools.product(CHARSET, repeat=n)] if n == 3 else []
        extra = [w.strip().lower() for w in s["watchlist"].replace("\n", ",").split(",")]
        extra = [w for w in extra if NAME_RE.match(w)]
        return list(dict.fromkeys(names + extra))

    def mark_released(self, n: str, rel_lo: float, rel_hi: float, s: dict, precise: bool):
        """Name was released between rel_lo and rel_hi. The drop follows after the hold period."""
        hold = hold_secs(s)
        lo, hi = rel_lo + hold, rel_hi + hold
        self.db.x("UPDATE names SET state='released',drop_lo=?,drop_hi=?,checked_at=?,rel_lo=?,rel_hi=?,calib=NULL WHERE name=?",
                  lo, hi, rel_hi, rel_lo if precise else None, rel_hi if precise else None, n)
        star = (self.db.one("SELECT star FROM names WHERE name=?", n) or {}).get("star")
        if precise:
            log_msg = self.t("fast_released", name=n, lo=fmt(lo), hi=fmt(hi), u=hi - lo)
        else:
            log_msg = self.t("released", name=n, lo=fmt(lo), hi=fmt(hi))
        made = None
        try:
            if precise and s["fast_auto"]:
                # If the uncertainty fits within the spread, an exact snipe; otherwise watch
                if hi - lo <= int(s["spread_step_ms"]) * int(s["spread_max"]) / 1000:
                    self.add_target(n, "drop", drop_at=lo, drop_end=hi); made = "exact"
                else:
                    self.add_target(n, "watch", lo=lo, hi=hi); made = "watch"
            elif s["auto_snipe"]:
                self.add_target(n, "watch", lo=lo, hi=hi); made = "watch"
        except ValueError as e:
            self.log(f"{n}: {e}", "warn")
        if star:
            desc = self.t("d_fav", rlo=int(rel_lo), rhi=int(rel_hi), lo=int(lo),
                          u=ago_span(hi - lo)) if precise else self.t("d_fav_slow", lo=int(lo), hi=int(hi))
            desc += "\n" + self.t({"exact": "d_fav_exact", "watch": "d_fav_watch"}.get(made, "d_fav_none"))
            act = self.t("a_fav" if made else "a_fav_none", url=namemc(n))
            self.notify("fav", log_msg, "ok", title=self.t("ti_fav", name=n), desc=desc, action=act,
                        page="snipes" if made else "names", ping=True)
        else:
            self.log(log_msg, "ok")
            self.released_buf.append((n, lo, hi))

    def process_chunk(self, chunk: list[str], found: dict, s: dict, fast: bool = False):
        now = self.now()
        for n in chunk:
            row = self.db.one("SELECT * FROM names WHERE name=?", n)
            if n in found and row and row["state"] == "released" and row["uuid"] is None:
                continue  # imported from NameMC: trust that time, don't overwrite
            if (not fast and s["fast_enabled"] and n not in found and row
                    and row["star"] and row["state"] == "taken"):
                continue  # favourite: the fast lane determines the release moment more precisely
            if n in found:
                if row and row["state"] == "released":
                    why = self.t("retaken_owner" if row["uuid"] == found[n] else "retaken_other")
                    had = self.db.q("SELECT id FROM targets WHERE name=? AND status IN ('queued','armed')", n)
                    if had or row["star"]:
                        self.notify("retaken", self.t("retaken", name=n, why=why), "warn",
                                    title=self.t("ti_retaken", name=n), desc=self.t("d_retaken", name=n, why=why),
                                    page="snipes", ping=False)
                    else:
                        self.log(self.t("retaken", name=n, why=why), "warn")
                    for t in had:
                        if t["id"] in self.active:
                            self.active[t["id"]].cancel()
                        else:
                            self.set_target(t["id"], "cancelled", self.t("res_retaken"))
                self.db.x(
                    "INSERT INTO names(name,state,uuid,checked_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET state='taken',uuid=excluded.uuid,"
                    "drop_lo=NULL,drop_hi=NULL,checked_at=excluded.checked_at",
                    n, "taken", found[n], now,
                )
            elif row is None:
                self.db.x("INSERT INTO names(name,state,checked_at) VALUES(?,?,?)", n, "free", now)
            elif row["state"] == "taken":
                self.mark_released(n, row["checked_at"], now, s, precise=fast)
            else:
                self.db.x("UPDATE names SET checked_at=? WHERE name=?", now, n)

    async def scanner(self):
        while True:
            s = self.settings()
            if not s["scan_enabled"]:
                self.scan["running"] = False
                await asyncio.sleep(3)
                continue
            names = self.scan_list(s)
            if not names:
                await asyncio.sleep(10)
                continue
            self.scan.update(running=True, pos=0, total=len(names), started_at=time.time())
            self.log(self.t("scan_start", n=self.scan["round"] + 1, count=len(names)))
            for i in range(0, len(names), 10):
                s = self.settings()
                if not s["scan_enabled"]:
                    break
                chunk = names[i:i + 10]
                try:
                    found = await self.bulk(chunk)
                    if found is not None:
                        self.process_chunk(chunk, found, s)
                        self.slow = max(0.0, self.slow - 0.01)
                    else:
                        self.log(self.t("chunk_skip", name=chunk[0]), "warn")
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.log(self.t("scan_err", name=chunk[0], detail=f"{type(e).__name__} {e}"), "error")
                self.scan["pos"] = i + len(chunk)
                await asyncio.sleep(float(s["bulk_delay"]) + self.slow)
            else:
                self.scan["round"] += 1
                self.scan["last_secs"] = time.time() - self.scan["started_at"]
                self.log(self.t("scan_done", n=self.scan["round"]))

    async def fast_scanner(self):
        """Fast lane: check taken favourites every few seconds."""
        while True:
            s = self.settings()
            names = [r["name"] for r in self.db.q("SELECT name FROM names WHERE star=1 AND state='taken' ORDER BY name")] \
                if s["fast_enabled"] else []
            self.fast.update(running=bool(names), count=len(names))
            if not names:
                await asyncio.sleep(3)
                continue
            for i in range(0, len(names), 10):
                chunk = names[i:i + 10]
                try:
                    found = await self.bulk(chunk)
                    if found is not None:
                        self.process_chunk(chunk, found, self.settings(), fast=True)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.log(self.t("scan_err", name=chunk[0], detail=f"{type(e).__name__} {e}"), "error")
                await asyncio.sleep(0.3)
            self.fast["last"] = time.time()
            await asyncio.sleep(float(s["fast_interval"]))

    # ---------- calibration ----------
    def calibration(self) -> dict:
        d = [r["calib"] for r in self.db.q("SELECT calib FROM names WHERE calib IS NOT NULL")]
        if not d:
            return {"n": 0}
        return {"n": len(d), "avg": statistics.mean(d), "min": min(d), "max": max(d)}

    def apply_calibration(self) -> float:
        c = self.calibration()
        if not c["n"]:
            raise ValueError(self.t("calib_none"))
        s = self.settings()
        new = float(s.get("hold_offset_s") or 0) + c["avg"]
        self.db.x("INSERT OR REPLACE INTO settings VALUES(?,?)", "hold_offset_s", json.dumps(round(new, 3)))
        self.db.x("UPDATE names SET calib=NULL")
        self.log(self.t("calib_applied", d=c["avg"], total=new), "ok")
        return new

    # ---------- names ----------
    def names(self, state: str = "", q: str = "", limit: int = 100, offset: int = 0, kind: str = "") -> dict:
        where, args = [], []
        if state in ("taken", "free", "released"):
            where.append("state=?"); args.append(state)
        if q:
            where.append("name LIKE ?"); args.append(q.lower().replace("*", "%") + ("" if "*" in q else "%"))
        if kind == "letters":
            where.append("name NOT GLOB '*[^a-z]*'")
        elif kind == "no_underscore":
            where.append("name NOT GLOB '*_*'")
        elif kind == "starred":
            where.append("star=1")
        w = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.db.one(f"SELECT COUNT(*) c FROM names {w}", *args)["c"]
        order = "drop_lo" if state == "released" else "name"
        rows = self.db.q(
            f"SELECT name,state,uuid,drop_lo,drop_hi,checked_at,star FROM names {w} ORDER BY star DESC, {order} LIMIT ? OFFSET ?",
            *args, max(1, min(limit, 500)), max(0, offset),
        )
        return {"total": total, "rows": rows}

    def set_star(self, name: str, star: bool):
        if not self.db.n("UPDATE names SET star=? WHERE name=?", int(bool(star)), name):
            raise ValueError(self.t("name_missing"))

    # ---------- targets ----------
    def casing(self, name: str, claim_as) -> str | None:
        """Validate the desired capitalisation: same characters as the name, different case only."""
        claim_as = (claim_as or "").strip()
        if not claim_as or claim_as == name:
            return None
        if claim_as.lower() != name:
            raise ValueError(self.t("bad_casing", name=name))
        return claim_as

    def add_target(self, name, mode, drop_at=None, lo=None, hi=None, hours=24.0, account_id=None, drop_end=None,
                   claim_as=None):
        raw = name.strip()
        name = raw.lower()
        if not NAME_RE.match(name):
            raise ValueError(self.t("bad_name"))
        claim_as = self.casing(name, claim_as)
        if self.db.one("SELECT id FROM targets WHERE name=? AND status IN ('queued','armed')", name):
            raise ValueError(self.t("dup_target", name=name))
        pin = self.check_pin(account_id)
        s = self.settings()
        now = self.now()
        if mode == "drop":
            if not drop_at or drop_at < now:
                raise ValueError(self.t("drop_past"))
            if drop_end is not None and drop_end <= drop_at:
                drop_end = None
            ws, we = drop_at - 120, (drop_end or drop_at) + 5
        elif lo is not None:
            ws = lo - float(s["window_before_min"]) * 60
            we = hi + float(s["window_after_min"]) * 60
        else:
            ws, we = now, now + float(hours) * 3600
        tid = self.db.x(
            "INSERT INTO targets(name,mode,drop_at,drop_end,window_start,window_end,status,created,pinned,claim_as) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            name, mode, drop_at, drop_end if mode == "drop" else None, ws, we, "queued", time.time(), pin, claim_as,
        )
        if mode == "drop" and drop_end:
            self.log(self.t("added_spread", name=name, at=fmt(drop_at), end=fmt(drop_end)))
        elif mode == "drop":
            self.log(self.t("added_exact", name=name, at=fmt(drop_at)))
        else:
            self.log(self.t("added_watch", name=name, start=fmt(ws), end=fmt(we)))
        return tid

    def import_drops(self, items: list[dict]) -> dict:
        """items: [{name, drop_at (epoch), unc (seconds)}] from a NameMC list."""
        added, skipped = [], []
        for it in items:
            name = str(it.get("name", "")).strip().lower()
            try:
                t, unc = float(it["drop_at"]), max(0.0, float(it.get("unc", 0)))
                if not NAME_RE.match(name):
                    raise ValueError(self.t("bad_name_short"))
                lo, hi = t - unc, t + unc
                row = self.db.one("SELECT * FROM names WHERE name=?", name)
                calib = None
                if row and row["rel_lo"] is not None and unc <= 1:
                    # Own measurement via the fast lane: compare with the NameMC time
                    pred = (row["rel_lo"] + row["rel_hi"]) / 2 + hold_secs(self.settings())
                    calib = t - pred
                    self.log(self.t("calib_log", name=name, d=calib, u=(row["rel_hi"] - row["rel_lo"]) / 2))
                # A queued snipe on this name is replaced; pinned account and capitalisation carry over
                keep = {"account_id": None, "claim_as": None}
                for old in self.db.q("SELECT * FROM targets WHERE name=? AND status='queued'", name):
                    keep = {"account_id": old["pinned"], "claim_as": old["claim_as"]}
                    self.set_target(old["id"], "cancelled", self.t("import_replaced"))
                self.db.x(
                    "INSERT INTO names(name,state,drop_lo,drop_hi,checked_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(name) DO UPDATE SET state='released',drop_lo=excluded.drop_lo,"
                    "drop_hi=excluded.drop_hi",
                    name, "released", lo, hi, self.now(),
                )
                if calib is not None:
                    self.db.x("UPDATE names SET calib=? WHERE name=?", calib, name)
                if unc <= 1:
                    self.add_target(name, "drop", drop_at=t, **keep)
                else:
                    self.add_target(name, "watch", lo=lo, hi=hi, **keep)
                added.append(name)
            except (ValueError, KeyError, TypeError) as e:
                skipped.append(f"{name or '?'}: {e}")
        self.log(self.t("import_done", added=len(added), skipped=len(skipped)))
        return {"added": added, "skipped": skipped}

    def target_from_drop(self, name: str, account_id=None, claim_as=None):
        row = self.db.one("SELECT * FROM names WHERE name=? AND state='released'", name.lower())
        if not row:
            raise ValueError(self.t("no_drop"))
        return self.add_target(name, "watch", lo=row["drop_lo"], hi=row["drop_hi"], account_id=account_id,
                               claim_as=claim_as)

    def set_target_casing(self, tid: int, claim_as):
        t = self.db.one("SELECT * FROM targets WHERE id=?", tid)
        if not t or t["status"] != "queued":
            raise ValueError(self.t("casing_only_queued"))
        c = self.casing(t["name"], claim_as)
        self.db.x("UPDATE targets SET claim_as=? WHERE id=?", c, tid)
        self.log(self.t("casing_set", name=t["name"], as_=c or t["name"]))

    def set_target(self, tid, status, result=None):
        self.db.x("UPDATE targets SET status=?, result=? WHERE id=?", status, result, tid)

    def cancel_target(self, tid: int):
        task = self.active.get(tid)
        if task:
            task.cancel()
        else:
            self.set_target(tid, "cancelled", self.t("res_cancelled"))

    def send_points(self, t) -> list[float]:
        """Send times in seconds relative to drop_at. With an uncertain window, spread until drop_end."""
        s = self.settings()
        offs = sorted(int(x) for x in str(s["offsets"]).split(",") if x.strip())
        pts = [o / 1000 for o in offs]
        span = (t.get("drop_end") or t["drop_at"]) - t["drop_at"]
        if span > 0:
            step, extra, k = int(s["spread_step_ms"]) / 1000, 0, int(s["spread_step_ms"]) / 1000
            while k < span and extra < int(s["spread_max"]):
                pts.append(k)
                k += step
                extra += 1
            pts += [span + o / 1000 for o in offs if o >= 0]
        return sorted({round(p, 3) for p in pts})

    async def run_drop(self, t, acc) -> bool:
        pts = self.send_points(t)
        local = t["drop_at"] - self.ntp
        self.log(self.t("armed_drop", name=t["name"], label=acc["label"], at=fmt(t["drop_at"])))
        await sleep_until(local + pts[0] - 5)
        acc = self.db.one("SELECT * FROM accounts WHERE id=?", acc["id"]) or acc
        await self.warm(min(len(pts), 6), acc["token"])
        # Never fire more claims than the per-minute budget has left; keep an even spread
        key, limit = f"claim:{acc['id']}", int(self.settings()["rl_claims_per_min"])
        cap = max(1, limit - self.limiter.used(key, 60))
        if len(pts) > cap:
            pts = [pts[i] for i in sorted({round(j * (len(pts) - 1) / max(1, cap - 1)) for j in range(cap)})]
            self.log(self.t("claims_capped", name=t["name"], n=len(pts)), "warn")
        tasks = []
        for i, o in enumerate(pts, 1):
            await sleep_until(local + o)
            if any(x.done() and x.result() for x in tasks):
                break
            if self.cooling(key):
                break  # Mojang said 429: stop instead of hammering
            tasks.append(asyncio.create_task(self.claim(t.get("claim_as") or t["name"], acc, i, t["id"])))
        return any(await asyncio.gather(*tasks))

    def watch_pool(self, claimer_id: int, s: dict) -> list[dict]:
        """Helper accounts: valid token, not busy with their own snipe. They never claim."""
        if not s.get("helpers_enabled"):
            return []
        now = time.time()
        out = []
        for a in self.db.q("SELECT * FROM accounts WHERE id != ? AND COALESCE(helper,1)=1 ORDER BY id", claimer_id):
            if a["id"] in self.busy or a["id"] in self.refresh_failed:
                continue
            if a["status"] == "expired" or (a["exp"] and a["exp"] < now + 60):
                continue
            out.append(a)
        return out

    async def safe_availability(self, name: str, token: str, aid: int | None = None) -> str:
        try:
            return await self.availability(name, token, aid)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return f"ERR {type(e).__name__}"

    async def run_watch(self, t, acc):
        """Watch: claimer and helpers take turns checking; only the claimer claims."""
        name = t["name"]
        claim_name = t.get("claim_as") or name
        s = self.settings()
        helpers = self.watch_pool(acc["id"], s)
        self.log(self.t("armed_watch", name=name, label=acc["label"], end=fmt(t["window_end"])))
        if helpers:
            self.log(self.t("helpers_on", name=name, n=len(helpers), labels=", ".join(h["label"] for h in helpers),
                            every=float(s["watch_poll"]) / (len(helpers) + 1)))
        pause: dict[int, float] = {}      # account id -> skip until (after 429 or error)
        errors = 0
        turn = 0
        last_pool = time.time()
        while self.now() < t["window_end"]:
            s = self.settings()
            poll = max(1.0, float(s["watch_poll"]))
            acc = self.db.one("SELECT * FROM accounts WHERE id=?", acc["id"]) or acc
            if time.time() - last_pool > 60:
                helpers, last_pool = self.watch_pool(acc["id"], s), time.time()
            pool = [acc] + helpers
            now = time.time()
            ready = [a for a in pool if pause.get(a["id"], 0) <= now]
            if not ready:
                await asyncio.sleep(0.5)
                continue
            who = ready[turn % len(ready)]
            turn += 1
            st = await self.safe_availability(name, who["token"], who["id"])
            if st == "AVAILABLE":
                by = "" if who["id"] == acc["id"] else self.t("seen_by", label=who["label"])
                self.log(self.t("name_free", name=name) + by, "ok")
                for i in range(1, 4):
                    if await self.claim(claim_name, acc, i, t["id"]):
                        return True
                    if self.cooling(f"claim:{acc['id']}"):
                        break
                    await asyncio.sleep(0.2)
                return False
            if st == "NOT_ALLOWED":
                raise RuntimeError(self.t("blocked"))
            if st == "UNAUTHORIZED":
                if who["id"] == acc["id"]:
                    # Linked account: try renewing first, give up only after that
                    if acc["refresh_token"] and await self.try_refresh(acc["id"]):
                        continue
                    raise RuntimeError(self.t("token_expired", label=acc["label"]))
                helpers = [h for h in helpers if h["id"] != who["id"]]
                self.log(self.t("helper_dropped", label=who["label"]), "warn")
            elif st == "RATE_LIMITED":
                pause[who["id"]] = time.time() + max(poll * 3, self.cooling(f"chk:{who['id']}"))
                self.log(self.t("helper_rl", label=who["label"]), "warn")
            elif st == "THROTTLED":
                # Own limiter: this account used its check budget, skip it until there's room again
                pause[who["id"]] = time.time() + max(1.0, self.limiter.wait_time(
                    f"chk:{who['id']}", int(s["rl_checks_per_min"]), 60))
            elif st.startswith("ERR") or st.startswith("HTTP"):
                # Network error or unexpected response: don't give up, wait briefly and continue
                errors += 1
                pause[who["id"]] = time.time() + poll
                if errors in (1, 10, 100):
                    self.log(self.t("watch_err", name=name, st=st, n=errors), "warn")
            # Each token checks once per 'poll' seconds; together every poll/count seconds.
            # If one pauses, the others don't speed up (they would hit the rate limit).
            await asyncio.sleep(poll / max(1, len(ready)))
        return None

    async def run_target(self, t, acc):
        try:
            if t["mode"] == "drop":
                ok = await self.run_drop(t, acc)
            else:
                ok = await self.run_watch(t, acc)
            if ok:
                self.set_target(t["id"], "won", self.t("res_won", label=acc["label"]))
                self.notify("result", self.t("won", name=t["name"], label=acc["label"]), "ok",
                            title=self.t("ti_won", name=t["name"]),
                            desc=self.t("d_won", name=t["name"], label=acc["label"], ts=int(time.time())),
                            page="snipes", ping=True)
                await self.check_account(acc["id"])
            elif ok is None:
                self.set_target(t["id"], "missed", self.t("res_missed"))
                self.notify("result", self.t("missed", name=t["name"]), "warn",
                            title=self.t("ti_missed", name=t["name"]), desc=self.t("d_missed"), page="snipes", ping=False)
            else:
                self.set_target(t["id"], "lost", self.t("res_lost"))
                self.notify("result", self.t("lost", name=t["name"]), "warn",
                            title=self.t("ti_lost", name=t["name"]), desc=self.t("d_lost"),
                            action=self.t("a_lost"), page="snipes", ping=False)
        except asyncio.CancelledError:
            self.set_target(t["id"], "cancelled", self.t("res_cancelled"))
            self.log(self.t("cancelled", name=t["name"]))
        except Exception as e:
            self.set_target(t["id"], "error", str(e))
            self.notify("result", self.t("err", name=t["name"], e=e), "error",
                        title=self.t("ti_err", name=t["name"]), desc=str(e),
                        action=self.t("a_err"), page="log", ping=True)
        finally:
            self.busy.discard(acc["id"])
            self.active.pop(t["id"], None)

    async def scheduler(self):
        last_acc = 0.0
        last_rem = 0.0
        while True:
            try:
                now = self.now()
                if now - last_rem > 60:
                    last_rem = now
                    await self.auto_refresh()
                    await self.token_reminders()
                    self.flush_released()
                if now - last_acc > 600:
                    last_acc = now
                    for a in self.db.q("SELECT id FROM accounts"):
                        if a["id"] not in self.busy:
                            await self.check_account(a["id"])
                for t in self.db.q("SELECT * FROM targets WHERE status='queued'"):
                    if now > t["window_end"]:
                        self.set_target(t["id"], "missed", self.t("res_missed"))
                        continue
                    if now < t["window_start"]:
                        continue
                    if t["pinned"]:
                        acc = self.db.one("SELECT * FROM accounts WHERE id=?", t["pinned"])
                        why = self.usable(acc)
                        if why:
                            if t["id"] not in self.warned:
                                self.warned.add(t["id"])
                                self.notify("problem", self.t("pinned_unusable", name=t["name"], why=why), "error",
                                            title=self.t("ti_noacc", name=t["name"]),
                                            desc=self.t("d_noacc_long", name=t["name"], why=why, end=int(t["window_end"])),
                                            action=self.t("a_noacc"), page="snipes")
                            continue
                    else:
                        acc = self.pick_account()
                        if not acc:
                            if t["id"] not in self.warned:
                                self.warned.add(t["id"])
                                self.notify("problem", self.t("no_account", name=t["name"]), "error",
                                            title=self.t("ti_noacc", name=t["name"]),
                                            desc=self.t("d_noacc_long", name=t["name"], why=self.t("d_noacc_why"),
                                                        end=int(t["window_end"])),
                                            action=self.t("a_noacc"), page="snipes")
                            continue
                    self.warned.discard(t["id"])
                    self.busy.add(acc["id"])
                    self.db.x("UPDATE targets SET status='armed', account_id=? WHERE id=?", acc["id"], t["id"])
                    self.active[t["id"]] = asyncio.create_task(self.run_target(t, acc))
            except Exception as e:
                self.log(self.t("sched_err", e=e), "error")
            await asyncio.sleep(1)

    # ---------- state for the UI ----------
    def state(self) -> dict:
        now = self.now()
        counts = {r["state"]: r["c"] for r in self.db.q("SELECT state, COUNT(*) c FROM names GROUP BY state")}
        upcoming = self.db.q(
            "SELECT name, drop_lo, drop_hi, star FROM names WHERE state='released' AND drop_hi > ? "
            "ORDER BY drop_lo LIMIT 60", now - 3600,
        )
        accounts = []
        for a in self.db.q("SELECT * FROM accounts ORDER BY id"):
            a["auto"] = bool(a.pop("refresh_token")) and a["id"] not in self.refresh_failed
            a["relink"] = a["id"] in self.refresh_failed
            a.pop("token")
            a["probe"] = json.loads(a["probe"]) if a["probe"] else None
            a["busy"] = a["id"] in self.busy
            a["cooldown"] = max(self.cooling(f"claim:{a['id']}"), self.cooling(f"chk:{a['id']}"))
            accounts.append(a)
        targets = self.db.q(
            "SELECT t.*, a.label account, p.label pinned_label, n.drop_lo n_lo, n.drop_hi n_hi FROM targets t "
            "LEFT JOIN accounts a ON a.id=t.account_id LEFT JOIN accounts p ON p.id=t.pinned "
            "LEFT JOIN names n ON n.name=t.name "
            "ORDER BY CASE WHEN t.status IN ('queued','armed') THEN 0 ELSE 1 END, "
            "CASE WHEN t.status IN ('queued','armed') THEN t.window_start ELSE -t.created END LIMIT 80"
        )
        ids = [t["id"] for t in targets]
        att: dict[int, list] = {}
        if ids:
            for r in self.db.q(f"SELECT target_id,idx,sent,ms,status,body FROM attempts "
                               f"WHERE target_id IN ({','.join('?' * len(ids))}) ORDER BY id", *ids):
                att.setdefault(r.pop("target_id"), []).append(r)
        for t in targets:
            t["attempts"] = att.get(t["id"], [])
            if t["status"] == "queued":
                t["token"] = self.token_plan(t)
        settings = self.settings()
        return {
            "now": now, "ntp": self.ntp, "ntp_info": self.ntp_info, "scan": self.scan, "counts": counts,
            "upcoming": upcoming, "accounts": accounts, "targets": targets, "settings": settings,
            "msa_ready": bool(settings.get("ms_client_id")),
            "fast": self.fast, "calib": self.calibration(),
            "starred": self.db.one("SELECT COUNT(*) c FROM names WHERE star=1")["c"],
        }
