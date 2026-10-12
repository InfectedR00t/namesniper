"""namesniper: web interface and API. Run with: python app.py"""
import asyncio
import base64
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel

from core import AuthError, Engine

engine = Engine(os.environ.get("SNIPER_DB", "sniper.db"))
PASSWORD = os.environ.get("SNIPER_PASSWORD")
STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app):
    await engine.start()
    yield
    await engine.stop()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    if PASSWORD:
        ok = False
        h = request.headers.get("authorization", "")
        if h.startswith("Basic "):
            try:
                _, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                ok = secrets.compare_digest(pw, PASSWORD)
            except Exception:
                pass
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="namesniper"'})
    return await call_next(request)


def bad(e: Exception):
    raise HTTPException(400, str(e))


class AccountIn(BaseModel):
    label: str = ""
    locked: bool = False
    token: str


class TokenIn(BaseModel):
    token: str


class TargetIn(BaseModel):
    name: str
    mode: str = "drop"
    drop_at: str | None = None
    hours: float = 24
    account_id: int | None = None


class PinIn(BaseModel):
    account_id: int | None = None
    claim_as: str | None = None


class CasingIn(BaseModel):
    claim_as: str | None = None


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/state")
async def state():
    return engine.state()


@app.post("/api/notify-test")
async def notify_test():
    if not engine.settings().get("webhook_url", "").strip():
        bad(ValueError(engine.t("need_webhook")))
    try:
        await engine.send_test()
    except Exception as e:
        bad(e)
    return {"ok": True}


@app.post("/api/settings")
async def save_settings(body: dict):
    try:
        engine.save_settings(body)
    except Exception as e:
        bad(e)
    return {"ok": True}


@app.post("/api/accounts")
async def add_account(body: AccountIn):
    if not body.token.strip():
        bad(ValueError(engine.t("token_missing")))
    aid = engine.add_account(body.label, body.token, body.locked)
    await engine.check_account(aid)
    return {"id": aid}


@app.put("/api/accounts/{aid}")
async def update_token(aid: int, body: TokenIn):
    engine.update_token(aid, body.token)
    await engine.check_account(aid)
    return {"ok": True}


class LockIn(BaseModel):
    locked: bool


@app.put("/api/accounts/{aid}/lock")
async def lock_account(aid: int, body: LockIn):
    try:
        engine.set_locked(aid, body.locked)
    except ValueError as e:
        bad(e)
    return {"ok": True}


class MsaIn(BaseModel):
    label: str = ""
    locked: bool = False


@app.post("/api/accounts/msa")
async def msa_new(body: MsaIn):
    try:
        return await engine.msa_start(body.label, body.locked)
    except (AuthError, ValueError) as e:
        bad(e)


@app.post("/api/accounts/{aid}/msa")
async def msa_link(aid: int):
    try:
        return await engine.msa_start(aid=aid)
    except (AuthError, ValueError) as e:
        bad(e)


@app.get("/api/msa/{fid}")
async def msa_status(fid: str):
    try:
        return engine.msa_flow(fid)
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.delete("/api/msa/{fid}")
async def msa_cancel(fid: str):
    engine.msa_cancel(fid)
    return {"ok": True}


@app.post("/api/accounts/{aid}/refresh")
async def refresh_account(aid: int):
    try:
        await engine.refresh_account(aid)
    except (AuthError, ValueError) as e:
        bad(e)
    await engine.check_account(aid)
    return {"ok": True}


@app.post("/api/accounts/{aid}/probe")
async def probe_account(aid: int):
    try:
        return await engine.probe(aid)
    except ValueError as e:
        bad(e)
    except Exception as e:
        bad(RuntimeError(f"{type(e).__name__}: {e}"))


@app.post("/api/calibration/apply")
async def calibration_apply():
    try:
        return {"hold_offset_s": engine.apply_calibration()}
    except ValueError as e:
        bad(e)


@app.post("/api/ntp")
async def resync_ntp():
    return await engine.sync_ntp()


@app.put("/api/accounts/{aid}/helper")
async def helper_account(aid: int, body: LockIn):
    try:
        engine.set_helper(aid, body.locked)
    except ValueError as e:
        bad(e)
    return {"ok": True}


@app.post("/api/accounts/{aid}/check")
async def check_account(aid: int):
    await engine.check_account(aid)
    return {"ok": True}


@app.delete("/api/accounts/{aid}")
async def delete_account(aid: int):
    if aid in engine.busy:
        bad(ValueError(engine.t("acc_busy")))
    engine.db.x("UPDATE targets SET pinned=NULL WHERE pinned=? AND status='queued'", aid)
    engine.db.x("DELETE FROM accounts WHERE id=?", aid)
    return {"ok": True}


@app.post("/api/targets")
async def add_target(body: TargetIn):
    try:
        drop = None
        if body.mode == "drop":
            if not body.drop_at:
                raise ValueError(engine.t("drop_missing"))
            drop = datetime.fromisoformat(body.drop_at.replace("Z", "+00:00")).timestamp()
        return {"id": engine.add_target(body.name, body.mode, drop_at=drop, hours=body.hours, account_id=body.account_id,
                                        claim_as=body.name.strip())}
    except ValueError as e:
        bad(e)


@app.get("/api/names")
async def list_names(state: str = "", q: str = "", limit: int = 100, offset: int = 0, kind: str = ""):
    return engine.names(state, q, limit, offset, kind)


class StarIn(BaseModel):
    star: bool


@app.put("/api/names/{name}/star")
async def star_name(name: str, body: StarIn):
    try:
        engine.set_star(name.lower(), body.star)
    except ValueError as e:
        bad(e)
    return {"ok": True}


@app.post("/api/import")
async def import_drops(body: list[dict]):
    return engine.import_drops(body)


@app.post("/api/names/{name}/snipe")
async def snipe_drop(name: str, body: PinIn | None = None):
    try:
        return {"id": engine.target_from_drop(name, body.account_id if body else None, name.strip())}
    except ValueError as e:
        bad(e)


@app.patch("/api/targets/{tid}")
async def pin_target(tid: int, body: PinIn):
    try:
        engine.set_target_account(tid, body.account_id)
    except ValueError as e:
        bad(e)
    return {"ok": True}


@app.put("/api/targets/{tid}/casing")
async def set_casing(tid: int, body: CasingIn):
    try:
        engine.set_target_casing(tid, body.claim_as)
    except ValueError as e:
        bad(e)
    return {"ok": True}


@app.delete("/api/targets/{tid}")
async def cancel_target(tid: int):
    engine.cancel_target(tid)
    return {"ok": True}


@app.post("/api/check/{name}")
async def check_name(name: str):
    return {"status": await engine.check_name(name.lower())}


@app.get("/api/events")
async def events(request: Request):
    q: asyncio.Queue = asyncio.Queue()
    engine.subs.add(q)

    async def gen():
        try:
            recent = engine.db.q("SELECT ts, level, msg FROM events ORDER BY id DESC LIMIT 100")
            for e in reversed(recent):
                yield f"data: {json.dumps(e)}\n\n"
            while not await request.is_disconnected():
                try:
                    e = await asyncio.wait_for(q.get(), 15)
                    yield f"data: {json.dumps(e)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            engine.subs.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.environ.get("SNIPER_HOST", "127.0.0.1"),
        port=int(os.environ.get("SNIPER_PORT", "8787")),
        log_level="warning",
    )
