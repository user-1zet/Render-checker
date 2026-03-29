from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional
import socket
import re
import uvicorn
import os

app = FastAPI(title="MTProto Proxy Checker")

HEX_RE = re.compile(r"^[a-fA-F0-9_\-]+$")
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+$")

class ProxyItem(BaseModel):
    server: str
    port: int
    secret: str

class CheckRequest(BaseModel):
    proxies: List[ProxyItem] = Field(default_factory=list)
    timeout_ms: Optional[int] = 2500

def is_valid_secret(secret: str) -> bool:
    if not secret:
        return False
    s = secret.strip().replace(" ", "")
    if len(s) < 16:
        return False
    return bool(HEX_RE.match(s))

def is_valid_server(server: str) -> bool:
    if not server:
        return False
    s = server.strip()
    return bool(IP_RE.match(s) or DOMAIN_RE.match(s))

def tcp_check(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp_ok"
    except Exception as e:
        return False, str(e)

@app.post("/check")
def check(req: CheckRequest):
    alive = []
    dead = []
    timeout = max(0.5, min((req.timeout_ms or 2500) / 1000.0, 10.0))

    for p in req.proxies:
        server = p.server.strip()
        secret = p.secret.strip().replace(" ", "")
        port = int(p.port)

        if not is_valid_server(server):
            dead.append({**p.model_dump(), "reason": "bad_server_format"})
            continue

        if port < 1 or port > 65535:
            dead.append({**p.model_dump(), "reason": "bad_port"})
            continue

        if not is_valid_secret(secret):
            dead.append({**p.model_dump(), "reason": "bad_secret_format"})
            continue

        ok, reason = tcp_check(server, port, timeout)
        if ok:
            alive.append({**p.model_dump(), "secret": secret, "status": "alive"})
        else:
            dead.append({**p.model_dump(), "secret": secret, "reason": reason})

    return {"alive": alive, "dead": dead, "count_alive": len(alive), "count_dead": len(dead)}

@app.get("/")
def root():
    return {"ok": True, "service": "mtproto-checker"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)