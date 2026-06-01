"""
auth.py - credentials only from .env
"""
import hashlib, hmac, json, os, time
from typing import Optional
from dotenv import load_dotenv
from fastapi import HTTPException, Request, status

load_dotenv(override=True)

_BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_SECRET_FILE = os.path.join(_BASE_DIR, ".shieldsoc_secret")
TOKEN_TTL_SEC = 8 * 3600

def _get_secret() -> bytes:
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, "rb") as f:
            return f.read().strip()
    secret = os.urandom(32).hex().encode()
    with open(_SECRET_FILE, "wb") as f:
        f.write(secret)
    os.chmod(_SECRET_FILE, 0o600)
    return secret

_SECRET = _get_secret()

def _get_env_creds() -> tuple[str, str]:
    user = os.environ.get("SHIELDSOC_USER", "").strip()
    pwd  = os.environ.get("SHIELDSOC_PASS", "").strip()
    if not user or not pwd:
        print("=" * 55)
        print("❌  SHIELDSOC_USER and SHIELDSOC_PASS not set in .env")
        print("=" * 55)
        raise RuntimeError("Set SHIELDSOC_USER and SHIELDSOC_PASS in .env")
    return user, pwd

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_credentials(username: str, password: str) -> bool:
    env_user, env_pass = _get_env_creds()
    return (
        hmac.compare_digest(username.strip(), env_user) and
        hmac.compare_digest(_hash(password), _hash(env_pass))
    )

def change_password(old_password: str, new_password: str) -> tuple[bool, str]:
    _, env_pass = _get_env_creds()
    if not hmac.compare_digest(_hash(old_password), _hash(env_pass)):
        return False, "Current password is incorrect"
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters"
    env_path = os.path.join(_BASE_DIR, ".env")
    try:
        lines = open(env_path).readlines() if os.path.exists(env_path) else []
        found = False
        for i, l in enumerate(lines):
            if l.startswith("SHIELDSOC_PASS="):
                lines[i] = f"SHIELDSOC_PASS={new_password}\n"
                found = True
        if not found:
            lines.append(f"SHIELDSOC_PASS={new_password}\n")
        open(env_path, "w").writelines(lines)
        os.environ["SHIELDSOC_PASS"] = new_password
        load_dotenv(override=True)
        return True, "Password updated in .env"
    except Exception as e:
        return False, f"Failed to write .env: {e}"

def get_username() -> str:
    user, _ = _get_env_creds()
    return user

def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64(s: str) -> bytes:
    import base64
    pad = 4 - len(s) % 4
    if pad != 4: s += "=" * pad
    return base64.urlsafe_b64decode(s)

def create_token(username: str) -> str:
    header  = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": username, "iat": int(time.time()), "exp": int(time.time()) + TOKEN_TTL_SEC}).encode())
    sig     = _b64(hmac.new(_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token: str) -> Optional[str]:
    try:
        h, p, sig = token.split(".")
        expected  = _b64(hmac.new(_SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected): return None
        data = json.loads(_unb64(p))
        if data.get("exp", 0) < time.time(): return None
        return data.get("sub")
    except Exception:
        return None

def _get_token(request: Request) -> Optional[str]:
    t = request.cookies.get("shieldsoc_token")
    if t: return t
    a = request.headers.get("Authorization", "")
    return a[7:] if a.startswith("Bearer ") else None

async def require_auth(request: Request) -> str:
    token    = _get_token(request)
    username = verify_token(token) if token else None
    if username: return username
    accept = request.headers.get("accept", "")
    path   = request.url.path
    if "text/html" in accept or not path.startswith("/api/"):
        raise HTTPException(status_code=302, headers={"Location": f"/login?next={path}"})
    raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})

try:
    _u, _ = _get_env_creds()
    print(f"✅ Auth: user='{_u}' loaded from .env")
except RuntimeError:
    pass