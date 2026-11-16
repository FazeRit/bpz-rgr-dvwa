import os, re, pathlib, datetime
import pytest, requests

BASE = os.environ.get("TARGET", "http://127.0.0.1:4280").rstrip("/")
EVIDENCE = pathlib.Path(__file__).resolve().parent.parent / "evidence" / os.environ.get("EVIDENCE_TAG", "run")


def _token(html):
    m = re.search(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]", html)
    return m.group(1) if m else ""


def login(level):
    s = requests.Session()
    r = s.get(f"{BASE}/setup.php")
    if "dvwa_" not in r.text or "Database has been created" not in r.text:
        s.post(f"{BASE}/setup.php", data={"create_db": "Create / Reset Database", "user_token": _token(r.text)})
    r = s.get(f"{BASE}/login.php")
    s.post(f"{BASE}/login.php", data={"username": "admin", "password": "password", "Login": "Login", "user_token": _token(r.text)})
    r = s.get(f"{BASE}/security.php")
    s.post(f"{BASE}/security.php", data={"security": level, "seclev_submit": "Submit", "user_token": _token(r.text)})
    s.cookies.set("security", level)
    return s


def record(name, resp):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    req = resp.request
    body = req.body if isinstance(req.body, (bytes, type(None))) else req.body.encode()
    body = (body or b"")[:1500].decode("latin-1")
    text = resp.text
    m = re.search(r'<div class="vulnerable_code_area">(.*?)</div>', text, re.S)
    excerpt = (m.group(1) if m else text)[:2500]
    (EVIDENCE / f"{name}.txt").write_text(
        f"# {datetime.datetime.now(datetime.UTC).isoformat()}  target={BASE}\n"
        f"> {req.method} {req.url}\n" + "".join(f"> {k}: {v}\n" for k, v in req.headers.items() if k.lower() != "cookie")
        + f">\n{body}\n\n< HTTP {resp.status_code}\n" + "".join(f"< {k}: {v}\n" for k, v in resp.headers.items())
        + f"<\n{excerpt}\n", encoding="utf-8")


@pytest.fixture(params=["low", "medium", "high"])
def session(request):
    return request.param, login(request.param)
