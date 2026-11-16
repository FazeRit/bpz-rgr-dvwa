import io, re, struct, zlib, uuid
import pytest, requests
from conftest import BASE, record

UPLOAD = f"{BASE}/vulnerabilities/upload/"
FI = f"{BASE}/vulnerabilities/fi/"


def tiny_png():
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def upload(s, filename, content, ctype):
    return s.post(UPLOAD, files={"uploaded": (filename, io.BytesIO(content), ctype)},
                  data={"Upload": "Upload", "MAX_FILE_SIZE": "100000"})


def served(name):
    return requests.get(f"{BASE}/hackable/uploads/{name}")


def result_block(html):
    m = re.search(r"</form>\s*(<pre>.*?</pre>)", html, re.S)
    return m.group(1) if m else ""


def test_v1_non_image_with_script_extension_is_rejected(session):
    level, s = session
    name = f"rgr-{uuid.uuid4().hex[:8]}.php"
    r = upload(s, name, b"RGR-MARKER plain text, not an image\n", "application/octet-stream")
    record(f"V1-{level}", r)
    assert "not uploaded" in r.text
    assert served(name).status_code in (403, 404), "файл збережено й віддається сервером"


def test_v2_spoofed_content_type_is_rejected(session):
    level, s = session
    name = f"rgr-{uuid.uuid4().hex[:8]}.txt"
    r = upload(s, name, b"RGR-MARKER text with spoofed image/png header\n", "image/png")
    record(f"V2-{level}", r)
    assert "not uploaded" in r.text
    assert served(name).status_code == 404


def test_v3_client_filename_and_trailing_payload_not_preserved(session):
    level, s = session
    name = f"rgr-{uuid.uuid4().hex[:8]}.png"
    marker = b"RGR-TRAILING-MARKER"
    r = upload(s, name, tiny_png() + marker, "image/png")
    record(f"V3-{level}", r)
    assert served(name).status_code == 404, "файл збережено під іменем клієнта"
    m = re.search(r"([0-9a-f]{32}\.png) succesfully uploaded", r.text)
    assert m, "сервер має сам генерувати ім'я файлу"
    stored = served(m.group(1))
    assert stored.status_code == 200 and marker not in stored.content


def test_v4_upload_response_does_not_disclose_path(session):
    level, s = session
    r = upload(s, "rgr.png", tiny_png(), "image/png")
    record(f"V4-{level}", r)
    out = result_block(r.text)
    assert out, "немає повідомлення про результат"
    assert "hackable/uploads" not in out and "../" not in out


TRAVERSAL = {
    "low": "../../robots.txt",
    "medium": "..././..././robots.txt",
    "high": "file4.php",
}


def test_v5_v7_page_parameter_limited_to_allowlist(session):
    level, s = session
    r = s.get(FI, params={"page": TRAVERSAL[level]})
    record(f"V5-7-{level}", r)
    assert "User-agent" not in r.text, "вміст файлу поза модулем повернуто клієнту"
    assert "Good job!" not in r.text, "прихована сторінка file4.php доступна"
    assert "File not found" in r.text


def test_allowlisted_pages_still_work(session):
    level, s = session
    r = s.get(FI, params={"page": "file1.php"})
    assert r.status_code == 200 and "File 1" in r.text


def test_valid_png_upload_still_works(session):
    level, s = session
    r = upload(s, "ok.png", tiny_png(), "image/png")
    assert "succesfully uploaded" in r.text


def test_v8_view_source_params_limited_to_allowlist(session):
    level, s = session
    r = s.get(f"{BASE}/vulnerabilities/view_source.php",
              params={"id": "fi", "security": "../../../hackable/flags/fi"})
    record(f"V8-{level}", r)
    assert "Bond. James Bond" not in r.text, "вихідний код файлу поза модулем повернуто клієнту"
    assert r.status_code == 400


def test_view_source_legit_still_works(session):
    level, s = session
    r = s.get(f"{BASE}/vulnerabilities/view_source.php", params={"id": "fi", "security": level})
    assert r.status_code == 200 and "vulnerabilities/fi/source" in r.text
