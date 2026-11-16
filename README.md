# РГР «Аудит захищеності програмного застосунку», варіант 8

Ціль: DVWA (PHP), upstream `digininja/DVWA@a1978a2`. Профіль: завантаження файлів і обхід каталогів.

- `target/` — код DVWA; тег `vulnerable-baseline` містить вихідну вразливу версію.
- Виправлення: `target/vulnerabilities/upload/source/*.php`, `target/dvwa/includes/secure_upload.inc.php`, `target/vulnerabilities/fi/source/*.php`, `target/vulnerabilities/view_*.php`, `target/dvwa/includes/dvwaPage.inc.php`, `target/hardening/`, `target/vulnerabilities/api/composer.lock`.
- `tests/` — регресійні тести (pytest).
- `compose.yml`, `deploy/` — ізольоване середовище; `scripts/`, `tools/` — запуск сканерів і власні правила Semgrep.

```bash
scripts/prepare-baseline.sh
docker compose up -d --build        # 127.0.0.1:4280 виправлена, :4281 вразлива
uv venv .venv && uv pip install --python .venv pytest requests
TARGET=http://127.0.0.1:4281 .venv/bin/pytest tests   # 15 failed
TARGET=http://127.0.0.1:4280 .venv/bin/pytest tests   # 27 passed
scripts/run-scans.sh .baseline/target scans/before
scripts/run-scans.sh target scans/after
```

CI: `.github/workflows/security.yml` (стадії sast, sca з SBOM, secrets і quality gate `tools/gate.py`).
