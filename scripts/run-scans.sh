#!/usr/bin/env bash
set -euo pipefail
SRC=$(realpath "$1"); OUT=$(realpath -m "$2"); ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
SEMGREP=semgrep/semgrep:1.95.0; TRIVY=aquasec/trivy:0.58.1; GITLEAKS=zricethezav/gitleaks:v8.21.2
docker run --rm -v "$SRC:/src:ro" $SEMGREP semgrep scan --config p/php --config p/security-audit --json --metrics=off /src > "$OUT/semgrep.json" 2> "$OUT/semgrep.log" || true
docker run --rm -v "$SRC:/src:ro" -v "$ROOT/tools/semgrep:/rules:ro" $SEMGREP semgrep scan --config /rules/variant8.yml --json --metrics=off /src/vulnerabilities/upload /src/vulnerabilities/fi /src/vulnerabilities/view_source.php /src/vulnerabilities/view_source_all.php /src/vulnerabilities/view_help.php > "$OUT/semgrep-variant8.json" 2>> "$OUT/semgrep.log" || true
docker run --rm -v "$SRC:/src:ro" $TRIVY fs --scanners vuln,secret --format json /src > "$OUT/trivy.json" 2> "$OUT/trivy.log" || true
docker run --rm -v "$SRC:/src:ro" -v "$OUT:/out" $TRIVY fs -q --format cyclonedx --output /out/sbom.json /src || true
docker run --rm -v "$SRC:/src:ro" -v "$OUT:/out" $GITLEAKS dir /src --report-format json --report-path /out/gitleaks.json --exit-code 0 > "$OUT/gitleaks.log" 2>&1 || true
python3 "$ROOT/tools/summarize.py" "$OUT" > "$OUT/summary.tsv"
echo "findings: $(wc -l < "$OUT/summary.tsv")"
