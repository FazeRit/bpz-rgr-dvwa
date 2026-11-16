import json
import os
import sys

REPORTS = os.environ.get("REPORTS_DIR", "reports")


def load(name):
    try:
        with open(os.path.join(REPORTS, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def semgrep_errors(report):
    return [r for r in report.get("results", []) if r["extra"]["severity"] == "ERROR"]


def trivy_high(report):
    return [v for res in report.get("Results", []) for v in res.get("Vulnerabilities") or []
            if v["Severity"] in ("HIGH", "CRITICAL")]


def main():
    reports = {name: load(name) for name in ("semgrep-v8.json", "trivy.json", "gitleaks.json")}
    missing = [name for name, data in reports.items() if data is None]
    if missing:
        print(f"::error::Quality gate: missing or broken reports {missing}, build blocked")
        return 1

    failed = False
    for r in semgrep_errors(reports["semgrep-v8.json"]):
        print(f"::error file={r['path']},line={r['start']['line']}::{r['check_id'].split('.')[-1]}")
        failed = True
    for v in trivy_high(reports["trivy.json"]):
        print(f"::error::{v['VulnerabilityID']} {v['PkgName']}@{v['InstalledVersion']} ({v['Severity']})")
        failed = True
    for s in reports["gitleaks.json"]:
        print(f"::error file={s['File']},line={s['StartLine']}::secret {s['RuleID']}")
        failed = True

    print("Quality gate: failed" if failed else "Quality gate: passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
