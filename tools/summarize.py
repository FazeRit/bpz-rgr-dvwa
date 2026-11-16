import json, sys, os
d = sys.argv[1]
rows = []
def load(n):
    p = os.path.join(d, n)
    try:
        return json.load(open(p))
    except Exception:
        return None
for fn in ('semgrep.json', 'semgrep-variant8.json'):
  s = load(fn)
  if s:
    for r in s['results']:
        rows.append(('SAST/semgrep' + ('-v8' if 'variant8' in fn else ''), r['check_id'].split('.')[-1], r['path'].removeprefix('/src/'), r['start']['line'], r['extra']['severity'], (r['extra'].get('metadata', {}).get('cwe') or [''])[0]))
t = load('trivy.json')
if t:
    for res in t.get('Results', []):
        for v in res.get('Vulnerabilities') or []:
            rows.append(('SCA/trivy', v['VulnerabilityID'], res['Target'].removeprefix('/src/'), v['PkgName'] + '@' + v['InstalledVersion'], v['Severity'], 'fixed:' + v.get('FixedVersion', '')))
        for v in res.get('Secrets') or []:
            rows.append(('Secrets/trivy', v['RuleID'], res['Target'].removeprefix('/src/'), v['StartLine'], v['Severity'], ''))
g = load('gitleaks.json')
if g:
    for v in g:
        rows.append(('Secrets/gitleaks', v['RuleID'], v['File'].removeprefix('/src/'), v['StartLine'], '', ''))
for r in rows:
    print('\t'.join(map(str, r)))
