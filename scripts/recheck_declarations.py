#!/usr/bin/env python3
"""Re-check the dependency declarations behind the exposure test against PyPI.

For every (SDK release, CVE) pair in the exposure table, fetch the release's
metadata from PyPI and compare the declared constraint on the vulnerable
package with the constraint recorded in the table. Where a release has no
wheel metadata on PyPI, fall back to the source distribution's requires.txt.

Usage:
    python3 scripts/recheck_declarations.py [pairs.csv] [--out report.csv]

Without arguments the script checks data/exposure/exposure_pairs.csv (Table 7) and writes its
report to rerun/recheck_report.csv.

Input columns (header names, any order; extra columns are ignored):
    sdk_package  PyPI project name of the SDK, e.g. qiskit-ibm-runtime
    sdk_release  SDK release tested, e.g. 0.23.0
    cve          CVE identifier, e.g. CVE-2024-35195
    package      vulnerable dependency, e.g. requests
    constraint   constraint recorded in the table, e.g. >=2.19  ('(unbounded)' = no constraint)

Exit status is 0 when every pair matches and 1 otherwise.
Standard library only; no third-party packages required.
"""
import argparse, csv, io, json, os, re, sys, tarfile, urllib.error, urllib.request, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UA = {"User-Agent": "exposure-recheck/1.0 (replication script)"}

def norm_name(s):
    return re.sub(r"[-_.]+", "-", s).lower()

def norm_spec(s):
    """Canonical form of a version specifier: no spaces, sorted clauses."""
    s = (s or "").strip().strip("()[]")
    if not s or s.lower() in ("any", "none", "unbounded", "no bound", "no constraint", "-", "—", "---"):
        return ""
    parts = [p.strip().replace(" ", "") for p in s.split(",") if p.strip()]
    return ",".join(sorted(parts))

import ssl
_CTXS = [ssl.create_default_context()]          # system certificates first
try:
    import certifi                               # fall back to certifi's bundle if the system store fails
    _CTXS.append(ssl.create_default_context(cafile=certifi.where()))
except ImportError:
    pass

def fetch(url):
    last = None
    for ctx in _CTXS:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60, context=ctx) as r:
                return r.read()
        except urllib.error.URLError as e:
            last = e
            if not isinstance(e.reason, ssl.SSLError):
                raise
    raise last

def constraint_from_requires_dist(requires_dist, package):
    """Return (found, spec) for the first non-extra requirement naming `package`."""
    for req in requires_dist or []:
        if "extra ==" in req:
            continue
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(\(([^)]*)\)|([^;]*))?", req)
        if not m:
            continue
        if norm_name(m.group(1)) != norm_name(package):
            continue
        spec = m.group(4) if m.group(4) is not None else (m.group(5) or "")
        return True, spec.strip()
    return False, None

def constraint_from_sdist(sdist_url, package):
    """Parse *.egg-info/requires.txt from a source distribution."""
    data = fetch(sdist_url)
    lines = None
    if sdist_url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith("requires.txt") and ".egg-info/" in n:
                    lines = z.read(n).decode("utf-8", "replace").splitlines(); break
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t.getmembers():
                if m.name.endswith("requires.txt") and ".egg-info/" in m.name:
                    lines = t.extractfile(m).read().decode("utf-8", "replace").splitlines(); break
    if lines is None:
        return False, None
    reqs = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        if ln.startswith("["):          # start of an extras section: stop
            break
        reqs.append(ln)
    return constraint_from_requires_dist(reqs, package)

def check_pair(sdk, release, package):
    meta = json.loads(fetch(f"https://pypi.org/pypi/{sdk}/{release}/json"))
    info = meta["info"]
    source = "requires_dist"
    found, spec = constraint_from_requires_dist(info.get("requires_dist"), package)
    if info.get("requires_dist") is None or (not found and not info.get("requires_dist")):
        sdists = [u for u in meta.get("urls", []) if u.get("packagetype") == "sdist"]
        if sdists:
            source = "sdist requires.txt"
            found, spec = constraint_from_sdist(sdists[0]["url"], package)
    yanked = any(u.get("yanked") for u in meta.get("urls", [])) if meta.get("urls") else False
    upload = min((u["upload_time"] for u in meta.get("urls", [])), default="")
    return found, spec, source, yanked, upload[:10]

ALIASES = {
    "sdk": ("sdk_package", "sdk", "project", "package_name", "sdk_name", "pypi_name", "pypi_project"),
    "release": ("release", "version", "sdk_release", "sdk_version", "release_tested", "tested_release"),
    "cve": ("cve", "cve_id", "cve-id", "vulnerability"),
    "package": ("package", "dependency", "dep", "vulnerable_package", "dependency_name"),
    "constraint": ("constraint", "declared", "declared_constraint", "requires", "specifier", "requirement", "declared_requirement"),
}

def canon(row):
    out = {}
    low = {k.strip().lower().replace(" ", "_"): (v or "").strip() for k, v in row.items() if k}
    for want, names in ALIASES.items():
        for n in names:
            if n in low:
                out[want] = low[n]; break
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=os.path.join(ROOT, "data", "exposure", "exposure_pairs.csv"))
    ap.add_argument("--out", default=os.path.join(ROOT, "rerun", "recheck_report.csv"))
    a = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    rows = list(csv.DictReader(open(a.csv, newline="", encoding="utf-8")))
    rows = [canon(r) for r in rows]
    need = {"sdk", "release", "cve", "package", "constraint"}
    missing = need - set(rows[0].keys())
    if missing:
        hdr = list(csv.reader(open(a.csv, newline="", encoding="utf-8")))[0]
        sys.exit(f"input is missing columns: {sorted(missing)}\nyour header is: {hdr}\n"
                 f"accepted names: " + "; ".join(f"{k}: {', '.join(v)}" for k, v in ALIASES.items()))

    report, mismatches = [], 0
    for r in rows:
        try:
            found, spec, source, yanked, upload = check_pair(r["sdk"], r["release"], r["package"])
        except urllib.error.URLError as e:           # cannot reach PyPI: stop, do not report 25 false mismatches
            sys.exit(f"cannot reach PyPI: {e.reason}\n"
                     "If this is CERTIFICATE_VERIFY_FAILED, install certificates for your Python "
                     "(macOS python.org build: run 'Install Certificates.command' in the Python folder "
                     "under /Applications) or run 'python3 -m pip install certifi' and rerun.")
        except Exception as e:                       # missing release, bad metadata, ...
            found, spec, source, yanked, upload = False, None, f"ERROR: {e}", None, ""
        live = "" if (found and spec is None) else (spec if found else None)
        recorded = norm_spec(r["constraint"])
        if live is None:
            status = "NOT DECLARED"
        elif norm_spec(live) == recorded:
            status = "match"
        else:
            status = "MISMATCH"
        if status != "match":
            mismatches += 1
        report.append({**r, "live_constraint": "" if live is None else live, "source": source,
                       "upload_date": upload, "yanked": yanked, "status": status})
        print(f"{r['sdk']:<22} {r['release']:<10} {r['cve']:<15} {r['package']:<9} "
              f"table={r['constraint'] or '(unbounded)':<16} live={('(unbounded)' if live=='' else live) if live is not None else '(not declared)':<16} {status}")

    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report[0].keys()))
        w.writeheader(); w.writerows(report)
    print(f"\n{len(rows)} pairs checked, {len(rows)-mismatches} match, {mismatches} differ. Report: {a.out}")
    sys.exit(1 if mismatches else 0)

if __name__ == "__main__":
    main()
