#!/usr/bin/env python3
"""Recompute the Tier 2 exposure test, the fix timing and the constraint snapshot from PyPI.

1. Exposure test (Section 3.3, Table 7 of the paper). For every Tier 2 candidate CVE that reached
   the test (data/selection/candidates.csv) and every SDK package (data/exposure/sdk_packages.csv),
   find the release that was in force on the CVE's publication date, read the constraint that
   release declares on the vulnerable package, and report the first affected release that the
   constraint admits. The pairs of the 12 included CVEs are Table 7; the pairs of the candidates
   that were excluded afterwards are written to a second file.
2. Fix timing (Section 4.2). Upload date of the fixed release of each Tier 2 corpus CVE against the
   CVE's publication date. Where a fix was back-ported to several release lines, the last upload
   counts.
3. Constraint snapshot (Section 4.2). The constraints that the SDK releases current on the snapshot
   date declare on the corpus packages, and whether they still admit a release affected by a
   corpus CVE.

Definitions
  release in force    highest final version (no pre-release, not yanked) uploaded on or before the date
  declared            a requirement that is not tied to an extra. It is read from the release
                      metadata on PyPI; where PyPI holds none, from requires.txt in the source
                      distribution; where there is no source distribution, from the wheel's METADATA
  affected releases   the releases to which PyPI attaches an advisory carrying the CVE identifier
                      (PyPI takes these advisories from OSV)

Usage
  python3 scripts/exposure_test.py                  writes rerun/*.csv and compares with data/exposure/
  python3 scripts/exposure_test.py --snapshot 2026-09-28 --out rerun --workers 8

The first run makes about 2,000 requests to pypi.org and files.pythonhosted.org and caches the
answers under <out>/cache, so a second run needs no network. Requires Python 3.8+ and the
'packaging' library (python3 -m pip install packaging).
"""
import argparse
import collections
import concurrent.futures
import csv
import datetime
import io
import json
import os
import re
import ssl
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
import zipfile

try:
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version
except ImportError:
    sys.exit("This script needs the 'packaging' library: python3 -m pip install packaging")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
UA = {"User-Agent": "exposure-test/1.0 (replication script)"}

# ------------------------------------------------------------------------------------------------ PyPI access

_CONTEXTS = [ssl.create_default_context()]
try:                                    # some Python installations ship without root certificates
    import certifi
    _CONTEXTS.append(ssl.create_default_context(cafile=certifi.where()))
except ImportError:
    pass


class PyPI:
    """Cached, read-only access to the PyPI JSON API and to release files."""

    def __init__(self, cache_dir):
        self.cache = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _download(self, url):
        last = None
        for attempt in range(4):
            for ctx in _CONTEXTS:
                try:
                    req = urllib.request.Request(url, headers=UA)
                    with urllib.request.urlopen(req, timeout=90, context=ctx) as r:
                        return r.read()
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        return None
                    last = e
                    break                               # server answered: retry later, same certificates
                except urllib.error.URLError as e:
                    last = e
                    if not isinstance(e.reason, ssl.SSLError):
                        break
            time.sleep(2 * (attempt + 1))
        sys.exit(f"cannot fetch {url}: {last}\n"
                 "If this is CERTIFICATE_VERIFY_FAILED, run 'python3 -m pip install certifi' and try again.")

    def _cached(self, url, name):
        path = os.path.join(self.cache, re.sub(r"[^A-Za-z0-9._=+-]", "_", name))
        if not os.path.exists(path):
            data = self._download(url)
            tmp = f"{path}.{threading.get_ident()}.tmp"
            with open(tmp, "wb") as f:
                f.write(data if data is not None else b"")
            os.replace(tmp, path)
        with open(path, "rb") as f:
            return f.read()

    def project(self, name):
        data = self._cached(f"https://pypi.org/pypi/{name}/json", f"{norm(name)}.json")
        return json.loads(data) if data else None

    def release(self, name, version):
        data = self._cached(f"https://pypi.org/pypi/{name}/{version}/json", f"{norm(name)}=={version}.json")
        return json.loads(data) if data else None

    def file(self, url):
        return self._cached(url, "file-" + os.path.basename(url))

    # -- releases ---------------------------------------------------------------------------------------

    def final_releases(self, name):
        """[(upload date, version)] of final, non-yanked releases."""
        d = self.project(name)
        out = []
        for version, files in (d or {}).get("releases", {}).items():
            v = parse_version(version)
            if not files or v is None or v.is_prerelease or v.is_devrelease:
                continue
            if all(f.get("yanked") for f in files):
                continue
            out.append((min(f["upload_time"] for f in files)[:10], version))
        return out

    def uploads(self, name):
        """{version: (upload date, yanked)} for every release that has files, yanked ones included."""
        d = self.project(name)
        return {v: (min(f["upload_time"] for f in files)[:10], all(f.get("yanked") for f in files))
                for v, files in (d or {}).get("releases", {}).items() if files}

    def in_force(self, name, date):
        """Highest final version uploaded on or before `date` (YYYY-MM-DD), with its upload date."""
        cands = [(up, v) for up, v in self.final_releases(name) if up <= date]
        if not cands:
            return None
        up, v = max(cands, key=lambda x: Version(x[1]))
        return v, up

    # -- declared requirements ----------------------------------------------------------------------

    def requirements(self, name, version):
        """(list of requirement strings, source) for one release; (None, reason) if nothing can be read."""
        d = self.release(name, version)
        if not d:
            return None, "release not on PyPI"
        declared = d["info"].get("requires_dist")
        if declared is not None:
            return declared, "metadata"
        sdists = [u for u in d.get("urls", []) if u.get("packagetype") == "sdist"]
        if sdists:
            reqs = self._sdist_requires(sdists[0]["url"])
            if reqs is not None:
                return reqs, "sdist"
        wheels = sorted((u for u in d.get("urls", []) if u.get("packagetype") == "bdist_wheel"), key=lambda u: u["filename"])
        if wheels:
            text = self.file(wheels[0]["url"] + ".metadata")
            if text:
                lines = text.decode("utf-8", "replace").splitlines()
                return [ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("requires-dist:")], "wheel"
        return None, "no readable metadata"

    def _sdist_requires(self, url):
        """Requirements in *.egg-info/requires.txt of a source distribution.

        setuptools writes requires.txt only when the project declares requirements, so an egg-info
        directory without that file means that none are declared. Returns None when the archive has
        no egg-info directory at all.
        """
        data = self.file(url)
        names, read = [], None
        if url.endswith(".zip"):
            z = zipfile.ZipFile(io.BytesIO(data))
            names, read = z.namelist(), z.read
        else:
            t = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            names, read = [m.name for m in t.getmembers()], (lambda n: t.extractfile(n).read())
        egg = [n for n in names if ".egg-info/" in n]
        if not egg:
            return None
        files = sorted((n for n in egg if n.endswith("/requires.txt")), key=len)
        if not files:
            return []
        reqs, section = [], ""
        for line in read(files[0]).decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("["):
                section = line.strip("[]")
            elif section == "":
                reqs.append(line)
            elif section.startswith(":"):               # "[:python_version < '3.8']" is a marker, not an extra
                reqs.append(f"{line}; {section[1:]}")
        return reqs

    # -- advisories ---------------------------------------------------------------------------------

    def advisories(self, package, workers):
        """{advisory id: {"ids": all identifiers, "versions": affected releases}} for one package."""
        d = self.project(package)
        versions = [v for v, files in d["releases"].items() if files]
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            releases = list(pool.map(lambda v: (v, self.release(package, v)), versions))
        out = {}
        for version, rel in releases:
            for adv in (rel or {}).get("vulnerabilities") or []:
                if adv.get("withdrawn"):
                    continue
                a = out.setdefault(adv["id"], {"ids": {adv["id"]}, "versions": set()})
                a["ids"].update(adv.get("aliases") or [])
                a["versions"].add(version)
        return out


# ------------------------------------------------------------------------------------------------ helpers

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_version(v):
    try:
        return Version(v)
    except InvalidVersion:
        return None


REQUIREMENT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(\(([^)]*)\)|([^;]*))?(;(.*))?$")


def constraints_on(requirements, package):
    """Constraints that non-extra requirements place on `package`; '' means unbounded."""
    out = []
    for req in requirements or []:
        m = REQUIREMENT.match(req)
        if not m or norm(m.group(1)) != norm(package):
            continue
        if re.search(r"extra\s*==", m.group(7) or ""):
            continue
        spec = m.group(4) if m.group(4) is not None else (m.group(5) or "")
        out.append(",".join(p.strip().replace(" ", "") for p in spec.split(",") if p.strip()))
    return list(dict.fromkeys(out))


def admitted(spec, versions):
    """The versions (sorted) that the specifier admits."""
    try:
        s = SpecifierSet(spec)
    except InvalidSpecifier:
        return []
    ok = [v for v in versions if parse_version(v) is not None and s.contains(parse_version(v), prereleases=True)]
    return sorted(ok, key=Version)


def cve_key(cve):
    _, year, number = cve.split("-")
    return int(year), int(number)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def days(a, b):
    return (datetime.date.fromisoformat(b) - datetime.date.fromisoformat(a)).days


# ------------------------------------------------------------------------------------------------ the three analyses

PAIR_FIELDS = ["cve", "package", "published", "sdk", "sdk_package", "sdk_release", "release_date",
               "constraint", "first_admitted_affected", "source"]
FIX_FIELDS = ["cve", "package", "published", "fixed_releases", "upload_dates", "fix_date", "days_from_publication", "timing", "note"]
NOW_FIELDS = ["sdk", "sdk_package", "release", "release_date", "requests", "urllib3", "protobuf", "waitress",
              "still_admits", "admitted_affected_releases"]


def exposure_pairs(pypi, candidates, sdk_packages, affected):
    rows = []
    for c in candidates:
        for s in sdk_packages:
            hit = pypi.in_force(s["pypi_package"], c["published"])
            if not hit:
                continue
            release, uploaded = hit
            reqs, source = pypi.requirements(s["pypi_package"], release)
            if reqs is None:
                print(f"  warning: {s['pypi_package']} {release}: {source}")
                continue
            for spec in constraints_on(reqs, c["component"]):
                ok = admitted(spec, affected[c["component"]].get(c["cve"], []))
                rows.append({"cve": c["cve"], "package": c["component"], "published": c["published"],
                             "sdk": s["sdk"], "sdk_package": s["pypi_package"], "sdk_release": release, "release_date": uploaded,
                             "constraint": spec or "(unbounded)", "first_admitted_affected": ok[0] if ok else "", "source": source})
    return rows


def fix_timing(pypi, corpus):
    rows = []
    for c in corpus:
        if c["tier"] != "2":
            continue
        uploads = pypi.uploads(c["project"])
        fixed = c["fixed_in"].split("/")
        dates = [uploads[v][0] for v in fixed]
        fix_date = max(dates)
        lag = days(c["published"], fix_date)
        note = ""
        yanked = [v for v in fixed if uploads[v][1]]
        if yanked:                                      # a yanked release stays on PyPI but is no longer installed by default
            later = sorted((v for v, (up, y) in uploads.items() if not y and parse_version(v) is not None
                            and not parse_version(v).is_prerelease and parse_version(v) > Version(yanked[-1])), key=Version)
            note = f"{', '.join(yanked)} later yanked on PyPI"
            if later:
                note += f"; next release {later[0]} uploaded {uploads[later[0]][0]}"
        rows.append({"cve": c["cve"], "package": c["project"], "published": c["published"], "fixed_releases": "/".join(fixed),
                     "upload_dates": "/".join(dates), "fix_date": fix_date, "days_from_publication": lag,
                     "timing": "same day" if lag == 0 else ("before" if lag < 0 else "after"), "note": note})
    return rows


def constraint_snapshot(pypi, sdk_packages, corpus, affected, snapshot):
    packages = ["requests", "urllib3", "protobuf", "waitress"]
    by_package = collections.defaultdict(dict)                       # package -> {affected version: [corpus CVEs]}
    for c in corpus:
        if c["tier"] == "2":
            for v in affected[c["project"]].get(c["cve"], []):
                by_package[c["project"]].setdefault(v, []).append(c["cve"])
    rows = []
    for s in sdk_packages:
        if s["status"] != "current":
            continue
        hit = pypi.in_force(s["pypi_package"], snapshot)
        if not hit:
            continue
        release, uploaded = hit
        reqs, _ = pypi.requirements(s["pypi_package"], release)
        row = {"sdk": s["sdk"], "sdk_package": s["pypi_package"], "release": release, "release_date": uploaded}
        notes = []
        for p in packages:
            specs = constraints_on(reqs, p)
            row[p] = " | ".join(x or "(unbounded)" for x in specs)
            for spec in specs:
                ok = admitted(spec, by_package[p])
                if ok:
                    cves = sorted({cve for v in ok for cve in by_package[p][v]}, key=cve_key)
                    notes.append(f"{p} {ok[0]}..{ok[-1]} [{' '.join(cves)}]")
        row["still_admits"] = "yes" if notes else "no"
        row["admitted_affected_releases"] = "; ".join(notes)
        rows.append(row)
    return rows


# ------------------------------------------------------------------------------------------------ reporting

def compare(name, new, shipped_path, fields):
    if not os.path.exists(shipped_path):
        print(f"  {name}: nothing to compare with ({shipped_path} not found)")
        return
    old = read_csv(shipped_path)
    a = [tuple(str(r[f]) for f in fields) for r in new]
    b = [tuple(str(r.get(f, "")) for f in fields) for r in old]
    if a == b:
        print(f"  {name}: identical to the file in data/exposure/ ({len(a)} rows)")
        return
    only_new, only_old = [r for r in a if r not in b], [r for r in b if r not in a]
    print(f"  {name}: DIFFERS from the file in data/exposure/ ({len(only_new)} rows only in the rerun, {len(only_old)} only in the data)")
    for r in only_new[:15]:
        print("     rerun:", ", ".join(r))
    for r in only_old[:15]:
        print("     data :", ", ".join(r))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", default=os.path.join(ROOT, "data"), help="data directory of the package")
    ap.add_argument("--out", default=os.path.join(ROOT, "rerun"), help="where the recomputed files and the cache go")
    ap.add_argument("--snapshot", default="2026-09-28", help="date of the constraint snapshot (default: the search date)")
    ap.add_argument("--workers", type=int, default=8, help="parallel requests to PyPI")
    args = ap.parse_args()

    corpus = read_csv(os.path.join(args.data, "corpus", "corpus.csv"))
    sdk_packages = read_csv(os.path.join(args.data, "exposure", "sdk_packages.csv"))
    candidates = [c for c in read_csv(os.path.join(args.data, "selection", "candidates.csv"))
                  if c["tier"] == "2" and c["outcome"] != "not confirmed (IC3)"]
    os.makedirs(args.out, exist_ok=True)
    pypi = PyPI(os.path.join(args.out, "cache"))

    packages = sorted({c["component"] for c in candidates})
    print(f"Reading PyPI's advisories for {len(packages)} packages (the first run downloads one small file per release) ...")
    affected, advisories = {}, {}
    for p in packages:
        advisories[p] = pypi.advisories(p, args.workers)
        per_cve = collections.defaultdict(set)
        for adv in advisories[p].values():
            for i in adv["ids"]:
                if i.startswith("CVE-"):
                    per_cve[i] |= adv["versions"]
        affected[p] = {cve: [v for v in vs if parse_version(v) is not None] for cve, vs in per_cve.items()}
        print(f"  {p:<10} {len(advisories[p]):>3} advisories")

    print("\n1. Exposure test")
    pairs = exposure_pairs(pypi, candidates, sdk_packages, affected)
    included = {c["cve"] for c in candidates if c["outcome"] == "included"}
    table7 = [r for r in pairs if r["cve"] in included]                  # the pairs of Table 7
    others = [r for r in pairs if r["cve"] not in included]              # candidates excluded later, at IC4
    write_csv(os.path.join(args.out, "exposure_pairs.csv"), table7, PAIR_FIELDS)
    write_csv(os.path.join(args.out, "exposure_pairs_excluded_candidates.csv"), others, PAIR_FIELDS)
    declaring, admitting = collections.Counter(), collections.Counter()
    for r in pairs:
        declaring[r["cve"]] += 1
        admitting[r["cve"]] += bool(r["first_admitted_affected"])
    disagree = 0
    for c in candidates:
        exposed = admitting[c["cve"]] > 0
        if exposed != (c["outcome"] != "not exposed"):
            disagree += 1
            print(f"  DIFFERS: {c['cve']} is recorded as '{c['outcome']}' but {admitting[c['cve']]} pair(s) admit an affected release")
        if c["sdk_releases_declaring"] and (int(c["sdk_releases_declaring"]) != declaring[c["cve"]] or int(c["sdk_releases_admitting"]) != admitting[c["cve"]]):
            disagree += 1
            print(f"  DIFFERS: {c['cve']}: candidates.csv records {c['sdk_releases_declaring']}/{c['sdk_releases_admitting']} declaring/admitting pairs, "
                  f"the rerun finds {declaring[c['cve']]}/{admitting[c['cve']]}")
    inc = [c["cve"] for c in candidates if c["outcome"] == "included"]
    print(f"  {len(candidates)} Tier 2 candidates: {sum(1 for c in candidates if admitting[c['cve']])} exposed, "
          f"{sum(1 for c in candidates if not admitting[c['cve']])} not exposed; {disagree} disagreement(s) with candidates.csv")
    print(f"  included CVEs: {len(inc)}; pairs: {sum(declaring[c] for c in inc)}; pairs that admit an affected release: {sum(admitting[c] for c in inc)}")
    compare("exposure_pairs.csv", table7, os.path.join(args.data, "exposure", "exposure_pairs.csv"), PAIR_FIELDS)
    compare("exposure_pairs_excluded_candidates.csv", others,
            os.path.join(args.data, "exposure", "exposure_pairs_excluded_candidates.csv"), PAIR_FIELDS)

    print("\n2. Fix timing")
    timing = fix_timing(pypi, corpus)
    write_csv(os.path.join(args.out, "fix_timing.csv"), timing, FIX_FIELDS)
    count = collections.Counter(r["timing"] for r in timing)
    print(f"  fix on PyPI on or before the publication date: {count['before'] + count['same day']} of {len(timing)} "
          f"(same day: {count['same day']}, earlier: {count['before']}, later: {count['after']})")
    for r in timing:
        if r["timing"] == "after" or abs(r["days_from_publication"]) > 365:
            print(f"  {r['cve']}: fix {r['fix_date']}, published {r['published']} ({r['days_from_publication']:+d} days)")
    compare("fix_timing.csv", timing, os.path.join(args.data, "exposure", "fix_timing.csv"), FIX_FIELDS)

    print(f"\n3. Constraints of the releases current on {args.snapshot}")
    now = constraint_snapshot(pypi, sdk_packages, corpus, affected, args.snapshot)
    write_csv(os.path.join(args.out, "current_constraints.csv"), now, NOW_FIELDS)
    sdks = list(dict.fromkeys(r["sdk"] for r in now))
    still = [s for s in sdks if any(r["still_admits"] == "yes" for r in now if r["sdk"] == s)]
    print(f"  SDKs whose constraints still admit a release affected by a corpus CVE: {len(still)} of {len(sdks)} ({', '.join(still)})")
    compare("current_constraints.csv", now, os.path.join(args.data, "exposure", "current_constraints.csv"), NOW_FIELDS)

    # Advisories that PyPI lists today and that the searches of the study did not return: they were
    # published after the search date (three urllib3 advisories of 29 September 2026 at the time of writing).
    known = set()
    for name in ("screening_decisions.csv", "requests_search_records.csv"):
        path = os.path.join(args.data, "selection", name)
        if os.path.exists(path):
            for r in read_csv(path):
                known.update(r["identifiers"].split(";"))
    if known:
        print("\nAdvisories on PyPI today that are not among the records screened in the study:")
        new = set()
        for p in packages:
            for adv in advisories[p].values():
                if not (adv["ids"] & known):
                    ids = sorted(adv["ids"])
                    new.add((p, next((i for i in ids if i.startswith("CVE-")), ids[0])))
        for p, key in sorted(new):
            print(f"  {p}: {key}")
        if not new:
            print("  none")
    print(f"\nFiles written to {args.out}")


if __name__ == "__main__":
    main()
