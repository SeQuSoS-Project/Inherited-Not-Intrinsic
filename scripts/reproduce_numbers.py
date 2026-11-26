#!/usr/bin/env python3
"""Recompute the numbers reported in the paper from the files in data/.

Each line shows a value computed from the data and, where the paper prints that value, the value
as printed. The script needs no network and only the Python standard library:

    python3 scripts/reproduce_numbers.py

It exits with status 1 if a computed value differs from the printed one.
"""
import collections
import csv
import datetime
import os
import sys

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DATABASES = ["NVD", "CVE List", "GHSA", "OSV"]


def read(*path):
    with open(os.path.join(DATA, *path), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


checked = differing = 0


def show(label, value, paper=None):
    """Print one value; compare it with the value printed in the paper if one is given."""
    global checked, differing
    text = f"{value:,}" if isinstance(value, int) else str(value)
    line = f"  {label:<74} {text}"
    if paper is not None:
        checked += 1
        if value != paper:
            differing += 1
            line += f"   <-- the paper prints {paper}"
    print(line)


def head(title):
    print(f"\n{title}")


def per_db(rows):
    return "/".join(str(sum(int(r["hits"]) for r in rows if r["database"] == d)) for d in DATABASES)


def share(part, whole):
    return f"{round(100 * part / whole)}%"


log = read("search", "search_log.csv")
hits = read("search", "hit_lists.csv")
declared = read("search", "tier2_declared_dependencies.csv")
screening = read("selection", "screening_decisions.csv")
requests_records = read("selection", "requests_search_records.csv")
candidates = read("selection", "candidates.csv")
corpus = read("corpus", "corpus.csv")
pairs = read("exposure", "exposure_pairs.csv")
timing = read("exposure", "fix_timing.csv")
current = read("exposure", "current_constraints.csv")
sdk_packages = read("exposure", "sdk_packages.csv")

by_string = collections.defaultdict(int)
for r in log:
    by_string[(r["tier"], r["search_string"])] += int(r["hits"])
tier = {t: [r for r in log if r["tier"] == t] for t in "123"}
tabulated = [r for r in log if r["reported_in"].startswith("Table")]

# ------------------------------------------------------------------------------------------------
head("Section 3.1.1 and Table 2: Tier 1 searches")
show("search strings", len({r["search_string"] for r in tier["1"]}), 29)
show("searches (string x database)", len(tier["1"]), 116)
show("hits", sum(int(r["hits"]) for r in tier["1"]), 1164)
show("hits per database (NVD/CVE List/GHSA/OSV)", per_db(tier["1"]), "245/267/239/413")
show("hits for 'quantum'", by_string[("1", "quantum")], 841)
show("hits for 'xanadu'", by_string[("1", "xanadu")], 208)
show("share of the two strings", share(by_string[("1", "quantum")] + by_string[("1", "xanadu")], sum(int(r["hits"]) for r in tier["1"])), "90%")
show("strings with no record in any database", sum(1 for (t, s), n in by_string.items() if t == "1" and n == 0), 11)

head("Section 3.1.2 and Table 3: Tier 2 searches")
names = {r["search_string"] for r in tier["2"]}
show("package names searched", len(names), 90)
show("distinct dependencies declared by the SDK releases", len({r["dependency"] for r in declared if r["tier2_search_string"] == "yes"}), 90)
tab3 = [r for r in tier["2"] if r["reported_in"] == "Table 3"]
show("packages in Table 3", len({r["search_string"] for r in tab3}), 12)
show("searches in Table 3", len(tab3), 48)
show("hits in Table 3", sum(int(r["hits"]) for r in tab3), 1591)
show("hits per database", per_db(tab3), "408/439/627/117")
req = [r for r in tier["2"] if r["search_string"] == "requests"]
show("hits for 'requests'", sum(int(r["hits"]) for r in req), 33264)
show("share of 'requests' in all Tier 2 hits", share(sum(int(r["hits"]) for r in req), sum(int(r["hits"]) for r in tier["2"])), "90%")
show("OSV records for 'requests'", next(int(r["hits"]) for r in req if r["database"] == "OSV"), 16)
show("CVEs that concern the requests library", sum(1 for r in requests_records if r["pypi_package"] == "requests"), 8)
show("unique records of the 'requests' search", len(requests_records))
show("hits of those records", sum(int(r["hits"]) for r in requests_records), 33264)
sept = max(r["snapshot_date"] for r in declared)
sdk_of = {r["pypi_package"]: r["sdk"] for r in sdk_packages}
show("SDKs that declare requests", len({sdk_of[r["sdk_package"]] for r in declared if r["dependency"] == "requests" and r["snapshot_date"] == sept}), 6)
homonym = {s for s in names if any(r["search_string"] == s and "common word" in r["reported_in"] for r in tier["2"])}
show("package names that are common words or other products", len(homonym), 21)
show("their hits", sum(by_string[("2", s)] for s in homonym), 2201)
for s, n in (("deprecated", 854), ("attrs", 265), ("cma", 260), ("packaging", 219), ("jax", 205), ("toml", 185)):
    show(f"   hits for '{s}'", by_string[("2", s)], n)
zero = {s for s in names if by_string[("2", s)] == 0}
show("package names with no record in any database", len(zero), 56)
cuda = {r["dependency"] for r in declared if r["sdk_package"].startswith("cuda-quantum")}
show("   of which declared only by CUDA-Q", len(cuda & zero), 21)

head("Section 3.1.3 and Table 4: Tier 3 searches")
show("search strings", len({r["search_string"] for r in tier["3"]}), 10)
show("searches", len(tier["3"]), 40)
show("hits", sum(int(r["hits"]) for r in tier["3"]), 288)
show("hits per database", per_db(tier["3"]), "54/90/97/47")

head("All searches")
show("search strings", len(by_string), 129)
show("hits in Tables 2-4", sum(int(r["hits"]) for r in tabulated), 3043)
listed = collections.Counter((r["tier"], r["search_string"], r["database"]) for r in hits)
show("records in hit_lists.csv", len(hits), 3043)
show("table cells whose count differs from the records listed for the search",
     sum(1 for r in tabulated if int(r["hits"]) != listed[(r["tier"], r["search_string"], r["database"])]), 0)

# ------------------------------------------------------------------------------------------------
head("Section 3.2: selection")
decision = collections.Counter(r["decision"] for r in screening)
counted = collections.Counter(r["counted_in_paper_as"] for r in screening)
show("unique records", len(screening), 1473)
show("duplicates (hits minus unique records)", len(hits) - len(screening), 1570)
show("EC1, homonym or unrelated product", counted["EC1"], 904)
show("EC2, as counted in the paper", counted["EC2"], 9)
show("   rejected or withdrawn identifier (EC2)", decision["EC2"])
show("   not confirmed by a vendor or reviewed advisory (IC3)", decision["IC3 not met"])
show("EC3, not a CVE record", counted["EC3"], 464)
for kind, n in collections.Counter(r["reason"].split(": ", 1)[1] for r in screening if r["decision"] == "EC3").most_common():
    show(f"   {kind}", n)
show("EC4, post-quantum implementation off the service path", counted["EC4"], 25)
remaining = len(screening) - counted["EC1"] - counted["EC2"] - counted["EC3"] - counted["EC4"]
show("records remaining", remaining, 71)
show("removed by the exposure and reachability checks", counted["removed after screening"], 48)
show("   not exposed", decision["not exposed"])
show("   not reachable (IC4)", decision["IC4 not met"])
show("included from the searches of Tables 2-4", decision["included"], 23)
show("included from the 'requests' search", sum(1 for r in requests_records if r["decision"] == "included"), 2)
show("CVEs in the corpus", len(corpus), 25)

# ------------------------------------------------------------------------------------------------
head("Table 6 and abstract: the corpus")
by_tier = collections.Counter(r["tier"] for r in corpus)
show("Tier 1 / Tier 2 / Tier 3", f"{by_tier['1']}/{by_tier['2']}/{by_tier['3']}", "8/12/5")
verdict = collections.Counter(r["verdict"] for r in corpus)
qiv = verdict["QIV-A"] + verdict["QIV-B"] + verdict["QIV-B*"]
show("intrinsic (I)", verdict["I"], 2)
show("unclassifiable (U)", verdict["U"], 1)
show("quantum-inherited (QIV)", qiv, 17)
show("   artefact-borne (QIV-A)", verdict["QIV-A"], 4)
show("   boundary-borne (QIV-B)", verdict["QIV-B"])
show("   boundary-borne, conditional C2 (QIV-B*)", verdict["QIV-B*"])
show("ordinary supply-chain (OSV)", verdict["OSV"], 5)
show("records that meet C1 (inherited origin)", sum(1 for r in corpus if r["c1_inherited_origin"] == "met"))
show("CVSS scores assigned by the CNA only", sum(1 for r in corpus if r["cvss_source"] == "CNA"))
show("reachability H / M", "/".join(str(sum(1 for r in corpus if r["reachability"] == x)) for x in "HM"))

head("Table 9: weakness classes by tier")
paper9 = {"Unsafe deserialization": "5/0/0", "Input validation & resource exhaustion": "1/7/0",
          "Information exposure & side channels": "0/3/3", "Memory safety": "1/0/1", "Trust & authentication": "0/2/0",
          "Cryptographic weakness": "0/0/1", "Insufficient information": "1/0/0"}
for cls, expected in paper9.items():
    rows = [r for r in corpus if r["weakness_class"] == cls]
    cwes = sorted({int(r["cwe"][4:]) for r in rows if r["cwe"]})
    show(f"{cls} (Tier 1/2/3)", "/".join(str(sum(1 for r in rows if r["tier"] == t)) for t in "123"), expected)
    show("   CWEs", ", ".join(map(str, cwes)) or "none")

# ------------------------------------------------------------------------------------------------
head("Section 4.1: results per tier")
t1 = [r for r in corpus if r["tier"] == "1"]
project = collections.Counter(r["project"] for r in t1)
show("Tier 1: Qiskit / IBM Runtime / Braket SDK / CUDA-Q / Q#",
     "/".join(str(project[p]) for p in ("Qiskit", "Qiskit IBM Runtime", "Amazon Braket SDK", "CUDA-Q", "Q# / QDK")), "4/1/1/1/1")
show("Tier 1 published from March 2024 onwards", sum(1 for r in t1 if r["published"] >= "2024-03"), 7)
show("Tier 1 published in 2026", sum(1 for r in t1 if r["published"].startswith("2026")), 4)
show("Tier 1 with CWE-502", sum(1 for r in t1 if r["cwe"] == "CWE-502"), 5)
show("   of which in the QPY reader", sum(1 for r in t1 if r["cwe"] == "CWE-502" and r["component"] == "Qiskit QPY"), 3)
t2 = [r for r in corpus if r["tier"] == "2"]
package = collections.Counter(r["project"] for r in t2)
show("Tier 2: urllib3 / waitress / requests / protobuf", "/".join(str(package[p]) for p in ("urllib3", "waitress", "requests", "protobuf")), "7/2/2/1")
unreachable = collections.Counter(r["component"] for r in candidates if r["outcome"] == "not reachable (IC4)")
numerical = ["numpy", "scipy", "joblib", "tqdm", "psutil"]
show("numerical and utility candidates that fail reachability", sum(unreachable[p] for p in numerical), 12)
show("   numpy / scipy / joblib / tqdm / psutil", "/".join(str(unreachable[p]) for p in numerical), "8/1/1/1/1")
bombs = sorted(r["published"] for r in t2 if r["project"] == "urllib3" and "decompression" in r["flaw"])
span = (datetime.date.fromisoformat(bombs[-1]) - datetime.date.fromisoformat(bombs[0])).days
show("urllib3 decompression CVEs", len(bombs), 3)
show("   days between the first and the last", span)
show("   share of Tier 2", share(len(bombs), len(t2)), "25%")
t3 = collections.Counter(r["project"] for r in corpus if r["tier"] == "3")
show("Tier 3: liboqs / oqs-provider", f"{t3['liboqs']}/{t3['oqs-provider']}")
show("liboqs candidates that fail reachability", unreachable["liboqs"], 2)

head("Section 4.2 and Table 7: exposure")
admitting = [r for r in pairs if r["first_admitted_affected"]]
show("(SDK release, CVE) pairs", len(pairs), 25)
show("pairs whose constraint admits an affected release", len(admitting), 24)
show("   share", share(len(admitting), len(pairs)), "96%")
show("pairs with an unbounded declaration", sum(1 for r in pairs if r["constraint"] == "(unbounded)"), 5)
show("pairs read from the source distribution", sum(1 for r in pairs if r["source"] == "sdist"), 3)
show("   their SDKs", ", ".join(sorted({r["sdk"] for r in pairs if r["source"] == "sdist"})))
show("   latest of their release dates", max(r["release_date"] for r in pairs if r["source"] == "sdist"))
on_time = [r for r in timing if int(r["days_from_publication"]) <= 0]
show("CVEs whose fix was on PyPI on or before publication", f"{len(on_time)} of {len(timing)}", "11 of 12")
show("   fix uploaded on the day of publication", sum(1 for r in timing if r["timing"] == "same day"), 8)
late = [r for r in timing if int(r["days_from_publication"]) > 0]
show("   fix uploaded later", ", ".join(f"{r['cve']} (+{r['days_from_publication']} days)" for r in late), "CVE-2018-18074 (+9 days)")
early = min(timing, key=lambda r: int(r["days_from_publication"]))
show("   earliest fix relative to publication", f"{early['cve']} ({-int(early['days_from_publication']) / 365.25:.1f} years before)", "CVE-2018-25091 (4.5 years before)")
sdks = list(dict.fromkeys(r["sdk"] for r in current))
still = [s for s in sdks if any(r["still_admits"] == "yes" for r in current if r["sdk"] == s)]
show("SDKs that still admit an affected release on 28 September 2026", f"{len(still)} of {len(sdks)}", "4 of 12")
show("   which", ", ".join(still))

head("Section 5 and Section 7")
show("corpus CVEs with CVSS 7.0 or higher", sum(1 for r in corpus if float(r["cvss"]) >= 7.0), 17)
scored = sorted((r for r in candidates if r["tier"] == "2" and r["cvss"]), key=lambda r: -float(r["cvss"]))
show("two highest-scored dependency candidates", " and ".join(f"{r['cve']} ({r['component']}, {r['cvss']})" for r in scored[:2]))
show("   reachable from a documented workflow", sum(1 for r in scored[:2] if r["outcome"] == "included"), 0)
show("Tier 1 CVEs that are parsing or deserialization bugs", sum(1 for r in t1 if r["cwe"] in ("CWE-502", "CWE-674")), 6)
show("QIVs among the records that meet C1", f"{qiv} of {sum(1 for r in corpus if r['c1_inherited_origin'] == 'met')}")
show("projects with a Tier 1 entry", len(project), 5)
families = list(dict.fromkeys(r["sdk"] for r in sdk_packages))
show("SDKs without any record", f"{len(families) - len([p for p in project if p in families])} of {len(families)}", "8 of 12")
show("advisories without a CVE identifier (EC3)", counted["EC3"], 464)

print(f"\n{checked} values compared with the paper, {differing} differ.")
sys.exit(1 if differing else 0)
