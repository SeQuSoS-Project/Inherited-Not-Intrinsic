Inherited, Not Intrinsic

This repository contains the replication package of the paper Inherited, Not Intrinsic: An Empirical Study of Security Vulnerabilities in Quantum Programming Language Ecosystems. It holds the data behind the tables and numbers of the paper, and three Python scripts. One script recomputes the numbers of the paper from the data. The other two repeat the exposure analysis against the Python Package Index (PyPI).

How to cite

The replication package is free to use and to modify. However, you must add reference [1] in case of any publication/production/execution/etc.

[1] B. Rahman, M. Haghparast, T. Mikkonen, "Inherited, Not Intrinsic: An Empirical Study of Security Vulnerabilities in Quantum Programming Language Ecosystems," manuscript submitted to the Journal of Systems and Software, 2026. To be updated after publication.

Directory Structure

The data are organized by the steps of the study: search, selection, corpus and exposure analysis. The scripts expect this relative directory structure.

text
Inherited-Not-Intrinsic/
├── README.md
├── data/
│   ├── search/
│   │   ├── search_log.csv                          (516 rows; every search: string, database, hit count)
│   │   ├── hit_lists.csv                           (3,043 rows; the records returned by the searches of Tables 2-4)
│   │   └── tier2_declared_dependencies.csv         (268 rows; the declared dependencies behind the 90 Tier 2 names)
│   ├── selection/
│   │   ├── screening_decisions.csv                 (1,473 rows; every unique record with its decision and reason)
│   │   ├── requests_search_records.csv             (12,722 rows; the same for the separate "requests" search)
│   │   └── candidates.csv                          (84 rows; the records assessed one by one after screening)
│   ├── corpus/
│   │   └── corpus.csv                              (25 rows; the corpus of Tables 6, 8 and 9)
│   └── exposure/
│       ├── sdk_packages.csv                        (19 rows; the PyPI packages that make up each SDK)
│       ├── exposure_pairs.csv                      (25 rows; Table 7)
│       ├── exposure_pairs_excluded_candidates.csv  (94 rows; the same test for the candidates excluded at IC4)
│       ├── fix_timing.csv                          (12 rows; fix upload date against the CVE's publication date)
│       └── current_constraints.csv                 (18 rows; the constraints declared on 28 September 2026)
├── scripts/
│   ├── reproduce_numbers.py                        (recomputes the numbers of the paper from data/; no network)
│   ├── recheck_declarations.py                     (re-checks the declarations of Table 7 against PyPI)
│   └── exposure_test.py                            (repeats the exposure analysis from PyPI)
└── rerun/                                          (created when the PyPI scripts run; not in the repository)
Where each part of the paper comes from

Table and section numbers are those of the submitted manuscript.

In the paper	File
Table 1, SDK versions	data/exposure/current_constraints.csv (columns release, release_date)
Tables 2-4, hits per search string and database	data/search/search_log.csv
Section 3.1.2, the 90 package names	data/search/tier2_declared_dependencies.csv
Section 3.1.2, the requests search	data/selection/requests_search_records.csv
Section 3.2, selection counts	data/selection/screening_decisions.csv
Section 3.3, exposure and reachability checks	data/selection/candidates.csv
Tables 6, 8 and 9	data/corpus/corpus.csv
Table 7	data/exposure/exposure_pairs.csv
Section 4.2, fix timing	data/exposure/fix_timing.csv
Section 4.2, constraints on 28 September 2026	data/exposure/current_constraints.csv
Section 7, advisories without a CVE identifier	screening_decisions.csv, rows with decision = EC3
Section 7, CVEs excluded by the reachability criterion	candidates.csv, rows with outcome = not reachable (IC4)
Reproducing the results

Run the scripts from the repository root. They need Python 3.8 or later.

python3 scripts/reproduce_numbers.py

prints the numbers of the paper section by section, each computed from the files in data/, and compares them with the printed values. It ends with 89 values compared with the paper, 0 differ.

python3 scripts/recheck_declarations.py

fetches the 25 SDK releases of Table 7 from PyPI and compares the constraint each one declares on the vulnerable package with the constraint in the table. It uses the standard library only and ends with 25 pairs checked, 25 match, 0 differ.

python3 -m pip install packaging
python3 scripts/exposure_test.py

repeats the exposure analysis from PyPI alone. For each of the 64 Tier 2 candidates that reached the test it finds the release of every SDK package that was in force on the CVE's publication date, reads the declared constraint and determines the first affected release that the constraint admits. It also recomputes the fix timing and the constraint snapshot. The results go to rerun/ and are compared with the files in data/exposure/. The first run makes about 2,000 requests to PyPI and takes a few minutes; the answers are cached in rerun/cache/ (about 160 MB).

We last ran the three scripts on 26 November 2026. PyPI's advisory data keep changing, so a later run of exposure_test.py may report differences. The script also lists the advisories that PyPI holds today and that were not among the records we screened.

Notes on the data

Searches. search_log.csv has one row per search string and database: 29 Tier 1 strings, 90 Tier 2 package names and 10 Tier 3 strings in four databases. hits is the count reported in the paper. Tables 2-4 print the counts of 51 strings; each of these counts is the number of records that hit_lists.csv lists for the search. For the other 78 package names the paper reports the counts in the text of Section 3.1.2 (33,264 hits for requests, 2,201 hits for 21 names that are also common words or other products, and no record for 56 names). In hit_lists.csv each row is one record returned by one search; aliases lists the other identifiers given in the record.

Tier 2 names. tier2_declared_dependencies.csv lists the required, non-optional dependencies of the SDK releases that were current when the dependencies were recorded, on 25 March 2026 and again on 23 September 2026. The 90 search strings are the distinct names in this file, without the SDKs' own packages. The file gives the names in PyPI's normalised spelling, so the search string backports.entry-points-selectable appears in it as backports-entry-points-selectable. CUDA-Q was added to the scope after the first date.

Selection. Records that share an identifier were merged, which turns the 3,043 hits into 1,473 unique records. decision in screening_decisions.csv takes these values:

decision	Meaning	Records
EC1	lexical homonym or unrelated product	904
EC2	CVE identifier rejected or advisory withdrawn	4
EC3	not a CVE record (malicious-package report; GitHub, RustSec, Go or distribution advisory)	464
EC4	post-quantum implementation that is not on a quantum-cloud service path	25
IC3 not met	no vendor, maintainer or GitHub-reviewed advisory confirms the CVE	5
not exposed	no SDK release in force on the publication date declared the package	22
IC4 not met	no documented SDK workflow or service path reaches the vulnerable code	26
included	in the corpus	23

The paper reports the four records with a rejected or withdrawn identifier and the five unconfirmed CVEs together, as nine records. The column counted_in_paper_as gives the grouping used in Section 3.2. The requests search contributes two more CVEs, which gives the corpus of 25. requests_search_records.csv has the same columns. Of its records, 145 were also returned by the searches of Tables 2-4 (column also_in_screening_decisions); each file gives the decision for the search it belongs to.

candidates.csv holds the 84 records that were assessed one by one: the 76 that passed EC1-EC4 in the searches of Tables 2-4 and the eight CVEs of the requests library. For each record it gives the outcome, the number of SDK releases that declared the package and the number whose constraint admitted an affected release, and, for the records that failed IC4, the vulnerable code and the reason why no documented workflow reaches it.

Corpus. corpus.csv has one row per CVE. flaw and workflow carry the text of Tables 6 and 8. capec_fits is "no" where the official CAPEC pattern of the CWE does not describe the flaw (the mark § in Table 6). cvss_source is "CNA" where NIST has not scored the record. rationale states the reason for the verdict.

Exposure. sdk_packages.csv lists the PyPI packages that count as each SDK. Two legacy names are included because releases under them were in force when older CVEs were published: qiskit-terra, which carried Qiskit's code and dependencies between 2018 and 2024, and cirq, which did so until 2021. The release in force on a date is the highest final version uploaded on or before that date. A package is declared if the release requires it without an extra. Constraints are read from the release metadata on PyPI, from requires.txt in the source distribution where PyPI holds no metadata, and from the wheel where there is no source distribution. Affected releases are those to which PyPI attaches an advisory with the CVE identifier; PyPI takes these advisories from OSV. first_admitted_affected is the lowest affected release that the constraint admits and is empty where it admits none. In fix_timing.csv the fix date is the upload date of the fixed release, and the latest one where a fix was back-ported to several release lines.

Known limits
The hit counts in Tables 2-4 are the numbers of records in hit_lists.csv, the lists that we de-duplicated and screened. The lists were rebuilt from bulk copies of the databases. The counts that the search interfaces displayed on 28 September 2026 differed from them in eight of the 204 table cells, by 14 hits in total (Google Quantum, quantum, ML-DSA and kyber in the CVE List, quantum and xanadu in OSV, open quantum safe and post-quantum in the GitHub Advisory Database).
The most recent CVE record in the lists was published on 22 September 2026.
hit_lists.csv covers the 51 strings of Tables 2-4. For requests the package gives the merged records with the databases that returned them. For the other 77 package names only the counts were kept.
The databases have changed since the search date. Three urllib3 advisories (CVE-2026-97687, CVE-2026-97688 and CVE-2026-97689) were published on 29 September 2026 and appear in any later search. qiskit-ibm-runtime 0.50.0, released on 24 September 2026, declares one dependency that is not among the 90 names (qiskit-mitigation); PyPI lists no advisory for it.
Reachability ratings and QIV verdicts are our judgements, as Section 7 of the paper explains. The package records them with their rationale but cannot reproduce them mechanically.
Data sources

National Vulnerability Database (https://nvd.nist.gov), CVE List (https://www.cve.org), GitHub Advisory Database (https://github.com/advisories), OSV (https://osv.dev) and the Python Package Index (https://pypi.org). The identifiers and the short description fragments in the data files come from these databases and remain under their terms of use.

## Acknowledgements

This work has been supported by the Business Finland through project SeQuSoS (Grant No. 112/31/2024), and Research Council of Finland through project Profi 8 - qSIME (Grants No. 365343).

## Contributors
- Badhon Rahman ([@BadhonRahman01](https://github.com/BadhonRahman01)), University of Jyväskylä*
Majid Haghparast ([@MajidHaghparast](https://github.com/MajidHaghparast)), University of Jyväskylä
Tommi Mikkonen, University of Jyväskylä

Contact
Badhon Rahman <badhon.b.rahman@jyu.fi> (corresponding author)
Majid Haghparast <majid.m.haghparast@jyu.fi>
