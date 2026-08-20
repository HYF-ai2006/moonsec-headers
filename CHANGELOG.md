# Changelog

## 0.1.0 - 2026-08-20

- Added reusable security profiles for static sites, SPAs, APIs, admin consoles, docs, widgets, dashboards, downloads, Wasm edges, portals, login flows, and media CDNs.
- Added profile assessment with matched, missing, weak, conflict, optional counters and Markdown/PlainText/Checklist/JSON recommendation output.
- Added deep CSP analysis with source expression classification, directive fallback summaries, risk observations, Markdown output, and JSON output.
- Added policy builders for CSP, HSTS, Permissions-Policy, security header plans, plan validation, and runnable plan audits.
- Added extra report formats: detailed Markdown, PlainText, Checklist, and SARIF-like JSON.
- Expanded the CLI example to show both insecure-header auditing and generated static-site header plans.
- Added CI gate helpers for score thresholds, blocking findings, clean reports, and required profile checks.
- Improved profile matching for case-insensitive CSP/HSTS clauses and alternative permission clauses.
- Added contributor guidance, security reporting guidance, issue templates, PR checklist, and release reproducibility checklist.
- Expanded the test suite to 23 tests and raised effective MoonBit source size to 4649 lines.

## Initial implementation - 2026-08-02

- Added MoonBit header parser with normalized names, duplicate value storage, and parse issues.
- Added CSP parser with directive values, duplicate directive detection, and default-src fallback helpers.
- Added security audit rules for CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, and risky CORS combinations.
- Added score, grade, stable finding IDs, Markdown report export, and JSON report export.
- Added deterministic CLI smoke example at `cmd/main`.
- Added tests covering normal input, malformed input, boundary input, CSP conversion, core audit logic, and report export.
- Added README, submission document, design notes, research notes, test record, MIT license, and GitHub Actions CI.
- Filled participant submission information and updated package metadata for `HYF-ai2006/moonsec-headers`.
