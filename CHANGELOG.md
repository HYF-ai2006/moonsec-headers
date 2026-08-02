# Changelog

## 0.1.0 - 2026-08-02

- Added MoonBit header parser with normalized names, duplicate value storage, and parse issues.
- Added CSP parser with directive values, duplicate directive detection, and default-src fallback helpers.
- Added security audit rules for CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, and risky CORS combinations.
- Added score, grade, stable finding IDs, Markdown report export, and JSON report export.
- Added deterministic CLI smoke example at `cmd/main`.
- Added tests covering normal input, malformed input, boundary input, CSP conversion, core audit logic, and report export.
- Added README, submission document, design notes, research notes, test record, MIT license, and GitHub Actions CI.
- Filled participant submission information and updated package metadata for `HYF-ai2006/moonsec-headers`.
