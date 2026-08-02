///|
/// moonsec-headers audits HTTP response security headers from plain text.
///
/// The library intentionally accepts raw header blocks instead of performing
/// network requests. That keeps it deterministic for CI, Wasm, and offline
/// resource pipelines.
pub(all) enum Severity {
  Critical
  High
  Medium
  Low
  Info
} derive(Eq, Debug)

///|
pub(all) enum ParseIssueKind {
  EmptyName
  MissingColon
  ControlCharacter
  EmptyDirective
  DuplicateDirective
  InvalidToken
} derive(Eq, Debug)

///|
pub(all) struct ParseIssue {
  kind : ParseIssueKind
  line : Int
  name : String
  message : String
} derive(Eq, Debug)

///|
pub(all) struct Header {
  name : String
  value : String
  line : Int
} derive(Eq, Debug)

///|
pub(all) struct HeaderSet {
  headers : Array[Header]
  index : Map[String, Array[String]]
  issues : Array[ParseIssue]
} derive(Eq, Debug)

///|
pub(all) struct Directive {
  name : String
  values : Array[String]
} derive(Eq, Debug)

///|
pub(all) struct CspPolicy {
  raw : String
  directives : Array[Directive]
  duplicates : Array[String]
  issues : Array[ParseIssue]
} derive(Eq, Debug)

///|
pub(all) struct Finding {
  id : String
  severity : Severity
  header : String
  message : String
  evidence : String
  remediation : String
} derive(Eq, Debug)

///|
pub(all) struct AuditReport {
  score : Int
  grade : String
  findings : Array[Finding]
  headers : HeaderSet
} derive(Eq, Debug)

///|
pub fn Severity::weight(self : Severity) -> Int {
  match self {
    Critical => 30
    High => 20
    Medium => 10
    Low => 4
    Info => 0
  }
}

///|
pub fn Severity::label(self : Severity) -> String {
  match self {
    Critical => "critical"
    High => "high"
    Medium => "medium"
    Low => "low"
    Info => "info"
  }
}

///|
pub fn ParseIssueKind::label(self : ParseIssueKind) -> String {
  match self {
    EmptyName => "empty-name"
    MissingColon => "missing-colon"
    ControlCharacter => "control-character"
    EmptyDirective => "empty-directive"
    DuplicateDirective => "duplicate-directive"
    InvalidToken => "invalid-token"
  }
}

///|
pub fn normalize_header_name(name : StringView) -> String {
  name.trim().to_lower().to_owned()
}

///|
pub fn is_known_security_header(name : StringView) -> Bool {
  let n = normalize_header_name(name)
  n == "content-security-policy" ||
  n == "content-security-policy-report-only" ||
  n == "strict-transport-security" ||
  n == "x-content-type-options" ||
  n == "x-frame-options" ||
  n == "referrer-policy" ||
  n == "permissions-policy" ||
  n == "cross-origin-opener-policy" ||
  n == "cross-origin-resource-policy" ||
  n == "cross-origin-embedder-policy" ||
  n == "access-control-allow-origin" ||
  n == "access-control-allow-credentials"
}

///|
pub fn parse_header_line(
  line : StringView,
  line_number : Int,
) -> Result[Header, ParseIssue] {
  match line.split_once(":") {
    Some((name_view, value_view)) => {
      let name = normalize_header_name(name_view)
      let value = value_view.trim().to_owned()
      if name.is_empty() {
        Err({
          kind: EmptyName,
          line: line_number,
          name: "",
          message: "header name is empty",
        })
      } else if has_control_character(name) || has_control_character(value) {
        Err({
          kind: ControlCharacter,
          line: line_number,
          name,
          message: "header contains a control character",
        })
      } else {
        Ok({ name, value, line: line_number })
      }
    }
    None =>
      Err({
        kind: MissingColon,
        line: line_number,
        name: "",
        message: "header line must contain ':'",
      })
  }
}

///|
pub fn parse_headers(raw : StringView) -> HeaderSet {
  let headers : Array[Header] = []
  let issues : Array[ParseIssue] = []
  let index : Map[String, Array[String]] = Map([])
  for line_number, line in raw.split("\n").iter2() {
    let trimmed = line.trim()
    if !trimmed.is_empty() {
      match parse_header_line(trimmed, line_number + 1) {
        Ok(header) => {
          let values = index.get_or_init(header.name, () => [])
          values.push(header.value)
          headers.push(header)
        }
        Err(issue) => issues.push(issue)
      }
    }
  }
  { headers, index, issues }
}

///|
pub fn HeaderSet::has(self : HeaderSet, name : StringView) -> Bool {
  self.index.contains(normalize_header_name(name))
}

///|
pub fn HeaderSet::get(self : HeaderSet, name : StringView) -> String? {
  match self.index.get(normalize_header_name(name)) {
    Some(values) =>
      match values.get(0) {
        Some(value) => Some(value)
        None => None
      }
    None => None
  }
}

///|
pub fn HeaderSet::get_all(self : HeaderSet, name : StringView) -> Array[String] {
  match self.index.get(normalize_header_name(name)) {
    Some(values) => values.copy()
    None => []
  }
}

///|
pub fn HeaderSet::security_headers(self : HeaderSet) -> Array[Header] {
  self.headers.filter(header => is_known_security_header(header.name))
}

///|
pub fn parse_csp(value : StringView) -> CspPolicy {
  let directives : Array[Directive] = []
  let duplicates : Array[String] = []
  let issues : Array[ParseIssue] = []
  let seen : Map[String, Bool] = Map([])
  for offset, raw_part in value.split(";").iter2() {
    let part = raw_part.trim()
    if !part.is_empty() {
      let tokens = split_ascii_words(part)
      if tokens.is_empty() {
        issues.push({
          kind: EmptyDirective,
          line: offset + 1,
          name: "",
          message: "CSP directive is empty",
        })
      } else {
        let name = tokens[0].to_lower()
        if seen.contains(name) {
          duplicates.push(name)
          issues.push({
            kind: DuplicateDirective,
            line: offset + 1,
            name,
            message: "CSP directive appears more than once; later values are ignored by browsers",
          })
        } else {
          seen.set(name, true)
        }
        let values : Array[String] = []
        for i in 1..<tokens.length() {
          values.push(tokens[i])
        }
        directives.push({ name, values })
      }
    }
  }
  { raw: value.to_owned(), directives, duplicates, issues }
}

///|
pub fn CspPolicy::has_directive(self : CspPolicy, name : StringView) -> Bool {
  self.directive(name) is Some(_)
}

///|
pub fn CspPolicy::directive(self : CspPolicy, name : StringView) -> Directive? {
  let expected = name.trim().to_lower().to_owned()
  self.directives.iter().find_first(d => d.name == expected)
}

///|
pub fn CspPolicy::values_for(
  self : CspPolicy,
  name : StringView,
) -> Array[String] {
  match self.directive(name) {
    Some(d) => d.values.copy()
    None => []
  }
}

///|
pub fn CspPolicy::effective_values(
  self : CspPolicy,
  name : StringView,
) -> Array[String] {
  match self.directive(name) {
    Some(d) => d.values.copy()
    None =>
      match self.directive("default-src") {
        Some(d) => d.values.copy()
        None => []
      }
  }
}

///|
pub fn audit_headers(raw : StringView) -> AuditReport {
  audit_header_set(parse_headers(raw))
}

///|
pub fn audit_header_set(headers : HeaderSet) -> AuditReport {
  let findings : Array[Finding] = []
  for issue in headers.issues {
    findings.push({
      id: "parse." + issue.kind.label(),
      severity: Medium,
      header: "headers",
      message: issue.message,
      evidence: "line " + issue.line.to_string(),
      remediation: "Keep every input line in the form 'Header-Name: value'.",
    })
  }
  audit_csp(headers, findings)
  audit_hsts(headers, findings)
  audit_x_content_type_options(headers, findings)
  audit_frame_controls(headers, findings)
  audit_referrer_policy(headers, findings)
  audit_permissions_policy(headers, findings)
  audit_cross_origin_isolation(headers, findings)
  audit_cors(headers, findings)
  let score = score_findings(findings)
  { score, grade: grade_score(score), findings, headers }
}

///|
fn audit_csp(headers : HeaderSet, findings : Array[Finding]) -> Unit {
  match headers.get("content-security-policy") {
    Some(value) => {
      let policy = parse_csp(value)
      for issue in policy.issues {
        findings.push({
          id: "csp." + issue.kind.label(),
          severity: Low,
          header: "content-security-policy",
          message: issue.message,
          evidence: issue.name,
          remediation: "Declare each CSP directive at most once.",
        })
      }
      let script_values = policy.effective_values("script-src")
      let default_values = policy.values_for("default-src")
      if default_values.is_empty() && script_values.is_empty() {
        findings.push({
          id: "csp.missing-default-src",
          severity: Medium,
          header: "content-security-policy",
          message: "CSP does not provide default-src or script-src fallback.",
          evidence: value,
          remediation: "Add at least default-src 'self' or a stricter directive set.",
        })
      }
      if contains_token(script_values, "'unsafe-inline'") {
        findings.push({
          id: "csp.unsafe-inline-script",
          severity: High,
          header: "content-security-policy",
          message: "script-src allows 'unsafe-inline'.",
          evidence: join_tokens(script_values),
          remediation: "Prefer nonces, hashes, or external scripts without unsafe inline execution.",
        })
      }
      if contains_token(script_values, "'unsafe-eval'") {
        findings.push({
          id: "csp.unsafe-eval",
          severity: High,
          header: "content-security-policy",
          message: "script-src allows 'unsafe-eval'.",
          evidence: join_tokens(script_values),
          remediation: "Remove 'unsafe-eval' and replace dynamic code evaluation.",
        })
      }
      if contains_token(script_values, "*") {
        findings.push({
          id: "csp.wildcard-script",
          severity: High,
          header: "content-security-policy",
          message: "script-src allows every origin.",
          evidence: join_tokens(script_values),
          remediation: "List trusted script origins explicitly.",
        })
      }
      if contains_http_scheme(script_values) {
        findings.push({
          id: "csp.http-script-source",
          severity: Medium,
          header: "content-security-policy",
          message: "script-src contains an insecure http: source.",
          evidence: join_tokens(script_values),
          remediation: "Use https: sources or hostnames that are always served over TLS.",
        })
      }
      if !directive_is_none(policy, "object-src") {
        findings.push({
          id: "csp.object-src-not-none",
          severity: Medium,
          header: "content-security-policy",
          message: "object-src is absent or not restricted to 'none'.",
          evidence: policy.values_for("object-src").join(" "),
          remediation: "Add object-src 'none' to block legacy plugin surfaces.",
        })
      }
      if !directive_mentions_self_or_none(policy, "base-uri") {
        findings.push({
          id: "csp.base-uri-missing",
          severity: Medium,
          header: "content-security-policy",
          message: "base-uri is absent or too broad.",
          evidence: policy.values_for("base-uri").join(" "),
          remediation: "Add base-uri 'self' or base-uri 'none'.",
        })
      }
      if !policy.has_directive("frame-ancestors") &&
        !headers.has("x-frame-options") {
        findings.push({
          id: "csp.frame-ancestors-missing",
          severity: Medium,
          header: "content-security-policy",
          message: "No clickjacking protection was found.",
          evidence: "frame-ancestors and x-frame-options are both absent",
          remediation: "Add frame-ancestors 'none' or 'self'.",
        })
      }
    }
    None =>
      findings.push({
        id: "csp.missing",
        severity: High,
        header: "content-security-policy",
        message: "Content-Security-Policy is missing.",
        evidence: "",
        remediation: "Add a site-specific CSP starting with default-src 'self'.",
      })
  }
}

///|
fn audit_hsts(headers : HeaderSet, findings : Array[Finding]) -> Unit {
  match headers.get("strict-transport-security") {
    Some(value) => {
      let lowered = value.to_lower()
      let max_age = parse_hsts_max_age(lowered)
      match max_age {
        Some(seconds) =>
          if seconds < 15552000 {
            findings.push({
              id: "hsts.max-age-short",
              severity: Medium,
              header: "strict-transport-security",
              message: "HSTS max-age is shorter than 180 days.",
              evidence: seconds.to_string(),
              remediation: "Use max-age=31536000 once HTTPS is stable for the whole site.",
            })
          }
        None =>
          findings.push({
            id: "hsts.max-age-missing",
            severity: High,
            header: "strict-transport-security",
            message: "HSTS is present but max-age is missing or invalid.",
            evidence: value,
            remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
          })
      }
      if !lowered.contains("includesubdomains") {
        findings.push({
          id: "hsts.include-subdomains-missing",
          severity: Low,
          header: "strict-transport-security",
          message: "HSTS does not include subdomains.",
          evidence: value,
          remediation: "Add includeSubDomains when all subdomains are HTTPS ready.",
        })
      }
    }
    None =>
      findings.push({
        id: "hsts.missing",
        severity: Medium,
        header: "strict-transport-security",
        message: "Strict-Transport-Security is missing.",
        evidence: "",
        remediation: "Add an HSTS header for HTTPS responses.",
      })
  }
}

///|
fn audit_x_content_type_options(
  headers : HeaderSet,
  findings : Array[Finding],
) -> Unit {
  match headers.get("x-content-type-options") {
    Some(value) =>
      if value.to_lower().trim().to_owned() != "nosniff" {
        findings.push({
          id: "xcto.invalid",
          severity: Medium,
          header: "x-content-type-options",
          message: "X-Content-Type-Options is not set to nosniff.",
          evidence: value,
          remediation: "Use X-Content-Type-Options: nosniff.",
        })
      }
    None =>
      findings.push({
        id: "xcto.missing",
        severity: Low,
        header: "x-content-type-options",
        message: "X-Content-Type-Options is missing.",
        evidence: "",
        remediation: "Add X-Content-Type-Options: nosniff.",
      })
  }
}

///|
fn audit_frame_controls(headers : HeaderSet, findings : Array[Finding]) -> Unit {
  let has_frame_ancestors = match headers.get("content-security-policy") {
    Some(value) => parse_csp(value).has_directive("frame-ancestors")
    None => false
  }
  match headers.get("x-frame-options") {
    Some(value) => {
      let v = value.to_lower().trim().to_owned()
      if v != "deny" && v != "sameorigin" {
        findings.push({
          id: "xfo.invalid",
          severity: Medium,
          header: "x-frame-options",
          message: "X-Frame-Options is neither DENY nor SAMEORIGIN.",
          evidence: value,
          remediation: "Use DENY, SAMEORIGIN, or prefer CSP frame-ancestors.",
        })
      }
    }
    None =>
      if !has_frame_ancestors {
        findings.push({
          id: "xfo.missing",
          severity: Low,
          header: "x-frame-options",
          message: "X-Frame-Options is missing and CSP frame-ancestors is absent.",
          evidence: "",
          remediation: "Add CSP frame-ancestors or X-Frame-Options.",
        })
      }
  }
}

///|
fn audit_referrer_policy(
  headers : HeaderSet,
  findings : Array[Finding],
) -> Unit {
  match headers.get("referrer-policy") {
    Some(value) => {
      let v = value.to_lower().trim().to_owned()
      if v == "unsafe-url" {
        findings.push({
          id: "referrer.unsafe-url",
          severity: High,
          header: "referrer-policy",
          message: "Referrer-Policy unsafe-url can leak full URLs to third-party origins.",
          evidence: value,
          remediation: "Use strict-origin-when-cross-origin, same-origin, or no-referrer.",
        })
      } else if v == "no-referrer-when-downgrade" {
        findings.push({
          id: "referrer.legacy-default",
          severity: Medium,
          header: "referrer-policy",
          message: "Referrer-Policy uses the legacy browser default.",
          evidence: value,
          remediation: "Use strict-origin-when-cross-origin or stricter.",
        })
      }
    }
    None =>
      findings.push({
        id: "referrer.missing",
        severity: Low,
        header: "referrer-policy",
        message: "Referrer-Policy is missing.",
        evidence: "",
        remediation: "Add Referrer-Policy: strict-origin-when-cross-origin or stricter.",
      })
  }
}

///|
fn audit_permissions_policy(
  headers : HeaderSet,
  findings : Array[Finding],
) -> Unit {
  match headers.get("permissions-policy") {
    Some(value) => {
      let lower = value.to_lower()
      for feature in ["camera", "microphone", "geolocation"] {
        if !permissions_policy_disables(lower, feature) {
          findings.push({
            id: "permissions." + feature + "-not-disabled",
            severity: Low,
            header: "permissions-policy",
            message: "Permissions-Policy does not explicitly disable " +
            feature +
            ".",
            evidence: value,
            remediation: "Use " +
            feature +
            "=() unless the feature is required.",
          })
        }
      }
    }
    None =>
      findings.push({
        id: "permissions.missing",
        severity: Info,
        header: "permissions-policy",
        message: "Permissions-Policy is missing.",
        evidence: "",
        remediation: "Add a Permissions-Policy for high-risk browser features.",
      })
  }
}

///|
fn audit_cross_origin_isolation(
  headers : HeaderSet,
  findings : Array[Finding],
) -> Unit {
  match headers.get("cross-origin-opener-policy") {
    Some(value) => {
      let v = value.to_lower().trim().to_owned()
      if v != "same-origin" && v != "same-origin-allow-popups" {
        findings.push({
          id: "coop.weak",
          severity: Low,
          header: "cross-origin-opener-policy",
          message: "Cross-Origin-Opener-Policy is present but weak.",
          evidence: value,
          remediation: "Use same-origin for isolated applications.",
        })
      }
    }
    None =>
      findings.push({
        id: "coop.missing",
        severity: Info,
        header: "cross-origin-opener-policy",
        message: "Cross-Origin-Opener-Policy is missing.",
        evidence: "",
        remediation: "Add COOP when the application needs cross-origin isolation.",
      })
  }
  match headers.get("cross-origin-resource-policy") {
    Some(value) => {
      let v = value.to_lower().trim().to_owned()
      if v != "same-origin" && v != "same-site" && v != "cross-origin" {
        findings.push({
          id: "corp.invalid",
          severity: Low,
          header: "cross-origin-resource-policy",
          message: "Cross-Origin-Resource-Policy has an unrecognized value.",
          evidence: value,
          remediation: "Use same-origin, same-site, or cross-origin.",
        })
      }
    }
    None =>
      findings.push({
        id: "corp.missing",
        severity: Info,
        header: "cross-origin-resource-policy",
        message: "Cross-Origin-Resource-Policy is missing.",
        evidence: "",
        remediation: "Add CORP for resources that should not be embedded cross-origin.",
      })
  }
}

///|
fn audit_cors(headers : HeaderSet, findings : Array[Finding]) -> Unit {
  let origin = headers.get("access-control-allow-origin")
  let credentials = headers.get("access-control-allow-credentials")
  match (origin, credentials) {
    (Some(o), Some(c)) =>
      if o.trim().to_owned() == "*" && c.to_lower().trim().to_owned() == "true" {
        findings.push({
          id: "cors.wildcard-with-credentials",
          severity: High,
          header: "access-control-allow-origin",
          message: "CORS allows every origin while credentials are enabled.",
          evidence: "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
          remediation: "Echo only allowlisted origins when credentials are required.",
        })
      }
    _ => ()
  }
}

///|
pub fn score_findings(findings : Array[Finding]) -> Int {
  let mut score = 100
  for finding in findings {
    score = score - finding.severity.weight()
  }
  if score < 0 {
    0
  } else {
    score
  }
}

///|
pub fn grade_score(score : Int) -> String {
  if score >= 90 {
    "A"
  } else if score >= 75 {
    "B"
  } else if score >= 60 {
    "C"
  } else if score >= 40 {
    "D"
  } else {
    "F"
  }
}

///|
pub fn AuditReport::count_by_severity(
  self : AuditReport,
  severity : Severity,
) -> Int {
  self.findings.count_if(f => f.severity == severity)
}

///|
pub fn AuditReport::has_finding(self : AuditReport, id : StringView) -> Bool {
  let expected = id.to_owned()
  self.findings.any(f => f.id == expected)
}

///|
pub fn AuditReport::to_markdown(self : AuditReport) -> String {
  let lines : Array[String] = []
  lines.push("# Security Header Audit")
  lines.push("")
  lines.push("- Score: " + self.score.to_string())
  lines.push("- Grade: " + self.grade)
  lines.push("- Findings: " + self.findings.length().to_string())
  lines.push("")
  lines.push("| Severity | Header | Finding |")
  lines.push("| --- | --- | --- |")
  for finding in self.findings {
    lines.push(
      "| " +
      finding.severity.label() +
      " | " +
      finding.header +
      " | " +
      finding.message.replace_all(old="|", new="\\|") +
      " |",
    )
  }
  lines.join("\n")
}

///|
pub fn AuditReport::to_json_string(self : AuditReport) -> String {
  let finding_values : Array[Json] = []
  for finding in self.findings {
    finding_values.push(finding_to_json(finding))
  }
  let header_values : Array[Json] = []
  for header in self.headers.headers {
    header_values.push(
      Json::object(
        Map([
          ("name", Json::string(header.name)),
          ("value", Json::string(header.value)),
          (
            "line",
            Json::number(header.line.to_double(), repr=header.line.to_string()),
          ),
        ]),
      ),
    )
  }
  Json::object(
    Map([
      (
        "score",
        Json::number(self.score.to_double(), repr=self.score.to_string()),
      ),
      ("grade", Json::string(self.grade)),
      ("findings", Json::array(finding_values)),
      ("headers", Json::array(header_values)),
    ]),
  ).stringify(indent=2)
}

///|
fn finding_to_json(finding : Finding) -> Json {
  Json::object(
    Map([
      ("id", Json::string(finding.id)),
      ("severity", Json::string(finding.severity.label())),
      ("header", Json::string(finding.header)),
      ("message", Json::string(finding.message)),
      ("evidence", Json::string(finding.evidence)),
      ("remediation", Json::string(finding.remediation)),
    ]),
  )
}

///|
pub fn recommended_baseline() -> String {
  [
    "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security: max-age=31536000; includeSubDomains", "X-Content-Type-Options: nosniff",
    "Referrer-Policy: strict-origin-when-cross-origin", "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy: same-origin", "Cross-Origin-Resource-Policy: same-origin",
  ].join("\n")
}

///|
pub fn sample_insecure_headers() -> String {
  [
    "Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval' http:",
    "Strict-Transport-Security: max-age=300", "X-Content-Type-Options: sniff", "X-Frame-Options: ALLOW-FROM https://example.test",
    "Referrer-Policy: unsafe-url", "Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true",
  ].join("\n")
}

///|
fn contains_token(values : Array[String], token : String) -> Bool {
  values.any(v => v == token)
}

///|
fn contains_http_scheme(values : Array[String]) -> Bool {
  values.any(v => v == "http:" || v.has_prefix("http://"))
}

///|
fn directive_is_none(policy : CspPolicy, name : StringView) -> Bool {
  let values = policy.values_for(name)
  values.length() == 1 && values[0] == "'none'"
}

///|
fn directive_mentions_self_or_none(
  policy : CspPolicy,
  name : StringView,
) -> Bool {
  let values = policy.values_for(name)
  contains_token(values, "'self'") || contains_token(values, "'none'")
}

///|
fn join_tokens(tokens : Array[String]) -> String {
  if tokens.is_empty() {
    ""
  } else {
    tokens.join(" ")
  }
}

///|
fn parse_hsts_max_age(value : String) -> Int? {
  let mut parsed : Int? = None
  for part in value.split(";") {
    let p = part.trim().to_owned()
    if p.has_prefix("max-age=") {
      let number = p.strip_prefix("max-age=").unwrap().to_owned()
      if is_ascii_digits(number) {
        parsed = try @string.parse_int(number) |> Some catch {
          _ => None
        }
      }
    }
  }
  parsed
}

///|
fn permissions_policy_disables(value : String, feature : String) -> Bool {
  value.contains(feature + "=()") || value.contains(feature + "=(self)")
}

///|
fn has_control_character(value : String) -> Bool {
  value.any(ch => {
    let code = ch.to_int()
    code < 32 && ch != '\t'
  })
}

///|
fn split_ascii_words(input : StringView) -> Array[String] {
  let words : Array[String] = []
  for part in input.split(" ") {
    let token = part.trim()
    if !token.is_empty() {
      words.push(token.to_owned())
    }
  }
  words
}

///|
fn is_ascii_digits(value : String) -> Bool {
  !value.is_empty() && value.all(ch => ch >= '0' && ch <= '9')
}
