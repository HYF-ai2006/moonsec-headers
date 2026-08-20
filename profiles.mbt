///|
/// Security baseline profiles for common deployment shapes.
///
/// The generic audit report tells you what is wrong. These profiles tell you
/// what a sensible target configuration looks like for different scenarios.
pub(all) enum RequirementMode {
  Exact
  Contains
  ContainsAny
  Prefix
  AnyOf
  Absent
} derive(Eq, Debug)

///|
pub(all) enum ProfileKind {
  StaticSite
  SpaApp
  ApiService
  AdminConsole
  DocsSite
  EmbeddedWidget
  InternalDashboard
  FileDownload
  WasmEdge
  PublicPortal
  LoginFlow
  MediaCdn
} derive(Eq, Debug)

///|
pub(all) enum ProfileStatus {
  Satisfied
  Missing
  Weak
  Conflict
  Optional
} derive(Eq, Debug)

///|
pub(all) struct HeaderRequirement {
  name : String
  expected : String
  mode : RequirementMode
  required : Bool
  severity : Severity
  rationale : String
} derive(Eq, Debug)

///|
pub(all) struct SecurityProfile {
  kind : ProfileKind
  key : String
  title : String
  audience : String
  summary : String
  requirements : Array[HeaderRequirement]
} derive(Eq, Debug)

///|
pub(all) struct ProfileFinding {
  name : String
  status : ProfileStatus
  actual : String?
  expected : String
  severity : Severity
  rationale : String
} derive(Eq, Debug)

///|
pub(all) struct ProfileAssessment {
  profile_key : String
  score : Int
  matched : Int
  missing : Int
  weak : Int
  conflict : Int
  optional : Int
  findings : Array[ProfileFinding]
} derive(Eq, Debug)

///|
pub fn RequirementMode::label(self : RequirementMode) -> String {
  match self {
    Exact => "exact"
    Contains => "contains"
    ContainsAny => "contains-any"
    Prefix => "prefix"
    AnyOf => "any-of"
    Absent => "absent"
  }
}

///|
pub fn ProfileStatus::label(self : ProfileStatus) -> String {
  match self {
    Satisfied => "satisfied"
    Missing => "missing"
    Weak => "weak"
    Conflict => "conflict"
    Optional => "optional"
  }
}

///|
pub fn ProfileKind::label(self : ProfileKind) -> String {
  match self {
    StaticSite => "static-site"
    SpaApp => "spa-app"
    ApiService => "api-service"
    AdminConsole => "admin-console"
    DocsSite => "docs-site"
    EmbeddedWidget => "embedded-widget"
    InternalDashboard => "internal-dashboard"
    FileDownload => "file-download"
    WasmEdge => "wasm-edge"
    PublicPortal => "public-portal"
    LoginFlow => "login-flow"
    MediaCdn => "media-cdn"
  }
}

///|
pub fn requirement(
  name : StringView,
  expected : StringView,
  mode? : RequirementMode = Exact,
  required? : Bool = true,
  severity? : Severity = Medium,
  rationale? : StringView = "",
) -> HeaderRequirement {
  {
    name: name.to_owned(),
    expected: expected.to_owned(),
    mode,
    required,
    severity,
    rationale: rationale.to_owned(),
  }
}

///|
pub fn profile(
  kind : ProfileKind,
  key : StringView,
  title : StringView,
  audience : StringView,
  summary : StringView,
  requirements : Array[HeaderRequirement],
) -> SecurityProfile {
  {
    kind,
    key: key.to_owned(),
    title: title.to_owned(),
    audience: audience.to_owned(),
    summary: summary.to_owned(),
    requirements,
  }
}

///|
pub fn requirement_matches(
  req : HeaderRequirement,
  actual : StringView,
) -> Bool {
  match req.mode {
    Exact => actual.trim().to_lower().to_owned() == req.expected.to_lower()
    Contains => contains_expected_clauses(actual, req.expected)
    ContainsAny => contains_any_clause(actual, req.expected)
    Prefix =>
      actual.trim().to_lower().to_owned().has_prefix(req.expected.to_lower())
    AnyOf => any_of_matches(actual, req.expected)
    Absent => actual.is_empty()
  }
}

///|
/// A header requirement may describe several CSP or HSTS clauses separated by
/// semicolons. Match each clause independently so unrelated clauses can be
/// inserted without making an otherwise valid policy look weak.
fn contains_expected_clauses(actual : StringView, expected : String) -> Bool {
  let lowered_actual = actual.trim().to_lower().to_owned()
  expected
  .split(";")
  .all(part => {
    let clause = part.trim().to_lower().to_owned()
    clause.is_empty() || lowered_actual.contains(clause)
  })
}

///|
fn contains_any_clause(actual : StringView, expected : String) -> Bool {
  let lowered_actual = actual.trim().to_lower().to_owned()
  expected
  .split("|")
  .any(part => {
    let clause = part.trim().to_lower().to_owned()
    !clause.is_empty() && lowered_actual.contains(clause)
  })
}

///|
fn any_of_matches(actual : StringView, expected : String) -> Bool {
  let lowered = actual.trim().to_lower().to_owned()
  for candidate in expected.split("|") {
    if lowered == candidate.trim().to_lower().to_owned() {
      return true
    }
  }
  false
}

///|
pub fn SecurityProfile::required_count(self : SecurityProfile) -> Int {
  self.requirements.count_if(req => req.required)
}

///|
pub fn SecurityProfile::optional_count(self : SecurityProfile) -> Int {
  self.requirements.count_if(req => !req.required)
}

///|
pub fn SecurityProfile::find_requirement(
  self : SecurityProfile,
  name : StringView,
) -> HeaderRequirement? {
  let expected = normalize_header_name(name)
  self.requirements.iter().find_first(req => req.name == expected)
}

///|
pub fn SecurityProfile::required_headers(
  self : SecurityProfile,
) -> Array[String] {
  self.requirements.filter(req => req.required).map(req => req.name)
}

///|
pub fn SecurityProfile::optional_headers(
  self : SecurityProfile,
) -> Array[String] {
  self.requirements.filter(req => !req.required).map(req => req.name)
}

///|
pub fn SecurityProfile::to_markdown(self : SecurityProfile) -> String {
  let lines : Array[String] = []
  lines.push("## " + self.title)
  lines.push("")
  lines.push("- Key: `" + self.key + "`")
  lines.push("- Audience: " + self.audience)
  lines.push("- Summary: " + self.summary)
  lines.push("- Required headers: " + self.required_count().to_string())
  lines.push("- Optional headers: " + self.optional_count().to_string())
  lines.push("")
  lines.push("| Header | Mode | Required | Severity | Rationale |")
  lines.push("| --- | --- | --- | --- | --- |")
  for req in self.requirements {
    lines.push(
      "| `" +
      req.name +
      "` | " +
      req.mode.label() +
      " | " +
      bool_text(req.required) +
      " | " +
      req.severity.label() +
      " | " +
      req.rationale.replace_all(old="|", new="\\|") +
      " |",
    )
  }
  lines.join("\n")
}

///|
fn bool_text(flag : Bool) -> String {
  if flag {
    "yes"
  } else {
    "no"
  }
}

///|
pub fn SecurityProfile::score_headers(
  self : SecurityProfile,
  headers : HeaderSet,
) -> ProfileAssessment {
  let findings : Array[ProfileFinding] = []
  let mut matched = 0
  let mut missing = 0
  let mut weak = 0
  let mut conflict = 0
  let mut optional = 0
  for req in self.requirements {
    let actual = headers.get(req.name)
    match actual {
      Some(value) =>
        if req.mode == Absent {
          conflict += 1
          findings.push({
            name: req.name,
            status: Conflict,
            actual,
            expected: req.expected,
            severity: req.severity,
            rationale: req.rationale,
          })
        } else if requirement_matches(req, value) {
          matched += 1
          findings.push({
            name: req.name,
            status: Satisfied,
            actual,
            expected: req.expected,
            severity: req.severity,
            rationale: req.rationale,
          })
        } else {
          weak += 1
          findings.push({
            name: req.name,
            status: Weak,
            actual,
            expected: req.expected,
            severity: req.severity,
            rationale: req.rationale,
          })
        }
      None =>
        if req.required {
          missing += 1
          findings.push({
            name: req.name,
            status: Missing,
            actual: None,
            expected: req.expected,
            severity: req.severity,
            rationale: req.rationale,
          })
        } else {
          optional += 1
          findings.push({
            name: req.name,
            status: Optional,
            actual: None,
            expected: req.expected,
            severity: req.severity,
            rationale: req.rationale,
          })
        }
    }
  }
  let score = score_profile_result(matched, missing, weak, conflict, optional)
  {
    profile_key: self.key,
    score,
    matched,
    missing,
    weak,
    conflict,
    optional,
    findings,
  }
}

///|
fn score_profile_result(
  matched : Int,
  missing : Int,
  weak : Int,
  conflict : Int,
  optional : Int,
) -> Int {
  let mut score = 100
  score -= missing * 14
  score -= weak * 9
  score -= conflict * 18
  score -= optional * 1
  score += matched / 2
  if score < 0 {
    0
  } else {
    score
  }
}

///|
pub fn ProfileAssessment::summary(self : ProfileAssessment) -> String {
  "matched=" +
  self.matched.to_string() +
  ", missing=" +
  self.missing.to_string() +
  ", weak=" +
  self.weak.to_string() +
  ", conflict=" +
  self.conflict.to_string()
}

///|
/// Returns true when all required profile checks are satisfied.
pub fn ProfileAssessment::meets_required(self : ProfileAssessment) -> Bool {
  self.missing == 0 && self.weak == 0 && self.conflict == 0
}

///|
pub fn ProfileAssessment::to_markdown(self : ProfileAssessment) -> String {
  let lines : Array[String] = []
  lines.push("# Profile Assessment")
  lines.push("")
  lines.push("- Profile: `" + self.profile_key + "`")
  lines.push("- Score: " + self.score.to_string())
  lines.push("- Summary: " + self.summary())
  lines.push("")
  lines.push("| Header | Status | Expected | Actual | Severity |")
  lines.push("| --- | --- | --- | --- | --- |")
  for finding in self.findings {
    lines.push(
      "| `" +
      finding.name +
      "` | " +
      finding.status.label() +
      " | " +
      finding.expected.replace_all(old="|", new="\\|") +
      " | " +
      option_text(finding.actual) +
      " | " +
      finding.severity.label() +
      " |",
    )
  }
  lines.join("\n")
}

///|
fn option_text(value : String?) -> String {
  match value {
    Some(v) => v.replace_all(old="|", new="\\|")
    None => "-"
  }
}

///|
pub fn profile_lookup(key : StringView) -> SecurityProfile? {
  let expected = key.to_lower().to_owned()
  for p in profile_catalog() {
    if p.key == expected {
      return Some(p)
    }
  }
  None
}

///|
pub fn profile_catalog() -> Array[SecurityProfile] {
  [
    static_site_profile(),
    spa_app_profile(),
    api_service_profile(),
    admin_console_profile(),
    docs_site_profile(),
    embedded_widget_profile(),
    internal_dashboard_profile(),
    file_download_profile(),
    wasm_edge_profile(),
    public_portal_profile(),
    login_flow_profile(),
    media_cdn_profile(),
  ]
}

///|
pub fn profile_keys() -> Array[String] {
  profile_catalog().map(p => p.key)
}

///|
pub fn profile_titles() -> Array[String] {
  profile_catalog().map(p => p.title)
}

///|
pub fn profile_count() -> Int {
  profile_catalog().length()
}

///|
pub fn profile_catalog_markdown() -> String {
  let lines : Array[String] = []
  lines.push("# Security Profiles")
  lines.push("")
  lines.push("- Count: " + profile_count().to_string())
  lines.push("")
  for p in profile_catalog() {
    lines.push("- `" + p.key + "` - " + p.summary)
  }
  lines.join("\n")
}

///|
pub fn static_site_profile() -> SecurityProfile {
  profile(
    StaticSite,
    "static-site",
    "Static Site",
    "marketing pages, docs, and pre-rendered sites",
    "A baseline for static web delivery with no privileged browser APIs.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        mode=Contains,
        severity=High,
        rationale="Static sites should keep every script and object source explicit.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=Medium,
        rationale="Static sites should force HTTPS for a long window.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Content sniffing is an avoidable source of script injection.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin|no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Shared content should not leak full path details to other origins.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Static sites rarely need device sensors or capture APIs.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Isolation is helpful but not always necessary for public pages.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin|same-site",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Static assets can often be tightened to reduce embedding risk.",
      ),
      requirement(
        "x-frame-options",
        "deny|sameorigin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Clickjacking protection should come from CSP or XFO.",
      ),
    ],
  )
}

///|
pub fn spa_app_profile() -> SecurityProfile {
  profile(
    SpaApp,
    "spa-app",
    "Single-Page App",
    "client-heavy applications with dynamic script loading",
    "A profile for app shells that still need tight script governance.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; script-src 'self'",
        mode=Contains,
        severity=High,
        rationale="App shells should pin script loading to trusted origins.",
      ),
      requirement(
        "content-security-policy",
        "frame-ancestors 'none'",
        mode=Contains,
        severity=Medium,
        rationale="Client applications are common clickjacking targets.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=Medium,
        rationale="SPA deployment benefits from a long HTTPS baseline.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Script and module delivery should not rely on MIME guessing.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin",
        mode=Exact,
        severity=Low,
        rationale="SPAs often fetch many cross-origin APIs and assets.",
      ),
      requirement(
        "permissions-policy",
        "geolocation=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Application shells usually do not need privileged APIs at load time.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Isolation is valuable if the app uses high-value auth flows.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="SPA assets are usually best kept within the same origin set.",
      ),
    ],
  )
}

///|
pub fn api_service_profile() -> SecurityProfile {
  profile(
    ApiService,
    "api-service",
    "API Service",
    "JSON and machine-facing services",
    "A profile for services that emit JSON, tokens, or binary data.",
    [
      requirement(
        "content-security-policy",
        "default-src 'none'",
        mode=Contains,
        severity=High,
        rationale="APIs should not expose browser execution surfaces by default.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=High,
        rationale="Machine clients should still only talk to HTTPS endpoints.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="JSON endpoints should not be sniffed as executable content.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer|strict-origin-when-cross-origin",
        mode=AnyOf,
        severity=Low,
        rationale="APIs should avoid leaking identifying request paths.",
      ),
      requirement(
        "access-control-allow-origin",
        "*",
        mode=Exact,
        required=false,
        severity=Low,
        rationale="Cross-origin access must be explicitly intended and reviewed.",
      ),
      requirement(
        "access-control-allow-credentials",
        "true",
        mode=Exact,
        required=false,
        severity=Low,
        rationale="Credentialed API access should be narrowly controlled.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="APIs usually benefit from not being embeddable cross-origin.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Machine APIs should not imply browser capture permissions.",
      ),
    ],
  )
}

///|
pub fn admin_console_profile() -> SecurityProfile {
  profile(
    AdminConsole,
    "admin-console",
    "Admin Console",
    "operator and configuration dashboards",
    "A tighter profile for privileged interfaces and operational backends.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        mode=Contains,
        severity=High,
        rationale="Administrative screens should minimize all third-party execution.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
        mode=Contains,
        severity=High,
        rationale="Operators deserve the strongest HTTPS baseline available.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Admin consoles often render mixed data and attachments.",
      ),
      requirement(
        "x-frame-options",
        "deny",
        mode=AnyOf,
        severity=Medium,
        rationale="Administrative UI should not be embedded elsewhere.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Operational URLs should stay private when operators switch tabs.",
      ),
      requirement(
        "permissions-policy",
        "geolocation=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Operator dashboards rarely need sensor or capture APIs.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Isolation strengthens stateful login and tab separation.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Console assets are usually not meant for other origins.",
      ),
    ],
  )
}

///|
pub fn docs_site_profile() -> SecurityProfile {
  profile(
    DocsSite,
    "docs-site",
    "Documentation Site",
    "developer docs and reference portals",
    "A profile for documentation surfaces that need clarity without looseness.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; object-src 'none'",
        mode=Contains,
        severity=High,
        rationale="Docs pages can still be abused for script or embed injection.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=Medium,
        rationale="Documentation should be safely cached behind HTTPS.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Docs often serve code samples and raw assets.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin",
        mode=Exact,
        severity=Low,
        rationale="Documentation links often cross domains and external sites.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Docs pages should not hint at interactive device access.",
      ),
      requirement(
        "x-frame-options",
        "sameorigin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Embedding is okay only when explicitly intended.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin-allow-popups|same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Docs may open external links but should stay isolated.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-site",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Reference sites can often keep assets site-local.",
      ),
    ],
  )
}

///|
pub fn embedded_widget_profile() -> SecurityProfile {
  profile(
    EmbeddedWidget,
    "embedded-widget",
    "Embedded Widget",
    "widgets designed to be embedded in other sites",
    "A profile for third-party widgets with controlled embedding behavior.",
    [
      requirement(
        "content-security-policy",
        "frame-ancestors",
        mode=Contains,
        severity=High,
        rationale="Embedded widgets must declare who can embed them.",
      ),
      requirement(
        "content-security-policy",
        "script-src 'self'",
        mode=Contains,
        severity=High,
        rationale="Widget code should load scripts from predictable origins.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=Medium,
        rationale="Third-party embedding still depends on HTTPS integrity.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Widgets often load fragments and typed content.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin",
        mode=Exact,
        severity=Low,
        rationale="Embedded widgets should not leak tenant-specific paths.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Embedded widgets should not request sensor access by default.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "unsafe-none",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Embeddable content usually cannot demand full browsing isolation.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "cross-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Widgets often need controlled cross-origin resource delivery.",
      ),
    ],
  )
}

///|
pub fn internal_dashboard_profile() -> SecurityProfile {
  profile(
    InternalDashboard,
    "internal-dashboard",
    "Internal Dashboard",
    "staff-only analytics and operations surfaces",
    "A profile for internal dashboards with stronger privacy expectations.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'",
        mode=Contains,
        severity=High,
        rationale="Internal dashboards should still treat scripts as untrusted input.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
        mode=Contains,
        severity=High,
        rationale="Internal zones often span multiple subdomains and services.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Dashboards tend to render mixed data attachments and inline tools.",
      ),
      requirement(
        "x-frame-options",
        "deny",
        mode=AnyOf,
        severity=Medium,
        rationale="Internal systems should resist clickjacking too.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Internal route names are often sensitive by themselves.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Operations dashboards rarely use browser capture APIs.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Isolation is usually worth it for internal authenticated apps.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Internal resources should generally stay same-origin only.",
      ),
    ],
  )
}

///|
pub fn file_download_profile() -> SecurityProfile {
  profile(
    FileDownload,
    "file-download",
    "File Download Service",
    "downloads, release assets, and binary distribution endpoints",
    "A profile for download handlers that should behave like inert delivery.",
    [
      requirement(
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
        mode=Contains,
        severity=High,
        rationale="Download endpoints should not advertise script execution surfaces.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=High,
        rationale="Binary distribution should be protected by long-lived HTTPS.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Downloads should preserve their declared MIME types.",
      ),
      requirement(
        "content-disposition",
        "attachment",
        mode=Contains,
        severity=Medium,
        required=false,
        rationale="File download responses should bias toward attachment semantics.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Binary release URLs can be sensitive identifiers.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Download responses should not hint at privileged browser use.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-site|same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Distribution hosts should control who can embed assets.",
      ),
      requirement(
        "cache-control",
        "no-transform",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Downloads should avoid unexpected intermediary rewrites.",
      ),
    ],
  )
}

///|
pub fn wasm_edge_profile() -> SecurityProfile {
  profile(
    WasmEdge,
    "wasm-edge",
    "Wasm Edge App",
    "WebAssembly edge or browser apps",
    "A profile for Wasm-heavy frontends and edge runtimes.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; script-src 'self'; object-src 'none'",
        mode=Contains,
        severity=High,
        rationale="Wasm apps usually need a compact, explicit execution budget.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=High,
        rationale="Edge code and browser code both benefit from strong HTTPS.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Wasm delivery often includes multiple asset types.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        severity=Low,
        required=false,
        rationale="SharedArrayBuffer and isolation-related features are easier this way.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-origin",
        mode=AnyOf,
        severity=Low,
        required=false,
        rationale="Wasm bundles and memory helpers should remain tightly scoped.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin",
        mode=Exact,
        severity=Low,
        rationale="Wasm apps frequently call out to analytics and service APIs.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Wasm runtimes seldom need access to hardware sensors.",
      ),
      requirement(
        "x-frame-options",
        "deny",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Browser apps that render sensitive state should not be framed.",
      ),
    ],
  )
}

///|
pub fn public_portal_profile() -> SecurityProfile {
  profile(
    PublicPortal,
    "public-portal",
    "Public Portal",
    "customer-facing product portals",
    "A balanced profile for public product areas with account access.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        mode=Contains,
        severity=High,
        rationale="Public portals need a conservative but usable baseline.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
        mode=Contains,
        severity=High,
        rationale="Public portals usually span multiple branded subdomains.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Portal pages often mix HTML, JSON, and downloadable files.",
      ),
      requirement(
        "referrer-policy",
        "strict-origin-when-cross-origin",
        mode=Exact,
        severity=Low,
        rationale="Customer journeys should not leak full URLs by default.",
      ),
      requirement(
        "permissions-policy",
        "geolocation=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Most portals do not need device location access.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin-allow-popups|same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Portals sometimes open payment or support windows.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "same-site",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Customer portals often rely on same-site assets and embeds.",
      ),
      requirement(
        "x-frame-options",
        "sameorigin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Framing should be deliberate if enabled at all.",
      ),
    ],
  )
}

///|
pub fn login_flow_profile() -> SecurityProfile {
  profile(
    LoginFlow,
    "login-flow",
    "Login Flow",
    "authentication and sign-in journeys",
    "A profile tuned for login forms, MFA prompts, and password resets.",
    [
      requirement(
        "content-security-policy",
        "default-src 'self'; script-src 'self'; form-action 'self'",
        mode=Contains,
        severity=High,
        rationale="Login flows should keep scripts and form posts on trusted origins.",
      ),
      requirement(
        "content-security-policy",
        "frame-ancestors 'none'",
        mode=Contains,
        severity=High,
        rationale="Authentication screens are attractive clickjacking targets.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000",
        mode=Contains,
        severity=High,
        rationale="Credential exchange should always stay on HTTPS.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Login pages often mix JSON config and HTML templates.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Authentication URLs should not leak account state through referrers.",
      ),
      requirement(
        "permissions-policy",
        "camera=()|microphone=()",
        mode=ContainsAny,
        required=false,
        severity=Low,
        rationale="Only explicit MFA screens should ever need those capabilities.",
      ),
      requirement(
        "cross-origin-opener-policy",
        "same-origin",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Auth windows should isolate themselves from opener state.",
      ),
      requirement(
        "x-frame-options",
        "deny",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="If CSP frame-ancestors exists, XFO can still reinforce the stance.",
      ),
    ],
  )
}

///|
pub fn media_cdn_profile() -> SecurityProfile {
  profile(
    MediaCdn,
    "media-cdn",
    "Media CDN",
    "asset and image delivery edges",
    "A profile for image, video, font, and binary asset distribution.",
    [
      requirement(
        "content-security-policy",
        "default-src 'none'",
        mode=Contains,
        severity=High,
        rationale="CDN asset endpoints should not imply generic browser execution.",
      ),
      requirement(
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
        mode=Contains,
        severity=High,
        rationale="Media edges commonly front large public surfaces.",
      ),
      requirement(
        "x-content-type-options",
        "nosniff",
        mode=Exact,
        severity=Medium,
        rationale="Asset delivery must preserve declared MIME types.",
      ),
      requirement(
        "cache-control",
        "public",
        mode=Contains,
        severity=Medium,
        required=false,
        rationale="Media CDNs typically need explicit caching behavior.",
      ),
      requirement(
        "cross-origin-resource-policy",
        "cross-origin",
        mode=AnyOf,
        severity=Low,
        required=false,
        rationale="CDN assets are often consumed cross-origin by design.",
      ),
      requirement(
        "referrer-policy",
        "no-referrer",
        mode=AnyOf,
        severity=Low,
        rationale="Asset URLs can reveal bucket or tenant details.",
      ),
      requirement(
        "permissions-policy",
        "camera=()",
        mode=Contains,
        required=false,
        severity=Low,
        rationale="Static media delivery does not need browser sensor permissions.",
      ),
      requirement(
        "x-frame-options",
        "deny",
        mode=AnyOf,
        required=false,
        severity=Low,
        rationale="Assets do not gain anything from being framed as UI.",
      ),
    ],
  )
}

///|
pub fn profile_assessment_catalog(profile : SecurityProfile) -> Array[String] {
  profile.requirements.map(req => {
    req.name + ":" + req.mode.label() + ":" + bool_text(req.required)
  })
}

///|
pub fn profile_gap_headers(
  profile : SecurityProfile,
  headers : HeaderSet,
) -> Array[String] {
  let gaps : Array[String] = []
  let assessment = profile.score_headers(headers)
  for finding in assessment.findings {
    if finding.status != Satisfied {
      gaps.push(finding.name)
    }
  }
  gaps
}

///|
pub fn profile_is_strict(profile : SecurityProfile) -> Bool {
  profile.required_count() >= 6 && profile.optional_count() <= 4
}

///|
pub fn strict_profiles() -> Array[SecurityProfile] {
  profile_catalog().filter(profile_is_strict)
}

///|
pub fn profile_names_markdown() -> String {
  let lines : Array[String] = []
  lines.push("### Profile names")
  for name in profile_keys() {
    lines.push("- `" + name + "`")
  }
  lines.join("\n")
}

///|
pub fn profile_audiences_markdown() -> String {
  let lines : Array[String] = []
  lines.push("### Profile audiences")
  for p in profile_catalog() {
    lines.push("- " + p.title + ": " + p.audience)
  }
  lines.join("\n")
}

///|
pub fn profile_summaries_markdown() -> String {
  let lines : Array[String] = []
  lines.push("# Profile Summary")
  lines.push("")
  for p in profile_catalog() {
    lines.push("- " + p.key + " => " + p.summary)
  }
  lines.join("\n")
}
