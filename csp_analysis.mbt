///|
/// Deeper Content-Security-Policy source analysis.
///
/// The core parser keeps CSP syntax lightweight. This module adds a second
/// layer that classifies source expressions and explains why a policy is broad
/// or narrow enough for production review.
pub(all) enum CspSourceKind {
  CspSourceNone
  CspSourceSelf
  CspSourceUnsafeInline
  CspSourceUnsafeEval
  CspSourceStrictDynamic
  CspSourceNonce
  CspSourceHash
  CspSourceHttpsScheme
  CspSourceHttpScheme
  CspSourceDataScheme
  CspSourceBlobScheme
  CspSourceFilesystemScheme
  CspSourceWildcard
  CspSourceHost
  CspSourceKeyword
  CspSourceUnknown
} derive(Eq, Debug)

///|
pub(all) enum CspDirectiveFamily {
  CspFamilyFetch
  CspFamilyDocument
  CspFamilyNavigation
  CspFamilyReporting
  CspFamilySandbox
  CspFamilyMixedContent
  CspFamilyOther
} derive(Eq, Debug)

///|
pub(all) struct CspSourceExpression {
  directive : String
  raw : String
  normalized : String
  kind : CspSourceKind
  secure_transport : Bool
  broad : Bool
  note : String
} derive(Eq, Debug)

///|
pub(all) struct CspDirectiveSummary {
  name : String
  family : CspDirectiveFamily
  explicit : Bool
  value_count : Int
  source_count : Int
  has_none : Bool
  has_self : Bool
  has_wildcard : Bool
  has_http : Bool
  has_inline : Bool
  has_eval : Bool
  has_nonce : Bool
  has_hash : Bool
  notes : Array[String]
} derive(Eq, Debug)

///|
pub(all) struct CspObservation {
  id : String
  severity : Severity
  directive : String
  source : String
  message : String
  recommendation : String
} derive(Eq, Debug)

///|
pub(all) struct CspAnalysis {
  score : Int
  policy : CspPolicy
  observations : Array[CspObservation]
  directives : Array[CspDirectiveSummary]
  sources : Array[CspSourceExpression]
} derive(Eq, Debug)

///|
pub fn CspSourceKind::label(self : CspSourceKind) -> String {
  match self {
    CspSourceNone => "none"
    CspSourceSelf => "self"
    CspSourceUnsafeInline => "unsafe-inline"
    CspSourceUnsafeEval => "unsafe-eval"
    CspSourceStrictDynamic => "strict-dynamic"
    CspSourceNonce => "nonce"
    CspSourceHash => "hash"
    CspSourceHttpsScheme => "https-scheme"
    CspSourceHttpScheme => "http-scheme"
    CspSourceDataScheme => "data-scheme"
    CspSourceBlobScheme => "blob-scheme"
    CspSourceFilesystemScheme => "filesystem-scheme"
    CspSourceWildcard => "wildcard"
    CspSourceHost => "host"
    CspSourceKeyword => "keyword"
    CspSourceUnknown => "unknown"
  }
}

///|
pub fn CspDirectiveFamily::label(self : CspDirectiveFamily) -> String {
  match self {
    CspFamilyFetch => "fetch"
    CspFamilyDocument => "document"
    CspFamilyNavigation => "navigation"
    CspFamilyReporting => "reporting"
    CspFamilySandbox => "sandbox"
    CspFamilyMixedContent => "mixed-content"
    CspFamilyOther => "other"
  }
}

///|
pub fn csp_source_directives() -> Array[String] {
  [
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src",
    "object-src", "manifest-src", "worker-src", "child-src", "frame-src", "prefetch-src",
  ]
}

///|
pub fn csp_document_directives() -> Array[String] {
  ["base-uri", "sandbox", "plugin-types"]
}

///|
pub fn csp_navigation_directives() -> Array[String] {
  ["form-action", "frame-ancestors", "navigate-to"]
}

///|
pub fn csp_reporting_directives() -> Array[String] {
  ["report-uri", "report-to"]
}

///|
pub fn csp_mixed_content_directives() -> Array[String] {
  ["upgrade-insecure-requests", "block-all-mixed-content"]
}

///|
pub fn csp_all_interesting_directives() -> Array[String] {
  let names : Array[String] = []
  for name in csp_source_directives() {
    names.push(name)
  }
  for name in csp_document_directives() {
    names.push(name)
  }
  for name in csp_navigation_directives() {
    names.push(name)
  }
  for name in csp_reporting_directives() {
    names.push(name)
  }
  for name in csp_mixed_content_directives() {
    names.push(name)
  }
  names
}

///|
pub fn csp_directive_family(name : StringView) -> CspDirectiveFamily {
  let n = csp_normalize_name(name)
  if csp_source_directive(n) {
    CspFamilyFetch
  } else if csp_document_directive(n) {
    CspFamilyDocument
  } else if csp_navigation_directive(n) {
    CspFamilyNavigation
  } else if csp_reporting_directive(n) {
    CspFamilyReporting
  } else if csp_mixed_content_directive(n) {
    CspFamilyMixedContent
  } else if n == "sandbox" {
    CspFamilySandbox
  } else {
    CspFamilyOther
  }
}

///|
pub fn csp_source_directive(name : StringView) -> Bool {
  let n = csp_normalize_name(name)
  csp_source_directives().any(item => item == n)
}

///|
pub fn csp_document_directive(name : StringView) -> Bool {
  let n = csp_normalize_name(name)
  csp_document_directives().any(item => item == n)
}

///|
pub fn csp_navigation_directive(name : StringView) -> Bool {
  let n = csp_normalize_name(name)
  csp_navigation_directives().any(item => item == n)
}

///|
pub fn csp_reporting_directive(name : StringView) -> Bool {
  let n = csp_normalize_name(name)
  csp_reporting_directives().any(item => item == n)
}

///|
pub fn csp_mixed_content_directive(name : StringView) -> Bool {
  let n = csp_normalize_name(name)
  csp_mixed_content_directives().any(item => item == n)
}

///|
pub fn classify_csp_source(token : StringView) -> CspSourceKind {
  let value = csp_normalize_source(token)
  if value == "'none'" {
    CspSourceNone
  } else if value == "'self'" {
    CspSourceSelf
  } else if value == "'unsafe-inline'" {
    CspSourceUnsafeInline
  } else if value == "'unsafe-eval'" {
    CspSourceUnsafeEval
  } else if value == "'strict-dynamic'" {
    CspSourceStrictDynamic
  } else if value.has_prefix("'nonce-") {
    CspSourceNonce
  } else if value.has_prefix("'sha256-") ||
    value.has_prefix("'sha384-") ||
    value.has_prefix("'sha512-") {
    CspSourceHash
  } else if value == "https:" {
    CspSourceHttpsScheme
  } else if value == "http:" {
    CspSourceHttpScheme
  } else if value == "data:" {
    CspSourceDataScheme
  } else if value == "blob:" {
    CspSourceBlobScheme
  } else if value == "filesystem:" {
    CspSourceFilesystemScheme
  } else if value == "*" ||
    value.has_prefix("*.") ||
    value.contains("://*") ||
    value.contains("*.") {
    CspSourceWildcard
  } else if value.has_prefix("'") {
    CspSourceKeyword
  } else if value.contains("://") ||
    value.contains(".") ||
    value == "localhost" ||
    value.has_prefix("localhost:") {
    CspSourceHost
  } else {
    CspSourceUnknown
  }
}

///|
pub fn csp_source_expression(
  directive : StringView,
  token : StringView,
) -> CspSourceExpression {
  let normalized = csp_normalize_source(token)
  let kind = classify_csp_source(normalized)
  {
    directive: csp_normalize_name(directive),
    raw: token.trim().to_owned(),
    normalized,
    kind,
    secure_transport: csp_source_secure_transport(kind, normalized),
    broad: csp_source_is_broad(kind, normalized),
    note: csp_source_note(kind, normalized),
  }
}

///|
pub fn CspSourceExpression::risk_label(self : CspSourceExpression) -> String {
  if self.broad {
    "broad"
  } else if !self.secure_transport {
    "insecure-transport"
  } else {
    "narrow"
  }
}

///|
pub fn CspSourceExpression::to_markdown_row(
  self : CspSourceExpression,
) -> String {
  "| `" +
  self.directive +
  "` | `" +
  self.raw.replace_all(old="|", new="\\|") +
  "` | " +
  self.kind.label() +
  " | " +
  self.risk_label() +
  " | " +
  self.note.replace_all(old="|", new="\\|") +
  " |"
}

///|
pub fn CspSourceExpression::to_json_string(
  self : CspSourceExpression,
) -> String {
  Json::object(
    Map([
      ("directive", Json::string(self.directive)),
      ("raw", Json::string(self.raw)),
      ("kind", Json::string(self.kind.label())),
      ("risk", Json::string(self.risk_label())),
      ("note", Json::string(self.note)),
    ]),
  ).stringify(indent=2)
}

///|
pub fn CspPolicy::directive_names(self : CspPolicy) -> Array[String] {
  self.directives.map(d => d.name)
}

///|
pub fn CspPolicy::has_nonce(self : CspPolicy) -> Bool {
  self.all_sources().any(src => src.kind == CspSourceNonce)
}

///|
pub fn CspPolicy::has_hash(self : CspPolicy) -> Bool {
  self.all_sources().any(src => src.kind == CspSourceHash)
}

///|
pub fn CspPolicy::has_strict_dynamic(self : CspPolicy) -> Bool {
  self.all_sources().any(src => src.kind == CspSourceStrictDynamic)
}

///|
pub fn CspPolicy::all_sources(self : CspPolicy) -> Array[CspSourceExpression] {
  let sources : Array[CspSourceExpression] = []
  for directive in self.directives {
    if csp_source_directive(directive.name) ||
      csp_document_directive(directive.name) ||
      csp_navigation_directive(directive.name) {
      for token in directive.values {
        sources.push(csp_source_expression(directive.name, token))
      }
    }
  }
  sources
}

///|
pub fn CspPolicy::sources_for(
  self : CspPolicy,
  directive : StringView,
) -> Array[CspSourceExpression] {
  let name = csp_normalize_name(directive)
  self
  .effective_source_values(name)
  .map(token => csp_source_expression(name, token))
}

///|
pub fn CspPolicy::explicit_sources_for(
  self : CspPolicy,
  directive : StringView,
) -> Array[CspSourceExpression] {
  let name = csp_normalize_name(directive)
  self.values_for(name).map(token => csp_source_expression(name, token))
}

///|
pub fn CspPolicy::effective_source_values(
  self : CspPolicy,
  directive : StringView,
) -> Array[String] {
  csp_effective_source_values(self, csp_normalize_name(directive), 0)
}

///|
fn csp_effective_source_values(
  policy : CspPolicy,
  directive : String,
  depth : Int,
) -> Array[String] {
  if depth > 4 {
    []
  } else {
    match policy.directive(directive) {
      Some(directive_data) => directive_data.values.copy()
      None =>
        match csp_fallback_directive(directive) {
          Some(parent) => csp_effective_source_values(policy, parent, depth + 1)
          None => []
        }
    }
  }
}

///|
pub fn csp_fallback_directive(directive : StringView) -> String? {
  let name = csp_normalize_name(directive)
  if name == "script-src-elem" || name == "script-src-attr" {
    Some("script-src")
  } else if name == "style-src-elem" || name == "style-src-attr" {
    Some("style-src")
  } else if name == "worker-src" || name == "frame-src" {
    Some("child-src")
  } else if name == "script-src" ||
    name == "style-src" ||
    name == "img-src" ||
    name == "font-src" ||
    name == "connect-src" ||
    name == "media-src" ||
    name == "object-src" ||
    name == "manifest-src" ||
    name == "prefetch-src" ||
    name == "child-src" {
    Some("default-src")
  } else {
    None
  }
}

///|
pub fn CspPolicy::directive_summary(
  self : CspPolicy,
  directive : StringView,
) -> CspDirectiveSummary {
  let name = csp_normalize_name(directive)
  let explicit = self.has_directive(name)
  let values = self.effective_source_values(name)
  let sources = values.map(token => csp_source_expression(name, token))
  let notes : Array[String] = []
  if !explicit {
    match csp_fallback_directive(name) {
      Some(parent) => notes.push("falls back to " + parent)
      None => notes.push("not declared")
    }
  }
  if sources.any(src => src.kind == CspSourceWildcard) {
    notes.push("allows wildcard source")
  }
  if sources.any(src => src.kind == CspSourceHttpScheme) {
    notes.push("allows insecure transport")
  }
  if sources.any(src => src.kind == CspSourceDataScheme) {
    notes.push("allows data: URLs")
  }
  if sources.any(src => src.kind == CspSourceUnsafeInline) {
    notes.push("allows inline execution")
  }
  if sources.any(src => src.kind == CspSourceNonce) ||
    sources.any(src => src.kind == CspSourceHash) {
    notes.push("uses nonce or hash based trust")
  }
  {
    name,
    family: csp_directive_family(name),
    explicit,
    value_count: values.length(),
    source_count: sources.length(),
    has_none: sources.any(src => src.kind == CspSourceNone),
    has_self: sources.any(src => src.kind == CspSourceSelf),
    has_wildcard: sources.any(src => src.kind == CspSourceWildcard),
    has_http: sources.any(src => src.kind == CspSourceHttpScheme),
    has_inline: sources.any(src => src.kind == CspSourceUnsafeInline),
    has_eval: sources.any(src => src.kind == CspSourceUnsafeEval),
    has_nonce: sources.any(src => src.kind == CspSourceNonce),
    has_hash: sources.any(src => src.kind == CspSourceHash),
    notes,
  }
}

///|
pub fn CspDirectiveSummary::stance(self : CspDirectiveSummary) -> String {
  if self.has_none {
    "blocked"
  } else if self.has_wildcard ||
    self.has_http ||
    self.has_inline ||
    self.has_eval {
    "broad"
  } else if self.has_nonce || self.has_hash {
    "tokenized"
  } else if self.has_self && self.source_count <= 2 {
    "same-origin"
  } else if self.source_count == 0 {
    "missing"
  } else {
    "explicit"
  }
}

///|
pub fn CspDirectiveSummary::to_markdown_row(
  self : CspDirectiveSummary,
) -> String {
  "| `" +
  self.name +
  "` | " +
  self.family.label() +
  " | " +
  bool_word(self.explicit) +
  " | " +
  self.stance() +
  " | " +
  self.notes.join("; ").replace_all(old="|", new="\\|") +
  " |"
}

///|
pub fn CspDirectiveSummary::to_json_string(
  self : CspDirectiveSummary,
) -> String {
  Json::object(
    Map([
      ("name", Json::string(self.name)),
      ("family", Json::string(self.family.label())),
      ("explicit", Json::string(bool_word(self.explicit))),
      ("stance", Json::string(self.stance())),
      (
        "value_count",
        Json::number(
          self.value_count.to_double(),
          repr=self.value_count.to_string(),
        ),
      ),
      ("notes", Json::array(self.notes.map(note => Json::string(note)))),
    ]),
  ).stringify(indent=2)
}

///|
pub fn analyze_csp_header(value : StringView) -> CspAnalysis {
  analyze_csp_policy(parse_csp(value))
}

///|
pub fn analyze_csp_policy(policy : CspPolicy) -> CspAnalysis {
  let observations : Array[CspObservation] = []
  let directives : Array[CspDirectiveSummary] = []
  for issue in policy.issues {
    observations.push({
      id: "parse." + issue.kind.label(),
      severity: Low,
      directive: issue.name,
      source: "",
      message: issue.message,
      recommendation: "Declare each CSP directive once and keep empty directive fragments out of the policy.",
    })
  }
  for name in csp_all_interesting_directives() {
    directives.push(policy.directive_summary(name))
  }
  csp_check_default_src(policy, observations)
  csp_check_script_src(policy, observations)
  csp_check_style_src(policy, observations)
  csp_check_object_src(policy, observations)
  csp_check_base_uri(policy, observations)
  csp_check_frame_ancestors(policy, observations)
  csp_check_form_action(policy, observations)
  csp_check_connect_src(policy, observations)
  csp_check_frame_src(policy, observations)
  csp_check_img_src(policy, observations)
  csp_check_reporting(policy, observations)
  csp_check_mixed_content(policy, observations)
  let score = csp_analysis_score(observations)
  { score, policy, observations, directives, sources: policy.all_sources() }
}

///|
fn csp_check_default_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.values_for("default-src")
  if values.is_empty() {
    observations.push(
      csp_observation(
        "default-src.missing",
        Medium,
        "default-src",
        "",
        "default-src is missing, so fallback behavior is harder to reason about.",
        "Add default-src 'self' or default-src 'none' and open only the directives that are needed.",
      ),
    )
  } else {
    csp_check_source_values("default-src", values, observations)
    if csp_values_have(values, "*") {
      observations.push(
        csp_observation(
          "default-src.wildcard",
          High,
          "default-src",
          values.join(" "),
          "default-src allows every origin.",
          "Replace * with explicit origins or a narrower fallback such as 'self'.",
        ),
      )
    }
  }
}

///|
fn csp_check_script_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("script-src")
  if values.is_empty() {
    observations.push(
      csp_observation(
        "script-src.missing",
        High,
        "script-src",
        "",
        "script execution has no explicit source list.",
        "Declare script-src with trusted hosts, nonces, or hashes.",
      ),
    )
  } else {
    csp_check_source_values("script-src", values, observations)
    if csp_values_have(values, "'unsafe-inline'") {
      observations.push(
        csp_observation(
          "script-src.unsafe-inline",
          High,
          "script-src",
          values.join(" "),
          "script-src permits inline script execution.",
          "Use nonce or hash based script trust and remove 'unsafe-inline'.",
        ),
      )
    }
    if csp_values_have(values, "'unsafe-eval'") {
      observations.push(
        csp_observation(
          "script-src.unsafe-eval",
          High,
          "script-src",
          values.join(" "),
          "script-src permits dynamic code evaluation.",
          "Remove eval-style code paths or isolate them behind a more limited runtime.",
        ),
      )
    }
    if csp_values_have(values, "data:") {
      observations.push(
        csp_observation(
          "script-src.data",
          High,
          "script-src",
          values.join(" "),
          "data: scripts are executable content with very broad injection risk.",
          "Remove data: from script-src.",
        ),
      )
    }
    if csp_values_have(values, "blob:") {
      observations.push(
        csp_observation(
          "script-src.blob",
          Medium,
          "script-src",
          values.join(" "),
          "blob: scripts are hard to inventory and review.",
          "Prefer signed external scripts or nonce-protected inline bootstrap code.",
        ),
      )
    }
    if policy.has_strict_dynamic() && !policy.has_nonce() && !policy.has_hash() {
      observations.push(
        csp_observation(
          "script-src.strict-dynamic-without-token",
          Medium,
          "script-src",
          values.join(" "),
          "strict-dynamic appears without a nonce or hash root of trust.",
          "Pair strict-dynamic with nonce or hash based bootstrap scripts.",
        ),
      )
    }
  }
}

///|
fn csp_check_style_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("style-src")
  if !values.is_empty() {
    csp_check_source_values("style-src", values, observations)
    if csp_values_have(values, "'unsafe-inline'") &&
      !csp_values_have_kind(values, CspSourceNonce) &&
      !csp_values_have_kind(values, CspSourceHash) {
      observations.push(
        csp_observation(
          "style-src.unsafe-inline",
          Medium,
          "style-src",
          values.join(" "),
          "style-src allows inline CSS without a nonce or hash.",
          "Move CSS into trusted stylesheets or protect inline styles with hashes.",
        ),
      )
    }
  }
}

///|
fn csp_check_object_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("object-src")
  if values.length() != 1 || values[0] != "'none'" {
    observations.push(
      csp_observation(
        "object-src.not-none",
        Medium,
        "object-src",
        values.join(" "),
        "object-src is not locked to 'none'.",
        "Set object-src 'none' unless legacy plugin content is deliberately required.",
      ),
    )
  }
}

///|
fn csp_check_base_uri(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.values_for("base-uri")
  if values.is_empty() {
    observations.push(
      csp_observation(
        "base-uri.missing",
        Medium,
        "base-uri",
        "",
        "base-uri is missing.",
        "Add base-uri 'self' or base-uri 'none' to prevent injected base tags from rewriting links.",
      ),
    )
  } else if !csp_values_have(values, "'self'") &&
    !csp_values_have(values, "'none'") {
    observations.push(
      csp_observation(
        "base-uri.broad",
        Medium,
        "base-uri",
        values.join(" "),
        "base-uri allows external base targets.",
        "Restrict base-uri to 'self' or 'none'.",
      ),
    )
  }
}

///|
fn csp_check_frame_ancestors(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.values_for("frame-ancestors")
  if values.is_empty() {
    observations.push(
      csp_observation(
        "frame-ancestors.missing",
        Medium,
        "frame-ancestors",
        "",
        "frame-ancestors is missing.",
        "Add frame-ancestors 'none' for non-embeddable pages or a tight allowlist for embed flows.",
      ),
    )
  } else {
    csp_check_source_values("frame-ancestors", values, observations)
    if csp_values_have(values, "*") {
      observations.push(
        csp_observation(
          "frame-ancestors.wildcard",
          High,
          "frame-ancestors",
          values.join(" "),
          "The page can be framed by any origin.",
          "Use frame-ancestors 'none', 'self', or a narrow partner allowlist.",
        ),
      )
    }
  }
}

///|
fn csp_check_form_action(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.values_for("form-action")
  if values.is_empty() {
    observations.push(
      csp_observation(
        "form-action.missing",
        Low,
        "form-action",
        "",
        "form submissions are not constrained by CSP.",
        "Add form-action 'self' for apps that submit credentials or personal data.",
      ),
    )
  } else {
    csp_check_source_values("form-action", values, observations)
  }
}

///|
fn csp_check_connect_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("connect-src")
  if !values.is_empty() {
    csp_check_source_values("connect-src", values, observations)
    if csp_values_have(values, "*") {
      observations.push(
        csp_observation(
          "connect-src.wildcard",
          Medium,
          "connect-src",
          values.join(" "),
          "connect-src allows requests to every origin.",
          "List API, metrics, and realtime endpoints explicitly.",
        ),
      )
    }
  }
}

///|
fn csp_check_frame_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("frame-src")
  if !values.is_empty() {
    csp_check_source_values("frame-src", values, observations)
    if csp_values_have(values, "*") {
      observations.push(
        csp_observation(
          "frame-src.wildcard",
          Medium,
          "frame-src",
          values.join(" "),
          "frame-src allows embedding arbitrary content.",
          "Use a narrow payment, video, or partner frame allowlist.",
        ),
      )
    }
  }
}

///|
fn csp_check_img_src(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let values = policy.effective_source_values("img-src")
  if !values.is_empty() {
    csp_check_source_values("img-src", values, observations)
    if csp_values_have(values, "data:") {
      observations.push(
        csp_observation(
          "img-src.data",
          Low,
          "img-src",
          values.join(" "),
          "img-src permits inline data: images.",
          "Keep data: only when placeholders or generated images are intentionally required.",
        ),
      )
    }
  }
}

///|
fn csp_check_reporting(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  if !policy.has_directive("report-uri") && !policy.has_directive("report-to") {
    observations.push(
      csp_observation(
        "reporting.missing",
        Info,
        "report-uri",
        "",
        "CSP violation reporting is not configured.",
        "Add report-to or report-uri in monitoring deployments.",
      ),
    )
  }
}

///|
fn csp_check_mixed_content(
  policy : CspPolicy,
  observations : Array[CspObservation],
) -> Unit {
  let all = policy.all_sources()
  let has_http = all.any(src => {
    src.kind == CspSourceHttpScheme || src.normalized.has_prefix("http://")
  })
  if has_http && !policy.has_directive("upgrade-insecure-requests") {
    observations.push(
      csp_observation(
        "mixed-content.no-upgrade",
        Medium,
        "upgrade-insecure-requests",
        "",
        "The policy allows HTTP sources without upgrade-insecure-requests.",
        "Prefer HTTPS sources and add upgrade-insecure-requests during migration.",
      ),
    )
  }
}

///|
fn csp_check_source_values(
  directive : String,
  values : Array[String],
  observations : Array[CspObservation],
) -> Unit {
  for value in values {
    let source = csp_source_expression(directive, value)
    if source.kind == CspSourceWildcard {
      observations.push(
        csp_observation(
          directive + ".wildcard-source",
          Medium,
          directive,
          source.raw,
          directive + " contains a wildcard source.",
          "Replace wildcard sources with explicit schemes or hosts.",
        ),
      )
    }
    if source.kind == CspSourceHttpScheme ||
      source.normalized.has_prefix("http://") {
      observations.push(
        csp_observation(
          directive + ".http-source",
          Medium,
          directive,
          source.raw,
          directive + " contains an insecure HTTP source.",
          "Use HTTPS-only source expressions.",
        ),
      )
    }
    if source.kind == CspSourceFilesystemScheme {
      observations.push(
        csp_observation(
          directive + ".filesystem-source",
          Low,
          directive,
          source.raw,
          directive + " allows filesystem: URLs.",
          "Remove filesystem: unless a controlled legacy browser surface requires it.",
        ),
      )
    }
  }
}

///|
pub fn CspAnalysis::to_findings(self : CspAnalysis) -> Array[Finding] {
  self.observations.map(obs => obs.to_finding())
}

///|
pub fn CspObservation::to_finding(self : CspObservation) -> Finding {
  {
    id: "csp.deep." + self.id,
    severity: self.severity,
    header: "content-security-policy",
    message: self.message,
    evidence: if self.source.is_empty() {
      self.directive
    } else {
      self.source
    },
    remediation: self.recommendation,
  }
}

///|
pub fn audit_headers_with_csp_analysis(raw : StringView) -> AuditReport {
  let base = audit_headers(raw)
  let findings = base.findings.copy()
  match base.headers.get("content-security-policy") {
    Some(value) => {
      let analysis = analyze_csp_header(value)
      for finding in analysis.to_findings() {
        if !csp_finding_id_exists(findings, finding.id) {
          findings.push(finding)
        }
      }
    }
    None => ()
  }
  let score = score_findings(findings)
  { score, grade: grade_score(score), findings, headers: base.headers }
}

///|
pub fn CspAnalysis::count_by_severity(
  self : CspAnalysis,
  severity : Severity,
) -> Int {
  self.observations.count_if(obs => obs.severity == severity)
}

///|
pub fn CspAnalysis::has_observation(
  self : CspAnalysis,
  id : StringView,
) -> Bool {
  let expected = id.to_owned()
  self.observations.any(obs => obs.id == expected)
}

///|
pub fn CspAnalysis::summary(self : CspAnalysis) -> String {
  "score=" +
  self.score.to_string() +
  ", directives=" +
  self.directives.length().to_string() +
  ", sources=" +
  self.sources.length().to_string() +
  ", observations=" +
  self.observations.length().to_string()
}

///|
pub fn CspAnalysis::to_markdown(self : CspAnalysis) -> String {
  let lines : Array[String] = []
  lines.push("# CSP Analysis")
  lines.push("")
  lines.push("- " + self.summary())
  lines.push("- critical=" + self.count_by_severity(Critical).to_string())
  lines.push("- high=" + self.count_by_severity(High).to_string())
  lines.push("- medium=" + self.count_by_severity(Medium).to_string())
  lines.push("- low=" + self.count_by_severity(Low).to_string())
  lines.push("")
  lines.push("## Directive Summary")
  lines.push("")
  lines.push("| Directive | Family | Explicit | Stance | Notes |")
  lines.push("| --- | --- | --- | --- | --- |")
  for directive in self.directives {
    lines.push(directive.to_markdown_row())
  }
  lines.push("")
  lines.push("## Sources")
  lines.push("")
  lines.push("| Directive | Source | Kind | Risk | Note |")
  lines.push("| --- | --- | --- | --- | --- |")
  for source in self.sources {
    lines.push(source.to_markdown_row())
  }
  lines.push("")
  lines.push("## Observations")
  lines.push("")
  for obs in self.observations {
    lines.push(
      "- " + obs.severity.label() + " `" + obs.id + "`: " + obs.message,
    )
  }
  lines.join("\n")
}

///|
pub fn CspAnalysis::to_json_string(self : CspAnalysis) -> String {
  Json::object(
    Map([
      (
        "score",
        Json::number(self.score.to_double(), repr=self.score.to_string()),
      ),
      ("summary", Json::string(self.summary())),
      (
        "directives",
        Json::array(
          self.directives.map(item => csp_directive_summary_json(item)),
        ),
      ),
      (
        "sources",
        Json::array(self.sources.map(item => csp_source_expression_json(item))),
      ),
      (
        "observations",
        Json::array(self.observations.map(item => csp_observation_json(item))),
      ),
    ]),
  ).stringify(indent=2)
}

///|
fn csp_directive_summary_json(item : CspDirectiveSummary) -> Json {
  Json::object(
    Map([
      ("name", Json::string(item.name)),
      ("family", Json::string(item.family.label())),
      ("explicit", Json::string(bool_word(item.explicit))),
      ("stance", Json::string(item.stance())),
      ("notes", Json::array(item.notes.map(note => Json::string(note)))),
    ]),
  )
}

///|
fn csp_source_expression_json(item : CspSourceExpression) -> Json {
  Json::object(
    Map([
      ("directive", Json::string(item.directive)),
      ("raw", Json::string(item.raw)),
      ("kind", Json::string(item.kind.label())),
      ("risk", Json::string(item.risk_label())),
      ("note", Json::string(item.note)),
    ]),
  )
}

///|
fn csp_observation_json(item : CspObservation) -> Json {
  Json::object(
    Map([
      ("id", Json::string(item.id)),
      ("severity", Json::string(item.severity.label())),
      ("directive", Json::string(item.directive)),
      ("source", Json::string(item.source)),
      ("message", Json::string(item.message)),
      ("recommendation", Json::string(item.recommendation)),
    ]),
  )
}

///|
fn csp_analysis_score(observations : Array[CspObservation]) -> Int {
  let mut score = 100
  for obs in observations {
    score = score - obs.severity.weight()
  }
  if score < 0 {
    0
  } else {
    score
  }
}

///|
fn csp_observation(
  id : String,
  severity : Severity,
  directive : String,
  source : String,
  message : String,
  recommendation : String,
) -> CspObservation {
  { id, severity, directive, source, message, recommendation }
}

///|
fn csp_source_secure_transport(
  kind : CspSourceKind,
  normalized : String,
) -> Bool {
  match kind {
    CspSourceHttpScheme => false
    CspSourceHost => !normalized.has_prefix("http://")
    _ => true
  }
}

///|
fn csp_source_is_broad(kind : CspSourceKind, normalized : String) -> Bool {
  kind == CspSourceWildcard ||
  kind == CspSourceUnsafeInline ||
  kind == CspSourceUnsafeEval ||
  kind == CspSourceDataScheme ||
  normalized.contains("://*") ||
  normalized == "*"
}

///|
fn csp_source_note(kind : CspSourceKind, normalized : String) -> String {
  match kind {
    CspSourceNone => "blocks the directive completely"
    CspSourceSelf => "same-origin source"
    CspSourceUnsafeInline => "allows inline code or styles"
    CspSourceUnsafeEval => "allows dynamic code evaluation"
    CspSourceStrictDynamic =>
      "delegates trust from nonce or hash bootstrap code"
    CspSourceNonce => "nonce based source token"
    CspSourceHash => "hash based source token"
    CspSourceHttpsScheme => "allows any HTTPS origin"
    CspSourceHttpScheme => "allows insecure HTTP origins"
    CspSourceDataScheme => "allows inline data URLs"
    CspSourceBlobScheme => "allows generated blob URLs"
    CspSourceFilesystemScheme => "allows filesystem URLs"
    CspSourceWildcard => "matches a broad set of origins"
    CspSourceHost =>
      if normalized.has_prefix("https://") {
        "explicit HTTPS host"
      } else {
        "explicit host"
      }
    CspSourceKeyword => "CSP keyword source"
    CspSourceUnknown => "unclassified source expression"
  }
}

///|
fn csp_values_have(values : Array[String], token : String) -> Bool {
  let expected = csp_normalize_source(token)
  values.any(value => csp_normalize_source(value) == expected)
}

///|
fn csp_values_have_kind(values : Array[String], kind : CspSourceKind) -> Bool {
  values.any(value => classify_csp_source(value) == kind)
}

///|
fn csp_finding_id_exists(findings : Array[Finding], id : String) -> Bool {
  findings.any(finding => finding.id == id)
}

///|
fn csp_normalize_name(name : StringView) -> String {
  name.trim().to_lower().to_owned()
}

///|
fn csp_normalize_source(token : StringView) -> String {
  token.trim().to_lower().to_owned()
}

///|
fn bool_word(flag : Bool) -> String {
  if flag {
    "yes"
  } else {
    "no"
  }
}
