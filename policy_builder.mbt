///|
/// Header and CSP policy builders.
///
/// This module lets callers generate deterministic response-header baselines
/// instead of copying long strings between services and CI fixtures.
pub(all) enum HeaderPlanKind {
  HeaderPlanStaticSite
  HeaderPlanSpaApp
  HeaderPlanApiService
  HeaderPlanAdminConsole
  HeaderPlanLoginFlow
  HeaderPlanMediaCdn
  HeaderPlanCustom
} derive(Eq, Debug)

///|
pub(all) enum ValidationLevel {
  ValidationError
  ValidationWarning
  ValidationNote
} derive(Eq, Debug)

///|
pub(all) struct HeaderPair {
  name : String
  value : String
} derive(Eq, Debug)

///|
pub(all) struct CspDirectiveSpec {
  name : String
  values : Array[String]
} derive(Eq, Debug)

///|
pub(all) struct CspBuilder {
  report_only : Bool
  directives : Array[CspDirectiveSpec]
} derive(Eq, Debug)

///|
pub(all) struct HstsConfig {
  max_age : Int
  include_subdomains : Bool
  preload : Bool
} derive(Eq, Debug)

///|
pub(all) struct ValidationMessage {
  level : ValidationLevel
  field : String
  message : String
} derive(Eq, Debug)

///|
pub(all) struct PolicyValidation {
  ok : Bool
  messages : Array[ValidationMessage]
} derive(Eq, Debug)

///|
pub(all) struct HeaderPlan {
  kind : HeaderPlanKind
  title : String
  scenario : String
  headers : Array[HeaderPair]
  notes : Array[String]
} derive(Eq, Debug)

///|
pub fn HeaderPlanKind::label(self : HeaderPlanKind) -> String {
  match self {
    HeaderPlanStaticSite => "static-site"
    HeaderPlanSpaApp => "spa-app"
    HeaderPlanApiService => "api-service"
    HeaderPlanAdminConsole => "admin-console"
    HeaderPlanLoginFlow => "login-flow"
    HeaderPlanMediaCdn => "media-cdn"
    HeaderPlanCustom => "custom"
  }
}

///|
pub fn ValidationLevel::label(self : ValidationLevel) -> String {
  match self {
    ValidationError => "error"
    ValidationWarning => "warning"
    ValidationNote => "note"
  }
}

///|
pub fn header_pair(name : StringView, value : StringView) -> HeaderPair {
  { name: name.trim().to_owned(), value: value.trim().to_owned() }
}

///|
pub fn HeaderPair::line(self : HeaderPair) -> String {
  self.name + ": " + self.value
}

///|
pub fn HeaderPair::normalized_name(self : HeaderPair) -> String {
  normalize_header_name(self.name)
}

///|
pub fn HeaderPair::to_markdown_row(self : HeaderPair) -> String {
  "| `" +
  self.name +
  "` | `" +
  self.value.replace_all(old="|", new="\\|") +
  "` |"
}

///|
pub fn new_csp_builder() -> CspBuilder {
  { report_only: false, directives: [] }
}

///|
pub fn csp_report_only_builder() -> CspBuilder {
  { report_only: true, directives: [] }
}

///|
pub fn CspBuilder::as_enforcing(self : CspBuilder) -> CspBuilder {
  { report_only: false, directives: self.copy_directives() }
}

///|
pub fn CspBuilder::as_report_only(self : CspBuilder) -> CspBuilder {
  { report_only: true, directives: self.copy_directives() }
}

///|
pub fn CspBuilder::copy_directives(
  self : CspBuilder,
) -> Array[CspDirectiveSpec] {
  self.directives.map(spec => { name: spec.name, values: spec.values.copy() })
}

///|
pub fn CspBuilder::with_directive(
  self : CspBuilder,
  name : StringView,
  values : Array[String],
) -> CspBuilder {
  let normalized = builder_normalize_name(name)
  let next : Array[CspDirectiveSpec] = []
  let mut found = false
  for spec in self.directives {
    if spec.name == normalized {
      next.push({ name: normalized, values: values.copy() })
      found = true
    } else {
      next.push({ name: spec.name, values: spec.values.copy() })
    }
  }
  if !found {
    next.push({ name: normalized, values: values.copy() })
  }
  { report_only: self.report_only, directives: next }
}

///|
pub fn CspBuilder::append_value(
  self : CspBuilder,
  name : StringView,
  value : StringView,
) -> CspBuilder {
  let normalized = builder_normalize_name(name)
  let next : Array[CspDirectiveSpec] = []
  let mut found = false
  for spec in self.directives {
    if spec.name == normalized {
      let values = spec.values.copy()
      let token = value.trim().to_owned()
      if !values.any(item => item == token) {
        values.push(token)
      }
      next.push({ name: spec.name, values })
      found = true
    } else {
      next.push({ name: spec.name, values: spec.values.copy() })
    }
  }
  if !found {
    next.push({ name: normalized, values: [value.trim().to_owned()] })
  }
  { report_only: self.report_only, directives: next }
}

///|
pub fn CspBuilder::without_directive(
  self : CspBuilder,
  name : StringView,
) -> CspBuilder {
  let normalized = builder_normalize_name(name)
  {
    report_only: self.report_only,
    directives: self.directives
    .filter(spec => spec.name != normalized)
    .map(spec => { name: spec.name, values: spec.values.copy() }),
  }
}

///|
pub fn CspBuilder::has_directive(self : CspBuilder, name : StringView) -> Bool {
  let normalized = builder_normalize_name(name)
  self.directives.any(spec => spec.name == normalized)
}

///|
pub fn CspBuilder::values_for(
  self : CspBuilder,
  name : StringView,
) -> Array[String] {
  let normalized = builder_normalize_name(name)
  match self.directives.iter().find_first(spec => spec.name == normalized) {
    Some(spec) => spec.values.copy()
    None => []
  }
}

///|
pub fn CspBuilder::header_name(self : CspBuilder) -> String {
  if self.report_only {
    "Content-Security-Policy-Report-Only"
  } else {
    "Content-Security-Policy"
  }
}

///|
pub fn CspDirectiveSpec::render(self : CspDirectiveSpec) -> String {
  if self.values.is_empty() {
    self.name
  } else {
    self.name + " " + self.values.join(" ")
  }
}

///|
pub fn CspBuilder::render(self : CspBuilder) -> String {
  self.directives.map(spec => spec.render()).join("; ")
}

///|
pub fn CspBuilder::to_header_pair(self : CspBuilder) -> HeaderPair {
  header_pair(self.header_name(), self.render())
}

///|
pub fn CspBuilder::to_header_line(self : CspBuilder) -> String {
  self.to_header_pair().line()
}

///|
pub fn CspBuilder::parse_policy(self : CspBuilder) -> CspPolicy {
  parse_csp(self.render())
}

///|
pub fn CspBuilder::analyze(self : CspBuilder) -> CspAnalysis {
  analyze_csp_policy(self.parse_policy())
}

///|
pub fn CspBuilder::validate(self : CspBuilder) -> PolicyValidation {
  let messages : Array[ValidationMessage] = []
  let names : Array[String] = []
  for spec in self.directives {
    if spec.name.trim().is_empty() {
      messages.push(
        validation_message(
          ValidationError,
          "directive",
          "CSP directive name cannot be empty.",
        ),
      )
    }
    if names.any(name => name == spec.name) {
      messages.push(
        validation_message(
          ValidationError,
          spec.name,
          "CSP directive appears more than once in the builder.",
        ),
      )
    } else {
      names.push(spec.name)
    }
    if spec.values.length() > 1 &&
      spec.values.any(value => builder_normalize_value(value) == "'none'") {
      messages.push(
        validation_message(
          ValidationWarning,
          spec.name,
          "'none' should not be combined with other source expressions.",
        ),
      )
    }
    for value in spec.values {
      let source = csp_source_expression(spec.name, value)
      if source.kind == CspSourceUnknown {
        messages.push(
          validation_message(
            ValidationNote,
            spec.name,
            "Source expression `" +
            value +
            "` is not recognized by the lightweight classifier.",
          ),
        )
      }
      if !source.secure_transport {
        messages.push(
          validation_message(
            ValidationWarning,
            spec.name,
            "Source expression `" + value + "` uses insecure transport.",
          ),
        )
      }
    }
  }
  if !self.has_directive("default-src") {
    messages.push(
      validation_message(
        ValidationWarning,
        "default-src",
        "default-src is recommended as a clear fallback.",
      ),
    )
  }
  {
    ok: messages.count_if(item => item.level == ValidationError) == 0,
    messages,
  }
}

///|
pub fn hsts_config(
  max_age : Int,
  include_subdomains : Bool,
  preload : Bool,
) -> HstsConfig {
  { max_age, include_subdomains, preload }
}

///|
pub fn recommended_hsts_config() -> HstsConfig {
  { max_age: 31536000, include_subdomains: true, preload: false }
}

///|
pub fn HstsConfig::render(self : HstsConfig) -> String {
  let parts : Array[String] = ["max-age=" + self.max_age.to_string()]
  if self.include_subdomains {
    parts.push("includeSubDomains")
  }
  if self.preload {
    parts.push("preload")
  }
  parts.join("; ")
}

///|
pub fn HstsConfig::to_header_pair(self : HstsConfig) -> HeaderPair {
  header_pair("Strict-Transport-Security", self.render())
}

///|
pub fn hsts_header(
  max_age : Int,
  include_subdomains : Bool,
  preload : Bool,
) -> HeaderPair {
  hsts_config(max_age, include_subdomains, preload).to_header_pair()
}

///|
pub fn x_content_type_options_header() -> HeaderPair {
  header_pair("X-Content-Type-Options", "nosniff")
}

///|
pub fn referrer_policy_header(value : StringView) -> HeaderPair {
  header_pair("Referrer-Policy", value)
}

///|
pub fn x_frame_options_header(value : StringView) -> HeaderPair {
  header_pair("X-Frame-Options", value)
}

///|
pub fn cross_origin_opener_policy_header(value : StringView) -> HeaderPair {
  header_pair("Cross-Origin-Opener-Policy", value)
}

///|
pub fn cross_origin_resource_policy_header(value : StringView) -> HeaderPair {
  header_pair("Cross-Origin-Resource-Policy", value)
}

///|
pub fn cross_origin_embedder_policy_header(value : StringView) -> HeaderPair {
  header_pair("Cross-Origin-Embedder-Policy", value)
}

///|
pub fn permissions_policy_header(
  disabled_features : Array[String],
) -> HeaderPair {
  let values : Array[String] = []
  for feature in disabled_features {
    values.push(feature + "=()")
  }
  header_pair("Permissions-Policy", values.join(", "))
}

///|
pub fn cache_control_header(value : StringView) -> HeaderPair {
  header_pair("Cache-Control", value)
}

///|
pub fn content_disposition_header(value : StringView) -> HeaderPair {
  header_pair("Content-Disposition", value)
}

///|
pub fn static_site_csp() -> CspBuilder {
  new_csp_builder()
  .with_directive("default-src", ["'self'"])
  .with_directive("object-src", ["'none'"])
  .with_directive("base-uri", ["'self'"])
  .with_directive("frame-ancestors", ["'none'"])
  .with_directive("script-src", ["'self'"])
  .with_directive("style-src", ["'self'"])
  .with_directive("img-src", ["'self'", "data:"])
  .with_directive("font-src", ["'self'"])
  .with_directive("connect-src", ["'self'"])
  .with_directive("form-action", ["'self'"])
}

///|
pub fn spa_csp(
  api_origin : StringView,
  asset_origin : StringView,
) -> CspBuilder {
  static_site_csp()
  .with_directive("connect-src", ["'self'", api_origin.trim().to_owned()])
  .append_value("script-src", asset_origin)
  .append_value("style-src", asset_origin)
}

///|
pub fn api_service_csp() -> CspBuilder {
  new_csp_builder()
  .with_directive("default-src", ["'none'"])
  .with_directive("object-src", ["'none'"])
  .with_directive("frame-ancestors", ["'none'"])
  .with_directive("base-uri", ["'none'"])
  .with_directive("form-action", ["'none'"])
}

///|
pub fn admin_console_csp(api_origin : StringView) -> CspBuilder {
  new_csp_builder()
  .with_directive("default-src", ["'self'"])
  .with_directive("script-src", ["'self'"])
  .with_directive("style-src", ["'self'"])
  .with_directive("connect-src", ["'self'", api_origin.trim().to_owned()])
  .with_directive("img-src", ["'self'", "data:"])
  .with_directive("object-src", ["'none'"])
  .with_directive("base-uri", ["'self'"])
  .with_directive("frame-ancestors", ["'none'"])
  .with_directive("form-action", ["'self'"])
}

///|
pub fn login_flow_csp(identity_origin : StringView) -> CspBuilder {
  new_csp_builder()
  .with_directive("default-src", ["'self'"])
  .with_directive("script-src", ["'self'"])
  .with_directive("style-src", ["'self'"])
  .with_directive("connect-src", ["'self'", identity_origin.trim().to_owned()])
  .with_directive("img-src", ["'self'", "data:"])
  .with_directive("object-src", ["'none'"])
  .with_directive("base-uri", ["'self'"])
  .with_directive("frame-ancestors", ["'none'"])
  .with_directive("form-action", ["'self'", identity_origin.trim().to_owned()])
}

///|
pub fn media_cdn_csp() -> CspBuilder {
  new_csp_builder()
  .with_directive("default-src", ["'none'"])
  .with_directive("img-src", ["'self'", "https:"])
  .with_directive("media-src", ["'self'", "https:"])
  .with_directive("font-src", ["'self'", "https:"])
  .with_directive("object-src", ["'none'"])
  .with_directive("base-uri", ["'none'"])
  .with_directive("frame-ancestors", ["'none'"])
}

///|
pub fn header_plan(
  kind : HeaderPlanKind,
  title : StringView,
  scenario : StringView,
  headers : Array[HeaderPair],
  notes : Array[String],
) -> HeaderPlan {
  {
    kind,
    title: title.to_owned(),
    scenario: scenario.to_owned(),
    headers,
    notes,
  }
}

///|
pub fn static_site_header_plan() -> HeaderPlan {
  header_plan(
    HeaderPlanStaticSite,
    "Static Site Baseline",
    "Public static pages with no privileged browser API access.",
    [
      static_site_csp().to_header_pair(),
      recommended_hsts_config().to_header_pair(),
      x_content_type_options_header(),
      referrer_policy_header("strict-origin-when-cross-origin"),
      permissions_policy_header(["camera", "microphone", "geolocation"]),
      cross_origin_opener_policy_header("same-origin"),
      cross_origin_resource_policy_header("same-origin"),
    ],
    [
      "Designed for documentation, landing pages, and generated static sites.", "If third-party analytics are used, add only the required script and connect origins.",
    ],
  )
}

///|
pub fn spa_header_plan(
  api_origin : StringView,
  asset_origin : StringView,
) -> HeaderPlan {
  header_plan(
    HeaderPlanSpaApp,
    "SPA Baseline",
    "Single-page app shell with explicit API and asset origins.",
    [
      spa_csp(api_origin, asset_origin).to_header_pair(),
      recommended_hsts_config().to_header_pair(),
      x_content_type_options_header(),
      referrer_policy_header("strict-origin-when-cross-origin"),
      permissions_policy_header(["camera", "microphone", "geolocation"]),
      cross_origin_opener_policy_header("same-origin"),
      cross_origin_resource_policy_header("same-origin"),
    ],
    [
      "Keep API and asset origins separate so review output is easy to compare.",
      "Use report-only mode first if the current frontend has unknown dynamic imports.",
    ],
  )
}

///|
pub fn api_service_header_plan() -> HeaderPlan {
  header_plan(
    HeaderPlanApiService,
    "API Service Baseline",
    "JSON or RPC endpoints that should not expose browser execution surfaces.",
    [
      api_service_csp().to_header_pair(),
      recommended_hsts_config().to_header_pair(),
      x_content_type_options_header(),
      referrer_policy_header("no-referrer"),
      permissions_policy_header([
        "camera", "microphone", "geolocation", "payment", "usb",
      ]),
      cross_origin_opener_policy_header("same-origin"),
      cross_origin_resource_policy_header("same-origin"),
    ],
    [
      "CORS is intentionally not enabled by default.", "Add explicit Access-Control-Allow-Origin only for known browser clients.",
    ],
  )
}

///|
pub fn admin_console_header_plan(api_origin : StringView) -> HeaderPlan {
  header_plan(
    HeaderPlanAdminConsole,
    "Admin Console Baseline",
    "Authenticated operational UI with a high-value session surface.",
    [
      admin_console_csp(api_origin).to_header_pair(),
      hsts_header(31536000, true, false),
      x_content_type_options_header(),
      referrer_policy_header("no-referrer"),
      permissions_policy_header([
        "camera", "microphone", "geolocation", "payment", "usb",
      ]),
      cross_origin_opener_policy_header("same-origin"),
      cross_origin_resource_policy_header("same-origin"),
      x_frame_options_header("DENY"),
    ],
    [
      "Use no-referrer for administrative paths that may contain tenant or incident identifiers.",
      "Keep frame embedding disabled unless there is a documented SSO or support workflow.",
    ],
  )
}

///|
pub fn login_flow_header_plan(identity_origin : StringView) -> HeaderPlan {
  header_plan(
    HeaderPlanLoginFlow,
    "Login Flow Baseline",
    "Credential and MFA pages that post to a known identity origin.",
    [
      login_flow_csp(identity_origin).to_header_pair(),
      hsts_header(31536000, true, false),
      x_content_type_options_header(),
      referrer_policy_header("no-referrer"),
      permissions_policy_header(["camera", "microphone", "geolocation"]),
      cross_origin_opener_policy_header("same-origin"),
      cross_origin_resource_policy_header("same-origin"),
      x_frame_options_header("DENY"),
    ],
    [
      "Camera or microphone should be opened only for explicit MFA screens.", "Form targets stay limited to the application and identity provider.",
    ],
  )
}

///|
pub fn media_cdn_header_plan() -> HeaderPlan {
  header_plan(
    HeaderPlanMediaCdn,
    "Media CDN Baseline",
    "Static asset delivery edge for images, fonts, and media files.",
    [
      media_cdn_csp().to_header_pair(),
      hsts_header(31536000, true, false),
      x_content_type_options_header(),
      referrer_policy_header("no-referrer"),
      permissions_policy_header(["camera", "microphone", "geolocation"]),
      cross_origin_resource_policy_header("cross-origin"),
      cache_control_header("public, max-age=31536000, immutable"),
    ],
    [
      "CDN resources may intentionally be cross-origin embeddable.", "Keep executable surfaces disabled on asset hosts.",
    ],
  )
}

///|
pub fn HeaderPlan::to_header_block(self : HeaderPlan) -> String {
  self.headers.map(header => header.line()).join("\n")
}

///|
pub fn HeaderPlan::audit(self : HeaderPlan) -> AuditReport {
  audit_headers(self.to_header_block())
}

///|
pub fn HeaderPlan::audit_deep(self : HeaderPlan) -> AuditReport {
  audit_headers_with_csp_analysis(self.to_header_block())
}

///|
pub fn HeaderPlan::assess_with_profile(
  self : HeaderPlan,
  key : StringView,
) -> ProfileAssessment? {
  match profile_lookup(key) {
    Some(profile) =>
      Some(profile.score_headers(parse_headers(self.to_header_block())))
    None => None
  }
}

///|
pub fn HeaderPlan::validate(self : HeaderPlan) -> PolicyValidation {
  let messages : Array[ValidationMessage] = []
  let names : Array[String] = []
  for header in self.headers {
    let normalized = header.normalized_name()
    if normalized.is_empty() {
      messages.push(
        validation_message(
          ValidationError,
          "header",
          "Header name cannot be empty.",
        ),
      )
    }
    if names.any(name => name == normalized) {
      messages.push(
        validation_message(
          ValidationWarning,
          normalized,
          "Header appears more than once in the plan.",
        ),
      )
    } else {
      names.push(normalized)
    }
    if has_control_character_public(header.name) ||
      has_control_character_public(header.value) {
      messages.push(
        validation_message(
          ValidationError,
          normalized,
          "Header contains a control character.",
        ),
      )
    }
    if normalized == "content-security-policy" {
      let validation = parse_csp(header.value).issues
      for issue in validation {
        messages.push(
          validation_message(
            ValidationWarning,
            "content-security-policy",
            issue.message,
          ),
        )
      }
    }
  }
  if !names.any(name => name == "content-security-policy") {
    messages.push(
      validation_message(
        ValidationWarning,
        "content-security-policy",
        "Header plan does not include an enforcing CSP.",
      ),
    )
  }
  {
    ok: messages.count_if(message => message.level == ValidationError) == 0,
    messages,
  }
}

///|
pub fn HeaderPlan::to_markdown(self : HeaderPlan) -> String {
  let lines : Array[String] = []
  lines.push("# " + self.title)
  lines.push("")
  lines.push("- Kind: `" + self.kind.label() + "`")
  lines.push("- Scenario: " + self.scenario)
  lines.push("- Headers: " + self.headers.length().to_string())
  lines.push("")
  lines.push("| Header | Value |")
  lines.push("| --- | --- |")
  for header in self.headers {
    lines.push(header.to_markdown_row())
  }
  if !self.notes.is_empty() {
    lines.push("")
    lines.push("## Notes")
    for note in self.notes {
      lines.push("- " + note)
    }
  }
  lines.join("\n")
}

///|
pub fn HeaderPlan::to_json_string(self : HeaderPlan) -> String {
  Json::object(
    Map([
      ("kind", Json::string(self.kind.label())),
      ("title", Json::string(self.title)),
      ("scenario", Json::string(self.scenario)),
      ("headers", Json::array(self.headers.map(header => header_json(header)))),
      ("notes", Json::array(self.notes.map(note => Json::string(note)))),
    ]),
  ).stringify(indent=2)
}

///|
pub fn PolicyValidation::error_count(self : PolicyValidation) -> Int {
  self.messages.count_if(message => message.level == ValidationError)
}

///|
pub fn PolicyValidation::warning_count(self : PolicyValidation) -> Int {
  self.messages.count_if(message => message.level == ValidationWarning)
}

///|
pub fn PolicyValidation::note_count(self : PolicyValidation) -> Int {
  self.messages.count_if(message => message.level == ValidationNote)
}

///|
pub fn PolicyValidation::to_markdown(self : PolicyValidation) -> String {
  let lines : Array[String] = []
  lines.push("# Policy Validation")
  lines.push("")
  lines.push("- OK: " + builder_bool_word(self.ok))
  lines.push("- Errors: " + self.error_count().to_string())
  lines.push("- Warnings: " + self.warning_count().to_string())
  lines.push("- Notes: " + self.note_count().to_string())
  lines.push("")
  for message in self.messages {
    lines.push(
      "- " +
      message.level.label() +
      " `" +
      message.field +
      "`: " +
      message.message,
    )
  }
  lines.join("\n")
}

///|
pub fn header_plan_catalog() -> Array[HeaderPlan] {
  [
    static_site_header_plan(),
    spa_header_plan("https://api.example.test", "https://assets.example.test"),
    api_service_header_plan(),
    admin_console_header_plan("https://api-admin.example.test"),
    login_flow_header_plan("https://id.example.test"),
    media_cdn_header_plan(),
  ]
}

///|
pub fn header_plan_keys() -> Array[String] {
  header_plan_catalog().map(plan => plan.kind.label())
}

///|
pub fn header_plan_by_key(key : StringView) -> HeaderPlan? {
  let expected = key.trim().to_lower().to_owned()
  for plan in header_plan_catalog() {
    if plan.kind.label() == expected {
      return Some(plan)
    }
  }
  None
}

///|
pub fn header_plan_catalog_markdown() -> String {
  let lines : Array[String] = []
  lines.push("# Header Plan Catalog")
  lines.push("")
  for plan in header_plan_catalog() {
    lines.push("- `" + plan.kind.label() + "` - " + plan.scenario)
  }
  lines.join("\n")
}

///|
fn validation_message(
  level : ValidationLevel,
  field : String,
  message : String,
) -> ValidationMessage {
  { level, field, message }
}

///|
fn header_json(header : HeaderPair) -> Json {
  Json::object(
    Map([
      ("name", Json::string(header.name)),
      ("value", Json::string(header.value)),
      ("line", Json::string(header.line())),
    ]),
  )
}

///|
fn builder_normalize_name(name : StringView) -> String {
  name.trim().to_lower().to_owned()
}

///|
fn builder_normalize_value(value : StringView) -> String {
  value.trim().to_lower().to_owned()
}

///|
fn builder_bool_word(flag : Bool) -> String {
  if flag {
    "yes"
  } else {
    "no"
  }
}

///|
fn has_control_character_public(value : String) -> Bool {
  value.any(ch => {
    let code = ch.to_int()
    code < 32 && ch != '\t'
  })
}
