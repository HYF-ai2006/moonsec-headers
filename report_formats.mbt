///|
/// Additional renderers for audit reports and profile assessments.
pub(all) enum ReportFormat {
  Markdown
  PlainText
  Checklist
  Json
  Sarif
} derive(Eq, Debug)

///|
pub(all) struct RenderOptions {
  title : String
  limit : Int
  include_evidence : Bool
  include_remediation : Bool
  sort_by_severity : Bool
} derive(Eq, Debug)

///|
pub fn default_render_options() -> RenderOptions {
  {
    title: "Security Header Audit",
    limit: 50,
    include_evidence: true,
    include_remediation: true,
    sort_by_severity: true,
  }
}

///|
pub fn no_detail_render_options() -> RenderOptions {
  {
    title: "Security Header Audit",
    limit: 20,
    include_evidence: false,
    include_remediation: false,
    sort_by_severity: true,
  }
}

///|
pub fn AuditReport::render(
  self : AuditReport,
  format : ReportFormat,
  options? : RenderOptions = default_render_options(),
) -> String {
  match format {
    Markdown => self.to_detailed_markdown(options)
    PlainText => self.to_plain_text(options)
    Checklist => self.to_checklist_markdown(options)
    Json => self.to_json_string()
    Sarif => self.to_sarif_string(options)
  }
}

///|
pub fn AuditReport::to_detailed_markdown(
  self : AuditReport,
  options : RenderOptions,
) -> String {
  let findings = self.rendered_findings(options)
  let lines : Array[String] = []
  lines.push("# " + options.title)
  lines.push("")
  lines.push("- Score: " + self.score.to_string())
  lines.push("- Grade: " + self.grade)
  lines.push("- Findings: " + findings.length().to_string())
  lines.push("")
  lines.push("| Severity | Header | Message |")
  lines.push("| --- | --- | --- |")
  for finding in findings {
    lines.push(finding.to_markdown_row())
    if options.include_evidence {
      lines.push("")
      lines.push("  - Evidence: " + non_empty_or_dash(finding.evidence))
    }
    if options.include_remediation {
      lines.push("  - Remediation: " + non_empty_or_dash(finding.remediation))
    }
  }
  lines.join("\n")
}

///|
pub fn AuditReport::to_plain_text(
  self : AuditReport,
  options : RenderOptions,
) -> String {
  let findings = self.rendered_findings(options)
  let lines : Array[String] = []
  lines.push(options.title)
  lines.push("score=" + self.score.to_string() + ", grade=" + self.grade)
  lines.push("findings=" + findings.length().to_string())
  for finding in findings {
    lines.push(finding.to_plain_text_line())
    if options.include_evidence {
      lines.push("  evidence: " + non_empty_or_dash(finding.evidence))
    }
    if options.include_remediation {
      lines.push("  remediation: " + non_empty_or_dash(finding.remediation))
    }
  }
  lines.join("\n")
}

///|
pub fn AuditReport::to_checklist_markdown(
  self : AuditReport,
  options : RenderOptions,
) -> String {
  let findings = self.rendered_findings(options)
  let lines : Array[String] = []
  lines.push("# " + options.title + " Checklist")
  lines.push("")
  lines.push("- [x] Score " + self.score.to_string())
  lines.push("- [x] Grade " + self.grade)
  lines.push("- [x] Findings " + findings.length().to_string())
  lines.push("")
  for finding in findings {
    lines.push(
      "- [ ] " +
      finding.severity.label() +
      " " +
      finding.header +
      ": " +
      finding.message,
    )
    if options.include_remediation {
      lines.push("  - Fix: " + non_empty_or_dash(finding.remediation))
    }
  }
  lines.join("\n")
}

///|
pub fn AuditReport::to_sarif_string(
  self : AuditReport,
  options : RenderOptions,
) -> String {
  let findings = self.rendered_findings(options)
  let results : Array[Json] = []
  for finding in findings {
    results.push(finding_to_sarif_json(finding))
  }
  let sarif = Json::object(
    Map([
      ("version", Json::string("2.1.0")),
      (
        "runs",
        Json::array([
          Json::object(
            Map([
              (
                "tool",
                Json::object(
                  Map([
                    (
                      "driver",
                      Json::object(
                        Map([
                          ("name", Json::string("moonsec-headers")),
                          (
                            "informationUri",
                            Json::string(
                              "https://github.com/HYF-ai2006/moonsec-headers",
                            ),
                          ),
                        ]),
                      ),
                    ),
                  ]),
                ),
              ),
              ("results", Json::array(results)),
            ]),
          ),
        ]),
      ),
    ]),
  )
  sarif.stringify(indent=2)
}

///|
pub fn Finding::to_markdown_row(self : Finding) -> String {
  "| " +
  self.severity.label() +
  " | " +
  self.header +
  " | " +
  self.message +
  " |"
}

///|
pub fn Finding::to_plain_text_line(self : Finding) -> String {
  self.severity.label() + " " + self.header + ": " + self.message
}

///|
fn finding_to_sarif_json(finding : Finding) -> Json {
  Json::object(
    Map([
      ("ruleId", Json::string(finding.id)),
      ("level", Json::string(finding.severity.label())),
      ("message", Json::object(Map([("text", Json::string(finding.message))]))),
      (
        "properties",
        Json::object(
          Map([
            ("header", Json::string(finding.header)),
            ("evidence", Json::string(finding.evidence)),
            ("remediation", Json::string(finding.remediation)),
          ]),
        ),
      ),
    ]),
  )
}

///|
pub fn AuditReport::rendered_findings(
  self : AuditReport,
  options : RenderOptions,
) -> Array[Finding] {
  let findings = self.findings.copy()
  if options.sort_by_severity {
    findings.sort_by((a, b) => b.severity.weight() - a.severity.weight())
  }
  if findings.length() > options.limit {
    ignore(findings.drain(options.limit, findings.length()))
  }
  findings
}

///|
pub fn AuditReport::top_findings(
  self : AuditReport,
  limit : Int,
) -> Array[Finding] {
  let options = default_render_options()
  let findings = self.rendered_findings({
    title: options.title,
    limit,
    include_evidence: options.include_evidence,
    include_remediation: options.include_remediation,
    sort_by_severity: true,
  })
  findings
}

///|
pub fn AuditReport::findings_by_header(
  self : AuditReport,
  name : StringView,
) -> Array[Finding] {
  let expected = normalize_header_name(name)
  self.findings.filter(f => f.header == expected)
}

///|
pub fn AuditReport::findings_by_severity(
  self : AuditReport,
  severity : Severity,
) -> Array[Finding] {
  self.findings.filter(f => f.severity == severity)
}

///|
pub fn AuditReport::severity_breakdown(self : AuditReport) -> String {
  let critical = self.count_by_severity(Critical)
  let high = self.count_by_severity(High)
  let medium = self.count_by_severity(Medium)
  let low = self.count_by_severity(Low)
  let info = self.count_by_severity(Info)
  "critical=" +
  critical.to_string() +
  ", high=" +
  high.to_string() +
  ", medium=" +
  medium.to_string() +
  ", low=" +
  low.to_string() +
  ", info=" +
  info.to_string()
}

///|
pub fn AuditReport::to_issue_summary(self : AuditReport) -> String {
  let lines : Array[String] = []
  lines.push("# Issue Summary")
  lines.push("")
  lines.push("- Breakdown: " + self.severity_breakdown())
  lines.push("")
  for finding in self.findings {
    lines.push("- " + finding.id + " -> " + finding.to_plain_text_line())
  }
  lines.join("\n")
}

///|
fn non_empty_or_dash(value : String) -> String {
  if value.is_empty() {
    "-"
  } else {
    value
  }
}

///|
pub fn ProfileAssessment::to_plain_text(self : ProfileAssessment) -> String {
  let lines : Array[String] = []
  lines.push("Profile " + self.profile_key)
  lines.push("score=" + self.score.to_string())
  lines.push(self.summary())
  for finding in self.findings {
    lines.push(
      finding.name +
      " " +
      finding.status.label() +
      " " +
      finding.severity.label(),
    )
  }
  lines.join("\n")
}

///|
pub fn ProfileAssessment::to_checklist(self : ProfileAssessment) -> String {
  let lines : Array[String] = []
  lines.push("# Profile Checklist")
  lines.push("")
  for finding in self.findings {
    lines.push("- [ ] " + finding.name + " " + finding.status.label())
  }
  lines.join("\n")
}

///|
pub fn ProfileAssessment::to_json_string(self : ProfileAssessment) -> String {
  let items : Array[Json] = []
  for finding in self.findings {
    items.push(
      Json::object(
        Map([
          ("name", Json::string(finding.name)),
          ("status", Json::string(finding.status.label())),
          ("expected", Json::string(finding.expected)),
          ("actual", Json::string(option_text(finding.actual))),
          ("severity", Json::string(finding.severity.label())),
          ("rationale", Json::string(finding.rationale)),
        ]),
      ),
    )
  }
  Json::object(
    Map([
      ("profile_key", Json::string(self.profile_key)),
      (
        "score",
        Json::number(self.score.to_double(), repr=self.score.to_string()),
      ),
      (
        "matched",
        Json::number(self.matched.to_double(), repr=self.matched.to_string()),
      ),
      (
        "missing",
        Json::number(self.missing.to_double(), repr=self.missing.to_string()),
      ),
      ("weak", Json::number(self.weak.to_double(), repr=self.weak.to_string())),
      (
        "conflict",
        Json::number(self.conflict.to_double(), repr=self.conflict.to_string()),
      ),
      (
        "optional",
        Json::number(self.optional.to_double(), repr=self.optional.to_string()),
      ),
      ("findings", Json::array(items)),
    ]),
  ).stringify(indent=2)
}

///|
pub fn ProfileAssessment::recommendations(
  self : ProfileAssessment,
) -> Array[String] {
  let lines : Array[String] = []
  for finding in self.findings {
    match finding.status {
      Missing => lines.push("Add " + finding.name + ": " + finding.expected)
      Weak => lines.push("Tighten " + finding.name + ": " + finding.expected)
      Conflict => lines.push("Remove or change " + finding.name)
      Satisfied => ()
      Optional => ()
    }
  }
  lines
}

///|
pub fn ProfileAssessment::to_recommendations_markdown(
  self : ProfileAssessment,
) -> String {
  let lines : Array[String] = []
  lines.push("# Recommendations")
  lines.push("")
  for item in self.recommendations() {
    lines.push("- " + item)
  }
  lines.join("\n")
}
