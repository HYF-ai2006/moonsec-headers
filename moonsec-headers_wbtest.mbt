///|
test "parse_header_line normalizes names and trims values" {
  let parsed = parse_header_line(
    " Content-Security-Policy : default-src 'self' ", 7,
  )
  match parsed {
    Ok(header) => {
      @test.assert_eq(header.name, "content-security-policy")
      @test.assert_eq(header.value, "default-src 'self'")
      @test.assert_eq(header.line, 7)
    }
    Err(_) => fail("expected header line to parse")
  }
}

///|
test "parse_header_line reports malformed input" {
  match parse_header_line("not a header", 3) {
    Ok(_) => fail("expected malformed line to fail")
    Err(issue) => {
      @test.assert_eq(issue.kind, MissingColon)
      @test.assert_eq(issue.line, 3)
    }
  }
  match parse_header_line(": value", 4) {
    Ok(_) => fail("expected empty header name to fail")
    Err(issue) => @test.assert_eq(issue.kind, EmptyName)
  }
}

///|
test "parse_headers aggregates duplicate header values" {
  let set = parse_headers(
    "Referrer-Policy: same-origin\nReferrer-Policy: no-referrer\nBadLine",
  )
  @test.assert_eq(set.headers.length(), 2)
  @test.assert_eq(set.issues.length(), 1)
  @test.assert_eq(set.get("referrer-policy"), Some("same-origin"))
  @test.assert_eq(set.get_all("Referrer-Policy"), ["same-origin", "no-referrer"])
}

///|
test "security_headers filters known response headers" {
  let set = parse_headers(
    "Server: test\nX-Content-Type-Options: nosniff\nCross-Origin-Resource-Policy: same-origin",
  )
  let known = set.security_headers()
  @test.assert_eq(known.length(), 2)
  @test.assert_eq(known[0].name, "x-content-type-options")
  @test.assert_eq(known[1].name, "cross-origin-resource-policy")
}

///|
test "parse_csp extracts directives values and duplicate issues" {
  let policy = parse_csp(
    "default-src 'self'; script-src 'self' https://cdn.test; script-src 'none'; object-src 'none'",
  )
  @test.assert_eq(policy.directives.length(), 4)
  @test.assert_eq(policy.duplicates, ["script-src"])
  @test.assert_eq(policy.issues.length(), 1)
  @test.assert_eq(policy.values_for("script-src"), [
    "'self'", "https://cdn.test",
  ])
  @test.assert_eq(policy.effective_values("img-src"), ["'self'"])
  @test.assert_eq(policy.has_directive("object-src"), true)
}

///|
test "audit detects insecure security header choices" {
  let report = audit_headers(sample_insecure_headers())
  @test.assert_eq(report.has_finding("csp.unsafe-inline-script"), true)
  @test.assert_eq(report.has_finding("csp.unsafe-eval"), true)
  @test.assert_eq(report.has_finding("csp.wildcard-script"), true)
  @test.assert_eq(report.has_finding("hsts.max-age-short"), true)
  @test.assert_eq(report.has_finding("xcto.invalid"), true)
  @test.assert_eq(report.has_finding("cors.wildcard-with-credentials"), true)
  @test.assert_eq(report.count_by_severity(High) >= 4, true)
  @test.assert_eq(report.score < 60, true)
}

///|
test "recommended baseline has no actionable findings" {
  let report = audit_headers(recommended_baseline())
  @test.assert_eq(report.score, 100)
  @test.assert_eq(report.grade, "A")
  @test.assert_eq(report.findings.length(), 0)
  @test.assert_eq(report.is_clean(), true)
  @test.assert_eq(report.has_blocking_findings(), false)
  @test.assert_eq(report.passes(100), true)
}

///|
test "empty input reports missing boundary findings" {
  let report = audit_headers("")
  @test.assert_eq(report.has_finding("csp.missing"), true)
  @test.assert_eq(report.has_finding("hsts.missing"), true)
  @test.assert_eq(report.has_finding("xcto.missing"), true)
  @test.assert_eq(report.has_finding("xfo.missing"), true)
  @test.assert_eq(report.has_finding("referrer.missing"), true)
  @test.assert_eq(report.score < 70, true)
}

///|
test "audit report exposes useful CI gate helpers" {
  let report = audit_headers(sample_insecure_headers())
  @test.assert_eq(report.passes(80), false)
  @test.assert_eq(report.has_blocking_findings(), true)
  @test.assert_eq(report.is_clean(), false)
}

///|
test "exports markdown and json reports" {
  let report = audit_headers(sample_insecure_headers())
  let markdown = report.to_markdown()
  @test.assert_eq(markdown.contains("Security Header Audit"), true)
  @test.assert_eq(
    markdown.contains("csp") || markdown.contains("Content"),
    true,
  )
  let json = report.to_json_string()
  @test.assert_eq(json.contains("\"score\""), true)
  @test.assert_eq(json.contains("\"findings\""), true)
  @test.assert_eq(json.contains("cors.wildcard-with-credentials"), true)
}

///|
test "hsts max age parser handles invalid and valid values" {
  @test.assert_eq(
    parse_hsts_max_age("max-age=31536000; includesubdomains"),
    Some(31536000),
  )
  @test.assert_eq(parse_hsts_max_age("includeSubDomains"), None)
  @test.assert_eq(parse_hsts_max_age("max-age=abc"), None)
}

///|
test "profile catalog exposes reusable security baselines" {
  @test.assert_eq(profile_count() >= 12, true)
  @test.assert_eq(profile_keys().contains("static-site"), true)
  match profile_lookup("static-site") {
    Some(profile) => {
      @test.assert_eq(profile.kind, StaticSite)
      @test.assert_eq(profile.required_count() >= 4, true)
      let assessment = profile.score_headers(
        parse_headers(recommended_baseline()),
      )
      @test.assert_eq(assessment.missing, 0)
      @test.assert_eq(assessment.weak, 0)
      @test.assert_eq(assessment.meets_required(), true)
      @test.assert_eq(assessment.matched >= 4, true)
      @test.assert_eq(
        assessment.to_markdown().contains("Profile Assessment"),
        true,
      )
    }
    None => fail("expected static-site profile")
  }
}

///|
test "profile assessment reports weak and missing requirements" {
  let profile = admin_console_profile()
  let weak = parse_headers(
    [
      "Content-Security-Policy: default-src *; script-src * 'unsafe-inline'", "Strict-Transport-Security: max-age=300",
      "X-Content-Type-Options: nosniff",
    ].join("\n"),
  )
  let assessment = profile.score_headers(weak)
  @test.assert_eq(assessment.missing > 0, true)
  @test.assert_eq(assessment.weak > 0, true)
  @test.assert_eq(assessment.meets_required(), false)
  @test.assert_eq(assessment.recommendations().length() > 0, true)
  @test.assert_eq(assessment.to_json_string().contains("\"profile_key\""), true)
}

///|
test "detailed renderers support markdown plaintext checklist and sarif" {
  let report = audit_headers(sample_insecure_headers())
  @test.assert_eq(
    report.render(Markdown).contains("Security Header Audit"),
    true,
  )
  @test.assert_eq(report.render(PlainText).contains("score="), true)
  @test.assert_eq(report.render(Checklist).contains("- [ ]"), true)
  @test.assert_eq(report.render(Sarif).contains("\"2.1.0\""), true)
  @test.assert_eq(report.top_findings(2).length() <= 2, true)
  @test.assert_eq(
    report.findings_by_header("content-security-policy").length() > 0,
    true,
  )
  @test.assert_eq(report.severity_breakdown().contains("high="), true)
}

///|
test "csp source classifier recognizes risky and trusted tokens" {
  @test.assert_eq(classify_csp_source("'self'"), CspSourceSelf)
  @test.assert_eq(classify_csp_source("'nonce-abc'"), CspSourceNonce)
  @test.assert_eq(classify_csp_source("'sha256-abc'"), CspSourceHash)
  @test.assert_eq(classify_csp_source("http:"), CspSourceHttpScheme)
  @test.assert_eq(classify_csp_source("*.example.test"), CspSourceWildcard)
  let source = csp_source_expression("script-src", "http:")
  @test.assert_eq(source.secure_transport, false)
  @test.assert_eq(source.risk_label(), "insecure-transport")
  @test.assert_eq(source.to_json_string().contains("http-scheme"), true)
}

///|
test "deep csp analysis explains unsafe script policy" {
  let analysis = analyze_csp_header(
    "default-src *; script-src * 'unsafe-inline' 'unsafe-eval' http: data:; object-src https://plugins.example.test",
  )
  @test.assert_eq(analysis.has_observation("default-src.wildcard"), true)
  @test.assert_eq(analysis.has_observation("script-src.unsafe-inline"), true)
  @test.assert_eq(analysis.has_observation("script-src.unsafe-eval"), true)
  @test.assert_eq(analysis.has_observation("script-src.data"), true)
  @test.assert_eq(analysis.count_by_severity(High) >= 3, true)
  @test.assert_eq(analysis.sources.length() >= 6, true)
  @test.assert_eq(analysis.to_markdown().contains("Directive Summary"), true)
  @test.assert_eq(analysis.to_json_string().contains("\"observations\""), true)
}

///|
test "deep csp fallback follows child and default directives" {
  let policy = parse_csp(
    "default-src 'none'; child-src https://frames.example.test",
  )
  @test.assert_eq(policy.effective_source_values("script-src"), ["'none'"])
  @test.assert_eq(policy.effective_source_values("frame-src"), [
    "https://frames.example.test",
  ])
  let summary = policy.directive_summary("frame-src")
  @test.assert_eq(summary.explicit, false)
  @test.assert_eq(summary.notes.contains("falls back to child-src"), true)
}

///|
test "csp builder creates and validates deterministic policies" {
  let builder = static_site_csp()
  @test.assert_eq(builder.has_directive("script-src"), true)
  @test.assert_eq(builder.values_for("object-src"), ["'none'"])
  @test.assert_eq(builder.validate().ok, true)
  @test.assert_eq(builder.render().contains("default-src 'self'"), true)
  @test.assert_eq(
    builder.to_header_line().contains("Content-Security-Policy"),
    true,
  )
  @test.assert_eq(builder.analyze().score > 0, true)
}

///|
test "csp builder validation reports contradictory none source" {
  let builder = new_csp_builder()
    .with_directive("default-src", ["'none'", "'self'"])
    .with_directive("script-src", ["http:"])
  let validation = builder.validate()
  @test.assert_eq(validation.ok, true)
  @test.assert_eq(validation.warning_count() >= 1, true)
  @test.assert_eq(validation.to_markdown().contains("Warnings"), true)
}

///|
test "header plans render audit and profile assessment" {
  let plan = static_site_header_plan()
  let block = plan.to_header_block()
  @test.assert_eq(block.contains("Content-Security-Policy"), true)
  @test.assert_eq(plan.validate().ok, true)
  @test.assert_eq(plan.audit().score, 100)
  @test.assert_eq(plan.to_markdown().contains("Static Site Baseline"), true)
  @test.assert_eq(plan.to_json_string().contains("\"headers\""), true)
  match plan.assess_with_profile("static-site") {
    Some(assessment) => {
      @test.assert_eq(assessment.missing, 0)
      @test.assert_eq(assessment.weak, 0)
    }
    None => fail("expected profile assessment")
  }
}

///|
test "header plan catalog supports lookup for examples" {
  @test.assert_eq(header_plan_keys().contains("api-service"), true)
  match header_plan_by_key("api-service") {
    Some(plan) => {
      @test.assert_eq(plan.kind, HeaderPlanApiService)
      @test.assert_eq(
        plan.to_header_block().contains("default-src 'none'"),
        true,
      )
      @test.assert_eq(plan.audit().has_finding("csp.missing"), false)
    }
    None => fail("expected api-service header plan")
  }
  @test.assert_eq(header_plan_catalog_markdown().contains("media-cdn"), true)
}

///|
test "all published header plan examples are self-auditing" {
  for plan in header_plan_catalog() {
    @test.assert_eq(plan.validate().ok, true)
    let report = plan.audit()
    @test.assert_eq(report.has_blocking_findings(), false)
    @test.assert_eq(report.passes(90), true)
    match plan.assess_with_profile(plan.kind.label()) {
      Some(assessment) => @test.assert_eq(assessment.meets_required(), true)
      None => fail("expected catalog profile for header plan")
    }
  }
}

///|
test "report-only CSP builder preserves the report-only header" {
  let builder = csp_report_only_builder().with_directive("default-src", [
    "'self'",
  ])
  @test.assert_eq(builder.header_name(), "Content-Security-Policy-Report-Only")
  @test.assert_eq(builder.to_header_line().contains("Report-Only"), true)
}
