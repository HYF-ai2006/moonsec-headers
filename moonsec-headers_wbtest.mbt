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
