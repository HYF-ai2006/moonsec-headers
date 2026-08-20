///|
/// Runnable smoke example for the package.
///
/// It audits a deterministic header fixture so CI does not need network access.
fn main {
  let report = @headers.audit_headers(@headers.sample_insecure_headers())
  println(report.to_markdown())
  println("")
  let plan = @headers.static_site_header_plan()
  println(plan.to_markdown())
  println("")
  println(plan.audit().render(@headers.PlainText))
}
