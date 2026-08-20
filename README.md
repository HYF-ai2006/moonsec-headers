# moonsec-headers

[![MoonBit CI](https://github.com/HYF-ai2006/moonsec-headers/actions/workflows/ci.yml/badge.svg)](https://github.com/HYF-ai2006/moonsec-headers/actions/workflows/ci.yml)

moonsec-headers 是一个 MoonBit 原生 HTTP 安全响应头审计库。它把原始响应头文本解析为结构化数据，检查 Content-Security-Policy、HSTS、点击劫持防护、MIME sniffing 防护、Referrer-Policy、Permissions-Policy、跨源隔离和高风险 CORS 组合，并提供深度 CSP source 分析、安全场景 profile、策略生成器以及 Markdown、JSON、Checklist、SARIF-like 等报告输出。

## 解决的问题

Web 服务、Wasm 边缘函数、静态站点发布脚本和内部安全工具经常需要判断响应头是否具备基本防护。直接手写字符串判断容易遗漏大小写、重复头、CSP fallback、重复 directive、无效 max-age 等细节。moonsec-headers 提供可复用的解析器、规则审计器和报告模型，适合被其他 MoonBit 工具集成。

项目当前有效 MoonBit 源码超过 4k 行，核心功能、扩展 profile、策略生成器和测试均可本地构建运行。

## 适用场景

- MoonBit Web/Wasm 项目的发布前安全检查。
- 静态站点、API 网关、边缘函数的离线 header fixture 审计。
- CI 中对响应头快照进行回归测试。
- 教学项目中展示 CSP 与常见安全头的最小规则集。
- 安全工具作者需要一个无网络依赖的 MoonBit 基础库。

## 安装方式

Mooncakes 包名：

```text
HYF-ai2006/moonsec-headers
```

当前已发布版本：`0.1.0`。

发布到个人 Mooncakes owner 后，可在项目中添加：

```bash
moon add HYF-ai2006/moonsec-headers
```

然后在 `moon.pkg` 中导入：

```text
import {
  "HYF-ai2006/moonsec-headers" @headers
}
```

## 最小使用示例

```moonbit
let raw = [
  "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "Strict-Transport-Security: max-age=31536000; includeSubDomains",
  "X-Content-Type-Options: nosniff",
  "Referrer-Policy: strict-origin-when-cross-origin",
  "Permissions-Policy: camera=(), microphone=(), geolocation=()",
].join("\n")

let report = @headers.audit_headers(raw)
println(report.to_markdown())
```

## 生成安全响应头基线

```moonbit
let plan = @headers.static_site_header_plan()
println(plan.to_header_block())

let report = plan.audit()
println(report.render(@headers.PlainText))
```

也可以按场景生成：

```moonbit
let spa = @headers.spa_header_plan(
  "https://api.example.test",
  "https://assets.example.test",
)
let assessment = spa.assess_with_profile("spa-app")
```

## 本地运行

```bash
moon check
moon build
moon test
moon run cmd/main
moon publish --dry-run
```

`cmd/main` 使用内置的不安全响应头 fixture，输出一份 Markdown 审计报告，适合作为 CI smoke test。

## 核心 API

- `parse_header_line(line, line_number)`：解析单行 HTTP header，返回结构化 `Header` 或 `ParseIssue`。
- `parse_headers(raw)`：解析多行响应头文本，保留重复 header 值并记录格式问题。
- `parse_csp(value)`：解析 CSP directive、值、重复 directive 和 CSP 解析问题。
- `audit_headers(raw)`：从原始响应头文本生成 `AuditReport`。
- `audit_header_set(headers)`：从已解析的 `HeaderSet` 生成审计报告。
- `audit_headers_with_csp_analysis(raw)`：在基础审计外追加深度 CSP source 风险分析。
- `analyze_csp_header(value)`：对 CSP source expression 做分类、fallback 分析和风险观察。
- `profile_catalog()` / `profile_lookup(key)`：获取 static-site、spa-app、api-service、admin-console 等安全 profile。
- `SecurityProfile::score_headers(headers)`：按指定场景 profile 评估响应头是否达到基线。
- `ProfileAssessment::meets_required()`：判断 profile 的必需项是否全部满足。
- `RequirementMode`：支持 exact、contains、contains-any、prefix、any-of 和 absent 匹配模式。
- `static_site_header_plan()` / `spa_header_plan(...)` / `api_service_header_plan()`：生成可直接使用的安全响应头方案。
- `CspBuilder`：以结构化方式生成 CSP directive，支持追加、替换、校验和分析。
- `AuditReport::to_markdown()`：导出 Markdown 表格报告。
- `AuditReport::to_json_string()`：导出 JSON 报告。
- `AuditReport::passes(score)` / `has_blocking_findings()`：为 CI 或发布流程提供质量门禁判断。
- `AuditReport::render(format)`：导出 Markdown、PlainText、Checklist、JSON 或 SARIF-like 报告。
- `recommended_baseline()`：返回一组可作为起点的安全响应头。
- `sample_insecure_headers()`：返回 CLI 与测试使用的不安全 fixture。

## 支持范围

- Header 名大小写归一化、空白裁剪、重复 header 聚合。
- CSP directive 解析、default-src fallback、重复 directive 识别。
- CSP 中 `unsafe-inline`、`unsafe-eval`、通配 script 源、HTTP script 源、缺少 object-src/base-uri/frame-ancestors 的风险提示。
- HSTS `max-age` 解析、短 max-age、缺失 includeSubDomains。
- X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy。
- COOP/CORP 的基础值检查。
- `Access-Control-Allow-Origin: *` 与 credential CORS 组合检查。
- Markdown 与 JSON 报告导出。
- CSP source expression 分类：`'self'`、`'none'`、nonce、hash、`strict-dynamic`、HTTP/HTTPS scheme、data/blob/filesystem、通配源和 host 源。
- 深度 CSP 观察：脚本执行源、样式源、对象源、表单提交、frame ancestors、connect-src、混合内容升级和 CSP violation reporting。
- 12 个安全 profile：static-site、spa-app、api-service、admin-console、docs-site、embedded-widget、internal-dashboard、file-download、wasm-edge、public-portal、login-flow、media-cdn。
- 安全响应头策略生成器：静态站、SPA、API、管理后台、登录页、媒体 CDN。
- Markdown、PlainText、Checklist、JSON、SARIF-like 报告输出。

## 暂不支持范围

- 不发起网络请求，不抓取真实站点。
- 不实现完整浏览器级 CSP 解释器。
- 不验证 nonce/hash 是否与 HTML 内容匹配。
- 不根据业务自动决定第三方域名 allowlist，调用方需要显式传入。
- 不解析 HTTP/2 伪头或二进制协议帧。
- 不替代专业渗透测试、合规认证或浏览器安全模型。

## 测试与验收

当前测试覆盖：

- 正常 header 输入。
- 错误 header 输入。
- 空输入边界。
- 重复 header 聚合。
- CSP directive 数据结构转换。
- 核心审计规则。
- Markdown/JSON 导出。
- 深度 CSP source 分类、fallback 和高风险策略观察。
- 安全 profile 评估。
- 策略生成器、header plan 渲染、校验和 profile assessment。
- Markdown、PlainText、Checklist、JSON、SARIF-like 输出。
- CLI smoke fixture。

当前本地测试：23 个测试全部通过。

运行命令：

```bash
moon check
moon build
moon test
moon run cmd/main
moon publish --dry-run
```

CI 使用 `moon fmt --check`、`moon check --deny-warn`、`moon build`、`moon test --deny-warn`、`git diff --check` 和 `moon run cmd/main`。验收前的完整复现顺序见 [`docs/release-checklist.md`](docs/release-checklist.md)，贡献和问题反馈约定见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。

## 开源许可证与第三方说明

本项目使用 MIT 许可证。核心功能为原创 MoonBit 实现，不移植第三方源码，不包含图片、音频、字体或来源不明素材。项目仅依赖 MoonBit 官方 core 包。
