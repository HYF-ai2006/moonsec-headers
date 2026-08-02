# moonsec-headers

moonsec-headers 是一个 MoonBit 原生 HTTP 安全响应头审计库。它把原始响应头文本解析为结构化数据，检查 Content-Security-Policy、HSTS、点击劫持防护、MIME sniffing 防护、Referrer-Policy、Permissions-Policy、跨源隔离和高风险 CORS 组合，并导出 Markdown 或 JSON 报告。

## 解决的问题

Web 服务、Wasm 边缘函数、静态站点发布脚本和内部安全工具经常需要判断响应头是否具备基本防护。直接手写字符串判断容易遗漏大小写、重复头、CSP fallback、重复 directive、无效 max-age 等细节。moonsec-headers 提供可复用的解析器、规则审计器和报告模型，适合被其他 MoonBit 工具集成。

## 适用场景

- MoonBit Web/Wasm 项目的发布前安全检查。
- 静态站点、API 网关、边缘函数的离线 header fixture 审计。
- CI 中对响应头快照进行回归测试。
- 教学项目中展示 CSP 与常见安全头的最小规则集。
- 安全工具作者需要一个无网络依赖的 MoonBit 基础库。

## 安装方式

Mooncakes 包名：

```text
username/moonsec-headers
```

发布到个人 Mooncakes owner 后，可在项目中添加：

```bash
moon add username/moonsec-headers
```

然后在 `moon.pkg` 中导入：

```text
import {
  "username/moonsec-headers" @headers
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
- `AuditReport::to_markdown()`：导出 Markdown 表格报告。
- `AuditReport::to_json_string()`：导出 JSON 报告。
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

## 暂不支持范围

- 不发起网络请求，不抓取真实站点。
- 不实现完整浏览器级 CSP 解释器。
- 不验证 nonce/hash 是否与 HTML 内容匹配。
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
- CLI smoke fixture。

运行命令：

```bash
moon check
moon build
moon test
moon run cmd/main
moon publish --dry-run
```

## 开源许可证与第三方说明

本项目使用 MIT 许可证。核心功能为原创 MoonBit 实现，不移植第三方源码，不包含图片、音频、字体或来源不明素材。项目仅依赖 MoonBit 官方 core 包。
