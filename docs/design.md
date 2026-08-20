# 设计说明

## 项目定位

moonsec-headers 是一个纯 MoonBit 基础库，用于把原始 HTTP 响应头文本转换为结构化模型，并根据常见 Web 安全基线生成可解释审计报告。

项目不负责发起 HTTP 请求，也不扫描真实站点。调用者可以从任意来源提供响应头文本：测试 fixture、反向代理导出的 header、CI 中保存的快照、Wasm 应用的配置输出等。

2026-08-19 后，项目边界扩展为四层能力：基础解析、规则审计、场景化 profile 评估、响应头策略生成。扩展后仍保持离线、无网络请求、无第三方运行时依赖的设计。

## 数据流

```mermaid
flowchart LR
  A["Raw header text"] --> B["parse_headers"]
  B --> C["HeaderSet"]
  C --> D["parse_csp"]
  C --> E["audit_header_set"]
  D --> E
  E --> F["AuditReport"]
  F --> G["Markdown report"]
  F --> H["JSON report"]
  D --> I["analyze_csp_header"]
  I --> J["CspAnalysis"]
  K["HeaderPlan / CspBuilder"] --> B
  K --> L["Generated header block"]
```

## 核心模型

- `Header`：规范化后的 header 名、值和原始行号。
- `HeaderSet`：header 数组、按规范化名称索引的多值 Map、解析问题数组。
- `Directive`：CSP directive 名称和值数组。
- `CspPolicy`：CSP 原文、directive 列表、重复 directive 和解析问题。
- `Finding`：规则 ID、严重级别、关联 header、证据和修复建议。
- `AuditReport`：总分、等级、发现项和原始解析结果。
- `CspSourceExpression`：CSP source token 的归一化值、分类、传输安全性、宽泛程度和解释。
- `CspDirectiveSummary`：directive 的族类、显式声明状态、fallback、source 类型和姿态判断。
- `CspAnalysis`：深度 CSP 分析结果，包含观察项、source 列表、directive summary 和分数。
- `SecurityProfile`：面向具体部署形态的安全响应头需求集合。
- `ProfileAssessment`：某组 header 对 profile 的匹配、缺失、弱配置、冲突和建议。
- `CspBuilder`：结构化 CSP 生成器，支持替换 directive、追加 source、渲染、校验和分析。
- `HeaderPlan`：某个场景下完整响应头基线，包括 header 列表、说明、审计和导出方法。

## 审计规则边界

当前规则集聚焦评审和工程实践中容易复现的响应头问题：

- CSP 缺失、`unsafe-inline`、`unsafe-eval`、script 通配源、HTTP script 源。
- CSP 缺失 `object-src 'none'`、`base-uri`、`frame-ancestors`。
- HSTS 缺失、`max-age` 缺失、`max-age` 过短、缺少 `includeSubDomains`。
- `X-Content-Type-Options` 缺失或非 `nosniff`。
- `X-Frame-Options` 缺失或非法值。
- `Referrer-Policy` 缺失、`unsafe-url`、旧默认值。
- `Permissions-Policy` 缺失或未限制 camera/microphone/geolocation。
- COOP/CORP 基础存在性和值检查。
- CORS 通配 origin 与 credentials 组合。

深度 CSP 分析单独覆盖：

- source expression 分类：`'self'`、`'none'`、nonce、hash、`strict-dynamic`、HTTP/HTTPS、data、blob、filesystem、wildcard、host。
- fetch/document/navigation/reporting/mixed-content directive 族类。
- `script-src-elem`、`script-src-attr`、`style-src-*`、`worker-src`、`frame-src`、`child-src` 到 `default-src` 的 fallback。
- `form-action`、`frame-ancestors`、`connect-src`、`img-src`、CSP reporting 和 `upgrade-insecure-requests` 的解释性观察。

## 评分模型

初始分为 100，根据发现项严重程度扣分：

- Critical：30 分。
- High：20 分。
- Medium：10 分。
- Low：4 分。
- Info：0 分。

最低分为 0。等级：

- A：90 到 100。
- B：75 到 89。
- C：60 到 74。
- D：40 到 59。
- F：0 到 39。

Profile requirement 支持 exact、contains、contains-any、prefix、any-of 和 absent 模式。`contains` 会对分号分隔的 CSP/HSTS 条款逐项进行大小写不敏感匹配，允许调用方在目标条款之间插入其他合法 directive；`contains-any` 用于权限等“命中任一候选条款”的场景。

## 可维护性

规则 ID 使用稳定字符串，例如 `csp.unsafe-inline-script`、`hsts.max-age-short`。后续新增规则时应保持已有 ID 不变，以便 CI 和下游工具用 `has_finding` 做回归断言。

后续可扩展方向：

- 为 `Content-Security-Policy-Report-Only` 增加与 enforcing CSP 区分的审计策略。
- 增加 `require-trusted-types-for`、`trusted-types` 等现代 CSP 规则。
- 增加 JUnit XML 导出，便于更多 CI 消费。
- 将 profile 与 builder 进一步拆成可配置模板，允许调用方组合自己的部署形态。
