# 同类边界与独立贡献对照

更新日期：2026-08-23

## 使用目的

近期 MoonBit 项目初审反馈反复关注两件事：项目是否与已有工具实质重叠，以及申报材料是否主动说明相邻关系和新增价值。本表把本项目的输入、输出和明确不做的事情固定下来，方便评审、使用者和后续贡献者快速核对。

表中的“相邻类别”是功能类别，不是对任何具体项目的评价，也不表示本项目依赖或移植了这些类别中的实现。项目关系应以公开代码、模块依赖和提交记录为准。

## 功能对照

| 相邻类别 | 它们通常处理什么 | 本项目是否处理 | 可核验的边界 |
| --- | --- | --- | --- |
| 通用代码、仓库或项目审查工具 | 扫描源码、依赖、仓库元数据、CI 或项目规范 | 否 | 本项目只接收调用方已经取得的 HTTP 响应头文本，不读取仓库、不扫描源码、不检查依赖许可证状态 |
| robots.txt、sitemap 或抓取策略工具 | 解释搜索引擎抓取规则、站点地图和抓取任务 | 否 | 不解析 robots.txt 或 sitemap，不规划抓取任务，也不发起网络请求 |
| 开源来源、验收轨迹或审查证明工具 | 记录来源、提交证据、验证过程和项目关系 | 否 | `docs/provenance.md` 只披露本项目实现来源；运行时 API 不证明作者身份、代码来源或验收资格 |
| 通用约束、谓词或规则求解引擎 | 对任意对象定义约束、谓词和组合关系 | 否 | 本项目的规则固定围绕 HTTP 安全响应头和 CSP 语义，不提供通用约束语言或求解器 |
| Web 框架中间件或 HTTP 服务组件 | 在服务运行时生成响应、路由或安全头 | 否 | 不实现 HTTP 服务、路由、中间件或请求处理；策略生成器只返回可供调用方采用的 header 文本 |
| MoonBit Web 框架安全中间件（以 [`RabitLogic/mbit@0.2.2`](https://assets.mooncakes.io/assets/RabitLogic/mbit%400.2.2/mbit.mbt.html) 的 `secure` 为例） | 在运行时为 Web 请求设置 CSP、HSTS、X-Frame-Options 等响应头，并可结合 CSRF 流程 | 否 | `mbit` 是包含路由、服务器和中间件的 Web 框架；本项目不处理请求、不注入响应头、不实现 CSRF，也不复制或依赖其源码 |
| 在线站点扫描器或浏览器自动化工具 | 访问真实 URL、加载页面并观察浏览器行为 | 否 | 无 HTTP 客户端、浏览器驱动和站点抓取逻辑；测试与示例使用离线字符串 fixture |
| HTTP 安全响应头与 CSP 离线语义库 | 解析已取得的响应头，审计安全规则，生成策略并输出报告 | 是 | 这是本项目的唯一核心范围：`parse_headers`、`audit_headers`、`analyze_csp_header`、安全 profile、header plan 和 Markdown/JSON 等报告 |

## 具体相邻项目披露

2026-08-23 的公开资料复核发现，Mooncakes 包 `RabitLogic/mbit@0.2.2` 的文档包含 `secure` Web 中间件，覆盖 CSP、HSTS、X-Frame-Options 和 CSRF 等运行时能力。这个项目与 moonsec-headers 在“安全响应头”主题上存在交集，因此在这里主动披露；但两者的执行阶段、输入输出和职责不同。

- `mbit`：运行 Web 服务器、处理请求和路由，并在运行时生成安全响应头。
- `moonsec-headers`：接收已经取得的 header 文本，离线解析、分析、生成报告和评估策略。
- 组合关系：调用方可以先使用 Web 框架或代理生成响应头，再把 header 快照交给本项目验证；本项目不是 `mbit` 的替代实现。

本项目没有引入 `RabitLogic/mbit` 依赖，没有复制其源码、测试数据或 API；当前 MoonBit 依赖仍只有官方 `core` 包。

## 独立贡献

本项目的新增价值不是把“审查”泛化成一个通用入口，而是为 MoonBit 生态提供一组可复用的、无网络依赖的 HTTP 安全头语义组件：

- 保留重复 header 值、规范化名称并记录解析问题的结构化模型；
- 对 CSP source expression、directive 族类和 `default-src` fallback 做可解释分析；
- 面向静态站点、SPA、API、管理后台、Wasm edge 等部署形态的安全 profile；
- 以 `CspBuilder` 和 `HeaderPlan` 生成可审计的安全响应头基线；
- 输出稳定规则 ID、证据、修复建议以及 Markdown、PlainText、Checklist、JSON、SARIF-like 结果。

这些功能都围绕“响应头文本”这一输入边界展开，不扩展为仓库审查、来源证明、在线扫描、Web 服务或通用规则引擎。

## 最小可复核样例

输入是响应头文本，而不是 URL：

```moonbit
import {
  "HYF-ai2006/moonsec-headers" @headers,
}

let report = @headers.audit_headers(
  "Content-Security-Policy: default-src 'self'\nX-Content-Type-Options: nosniff",
)
println(report.to_markdown())
```

调用方如需在线抓取或服务端注入，应在项目外完成，再把取得的响应头交给本库。这种组合方式保留了本库的离线、可测试和可嵌入特征。

## 关系披露规则

- 本项目不复制相邻工具的源码、测试素材或专有数据；当前 MoonBit 依赖只有官方 `core` 包。
- 如果未来引入上游实现、兼容某个具体格式，必须在 README、`docs/provenance.md`、CHANGELOG 和申报材料中写明名称、链接、许可证、使用范围和差异。
- 如果生态中出现功能相邻的 MoonBit 包，应先建立 issue，补充对照测试，再在版本说明中记录兼容性或不兼容性。
