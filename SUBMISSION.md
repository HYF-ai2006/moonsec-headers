# moonsec-headers 项目申报书

## 基本信息

- 项目名称：moonsec-headers：MoonBit 原生 HTTP 安全响应头与 CSP 审计库
- 参赛者：韩云飞
- 联系方式：已按官方报名问卷填写（公开仓库不展示个人联系方式）
- GitHub 仓库链接：https://github.com/HYF-ai2006/moonsec-headers
- 项目方向：MoonBit 原生开源库 / Web 安全基础工具 / 规则校验与报告导出
- 是否为移植项目：否，原创 MoonBit 开源项目
- 开源许可证：MIT

## 项目简介

moonsec-headers 是一个用 MoonBit 实现的 HTTP 安全响应头审计库。项目接收原始响应头文本，解析 Content-Security-Policy、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP/CORP 和 CORS 相关头，输出带评分、风险等级、证据和修复建议的 Markdown、JSON、Checklist、PlainText 与 SARIF-like 报告。项目还提供深度 CSP source expression 分析、场景化安全 profile 和响应头策略生成器，解决 Web/Wasm 项目、静态站点发布脚本和内部安全工具在发布前缺少可复用响应头检查能力的问题。

## 项目方向与适用场景

本项目面向 MoonBit Web/Wasm 应用作者、安全工具开发者、API 网关配置维护者和教学项目。调用者只需要提供响应头文本即可离线审计，不依赖真实网络请求，适合接入 CI、资源发布流程、边缘函数配置检查和安全规则教学。项目边界清晰：只做响应头解析、规则校验和报告导出，不做在线爬取、浏览器模拟或渗透测试。

## 已实现的核心功能

- HTTP header 行解析、名称归一化、重复 header 聚合与格式错误记录；
- CSP directive 解析、重复 directive 识别、default-src fallback 与高风险 source 检测；
- HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP/CORP、CORS 组合审计；
- 深度 CSP source 分类、fallback 分析、风险观察与结构化输出；
- static-site、spa-app、api-service、admin-console、login-flow、media-cdn 等安全 profile；
- CSP builder、HSTS builder、Permissions-Policy helper 和完整 header plan 生成；
- 稳定规则 ID、评分等级、Markdown、PlainText、Checklist、JSON、SARIF-like 报告导出；
- 提供可运行 CLI 示例、单元测试、README、CI、设计说明、测试记录和维护计划。

## 项目现有基础与完成情况

当前已完成 MoonBit 工程、核心库、23 个本地测试、`cmd/main` CLI smoke 示例、README、GitHub Actions CI、MIT 许可证、调研记录、设计说明、测试记录、更新日志、维护计划和贡献/安全报告入口。当前有效 MoonBit 源码为 4649 行，已超过 4k 行。项目 `HYF-ai2006/moonsec-headers` 版本 `0.1.0` 已成功发布至 Mooncakes，发布前预检和服务端校验均通过。

## 原创或参考说明

本项目为原创 MoonBit 实现，不移植第三方源码，不包含来源不明素材或私有代码。项目仅依赖 MoonBit 官方 core 包，许可证为 MIT。

## 与同类项目的边界和独立贡献

本项目不是通用代码质量检查器、依赖许可证扫描器、仓库来源证明工具、在线站点扫描器、HTTP 服务端或浏览器自动化工具。它的输入是调用方已经取得的原始 HTTP 响应头文本，核心输出是结构化 header/CSP 解析结果、稳定规则 ID、可解释风险报告和场景化安全 header plan。

独立贡献包括：面向 MoonBit 的 header 多值解析模型；CSP source expression 分类与 directive fallback 分析；面向静态站、SPA、API、管理后台等场景的 profile；可复用的 CSP/header plan builder；以及 Markdown、JSON、Checklist、PlainText、SARIF-like 报告输出。项目不依赖或复制其他审查工具的实现，也不宣称覆盖通用审计工具的功能。

如果后续发现 MoonBit 生态中出现相邻项目，本项目将以“离线响应头语义审计与策略生成”作为明确范围，优先通过 issue 说明差异、补充对比测试，并在 CHANGELOG 中记录兼容性变化。

本项目已提供一份面向评审复核的[同类边界与独立贡献对照表](docs/differentiation-matrix.md)，逐项说明与通用审查、robots/sitemap、来源证明、约束引擎、Web 中间件和在线扫描器等相邻类别的关系，以及本项目实际覆盖的响应头离线解析、CSP 语义审计、策略生成和报告导出范围。
