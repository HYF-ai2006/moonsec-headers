# moonsec-headers 项目申报书

## 基本信息

- 项目名称：moonsec-headers：MoonBit 原生 HTTP 安全响应头与 CSP 审计库
- 参赛者：韩云飞
- 联系方式：15633561071
- GitHub 仓库链接：https://github.com/HYF-ai2006/moonsec-headers
- 项目方向：MoonBit 原生开源库 / Web 安全基础工具 / 规则校验与报告导出
- 是否为移植项目：否，原创 MoonBit 开源项目
- 开源许可证：MIT

## 项目简介

moonsec-headers 是一个用 MoonBit 实现的 HTTP 安全响应头审计库。项目接收原始响应头文本，解析 Content-Security-Policy、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP/CORP 和 CORS 相关头，输出带评分、风险等级、证据和修复建议的 Markdown 或 JSON 报告。它解决 Web/Wasm 项目、静态站点发布脚本和内部安全工具在发布前缺少可复用响应头检查能力的问题。

## 项目方向与适用场景

本项目面向 MoonBit Web/Wasm 应用作者、安全工具开发者、API 网关配置维护者和教学项目。调用者只需要提供响应头文本即可离线审计，不依赖真实网络请求，适合接入 CI、资源发布流程、边缘函数配置检查和安全规则教学。项目边界清晰：只做响应头解析、规则校验和报告导出，不做在线爬取、浏览器模拟或渗透测试。

## 拟实现的核心功能

- HTTP header 行解析、名称归一化、重复 header 聚合与格式错误记录；
- CSP directive 解析、重复 directive 识别、default-src fallback 与高风险 source 检测；
- HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP/CORP、CORS 组合审计；
- 稳定规则 ID、评分等级、Markdown 报告和 JSON 报告导出；
- 提供可运行 CLI 示例、单元测试、README、CI、设计说明、测试记录和维护计划。

## 项目现有基础与本次计划

当前已完成 MoonBit 工程、核心库、10 个核心测试、`cmd/main` CLI smoke 示例、README、GitHub Actions CI、MIT 许可证、调研记录、设计说明、测试记录、更新日志和维护计划。本轮先完成源码、文档、测试、构建和公开仓库准备；Mooncakes 发布环节后续在登录后执行 `moon publish --dry-run` 与正式发布。

## 原创或参考说明

本项目为原创 MoonBit 实现，不移植第三方源码，不包含来源不明素材或私有代码。项目仅依赖 MoonBit 官方 core 包，许可证为 MIT。
