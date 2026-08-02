# moonsec-headers 项目申报书

## 基本信息

- 项目名称：moonsec-headers：MoonBit 原生 HTTP 安全响应头与 CSP 审计库
- 参赛者：<待填写>
- 联系方式：<待填写>
- GitHub 仓库链接：<待填写>
- 项目方向：MoonBit 原生开源库 / Web 安全基础工具 / 规则校验与报告导出
- 是否为移植项目：否，原创 MoonBit 开源项目
- 开源许可证：MIT

## 项目简介

moonsec-headers 用 MoonBit 实现 HTTP 响应头解析、Content-Security-Policy 解析、安全头风险审计和 Markdown/JSON 报告导出。它解决 Web/Wasm 项目在发布前难以复用响应头安全检查的问题，可在 CI、静态站点发布、边缘函数配置验证和教学项目中离线运行。

## 项目方向与适用场景

本项目适合 MoonBit Web/Wasm 应用作者、安全工具开发者、API 网关配置维护者和教学项目使用。调用者提供响应头文本即可得到结构化审计结果，不需要真实网络访问，评审可直接通过测试和 CLI 示例复现。

## 拟实现的核心功能

- HTTP header 行解析、名称归一化、重复 header 聚合与格式错误记录；
- CSP directive 解析、重复 directive 识别、default-src fallback 与高风险 source 检测；
- HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy、COOP/CORP、CORS 组合审计；
- 评分、等级、稳定规则 ID、Markdown 与 JSON 报告导出；
- 提供测试、CLI 示例、README、CI、设计说明和 Mooncakes 发布配置。

## 项目现有基础与本次计划

当前已完成 MoonBit 工程、核心库、10 个核心测试、CLI smoke 示例、README、设计说明、调研记录、测试记录、MIT 许可证和 GitHub Actions CI。后续计划包括发布到 Mooncakes、增加 Report-Only CSP 策略、导出 SARIF/JUnit XML、提供更多配置 profile。

## 原创或参考说明

本项目为原创 MoonBit 实现，不移植第三方源码，不包含来源不明素材或私有代码。项目仅依赖 MoonBit 官方 core 包。
