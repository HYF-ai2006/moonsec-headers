# 维护计划

## 功能边界

moonsec-headers 只处理调用者提供的 HTTP 响应头文本。项目不内置爬虫、HTTP 客户端、浏览器模拟器或在线扫描任务。

## 后续工单建议

- Issue 1：为 Content-Security-Policy-Report-Only 增加独立审计模式。
- Issue 2：增加 Trusted Types 相关 CSP 规则。
- Issue 3：允许调用方自定义 SecurityProfile，并提供 profile diff 工具。
- Issue 4：将 SARIF-like 输出升级为更完整的 SARIF rule metadata。
- Issue 5：增加更多自制 fixture，覆盖重复 header、大小写混合、空 directive 和边界 max-age。
- Issue 6：为 HeaderPlan 增加更多部署模板，例如 OAuth callback、public API、download endpoint。
- Issue 7：为 CspBuilder 增加 directive 排序策略和 report-only/enforcing 成对输出。

## 版本发布记录

- 0.1.0（2026-08-20）：已发布至 Mooncakes，包含解析、审计、深度 CSP 分析、profile、策略生成器、报告导出、CLI 示例、23 个测试和 CI gate helpers。
- Initial implementation（2026-08-02）：完成基础解析、审计、报告导出、CLI 示例、测试和 CI。

## 贡献约定

- 新增规则必须提供稳定规则 ID。
- 新增规则必须至少包含一个触发测试和一个不触发测试。
- 不引入来源不明测试数据或素材。
- 修改公开 API 时同步更新 README、设计说明和变更记录。
