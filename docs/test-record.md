# 测试记录

日期：2026-08-20

## 测试范围

已覆盖核心路径：

- 正常 header 行解析与名称归一化。
- 缺少冒号、空 header 名等错误输入。
- 多行 header 聚合与重复 header 值保留。
- 已知安全响应头过滤。
- CSP directive 解析、重复 directive 记录、default-src fallback。
- 不安全 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、CORS 组合的规则发现。
- 推荐基线无发现项。
- 空输入边界检查。
- Markdown 与 JSON 报告导出。
- HSTS max-age 数字解析。
- 安全 profile catalog、profile lookup 和 profile assessment。
- 深度 CSP source 分类、fallback 关系和高风险观察。
- CSP builder 的 directive 替换、追加、渲染、校验和分析。
- Header plan 的 Markdown/JSON 输出、审计和 profile assessment。
- Markdown、PlainText、Checklist、SARIF-like 等扩展报告格式。
- CI gate helpers：分数门槛、阻断级发现、空报告和 profile 必需项判断。
- 全部 header plan catalog 的验证、审计和 profile 对齐。
- report-only CSP builder 的 header 名称和渲染。

## 本地命令

```bash
moon check
moon build
moon test
moon run cmd/main
moon check --deny-warn
moon test --deny-warn
moon fmt --check
git diff --check
```

## 当前结果

已执行：

```text
moon check
passed

moon build
passed

moon test
Total tests: 23, passed: 23, failed: 0.

moon run cmd/main
passed, emitted a Markdown report for the insecure fixture and a generated static-site header plan.

moon check --deny-warn
passed

moon test --deny-warn
Total tests: 23, passed: 23, failed: 0.

moon fmt --check
passed

git diff --check
passed, only Windows line-ending notices were shown.
```

Mooncakes 发布记录：

```text
moon whoami
Logged in as HYF-ai2006

moon publish --dry-run
Server status: 202 Accepted
Dry run completed successfully. No changes were made.

moon publish
Server status: 200 OK
```

已发布包：`HYF-ai2006/moonsec-headers`，版本 `0.1.0`。`moon publish --dry-run` 在当前 Moon 工具链中会把服务端的 `202 Accepted` 显示为非零退出，但服务端明确返回预检成功；正式 `moon publish` 以退出码 0 完成。

## 测试数据说明

测试使用自制字符串 fixture：

- `recommended_baseline()`：推荐安全响应头基线。
- `sample_insecure_headers()`：不安全响应头样例，用于规则触发和 CLI smoke test。
- `static_site_header_plan()` 等 header plan：生成可审计的安全配置样例。
- `analyze_csp_header(...)` 测试字符串：覆盖 unsafe-inline、unsafe-eval、HTTP scheme、data scheme、fallback 和 wildcard。

项目不使用来源不明文件、图片、音频、字体或私有测试数据。

## 2026-08-21 文档补强复核

本次仅补充同类边界与独立贡献说明，未修改 MoonBit 源码、公开 API、依赖或已发布版本。补充文档后重新执行 `moon fmt --check`、`moon check --deny-warn`、`moon build`、`moon test --deny-warn`、`moon run cmd/main`、`moon check --target all`、Wasm/Wasm-GC 测试和 `git diff --check`，结果全部通过。

## 有效代码规模

按排除空行和 `//` 注释行统计，当前 MoonBit 有效源码行数为 4649 行，已超过 4k 参考规模。
