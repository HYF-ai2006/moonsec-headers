# 测试记录

日期：2026-08-02

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

## 本地命令

```bash
moon check
moon build
moon test
moon run cmd/main
moon publish --dry-run
```

## 当前结果

已执行：

```text
moon test
Total tests: 10, passed: 10, failed: 0.
```

`moon check` 已通过。`moon build`、`moon run cmd/main` 与 `moon publish --dry-run` 在最终自检阶段统一记录。

## 测试数据说明

测试使用自制字符串 fixture：

- `recommended_baseline()`：推荐安全响应头基线。
- `sample_insecure_headers()`：不安全响应头样例，用于规则触发和 CLI smoke test。

项目不使用来源不明文件、图片、音频、字体或私有测试数据。
