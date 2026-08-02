# 选题调研记录

日期：2026-08-02

## 调研目标

为 MoonBit 8 月黑客松选择一个不与现有 Mooncakes 包高度重复、评审容易复现、具有后续维护价值的基础库方向。

## Mooncakes 查重

已下载 `https://mooncakes.io/api/v0/modules` 模块列表，共 1775 个模块。

初始备选方向为 robots.txt / sitemap 解析与抓取规则审计。关键词 `robot`、`robots`、`sitemap`、`crawl`、`crawler` 命中 `2111950632/robots-gate`，其描述为“审计 robots.txt 策略、解释访问决策、校验站点地图并规划合规抓取任务”，与备选方向高度重合，因此放弃。

最终方向切换为 HTTP 安全响应头与 CSP 审计。关键词查重结果：

- `csp`：0 个命中。
- `content-security-policy`：0 个命中。
- `security header` / `security-header`：0 个命中。
- `hsts`：0 个命中。
- `permissions-policy`：0 个命中。
- `referrer-policy`：0 个命中。
- `x-frame`：0 个命中。
- `x-content-type`：0 个命中。

`cors` 命中 Web 框架中的 CORS 中间件，但本项目不提供 Web 框架，也不处理请求路由；只做响应头文本解析、规则审计与报告导出，功能边界不同。

## GitHub 查重

使用 GitHub repository search 检索：

- `MoonBit CSP parser`：0 个仓库。
- `MoonBit Content Security Policy`：0 个仓库。
- `MoonBit security headers`：0 个仓库。
- `moonsec-headers`：0 个仓库。
- `csp-audit MoonBit`：0 个仓库。

## 结论

`moonsec-headers` 选择 MoonBit 原生安全头解析与审计方向。它满足：

- MoonBit 生态缺口明确。
- 不依赖外部网络即可测试与验收。
- 可被 Web、Wasm、CI、静态站点发布流程复用。
- 功能边界清楚：只接收响应头文本，不抓取站点、不替代完整扫描器。
