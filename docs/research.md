# 选题调研记录

日期：2026-08-02（历史查重快照）

## 调研目标

为 MoonBit 8 月黑客松选择一个不与现有 Mooncakes 包高度重复、评审容易复现、具有后续维护价值的基础库方向。

## Mooncakes 查重

已下载 `https://mooncakes.io/api/v0/modules` 模块列表，共 1775 个模块。

初始备选方向为 robots.txt / sitemap 解析与抓取规则审计。关键词 `robot`、`robots`、`sitemap`、`crawl`、`crawler` 命中 `2111950632/robots-gate`，其描述为“审计 robots.txt 策略、解释访问决策、校验站点地图并规划合规抓取任务”，与备选方向高度重合，因此放弃。

最终方向切换为 HTTP 安全响应头与 CSP 的离线语义分析。关键词查重结果：

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

## 2026-08-23 相邻项目复核

历史查重快照不能替代当前生态复核。本次重新查看公开 Mooncakes 文档时发现，`RabitLogic/mbit@0.2.2` 包包含 `secure` Web 中间件，文档列出 CSP、HSTS、X-Frame-Options 和 CSRF 等运行时能力，详见其[公开包文档](https://assets.mooncakes.io/assets/RabitLogic/mbit%400.2.2/mbit.mbt.html)。这说明生态中存在“安全响应头”主题上的相邻能力，不能继续笼统表述为完全没有相关项目。

该相邻项目与本项目的边界如下：`mbit` 负责 Web 服务器、路由和运行时中间件；本项目只处理已经取得的响应头文本，提供离线解析、CSP 语义分析、profile 评估、策略生成和多格式报告。本项目不依赖或复制 `mbit`，也不替代其运行时响应头注入能力；两者可以通过 header 快照组成“生成后再验证”的流程。

因此，项目材料统一使用“HTTP 安全响应头离线语义分析与策略生成”定位，并在[同类边界对照表](differentiation-matrix.md)中主动披露这一具体相邻关系。

## 结论

`moonsec-headers` 选择 MoonBit 原生安全头离线解析与语义分析方向。以上查重结果分为历史快照和 2026-08-23 的相邻项目复核，不构成对后来新增项目的永久排他性声明；项目申报时仍应以当前生态检索和评审意见为准。

## 独立贡献披露

本项目不是 robots/sitemap、通用代码质量、依赖许可证、仓库来源证明或在线站点扫描工具的延伸。核心输入是原始 HTTP 响应头文本，核心输出是 header/CSP 结构化模型、安全规则发现、场景 profile、策略生成和可消费报告。项目不复用其他项目的源码、运行时依赖或测试素材；仅使用 MoonBit 官方 core 包。

最终方向满足：

- MoonBit 生态缺口明确。
- 不依赖外部网络即可测试与验收。
- 可被 Web、Wasm、CI、静态站点发布流程复用。
- 功能边界清楚：只接收响应头文本，不抓取站点、不替代完整扫描器。

## 初审风险补充

近期公开反馈显示，MoonBit 项目初审会重点核对通用审查、robots/sitemap、来源证明、约束引擎、Web 中间件和在线扫描等相邻方向的实质重叠关系。为避免只写“不同”而缺少可核验依据，本项目新增了[同类边界与独立贡献对照表](differentiation-matrix.md)，将每个相邻类别的典型输入、输出和本项目明确不覆盖的部分列出。

该表是项目材料的边界说明，不是对其他项目的评价，也不替代提交前针对当前 Mooncakes 生态的最新查重。
