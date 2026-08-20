# 贡献指南

感谢关注 moonsec-headers。项目定位是可复用的 MoonBit HTTP 安全响应头解析、审计、策略生成和报告导出库。

## 开始开发

先确认本地 MoonBit 工具链可用，然后在仓库根目录执行：

```bash
moon fmt
moon check --deny-warn
moon build
moon test --deny-warn
moon run cmd/main
```

项目不发起网络请求。测试和示例应使用可公开再分发的自制字符串 fixture，避免提交真实站点响应、凭据、个人信息或来源不明素材。

## 提交代码

- 新增审计规则时提供稳定的规则 ID、触发测试和不触发测试。
- 修改公开 API 时同步更新 README、设计说明和 CHANGELOG。
- 修改 profile 或策略模板时说明适用场景、默认假设和不适用范围。
- 新增第三方代码、生成代码、测试数据或素材时，在 README 或专门文档中说明来源和许可证。
- 提交前运行 `moon fmt --check`、`moon check --deny-warn`、`moon build` 和 `moon test --deny-warn`。

提交信息建议使用简短的动词开头，例如 `feat:`、`fix:`、`test:`、`docs:` 或 `ci:`。一个提交尽量对应一个可解释的改动，方便验收时追踪开发过程。

## Pull Request

请在 PR 描述中说明用途、行为变化、测试命令和许可证影响。涉及安全规则的改动应附上输入 fixture、关键输出或报告变化。不要在公开 issue 或 PR 中粘贴真实 token、Cookie、个人联系方式、站点内部响应或未修复漏洞细节。
