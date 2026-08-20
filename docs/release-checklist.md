# 发布与验收复现清单

这份清单用于在本地复现项目状态。它不执行 GitHub 登录、GitHub Desktop 操作或远端推送。

## 本地质量门禁

在仓库根目录依次执行：

```bash
moon version --all
moon fmt --check
moon check --deny-warn
moon build
moon test --deny-warn
moon run cmd/main
git diff --check
```

预期结果：格式检查、检查、构建和测试成功；测试输出应显示所有测试通过；CLI 应输出不安全 fixture 的审计报告和一个生成的安全 header plan。

## 公开仓库核对

- 默认分支包含 README、LICENSE、CI、测试、示例和当前源代码。
- GitHub Actions 的 CI 能完成格式检查、无警告检查、构建、测试、空白检查和 CLI smoke test。
- `git log` 能看出功能、测试、文档和 CI 的分阶段提交。
- 不包含 `_build/`、`.mooncakes/`、凭据、真实站点响应、个人敏感信息副本或来源不明素材。

## Mooncakes 发布前

Mooncakes 发布需要在正确的 MoonBit 账号环境中进行。先确认 `moon.mod` 的模块名与发布 owner 一致，再执行：

```bash
moon publish --dry-run
moon publish
```

本项目当前暂不执行发布命令。发布后应把版本号、包链接和命令输出补充到更新日志或发布记录中。
