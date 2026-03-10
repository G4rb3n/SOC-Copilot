# Contributing to SOC-Copilot

感谢你有兴趣为SOC-Copilot做出贡献！🎉

## 📋 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发流程](#开发流程)
- [提交规范](#提交规范)
- [代码规范](#代码规范)
- [添加经验知识](#添加经验知识)

---

## 行为准则

本项目采用贡献者公约作为行为准则。参与此项目即表示您同意遵守其条款。请阅读 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 了解详情。

---

## 如何贡献

### 报告Bug

如果您发现了bug，请通过 [GitHub Issues](https://github.com/G4rb3n/SOC-Copilot/issues) 提交。提交时请：

1. 使用清晰的标题描述问题
2. 描述复现步骤
3. 说明预期行为和实际行为
4. 附上相关日志或截图

### 建议新功能

欢迎提出新功能建议！请在Issue中详细描述：

1. 功能描述
2. 使用场景
3. 预期效果

### 提交代码

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

---

## 开发流程

```bash
# 1. Fork并克隆仓库
git clone https://github.com/your-username/SOC-Copilot.git

# 2. 创建分支
git checkout -b feature/your-feature-name

# 3. 进行开发
# ...

# 4. 提交更改
git add .
git commit -m "feat: add new feature"

# 5. 推送到远程
git push origin feature/your-feature-name

# 6. 创建Pull Request
```

---

## 提交规范

请使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

| 类型 | 描述 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug修复 |
| `docs` | 文档更新 |
| `style` | 代码格式（不影响功能） |
| `refactor` | 代码重构 |
| `perf` | 性能优化 |
| `test` | 添加测试 |
| `chore` | 构建/工具变动 |

示例：
```
feat: add webshell detection rule
fix: correct triage logic for metasploit alerts
docs: update installation guide
```

---

## 代码规范

### Markdown文件

- 使用UTF-8编码
- 中英文之间加空格
- 使用标准的Markdown语法

### Python脚本

- 遵循PEP 8规范
- 添加必要的注释
- 使用有意义的变量名

### Shell脚本

- 使用bash shebang: `#!/bin/bash`
- 添加错误处理
- 使用有意义的变量名

---

## 添加经验知识

SOC-Copilot的核心在于经验知识库。您可以通过以下方式贡献：

### 1. 添加研判经验

在 `reference/triage/` 目录下添加：

```markdown
# 攻击类型名称

## 攻击描述
简要描述该攻击类型

## 检测特征
- 特征1
- 特征2

## 研判要点
1. 要点1
2. 要点2

## 误报排除
如何排除误报情况

## 响应建议
建议的响应措施
```

### 2. 添加调查经验

在 `reference/investigation/` 目录下添加调查分析方法

### 3. 添加响应经验

在 `reference/response/` 目录下添加响应处置方法

---

## 需要帮助？

如果您有任何问题，可以：

- 在 [Discussions](https://github.com/G4rb3n/SOC-Copilot/discussions) 中提问
- 发送邮件至项目维护者

感谢您的贡献！🙏
