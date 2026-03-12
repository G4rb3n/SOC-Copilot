<div align="center">

# SOC-Copilot

**🤖 AI-Powered Security Operations Center Assistant**

[![GitHub Stars](https://img.shields.io/github/stars/G4rb3n/SOC-Copilot?style=social)](https://github.com/G4rb3n/SOC-Copilot/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/G4rb3n/SOC-Copilot?style=social)](https://github.com/G4rb3n/SOC-Copilot/network/members)
[![License](https://img.shields.io/github/license/G4rb3n/SOC-Copilot)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/G4rb3n/SOC-Copilot)](https://github.com/G4rb3n/SOC-Copilot/issues)

**English | [简体中文](README.md)**

An AI-powered SOC assistant built on Agent-Skills technology for intelligent alert triage, investigation, and automated incident response.

`#AgenticSOC` `#NextGenSIEM` `#AICyberSecurity` `#IncidentResponse` `#SecurityAutomation`

</div>

---

## 📖 Table of Contents

- [✨ Key Features](#-key-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [📋 Workflow](#-workflow)
- [🎯 Capabilities & Limitations](#-capabilities--limitations)
- [📸 Screenshots](#-screenshots)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Intelligent Triage** | Automated alert triage based on experience library, supporting both rule matching and AI analysis |
| 🕵️ **Deep Investigation** | Automated threat hunting, correlation analysis, and investigation script generation |
| 🛡️ **Automated Response** | Intelligent response script generation (Bash/PowerShell) for one-click remediation |
| 📊 **Report Generation** | Automatic professional analysis report output in multiple formats |
| 🧠 **Self-Learning** | Analysis results automatically固化 as rules, continuously improving triage capabilities |
| ⚡ **Efficiency Boost** | Computational cost gradually decreases as rules accumulate |

---

## 🏗️ Architecture

![Architecture](./SOC-Copilot.png)

SOC-Copilot employs an innovative **dual-track processing mechanism**:
- **Predictable Alerts** → Rule Matching → Script-based Automated Response
- **Unpredictable Alerts** → LLM Analysis → Generate New Rules & Scripts → User Review &固化

![Performance Curve](./Graph.png)

---

## 🚀 Quick Start

### Installation

#### Method 1: For Claude Code Users

```bash
# Clone the repository
git clone https://github.com/G4rb3n/SOC-Copilot.git

# Install to Claude Skills directory
mv SOC-Copilot ~/.claude/skills/
cd ~/.claude/skills/SOC-Copilot
```

#### Method 2: For OpenClaw Users

If you're using the [OpenClaw](https://github.com/OpenClaw/OpenClaw) platform:

```bash
# Clone to OpenClaw Skills directory
git clone https://github.com/G4rb3n/SOC-Copilot.git ~/.openclaw/skills/SOC-Copilot
```

> 💡 **Tip**: After installation, start a new session (run `/new`) to load the skill.

### Usage

```bash
# Start Claude
claude

# Run SOC-Copilot
/soc-copilot ./samples/
```

---

## 📋 Workflow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Alert Input │ -> │   Triage    │ -> │ Investigation│ -> │  Response   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                          │                  │                  │
                          v                  v                  v
                   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
                   │Generate Rules│    │Generate Script│   │Generate Script│
                   └─────────────┘    └─────────────┘    └─────────────┘
                          │                  │                  │
                          └──────────────────┴──────────────────┘
                                            │
                                            v
                                    ┌─────────────┐
                                    │ User Review │
                                    └─────────────┘
```

### Detailed Process

1. **Triage Phase**
   - Read alert logs from specified directory
   - Analyze using experience library at `reference/triage/triage.md`
   - Generate triage rules and save to `scripts/triage_rules/`

2. **Investigation Phase**
   - Deep analysis using `reference/investigation/investigation.md`
   - Generate Python investigation scripts to `scripts/investigation/`

3. **Response Phase**
   - Remediation using `reference/incident_response/incident_response.md`
   - Generate Bash/PowerShell response scripts to `scripts/incident_response/`

4. **Reporting Phase**
   - Output analysis report based on `assets/analysis_report.md` template
   - Save to `reports/` directory

---

## 🎯 Capabilities & Limitations

> ⚠️ Understanding boundaries helps maximize value

| ✅ Supported Capabilities | ❌ Unsupported Capabilities |
|--------------------------|----------------------------|
| Alert triage analysis | Raw log detection |
| Threat hunting & investigation | Real-time massive alert processing |
| Automated incident response | Replacing security analysts |
| Self-learning rule generation | - |

---

## 📸 Screenshots

### Triage Phase
![Triage](./triage.png)

### Investigation Phase
![Investigation](./investigation.png)

### Response Phase
![Response](./response.png)

### Report Phase
![Report](./report.png)

---

## 📁 Project Structure

```
SOC-Copilot/
├── assets/                 # Template resources
│   ├── triage_rule.yml     # Triage rule template
│   └── analysis_report.md  # Analysis report template
├── reference/              # Experience knowledge base
│   ├── triage/             # Triage experience
│   │   ├── endpoint/       # Endpoint security
│   │   └── network/        # Network security
│   ├── investigation/      # Investigation experience
│   └── response/           # Response experience
├── scripts/                # Generated scripts
│   ├── triage_rules/       # Triage rules
│   ├── investigation/      # Investigation scripts
│   └── incident_response/  # Response scripts
├── samples/                # Sample alerts
└── reports/                # Analysis reports
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) to learn how to:
- 🐛 Report bugs
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit code

### Adding New Experience Knowledge

You can actively input SKILL files to train the SOC sub-engine:

1. Create experience documents in the corresponding `reference/` directory
2. Write analysis experience following existing formats
3. Submit a PR to merge into the main branch

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

Thanks to all contributors!

---

<div align="center">

**If this project helps you, please give it a ⭐ Star!**

[![Star History Chart](https://api.star-history.com/svg?repos=G4rb3n/SOC-Copilot&type=Date)](https://star-history.com/#G4rb3n/SOC-Copilot&Date)

</div>
