---
name: soc-copilot
description: SOC子引擎，基于agent-skills技术通过AI赋能SOC平台，对SOC告警进行研判、调查、响应。SOC子引擎的核心理念为构建一个自我学习的安全引擎，可预测的告警通过规则匹配并通过脚本自动化处置，不可预测的告警通过大模型研判分析，分析完后生成规则和处置脚本，用户审核后固化到规则引擎，除此之外，用户可以主动输入SKILL对SOC子引擎进行训练。
argument-hint: "[告警日志目录路径]"
---

## 工作流程
1、从用户输入的路径获取该目录下的所有告警日志，通过经验'{reference/triage/triage.md}'对告警进行研判分析。研判完成后，按照模板'{assets/triage_rule.yml}'生成对应的研判规则（规则要尽可能地泛化），生成后询问用户是否手工编辑修改或反馈模型修改，最终用户审核后固化到'{scripts/triage_rules}'。
2、询问用户是否需要进一步分析或溯源，若需要，则调用'{reference/investigation/investigation.md}'对告警进行调查分析。调查溯源完毕后，生成对应的python调查脚本（脚本要尽可能地泛化），生成后询问用户是否手工编辑修改或反馈模型修改，最终用户审核后固化到'{scripts/investigation}'
3、询问用户是否进行响应处置，若需要，则调用'{reference/incident_response/incident_response.md}'对失陷主机进行响应处置。响应处置完毕后，生成对应的bash/powershell响应脚本（脚本要尽可能地泛化），生成后询问用户是否手工编辑修改或反馈模型修改，最终用户审核后固化到'{scripts/incident_response}'。
4、最终根据模板'{assets/analysis_report.md}'输出分析报告保存到'{reports/}'路径。
5、用户可主动主动输入SKILL到'{reference/}'对SOC子引擎的研判、调查、响应能力进行训练。