#!/usr/bin/env python3
"""
Webshell上传攻击调查脚本
用于调查webshell上传攻击的入口点、后渗透行为和失陷范围
"""

import argparse
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional


class WebshellInvestigator:
    """Webshell攻击调查器"""

    def __init__(self, alert_data: Dict):
        """
        初始化调查器

        Args:
            alert_data: 告警数据字典
        """
        self.alert_data = alert_data
        self.attacker_ip = alert_data.get("sip") or alert_data.get("attacker")
        self.victim_ip = alert_data.get("dip") or alert_data.get("victim")
        self.attack_time = alert_data.get("write_date") or alert_data.get("timestamp")
        self.uploaded_file = self._extract_uploaded_file()
        self.webshell_path = self._extract_webshell_path()

    def _extract_uploaded_file(self) -> Optional[str]:
        """提取上传的文件名"""
        req_body = self.alert_data.get("req_body", "")
        if "filename=" in req_body:
            try:
                import re
                match = re.search(r'filename="([^"]+)"', req_body)
                if match:
                    return match.group(1)
            except Exception:
                pass
        return None

    def _extract_webshell_path(self) -> Optional[str]:
        """提取webshell保存路径"""
        rsp_body = self.alert_data.get("rsp_body", "")
        try:
            data = json.loads(rsp_body) if rsp_body else {}
            return data.get("path")
        except Exception:
            return None

    def generate_spl_queries(self) -> Dict[str, str]:
        """
        生成调查用的SPL查询语句

        Returns:
            包含各类查询语句的字典
        """
        queries = {
            "investigation_note": f"""
# Webshell上传攻击调查

## 告警基本信息
- 攻击者IP: {self.attacker_ip}
- 受害主机: {self.victim_ip}
- 攻击时间: {self.attack_time}
- 上传文件: {self.uploaded_file}
- Webshell路径: {self.webshell_path}
""",
            "1_attack_entry_spl": f"""
# 1. 查询攻击者IP对受害主机的所有访问记录（攻击入口点溯源）
index=web sourcetype=webaccess (src_ip="{self.attacker_ip}" AND dst_ip="{self.victim_ip}")
| table _time, src_ip, dst_ip, method, uri, status, user_agent, req_body
| sort _time asc
""",
            "2_victim_http_spl": f"""
# 2. 查询受害主机在攻击时间前后24小时的HTTP日志（前后行为分析）
index=web sourcetype=webaccess dst_ip="{self.victim_ip}"
| _time > {self.attack_time} - 24h AND _time < {self.attack_time} + 24h
| table _time, src_ip, dst_ip, method, uri, status, user_agent, req_body
| sort _time asc
""",
            "3_webshell_access_spl": f"""
# 3. 查询对上传webshell的访问记录（后渗透行为检测）
index=web sourcetype=webaccess dst_ip="{self.victim_ip}"
| uri matches ".*{self.uploaded_file or 'shell'}.*" OR req_body matches ".*(eval|exec|system|shell).*"
| table _time, src_ip, dst_ip, method, uri, status, req_body
| sort _time asc
""",
            "4_lateral_movement_spl": f"""
# 4. 查询受害主机的横向移动行为（内网扫描/渗透）
index=web sourcetype=webaccess src_ip="{self.victim_ip}"
| _time > {self.attack_time}
| stats count by dst_ip, dst_port
| where count > 10
| sort -count
""",
            "5_related_alerts_spl": f"""
# 5. 查询受害主机的其他告警（失陷范围评估）
index=alerts dst_ip="{self.victim_ip}"
| _time > {self.attack_time} - 7d AND _time < {self.attack_time} + 7d
| table _time, alert_name, attack_type, severity, attack_result
| sort _time asc
""",
            "6_file_check_spl": f"""
# 6. 检查webshell文件是否仍然存在（需要EDR数据）
index=edr dst_ip="{self.victim_ip}" file_path="{self.webshell_path or '/tmp/join/shell.jsp'}"
| table _time, dst_ip, file_path, file_exists, file_md5, file_sha256
| stats latest(_time) as latest_check by file_path
"""
        }

        return queries

    def generate_investigation_report(self) -> str:
        """
        生成调查报告模板

        Returns:
            调查报告文本
        """
        report = f"""
# Webshell上传攻击调查报告

## 一、告警概述

### 1.1 基本信息
| 项目 | 内容 |
|------|------|
| 攻击者IP | {self.attacker_ip} |
| 受害主机 | {self.victim_ip} |
| 攻击时间 | {self.attack_time} |
| 攻击类型 | {self.alert_data.get('attack_type', '未知')} |
| 告警名称 | {self.alert_data.get('rule_name', '未知')} |
| 告警等级 | {self.alert_data.get('severity', '未知')} |

### 1.2 攻击特征
| 项目 | 内容 |
|------|------|
| 上传文件名 | {self.uploaded_file or '未知'} |
| Webshell路径 | {self.webshell_path or '未知'} |
| HTTP方法 | {self.alert_data.get('method', '未知')} |
| 请求URI | {self.alert_data.get('uri', '未知')} |
| 响应状态 | {self.alert_data.get('rsp_status', '未知')} |

## 二、调查计划

### 2.1 攻击入口点溯源
- [ ] 查询攻击者IP {self.attacker_ip} 对受害主机的所有访问记录
- [ ] 分析攻击前的探测、扫描行为
- [ ] 确定攻击利用的漏洞或入口

### 2.2 后渗透行为调查
- [ ] 检查webshell文件 {self.webshell_path or '未知'} 是否存在
- [ ] 查询对webshell的访问记录
- [ ] 分析webshell执行的操作（命令执行、文件操作等）

### 2.3 失陷范围评估
- [ ] 查询受害主机的横向移动行为
- [ ] 查询受害主机的其他相关告警
- [ ] 评估是否有其他主机失陷

## 三、调查结果

### 3.1 攻击入口点
（待调查后填写）

### 3.2 后渗透行为
（待调查后填写）

### 3.3 失陷范围
（待调查后填写）

## 四、处置建议
（待调查后填写）
"""

        return report

    def save_queries(self, output_file: str = "investigation_queries.txt"):
        """
        保存SPL查询语句到文件

        Args:
            output_file: 输出文件路径
        """
        queries = self.generate_spl_queries()

        with open(output_file, "w", encoding="utf-8") as f:
            for key, query in queries.items():
                f.write(f"{query}\n\n")

        print(f"[+] 调查查询语句已保存到: {output_file}")

    def save_report(self, output_file: str = "investigation_report.md"):
        """
        保存调查报告模板到文件

        Args:
            output_file: 输出文件路径
        """
        report = self.generate_investigation_report()

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"[+] 调查报告模板已保存到: {output_file}")


def parse_alert_log(log_file: str) -> List[Dict]:
    """
    解析告警日志文件

    Args:
        log_file: 日志文件路径

    Returns:
        告警数据列表
    """
    alerts = []

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                # 解析日志行: timestamp|!src_ip|!...|!{json}
                if "|!" in line:
                    parts = line.split("|!")
                    json_str = parts[-1]
                    alert_data = json.loads(json_str)
                else:
                    alert_data = json.loads(line)

                alerts.append(alert_data)
            except json.JSONDecodeError:
                pass

    return alerts


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="Webshell上传攻击调查脚本")
    parser.add_argument("alert_file", help="告警日志文件路径")
    parser.add_argument("-o", "--output", default="investigation_output",
                       help="输出目录（默认: investigation_output）")
    args = parser.parse_args()

    # 解析告警日志
    alerts = parse_alert_log(args.alert_file)

    if not alerts:
        print("[-] 未找到有效的告警数据")
        return

    # 处理每个告警
    for i, alert_data in enumerate(alerts, 1):
        print(f"\n[*] 正在处理第 {i}/{len(alerts)} 个告警...")

        investigator = WebshellInvestigator(alert_data)

        # 创建输出目录
        import os
        output_dir = args.output
        os.makedirs(output_dir, exist_ok=True)

        # 保存查询语句
        queries_file = os.path.join(output_dir, f"queries_{i}.txt")
        investigator.save_queries(queries_file)

        # 保存调查报告
        report_file = os.path.join(output_dir, f"report_{i}.md")
        investigator.save_report(report_file)

    print(f"\n[+] 调查脚本执行完成，结果保存在: {args.output}")


if __name__ == "__main__":
    main()
