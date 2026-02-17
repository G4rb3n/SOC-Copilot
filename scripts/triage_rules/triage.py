#!/usr/bin/env python3
"""
日志检测脚本
使用 triage_rules 下的规则对告警日志进行检测，返回研判结论
"""

import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any


class LogDetector:
    """日志检测器"""

    def __init__(self, rules_dir: str = None):
        """
        初始化检测器

        Args:
            rules_dir: 规则文件目录路径
        """
        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(__file__), "triage_rules")

        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        """加载所有规则文件"""
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"规则目录不存在: {self.rules_dir}")

        for rule_file in self.rules_dir.glob("*.yml"):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    rule_config = yaml.safe_load(f)
                    self.rules.append({
                        "name": rule_config.get("rule_name", ""),
                        "content": rule_config.get("rule_content", ""),
                        "triage_result": rule_config.get("triage_result", ""),
                        "attack_result": rule_config.get("attack_result", ""),
                        "file": rule_file.name
                    })
            except Exception as e:
                print(f"[错误] 加载规则失败 {rule_file.name}: {e}")

    def _parse_rule(self, rule_content: str) -> List[Dict]:
        """解析规则内容，提取条件表达式"""
        conditions = []
        lines = [line.strip() for line in rule_content.strip().split("\n") if line.strip()]

        for line in lines:
            # 去掉开头的 "and " 前缀
            if line.lower().startswith("and "):
                line = line[4:].strip()

            # 解析 matches 操作符
            if " matches " in line:
                parts = line.split(" matches ", 1)
                field = parts[0].strip()
                pattern = parts[1].strip().strip("'\"")
                conditions.append({"field": field, "op": "matches", "pattern": pattern})

            # 解析 == 操作符
            elif " == " in line:
                parts = line.split(" == ", 1)
                field = parts[0].strip()
                value = parts[1].strip().strip("'\"")
                conditions.append({"field": field, "op": "eq", "value": value})

            # 解析 != 操作符
            elif " != " in line:
                parts = line.split(" != ", 1)
                field = parts[0].strip()
                value = parts[1].strip().strip("'\"")
                conditions.append({"field": field, "op": "ne", "value": value})

            # 解析 contains 操作符
            elif " contains " in line:
                parts = line.split(" contains ", 1)
                field = parts[0].strip()
                value = parts[1].strip().strip("'\"")
                conditions.append({"field": field, "op": "contains", "value": value})

        return conditions

    def _map_field(self, field: str, alert_data: Dict) -> Optional[str]:
        """将规则字段映射到日志数据中的实际字段"""
        field_mapping = {
            "alert_name": ["attack_type", "vuln_name", "rule_name"],
            "request_body": ["parameter", "req_body"],
            "status_code": ["rsp_status"],
            "uri": ["uri"],
            "method": ["method"],
            "user_agent": ["agent"],
            "src_ip": ["sip", "attacker"],
            "dst_ip": ["dip", "victim"],
            "host": ["host"],
        }

        if field in alert_data:
            return str(alert_data[field])

        if field in field_mapping:
            for mapped_field in field_mapping[field]:
                if mapped_field in alert_data:
                    return str(alert_data[mapped_field])

        return None

    def _eval_condition(self, condition: Dict, alert_data: Dict) -> bool:
        """评估单个条件是否匹配"""
        field_value = self._map_field(condition["field"], alert_data)

        if field_value is None:
            return False

        if condition["op"] == "matches":
            try:
                pattern = condition["pattern"]
                return bool(re.search(pattern, field_value, re.IGNORECASE | re.DOTALL))
            except re.error:
                return False

        elif condition["op"] == "eq":
            return field_value == condition["value"]

        elif condition["op"] == "ne":
            return field_value != condition["value"]

        elif condition["op"] == "contains":
            return condition["value"] in field_value

        return False

    def _match_rule(self, rule: Dict, alert_data: Dict) -> bool:
        """检查告警数据是否匹配规则"""
        conditions = self._parse_rule(rule["content"])

        if not conditions:
            return False

        for condition in conditions:
            if not self._eval_condition(condition, alert_data):
                return False

        return True

    def detect(self, alert_data: Dict) -> Dict:
        """对告警数据进行检测"""
        for rule in self.rules:
            if self._match_rule(rule, alert_data):
                return {
                    "matched": True,
                    "triage_result": rule["triage_result"],
                    "attack_result": rule["attack_result"],
                    "rule_name": rule["name"]
                }

        return {
            "matched": False,
            "triage_result": "未知",
            "attack_result": "未知",
            "rule_name": None
        }

    def detect_file(self, file_path: str) -> List[Dict]:
        """检测文件中的所有告警日志"""
        results = []
        file_path = Path(file_path)

        if not file_path.exists():
            print(f"文件不存在: {file_path}")
            return results

        with open(file_path, "r", encoding="utf-8") as f:
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

                    result = self.detect(alert_data)
                    result["alert_name"] = alert_data.get("attack_type", "未知")
                    results.append(result)

                except json.JSONDecodeError:
                    pass

        return results


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="日志检测脚本")
    parser.add_argument("log_dir", nargs="?", default="samples", help="告警日志目录路径（默认: samples）")
    parser.add_argument("-r", "--rules", default="scripts/triage_rules", help="规则目录路径")
    args = parser.parse_args()

    detector = LogDetector(args.rules)

    log_dir = Path(args.log_dir)

    if not log_dir.exists():
        print(f"错误: 目录不存在 - {log_dir}")
        return

    if not log_dir.is_dir():
        print(f"错误: 不是目录 - {log_dir}")
        return

    for log_file in log_dir.glob("*.json"):
        results = detector.detect_file(log_file)
        for r in results:
            matched_rule = r["rule_name"] if r["rule_name"] else "无"
            print(f"{log_file.name} | {matched_rule} | {r['triage_result']}")


if __name__ == "__main__":
    main()
