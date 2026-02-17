#!/usr/bin/env python3
"""
Webshell上传事件调查脚本

用途：调查webshell上传事件的攻击入口点、webshell通信行为和横向移动行为
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Any


class WebshellInvestigator:
    """Webshell上传事件调查器"""

    def __init__(self, alert_data: Dict[str, Any], soc_api=None):
        """
        初始化调查器

        Args:
            alert_data: 告警数据
            soc_api: SOC平台API接口 (可选)
        """
        self.alert_data = alert_data
        self.soc_api = soc_api

        # 提取关键信息
        self.attacker_ip = alert_data.get('attacker')
        self.victim_ip = alert_data.get('victim')
        self.alert_time = datetime.fromtimestamp(int(alert_data.get('write_date', 0)))
        self.webshell_path = self._extract_webshell_path()
        self.webshell_filename = self._extract_webshell_filename()

    def _extract_webshell_path(self) -> str:
        """从响应体中提取webshell文件路径"""
        rsp_body = self.alert_data.get('rsp_body', '')
        try:
            data = json.loads(rsp_body)
            return data.get('path', '')
        except:
            return ''

    def _extract_webshell_filename(self) -> str:
        """从请求体中提取上传的文件名"""
        req_body = self.alert_data.get('req_body', '')
        if 'filename=' in req_body:
            import re
            match = re.search(r'filename="([^"]+)"', req_body)
            if match:
                return match.group(1)
        return ''

    def investigate_entry_point(self, hours_before: int = 24) -> Dict[str, Any]:
        """
        溯源攻击入口点

        Args:
            hours_before: 查询告警前多少小时的日志

        Returns:
            入口点调查结果
        """
        print(f"\n[*] 正在溯源攻击入口点 (告警前{hours_before}小时)...")

        start_time = self.alert_time - timedelta(hours=hours_before)
        end_time = self.alert_time

        results = {
            'phase': '攻击入口点溯源',
            'attacker_ip': self.attacker_ip,
            'victim_ip': self.victim_ip,
            'time_range': f"{start_time} - {end_time}",
            'findings': []
        }

        # 查询内容
        queries = [
            {
                'name': '漏洞扫描行为',
                'description': '检测攻击者是否对目标进行了漏洞扫描',
                'query': f"""
                sourcetype=http (dip="{self.victim_ip}" OR dip="{self.alert_data.get('host')}")
                AND sip="{self.attacker_ip}"
                AND time > [{start_time}] AND time < [{end_time}]
                | stats count BY uri, user_agent
                | sort count DESC
                """
            },
            {
                'name': '文件上传接口探测',
                'description': '检测攻击者是否探测过文件上传接口',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND sip="{self.attacker_ip}"
                AND uri="*upload*"
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, uri, method, status, user_agent
                | sort _time ASC
                """
            },
            {
                'name': '目录遍历尝试',
                'description': '检测攻击者是否尝试过目录遍历攻击',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND sip="{self.attacker_ip}"
                AND (uri="*../*" OR uri="*%2e*")
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, uri, status
                | sort _time ASC
                """
            },
            {
                'name': '应用系统探测',
                'description': '检测攻击者是否访问过应用系统管理页面',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND sip="{self.attacker_ip}"
                AND (uri="*admin*" OR uri="*manage*" OR uri="*console*")
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, uri, status, user_agent
                | sort _time ASC
                """
            }
        ]

        for query_info in queries:
            print(f"\n  查询: {query_info['name']}")
            print(f"  描述: {query_info['description']}")
            print(f"  SPL语句:\n{query_info['query']}")

            if self.soc_api:
                # 实际执行查询
                try:
                    data = self.soc_api.execute_query(query_info['query'])
                    results['findings'].append({
                        'name': query_info['name'],
                        'description': query_info['description'],
                        'data': data
                    })
                except Exception as e:
                    results['findings'].append({
                        'name': query_info['name'],
                        'error': str(e)
                    })
            else:
                # 无API时输出建议查询
                results['findings'].append({
                    'name': query_info['name'],
                    'description': query_info['description'],
                    'query': query_info['query'],
                    'note': '需要手动执行SPL查询'
                })

        return results

    def investigate_webshell_communication(self, hours_after: int = 24) -> Dict[str, Any]:
        """
        检测Webshell通信行为

        Args:
            hours_after: 查询告警后多少小时的日志

        Returns:
            Webshell通信检测结果
        """
        print(f"\n[*] 正在检测Webshell通信行为 (告警后{hours_after}小时)...")

        start_time = self.alert_time
        end_time = self.alert_time + timedelta(hours=hours_after)

        results = {
            'phase': 'Webshell通信检测',
            'victim_ip': self.victim_ip,
            'webshell_path': self.webshell_path,
            'webshell_filename': self.webshell_filename,
            'time_range': f"{start_time} - {end_time}",
            'findings': []
        }

        # 查询内容
        queries = [
            {
                'name': '直接访问webshell',
                'description': '检测攻击者是否直接访问上传的webshell文件',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND uri="*{self.webshell_filename}*"
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, sip, uri, method, status, req_body
                | sort _time ASC
                """
            },
            {
                'name': '命令执行特征请求',
                'description': '检测是否包含命令执行特征的HTTP请求',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND (req_body="*cmd=*" OR req_body="*exec=*" OR req_body="*system=*")
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, sip, uri, req_body
                | sort _time ASC
                """
            },
            {
                'name': '异常文件操作请求',
                'description': '检测是否有异常的文件操作请求',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND (uri="*file*" OR uri="*download*" OR uri="*upload*")
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, sip, uri, method, status, req_body
                | sort _time ASC
                """
            },
            {
                'name': '可疑源IP访问',
                'description': '检测是否有与攻击者相同IP的后续访问',
                'query': f"""
                sourcetype=http dip="{self.victim_ip}"
                AND sip="{self.attacker_ip}"
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, sip, uri, method, status, user_agent
                | sort _time ASC
                """
            }
        ]

        for query_info in queries:
            print(f"\n  查询: {query_info['name']}")
            print(f"  描述: {query_info['description']}")
            print(f"  SPL语句:\n{query_info['query']}")

            if self.soc_api:
                try:
                    data = self.soc_api.execute_query(query_info['query'])
                    results['findings'].append({
                        'name': query_info['name'],
                        'description': query_info['description'],
                        'data': data
                    })
                except Exception as e:
                    results['findings'].append({
                        'name': query_info['name'],
                        'error': str(e)
                    })
            else:
                results['findings'].append({
                    'name': query_info['name'],
                    'description': query_info['description'],
                    'query': query_info['query'],
                    'note': '需要手动执行SPL查询'
                })

        return results

    def investigate_lateral_movement(self, hours_after: int = 48) -> Dict[str, Any]:
        """
        检测横向移动行为

        Args:
            hours_after: 查询告警后多少小时的日志

        Returns:
            横向移动检测结果
        """
        print(f"\n[*] 正在检测横向移动行为 (告警后{hours_after}小时)...")

        start_time = self.alert_time
        end_time = self.alert_time + timedelta(hours=hours_after)

        results = {
            'phase': '横向移动检测',
            'compromised_host': self.victim_ip,
            'time_range': f"{start_time} - {end_time}",
            'findings': []
        }

        # 查询内容
        queries = [
            {
                'name': '内网扫描行为',
                'description': '检测失陷主机是否对内网进行扫描',
                'query': f"""
                sourcetype=http sip="{self.victim_ip}"
                AND (dip="10.*" OR dip="192.168.*" OR dip="172.16.*")
                AND time > [{start_time}] AND time < [{end_time}]
                | stats count BY dip
                | where count > 10
                | sort count DESC
                """
            },
            {
                'name': 'SMB/LDAP/SSH连接',
                'description': '检测是否有异常的内网协议连接',
                'query': f"""
                (sourcetype=firewall OR sourcetype=netflow)
                sip="{self.victim_ip}"
                AND (dst_port="445" OR dst_port="389" OR dst_port="22" OR dst_port="3389")
                AND (dip="10.*" OR dip="192.168.*" OR dip="172.16.*")
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, sip, dip, proto, dst_port, action
                | sort _time ASC
                """
            },
            {
                'name': '对内网其他主机的攻击',
                'description': '检测失陷主机是否对其他内网主机发起攻击',
                'query': f"""
                sourcetype=alert (victim_ip="10.*" OR victim_ip="192.168.*" OR victim_ip="172.16.*")
                AND attacker="{self.victim_ip}"
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, attacker, victim_ip, alert_name, attack_type
                | sort _time ASC
                """
            },
            {
                'name': '其他主机告警关联',
                'description': '检测内网其他主机是否有相关告警',
                'query': f"""
                sourcetype=alert attacker="{self.attacker_ip}"
                AND time > [{start_time}] AND time < [{end_time}]
                | table _time, attacker, victim_ip, alert_name, attack_type
                | stats count BY victim_ip
                | sort count DESC
                """
            }
        ]

        for query_info in queries:
            print(f"\n  查询: {query_info['name']}")
            print(f"  描述: {query_info['description']}")
            print(f"  SPL语句:\n{query_info['query']}")

            if self.soc_api:
                try:
                    data = self.soc_api.execute_query(query_info['query'])
                    results['findings'].append({
                        'name': query_info['name'],
                        'description': query_info['description'],
                        'data': data
                    })
                except Exception as e:
                    results['findings'].append({
                        'name': query_info['name'],
                        'error': str(e)
                    })
            else:
                results['findings'].append({
                    'name': query_info['name'],
                    'description': query_info['description'],
                    'query': query_info['query'],
                    'note': '需要手动执行SPL查询'
                })

        return results

    def generate_investigation_report(self) -> Dict[str, Any]:
        """
        生成完整的调查报告

        Returns:
            调查报告
        """
        print("\n" + "="*60)
        print("Webshell上传事件调查报告")
        print("="*60)

        report = {
            'alert_info': {
                'attacker_ip': self.attacker_ip,
                'victim_ip': self.victim_ip,
                'alert_time': str(self.alert_time),
                'webshell_path': self.webshell_path,
                'webshell_filename': self.webshell_filename
            },
            'investigation_results': []
        }

        # 执行各项调查
        report['investigation_results'].append(
            self.investigate_entry_point(hours_before=24)
        )
        report['investigation_results'].append(
            self.investigate_webshell_communication(hours_after=24)
        )
        report['investigation_results'].append(
            self.investigate_lateral_movement(hours_after=48)
        )

        return report


def main():
    """主函数"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python webshell_upload_investigation.py <alert_json_file>")
        print("\n示例:")
        print("  python webshell_upload_investigation.py alert.json")
        sys.exit(1)

    alert_file = sys.argv[1]

    # 读取告警文件
    try:
        with open(alert_file, 'r', encoding='utf-8') as f:
            alert_content = f.read()

        # 解析JSON (SOC告警格式可能包含管道符前缀)
        alert_json = None
        if '|' in alert_content:
            # 处理带|的格式
            parts = alert_content.split('|!')[-1]
            alert_json = json.loads(parts)
        else:
            alert_json = json.loads(alert_content)

    except Exception as e:
        print(f"Error: 无法解析告警文件 - {e}")
        sys.exit(1)

    # 创建调查器并生成报告
    investigator = WebshellInvestigator(alert_json)
    report = investigator.generate_investigation_report()

    # 输出报告
    report_file = f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n[+] 调查报告已保存至: {report_file}")


if __name__ == '__main__':
    main()
