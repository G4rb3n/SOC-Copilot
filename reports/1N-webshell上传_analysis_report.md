# SOC告警分析报告

**分析时间**: 2026-02-18 22:15:00
**告警日志**: 1N-webshell上传.json
**攻击类型**: webshell上传
**研判结论**: 定向攻击
**调查结果**: 确认攻击成功，攻击者通过接口 www.cccc.cn/uapim/upload/grouptemplet?groupid=82&fileType=jsp 上传webshell至服务器，webshell保存的本地路径为 /tmp/join/shell.jsp
**处置结果**: 建议封禁 59.56.48.110 攻击IP，删除服务器上的webshell文件 /tmp/join/shell.jsp，并加固文件上传接口

---

## 一、研判详情

### 1.1 研判结论
| 项目 | 内容 |
|------|------|
| **攻击定性** | 定向攻击 |
| **置信度** | 高 |
| **攻击类型** | webshell上传 |
| **攻击结果** | 成功 |

---

### 1.2 研判思维链
```
1. 日志类型识别
   └─> 告警名称: 发现上传jsp的webshell行为
   └─> 包含HTTP请求/响应信息
   └─> 判定为: network日志类型

2. 提取关键信息
   ├─ 告警名称: 发现上传jsp的webshell行为
   ├─ 源IP: 59.56.48.110 (外部IP)
   ├─ 目的IP: 2.15.16.44 (内部服务器)
   ├─ 访问方向: 外→内 (入站攻击)
   ├─ HTTP方法: POST
   ├─ URI: /uapim/upload/grouptemplet?groupid=82&fileType=jsp
   ├─ 上传文件名: shell.jsp
   ├─ 文件内容: <% {out.print("1f6a0505d6b50cd882c16ed12f6811a4");} %>
   ├─ 响应状态: 200 (成功)
   └─ HTTP响应: {"path":"/tmp/join/shell.jsp"}

3. 应用研判经验 (webshell_upload.md)
   ├─ [正报判断-1.1] 文件名后缀分析
   │   └─> .jsp ✅ 常见webshell脚本后缀
   ├─ [正报判断-1.1] 文件名特征分析
   │   └─> shell.jsp ✅ 包含"shell"攻击性关键词
   ├─ [正报判断-1.2] 文件内容分析
   │   ├─> 包含JSP可执行标签 <% ... %> ✅
   │   └─> 包含out.print()输出函数 ✅ 可用于输出命令执行结果
   ├─ [正报判断-2] 攻击结果验证
   │   ├─> HTTP响应: 200 ✅ 请求成功
   │   └─> 响应体: {"path":"/tmp/join/shell.jsp"} ✅ 文件已落地
   └─ [误报判断] 排除业务行为
       ├─> 访问方向: 外→内 ❌ 非内对内业务流量
       ├─> 文件名: shell.jsp ❌ 非规范业务文件名
       └─> 内容: 简单可执行代码 ❌ 非常规业务代码

4. 综合判定
   └─> 研判结果: 定向攻击 (真人攻击)
   └─> 攻击结果: 成功 (文件已上传至服务器)
```

---

## 二、攻击详情

### 2.1 攻击者信息
| 项目 | 内容 |
|------|------|
| **攻击者IP** | 59.56.48.110 |
| **地理位置** | 待查询 |
| **User-Agent** | Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0 |
| **攻击时间** | 2023-11-11 11:15:49 |

### 2.2 受害主机信息
| 项目 | 内容 |
|------|------|
| **受害主机IP** | 2.15.16.44 |
| **主机类型** | 服务器 |
| **Web服务** | JSP 7.1.8 (Tomcat) |
| **域名** | www.cccc.cn |

### 2.3 攻击特征
| 项目 | 内容 |
|------|------|
| **攻击接口** | /uapim/upload/grouptemplet?groupid=82&fileType=jsp |
| **上传文件名** | shell.jsp |
| **文件保存路径** | /tmp/join/shell.jsp |
| **Webshell类型** | JSP Webshell |
| **Webshell特征** | <% {out.print("1f6a0505d6b50cd882c16ed12f6811a4");} %> |

### 2.4 数据包内容
**HTTP请求:**
```http
POST /uapim/upload/grouptemplet?groupid=82&fileType=jsp HTTP/1.1
Host: www.cccc.cn
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymusymnhq
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0

------WebKitFormBoundarymusymnhq
Content-Disposition: form-data; name="upload"; filename="shell.jsp"
Content-Type: application/octet-stream

<% {out.print("1f6a0505d6b50cd882c16ed12f6811a4");} %>
------WebKitFormBoundarymusymnhq
Content-Disposition: form-data; name="submit"

submit
------WebKitFormBoundarymusymnhq--
```

**HTTP响应:**
```http
HTTP/1.1 200
Content-Type: text/html; charset=UTF-8
X-Powered-By: jsp/7.1.8

{"path":"/tmp/join/shell.jsp"}
```

---

## 三、调查详情

### 3.1 攻击链总结

攻击者通过文件上传接口 `/uapim/upload/grouptemplet` 成功上传名为 `shell.jsp` 的webshell文件，文件保存到服务器 `/tmp/join/shell.jsp`，HTTP响应状态码为200，表明攻击成功。

**攻击链路径:**
```
[攻击者 59.56.48.110]
    ↓
[www.cccc.cn (2.15.16.44)]
    ↓
[文件上传接口 /uapim/upload/grouptemplet]
    ↓
[Webshell保存 /tmp/join/shell.jsp]
    ↓
[服务器失陷]
```

### 3.2 攻击入口点溯源

**所需数据:**
- 目的IP (2.15.16.44) 在告警前后24小时的所有原始HTTP日志
- 源IP (59.56.48.110) 的历史访问记录

**调查目的:**
- 分析攻击者如何发现并利用文件上传接口
- 是否存在前置的漏洞扫描或探测行为
- 确定攻击利用的具体漏洞

**SPL查询语句:**
```spl
# 查询攻击者IP的所有访问记录
index=web sourcetype=webaccess src_ip="59.56.48.110" AND dst_ip="2.15.16.44"
| table _time, src_ip, dst_ip, method, uri, status, user_agent
| sort _time asc

# 查询受害主机在攻击时间前后的HTTP日志
index=web sourcetype=webaccess dst_ip="2.15.16.44"
| _time > 2023-11-11 10:15:49 AND _time < 2023-11-11 12:15:49
| table _time, src_ip, dst_ip, method, uri, status, req_body
| sort _time asc
```

### 3.3 Webshell通信检测

**所需数据:**
- 目的IP (2.15.16.44) 在webshell上传后的所有HTTP请求日志
- 对 `/tmp/join/shell.jsp` 的访问记录

**调查目的:**
- 检测攻击者是否已开始使用webshell
- 确定webshell被执行后的后渗透行为

**关键指标:**
- 是否有对 `/tmp/join/shell.jsp` 或包含 `shell.jsp` 的访问请求
- 是否有包含命令执行特征的HTTP请求 (如 `cmd=`、`exec=` 等参数)
- 是否有异常的文件操作请求

**SPL查询语句:**
```spl
# 查询对webshell的访问记录
index=web sourcetype=webaccess dst_ip="2.15.16.44"
| uri matches ".*shell.*\.jsp" OR req_body matches ".*(eval|exec|system|cmd).*"
| table _time, src_ip, dst_ip, method, uri, req_body
| sort _time asc
```

### 3.4 横向移动检测

**所需数据:**
- 目的IP (2.15.16.44) 失陷后的所有网络连接日志
- 内网其他主机的告警日志

**调查目的:**
- 检测失陷主机是否已被用于横向移动
- 评估是否有其他主机失陷

**关注行为:**
- 是否有内网扫描行为
- 是否对其他内网主机发起攻击
- 是否有SMB/SSH/RDP等协议的异常连接

**SPL查询语句:**
```spl
# 查询受害主机的横向移动行为
index=web sourcetype=webaccess src_ip="2.15.16.44"
| _time > 2023-11-11 11:15:49
| stats count by dst_ip, dst_port
| where count > 10
| sort -count

# 查询内网其他主机的告警
index=alerts dst_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| _time > 2023-11-11 11:15:49
| stats count by dst_ip, attack_type
| sort -count
```

---

## 四、处置建议

### 4.1 立即处置措施

#### 4.1.1 隔离失陷主机
```bash
# 方式1: 网络层面隔离 (推荐)
iptables -A INPUT -s 2.15.16.44 -j DROP
iptables -A OUTPUT -d 2.15.16.44 -j DROP

# 方式2: 关闭相关web服务
systemctl stop tomcat  # 或对应的web服务

# 方式3: 拔网线 (最彻底但影响业务，仅限极端情况)
```

#### 4.1.2 封禁攻击者IP
```bash
# 使用iptables封禁
iptables -A INPUT -s 59.56.48.110 -j DROP

# 保存iptables规则
iptables-save > /etc/iptables/rules.v4  # Debian/Ubuntu
# 或
service iptables save  # CentOS/RHEL

# 添加到hosts.deny
echo "ALL: 59.56.48.110" >> /etc/hosts.deny
```

#### 4.1.3 删除webshell文件
```bash
# 通过SSH/RDP登录失陷主机
rm -f /tmp/join/shell.jsp

# 检查是否还有其他可疑文件
find /tmp -name "*.jsp" -o -name "shell.*" 2>/dev/null
find /var/www/html -name "*.jsp" -o -name "shell.*" 2>/dev/null
```

### 4.2 全面排查措施

#### 4.2.1 查找其他潜在webshell
```bash
# 查找最近创建的可疑文件
find /var/www/html -name "*.jsp" -mtime -1 -ls
find /tmp -name "*.jsp" -mtime -1 -ls

# 查找包含webshell特征的文件
grep -r "eval(" /var/www/html --include="*.jsp"
grep -r "Runtime.getRuntime" /var/www/html --include="*.jsp"
grep -r "ProcessBuilder" /var/www/html --include="*.jsp"
grep -r "out.print" /var/www/html --include="*.jsp"
```

#### 4.2.2 检查webshell执行痕迹
```bash
# 检查可疑进程
ps aux | grep -E '(jsp|tomcat|java)' | grep -v grep

# 检查网络连接
netstat -tuln | grep LISTEN
netstat -tunap | grep ESTABLISHED

# 检查最近的命令历史
cat ~/.bash_history | tail -100
```

### 4.3 根本原因修复

#### 4.3.1 修复文件上传漏洞
- **限制文件类型**: 仅允许上传业务必需的文件类型（如图片、文档）
- **文件内容检测**: 对上传文件进行内容检查，拒绝包含可执行代码的文件
- **文件重命名**: 上传后重命名文件，避免使用原始文件名
- **存储位置**: 将上传文件存储在web目录之外
- **访问控制**: 对上传目录禁用执行权限
- **身份验证**: 加强上传接口的身份验证和授权检查

#### 4.3.2 Web服务器加固

**Nginx配置示例:**
```nginx
location ~ /uapim/upload/ {
    # 限制请求方法
    if ($request_method !~ ^(POST)$ ) {
        return 403;
    }
    # 禁止上传脚本文件
    location ~* \.(jsp|php|asp|aspx)$ {
        return 403;
    }
    # 限制请求大小
    client_max_body_size 10M;
}

# 禁止web目录执行JSP
location ~* /tmp/.*\.jsp$ {
    return 403;
}
```

**Apache配置示例:**
```apache
<Location "/uapim/upload/">
    # 限制请求方法
    <LimitExcept POST>
        Require all denied
    </LimitExcept>
    # 禁止上传脚本文件
    <FilesMatch "\.(jsp|php|asp|aspx)$">
        Require all denied
    </FilesMatch>
</Location>

# 禁止web目录执行JSP
<Directory "/tmp/">
    <FilesMatch "\.jsp$">
        Require all denied
    </FilesMatch>
</Directory>
```

### 4.4 加强安全监控

#### 4.4.1 监控规则建议
1. 监控 `/tmp/join/` 目录的文件创建行为
2. 监控 `/uapim/upload` 接口的访问，特别关注异常User-Agent
3. 监控web目录下JSP文件的创建和修改
4. 监控源IP `59.56.48.110` 的后续访问
5. 监控服务器上异常的进程启动和网络连接

#### 4.4.2 告警规则建议
```yaml
# Webshell文件上传告警规则
rule_name: Webshell文件上传
detection:
  - HTTP请求方法: POST
  - URI包含: /upload/
  - 请求体包含: "<%" AND "out.print"
  - 文件名后缀: .jsp|.php|.asp|.aspx
response:
  - 自动封禁源IP
  - 发送告警通知
```

### 4.5 后续建议
1. 进行全面的恶意代码扫描
2. 检查是否有其他主机失陷
3. 评估数据泄露风险
4. 进行安全加固和漏洞修复
5. 加强安全培训和意识教育
6. 定期进行安全审计和渗透测试

---

## 五、附件

### 5.1 IOC (妥协指标)

| 类型 | 值 | 描述 |
|------|-----|------|
| 恶意IP | 59.56.48.110 | 攻击者IP |
| 恶意文件 | /tmp/join/shell.jsp | Webshell文件路径 |
| 恶意文件名 | shell.jsp | 上传的webshell文件名 |
| 恶意URI | /uapim/upload/grouptemplet | 被利用的上传接口 |
| Webshell特征 | <% {out.print("...");} %> | JSP webshell代码特征 |
| Hash(MD5) | 待计算 | Webshell文件MD5值 |
| Hash(SHA256) | 待计算 | Webshell文件SHA256值 |

### 5.2 相关文件
- 研判规则: `scripts/triage_rules/webshell_upload_success.yml`
- 调查脚本: `scripts/investigation/webshell_upload_investigation.py`
- 响应脚本: `scripts/incident_response/webshell_response.sh`

### 5.3 参考资料
- 研判经验: `reference/triage/network/webshell_upload.md`
- MITRE ATT&CK: T1505.003 (Webshell)

---

**报告生成时间**: 2026-02-18 22:15:00
**报告生成者**: SOC-Copilot
