# SOC告警分析报告

**告警时间**: 2023-11-11 11:15:49
**告警名称**: webshell上传
**告警文件**: 1N-webshell上传.json

---

## 一、研判结论

| 研判结果 | 定向攻击 |
|----------|----------|
| **置信度** | 高 |
| **攻击类型** | webshell上传 |
| **攻击结果** | 成功 |

### 定性依据

1. **人为攻击特征**: 外部IP (59.56.48.110) 主动上传webshell文件，非自动化扫描行为
2. **攻击成功**: HTTP响应显示文件已成功上传至服务器路径 `/tmp/join/shell.jsp`
3. **恶意意图明确**:
   - 上传文件名为 `shell.jsp`，文件名中包含"shell"关键词
   - 文件后缀 `.jsp` 是常见JSP webshell后缀
   - 文件内容包含可执行的JSP代码 `<% {out.print("1f6a0505d6b50cd882c16ed12f6811a4");} %>`
4. **排除其他可能性**:
   - 非自动化攻击：非批量扫描器行为，是特定目标的上传操作
   - 非渗透测试：无明显的test、vulscan等测试特征
   - 非业务行为：外部IP攻击、恶意文件名、简单可执行代码

---

## 二、研判思维链

```
1. 日志类型识别
   └─> 告警名称: webshell上传
   └─> 包含HTTP请求/响应信息
   └─> 判定为: network日志类型

2. 提取关键信息
   ├─ 告警名称: webshell上传
   ├─ 源IP: 59.56.48.110 (外部IP)
   ├─ 目的IP: 2.15.16.44 (内部服务器)
   ├─ 访问方向: 外→内 (入站攻击)
   ├─ HTTP方法: POST
   ├─ URI: /uapim/upload/grouptemplet?groupid=82&fileType=jsp
   ├─ 上传文件名: shell.jsp
   ├─ 文件内容: <% {out.print("1f6a0505d6b50cd882c16ed12f6811a4");} %>
   ├─ 攻击结果: attack_result=1 (成功)
   └─ HTTP响应: {"path":"/tmp/join/shell.jsp"}

3. 应用研判经验 (webshell_upload.md)
   ├─ [正报判断-1.1] 文件名后缀分析
   │   └─> .jsp ✅ 常见webshell脚本后缀
   ├─ [正报判断-1.1] 文件名特征分析
   │   └─> shell.jsp ✅ 包含"shell"关键词
   ├─ [正报判断-1.2] 文件内容分析
   │   ├─> 包含JSP可执行标签 <% ... %> ✅
   │   └─> 包含out.print()输出函数 ✅
   ├─ [正报判断-2] 关联告警分析
   │   └─> attack_result=1 ✅ 攻击成功
   └─ [误报判断] 排除业务行为
       ├─> 访问方向: 外→内 ❌ 非内对内业务流量
       ├─> 文件名: shell.jsp ❌ 非规范业务文件名
       └─> 内容: 简单可执行代码 ❌ 非常规业务代码

4. 综合研判
   ├─ 文件名、内容、攻击结果均符合webshell特征
   ├─ 外部IP主动上传，具有明确恶意意图
   ├─ 攻击成功，主机已失陷
   └─> 结论: 定向攻击 - 攻击者成功上传webshell后门
```

---

## 三、调查结果

### 3.1 当前调查状态

**⚠️ 需要额外数据**: 由于告警已定性为定向攻击，按照调查流程需要进行以下调查，但需要SOC平台API访问权限：

### 3.2 需要调查的内容

#### 3.2.1 攻击入口点溯源
- **所需数据**: 目的IP (2.15.16.44) 在告警前后24小时的所有原始HTTP日志
- **调查目的**: 分析攻击者如何发现并利用文件上传接口
- **关联查询**:
  - 是否有针对该接口的漏洞扫描行为
  - 是否有针对该应用系统的其他攻击尝试

#### 3.2.2 Webshell通信检测
- **所需数据**: 目的IP (2.15.16.44) 在webshell上传后的所有HTTP请求日志
- **调查目的**: 检测攻击者是否已开始使用webshell
- **关键指标**:
  - 是否有对 `/tmp/join/shell.jsp` 的访问请求
  - 是否有包含命令执行特征的HTTP请求 (如 `cmd=`、`exec=` 等参数)
  - 是否有异常的文件操作请求

#### 3.2.3 横向移动检测
- **所需数据**:
  - 目的IP (2.15.16.44) 失陷后的所有网络连接日志
  - 内网其他主机的告警日志
- **调查目的**: 检测失陷主机是否已被用于横向移动
- **关注行为**:
  - 是否有内网扫描行为
  - 是否对其他内网主机发起攻击
  - 是否有SMB/SSH/RDP等协议的异常连接

#### 3.2.4 失陷范围评估
- **所需数据**:
  - 失陷主机的资产信息 (责任人、业务系统、重要性等)
  - 该主机上的其他告警
- **调查目的**: 评估影响范围和优先级

### 3.3 建议的SOC平台查询语句

```bash
# 1. 获取攻击入口点 - 查询文件上传接口的访问历史
GET /api/logs/http
{
  "filters": {
    "dst_ip": "2.15.16.44",
    "uri": "/uapim/upload/grouptemplet",
    "time_range": "2023-11-11 10:15:49 TO 2023-11-11 12:15:49"
  }
}

# 2. 检测webshell通信 - 查询shell.jsp的访问
GET /api/logs/http
{
  "filters": {
    "dst_ip": "2.15.16.44",
    "uri": "*shell.jsp*",
    "time_range": "2023-11-11 11:15:49 TO 2023-11-11 23:59:59"
  }
}

# 3. 横向移动检测 - 查询失陷后的异常连接
GET /api/logs/connections
{
  "filters": {
    "src_ip": "2.15.16.44",
    "time_range": "2023-11-11 11:15:49 TO 2023-11-11 23:59:59"
  }
}

# 4. 关联告警 - 查询同IP的其他告警
GET /api/alerts
{
  "filters": {
    "dst_ip": "2.15.16.44",
    "time_range": "2023-11-11 00:00:00 TO 2023-11-11 23:59:59"
  }
}
```

---

## 四、处置建议

### 4.1 紧急处置措施 (立即执行)

#### 4.1.1 隔离失陷主机
```bash
# 建议通过以下方式之一进行隔离
# 方式1: 网络层面隔离
iptables -A INPUT -s 2.15.16.44 -j DROP
iptables -A OUTPUT -d 2.15.16.44 -j DROP

# 方式2: 关闭相关服务
systemctl stop tomcat  # 或对应的web服务

# 方式3: 拔网线 (最彻底但影响业务)
```

#### 4.1.2 删除webshell文件
```bash
# 通过SSH/RDP登录失陷主机
rm -f /tmp/join/shell.jsp

# 检查是否还有其他可疑文件
find /tmp -name "*.jsp" -o -name "shell.*" 2>/dev/null
find /var/www/html -name "*.jsp" -o -name "shell.*" 2>/dev/null
```

#### 4.1.3 查找其他潜在webshell
```bash
# 查找最近创建的可疑文件
find /var/www/html -name "*.jsp" -mtime -1 -ls
find /tmp -name "*.jsp" -mtime -1 -ls

# 查找包含webshell特征的文件
grep -r "eval(" /var/www/html --include="*.jsp"
grep -r "Runtime.getRuntime" /var/www/html --include="*.jsp"
grep -r "ProcessBuilder" /var/www/html --include="*.jsp"
```

### 4.2 后续处置措施

#### 4.2.1 修复文件上传漏洞
- **限制文件类型**: 仅允许上传业务必需的文件类型
- **文件内容检测**: 对上传文件进行内容检查，拒绝包含可执行代码的文件
- **文件重命名**: 上传后重命名文件，避免使用原始文件名
- **存储位置**: 将上传文件存储在web目录之外
- **访问控制**: 对上传目录禁用执行权限

#### 4.2.2 加强安全监控
```
监控规则建议:
1. 监控 /tmp/join/ 目录的文件创建行为
2. 监控 /uapim/upload 接口的访问，特别关注异常User-Agent
3. 监控web目录下JSP文件的创建和修改
4. 监控源IP 59.56.48.110 的后续访问
```

#### 4.2.3 获取失陷主机登录凭证
- 请提供失陷主机 (2.15.16.44) 的登录方式 (SSH/RDP等)
- 提供登录账号/密码或密钥
- 提供必要的管理员权限，以便执行上述处置命令

### 4.3 经验总结与规则固化

#### 4.3.1 可生成的研判规则
```yaml
规则名称: webshell上传研判规则
规则ID: RULE-TRIAGE-WEBSHELL-001
版本: 1.0

匹配条件:
  - attack_type包含"webshell" OR "文件上传" OR "后门"
  AND 上传文件后缀 IN [".php", ".asp", ".aspx", ".jsp", ".jspx"]
  AND (
    文件名包含"shell" OR "webshell" OR "backdoor" OR "hack"
    OR 文件内容匹配正则: "(eval|system|exec|shell_exec|passthru|Runtime\\.getRuntime|ProcessBuilder)"
  )
  AND attack_result = 1

研判结论: 定向攻击
置信度: 高
```

#### 4.3.2 可生成的溯源脚本
```python
脚本名称: webshell_attack_traceback.py
功能: 自动溯源webshell攻击的入口点和通信行为

执行步骤:
1. 获取目的IP近24小时HTTP日志
2. 分析文件上传接口的访问历史
3. 检测webshell通信请求
4. 生成攻击时间线报告
5. 识别攻击者IP和攻击路径
```

#### 4.3.3 可生成的响应脚本
```python
脚本名称: webshell_response.sh
功能: 自动响应webshell上传事件

执行步骤:
1. 确认webshell文件路径
2. 隔离失陷主机 (可选)
3. 删除webshell文件
4. 查找其他潜在webshell
5. 生成处置报告
6. 通知相关人员
```

---

## 五、报告元信息

| 项 | 值 |
|----|-----|
| 分析时间 | 2026-02-14 |
| 告警源文件 | samples/1N-webshell上传.json |
| 分析引擎 | SOC-Copilot v1.0 |
| 报告格式 | Markdown |

---

**⚠️ 重要提示**:
1. 本报告基于单个告警日志分析，完整的调查需要SOC平台API支持
2. 建议尽快执行紧急处置措施，防止攻击者进一步利用webshell
3. 失陷主机可能已被完全控制，建议在隔离后进行全面的系统安全检查
4. 建议将本次经验固化为规则和脚本，形成自动化的处置能力
