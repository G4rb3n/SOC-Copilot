# Java进程异常子进程研判

## 目标
判断Java进程（如ActiveMQ、Tomcat等）创建异常子进程的告警是真实攻击，还是误报。

## 范围
- Java进程异常子进程
- Web服务器进程执行
- 应用服务器RCE
- 中间件命令执行
- 容器进程逃逸执行

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:hostName}` | 主机名 |
| `${alert:processPath}` | 父进程路径 |
| `${alert:childProcessPath}` | 子进程路径 |
| `${alert:commandLine}` | 命令行参数 |
| `${alert:user}` | 执行用户 |

## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **EDR工具**: `${edr-mcp}`
  - `${edr-getProcessTree}` - 获取进程树
  - `${edr-getFileContent}` - 获取文件内容
  - `${edr-getNetworkConnection}` - 获取网络连接
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getAsset}` - 获取资产信息

## 流程

### 正报判断

#### 1. 进程链分析
- **1-1.** 分析父进程特征
  - 从 `${alert:processPath}` 确认是否为Java应用服务器进程
  - 识别常见Java服务：`java.exe`、`javaw.exe`、`ActiveMQ`、`Tomcat`、`WebLogic`
  - 检查父进程命令行是否包含正常启动参数

- **1-2.** 分析子进程特征
  - 从 `${alert:childProcessPath}` 识别可疑进程
  - 检查是否为Shell进程：`cmd.exe`、`powershell.exe`、`bash`
  - 识别是否为下载工具：`certutil.exe`、`bitsadmin.exe`、`curl.exe`
  - 检查是否为系统工具：`whoami`、`net`、`systeminfo`

- **1-3.** 分析命令行参数
  - 从 `${alert:commandLine}` 识别可疑命令
  - 检查是否包含CertUtil下载参数：`-urlcache -split -f`
  - 识别是否包含PowerShell编码执行：`-enc`、`-encodedcommand`
  - 检查是否包含网络探测命令

#### 2. 关联行为分析
- **2-1.** 分析网络连接
  - 通过 `${edr-getNetworkConnection}` 获取该进程的网络连接
  - 检查子进程是否发起新的网络连接
  - 识别是否连接到可疑外部IP或非标准端口

- **2-2.** 分析文件操作
  - 检查是否在临时目录创建可执行文件
  - 识别是否下载或创建可疑脚本文件
  - 分析文件名是否为随机字符串

#### 3. 漏洞利用关联
- **3-1.** 分析前置告警
  - 通过 `${soc-getAlert}` 获取该主机近24小时告警
  - 检查是否存在CVE漏洞利用告警
  - 分析是否存在Web攻击告警

### 误报判断

#### 1. 业务场景分析
- **1-1.** 分析业务特征
  - 通过 `${soc-getAsset}` 获取主机资产信息
  - 确认Java应用的业务用途
  - 判断是否存在调用系统命令的业务需求

- **1-2.** 分析命令合理性
  - 从 `${alert:commandLine}` 判断命令是否为正常业务调用
  - 检查是否为监控脚本、备份脚本等合法操作
  - 识别命令参数是否符合业务逻辑

#### 2. 历史行为分析
- **2-1.** 分析历史执行
  - 通过 `${edr-getProcessTree}` 获取历史进程执行记录
  - 判断该子进程是否存在持续性的执行记录
  - 检查执行时间是否有规律性

#### 3. 签名验证
- **3-1.** 验证文件签名
  - 检查子进程文件是否具有有效数字签名
  - 识别是否为系统自带工具或商业软件