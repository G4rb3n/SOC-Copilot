# LSASS凭证转储研判

## 目标
判断LSASS进程内存访问/转储告警是真实攻击，还是误报。

## 范围
- LSASS进程内存访问
- 凭证转储
- Mimikatz活动
- 进程内存读取
- 敏感凭证获取

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:hostName}` | 主机名 |
| `${alert:processPath}` | 访问进程路径 |
| `${alert:targetProcess}` | 目标进程（LSASS） |
| `${alert:grantedAccess}` | 访问权限掩码 |
| `${alert:callTrace}` | 调用堆栈 |
| `${alert:user}` | 执行用户 |

## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **EDR工具**: `${edr-mcp}`
  - `${edr-getProcessTree}` - 获取进程树
  - `${edr-getFileHash}` - 获取文件哈希
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getAsset}` - 获取资产信息

## 流程

### 正报判断

#### 1. 访问权限分析
- **1-1.** 分析GrantedAccess掩码
  - 从 `${alert:grantedAccess}` 识别访问权限
  - `0x1010` - VM_READ权限（读取进程内存）
  - `0x1F0FFF` - PROCESS_ALL_ACCESS（完全访问）
  - `0x1F1FFF` - 包含读写的完全访问
  - 检查是否包含 `0x00000010` (VM_READ) 标志

- **1-2.** 分析调用堆栈
  - 从 `${alert:callTrace}` 识别调用来源
  - `UNKNOWN` 表示可能为注入代码调用
  - 检查是否包含可疑DLL（如 `mimilib.dll`）
  - 识别是否来自合法系统API调用

#### 2. 源进程分析
- **2-1.** 分析访问进程
  - 从 `${alert:processPath}` 识别发起访问的进程
  - 检查是否为可疑工具：`mimikatz.exe`、`procdump.exe`、`taskmgr.exe`
  - 识别是否为攻击框架进程：Metasploit、Cobalt Strike beacon
  - 检查是否为随机命名的进程

- **2-2.** 分析进程链
  - 通过 `${edr-getProcessTree}` 获取进程创建链
  - 检查父进程是否为漏洞利用后的异常进程
  - 识别是否存在权限提升行为（如getsystem）

#### 3. 关联行为分析
- **3-1.** 分析后续行为
  - 通过 `${soc-getAlert}` 获取该主机后续告警
  - 检查是否出现横向移动告警
  - 识别是否使用新凭证进行RDP/SMB访问
  - 分析是否有域管权限滥用

- **3-2.** 分析时间线
  - 检查LSASS访问是否在漏洞利用后短时间内发生
  - 分析是否在非工作时间执行

### 误报判断

#### 1. 合法工具分析
- **1-1.** 分析合法EDR/AV
  - 检查 `${alert:processPath}` 是否为已安装的EDR/AV程序
  - 识别是否为合法的安全扫描行为
  - 检查是否为授权的取证工具

- **1-2.** 分析系统工具
  - 检查是否为合法的系统管理工具
  - 识别是否为任务管理器的正常查询
  - 判断是否为Debug程序的合法附加

#### 2. 资产属性分析
- **2-1.** 分析主机角色
  - 通过 `${soc-getAsset}` 获取主机资产信息
  - 判断是否为域控制器（DC上LSASS访问更敏感）
  - 识别是否为特权服务器

- **2-2.** 分析访问用户
  - 从 `${alert:user}` 判断执行用户
  - 检查是否为本地SYSTEM账户（部分合法操作）
  - 识别是否为普通用户账户（高度可疑）

#### 3. 历史行为分析
- **3-1.** 分析历史告警
  - 通过 `${soc-getAlert}` 获取该主机历史LSASS访问告警
  - 判断是否为EDR的持续性扫描行为
  - 检查是否存在相同进程的重复告警