# CertUtil滥用研判

## 目标
判断CertUtil工具被滥用下载恶意文件的告警是真实攻击，还是误报。

## 范围
- CertUtil下载文件
- CertUtil编码解码
- CertUtilBase64操作
- 可疑证书工具使用
- LOLBIN滥用

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:hostName}` | 主机名 |
| `${alert:processPath}` | 进程路径 |
| `${alert:commandLine}` | 命令行参数 |
| `${alert:parentProcess}` | 父进程信息 |
| `${alert:filePath}` | 下载文件路径 |

## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **EDR工具**: `${edr-mcp}`
  - `${edr-getFileContent}` - 获取文件内容
  - `${edr-getFileHash}` - 获取文件哈希
  - `${edr-getProcessTree}` - 获取进程树
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getHttpLog}` - 获取HTTP日志

## 流程

### 正报判断

#### 1. 命令行特征分析
- **1-1.** 分析下载参数
  - 从 `${alert:commandLine}` 识别下载命令
  - 检查是否包含 `-urlcache`、`-split`、`-f` 参数组合
  - 识别是否从HTTP/HTTPS URL下载文件
  - 检查URL是否为IP地址形式（如 `http://166.62.100.52/`）

- **1-2.** 分析编码参数
  - 检查是否包含 `-encode`、`-decode` 参数
  - 识别是否对文件进行Base64编码/解码
  - 检查是否为隐藏恶意代码的编码操作

- **1-3.** 分析URL特征
  - 从 `${alert:commandLine}` 提取下载URL
  - 检查域名是否为新注册或可疑域名
  - 识别是否为IP直连形式
  - 检查URL路径是否包含随机字符串

#### 2. 父进程分析
- **2-1.** 分析调用来源
  - 从 `${alert:parentProcess}` 识别调用CertUtil的进程
  - 检查是否为异常父进程（如Java、Web服务器）
  - 识别是否为漏洞利用后的命令执行
  - 检查是否为脚本或宏代码调用

#### 3. 下载文件分析
- **3-1.** 分析文件特征
  - 通过 `${edr-getFileHash}` 获取文件哈希
  - 检查文件哈希是否在威胁情报中有记录
  - 从 `${alert:filePath}` 判断保存位置是否可疑
  - 识别文件名是否为随机字符串（如 `uFSyLszKsuR.exe`）

- **3-2.** 分析文件内容
  - 通过 `${edr-getFileContent}` 获取文件内容
  - 检查是否为PE可执行文件（MZ头）
  - 识别是否包含恶意代码特征
  - 检查是否为Metasploit、Cobalt Strike等攻击框架载荷

#### 4. 关联告警分析
- **4-1.** 分析上下文告警
  - 通过 `${soc-getAlert}` 获取该主机近24小时告警
  - 检查是否存在漏洞利用前置告警
  - 分析下载后是否有进程执行告警

### 误报判断

#### 1. 业务场景分析
- **1-1.** 分析下载内容
  - 检查下载URL是否为公司内部服务器
  - 识别下载文件是否为合法软件或更新包
  - 判断是否为IT运维操作

- **1-2.** 分析调用上下文
  - 检查父进程是否为已知的软件安装程序
  - 识别是否为系统管理工具调用
  - 判断是否为合法的证书操作

#### 2. 历史行为分析
- **2-1.** 分析历史执行
  - 通过 `${edr-getProcessTree}` 获取历史执行记录
  - 判断该命令是否有历史执行记录
  - 检查是否为周期性的合法操作