# Metasploit C2通信研判

## 目标
判断Metasploit框架C2通信告警是真实攻击，还是误报。

## 范围
- Metasploit框架通信
- Meterpreter会话
- Metasploit Stager
- 反向Shell通信
- Bind Shell通信

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:srcIp}` | 源IP地址 |
| `${alert:dstIp}` | 目的IP地址 |
| `${alert:dstPort}` | 目的端口 |
| `${alert:packetContent}` | 数据包内容 |
| `${alert:httpRequest}` | HTTP请求内容 |
| `${alert:httpResponse}` | HTTP响应内容 |
| `${alert:sslCert}` | SSL证书信息 |

## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getTcpLog}` - 获取TCP日志
  - `${soc-getHttpLog}` - 获取HTTP日志
  - `${soc-getAsset}` - 获取资产信息

## 流程

### 正报判断

#### 1. Stager特征分析

- **1-1.** 分析Metsrv绑定特征
  - 从 `${alert:packetContent}` 识别 `MetsrvBind` 特征
  - 检查是否包含 `stdapi_` 函数调用前缀
  - 识别Meterpreter的TLV(Type-Length-Value)数据结构

- **1-2.** 分析默认Stager字符串
  - 检查是否包含 `RECV`、`SEND`、`CORE` 等大写命令字
  - 识别常见Stager响应: `_response`、`_request` 后缀
  - 检查是否包含 `channel_id`、`request_id` 字段

#### 2. HTTP/HTTPS传输特征分析

- **2-1.** 分析默认URI特征
  - 从 `${alert:httpRequest}` 识别Metasploit默认URI模式:
    ```
    /        (默认根路径)
    /____    (4个下划线)
    /[随机4-8字符]
    ```
  - 检查URI是否为随机字母数字组合（如 `/aB3kL9mN`）
  - 识别URI中是否包含 `meta`、`meter` 等关键字

- **2-2.** 分析User-Agent特征
  - 从 `${alert:httpRequest}` 识别默认User-Agent:
    ```
    Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
    ```
  - 检查是否为自定义或随机UA字符串
  - 识别UA是否与操作系统指纹不匹配

- **2-3.** 分析HTTP请求特征
  - 检查请求头是否包含 `X-Requested-With: XMLHttpRequest`
  - 识别Cookie字段中的会话标识格式
  - 检查Content-Type是否为 `application/octet-stream`
  - 分析POST数据是否为二进制或base64编码

- **2-4.** 分析HTTP响应特征
  - 从 `${alert:httpResponse}` 识别响应体特征
  - 检查是否返回 `Keep-Alive` 头
  - 识别响应是否为加密的二进制数据

#### 3. TCP传输特征分析

- **3-1.** 分析端口特征
  - 检查 `${alert:dstPort}` 是否为常见默认端口:
    ```
    4444   (默认反向Shell端口)
    5555   (常用备用端口)
    6666   (常用备用端口)
    7777   (常用备用端口)
    8888   (常用备用端口)
    12345  (Netbus遗留，部分工具复用)
    31337  (Elite端口，部分工具复用)
    ```
  - 分析是否为高位随机端口（>10000）

- **3-2.** 分析数据包特征
  - 从 `${alert:packetContent}` 识别Meterpreter心跳包特征
  - 检查数据包长度是否固定（心跳通常为固定小包）
  - 分析心跳间隔（默认约5-10秒）

- **3-3.** 分析Bind Shell特征
  - 识别监听端口的入站连接模式
  - 检查是否为反向连接（被控端主动外连）
  - 分析连接建立后的首包特征

#### 4. SSL/TLS特征分析

- **4-1.** 分析证书特征
  - 从 `${alert:sslCert}` 识别证书信息
  - 检查证书是否为自签名
  - 识别默认证书特征:
    ```
    CN=localhost
    CN=www.example.com
    CN=[随机字符串]
    ```
  - 检查证书颁发者与使用者是否相同
  - 分析证书有效期是否异常（过长或过短）

- **4-2.** 分析TLS握手特征
  - 检查是否使用过时的TLS版本（TLS 1.0/1.1）
  - 识别加密套件是否为默认配置
  - 分析SNI字段是否与证书CN匹配

#### 5. 载荷特征分析

- **5-1.** 分析PE文件特征
  - 检查文件资源段是否包含 `Msf`、`Metasploit` 字符串
  - 识别编译时间戳是否异常
  - 检查导入表是否包含 `ws2_32.dll`、`wininet.dll` 等网络库

#### 6. 关联告警分析

- **6-1.** 分析前置告警
  - 通过 `${soc-getAlert}` 获取源IP近24小时告警
  - 检查是否存在漏洞利用告警
  - 分析是否存在Web攻击告警
  - 检查是否存在可执行文件下载告警

- **6-2.** 分析后续行为
  - 通过 `${soc-getTcpLog}` 获取源IP后续网络行为
  - 检查是否存在SMB扫描（445端口）
  - 分析是否存在RDP连接（3389端口）
  - 识别是否存在数据外泄流量

### 误报判断

#### 1. 资产信息分析
- **1-1.** 分析源IP资产
  - 通过 `${soc-getAsset}` 获取源IP资产信息
  - 判断是否为已知的安全测试主机
  - 检查是否在授权渗透测试IP列表中

#### 2. 业务流量分析
- **2-1.** 分析业务特征
  - 通过 `${soc-getHttpLog}` 获取该目的IP的HTTP日志
  - 判断该目的IP和端口是否为已知业务服务
  - 检查是否存在持续性的正常业务访问记录

- **2-2.** 分析通信对端
  - 调查目的IP的ASN和地理位置
  - 判断是否为云服务商IP（AWS、Azure等）
  - 检查是否为CDN或负载均衡节点

#### 3. 时间窗口分析
- **3-1.** 分析时间特征
  - 检查通信时间是否在授权测试窗口内
  - 判断是否在业务高峰期
  - 分析通信持续时间是否符合业务特征