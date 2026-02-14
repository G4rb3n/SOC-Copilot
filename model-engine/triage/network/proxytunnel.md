---
name: proxytunnel
description: 分析隧道代理的告警，判断是否为真实攻击，还是业务行为误报。
---

## 目标
判断隧道代理的告警是真实攻击，还是业务行为误报。

## 范围
- 隧道代理工具
- 端口转发
- 反向代理
- frp通信
- ngrok通信
- iox通信
- nps通信

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:direction}` | 告警访问方向 |
| `${alert:attackResult}` | 攻击结果 |
| `${alert:packetContent}` | 数据包内容 |
| `${alert:processPath}` | 告警进程路径 |


## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getTcpLog}` - 获取TCP日志
  - `${soc-getAsset}` - 获取资产信息
- **EDR工具**: `${edr-mcp}`
  - `${edr-getFileContent}` - 获取文件内容

## 流程

### 正报判断

#### 1. 通信特征分析
- **1-1.**分析工具特征
  - 从 `${alert:packetContent}` 识别是否存在隧道工具版本号类似的特征，如frp的{"version":"xxx", "os":"xxx", "arch":"xxx", "privilege":"xxx", "timestamp":"xxx", "pool_count":"xxx"}等
  - 从 `${alert:packetContent}` 识别是否存在隧道工具字符串类似的特征，如ngrok的tunnel.us.ngork.com等
- **1-2.**分析方向特征
  - 判断 `${alert:direction}` 是否为内对外

#### 2. 关联告警分析
- **2-1.** 分析相关告警
  - 通过 `${soc-getAlert}` 获取该源IP近24小时的告警，是否有相关的终端告警（进程通信目的IP和目的端口相匹配）
  - 通过 `${soc-getTcpLog}` 获取该源IP近24天的tcp日志，是否是一段时间持续的通信行为

### 误报判断

#### 1. 资产信息分析
- **1-1.** 分析受害资产
  - 通过 `${soc-getAsset}` 获取该源IP的资产信息，判断是否为个人PC，若是则大概率是客户端软件行为
  - 判断 `${alert:direction}` 是否为内对内或外对内

#### 2. 进程特征分析
- **1-1.**分析工具特征
  - 从 `${alert:processPath}` 识别是否为常见客户端软件的进程路径，如C:\Program Files (x86)\下载器\downloader.exe等

#### 3. 流量分析
- **3-1.** 分析tcp请求
  - 通过 `${soc-getTcpLog}` 获取该源IP近7天的tcp请求日志，判断该目的IP和目的端口是否一直有流量，若是则可能是业务或客户端软件的行为