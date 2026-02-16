# Webshell上传研判

## 目标
判断webshell上传的告警是真实攻击，还是业务行为误报。

## 范围
- webshell上传
- 文件上传
- web后门
- 脚本上传
- web目录写入
- web文件创建
- 一句话木马上传

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:direction}` | 告警访问方向 |
| `${alert:attackResult}` | 攻击结果 |
| `${alert:httpRequest}` | http请求内容 |
| `${alert:httpResponse}` | http响应内容 |
| `${alert:filePath}` | 告警文件路径 |

## 输出
| 参数 | 说明 |
|------|------|
| `${alert:triageResult}` | 研判结果 |
| `${alert:triageCoT}` | 研判思维链 |

## 工具
- **SOC工具**: `${soc-mcp}`
  - `${soc-getAlert}` - 获取告警信息
  - `${soc-getHttpLog}` - 获取HTTP日志
  - `${soc-getAsset}` - 获取资产信息
- **EDR工具**: `${edr-mcp}`
  - `${edr-getFileContent}` - 获取文件内容

## 流程

### 正报判断

#### 1. 文件特征分析
- **1-1.** 分析文件名后缀
  - 从 `${alert:httpRequest}` 或 `${alert:filePath}` 获取上传文件的名称
  - 检查是否为常见web脚本文件后缀名: `.php`、`.asp`、`.aspx`、`.jsp`、`.jspx` 等
  - 检查是否为常见图片马后缀名: `.jpg`、`.jpeg`、`.png` 等
  - 特别注意双后缀名文件: `.php.jpg`、`.asp.png` 等

- **1-2.** 分析文件内容
  - 从 `${alert:httpRequest}` 获取上传文件内容，或通过 `${edr-getFileContent}` 异步获取
  - 检查是否包含常见webshell命令: `eval`、`system`、`exec`、`shell_exec`、`passthru` 等
  - 检查是否包含常见webshell特征: `payload`、`passkey`、`base64` 等

#### 2. 关联告警分析
- **2-1.** 分析相关告警
  - 通过 `${soc-getAlert}` 获取该目的IP近24小时的告警，判断是否有其他关联告警，如漏洞扫描、webshell通信等

### 误报判断

#### 1. 资产信息分析
- **1-1.** 分析受害资产
  - 通过 `${soc-getAsset}` 获取该目的IP的资产信息，判断是否为存在文件上传相关业务的服务器（如web应用服务器、文件服务器等）
  - 判断 `${alert:direction}` 是否为内对内

#### 2. 文件特征分析
- **2-1.** 分析文件名特征
  - 从 `${alert:httpRequest}` 或 `${alert:filePath}` 获取上传文件的名称
  - 判断名称是否为常见的业务文件名（如 `index.php`、`config.php` 等）
  - 或者包含下划线等比较规范的业务文件名（如 `user_avatar.php`、`order_detail.php` 等）

- **2-2.** 分析文件内容特征
  - 从 `${alert:httpRequest}` 获取上传文件内容，或通过 `${edr-getFileContent}` 异步获取文件内容
  - 判断文件内容是否为常规的业务代码（包含大量注释、变量名称比较规范），或内容包含大部分乱码

#### 3. 历史告警分析
- **3-1.** 分析历史告警
  - 通过 `${soc-getAlert}` 获取该目的IP近7天的告警，判断是否有多个相似告警，以及告警里的上传文件名格式是否也是一致的

#### 4. 流量分析
- **4-1.** 分析HTTP请求
  - 通过 `${soc-getHttpLog}` 获取该目的IP近24小时的http请求日志，判断该url接口是否有其他相似的上传请求，以及上传文件名格式是否也是一致的