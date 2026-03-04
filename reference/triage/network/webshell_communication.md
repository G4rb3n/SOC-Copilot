# Webshell通信研判

## 目标
判断webshell通信的告警是真实攻击，还是业务行为误报。

## 范围
- webshell通信
- web后门通信
- 一句话木马执行
- 异常POST请求
- webshell管理工具流量（冰蝎、哥斯拉、蚁剑、菜刀等）

## 输入
| 参数 | 说明 |
|------|------|
| `${alert:name}` | 告警名称 |
| `${alert:severity}` | 告警等级 |
| `${alert:direction}` | 告警访问方向 |
| `${alert:attackResult}` | 攻击结果 |
| `${alert:httpRequest}` | http请求内容 |
| `${alert:httpResponse}` | http响应内容 |
| `${alert:url}` | 告警URL路径 |
| `${alert:processPath}` | 告警进程路径 |

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
  - `${soc-getTcpLog}` - 获取TCP日志
- **EDR工具**: `${edr-mcp}`
  - `${edr-getFileContent}` - 获取文件内容

## 流程

### 正报判断

#### 1. 请求特征分析
- **1-1.** 分析请求方式
  - 从 `${alert:httpRequest}` 识别请求方法是否为POST
  - 检查POST数据长度是否异常（webshell通信通常有较大的POST数据）

- **1-2.** 分析请求头特征
  - 从 `${alert:httpRequest}` 识别是否存在webshell管理工具的UA特征，如：
    - 蚁剑: `antSword`, `AntSword`
    - 菜刀: `Mozilla/5.0` 配合特定行为
  - 检查Content-Type是否为 `application/octet-stream` 或异常类型

- **1-3.** 分析请求体特征
  - **非加密通信**：直接查看请求中是否存在恶意函数或恶意代码，常见恶意函数包括：`eval`、`exec`、`base64_encode`、`system`、`passthru`、`shell_exec`等
  - **加密通信**：冰蝎、哥斯拉使用AES等加密，请求体为加密数据
  - 识别是否存在base64编码的命令执行特征
  - 识别是否存在常见的webshell参数名: `pass`, `password`, `cmd`, `command`, `shell`, `c`, `e`, `exec`, `eval`, `assert`
  - 识别是否存在一句话木马特征: `eval($_POST`, `assert($_POST`, `system($_POST`

#### 2. 响应特征分析
- **2-1.** 分析响应内容
  - 从 `${alert:httpResponse}` 识别是否包含命令执行结果特征
  - 识别是否包含文件操作结果（目录列表、文件内容等）
  - 识别是否包含数据库查询结果
  - 识别是否包含系统敏感信息（系统路径、用户名等）
  - 识别响应内容是否为加密数据（冰蝎、哥斯拉的加密响应）

- **2-2.** 分析响应状态
  - 检查 `${alert:attackResult}` 是否为成功
  - 检查HTTP状态码是否为200

#### 3. URL路径分析
- **3-1.** 分析URL特征
  - 从 `${alert:url}` 识别是否为异常路径
  - 检查是否为随机命名的文件: `/uploads/ab12cd34.php`, `/images/x9k2m.php`, `/0264172abff3cdd6.jsp`
  - 检查是否为隐藏文件: `/.shell.php`, `/.config.php`
  - 检查是否伪装成正常文件: `/images/logo.jpg.php`, `/upload/avatar.png.php`
  - 检查是否包含工具特征: `shell`, `bingxie`, `gesila`, `antsword`, `caidao`

#### 4. 关联告警分析
- **4-1.** 分析相关告警
  - 通过 `${soc-getAlert}` 获取该目的IP近24小时的告警，判断是否有webshell上传、漏洞利用等前置告警
  - 判断是否有同一源IP的多次webshell通信告警
  - 判断是否存在同一URL的多次访问告警

### 误报判断

#### 1. 资产信息分析
- **1-1.** 分析受害资产
  - 通过 `${soc-getAsset}` 获取该目的IP的资产信息，判断是否为存在动态交互业务的web服务器
  - 判断 `${alert:direction}` 是否为内对内或外对内（正常业务通常是外对内）

#### 2. 请求特征分析
- **2-1.** 分析请求内容
  - 从 `${alert:httpRequest}` 识别POST数据是否为正常的业务数据格式（JSON、表单等）
  - 识别是否存在正常的业务参数和值
  - 判断请求URL是否为已知的业务接口路径
  - **加密通信分析**：如果请求体明显乱码（各种符号+英文），且乱码很长，极可能是业务二进制数据导致的乱码；如果不是乱码，可尝试base64解码看能否得到明文，辅助研判是否为业务

- **2-2.** 分析URL路径
  - 从 `${alert:url}` 识别是否为常见的业务文件路径
  - 判断文件名是否符合业务命名规范（如 `index.jsp`, `api.php`, `upload.php`, `login.php`, `Upload.ashx`）

#### 3. 响应特征分析
- **3-1.** 分析响应内容
  - 从 `${alert:httpResponse}` 识别响应内容是否为正常的业务响应
  - 判断响应是否为JSON、HTML等正常格式
  - 识别响应内容是否包含正常的业务数据结构
  - 检查响应是否包含文件上传成功信息（如返回文件存储路径）

#### 4. 历史流量分析
- **4-1.** 分析HTTP请求历史
  - 通过 `${soc-getHttpLog}` 获取该目的IP近7天（或近一个月）的http请求日志
  - 判断该URL是否长期存在正常的业务访问
  - 判断该URL的请求频率和模式是否符合正常业务特征
  - 如果每隔段时间就有相同URL访问日志，几乎可判断是业务

- **4-2.** 分析访问模式
  - 检查是否存在同一源IP的大量相似请求（可能是正常的API调用）
  - 检查访问时间模式是否符合业务规律（工作时间集中等）

#### 5. 历史告警分析
- **5-1.** 分析历史告警
  - 通过 `${soc-getAlert}` 获取该目的IP近7天的告警
  - 判断是否存在相同URL的多次误报告警
  - 判断该告警是否为已知业务触发的规律性告警

#### 6. 文件特征分析
- **6-1.** 分析目标文件
  - 通过 `${edr-getFileContent}` 获取 `${alert:url}` 对应的文件内容
  - 判断文件是否为正常的业务代码
  - 识别文件是否包含常见的webshell特征代码