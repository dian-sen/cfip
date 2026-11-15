# cfip

CFData 测速结果的离线筛选与订阅发布工具。**不测速、不探测地址，不改变 CFData → GitHub → EDT 的使用方式。**

支持**移动**与**联通**两套独立优选结果，方便不同运营商网络环境分别使用。

```text
CFData 测速 → 上传 raw/results.csv          → GitHub Actions 筛选 → api/preferred.txt          (移动)
              上传 raw/results_unicom.csv   → GitHub Actions 筛选 → api/preferred_unicom.txt   (联通)
```

## 使用

### 移动（默认，保持兼容）

将 CFData 导出的结果上传/覆盖到 **`raw/results.csv`**。

上传后工作流自动更新：

```text
https://raw.githubusercontent.com/dian-sen/cfip/refs/heads/main/api%2Fpreferred.txt
```

### 联通

将联通网络下的 CFData 导出结果上传/覆盖到 **`raw/results_unicom.csv`**。

上传后工作流自动更新：

```text
https://raw.githubusercontent.com/dian-sen/cfip/refs/heads/main/api%2Fpreferred_unicom.txt
```

EDT 中可分别添加两条订阅，按当前网络环境选择使用。

### 输出格式

```text
38.47.220.144:443#HK-67ms
```

固定地区顺序为 HK、TW、JP、US、KR、SG、DE；每区按延迟取最多 10 个有效、去重后的端点。不足 10 条按实际数量输出；同延迟按端点排序，以免输入顺序变化产生无意义提交。IPv6 端点使用 `[IPv6]:端口`，是否可用还取决于订阅客户端支持。

工作流只负责生成文件；GitHub Raw 缓存与 EDT 自身刷新周期可能影响客户端看到更新的时间，不能保证推送即刻同步。标签延迟来自上传数据，不代表发布时重新测量。

## 格式识别

支持例如：

```csv
IP:PORT,源IP位置,网络延迟
38.47.220.144:443,HK,67ms
```

```csv
67MS,HKG,38.47.220.144:443
```

```csv
地区,端口,平均延迟(ms),IP地址
香港,443,67,38.47.220.144
```

```text
38.47.220.144:443#HKG-HK,67ms
38.47.220.144:443#HK-67ms
```

识别优先级：

1. 已识别的表头（中英文别名）；源 IP 地区优先于通用地区，通用地区优先于落地 colo。
2. 无表头时，结合地址结构、国家/机场代码、带单位延迟推断各列，不依赖列的固定位置。
3. 只有一个可用裸数字候选列时，可将其按毫秒解释；多个不可区分的数字列则拒绝猜测，保留旧订阅。

地区支持上述七个国家/地区的常用名称，以及 HKG、TPE、NRT、KIX、ICN、SIN、FRA、LAX 等 colo 代码。其他地区不参与发布；“源 IP 地区”不等于实际落地机房，脚本不额外验证归属。

延迟支持大小写不敏感的 `ms`、`s`、`us`/`µs`/`μs` 和中文单位，统一输出毫秒；无单位默认毫秒。缺失/无效延迟不伪造为 `99999ms`。分离的 IP 和端口列也可识别，但不会凭空补默认端口。

**任何猜测都存在信息边界**：无表头且速度、次数、端口和延迟都是裸数字时，不能可靠地凭数字推断用途。遇到多个候选、多个延迟指标或多个地址列时，工作流失败而不是悄悄选错。

### 识别歧义时手动指定列

在 GitHub Actions → **Filter Preferred IPs by Region** → **Run workflow**，选择 main 分支。可选填：

- `endpoint_column`：完整端点或 IP 列。
- `port_column`：单独的端口列。
- `region_column`：需要使用的地区列。
- `latency_column`：实际延迟列。

填 **从 1 开始的列号**或精确表头名，其余留空继续自动识别。例如 `IP,端口,地区,延迟,速度` 全为无表头裸数字，可指定端口列 `2`、延迟列 `4`。这些覆盖只用于这一次手动运行；下一次上传重新自动识别。手动运行时参数会同时应用于移动和联通两套结果。

`raw/results.txt` 当前不是工作流输入。如果该文件仅包含 `IP:端口#HKG-HK`、没有延迟，就无法据此选出最低延迟，不会拿它替代 CSV。

## 校验与失败保护

- 使用 Python `ipaddress` 校验地址，排除私网、回环、组播等非公网地址；端口须为 1–65535。
- 延迟必须是有限、非负的有效数字，排除负数、NaN、Infinity、速度和百分比；另限制极端指数避免异常文本膨胀。
- 同端点、同地区的重复记录保留最低延迟；同端点出现互相冲突的有效地区，隔离该端点并记录统计。
- 缺文件、空文件、无有效输出、列无法可靠推断时返回失败，**不覆盖上一版订阅**。
- 成功后先写临时文件并原子替换；测试或筛选失败不会进入提交步骤。
- 不设置固定的“每区必须 10 条”或强制地区齐全门槛，以允许上传不同规模的有效结果。部分坏行会跳过；非空不代表数据完整，应查看统计。
- Actions Summary 输出推断列、有效记录、丢弃原因及各地区数量，便于排查。
- 发布任务按分支串行执行，检出最新 main；不强制推送、不把旧结果 rebase 到新上传之上。若运行中 main 被更新导致 push 冲突，该次任务安全失败；可等后续上传任务或手动重跑。

## 本地开发

需要 Python 3.10+，仅使用标准库，无第三方 Python 依赖。

```sh
python3 -m unittest discover -s tests -v

# 移动
python3 scripts/filter_ips.py --input raw/results.csv --output /tmp/preferred-preview.txt

# 联通
python3 scripts/filter_ips.py --input raw/results_unicom.csv --output /tmp/preferred-unicom-preview.txt
```

列覆盖示例：

```sh
python3 scripts/filter_ips.py --latency-column 3
```

筛选脚本、测试、`filter-ip.yml`、`raw/results.csv` 或 `raw/results_unicom.csv` 更新后触发 main 发布流程；仅更新 README 或 `test.yml` 不触发发布。Pull Request 会执行只读测试和预览，不发布文件。

## Unicom 定额低延迟订阅

新增独立工作流 **Generate Unicom Top 60**，读取联通数据源 **`raw/results_unicom.csv`**，发布到 **`api/Unicom.txt`**（注意文件名大小写）：

```text
https://raw.githubusercontent.com/dian-sen/cfip/refs/heads/main/api/Unicom.txt
```

选择规则：

- 日本 JP：延迟最低的 20 个端点。
- 新加坡 SG：延迟最低的 10 个端点。
- 美国 US：延迟最低的 20 个端点。
- 其他地区（排除 JP、SG、US）：所有其他地区合并排序，取延迟最低的 10 个端点，并非每个地区各取 10 个。

先按各组名额选择，再将入选端点统一按延迟升序输出。最多 60 条；某组不足时仅输出实际可用数量，不借用其他组补齐。格式仍为 `IP:端口#地区-延迟ms`，不会改动原有 `preferred.txt` 和 `preferred_unicom.txt` 的筛选规则。

该订阅额外支持 ISO 两字母国家/地区代码（例如 NL、CA、GB），以及常用中英文别名和明确映射的 colo；未知标签跳过。沿用无表头/列乱序推断、严格地址与延迟校验、去重、地区冲突隔离和失败保留旧文件，无测速请求。

上传或覆盖 `raw/results_unicom.csv` 后自动运行；脚本、测试或新工作流更新也会触发。可在该工作流的 Run workflow 中手动指定列号或表头名，参数只用于该次运行。新工作流与旧发布流程共用分支发布锁，避免同时推送。

本地预览：

```sh
python3 scripts/filter_unicom.py --output /tmp/Unicom-preview.txt
python3 -m unittest discover -s tests -v
```
