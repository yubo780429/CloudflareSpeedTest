# CFST DualBench 2.1.0

CFST DualBench 是一个独立的 Cloudflare CDN 三协议对照测速工具。对同一份候选 IP 列表分别测量：

1. TCP + TLS + HTTP/1.1
2. TCP + TLS + HTTP/2
3. UDP + QUIC + TLS + HTTP/3

每个候选 IP 的三种下载测试都强制拨号到该 IP，同时保留测速 URL 的域名作为 TLS SNI 和 HTTP Host。程序会校验实际响应协议版本；HTTP/2 请求如果实际得到 HTTP/1.1，或 HTTP/3 请求得到较低版本，都会判定失败，不会把回退速度写入该协议排名。

## 本版重点修复

- 默认测速地址改为 `https://h3.speed.cloudflare.com/__down?bytes=10000000000`，不再使用已对本次请求返回 403 的 `https://cf.xiu2.xyz/url`。
- HTTP/1.1、HTTP/2 的 TLS ALPN 分别限定为 `http/1.1`、`h2`；HTTP/3 使用 QUIC，ALPN 为 `h3`。
- 严格验证实际响应的 `ProtoMajor/ProtoMinor`。协议不匹配时记录错误并排除出协议排名。
- 禁止自动跟随重定向。3xx 状态和 `Location` 会写入诊断文件，避免跟随跳转后测到非候选 IP。
- HTTP 正文按 `-dt` 的时间窗口计时。若下载对象提前 EOF，会在时间窗口内重新 GET；短文件不会只凭极短一次下载时间形成虚高排名。
- 协议排名 CSV 只保留有效成功样本；失败、403、协议降级和 QUIC 建连失败统一写入诊断 CSV。
- 优先从测速响应的 `colo` 元数据读取 Cloudflare PoP，并保留 CF-Ray、ALPN、状态码、实际 HTTP 协议、国家、城市、出口 IP、ASN、TTFB、请求次数等诊断字段。
- `result-compare.csv` 在启用 `-cfcolo` 时，只要 H1/H2/H3 至少一个实际成功响应属于该 Colo，就保留该 IP 的横向诊断行；各协议独立排名仍按各自的 Colo 过滤。
- 对 `speed.cloudflare.com` / `*.speed.cloudflare.com` 自动发送同源 Referer，兼容大尺寸下载端点对 Referer 的校验。

## 编译要求

- Go 1.26 或更新版本。
- 首次构建需要访问 Go Module Proxy，下载 `github.com/quic-go/quic-go v0.66.0` 及其依赖。
- Windows / Linux 均支持；HTTP/3 需要 UDP 通信。

Windows PowerShell：

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build-windows.ps1
```

Linux：

```bash
chmod +x build-linux.sh
./build-linux.sh
```

也可以手动构建：

```powershell
go mod tidy
go build -trimpath -ldflags "-s -w" -o cfst-dualbench-windows-amd64.exe .
```

## Windows 快速运行

```powershell
.\cfst-dualbench-windows-amd64.exe -dn 30 -dt 15s -t 4 -n 160 -cfcolo LAX -quic-stream-window 32 -quic-conn-window 64
```

PowerShell 推荐使用参数数组，避免反引号续行被粘贴破坏：

```powershell
$exe = ".\cfst-dualbench-windows-amd64.exe"
$args = @(
    "-dn", "30",
    "-dt", "15s",
    "-t", "4",
    "-n", "160",
    "-cfcolo", "LAX",
    "-quic-stream-window", "32",
    "-quic-conn-window", "64"
)
& $exe @args
```

`-n` 是并发延迟探测线程数，`-dn` 是进入三协议下载测试的 IP 数量；二者不是同一个参数，不要重复设置 `-n`。

## 首次冒烟测试建议

建议先只测一个已知可连通的 IP，并暂时不要加 `-cfcolo`，先观察该 IP 实际落到哪个 Cloudflare Colo：

```powershell
.\cfst-dualbench-windows-amd64.exe -ip "198.41.211.39" -dn 1 -dt 5s -t 1 -n 1 -out result-smoke
```

先检查 `result-smoke\result-diagnostics.csv` 中每个协议的状态、实际协议、ALPN、Colo 和错误。只有真实观测到 `LAX` 后，再使用 `-cfcolo LAX` 过滤排名。`-cfcolo` 只是结果过滤条件，不会把 Anycast 流量强制路由到 LAX。

## 自定义测速 URL

默认使用 Cloudflare 的 HTTP/3 专用测速主机下载接口：

```text
https://h3.speed.cloudflare.com/__down?bytes=10000000000
```

也可以指定自建 HTTPS 大文件地址：

```powershell
.\cfst-dualbench-windows-amd64.exe -url "https://speed.example.com/large.bin" -dn 30 -dt 15s
```

测速对象可以是有限大小的静态文件。若在 `-dt` 时间窗口内提前下载完，程序会重复 GET 同一 URL，直至时间窗口结束；如果响应体为空或采样窗口明显不足，该协议会判为失败，不进入排名。

## 参数

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `-url` | `https://h3.speed.cloudflare.com/__down?bytes=10000000000` | HTTPS 下载测速 URL |
| `-f` | `ip.txt,ipv6.txt` | IP/CIDR 文件，多个文件逗号分隔 |
| `-ip` | 空 | 额外指定 IP/CIDR，逗号分隔；若未显式指定 `-f`，会替代默认文件 |
| `-tp` | `443` | TCP/UDP 目标端口 |
| `-n` | `160` | 并发 TCP/QUIC 延迟探测线程数 |
| `-t` | `4` | 每 IP TCP 和 QUIC 握手探测次数 |
| `-dn` | `20` | 按延迟排序后参与三协议下载测速的 IP 数量 |
| `-dt` | `10s` | 每协议正文测速时间，例如 `15s` |
| `-request-timeout` | `6s` | 每次请求建立连接及等待响应头的超时 |
| `-probe-timeout` | `1500ms` | TCP connect / QUIC 握手探测超时 |
| `-samples-per-cidr` | `32` | 每个 CIDR 随机抽样数 |
| `-allip` | `false` | 展开整个 CIDR（受最大地址数限制） |
| `-max-expand` | `65536` | `-allip` 时单个 CIDR 最大地址数 |
| `-cfcolo` | 空 | 按响应实际 Colo 过滤排名，例如 `LAX` |
| `-out` | `result-dualbench` | CSV 输出目录 |
| `-quic-stream-window` | `32` | QUIC Stream 最大接收窗口 MiB |
| `-quic-conn-window` | `64` | QUIC Connection 最大接收窗口 MiB |

## 输出文件

默认写入 `result-dualbench`：

- `result-tcp.csv`：只包含验证通过的 HTTP/1.1 排名。
- `result-h2.csv`：只包含验证通过的 HTTP/2 排名。
- `result-h3.csv`：只包含验证通过的 HTTP/3 排名。
- `result-compare.csv`：同 IP 三协议横向对照，失败协议速度留空，并保留协议错误。
- `result-diagnostics.csv`：全部候选下载 IP 的 TCP/QUIC 握手、HTTP 状态、实际协议、ALPN、TTFB、字节数、Colo、国家、城市、出口 IP、ASN、CF-Ray、请求次数、Content-Length、Location 和错误。

速度单位为 MiB/s（1 MiB = 1,048,576 bytes）。TTFB 从发出第一次请求开始计时，包含连接、TLS/QUIC 握手和等待首个响应头的时间。正文测速时间从首个响应头到达后开始；后续重复 GET 的请求开销包含在正文时间窗口内。

## 测试逻辑和限制

- H1/H2 使用 TCP；H3 使用独立 QUIC 连接，不依赖 curl，也不依赖 `curl --http3-only`。
- 三协议均直接连接候选 IP，不读取 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量；TLS SNI 和 HTTP Host 仍使用 URL 域名。
- 默认选择 `h3.speed.cloudflare.com`，而不是 `speed.cloudflare.com`：Cloudflare Speedtest 社区 issue 报告普通 `speed.cloudflare.com` 的 `__down` 请求仅走 HTTP/1.1，并指出 H3 测试使用独立的 `h3.speed.cloudflare.com` 主机；因此本工具对 H1/H2/H3 统一使用后者并严格验收实际协议。
- `-cfcolo` 是结果过滤条件，不会强制 Cloudflare 将 Anycast 连接路由到指定 PoP。程序记录每次实际响应的 `colo` / CF-Ray；如果连接实际落在 SIN，不能因为指定 `-cfcolo LAX` 就把它伪装成 LAX。
- HTTP/3 成功要求 QUIC 建连成功且响应实际为 HTTP/3。UDP/443 被本机防火墙、路由、运营商或 VPN/TUN 路径阻断时，H3 会失败并记录原因；不会回退到 H1/H2 冒充 H3。
- 如果测速站不支持 H2 或 H3，对应协议会明确失败。协议排名 CSV 不会包含降级结果。
- 候选 IP 的 Anycast 路由可能让不同 IP 到达同一个 PoP，也可能让同一 IP 在不同时段到达不同 PoP；Colo 是每次响应的观测值，不是 IP 的固定属性。
