# CFST DualBench 2.1.0 更新记录

1. 默认下载测速 URL 改为 Cloudflare HTTP/3 专用测速主机 `h3.speed.cloudflare.com/__down?bytes=10000000000`；对 Cloudflare Speedtest 子域自动补充同源 Referer。
2. TCP HTTP/1.1 和 HTTP/2 分别设置严格 ALPN，并根据实际响应协议版本验收。
3. HTTP/3 通过 quic-go 独立 QUIC Transport 发起请求；根据实际 HTTP/3 响应验收，不发生协议降级计分。
4. 下载对象提前 EOF 时重复请求同一对象，保持 `-dt` 的有效正文采样时间窗口。
5. 禁止自动重定向；诊断记录 Location，避免测速目标发生变化。
6. 排名 CSV 剔除 HTTP 状态异常、协议不匹配、正文错误及采样时间不足的样本。
7. 增强诊断 CSV，加入实际 HTTP 协议、ALPN、CF-Ray、Colo、国家、城市、出口 IP、ASN、Content-Length、请求次数和 Location；排名排序不再使用失败样本速度。
8. 修正 Colo 读取优先级：先读测速接口的 `colo` / `cf-meta-colo` 元数据，再退回 CF-Ray 后缀。
