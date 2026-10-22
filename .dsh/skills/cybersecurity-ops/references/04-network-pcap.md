# 网络流量与 PCAP 分析

> Sniffnet 让“看流量”变得可视化，Wireshark/tshark 让结论可证据化。这个手册的目标是：从 PCAP 或 Zeek/Suricata 日志中，给出**可复现的流量结论 + 检测建议**，而不是只贴“可疑 IP”。

## 1. 适用场景

- 告警：C2 beacon、DNS 隧道、数据外传、横向移动、端口扫描。
- 事件响应：确认受影响主机、时间线、外联目标。
- 网络取证：保留证据、计算哈希、提取对象。
- 检测工程：从真实流量提炼可部署的规则。

前提：流量采集合法；你有权分析该网络/主机；不要在生产核心链路随意抓包。

## 2. 采集与保全

- **采集点**：SPAN/TAP/主机抓包/云 VPC Flow Logs/防火墙日志。记录位置、接口、方向。
- **过滤器**：先宽后窄；记录 BPF，例如 `host 10.0.0.5 and (tcp port 443 or udp port 53)`。
- **时长/容量**：按问题设定；避免无限抓包占满磁盘。
- **哈希**：`sha256sum capture.pcapng`，写入证据清单。
- **元数据**：链路类型、snaplen、丢包计数、时区、捕获工具/版本。
- **只读**：原始 PCAP 只读；分析用副本。

```bash
# Linux 示例：限 60 秒/1000 包；先按授权调整接口与容量预算。
# tcpdump 默认写 pcap，文件扩展名不能改变格式。
timeout --signal=INT 60s sudo tcpdump -i eth0 -s 0 -c 1000 -w case-001.pcap 'host 10.0.0.5 and not port 22'
sha256sum case-001.pcap > case-001.pcap.sha256
```

Windows 可用 `dumpcap`/Wireshark；Sniffnet 适合快速可视化，但不替代证据链。

## 3. 第一轮：概览

```bash
# 文件信息、时间范围、包数
capinfos case-001.pcap

# 协议层级
tshark -r case-001.pcap -q -z io,phs

# 会话/端点 Top
tshark -r case-001.pcap -q -z conv,tcp
tshark -r case-001.pcap -q -z endpoints,ip

# DNS 查询
tshark -r case-001.pcap -Y dns -T fields -e frame.time_utc -e ip.src -e dns.qry.name \
  | sort | uniq -c | sort -nr | head -50

# HTTP Host/URI（明文）
tshark -r case-001.pcap -Y http.request -T fields \
  -e frame.time_utc -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
```

第一轮只回答：谁在说话、用什么协议、去了哪里、量级多大、有没有明显异常。

## 4. Beacon 分析

Beacon 的特征是**周期性 + 抖动 + 小请求/大响应或反之**。不要仅凭“每 60 秒一次”下结论；CDN、NTP、心跳、监控也会周期性。

### 4.1 从连接时间序列看

```bash
# 每个目的地的 TCP SYN 时间（IPv4）
tshark -r case-001.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && ip' \
  -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport \
  | awk '{key=$2":"$3; print key","$1}' | sort > syn.csv
```

用 Python/pandas 或 `scripts/secops.py` 之外的脚本计算间隔均值、标准差、抖动：

```text
jitter_pct = stdev(intervals) / mean(intervals) * 100
candidate if 5s < mean < 7200s and jitter_pct < 25 and connections >= 10
```

注意：睡眠/抖动可能让间隔看起来不规则；要结合多次会话、TLS 会话、目的 ASN、User-Agent、URI 等。

### 4.2 看流量形状

```bash
# 每个会话的包数/字节数（粗筛“小请求大响应”）
tshark -r case-001.pcap -q -z conv,tcp | sort -k5 -nr | head -30

# TLS SNI / JA3 / 证书（若可解密或握手可见）
tshark -r case-001.pcap -Y 'tls.handshake.extensions_server_name' \
  -T fields -e frame.time_utc -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# JA3 字段取决于 Wireshark 版本/插件；先用 `tshark -G fields | grep -i ja3`（Windows 用 findstr）确认。
tshark -r case-001.pcap -Y 'tls.handshake.type==1' \
  -T fields -e frame.time_utc -e ip.src -e ip.dst -e tls.handshake.ja3
```

JA3 会随客户端/版本变化，且可被伪造；把它当关联信号，不当铁证。字段不存在时用 Zeek `ssl.log` 的 `ja3`/`ja3s` 或 JA3 插件。

### 4.3 DNS 隧道

信号：

- 大量 TXT/NULL/AAAA 查询；子域很长、熵高、编码特征。
- 同一基域大量随机标签；查询/响应大小异常。
- 固定间隔的 DNS 请求；非常规 DNS 服务器。

```bash
# 查询名长度 Top
tshark -r case-001.pcap -Y dns.flags.response==0 \
  -T fields -e dns.qry.name \
  | awk '{print length($0), $0}' | sort -nr | head -50

# 高频基域（取最后两段，粗略）
tshark -r case-001.pcap -Y dns.flags.response==0 -T fields -e dns.qry.name \
  | awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -nr | head -30
```

高熵不一定是隧道（CDN、反病毒、遥测也会）；要看基域归属、客户端数量、数据方向。

## 5. 横向移动与认证

### 5.1 常见协议/端口

| 协议 | 端口 | 观察点 |
|---|---|---|
| SMB | 445 | 文件写入、服务创建、命名管道 |
| RDP | 3389 | 登录失败/成功、来源 |
| WinRM | 5985/5986 | 远程命令 |
| WMI/DCOM | 135/动态 | 远程执行 |
| Kerberos | 88 | TGT/TGS 异常、Kerberoasting |
| LDAP | 389/636 | 枚举、修改 |
| SSH | 22 | 登录、隧道 |
| 数据库 | 1433/3306/5432 | 异常查询/外联 |

```bash
# 内网 SMB 会话（示例）
tshark -r case-001.pcap -Y 'tcp.port==445 && smb2.cmd==1' \
  -T fields -e frame.time_utc -e ip.src -e ip.dst -e smb2.filename | head -50
```

加密流量看不到内容时，用 NetFlow/Zeek `conn.log`、EDR 进程树、认证日志补全。不要仅凭端口判断恶意。

### 5.2 扫描/爆破

- 大量 SYN 到不同端口、短连接、RST 比例高。
- 同一源对多主机 445/3389/22 的失败认证。
- 结合防火墙/EDR 告警，避免把漏洞扫描器当攻击。

## 6. 数据外传

信号：

- 内网主机向外部存储/ paste/匿名网盘的上传流量。
- 出站远大于入站；非工作时段；新目的 ASN/国家。
- DNS/ICMP/HTTPS 隧道；长连接；固定大小分块。
- 压缩/加密文件创建后立刻外传（需主机侧证据）。

```bash
# 出站 Top talkers（按字节）
tshark -r case-001.pcap -q -z endpoints,ip | head -40
```

外传结论必须谨慎：备份、云同步、视频会议也会产生大流量。结合文件访问、DLP、代理日志、目的信誉。

## 7. 证据与时间线

每个结论记录：

- PCAP 文件名 + SHA-256；捕获点/接口；时间范围（UTC）。
- 包号/流 ID/五元组；关键字段值。
- 主机资产归属（EDR/CMDB/DHCP/DNS）。
- 结论：`observed/suspected/confirmed`；反证是什么。
- 提取对象：`tshark --export-objects http,export/`，记录对象哈希。

```bash
# 导出 HTTP 对象（只在授权/隔离环境）
mkdir -p export
tshark -r case-001.pcap --export-objects http,export -q
sha256sum export/* > export.sha256
```

不要打开未知附件；按恶意样本流程处理（05）。

## 8. 工具

- **Wireshark/tshark**：逐包/字段/统计；首选证据工具。
- **Zeek**：conn/dns/http/tls/notice 日志；适合大流量和关联。
- **Suricata**：IDS 告警 + flow；规则验证。
- **RITA**：beacon/DNS 隧道分析（导入 Zeek 日志）。
- **Sniffnet**：快速可视化流量、按应用/国家筛选；适合初筛，不替代 PCAP 证据。
- **Arkime**：大规模 PCAP 检索（如已部署）。

## 9. 常见坑

- 抓到的是镜像/封装流量（VXLAN/GRE），内层五元组没解析。
- 大量丢包/截断（snaplen 太小），结论不完整。
- NAT/代理导致源 IP 不是主机真实 IP。
- 时钟不同步，跨设备时间线错位；记录时钟源。
- TLS 1.3 加密隐藏证书/SNI（ECH 可能进一步隐藏）；不要假装能看到。
- 把 CDN/云健康检查当 C2；看目的归属、客户端数量、行为。
- 只给 IP 不给端口/协议/时间，无法复现。
- 在生产上跑重型解析/导出，影响性能。

## 10. 交付模板

```markdown
## 流量结论
- 时间范围：2026-10-21T08:00:00Z ~ 09:00:00Z
- 捕获点：核心交换机 SPAN；接口 Gi1/0/24；snaplen 0
- PCAP：case-001.pcap；SHA-256：...
- 关键主机：10.0.0.5（WORKSTATION-07，EDR 确认）

## 发现
| ID | 时间(UTC) | 主机 | 目的地 | 协议/端口 | 观察 | 状态 | 证据 |
|---|---|---|---|---|---|---|---|
| NET-001 | 08:14:03 | 10.0.0.5 | 198.51.100.20 | TLS/443 | 每 60s±3s 小请求，持续 42min | suspected | frame 1832, 2104 |
...

## 判断
- 支持：周期、抖动、非业务目的 ASN、无对应代理记录。
- 反证：该主机有备份代理，目的 IP 属于备份服务？→ 已排除/未排除。
- 结论：suspected C2；建议隔离主机、提取内存、检查计划任务。

## 检测建议
- 字段：dst_ip, dst_port, ja3, interval, bytes_out
- 误报边界：备份/监控/心跳白名单；按资产角色调阈值
```

## 11. 设计依据

- **Sniffnet**：流量可视化、按应用/国家/协议筛选；本手册把它定位为初筛，不替代证据。
- **Wireshark/Zeek/Suricata**：字段级证据和可部署检测；本手册要求包号/流 ID/UTC。
- **RITA**：beacon/DNS 隧道思路；本手册给出可解释的间隔/抖动判据，而不是“黑盒分数”。

## 12. 参考

- Wireshark User Guide: <https://www.wireshark.org/docs/wsug_html_chunked/>
- tshark man page: <https://www.wireshark.org/docs/man-pages/tshark.html>
- Zeek docs: <https://docs.zeek.org/>
- Suricata docs: <https://docs.suricata.io/>
- RITA: <https://github.com/activecm/rita>
- Sniffnet: <https://github.com/GyulyVGC/sniffnet>
- MITRE ATT&CK Network Traffic: <https://attack.mitre.org/>
