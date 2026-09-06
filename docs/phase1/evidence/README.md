\# 第一阶段环境与基线证据索引



\## 基本信息



\- 项目目录：`D:\\homework\\NetProject\\tju\_tcp`

\- 基线版本：见 `baseline\_commit.txt`

\- 基线标签：`baseline`

\- 虚拟机：VirtualBox

\- client：`172.17.0.2`，SSH 转发端口 `2222`

\- server：`172.17.0.3`，SSH 转发端口 `2200`

\- 共享目录：`/vagrant/tju\_tcp`



\## 截图证据



| 证据 | 执行命令或操作 | 环境 | 观察结果 | 结论 | 对应清单 |

|---|---|---|---|---|---|

| `screenshots/01\_vagrant\_status.png` | `vagrant status` | Windows PowerShell | client、server 均为 `running (virtualbox)` | 两台课程虚拟机正常运行 | 3.2 |

| `screenshots/02\_ssh\_ports.png` | `vagrant port --guest 22 client/server` | Windows PowerShell | client 为 2222，server 为 2200 | SSH 端口映射正确 | 3.2 |

| `screenshots/03\_client\_server\_ip\_and\_mount.png` | 查询 `enp0s8` 地址和 `findmnt` | 两台 Ubuntu 虚拟机 | IP 为 `172.17.0.2/3`，共享目录类型为 `vboxsf` | 地址和共享目录正常 | 3.2 |

| `screenshots/04\_host\_and\_vagrant\_versions.png` | 系统、VirtualBox、Vagrant 和 box 版本查询 | Windows PowerShell | Windows 报告版本 25H2、构建 26200；VirtualBox 7.2.16；Vagrant 2.4.9；box 为 `ubuntu/netproj` | 宿主机及虚拟化环境版本已记录 | 3.1 |

| `screenshots/05\_guest\_tool\_versions.png` | 查询 Ubuntu、GCC、make、tcset、tcpdump 版本 | client、server | Ubuntu 20.04.2 LTS、GCC 9.4.0、Make 4.2.1、tcset 0.26.0、tcpdump 4.9.3 | 两端开发及测试工具可用 | 3.1、3.3 |

| `screenshots/05\_ai\_vagrant\_port\_correction.png` | 对比错误及正确的 `vagrant port` 命令 | Windows PowerShell | 错误命令把 `ssh` 解释为虚拟机名；改用 `--guest 22` 后成功 | AI 命令建议经过人工运行验证并修正 | 6.3、附录 A |

| `screenshots/06\_network\_configuration\_not\_applied.png` | `tcshow` 和双向 ping | client、server | tcshow 为空，RTT 小于约 1 ms | 初次启动后网络整形未生效 | 3.5 |

| `screenshots/07\_network\_configuration\_after\_provision.png` | `vagrant provision` 后重新执行 `tcshow` | client、server | 两端 outgoing 均为 20 ms、100 Mbps | 重新 provision 后网络整形恢复 | 3.2、3.5 |

| `screenshots/08\_bidirectional\_ping\_after\_provision.png` | 双向 `ping` | client、server | 双向约 42 ms RTT，0% packet loss | 两端各设置约 20 ms 延迟，默认无主动丢包 | 3.2 |

| `screenshots/09\_client\_server\_runningbaseline.png` | 编译并运行 `server`、`client` | client、server | 双方均收到 `hello world` 和 `hello tju` | 未修改基线可正常双向通信 | 3.2 |

| `screenshots/10\_baseline\_udp\_packet\_summary.png` | `tcpdump -nn -tttt -r` | server | 共 4 个 UDP 报文，端口为 20218，长度为 32、30 字节 | TJU\_TCP 基线由 UDP 承载且实现双向数据发送 | 3.3、4.4 |



\## 抓包证据



\- 文件：`pcap/baseline\_udp.pcap`

\- 抓包接口：`enp0s8`

\- 过滤条件：`udp port 20218`

\- 抓包结果：4 个报文，0 个内核丢包

\- SHA-256：`0B91C2B5AC2787D14F706F35C29BAD75A10C5A664EC76A0A1C91BFEEE134B480`

\- 报文方向：`172.17.0.2:20218` 与 `172.17.0.3:20218` 双向通信

\- 报文长度：32 和 30 字节

\- 人工核验：固定头部为 20 字节，因此 payload 分别为 12 和 10 字节，与 `hello world`、`hello tju` 的发送长度一致。



\## 已知问题



1\. 虚拟机首次运行时网络整形没有生效，重新执行 `vagrant provision client` 和 `vagrant provision server` 后恢复。

2\. tcpdump 不能直接在 `vboxsf` 共享目录中修改文件所有者，因此先写入 server 的 `/tmp`，再复制到共享目录。

3\. 新旧课程材料中的 IP 地址和可靠传输数据量存在差异；本项目 IP 以实际环境的 `172.17.0.2/3` 为准，数据量要求等待教师确认。

