# Claude Env Doctor

专注 Claude Code 的只读环境检测。一个 Python 文件，直接运行，无 Python 第三方依赖。

帮助发现本地配置冲突、代理路径偏差、证书错误和网络故障。每项结果给出证据和边界，不提供“防封分”或账号安全承诺。

## 使用

需要 **Python 3.10+**。联网检测还需要 **curl 7.70+**（macOS 自带的当前版本通常满足）。

```bash
git clone https://github.com/baohao2015/claude-env-doctor.git
python3 claude-env-doctor/claude_env.py
```

在平时启动 Claude 的终端、工程目录中运行。脚本可以放在任意目录：

```bash
python3 /path/to/claude-env-doctor/claude_env.py
```

默认读取当前工程配置，并发送少量**无账号认证**的网络诊断请求，不调用模型、不消耗模型 token。也可以：

```bash
# 只检查本地配置，完全不联网
python3 claude_env.py --offline

# 指定平时使用 Claude 的工程
python3 claude_env.py --project /path/to/your-project

# JSON 输出，供脚本或工作台读取
python3 claude_env.py --json

# 额外生成一个本地 HTML 报告；文件名必须尚不存在
python3 claude_env.py --html report.html
```

HTML 是没有脚本、外链、遥测的静态文件，打开后不会再次联网。无需启动服务、注册账号或安装浏览器插件。

Windows 使用 `python` 替代 `python3`。本地系统代理、DNS、隧道接口采集优先覆盖 macOS；Linux 有限支持，Windows 相关项显示未知。配置分析、报告和 curl 连接探针可以跨平台运行。

## 检查范围

| 检查 | 观察内容 | 如何解释 |
| --- | --- | --- |
| Claude 安装 | PATH 是否包含 `claude`；可读取时显示安装元数据版本 | 不启动 Claude，不执行 wrapper；不判断是不是最新版 |
| 配置文件 | 用户、工程、工程本地、本机 managed-settings.json 中的相关 `env` | 配置无法读取或格式无效会报问题，不输出文件内容 |
| 配置冲突 | 当前终端与文件中同一变量的不同值 | 不猜测实际会话的配置优先级，相关连接探针会跳过 |
| HTTP 代理 | 官方支持的代理变量、协议、优先顺序、NO_PROXY | 代理开启不判错；无效代理不会悄悄回退直连 |
| 系统网络 | macOS 系统代理/PAC、DNS 配置、常见隧道接口线索 | 系统代理不等于 CLI 继承；接口存在不等于接管流量 |
| TLS | 关闭校验的配置、CA 文件可读性与格式、HTTPS 校验结果 | 探针始终验证证书，不执行不安全的自动修复 |
| mTLS | 客户端证书和私钥路径是否可读 | 不读取私钥，不向服务器发送客户端证书；不验证认证结果 |
| 网络出口 | Cloudflare 与 Claude CDN trace（可用时）的 IP / 地区 | 只反映边缘服务观察，不等于 Anthropic 后端视角 |
| IPv6 | 系统路由模式下观察 IPv6 出口，比较地区差异 | 不可达显示未知；IPv6 可用本身不判为泄漏 |
| 端点连接 | Claude 网页、候选 API 的 DNS/TCP/TLS/HTTP 结果 | 401、403、407、429、服务端错误分别报告 |
| 时区 | 当前进程时区及相关配置是否存在 | 不把地区/语言/时区差异直接等同于账号风险 |

## 结果

- **问题**：观察到明确故障或不安全配置，例如代理 URL 无效、证书校验失败、关闭 TLS 校验。
- **注意**：需要核实，例如配置不同、HTTP 403、NO_PROXY 绕行、出口不同。
- **未知**：证据不足、检查未完成、能力未覆盖；不算通过。
- **通过**：仅这一项完成，例如收到 HTTP 成功响应，不代表账号或模型可用。
- **信息**：已观察到的配置和事实，例如无认证请求收到 HTTP 401。

退出码：`0` 表示没有明确的问题项，**不代表检查全部通过**；`1` 表示存在问题项；`2` 表示命令参数或报告输出错误；`130` 表示用户中断。

## 配置和探测边界

1. **这是外部诊断器。** 不读取正在运行的 Claude 进程环境，不启动 Claude、不执行 shell 配置、hooks、Node preload 或其他插件。应在平时启动 Claude 的同一个终端运行，并在 Claude 的 `/status` 确认实际配置。
2. **配置只做候选值采集。** 支持 `CLAUDE_CONFIG_DIR`；默认从最近的 Git 根目录（无 Git 则当前目录）读取 `.claude/settings.json` 和 `.claude/settings.local.json`。不模拟工程信任、命令行 `--settings`、受管理策略或 Desktop/后台 supervisor 的启动行为。同一变量值不同就报冲突，代价是可能跳过本来能连接的环境。
3. **代理遵循当前官方文档。** 优先顺序为 `https_proxy`、`HTTPS_PROXY`、`http_proxy`、`HTTP_PROXY`；不把 SOCKS 或仅设置 ALL_PROXY 当成受支持的 Claude Code 代理。NO_PROXY 支持主机名、域名后缀、IP/CIDR、逗号或空格分隔以及 `*`；复杂通配符、带端口和大小写值冲突会跳过网络探测。具体运行时的实现可能不同。
4. **探针使用 curl，未复刻 Claude 网络栈。** 不读取 `.curlrc`/`.netrc`，不跟随重定向，不继承 curl 自己的代理和证书变量。代理凭据通过标准输入交给 curl，不进入参数列表或报告。TLS 总是校验；配置 `NODE_EXTRA_CA_CERTS` 时会使用该 CA 文件，但 curl 与 Claude 的信任库合并方式可能不同。
5. **显式代理模式不另开直连 IPv6 探针。** 避免为了检测而制造额外直连路径。NO_PROXY 的有意绕行会单独报告；无显式代理时，系统路由可能已经由 TUN/VPN 接管。
6. **自定义 API 也只探测连通性。** 使用候选 `ANTHROPIC_BASE_URL` 的 `/v1/models`（已经以 `/v1` 结尾则追加 `/models`），发送无认证 HEAD 请求。远程明文 HTTP、带 query/fragment/内嵌凭据的 API URL 不会被探测。启用 Bedrock/Vertex/Foundry 模式时跳过 API 探测，不误测官方 API。自定义服务可能不支持这个路径或 HEAD，4xx 不能直接说明 Claude 的真实请求失败。
7. **不做账号风控预测。** 不检查付款身份、设备标识、浏览器指纹，不扫描账号历史、Cookie、钥匙串或聊天内容；DNS 配置不等于实际 DNS 出口，WebRTC 未覆盖。遵循平台实际支持范围和服务规则；本地报告无法替代服务端判断。

## 联网与隐私

默认最多约 5 个探针，并发最多 4 个，每个默认超时 8 秒，可用 `--timeout 5` 调整。

| 目的地 | 请求 | 用途 |
| --- | --- | --- |
| `https://www.cloudflare.com/cdn-cgi/trace` | GET，必要时另做 IPv6 GET | 当前探针出口 |
| `https://claude.ai/` | HEAD | 网页路径连通性 |
| `https://claude.ai/cdn-cgi/trace` | GET | Claude CDN 边缘出口（服务可能不开放） |
| 官方或配置的 API Base URL | HEAD `/v1/models` | API 路径连通性 |

这些服务及你的代理会看到探针的出口 IP 和正常 HTTP/TLS 请求元数据。需要代理认证时，只有所选代理会收到该代理的凭据；**不发送 Claude API Key、OAuth token、Cookie、聊天、代码或设备 ID**。没有项目自建后端或遥测。

默认不写状态文件，不记录出口历史，不改系统/代理/时区/配置。仅显式使用 `--html` 时创建报告；重定向 stdout 保存 JSON 由调用者决定。报告包含出口 IP、DNS 地址、服务主机名等网络信息，分享前请检查。

## 开发与验证

```bash
python3 -m unittest discover -s tests -v
```

测试使用临时目录和本机回环 HTTP/代理/TLS 服务，不连接真实 Claude，不使用真实账号。覆盖配置冲突、未知结果、代理失败不直连、凭据隔离、HTML 转义、HTTP 认证/限制/重定向、自签名 TLS 拒绝等行为。自签名 TLS 测试用本机 openssl 临时生成测试密钥；缺少 openssl 时仅跳过该测试。

初版在 macOS / Python 3.13 上完成本地测试；Linux、Windows 与其他 Python 版本尚未实机验证。未启用 GitHub Actions。测试通过不能证明真实网络或实际 Claude 会话通过。

## 依据与来源

规则核对日期：2026-11-13。平台文档可能变化，规则需要持续核实。

- [Claude Code 官方网络配置](https://code.claude.com/docs/en/network-config)
- [Claude Code 官方配置文件与作用范围](https://code.claude.com/docs/en/settings)
- [curl 官方文档](https://curl.se/docs/manpage.html)

需求调研参考了 [claude-switcher](https://github.com/YOURSJEYO/claude-switcher)、[ipcheck](https://github.com/stormzhang/ipcheck)、[claude-sonar](https://github.com/AschoofAlpha/claude-sonar) 的思路。本项目独立实现，未复制这些项目的源码；不依赖其账号管理或后台服务。

MIT License。
