#!/usr/bin/env python3
"""Read-only Claude Code environment diagnostics. Python 3.10+, curl, no packages."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import html
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

VERSION = "0.1.0"
PROXY_KEYS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")
NETWORK_KEYS = PROXY_KEYS + (
    "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY", "ANTHROPIC_BASE_URL", "TZ",
    "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS",
    "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_CLIENT_KEY", "SSL_CERT_FILE",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
)
SECRET_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
LIMITS = [
    "检查当前终端和指定工程的候选配置，不能读取正在运行的 Claude 的实际配置。",
    "未覆盖启动参数、shell 函数/别名、远端托管策略、MDM、Desktop/Cowork/后台 agent 的环境。请在 Claude /status 中确认实际配置。",
    "网络探针使用 curl，TLS/代理实现可能与 Claude 不同；没有发送账号、API Key、Cookie 或模型请求。",
    "DNS 配置与网卡存在不等于 DNS 泄漏或代理已经生效；未检测浏览器 WebRTC。",
    "结果不能预测 Anthropic 风控、实际所在地判定或账号安全。",
]


def clean(value):
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value))[:500]


def add(checks, key, status, title, evidence, action=""):
    checks.append(dict(id=key, status=status, title=title,
                       evidence=clean(evidence), action=clean(action)))


def run(command, *, timeout=4, env=None, data=None):
    try:
        return subprocess.run(command, input=data, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def parse_url(value, *, proxy=False):
    if not isinstance(value, str) or re.search(r"[\x00-\x20\x7f]", value):
        raise ValueError("URL 格式无效")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("URL 端口或主机格式无效") from None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("需要包含 http:// 或 https:// 的 URL；Claude Code 不支持 SOCKS")
    if parsed.query or parsed.fragment or (proxy and parsed.path not in ("", "/")):
        raise ValueError("不接受 query、fragment 或代理路径")
    if not proxy and (parsed.username is not None or parsed.password is not None):
        raise ValueError("API Base URL 不接受内嵌凭据")
    if port is not None and port == 0:
        raise ValueError("端口必须大于 0")
    return parsed


def public_url(value):
    """Only an origin: credentials, path, query and fragment never enter reports."""
    try:
        parsed = parse_url(value, proxy=False)
    except ValueError:
        try:
            parsed = parse_url(value, proxy=True)
        except ValueError:
            return "[无效 URL，原值隐藏]"
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return clean(f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port else ""))


def project_root(path):
    path = path.resolve()
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return path


def managed_path(env):
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    if os.name == "nt":
        return Path(env.get("ProgramFiles", r"C:\Program Files")) / "ClaudeCode/managed-settings.json"
    return Path("/etc/claude-code/managed-settings.json")


def read_config(project, env, home, checks, policy=None):
    """Collect candidates, without executing settings/hooks or guessing conflicts."""
    candidates = {key: [("当前终端", env[key])] for key in NETWORK_KEYS if key in env}
    config_dir = Path(env.get("CLAUDE_CONFIG_DIR") or home / ".claude").expanduser()
    paths = [("用户 settings.json", config_dir / "settings.json"),
             ("工程 settings.json", project / ".claude/settings.json"),
             ("工程 settings.local.json", project / ".claude/settings.local.json"),
             ("本机 managed-settings.json", policy or managed_path(env))]
    seen = set()
    for label, path in paths:
        if path in seen:
            continue
        seen.add(path)
        try:
            if not path.exists():
                continue
            if path.stat().st_size > 1024 * 1024:
                raise ValueError("文件超过 1 MiB")
            document = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(document, dict) or not isinstance(document.get("env", {}), dict):
                raise ValueError("需要 JSON 对象和 env 对象")
            selected = {}
            for key, value in document.get("env", {}).items():
                if key in NETWORK_KEYS:
                    if not isinstance(value, str):
                        raise ValueError("env 中的值需要是字符串")
                    selected[key] = value
            for key, value in selected.items():
                candidates.setdefault(key, []).append((label, value))
            add(checks, f"config.{label}", "pass", label, "JSON 与 env 字段可解析；未执行 hooks 或其他配置")
        except (OSError, ValueError):
            add(checks, f"config.{label}", "fail", label, "无法读取或格式无效；没有显示文件内容",
                "在 Claude /status、claude doctor 中确认配置错误；修正后重测。")
    resolved = {}
    conflicts = set()
    for key, values in candidates.items():
        distinct = {value for _, value in values}
        if len(distinct) == 1:
            resolved[key] = values[0][1]
        else:
            conflicts.add(key)
            if key not in SECRET_KEYS:
                add(checks, f"conflict.{key}", "warn", f"{key} 存在不同配置",
                    "来源：" + "、".join(source for source, _ in values),
                    "工具不猜测当前会话采用哪个值；在 Claude /status 确认，并让检测终端使用相同环境。")
    return resolved, conflicts, candidates


def no_proxy_matches(host, value):
    for entry in re.split(r"[\s,]+", value or ""):
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry == "*":
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
        entry = entry.strip("[]").lstrip(".")
        if host.lower() == entry or host.lower().endswith("." + entry):
            return True
    return False


def choose_proxy(env, conflicts, checks):
    if conflicts.intersection(PROXY_KEYS + ("no_proxy", "NO_PROXY", "all_proxy", "ALL_PROXY")):
        add(checks, "proxy", "unknown", "CLI 代理路径", "存在代理候选配置冲突；跳过网络探测以避免意外直连")
        return None, False
    if "no_proxy" in env and "NO_PROXY" in env and env["no_proxy"] != env["NO_PROXY"]:
        add(checks, "proxy", "unknown", "NO_PROXY 大小写配置不同", "绕行规则存在歧义；跳过网络探测")
        return None, False
    for entry in re.split(r"[\s,]+", env.get("no_proxy", env.get("NO_PROXY", ""))):
        if not entry or entry == "*":
            continue
        try:
            ipaddress.ip_network(entry.strip("[]"), strict=False)
        except ValueError:
            if not re.fullmatch(r"\.?[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", entry):
                add(checks, "proxy", "unknown", "NO_PROXY 含未覆盖的语法", "未执行网络探测，避免错误绕行",
                    "本版本支持主机名、域名后缀、IP/CIDR 和 *，不猜测端口及其他通配符语法。")
                return None, False
    configured = [(key, env[key]) for key in PROXY_KEYS if key in env]
    if configured and not configured[0][1] and any(value for _, value in configured):
        add(checks, "proxy", "unknown", "高优先级代理变量为空", "不同运行时对空值处理可能不同；跳过网络探测")
        return None, False
    proxies = [(key, value) for key, value in configured if value]
    if not proxies:
        if env.get("ALL_PROXY") or env.get("all_proxy"):
            add(checks, "proxy", "warn", "仅配置 ALL_PROXY", "官方文档未将 ALL_PROXY 列为 Claude Code 代理入口；跳过探测",
                "确认 Claude /status 中的代理，并使用官方支持的 HTTP_PROXY/HTTPS_PROXY。")
            return None, False
        add(checks, "proxy", "info", "CLI 代理入口", "未设置 HTTP(S) 代理；探针使用系统路由，可能经 TUN/VPN")
        return "", True
    key, proxy = proxies[0]
    try:
        parse_url(proxy, proxy=True)
    except ValueError as error:
        add(checks, "proxy", "fail", "CLI 代理入口无效", error,
            "确认端口、协议和服务状态；不会自动回退直连。")
        return None, False
    add(checks, "proxy", "info", "CLI 代理入口", f"{key} → {public_url(proxy)}；凭据隐藏")
    if len({value for _, value in proxies}) > 1:
        add(checks, "proxy.priority", "warn", "多个代理变量值不同",
            f"按官方顺序选择 {key}（小写 https_proxy 优先）", "清理不再使用的配置，避免不同工具采用不同入口。")
    return proxy, True


def inspect_host(env, checks):
    binary = shutil.which("claude")
    if binary:
        # Read metadata only: even --version could execute an arbitrary user wrapper.
        version = ""
        try:
            resolved = Path(binary).resolve()
            if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", resolved.name):
                version = resolved.name
            else:
                manifest = resolved.parent / "package.json"
                if manifest.is_file() and manifest.stat().st_size < 1024 * 1024:
                    package = json.loads(manifest.read_text(encoding="utf-8"))
                    if isinstance(package, dict) and package.get("name") == "@anthropic-ai/claude-code":
                        value = package.get("version", "")
                        if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", value):
                            version = value
        except (OSError, ValueError, RuntimeError):
            pass
        add(checks, "claude", "pass", "Claude 命令", "PATH 中存在 claude；" +
            (f"安装元数据版本 {version}" if version else "版本未知（未执行程序或 wrapper）"),
            "安装元数据不证明程序身份或当前运行版本；可自行运行 claude --version。")
    else:
        add(checks, "claude", "warn", "Claude 命令", "PATH 中未找到 claude", "若仅使用 Desktop，此项不适用；CLI 用户检查安装和 PATH。")
    add(checks, "timezone", "info", "时区", "当前进程 " + datetime.now().astimezone().strftime("%Z %z")
        + ("；配置中设置了 TZ" if env.get("TZ") else "；配置未设置 TZ"),
        "时区不同本身不代表网络故障；按真实工作环境核对，不自动修改。")
    if env.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        add(checks, "tls.disabled", "fail", "Claude TLS 校验可能被关闭", "NODE_TLS_REJECT_UNAUTHORIZED=0",
            "恢复证书校验；企业证书通过可信 CA 配置处理，不用关闭校验解决连接问题。")
    if env.get("NODE_OPTIONS"):
        add(checks, "node.options", "warn", "Node 启动选项", "设置了 NODE_OPTIONS；未显示或执行其内容",
            "检查是否包含历史代理注入或 TLS 相关选项；原生 Claude 与 npm 安装的行为可能不同。")
    for key in ("NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_CLIENT_KEY", "SSL_CERT_FILE"):
        if env.get(key):
            try:
                path = Path(env[key]).expanduser()
                valid = path.is_file() and os.access(path, os.R_OK)
            except (OSError, ValueError):
                valid = False
            add(checks, f"file.{key}", "info" if valid else "fail", key,
                "设置了可读文件（路径隐藏，未读取私钥）" if valid else "配置的文件不存在或不可读（路径隐藏）")
    if env.get("CLAUDE_CODE_CLIENT_CERT") or env.get("CLAUDE_CODE_CLIENT_KEY"):
        add(checks, "mtls", "unknown", "客户端证书认证", "探针不读取或发送客户端证书/私钥，mTLS 连接结果不代表 Claude 的实际认证结果")
    if sys.platform == "darwin":
        result = run(["scutil", "--proxy"])
        if result and result.returncode == 0:
            enabled = re.findall(r"\b(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*:\s*1", result.stdout)
            add(checks, "system.proxy", "info", "macOS 系统代理", "开启：" + ", ".join(enabled) if enabled else "未发现开启的系统代理/PAC",
                "系统代理状态不代表 Claude CLI 自动继承；以 CLI 配置与实际连通性为准。")
        else:
            add(checks, "system.proxy", "unknown", "macOS 系统代理", "系统查询未完成")
        result = run(["scutil", "--dns"])
        dns = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", result.stdout) if result and result.returncode == 0 else []
        result = run(["ifconfig", "-l"])
        interfaces = result.stdout.split() if result and result.returncode == 0 else []
    elif sys.platform.startswith("linux"):
        try:
            dns = re.findall(r"^nameserver\s+(\S+)", Path("/etc/resolv.conf").read_text(), re.M)
            interfaces = [path.name for path in Path("/sys/class/net").iterdir()]
        except OSError:
            dns, interfaces = [], []
    else:
        dns, interfaces = [], []
    addresses = []
    for address in dict.fromkeys(dns):
        try:
            addresses.append(str(ipaddress.ip_address(address)))
        except ValueError:
            pass
    add(checks, "dns.config", "info" if addresses else "unknown", "本机 DNS 配置",
        ", ".join(addresses[:12]) if addresses else "未获取到；当前系统可能未覆盖",
        "仅展示配置，没有发起额外 DNS 泄漏测试；本地 DNS 地址不能证明解析请求的实际出口。")
    tunnels = [name for name in interfaces if re.fullmatch(r"(?:utun|tun|tap|wg|tailscale)[\w.-]*", name)]
    add(checks, "tunnel", "info" if tunnels else "unknown", "隧道接口线索",
        ", ".join(tunnels[:12]) if tunnels else "未观察到常见隧道接口名",
        "接口存在不能证明接管 Claude 流量；没有 TUN 也不意味着 HTTP 代理失效。")


def curl_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'


def probe(url, proxy, no_proxy, timeout, *, trace=False, ipv6=False, ca=None):
    """No curlrc/netrc, redirects, cookies, auth headers, shell or inherited proxies."""
    parsed = parse_url(url)
    route = "" if no_proxy_matches(parsed.hostname, no_proxy) else proxy
    options = ["silent", "show-error", "proto = \"=http,https\"", "max-filesize = 65536",
               "connect-timeout = " + str(timeout), "max-time = " + str(timeout),
               "url = " + curl_quote(url), "proxy = " + curl_quote(route), 'noproxy = ""',
               "write-out = " + curl_quote("\n%{json}")]
    if not trace:
        options.append("head")
    if ipv6:
        options.append("ipv6")
    if ca:
        options.append("cacert = " + curl_quote(ca))
    child_env = {key: os.environ[key] for key in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR") if key in os.environ}
    process = run([shutil.which("curl") or "curl", "-q", "--config", "-"],
                  timeout=timeout + 2, env=child_env, data="\n".join(options) + "\n")
    if process is None:
        return dict(code=-1, http=0, trace={}, route="proxy" if route else "system")
    body, _, trailer = process.stdout.rpartition("\n")
    try:
        metadata = json.loads(trailer)
        if not isinstance(metadata, dict):
            raise ValueError()
        http = int(metadata.get("http_code", 0))
    except (ValueError, TypeError):
        return dict(code=-2, http=0, trace={}, route="proxy" if route else "system")
    trace_values = {}
    if trace and process.returncode == 0 and http == 200:
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        try:
            trace_values["ip"] = str(ipaddress.ip_address(fields.get("ip", "")))
            country = fields.get("loc", "")
            if re.fullmatch(r"[A-Z]{2}", country):
                trace_values["country"] = country
        except ValueError:
            trace_values = {}
    return dict(code=process.returncode, http=http, trace=trace_values,
                route="proxy" if route else "system")


def classify(result):
    code, status = result["code"], result["http"]
    if code:
        names = {5: "代理 DNS 解析失败", 6: "目标 DNS 解析失败", 7: "TCP 连接失败",
                 28: "连接或响应超时", 35: "TLS 握手失败", 60: "TLS 证书校验失败",
                 77: "CA 文件无法加载", 97: "代理握手失败", -1: "探针无法启动或超时",
                 -2: "探针结果无法解析；需要支持 %{json} 的 curl 7.70+"}
        return "fail", names.get(code, f"传输未完成（curl {code}）")
    if status == 401:
        return "info", "HTTP 401：服务要求认证；本工具未发送任何账号凭据"
    if status == 403:
        return "warn", "HTTP 403：请求受限；无法据此确定是地区、WAF、策略还是其他原因"
    if status == 407:
        return "fail", "HTTP 407：代理要求认证或拒绝了代理凭据"
    if status == 429:
        return "warn", "HTTP 429：请求被限流；不要连续重试"
    if 200 <= status < 300:
        return "pass", f"HTTP {status}：传输成功；不代表账号或模型调用可用"
    if 300 <= status < 400:
        return "warn", f"HTTP {status}：发生重定向；为保持探测边界，未跟随"
    if status >= 500:
        return "warn", f"HTTP {status}：服务端或中间网关错误"
    return "unknown", f"HTTP {status}：无法确认服务状态"


def inspect_network(env, conflicts, proxy, route_known, timeout, checks):
    if not shutil.which("curl"):
        add(checks, "network", "unknown", "网络探测", "未找到 curl；只完成本地检查")
        return
    if not route_known:
        return
    critical = {"ANTHROPIC_BASE_URL", "NODE_EXTRA_CA_CERTS", "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_CLIENT_KEY",
                "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"}
    if critical.intersection(conflicts) or any(c["id"].startswith("config.") and c["status"] == "fail" for c in checks):
        add(checks, "network", "unknown", "网络探测", "配置不完整或候选值冲突；跳过探测，避免误选目标或路径")
        return
    base = env.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com"
    try:
        target = parse_url(base)
    except ValueError as error:
        add(checks, "endpoint", "fail", "API Base URL", error, "修正端点配置后重测；不会自动回退官方端点。")
        return
    if target.scheme == "http":
        loopback = target.hostname == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(target.hostname).is_loopback
        except ValueError:
            pass
        add(checks, "endpoint.http", "info" if loopback else "fail", "API 使用 HTTP",
            "本地回环端点，未加密" if loopback else "非回环 HTTP 端点，传输未加密",
            "真实 Claude 请求可能携带凭据和代码；远程端点应使用 HTTPS。")
        if not loopback:
            return
    add(checks, "endpoint", "info", "候选 API 端点", public_url(base),
        "官方或自定义端点都只做无认证的连接探测；不评价服务商可信度。")
    no_proxy = env.get("no_proxy", env.get("NO_PROXY", ""))
    if no_proxy_matches(target.hostname, no_proxy) and proxy:
        add(checks, "proxy.bypass", "warn", "API 命中 NO_PROXY", "API 探针将绕过显式代理，使用系统路由",
            "确认这是有意配置；系统路由仍可能通过 TUN。")
    ca = env.get("NODE_EXTRA_CA_CERTS")
    if ca:
        try:
            ca = str(Path(ca).expanduser())
            ssl.create_default_context().load_verify_locations(cafile=ca)
        except (OSError, ValueError, ssl.SSLError):
            add(checks, "tls.ca", "fail", "额外 CA", "无法解析配置的 CA 文件；跳过探测")
            return
        add(checks, "tls.ca", "info", "额外 CA", "探针使用配置的 CA 文件；curl 与 Claude 的信任库合并方式可能不同")
    api = base.rstrip("/") + ("/models" if target.path.rstrip("/").endswith("/v1") else "/v1/models")
    jobs = [("egress", "网络出口", "https://www.cloudflare.com/cdn-cgi/trace", True, False),
            ("web", "Claude 网页连接", "https://claude.ai/", False, False),
            ("claude_trace", "Claude 边缘出口", "https://claude.ai/cdn-cgi/trace", True, False)]
    provider = any(env.get(key, "").lower() in ("1", "true") for key in
                   ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"))
    if provider:
        add(checks, "api", "unknown", "API 连接", "配置了云提供商模式；本版本不模拟云提供商认证和目标选择")
    else:
        jobs.append(("api", "API 连接", api, False, False))
    if not proxy:
        jobs.append(("ipv6", "IPv6 出口", "https://www.cloudflare.com/cdn-cgi/trace", True, True))
    else:
        add(checks, "ipv6", "unknown", "IPv6 出口", "显式 HTTP 代理模式下不另开直连 IPv6 探针，以免改变网络路径")
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [(job, executor.submit(probe, job[2], proxy, no_proxy, timeout,
                                        trace=job[3], ipv6=job[4], ca=ca)) for job in jobs]
        results = {}
        for (key, title, _, is_trace, _), future in futures:
            result = future.result()
            results[key] = result
            status, message = classify(result)
            if key == "ipv6" and (result["code"] or not result["trace"]):
                status, message = "unknown", "IPv6 探测未完成；不能据此确认已关闭或没有泄漏"
            elif is_trace and result["code"] == 0 and result["http"] == 200 and not result["trace"]:
                status, message = "unknown", "收到响应但不是有效 trace；出口未确认"
            if result["trace"]:
                message += "；出口 " + result["trace"]["ip"] + " / " + result["trace"].get("country", "未知地区")
            action = "仅代表此探针；trace 是 CDN 边缘观测，不等于 Anthropic 后端视角。" if is_trace else "按错误层排查代理、DNS、证书或目标服务；不要用关闭 TLS 校验解决问题。"
            add(checks, key, status, title, message, action)
    first = results.get("egress", {}).get("trace", {})
    second = results.get("claude_trace", {}).get("trace", {})
    if first and second:
        same = first["ip"] == second["ip"]
        add(checks, "egress.consistency", "info" if same else "warn", "跨目标出口对照",
            "两处出口 IP 相同" if same else "两处出口 IP 不同；可能是分流、双栈或负载均衡",
            "不同不自动等于泄漏；核对代理规则和预期线路。")
    ipv6_trace = results.get("ipv6", {}).get("trace", {})
    if first.get("country") and ipv6_trace.get("country") and first["country"] != ipv6_trace["country"]:
        add(checks, "ipv6.consistency", "warn", "IPv4/默认路径与 IPv6 地区不同",
            f"默认路径 {first['country']}；IPv6 {ipv6_trace['country']}",
            "核对双栈路由是否符合预期；IP 地理库也可能不准确。")


def audit(project, *, offline=False, timeout=8, env=None, home=None, policy=None):
    source_env = dict(os.environ if env is None else env)
    home = Path.home() if home is None else Path(home)
    checks = []
    config, conflicts, candidates = read_config(project, source_env, home, checks, policy)
    inspect_host(config, checks)
    proxy, known = choose_proxy(config, conflicts, checks)
    for key in SECRET_KEYS:
        if key in candidates:
            add(checks, f"auth.{key}", "info", key, "已设置；值未显示，也不会被发送")
    if offline:
        add(checks, "network", "unknown", "网络探测", "--offline：未发送网络请求")
    else:
        inspect_network(config, conflicts, proxy, known, timeout, checks)
    counts = {status: sum(c["status"] == status for c in checks)
              for status in ("pass", "fail", "warn", "unknown", "info")}
    return dict(schema_version=1, version=VERSION, generated_at=datetime.now().astimezone().isoformat(timespec="seconds"),
                platform=platform.system(), offline=offline, checks=checks, summary=counts, limitations=LIMITS)


LABELS = dict(pass_="通过", fail="问题", warn="注意", unknown="未知", info="信息")
LABELS["pass"] = LABELS.pop("pass_")


def render_text(report):
    lines = [f"Claude Env Doctor {report['version']} · 只读环境检测", ""]
    for check in report["checks"]:
        lines.append(f"[{LABELS[check['status']]}] {check['title']}：{check['evidence']}")
        if check["action"] and check["status"] in ("fail", "warn"):
            lines.append("       " + check["action"])
    lines += ["", " · ".join(f"{LABELS[key]} {value}" for key, value in report["summary"].items()),
              "结果只适用于列出的检查；没有账号安全评分。", "", "检测边界："]
    lines += ["- " + line for line in report["limitations"]]
    return "\n".join(lines)


def render_html(report):
    esc = html.escape
    rows = "".join(f"<tr><td class='{c['status']}'>{LABELS[c['status']]}</td><th scope='row'>{esc(c['title'])}</th>"
                   f"<td>{esc(c['evidence'])}<small>{esc(c['action'])}</small></td></tr>" for c in report["checks"])
    limits = "".join(f"<li>{esc(line)}</li>" for line in report["limitations"])
    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Claude Env Doctor · 检测报告</title>
<style>body{{max-width:960px;margin:48px auto;padding:0 24px;font:15px/1.7 system-ui,sans-serif;color:#252923;background:#fafaf7}}
h1{{font-size:26px;margin-bottom:4px}}p,small{{color:#62675e}}table{{width:100%;border-collapse:collapse;margin:28px 0}}th,td{{text-align:left;vertical-align:top;padding:14px 10px;border-bottom:1px solid #dedfd7}}th{{width:24%;font-weight:550}}td:first-child{{width:48px}}small{{display:block;margin-top:4px}}.fail{{color:#b03224}}.warn{{color:#8c6406}}.pass{{color:#26704b}}.unknown{{color:#777}}@media(max-width:600px){{body{{margin:24px auto;padding:0 12px}}th,td{{padding:10px 5px;font-size:13px}}}}</style>
<h1>Claude Env Doctor</h1><p>只读环境检测 · {esc(report['generated_at'])} · v{VERSION}</p>
<p>只展示检查证据，不提供账号安全评分。此文件无脚本、无外链、不会发起网络请求。</p>
<table><thead><tr><th>状态</th><th>检查</th><th>证据与建议</th></tr></thead><tbody>{rows}</tbody></table>
<h2>检测边界</h2><ul>{limits}</ul></html>"""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Claude Code 只读环境检测；默认发送少量无认证网络请求。")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--project", type=Path, default=Path.cwd(), help="Claude 工程目录（默认当前工程）")
    parser.add_argument("--offline", action="store_true", help="只检查本地配置，不联网")
    parser.add_argument("--json", action="store_true", help="输出结构化 JSON")
    parser.add_argument("--html", type=Path, metavar="FILE", help="额外保存一个无脚本的本地 HTML 报告（不覆盖已有文件）")
    parser.add_argument("--timeout", type=float, default=8, metavar="SECONDS", help="每个网络探针的超时，默认 8 秒")
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout <= 60:
        parser.error("--timeout 必须在 0.1 到 60 秒之间")
    if not args.project.is_dir():
        parser.error("--project 必须是已有目录")
    report = audit(project_root(args.project), offline=args.offline, timeout=args.timeout)
    if args.html:
        try:
            # Exclusive create prevents overwriting configs, existing reports or symlink targets.
            with args.html.open("x", encoding="utf-8") as output:
                output.write(render_html(report))
        except OSError:
            parser.error("HTML 报告无法创建；请使用可写目录中的新文件名")
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report))
    return 1 if report["summary"]["fail"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
