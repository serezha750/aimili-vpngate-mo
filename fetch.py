#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import time
import urllib.parse
import urllib.request
import socket
import ssl
import re
from typing import Any

import vpn_utils
import config
import state
import utils

# ---------- 代理请求辅助 ----------
def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else:  # http proxy
            if is_https:
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                pass

        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path

        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024:
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = config.API_URL

    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            utils.log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

# ---------- 解析器 ----------
def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def parse_auto_ovpn_json(text: str) -> list[dict[str, str]]:
    raw_nodes = json.loads(text)
    if not isinstance(raw_nodes, list):
        raise ValueError(f"auto-ovpn JSON 顶层应为数组，实际为 {type(raw_nodes).__name__}")
    rows = []
    for n in raw_nodes:
        if not isinstance(n, dict):
            continue
        config_b64 = (
            n.get("config_base64")
            or n.get("openvpn_config_base64")
            or n.get("OpenVPN_ConfigData_Base64")
            or ""
        )
        if not config_b64:
            continue
        rows.append({
            "IP": n.get("ip", ""),
            "HostName": n.get("hostname", ""),
            "CountryShort": n.get("country_short", n.get("countryCode", "XX")),
            "CountryLong": n.get("country", ""),
            "Score": str(n.get("score", 0)),
            "Ping": str(n.get("ping", 0)),
            "Speed": str(n.get("speed", 0)),
            "NumVpnSessions": str(n.get("sessions", n.get("numVpnSessions", 0))),
            "OpenVPN_ConfigData_Base64": config_b64,
        })
    return rows

def parse_ipspeed_html(text: str, base_url: str) -> list[dict[str, str]]:
    # 确保 re 已导入（本函数已使用）
    ovpn_links = re.findall(r'href="([^"]*\.ovpn)"', text)
    ovpn_urls = list(dict.fromkeys([urllib.parse.urljoin(base_url, m) for m in ovpn_links]))
    ip_country: dict[str, tuple[str, str]] = {}
    rows_html = re.findall(r'<tr[^>]*>(.*?)</tr>', text, re.DOTALL | re.IGNORECASE)
    for row_html in rows_html:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row_html, re.DOTALL | re.IGNORECASE)
        if len(cells) >= 3:
            country_long = re.sub(r'<[^>]+>', '', cells[1]).strip()
            filename = re.sub(r'<[^>]+>', '', cells[2]).strip()
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', filename)
            if ip_match and country_long:
                ip_country[ip_match.group(1)] = (country_long, filename)
    rows = []
    for url in ovpn_urls:
        filename = url.split("/")[-1]
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', filename)
        ip = ip_match.group(1) if ip_match else ""
        if not ip:
            continue
        country_long, _ = ip_country.get(ip, ("", ""))
        _CS = {"Japan":"JP","South Korea":"KR","Korea Republic of":"KR","USA":"US",
               "United States":"US","United Kingdom":"GB","Russian Federation":"RU",
               "Russia":"RU","France":"FR","Canada":"CA","Thailand":"TH","Vietnam":"VN",
               "Argentina":"AR","Australia":"AU","Netherlands":"NL","India":"IN",
               "Germany":"DE","Italy":"IT","Indonesia":"ID","Poland":"PL","Romania":"RO",
               "Sweden":"SE","Turkey":"TR","Ukraine":"UA","Emirates":"AE","Brazil":"BR",
               "Mexico":"MX","China":"CN","Belarus":"BY","Macedonia":"MK","Grenada":"GD"}
        country_short = _CS.get(country_long, "XX")
        try:
            config_text = fetch_api_text(url, True)
        except Exception:
            try:
                config_text = fetch_api_text(url, False)
            except Exception as e:
                print(f"[ipspeed] 下载 {url} 失败: {e}", flush=True)
                continue
        config_b64 = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
        rows.append({
            "IP": ip, "HostName": "", "CountryShort": country_short,
            "CountryLong": country_long, "Score": "0", "Ping": "0",
            "Speed": "0", "NumVpnSessions": "0",
            "OpenVPN_ConfigData_Base64": config_b64,
        })
    return rows

def parse_vpnbook_html(text: str, base_url: str) -> list[dict[str, str]]:
    match = re.search(r'\\"servers\\":(\[.*?\])', text, re.S)
    if not match:
        raise RuntimeError("VPNBook: 未找到 servers 数据")
    servers = json.loads(bytes(match.group(1), "utf-8").decode("unicode_escape"))

    match2 = re.search(r'\\"openvpn\\":\{.*?\\"protocols\\":\{(.*?)\}\},\\"wireguard\\":\{', text, re.S)
    if not match2:
        raise RuntimeError("VPNBook: 未找到 protocols 数据")
    protocols = list(dict.fromkeys(re.findall(r'\\"(tcp\d+|udp\d+)\\"', match2.group(1))))

    match3 = re.search(r'VPN.*?<code[^>]*>([^<]+)</code>.*?<code[^>]*>([^<]+)</code>', text, re.S)
    if match3:
        vb_user, vb_pass = match3.group(1).strip(), match3.group(2).strip()
    else:
        match3b = re.search(r'凭证.*?<code[^>]*>([^<]+)</code>.*?<code[^>]*>([^<]+)</code>', text, re.S)
        if match3b:
            vb_user, vb_pass = match3b.group(1).strip(), match3b.group(2).strip()
        else:
            vb_user, vb_pass = "vpn", "vpn"

    try:
        config.DATA_DIR.mkdir(exist_ok=True, parents=True)
        (config.DATA_DIR / "vpnbook_auth.txt").write_text(f"{vb_user}\n{vb_pass}\n", encoding="utf-8")
    except Exception:
        pass

    print(f"[vpnbook] 服务器={len(servers)} 协议={len(protocols)} "
          f"总配置={len(servers)*len(protocols)} 凭证={vb_user}/{vb_pass}", flush=True)

    rows = []
    for server in servers:
        host = server.get("hostname", "")
        ip = server.get("ipAddress", "")
        country_long = server.get("country", {}).get("name", "") if isinstance(server.get("country"), dict) else str(server.get("country", ""))
        _CS = {"Japan":"JP","South Korea":"KR","USA":"US","United States":"US",
               "United Kingdom":"GB","Netherlands":"NL","Germany":"DE","France":"FR",
               "Canada":"CA","Switzerland":"CH","Poland":"PL","Romania":"RO",
               "Czech Republic":"CZ","Italy":"IT","Spain":"ES","Finland":"FI",
               "Sweden":"SE","Singapore":"SG"}
        country_short = _CS.get(country_long, "XX")

        for protocol in protocols:
            api_url = (f"https://www.vpnbook.com/api/openvpn"
                       f"?hostname={host}&protocol={protocol}&ip={ip}")
            try:
                config_text = fetch_api_text(api_url, True)
            except Exception:
                try:
                    config_text = fetch_api_text(api_url, False)
                except Exception as e:
                    print(f"[vpnbook] 下载 {host}/{protocol} 失败: {e}", flush=True)
                    continue

            auth_line = f"\nauth-user-pass {config.DATA_DIR / 'vpnbook_auth.txt'}\n"
            if "auth-user-pass" not in config_text:
                config_text = config_text.rstrip() + auth_line
            else:
                config_text = re.sub(r"auth-user-pass\s+\S*", f"auth-user-pass {config.DATA_DIR / 'vpnbook_auth.txt'}", config_text)

            config_b64 = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
            rows.append({
                "IP": ip, "HostName": host, "CountryShort": country_short,
                "CountryLong": country_long, "Score": "0", "Ping": "0",
                "Speed": "0", "NumVpnSessions": "0",
                "OpenVPN_ConfigData_Base64": config_b64,
            })
    return rows

PARSERS = {
    "vpngate_csv": parse_vpngate_rows,
    "auto_ovpn_json": parse_auto_ovpn_json,
    "ipspeed_html": parse_ipspeed_html,
    "vpnbook_html": parse_vpnbook_html,
}

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = utils.safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = config.CONFIG_DIR / f"{node_id}.ovpn"

    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": utils.parse_int(row.get("Score")),
        "ping": utils.parse_int(row.get("Ping")),
        "speed": utils.parse_int(row.get("Speed")),
        "sessions": utils.parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = utils.load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()

    has_cache = len(state.read_nodes()) > 0
    max_attempts = 1 if has_cache else 2

    sources = sorted(
        [s for s in config.NODE_SOURCES if s.get("enabled")],
        key=lambda s: s.get("weight", 0),
        reverse=True,
    )

    last_err = None
    for source in sources:
        source_url = source["url"]
        parser = PARSERS.get(source["format"])
        if not parser:
            print(f"[fetch_candidates] 未知格式 {source['format']}，跳过源 {source['name']}", flush=True)
            continue

        attempts_targets = [(source_url, True), (source_url, False)]
        if source_url.startswith("https://"):
            attempts_targets.append((source_url.replace("https://", "http://"), True))

        utils.log_to_json("INFO", "Main", f"开始从源 {source['name']} 拉取节点列表...")

        source_count = 0
        for url, verify_ssl in attempts_targets:
            for i in range(max_attempts):
                if i > 0:
                    time.sleep(1.5)
                try:
                    msg = f"[{source['name']}] 拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                    print(f"[fetch_candidates] {msg}", flush=True)
                    utils.log_to_json("INFO", "Main", msg)
                    api_text = fetch_api_text(url, verify_ssl)

                    if source["format"] in ("ipspeed_html", "vpnbook_html"):
                        rows = parser(api_text, url)
                    else:
                        rows = parser(api_text)

                    for row in rows[:config.MAX_SCAN_ROWS]:
                        ip = row.get("IP", "")
                        if not ip or ip in seen_ips:
                            continue
                        encoded = row.get("OpenVPN_ConfigData_Base64", "")
                        if not encoded:
                            continue
                        try:
                            config_text = decode_config(encoded)
                            node = row_to_node(row, config_text)
                            node["source"] = source["name"]
                        except Exception as row_exc:
                            print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                            utils.log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                            continue
                        entry = blacklist.get(node["id"])
                        if entry and float(entry.get("until", 0) or 0) > time.time():
                            continue
                        candidates.append(node)
                        seen_ips.add(ip)
                        source_count += 1
                    if source_count:
                        break
                except Exception as e:
                    last_err = e
                    print(f"[fetch_candidates] 源 {source['name']} 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                    utils.log_to_json("WARNING", "Main", f"源 {source['name']} 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
            if source_count:
                break

        utils.log_to_json("INFO", "Main", f"源 {source['name']} 贡献 {source_count} 个节点")

    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(config.API_URL)
        full_err_msg = f"所有源均拉取失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        utils.log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        state.set_state(last_fetch_status="error", last_fetch_error_code=err_code, last_fetch_message=diag_msg)
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)

    state.set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"从 {len(sources)} 个源获取 {len(candidates)} 个候选节点",
        blacklisted_nodes=len(blacklist),
    )
    utils.log_to_json("INFO", "Main", f"多源获取完成，共 {len(candidates)} 个候选节点")
    return candidates