#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import random
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any
import os
import vpn_utils
import proxy_server
import config
import state
import utils
import fetch
import openvpn

# ---------- 内部辅助 ----------
active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = utils.safe_name(node_id)
    return config.CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            utils.parse_int(n.get("latency_ms")) or 999999,
            -utils.parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (-utils.parse_int(n.get("score")), utils.parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-utils.parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

# ---------- 核心业务函数 ----------
def test_node_by_id(node_id: str) -> dict[str, Any]:
    with state.lock:
        nodes = state.read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = utils.parse_int(node.get("remote_port"))
        fallback_ping = utils.parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        config.CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)

    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = openvpn.run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with state.lock:
        nodes = state.read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]

            sorted_nodes = sort_all_nodes(nodes)
            state.write_json(config.NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def tcp_prescreen_dead(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    tcp_nodes = [n for n in nodes if str(n.get("proto", "")).lower().startswith("tcp")]
    if not tcp_nodes:
        return {}

    dev = vpn_utils.get_physical_interface()
    dead: dict[str, dict[str, Any]] = {}
    dead_lock = threading.Lock()

    def probe(n: dict[str, Any]) -> None:
        host = str(n.get("remote_host") or n.get("ip") or "")
        port = utils.parse_int(n.get("remote_port"))
        if not host or not port:
            return
        if vpn_utils.tcp_latency_ms(host, port, dev) <= 0:
            with dead_lock:
                dead[n["id"]] = {
                    "id": n["id"],
                    "latency_ms": 0,
                    "probe_status": "unavailable",
                    "probe_message": "TCP 预筛失败：目标端口不可达，已跳过 OpenVPN 测试",
                    "probed_at": time.time(),
                    "owner": "",
                    "asn": "",
                    "as_name": "",
                    "location": "",
                    "ip_type": "",
                    "quality": "",
                }

    workers = min(config.TCP_PRESCREEN_CONCURRENCY, max(1, len(tcp_nodes)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(probe, tcp_nodes))
    return dead

# ========== 修改后的 test_multiple_nodes（支持删除 TCP 预筛死节点） ==========
def test_multiple_nodes(node_ids: list[str], max_workers: int | None = None) -> list[dict[str, Any]]:
    with state.lock:
        nodes = state.read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]

    dead_prescreen = tcp_prescreen_dead(to_test)
    if dead_prescreen:
        print(f"[分层测速] TCP 预筛淘汰 {len(dead_prescreen)} 个不可达节点，剩余 {len(to_test) - len(dead_prescreen)} 个进入 OpenVPN 测试", flush=True)
    to_test = [n for n in to_test if n.get("id") not in dead_prescreen]

    if max_workers is None:
        max_workers = config.OPENVPN_TEST_CONCURRENCY
    max_workers = min(max_workers, max(1, len(to_test)))

    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = utils.parse_int(n_info.get("remote_port"))
        fallback_ping = utils.parse_int(n_info.get("ping"))

        temp_path = test_config_path(node_id)
        try:
            config.CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }

        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = openvpn.run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map = dict(dead_prescreen)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }

    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    # ===== 删除 TCP 预筛死节点（受配置开关控制） =====
    with state.lock:
        current_nodes = state.read_nodes()
        dead_ids = set(dead_prescreen.keys())

        # 如果配置了删除（默认 True，可通过环境变量 DELETE_PRESCREEN_DEAD=1 开启）
        if getattr(config, 'DELETE_PRESCREEN_DEAD', True):
            # 从当前节点列表中过滤掉 dead_ids
            current_nodes = [n for n in current_nodes if n.get("id") not in dead_ids]
            print(f"[分层测速] 已从节点池中删除 {len(dead_ids)} 个 TCP 预筛不可达节点", flush=True)

        # 更新剩余节点的状态（跳过已删除的节点）
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map and nid not in dead_ids:
                n.update(updated_nodes_map[nid])

        sorted_nodes = sort_all_nodes(current_nodes)
        state.write_json(config.NODES_FILE, sorted_nodes)

    return list(updated_nodes_map.values())
# ===== 修改结束 =====

def mark_main_bad_node(node_id: str) -> None:
    nid = str(node_id or "").strip()
    if nid:
        state.main_bad_nodes[nid] = time.time() + config.MAIN_BAD_NODE_COOLDOWN

def main_bad_node_ids() -> set[str]:
    now = time.time()
    return {nid for nid, until in state.main_bad_nodes.items() if until > now}

def reset_main_proxy_connections() -> None:
    global main_egress_fail_count
    state.main_egress_fail_count = 0
    try:
        n = state.main_proxy_registry.close_all()
        proxy_server.purge_dns_cache("tun0")
        if n:
            print(f"[主代理] 节点切换完成，已重置 {n} 条下游连接并清隧道 DNS 缓存，强制其重连新隧道", flush=True)
            utils.log_to_json("INFO", "Proxy", f"主连接切换后重置 {n} 条下游连接，强制重连新隧道")
    except Exception as e:
        print(f"[主代理] 重置下游连接异常: {e}", flush=True)

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with state.lock:
        openvpn.cleanup_policy_routing()
        config_to_delete = None
        if state.active_openvpn_node_id:
            nodes = state.read_nodes()
            node = next((item for item in nodes if item.get("id") == state.active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")

        openvpn.stop_process(state.active_openvpn_process)
        state.active_openvpn_process = None
        state.active_openvpn_node_id = ""
        openvpn.kill_existing_openvpn_processes()

        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_active_openvpn()
    state.active_openvpn_process = None
    state.active_openvpn_node_id = ""
    with state.lock:
        nodes = state.read_nodes()
        for item in nodes:
            item["active"] = False
        state.write_json(config.NODES_FILE, nodes)
    state.set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return

    ui_cfg = config.load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    with state.lock:
        nodes = state.read_nodes()
        bad = main_bad_node_ids()
        candidates = [
            n for n in nodes
            if n.get("probe_status") == "available"
            and not n.get("active")
            and n.get("id") not in bad
        ]

        if routing_mode == "fixed_region" and target_country:
            candidates = [
                n for n in candidates
                if n.get("country") == target_country
                or vpn_utils.COUNTRY_TRANSLATIONS.get(n.get("country", ""), n.get("country", "")) == target_country
            ]
        if routing_mode == "favorites":
            fav_ids = set(ui_cfg.get("favorite_node_ids", []))
            fav_candidates = [n for n in candidates if n.get("id") in fav_ids]
            if fav_candidates:
                candidates = fav_candidates
            else:
                fav_fail_fallback = ui_cfg.get("fav_fail_fallback", True)
                if not fav_fail_fallback:
                    candidates = []

        routing_ip_type = ui_cfg.get("routing_ip_type", "all")
        if routing_ip_type == "residential":
            candidates = [n for n in candidates if n.get("ip_type") in ("residential", "mobile")]
        elif routing_ip_type == "hosting":
            candidates = [n for n in candidates if n.get("ip_type") == "hosting"]

        routing_isp = str(ui_cfg.get("routing_isp", "") or "").strip()
        if routing_isp:
            kws = [k.strip().lower() for k in routing_isp.split(",") if k.strip()]
            if kws:
                candidates = [
                    n for n in candidates
                    if any(kw in (str(n.get("owner", "")) + " " + str(n.get("as_name", "")) + " " + str(n.get("asn", ""))).lower() for kw in kws)
                ]

        candidates.sort(key=lambda n: (utils.parse_int(n.get("latency_ms")) or 999999, -utils.parse_int(n.get("score"))))

    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        utils.log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            utils.log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        utils.log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with state.lock:
            nodes = state.read_nodes()
            for item in nodes:
                item["active"] = False
            state.write_json(config.NODES_FILE, nodes)
        state.set_state(active_openvpn_node_id="", last_check_message=msg)

        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False)
                auto_switch_node()
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)

        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with state.lock:
        if state.is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        state.is_connecting = True
        state.set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")

    try:
        utils.log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = state.read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        ui_cfg = config.load_ui_config()
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = config.DATA_DIR / "ui_auth.json"
        with state.lock:
            config.DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        state.set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        state.set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            config.CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        state.set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = openvpn.run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            state.write_json(config.NODES_FILE, nodes)
            utils.log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            state.set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with state.lock:
                state.active_openvpn_node_id = ""
            raise RuntimeError(message)

        with state.lock:
            state.active_openvpn_process = process
            state.active_openvpn_node_id = node_id

        state.set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        openvpn.setup_policy_routing("tun0")

        global last_active_ping_time, last_active_latency
        state.last_active_ping_time = time.time()
        state.last_active_latency = 0

        state.set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = utils.parse_int(node.get("remote_port"))
            fallback = utils.parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                state.last_active_latency = latency
        except Exception:
            pass

        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{config.LOCAL_PROXY_HOST}]" if ":" in config.LOCAL_PROXY_HOST else config.LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{config.LOCAL_PROXY_PORT}"
        state.write_json(config.NODES_FILE, nodes)

        state.set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            state.set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
            reset_main_proxy_connections()
        else:
            state.set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )

        latency_str = f"{state.last_active_latency} ms" if state.last_active_latency > 0 else "检测超时"
        state.set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        utils.log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (state.active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            state.set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with state.lock:
            state.is_connecting = False

def active_openvpn_running() -> bool:
    return state.active_openvpn_process is not None and state.active_openvpn_process.poll() is None

# ---------- publicvpnlist 自动导入 ----------
PUBLICVPNLIST_LAST_RUN = 0.0
PUBLICVPNLIST_LOCK = threading.Lock()

def _import_publicvpnlist_nodes() -> list[str]:
    """
    扫描 publicvpnlist-ovpn 目录，将新节点导入到 config.NODES_FILE 中。
    返回新增节点 ID 列表，并更新 state.json 中的导入计数和时间。
    """
    ovpn_dir = config.ROOT_DIR / "publicvpnlist-ovpn"
    if not ovpn_dir.exists():
        print(f"[publicvpnlist] 目录 {ovpn_dir} 不存在，跳过导入", flush=True)
        return []

    nodes_json = config.NODES_FILE
    if not nodes_json.exists():
        print(f"[publicvpnlist] {nodes_json} 不存在，将创建", flush=True)
        nodes = []
    else:
        try:
            with open(nodes_json, "r", encoding="utf-8") as f:
                nodes = json.load(f)
        except Exception as e:
            print(f"[publicvpnlist] 读取 {nodes_json} 失败: {e}", flush=True)
            return []

    existing_ids = {n["id"] for n in nodes if isinstance(n, dict)}
    new_ids = []
    prefix = "publicvpnlist_"

    ovpn_files = list(ovpn_dir.glob("*.ovpn"))
    print(f"[publicvpnlist] 发现 {len(ovpn_files)} 个 OVPN 文件", flush=True)

    for ovpn_file in ovpn_files:
        try:
            config_text = ovpn_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"[publicvpnlist] 读取 {ovpn_file.name} 失败: {e}", flush=True)
            continue

        remote_line = None
        for line in config_text.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("remote "):
                remote_line = line_strip
                break
        if not remote_line:
            print(f"[publicvpnlist] 跳过 {ovpn_file.name}: 未找到 remote 行", flush=True)
            continue

        parts = remote_line.split()
        if len(parts) < 3:
            print(f"[publicvpnlist] 跳过 {ovpn_file.name}: remote 格式不完整", flush=True)
            continue
        remote_host = parts[1]
        try:
            remote_port = int(parts[2])
        except ValueError:
            remote_port = 443
        proto = parts[3].lower() if len(parts) > 3 else "tcp"

        node_id = prefix + ovpn_file.stem
        if node_id in existing_ids:
            continue

        node = {
            "id": node_id,
            "country": "",
            "country_short": "",
            "ip": remote_host,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "proto": proto,
            "config_text": config_text,
            "config_file": f"vpngate_data/configs/{node_id}.ovpn",
            "score": 0,
            "ping": 0,
            "speed": 0,
            "sessions": 0,
            "latency_ms": 0,
            "probe_status": "not_checked",
            "probe_message": "",
            "probed_at": 0,
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
            "fetched_at": time.time(),
            "source": "publicvpnlist_manual"
        }
        nodes.append(node)
        existing_ids.add(node_id)
        new_ids.append(node_id)
        print(f"[publicvpnlist] 添加节点: {node_id} -> {remote_host}:{remote_port} ({proto})", flush=True)

    if new_ids:
        nodes_json.parent.mkdir(parents=True, exist_ok=True)
        with open(nodes_json, "w", encoding="utf-8") as f:
            json.dump(nodes, f, ensure_ascii=False, indent=2)
        print(f"[publicvpnlist] 成功导入 {len(new_ids)} 个新节点，当前节点总数: {len(nodes)}", flush=True)
        state.set_state(
            publicvpnlist_import_count=len(new_ids),
            publicvpnlist_import_time=time.time(),
        )
    else:
        print("[publicvpnlist] 没有新节点需要导入", flush=True)

    return new_ids

def sync_publicvpnlist_import() -> int:
    global PUBLICVPNLIST_LAST_RUN
    if not config.PUBLICVPNLIST_SCRIPT.exists():
        return 0

    with PUBLICVPNLIST_LOCK:
        now = time.time()
        if now - PUBLICVPNLIST_LAST_RUN >= config.PUBLICVPNLIST_INTERVAL:
            PUBLICVPNLIST_LAST_RUN = now
            print("[publicvpnlist] 同步下载最新节点...", flush=True)
            env = os.environ.copy()
            ovpn_dir = str(config.ROOT_DIR / "publicvpnlist-ovpn")
            env["OUT_DIR"] = ovpn_dir
            try:
                proc = subprocess.Popen(
                    [sys.executable, str(config.PUBLICVPNLIST_SCRIPT), "--skip-import"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )
                stdout, stderr = proc.communicate(timeout=600)
                if proc.returncode != 0:
                    print(f"[publicvpnlist] 下载失败: {stderr}", flush=True)
                else:
                    print("[publicvpnlist] 下载完成", flush=True)
            except Exception as e:
                print(f"[publicvpnlist] 下载异常: {e}", flush=True)

        new_ids = _import_publicvpnlist_nodes()
        if new_ids:
            print(f"[publicvpnlist] 导入 {len(new_ids)} 个新节点", flush=True)
        return len(new_ids)

def run_publicvpnlist_import_and_test() -> None:
    if not config.PUBLICVPNLIST_SCRIPT.exists():
        return

    with PUBLICVPNLIST_LOCK:
        global PUBLICVPNLIST_LAST_RUN
        now = time.time()
        if now - PUBLICVPNLIST_LAST_RUN < config.PUBLICVPNLIST_INTERVAL:
            return
        PUBLICVPNLIST_LAST_RUN = now

    def _task() -> None:
        try:
            print("[publicvpnlist] 开始后台下载与导入...", flush=True)
            import subprocess
            env = os.environ.copy()
            env["OUT_DIR"] = str(config.ROOT_DIR / "publicvpnlist-ovpn")
            proc = subprocess.Popen(
                [sys.executable, str(config.PUBLICVPNLIST_SCRIPT), "--skip-import"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            stdout, stderr = proc.communicate(timeout=600)
            if proc.returncode != 0:
                print(f"[publicvpnlist] 下载失败: {stderr}", flush=True)
                return

            new_ids = _import_publicvpnlist_nodes()
            if new_ids:
                print(f"[publicvpnlist] 发现 {len(new_ids)} 个新节点，开始独立并发检测 (并发数: {config.PUBLICVPNLIST_TEST_CONCURRENCY})...", flush=True)
                test_multiple_nodes(new_ids, max_workers=config.PUBLICVPNLIST_TEST_CONCURRENCY)
                print(f"[publicvpnlist] 新节点检测完成", flush=True)
        except Exception as e:
            print(f"[publicvpnlist] 后台任务异常: {e}", flush=True)

    threading.Thread(target=_task, daemon=True).start()

def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    config.ensure_dirs()
    if not state.maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        state.set_state(last_check_message=msg)
        return msg
    state.is_connecting = True
    try:
        if force:
            with state.lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            ui_cfg = config.load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    target_id = state.active_openvpn_node_id or ui_cfg.get("fixed_node_id", "")
                    if target_id:
                        nodes = state.read_nodes()
                        if any(n.get("id") == target_id for n in nodes):
                            print(f"[维护线程] 检测到固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
                            state.is_connecting = False
                            try:
                                connect_node(target_id)
                            except Exception as e:
                                print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
                            state.is_connecting = True
                else:
                    has_active_id = False
                    with state.lock:
                        if state.active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        state.is_connecting = False
                        auto_switch_node()
                        state.is_connecting = True

        try:
            state.set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch.fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(config.API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            state.set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        try:
            sync_publicvpnlist_import()
        except Exception as e:
            print(f"[publicvpnlist] 同步导入失败: {e}", flush=True)

        if candidates or True:
            with state.lock:
                current_nodes = state.read_nodes()
                active_node = None
                if state.active_openvpn_node_id:
                    active_node = next((n for n in current_nodes if n.get("id") == state.active_openvpn_node_id), None)

                merged: list[dict[str, Any]] = []
                seen_ids: set[str] = set()

                if active_node:
                    merged.append(active_node)
                    seen_ids.add(active_node["id"])

                for cand in candidates:
                    if cand["id"] not in seen_ids:
                        merged.append(cand)
                        seen_ids.add(cand["id"])

                for n in current_nodes:
                    if n["id"] not in seen_ids:
                        merged.append(n)
                        seen_ids.add(n["id"])

                if len(merged) > 1000:
                    merged = merged[:1000]

                for n in merged:
                    config_path = Path(n["config_file"])
                    if not config_path.exists():
                        try:
                            config_path.write_text(n["config_text"], encoding="utf-8")
                        except Exception:
                            pass

                state.write_json(config.NODES_FILE, merged)

            with state.lock:
                current_nodes = state.read_nodes()
                to_test = [n for n in current_nodes if not n.get("active")]
                to_test_ids = [n["id"] for n in to_test]

            if candidates or to_test_ids:
                msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
                print(f"[周期检测] {msg}", flush=True)
                utils.log_to_json("INFO", "Main", msg)

                state.set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
                test_multiple_nodes(to_test_ids)
                state.is_connecting = False

                with state.lock:
                    merged = state.read_nodes()

                    available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
                    unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
                    active_node = next((n["id"] for n in merged if n.get("active")), "无")

                    status_report = (
                        f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                        f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                        f"【不可用节点】{len(unavailable_nodes)} 个; "
                        f"当前【正在正常运行的活动连接节点】为: {active_node}。"
                    )
                    print(f"[周期检测] {status_report}", flush=True)
                    utils.log_to_json("INFO", "Main", status_report)

                    if active_node != "无" and not active_openvpn_running():
                        warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                        print(warn_msg, flush=True)
                        utils.log_to_json("WARNING", "Main", warn_msg)

                    if not active_openvpn_running():
                        ui_cfg = config.load_ui_config()
                        connection_enabled = ui_cfg.get("connection_enabled", True)
                        if connection_enabled:
                            routing_mode = ui_cfg.get("routing_mode", "auto")
                            target_country = ui_cfg.get("force_country", "")

                            if routing_mode != "fixed_ip":
                                available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                                if routing_mode == "fixed_region" and target_country:
                                    available_candidates = [
                                        n for n in available_candidates
                                        if n.get("country") == target_country
                                        or vpn_utils.COUNTRY_TRANSLATIONS.get(n.get("country", ""), n.get("country", "")) == target_country
                                    ]
                                elif routing_mode == "favorites":
                                    fav_ids = set(ui_cfg.get("favorite_node_ids", []))
                                    fav_candidates = [n for n in available_candidates if n.get("id") in fav_ids]
                                    if fav_candidates:
                                        available_candidates = fav_candidates
                                    else:
                                        fav_fail_fallback = ui_cfg.get("fav_fail_fallback", True)
                                        if not fav_fail_fallback:
                                            available_candidates = []

                                routing_ip_type = ui_cfg.get("routing_ip_type", "all")
                                if routing_ip_type == "residential":
                                    available_candidates = [n for n in available_candidates if n.get("ip_type") in ("residential", "mobile")]
                                elif routing_ip_type == "hosting":
                                    available_candidates = [n for n in available_candidates if n.get("ip_type") == "hosting"]

                                if available_candidates:
                                    auto_switch_node()

            valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
            message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
            state.set_state(
                last_check_at=time.time(),
                last_check_message=message,
                active_openvpn_node_id=state.active_openvpn_node_id,
                valid_nodes=valid_nodes_count,
            )
            return message
        else:
            return "没有获取到任何节点，跳过检测"
    except Exception as e:
        raise e
    finally:
        state.is_connecting = False
        state.maintenance_lock.release()

# ---------- 代理健康检测 ----------
def check_proxy_health() -> dict[str, Any]:
    """检测本地代理出口是否可用。

    优化点：
    - 多端点并行探测，任一成功立即返回（降低误报与最坏等待时间）
    - 单次 curl 超时缩短为约 3s
    - 统一解析本机代理连接地址，减少重复逻辑
    """
    is_ipv6 = ":" in config.LOCAL_PROXY_HOST

    def _local_proxy_connect_hosts() -> list[tuple[int, str]]:
        """返回 [(address_family, host), ...] 按优先级尝试。"""
        host = config.LOCAL_PROXY_HOST
        if host in ("::", ""):
            return [(socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]
        if host == "0.0.0.0":
            return [(socket.AF_INET, "127.0.0.1")]
        if ":" in host:
            return [(socket.AF_INET6, host), (socket.AF_INET, "127.0.0.1")]
        return [(socket.AF_INET, host)]

    def _proxy_url_hosts() -> list[str]:
        host = config.LOCAL_PROXY_HOST
        if host == "::":
            return ["[::1]", "127.0.0.1"]
        if host == "0.0.0.0":
            return ["127.0.0.1"]
        if ":" in host:
            return [f"[{host}]", "127.0.0.1"]
        return [host]

    def _tcp_probe(timeout: float = 1.5) -> bool:
        for af, connect_host in _local_proxy_connect_hosts():
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((connect_host, config.LOCAL_PROXY_PORT))
                return True
            except Exception:
                continue
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        return False

    if not _tcp_probe(1.5):
        diag = vpn_utils.diagnose_local_obstructions(config.LOCAL_PROXY_PORT, host=config.LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {config.LOCAL_PROXY_PORT} 连接失败"
        return {"ok": False, "error": f"代理服务未运行 ({diag_msg})"}

    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点",
        }

    # 多端点：任一成功即可；并行缩短最坏等待
    health_endpoints = (
        "http://api.ipify.org",
        "http://ip.sb",
        "http://ifconfig.me/ip",
        "http://icanhazip.com",
    )
    curl_max_time = 3  # 秒
    curl_proc_timeout = curl_max_time + 1

    def _looks_like_ip(text: str) -> bool:
        text = text.strip()
        if not text or len(text) > 45:
            return False
        # 粗校验：IPv4 或 IPv6 字符集，避免把 HTML 错误页当 IP
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
            return True
        if ":" in text and re.match(r"^[0-9a-fA-F:]+$", text):
            return True
        return False

    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
        for p_host in _proxy_url_hosts():
            proxy_url = f"socks5h://{p_host}:{config.LOCAL_PROXY_PORT}"
            cmd = [
                "curl", "-s", "-L",
                "--max-redirs", "2",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", str(curl_max_time),
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=curl_proc_timeout)
                if res.returncode != 0:
                    continue
                lines = res.stdout.strip().splitlines()
                if len(lines) < 2:
                    continue
                ip = lines[0].strip()
                time_info = lines[-1].strip().split()
                if len(time_info) != 2:
                    continue
                total_time_str, http_code = time_info
                if http_code != "200" or not _looks_like_ip(ip):
                    continue
                latency_ms = int(float(total_time_str) * 1000)
                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                continue
        return None

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(health_endpoints))
    try:
        # 并行探测；拿到第一个成功结果即返回，并尽快结束线程池等待
        futures = {pool.submit(_curl_check_ip, url): url for url in health_endpoints}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=curl_proc_timeout + 1):
                try:
                    result = fut.result()
                except Exception:
                    continue
                if result and result.get("ok"):
                    return result
        except concurrent.futures.TimeoutError:
            pass

        # 全部失败：再确认代理端口是否仍在监听，区分“代理挂了”和“出口不通”
        if not _tcp_probe(1.0):
            diag = vpn_utils.diagnose_local_obstructions(config.LOCAL_PROXY_PORT, host=config.LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            return {"ok": False, "error": f"出口连接测试失败 | 代理端口 {config.LOCAL_PROXY_PORT} 已不可达"}

        tried = ", ".join(health_endpoints)
        return {
            "ok": False,
            "error": (
                f"出口连接测试失败（已并行尝试: {tried}；"
                "可能是节点已失效、隧道不转发，或 VPS 防火墙限制了相关出站）"
            ),
        }
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting, main_egress_fail_count
    time.sleep(30)
    last_proxy_ok: bool | None = None
    last_proxy_ip = ""
    while True:
        state.last_checker_heartbeat = time.time()
        try:
            if state.is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                state.set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                state.main_egress_fail_count = 0
                # 仅在状态变化时写 INFO，避免每 30s 刷盘
                if last_proxy_ok is not True or last_proxy_ip != res["ip"]:
                    utils.log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
                last_proxy_ok = True
                last_proxy_ip = res["ip"]
            else:
                last_proxy_ok = False
                last_proxy_ip = ""
                error_msg = res.get("error", "未知错误")
                if state.active_openvpn_node_id:
                    print(f"[警告] {config.LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    utils.log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                state.set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                if state.active_openvpn_node_id:
                    ui_cfg = config.load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    state.main_egress_fail_count += 1
                    if state.main_egress_fail_count < config.MAIN_EGRESS_FAIL_THRESHOLD:
                        print(f"[代理守护线程] 出口检测失败 {state.main_egress_fail_count}/{config.MAIN_EGRESS_FAIL_THRESHOLD} 次，暂不处理，继续观察。原因: {error_msg}", flush=True)
                    elif routing_mode != "fixed_ip":
                        state.main_egress_fail_count = 0
                        with state.lock:
                            nodes = state.read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == state.active_openvpn_node_id), None)
                            if active_node:
                                utils.mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                state.write_json(config.NODES_FILE, nodes)
                        mark_main_bad_node(state.active_openvpn_node_id)
                        auto_switch_node()
                    else:
                        state.main_egress_fail_count = 0
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {state.active_openvpn_node_id}", flush=True)
                        state.is_connecting = False
                        try:
                            connect_node(state.active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            utils.log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    while True:
        state.last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and state.active_openvpn_node_id:
                nodes = state.read_nodes()
                node = next((n for n in nodes if n.get("id") == state.active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = utils.parse_int(node.get("remote_port"))
                    fallback = utils.parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            state.set_state(active_node_latency=f"{latency} ms")
                        else:
                            state.set_state(active_node_latency="检测超时")
                    else:
                        state.set_state(active_node_latency="检测超时")
                else:
                    state.set_state(active_node_latency="检测超时")
            elif state.is_connecting:
                state.set_state(active_node_latency="测试中...")
            else:
                state.set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)

# ---------- 后台定期维护循环 ----------
def collector_loop() -> None:
    print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
    while True:
        try:
            maintain_valid_nodes(force=False)
        except Exception as e:
            print(f"[守护线程] 维护周期异常: {e}", flush=True)
            utils.log_to_json("ERROR", "Main", f"维护周期异常: {e}")
        state.last_collector_heartbeat = time.time()
        time.sleep(config.CHECK_INTERVAL_SECONDS)