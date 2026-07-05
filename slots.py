#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import threading
import time
import sys
import os
import signal
from pathlib import Path
from typing import Any
from collections import defaultdict

import vpn_utils
import proxy_server

import config
import state
import utils
import openvpn
import subprocess
import ipaddress      # 新增用于 IP 校验

# ---------- 槽位全局变量 ----------
exit_slots_lock = threading.RLock()
exit_slots_supervise_lock = threading.Lock()
exit_slots: dict[int, dict[str, Any]] = {}
exit_slot_proxy_stops: dict[int, threading.Event] = {}
slot_bad_nodes: dict[str, float] = {}
slot_egress_fail_counts: dict[int, int] = {}
last_exit_slots_heartbeat = 0.0
last_slot_egress_heartbeat = 0.0

# ---------- 历史管理 ----------
def load_slot_history() -> dict[str, list[str]]:
    """加载每个槽位使用过的节点ID列表"""
    if not config.SLOT_HISTORY_FILE.exists():
        return {}
    try:
        with open(config.SLOT_HISTORY_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_slot_history(history: dict[str, list[str]]) -> None:
    with open(config.SLOT_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def get_used_nodes(history: dict[str, list[str]]) -> set[str]:
    """获取所有已使用过的节点ID集合（全局去重）"""
    used = set()
    for ids in history.values():
        used.update(ids)
    return used

def record_node_used(slot: int, node_id: str) -> None:
    """记录某个槽位使用了某个节点"""
    history = load_slot_history()
    key = str(slot)
    if key not in history:
        history[key] = []
    if node_id not in history[key]:
        history[key].append(node_id)
    save_slot_history(history)

def reset_slot_history(slot: int = None) -> None:
    """重置历史记录，若指定slot则只重置该槽位，否则全部清空"""
    if slot is None:
        if config.SLOT_HISTORY_FILE.exists():
            config.SLOT_HISTORY_FILE.unlink()
    else:
        history = load_slot_history()
        history.pop(str(slot), None)
        save_slot_history(history)

# ---------- 辅助函数 ----------
def kill_slot_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        killed: list[int] = []
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
            if "openvpn" not in cmdline.lower() or config.SLOT_PROCESS_MARKER not in cmdline:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed.append(pid)
            except (ProcessLookupError, PermissionError):
                pass
        if killed:
            time.sleep(0.5)
            for pid in killed:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            print(f"[多出口] 启动清理遗留槽位隧道进程: {killed}", flush=True)
        for i in range(config.MAX_EXIT_SLOTS):
            openvpn.cleanup_policy_routing(config.SLOT_TABLE_BASE + i)
    except Exception as e:
        print(f"[多出口] 清理遗留槽位进程失败: {e}", flush=True)

def slot_device(i: int) -> str:
    return f"tun{config.SLOT_DEV_BASE + i}"

def slot_table(i: int) -> int:
    return config.SLOT_TABLE_BASE + i

def slot_port(i: int) -> int:
    return config.SLOT_PORT_BASE + i

def slot_config_path(i: int) -> Path:
    return config.CONFIG_DIR / f".slot_{i}.ovpn"

def _normalize_index_list(raw: Any) -> list[int]:
    out: set[int] = set()
    if isinstance(raw, (list, tuple)):
        for v in raw:
            try:
                iv = int(v)
            except (TypeError, ValueError):
                continue
            if 0 <= iv < config.MAX_EXIT_SLOTS:
                out.add(iv)
    return sorted(out)

def get_active_slots() -> list[int]:
    cfg = config.load_ui_config()
    if "exit_slot_active" in cfg:
        return _normalize_index_list(cfg.get("exit_slot_active"))
    count = config.bounded_int(cfg.get("exit_slot_count"), config.DEFAULT_EXIT_SLOTS, 50, config.MAX_EXIT_SLOTS)
    return list(range(count))

def get_paused_slots() -> set[int]:
    cfg = config.load_ui_config()
    return set(_normalize_index_list(cfg.get("exit_slot_paused")))

def _save_slot_lists(cfg: dict[str, Any], active: list[int] | None = None, paused: set[int] | None = None) -> None:
    if active is not None:
        cfg["exit_slot_active"] = active
        cfg["exit_slot_count"] = len(active)
    if paused is not None:
        cfg["exit_slot_paused"] = sorted(paused)
    auth_file = config.DATA_DIR / "ui_auth.json"
    config.DATA_DIR.mkdir(exist_ok=True, parents=True)
    auth_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

def get_exit_slot_config() -> dict[str, Any]:
    cfg = config.load_ui_config()
    active = get_active_slots()
    return {
        "count": len(active),
        "active": active,
        "paused": sorted(get_paused_slots() & set(active)),
        "country": str(cfg.get("exit_slot_country", "") or "").strip().upper(),
        "isp": str(cfg.get("exit_slot_isp", "") or "").strip(),
        "residential_only": bool(cfg.get("exit_slot_residential_only", False)),
    }

def set_exit_slot_config(count: Any = None, country: Any = None, residential_only: Any = None, isp: Any = None) -> dict[str, Any]:
    with state.lock:
        cfg = config.load_ui_config()
        active = paused = None
        if count is not None:
            n = config.bounded_int(count, config.DEFAULT_EXIT_SLOTS, 0, config.MAX_EXIT_SLOTS)
            active = list(range(n))
            paused = get_paused_slots() & set(active)
        if country is not None:
            cfg["exit_slot_country"] = str(country or "").strip().upper()
        if isp is not None:
            cfg["exit_slot_isp"] = str(isp or "").strip()
        if residential_only is not None:
            cfg["exit_slot_residential_only"] = bool(residential_only)
        try:
            _save_slot_lists(cfg, active, paused)
        except Exception as e:
            print(f"[多出口] 保存槽位配置失败: {e}", flush=True)
    return get_exit_slot_config()

def add_one_slot() -> dict[str, Any]:
    with state.lock:
        active = get_active_slots()
        if len(active) >= config.MAX_EXIT_SLOTS:
            return {"ok": False, "error": f"已达到最大出口数量 {config.MAX_EXIT_SLOTS}"}
        free = next((i for i in range(config.MAX_EXIT_SLOTS) if i not in active), None)
        if free is None:
            return {"ok": False, "error": f"已达到最大出口数量 {config.MAX_EXIT_SLOTS}"}
        active = sorted(active + [free])
        cfg = config.load_ui_config()
        _save_slot_lists(cfg, active=active)
    threading.Thread(target=supervise_exit_slots_once, daemon=True).start()
    return {"ok": True, "slot": free, "port": slot_port(free), "message": f"已新增槽位 #{free}（端口 {slot_port(free)}）"}

def delete_slot(i: int) -> dict[str, Any]:
    with state.lock:
        active = get_active_slots()
        if i not in active:
            return {"ok": False, "error": f"槽位 #{i} 不存在"}
        active = [x for x in active if x != i]
        cfg = config.load_ui_config()
        paused = get_paused_slots(); paused.discard(i)
        cmap = cfg.get("exit_slot_country_map");  cmap.pop(str(i), None) if isinstance(cmap, dict) else None
        pmap = cfg.get("exit_slot_pin_map");      pmap.pop(str(i), None) if isinstance(pmap, dict) else None
        _save_slot_lists(cfg, active=active, paused=paused)
    tear_down_slot(i, stop_proxy=True)
    write_slots_state()
    return {"ok": True, "slot": i, "message": f"已删除槽位 #{i}"}

def stop_slot(i: int) -> dict[str, Any]:
    with state.lock:
        active = get_active_slots()
        if i not in active:
            return {"ok": False, "error": f"槽位 #{i} 不存在"}
        cfg = config.load_ui_config()
        paused = get_paused_slots(); paused.add(i)
        _save_slot_lists(cfg, paused=paused)
    tear_down_slot(i, stop_proxy=True)
    mark_slot_paused(i)
    write_slots_state()
    return {"ok": True, "slot": i, "message": f"已停止槽位 #{i}"}

def start_slot(i: int) -> dict[str, Any]:
    with state.lock:
        active = get_active_slots()
        if i not in active:
            return {"ok": False, "error": f"槽位 #{i} 不存在"}
        cfg = config.load_ui_config()
        paused = get_paused_slots(); paused.discard(i)
        _save_slot_lists(cfg, paused=paused)
    threading.Thread(target=supervise_exit_slots_once, daemon=True).start()
    return {"ok": True, "slot": i, "message": f"已启动槽位 #{i}"}

def get_slot_country_map() -> dict[str, str]:
    cfg = config.load_ui_config()
    raw = cfg.get("exit_slot_country_map") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v or "").strip().upper() for k, v in raw.items()}

def per_slot_country(i: int) -> str:
    return get_slot_country_map().get(str(i), "") or get_exit_slot_config()["country"]

def get_slot_isp_map() -> dict[str, str]:
    cfg = config.load_ui_config()
    raw = cfg.get("exit_slot_isp_map") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v or "").strip() for k, v in raw.items()}

def per_slot_isp(i: int) -> str:
    return get_slot_isp_map().get(str(i), "") or get_exit_slot_config().get("isp", "")

def set_slot_isp(i: int, isp: Any) -> dict[str, str]:
    with state.lock:
        auth_file = config.DATA_DIR / "ui_auth.json"
        cfg = config.load_ui_config()
        m_ = cfg.get("exit_slot_isp_map")
        if not isinstance(m_, dict):
            m_ = {}
        val = str(isp or "").strip()
        if val:
            m_[str(i)] = val
        else:
            m_.pop(str(i), None)
        cfg["exit_slot_isp_map"] = m_
        try:
            config.DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[多出口] 保存槽位 ISP 失败: {e}", flush=True)
    return get_slot_isp_map()

def get_slot_pin_map() -> dict[str, str]:
    cfg = config.load_ui_config()
    raw = cfg.get("exit_slot_pin_map") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v}

def set_slot_pin(i: int, node_id: Any) -> dict[str, str]:
    with state.lock:
        auth_file = config.DATA_DIR / "ui_auth.json"
        cfg = config.load_ui_config()
        pm = cfg.get("exit_slot_pin_map")
        if not isinstance(pm, dict):
            pm = {}
        nid = str(node_id or "").strip()
        if nid:
            pm[str(i)] = nid
        else:
            pm.pop(str(i), None)
        cfg["exit_slot_pin_map"] = pm
        try:
            config.DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[多出口] 保存槽位锁定失败: {e}", flush=True)
    return get_slot_pin_map()

def set_slot_country(i: int, country: Any) -> dict[str, str]:
    with state.lock:
        auth_file = config.DATA_DIR / "ui_auth.json"
        cfg = config.load_ui_config()
        cmap = cfg.get("exit_slot_country_map")
        if not isinstance(cmap, dict):
            cmap = {}
        val = str(country or "").strip().upper()
        if val:
            cmap[str(i)] = val
        else:
            cmap.pop(str(i), None)
        cfg["exit_slot_country_map"] = cmap
        try:
            config.DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[多出口] 保存槽位地区失败: {e}", flush=True)
    return get_slot_country_map()

def current_slot_node_ids() -> set[str]:
    with exit_slots_lock:
        return {s.get("node_id") for s in exit_slots.values() if s.get("node_id")}

def pick_slot_node(i: int, used_ids: set[str]) -> dict[str, Any] | None:
    pin = get_slot_pin_map().get(str(i))
    if pin and pin not in used_ids:
        node = next((n for n in state.read_nodes()
                     if n.get("id") == pin and n.get("probe_status") == "available"), None)
        if node:
            return node
    cfg = get_exit_slot_config()
    picks = select_slot_nodes(used_ids, 1, per_slot_country(i), cfg["residential_only"], per_slot_isp(i))
    return picks[0] if picks else None

def select_slot_nodes(used_ids: set[str], need: int, country: str, residential_only: bool, isp: str = "", exclude_history: bool = True) -> list[dict[str, Any]]:
    if need <= 0:
        return []
    countries = [c.strip() for c in country.split(",") if c.strip()] if country else []
    isp_kws = [k.strip().lower() for k in isp.split(",") if k.strip()] if isp else []
    now = time.time()
    bad = {nid for nid, until in slot_bad_nodes.items() if until > now}
    pool: list[dict[str, Any]] = []
    history = load_slot_history() if exclude_history else {}
    used_history = get_used_nodes(history) if exclude_history else set()
    
    for n in state.read_nodes():
        if n.get("id") in used_ids or n.get("id") in bad:
            continue
        if exclude_history and n.get("id") in used_history:
            continue
        if n.get("probe_status") != "available":
            continue
        if residential_only and n.get("ip_type") not in ("residential", "mobile"):
            continue
        if countries and str(n.get("country_short", "")).upper() not in countries:
            continue
        if isp_kws:
            hay = (str(n.get("owner", "")) + " " + str(n.get("as_name", "")) + " " + str(n.get("asn", ""))).lower()
            if not any(kw in hay for kw in isp_kws):
                continue
        pool.append(n)
    pool.sort(key=lambda n: (utils.parse_int(n.get("latency_ms")) or 999999, -utils.parse_int(n.get("score"))))
    return pool[:need]

def ensure_slot_proxy(i: int) -> None:
    with exit_slots_lock:
        if i in exit_slot_proxy_stops:
            return
        stop_ev = threading.Event()
        exit_slot_proxy_stops[i] = stop_ev
    threading.Thread(
        target=proxy_server.start_proxy_server,
        args=(config.SLOT_PROXY_HOST, slot_port(i), slot_device(i), stop_ev),
        daemon=True,
    ).start()

def bring_up_slot(i: int, node: dict[str, Any]) -> bool:
    dev = slot_device(i)
    cfg_path = slot_config_path(i)
    try:
        config.CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        cfg_path.write_text(node.get("config_text") or "", encoding="utf-8")
    except Exception as e:
        print(f"[多出口] 槽位 {i} 写入配置失败: {e}", flush=True)
        return False

    extra = ["--setenv", config.SLOT_PROCESS_MARKER, str(i)]
    ok, message, process = openvpn.run_openvpn_until_ready(
        str(cfg_path), keep_alive=True, route_nopull=True,
        timeout=config.OPENVPN_TEST_TIMEOUT_SECONDS, dev=dev, extra_args=extra,
        report_status=False,
    )
    if not ok or process is None:
        print(f"[多出口] 槽位 {i} 节点 {node.get('id')} 连接失败: {message}", flush=True)
        # 将节点加入冷却，避免反复尝试
        node_id = node.get('id')
        if node_id:
            slot_bad_nodes[node_id] = time.time() + config.SLOT_BAD_NODE_COOLDOWN
            print(f"[多出口] 节点 {node_id} 已加入冷却 {config.SLOT_BAD_NODE_COOLDOWN}s", flush=True)
        try:
            if cfg_path.exists():
                cfg_path.unlink()
        except Exception:
            pass
        return False

    openvpn.setup_policy_routing(dev, slot_table(i))
    ensure_slot_proxy(i)
    with exit_slots_lock:
        exit_slots[i] = {
            "slot": i, "device": dev, "table": slot_table(i), "port": slot_port(i),
            "node_id": node.get("id"), "country": node.get("country"),
            "country_short": node.get("country_short"),
            "ip": node.get("ip") or node.get("remote_host"),
            "ip_type": node.get("ip_type"), "location": node.get("location"),
            "owner": node.get("owner"), "latency_ms": node.get("latency_ms"),
            "process": process, "status": "up", "since": time.time(), "message": "",
        }
    record_node_used(i, node.get("id"))
    print(f"[多出口] 槽位 {i} 已就绪: {node.get('country')} {node.get('ip')} -> 代理 127.0.0.1:{slot_port(i)} (设备 {dev})", flush=True)
    utils.log_to_json("INFO", "MultiExit", f"槽位 {i} 就绪: {node.get('country')} {node.get('ip')} 端口 {slot_port(i)}")
    return True

def mark_slot_pending(i: int, reason: str) -> None:
    with exit_slots_lock:
        exit_slots[i] = {
            "slot": i, "device": slot_device(i), "table": slot_table(i), "port": slot_port(i),
            "node_id": "", "country": "", "country_short": "", "ip": "", "ip_type": "",
            "location": "", "owner": "", "latency_ms": 0,
            "process": None, "status": "pending", "since": time.time(), "message": reason,
        }

def mark_slot_paused(i: int) -> None:
    with exit_slots_lock:
        exit_slots[i] = {
            "slot": i, "device": slot_device(i), "table": slot_table(i), "port": slot_port(i),
            "node_id": "", "country": "", "country_short": "", "ip": "", "ip_type": "",
            "location": "", "owner": "", "latency_ms": 0,
            "process": None, "status": "paused", "since": time.time(), "message": "已手动停止",
        }

def tear_down_slot(i: int, stop_proxy: bool = True) -> None:
    with exit_slots_lock:
        slot = exit_slots.pop(i, None)
        stop_ev = exit_slot_proxy_stops.pop(i, None) if stop_proxy else None
    if slot and slot.get("process"):
        openvpn.stop_process(slot["process"])
    openvpn.cleanup_policy_routing(slot_table(i))
    try:
        p = slot_config_path(i)
        if p.exists():
            p.unlink()
    except Exception:
        pass
    if stop_proxy and stop_ev is not None:
        stop_ev.set()
        print(f"[多出口] 槽位 {i} 已拆除（含代理端口 {slot_port(i)}）", flush=True)

def slot_process_alive(i: int) -> bool:
    with exit_slots_lock:
        slot = exit_slots.get(i)
    if not slot:
        return False
    p = slot.get("process")
    return p is not None and p.poll() is None

def write_slots_state() -> None:
    country_map = get_slot_country_map()
    isp_map = get_slot_isp_map()
    with exit_slots_lock:
        snapshot = []
        for i in sorted(exit_slots.keys()):
            s = exit_slots[i]
            p = s.get("process")
            alive = p is not None and p.poll() is None
            snapshot.append({
                "slot": i, "device": s.get("device"), "port": s.get("port"),
                "node_id": s.get("node_id", ""), "country": s.get("country", ""),
                "country_short": s.get("country_short", ""), "ip": s.get("ip", ""),
                "ip_type": s.get("ip_type", ""), "location": s.get("location", ""),
                "owner": s.get("owner", ""), "latency_ms": s.get("latency_ms", 0),
                "status": "up" if alive else s.get("status", "down"),
                "message": s.get("message", ""), "since": s.get("since", 0),
                "country_filter": country_map.get(str(i), ""),
                "isp_filter": isp_map.get(str(i), ""),
                "exit_ip": s.get("exit_ip", ""),
                "egress_ok": s.get("egress_ok"),
            })
    cfg = get_exit_slot_config()
    state.write_json(config.SLOTS_FILE, {
        "updated_at": time.time(), "desired_count": cfg["count"],
        "country": cfg["country"], "residential_only": cfg["residential_only"],
        "proxy_host": "0.0.0.0", "slots": snapshot,
    })

def build_3xui_outbounds() -> dict[str, Any]:
    with exit_slots_lock:
        live = [dict(s) for i, s in sorted(exit_slots.items())
                if s.get("process") is not None and s["process"].poll() is None]
    outbounds = []
    rules = []
    for s in live:
        tag = f"res-{s['slot']}-{(s.get('country_short') or 'XX').lower()}"
        outbounds.append({
            "tag": tag, "protocol": "socks",
            "settings": {"servers": [{"address": "127.0.0.1", "port": s["port"]}]},
        })
        rules.append({"type": "field", "inboundTag": [f"inbound-{s['slot']}"], "outboundTag": tag})
    return {
        "_note": "将 outbounds 合并进 3x-ui 的 Xray 配置；routing.rules 里的 inboundTag 改成你的实际 inbound 标签即可实现每入站走一个住宅出口。",
        "outbounds": outbounds,
        "routing": {"rules": rules},
    }

def supervise_exit_slots_once() -> None:
    if not exit_slots_supervise_lock.acquire(blocking=False):
        return
    try:
        active = set(get_active_slots())
        paused = get_paused_slots() & active

        with exit_slots_lock:
            known_indices = sorted(set(exit_slots.keys()) | set(exit_slot_proxy_stops.keys()))
        for i in known_indices:
            if i not in active:
                tear_down_slot(i, stop_proxy=True)

        all_nodes = state.read_nodes()
        node_status_map = {n.get('id'): n.get('probe_status') for n in all_nodes}
        available_nodes = [n for n in all_nodes if n.get('probe_status') == 'available']
        if not available_nodes:
            print("[多出口] 没有可用节点，跳过本轮启动", flush=True)
            write_slots_state()
            return

        reserved_node_ids = set(current_slot_node_ids())
        tasks = []

        slot_residential_only = get_exit_slot_config().get('residential_only', True)
        global_country = get_exit_slot_config().get('country', '')
        global_isp = get_exit_slot_config().get('isp', '')

        for i in sorted(active):
            if i in paused:
                if (i in exit_slot_proxy_stops) or (i in exit_slots and exit_slots[i].get('process') is not None):
                    tear_down_slot(i, stop_proxy=True)
                mark_slot_paused(i)
                continue

            if slot_process_alive(i):
                with exit_slots_lock:
                    s = exit_slots.get(i)
                    current_node_id = s.get("node_id") if s else None
                if current_node_id:
                    if node_status_map.get(current_node_id) != "available":
                        print(f"[多出口] 槽位 {i} 的节点 {current_node_id} 已失效，强制拆除并重新分配", flush=True)
                        tear_down_slot(i, stop_proxy=True)
                    else:
                        continue
                else:
                    tear_down_slot(i, stop_proxy=True)

            tear_down_slot(i, stop_proxy=False)

            country = per_slot_country(i) or global_country
            isp = per_slot_isp(i) or global_isp

            # 使用 select_slot_nodes 选择节点（自动排除坏节点和历史记录）
            candidates = select_slot_nodes(
                used_ids=reserved_node_ids,
                need=1,
                country=country,
                residential_only=slot_residential_only,
                isp=isp,
                exclude_history=True
            )
            if candidates:
                candidate = candidates[0]
                reserved_node_ids.add(candidate['id'])
                tasks.append((i, candidate))
            else:
                # 若无候选，清空历史并重试（忽略历史）
                reset_slot_history()
                candidates = select_slot_nodes(
                    used_ids=reserved_node_ids,
                    need=1,
                    country=country,
                    residential_only=slot_residential_only,
                    isp=isp,
                    exclude_history=False
                )
                if candidates:
                    candidate = candidates[0]
                    reserved_node_ids.add(candidate['id'])
                    tasks.append((i, candidate))
                else:
                    mark_slot_pending(i, f"暂无可用节点（{country or '不限地区'}），等待节点池补齐")

        max_parallel = min(20, len(tasks))
        if tasks:
            print(f"[多出口] 共 {len(tasks)} 个槽位待启动，并发数 {max_parallel}...", flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as executor:
                future_to_slot = {
                    executor.submit(_bring_up_wrapper, i, node): i
                    for i, node in tasks
                }
                for future in concurrent.futures.as_completed(future_to_slot):
                    idx = future_to_slot[future]
                    try:
                        ok = future.result()
                        if not ok:
                            mark_slot_pending(idx, "并发启动连接失败，待重试")
                    except Exception as e:
                        print(f"[多出口] 槽位 {idx} 并发启动异常: {e}", flush=True)
                        mark_slot_pending(idx, f"启动异常: {e}")

        write_slots_state()
    finally:
        exit_slots_supervise_lock.release()

def _bring_up_wrapper(i: int, node: dict) -> bool:
    try:
        return bring_up_slot(i, node)
    except Exception as e:
        print(f"[多出口] 槽位 {i} bring_up 内部异常: {e}", flush=True)
        return False

def switch_slot_node(i: int) -> dict[str, Any]:
    cfg = get_exit_slot_config()
    if i not in cfg["active"]:
        return {"ok": False, "error": f"槽位 #{i} 不存在"}
    if i in cfg["paused"]:
        return {"ok": False, "error": f"槽位 #{i} 已停止，请先启动再换 IP"}
    if not exit_slots_supervise_lock.acquire(blocking=False):
        return {"ok": False, "error": "供给器正忙，请稍后重试"}
    try:
        set_slot_pin(i, "")
        used = current_slot_node_ids()
        picks = select_slot_nodes(used, 1, per_slot_country(i), cfg["residential_only"], per_slot_isp(i), exclude_history=True)
        if not picks:
            return {"ok": False, "error": "没有其他可用住宅节点可切换（可放宽地区/运营商过滤或稍后重试）"}
        tear_down_slot(i, stop_proxy=False)
        if bring_up_slot(i, picks[0]):
            write_slots_state()
            return {"ok": True, "ip": picks[0].get("ip"), "country": picks[0].get("country")}
        mark_slot_pending(i, "手动切换后连接失败，待自动重试")
        write_slots_state()
        return {"ok": False, "error": f"切换到节点 {picks[0].get('id')} 失败，将自动重试"}
    finally:
        exit_slots_supervise_lock.release()

def assign_node_to_slot(i: int, node_id: str) -> dict[str, Any]:
    cfg = get_exit_slot_config()
    if i not in cfg["active"]:
        return {"ok": False, "error": f"槽位 #{i} 不存在"}
    node_id = str(node_id or "").strip()
    node = next((n for n in state.read_nodes() if n.get("id") == node_id), None)
    if not node:
        return {"ok": False, "error": "未找到该节点"}
    if node.get("probe_status") != "available":
        return {"ok": False, "error": "该节点当前不可用，请先在列表中检测/更新"}
    with exit_slots_lock:
        for idx, s in exit_slots.items():
            if idx != i and s.get("node_id") == node_id:
                return {"ok": False, "error": f"该节点已被槽位 #{idx} 使用，无法重复分配"}
    if not exit_slots_supervise_lock.acquire(blocking=False):
        return {"ok": False, "error": "供给器正忙，请稍后重试"}
    try:
        with state.lock:
            _cfg = config.load_ui_config()
            _paused = get_paused_slots(); _paused.discard(i)
            _save_slot_lists(_cfg, paused=_paused)
        set_slot_pin(i, node_id)
        tear_down_slot(i, stop_proxy=False)
        if bring_up_slot(i, node):
            write_slots_state()
            return {"ok": True, "slot": i, "ip": node.get("ip"), "country": node.get("country")}
        mark_slot_pending(i, f"分配节点 {node_id} 后连接失败，待自动重试")
        write_slots_state()
        return {"ok": False, "error": f"分配到槽位 #{i} 失败，将自动重试"}
    finally:
        exit_slots_supervise_lock.release()

def add_slot_with_node(node_id: str) -> dict[str, Any]:
    node_id = str(node_id or "").strip()
    node = next((n for n in state.read_nodes() if n.get("id") == node_id), None)
    if not node:
        return {"ok": False, "error": "未找到该节点"}
    if node.get("probe_status") != "available":
        return {"ok": False, "error": "该节点当前不可用，请先在列表中检测/更新"}
    with exit_slots_lock:
        for idx, s in exit_slots.items():
            if s.get("node_id") == node_id:
                return {"ok": False, "error": f"该节点已被槽位 #{idx} 使用"}
    with state.lock:
        active = get_active_slots()
        if len(active) >= config.MAX_EXIT_SLOTS:
            return {"ok": False, "error": f"已达到最大出口数量 {config.MAX_EXIT_SLOTS}"}
        new_idx = next((i for i in range(config.MAX_EXIT_SLOTS) if i not in active), None)
        if new_idx is None:
            return {"ok": False, "error": f"已达到最大出口数量 {config.MAX_EXIT_SLOTS}"}
        active = sorted(active + [new_idx])
        cfg = config.load_ui_config()
        _save_slot_lists(cfg, active=active)
    set_slot_pin(new_idx, node_id)
    result = assign_node_to_slot(new_idx, node_id)
    if result.get("ok"):
        result["message"] = f"已新增槽位 #{new_idx}（端口 {slot_port(new_idx)}）并锁定该节点"
    return result

def rotate_exit_slots(count: int, country: str = "", isp: str = "", residential_only: bool = True) -> dict[str, Any]:
    """设置槽位数量并全量轮换，确保每个槽位使用未被任何槽位使用过的节点"""
    # 先设置槽位配置
    result = set_exit_slot_config(count=count, country=country, residential_only=residential_only, isp=isp)
    if result.get("count", 0) == 0:
        return {"ok": True, "message": "出口已关闭"}
    
    # 强制重新分配所有槽位，使用历史排除
    with exit_slots_supervise_lock:
        # 拆除所有现有槽位
        for i in list(exit_slots.keys()):
            tear_down_slot(i, stop_proxy=True)
        # 重新启动
        supervise_exit_slots_once()
    return {"ok": True, "message": f"已重新分配 {count} 个出口，每个使用不同IP"}

# ========== 修复后的出口检测函数 ==========
def check_slot_egress(port: int) -> tuple[bool, str]:
    """
    通过 SOCKS5 代理检测出口是否可用。
    依次尝试多个公网 IP 查询端点，严格验证返回的是公网 IP 地址且 HTTP 状态码为 200。
    """
    endpoints = ["https://icanhazip.com", "http://ip.sb", "http://api.ipify.org", "http://ifconfig.me", "https://cip.cc"]
    for url in endpoints:
        try:
            # 使用 -w 获取 HTTP 状态码，并分离响应体
            res = subprocess.run(
                ["curl", "-s", "-x", f"socks5h://127.0.0.1:{port}", url,
                 "--max-time", "6", "-w", "%{http_code}"],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode != 0:
                continue

            stdout = res.stdout.strip()
            if len(stdout) < 3:
                continue

            # 取最后 3 位作为状态码，前面部分为响应体
            http_code = stdout[-3:]
            body = stdout[:-3].strip()

            if http_code != "200" or not body:
                continue

            # 严格验证是否为公网 IP（IPv4 或 IPv6）
            try:
                ip = ipaddress.ip_address(body)
                # 排除私有、回环、链路本地等非公网地址
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                    continue
                return True, str(ip)
            except ValueError:
                # 不是有效的 IP 地址
                continue
        except Exception:
            continue
    return False, ""

def slot_egress_checker_loop() -> None:
    global last_slot_egress_heartbeat
    time.sleep(20)
    while True:
        last_slot_egress_heartbeat = time.time()
        try:
            active = set(get_active_slots())
            paused = get_paused_slots()
            for i in sorted(active):
                if i in paused:
                    continue
                if not slot_process_alive(i):
                    continue
                ok, ip = check_slot_egress(slot_port(i))
                with exit_slots_lock:
                    s = exit_slots.get(i)
                    if s is not None:
                        s["exit_ip"] = ip if ok else ""
                        s["egress_ok"] = ok
                    nid = s.get("node_id") if s else ""
                if ok:
                    slot_egress_fail_counts[i] = 0
                    continue
                slot_egress_fail_counts[i] = slot_egress_fail_counts.get(i, 0) + 1
                if slot_egress_fail_counts[i] < config.SLOT_EGRESS_FAIL_THRESHOLD:
                    continue
                slot_egress_fail_counts[i] = 0
                if nid:
                    slot_bad_nodes[nid] = time.time() + config.SLOT_BAD_NODE_COOLDOWN
                print(f"[多出口] 槽位 {i} 节点 {nid} 出口不通，强制拆除并切换", flush=True)
                utils.log_to_json("WARNING", "MultiExit", f"槽位 {i} 节点 {nid} 出口不通，强制漂移")
                tear_down_slot(i, stop_proxy=True)
                threading.Thread(target=supervise_exit_slots_once, daemon=True).start()
        except Exception as e:
            print(f"[多出口] 出口健康检测异常: {e}", flush=True)
        time.sleep(config.SLOT_EGRESS_CHECK_INTERVAL)

def exit_slots_loop() -> None:
    global last_exit_slots_heartbeat
    while True:
        nodes = state.read_nodes()
        available = [n for n in nodes if n.get("probe_status") == "available"]
        if not available:
            print("[多出口] 等待节点池就绪（尚无可用节点），30秒后重试...", flush=True)
            time.sleep(30)
            continue
        last_exit_slots_heartbeat = time.time()
        try:
            supervise_exit_slots_once()
        except Exception as e:
            print(f"[多出口] 供给器循环异常: {e}", flush=True)
            utils.log_to_json("ERROR", "MultiExit", f"供给器循环异常: {e}")
        time.sleep(config.EXIT_SLOTS_CHECK_INTERVAL)