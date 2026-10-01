#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
import threading
from pathlib import Path
from typing import Any

import config
import utils

# ---------- 全局锁 ----------
lock = threading.RLock()
maintenance_lock = threading.Lock()

# ---------- 全局状态变量 ----------
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None   # 需导入 subprocess
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0
main_egress_fail_count = 0
main_bad_nodes: dict[str, float] = {}
main_proxy_registry = None   # 在 manager 中初始化

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

# ---------- 状态读写函数 ----------
def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(config.NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(config.STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", config.API_URL)
    state.setdefault("target_valid_nodes", config.TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", config.FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", config.CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{config.LOCAL_PROXY_HOST}]" if ":" in config.LOCAL_PROXY_HOST else config.LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{config.LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)

    ui_cfg = config.load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["routing_isp"] = ui_cfg.get("routing_isp", "")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    return state

def set_state(**updates: Any) -> None:
    """更新持久化状态。关键字段相对磁盘无变化时跳过写盘，降低 pinger/checker 的 IO。"""
    if not updates:
        return
    with lock:
        try:
            current = json.loads(config.STATE_FILE.read_text(encoding="utf-8"))
            if not isinstance(current, dict):
                current = {}
        except (OSError, json.JSONDecodeError):
            current = {}
        changed = False
        for k, v in updates.items():
            if current.get(k) != v:
                current[k] = v
                changed = True
        if not changed:
            return
        tmp = config.STATE_FILE.with_suffix(config.STATE_FILE.suffix + ".tmp")
        tmp.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(config.STATE_FILE)
