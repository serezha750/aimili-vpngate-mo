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
import socket
import ipaddress
import subprocess

import vpn_utils
import proxy_server

import config
import state
import utils
import openvpn

# ---------- 槽位全局变量 ----------
exit_slots_lock = threading.RLock()
exit_slots_supervise_lock = threading.Lock()
exit_slots: dict[int, dict[str, Any]] = {}
exit_slot_proxy_stops: dict[int, threading.Event] = {}
slot_bad_nodes: dict[str, float] = {}
slot_egress_fail_counts: dict[int, int] = {}
last_exit_slots_heartbeat = 0.0
last_slot_egress_heartbeat = 0.0
exit_slots_wake = threading.Event()  # 有槽位变化时唤醒供给循环，避免干等

# ---------- 历史管理（内存缓存 + 延迟刷盘，避免频繁磁盘 IO） ----------
_slot_history_cache: dict[str, list[str]] | None = None
_slot_history_dirty: bool = False
_slot_history_lock = threading.RLock()
_SLOT_HISTORY_FLUSH_INTERVAL = 5.0  # 秒：脏数据最长滞留时间
_last_history_flush = 0.0


def _read_history_from_disk() -> dict[str, list[str]]:
    if not config.SLOT_HISTORY_FILE.exists():
        return {}
    try:
        with open(config.SLOT_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # 规范化 value 为 list[str]
            out: dict[str, list[str]] = {}
            for k, v in data.items():
                if isinstance(v, list):
                    out[str(k)] = [str(x) for x in v]
                elif v is not None:
                    out[str(k)] = [str(v)]
            return out
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as e:
        print(f"[多出口] 读取 slot_history 失败，使用空历史: {e}", flush=True)
    return {}


def _write_history_to_disk(history: dict[str, list[str]]) -> None:
    try:
        config.SLOT_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = config.SLOT_HISTORY_FILE.with_suffix(config.SLOT_HISTORY_FILE.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        tmp.replace(config.SLOT_HISTORY_FILE)
    except OSError as e:
        print(f"[多出口] 写入 slot_history 失败: {e}", flush=True)


def load_slot_history() -> dict[str, list[str]]:
    """返回内存中的历史副本（只读场景可直接用，写场景请走 record/reset）。"""
    global _slot_history_cache
    with _slot_history_lock:
        if _slot_history_cache is None:
            _slot_history_cache = _read_history_from_disk()
        # 返回浅拷贝，避免外部直接改缓存
        return {k: list(v) for k, v in _slot_history_cache.items()}


def flush_slot_history(force: bool = False) -> None:
    """将脏缓存刷到磁盘。force=True 时无条件写入。"""
    global _slot_history_dirty, _last_history_flush
    with _slot_history_lock:
        if _slot_history_cache is None:
            return
        if not force and not _slot_history_dirty:
            return
        _write_history_to_disk(_slot_history_cache)
        _slot_history_dirty = False
        _last_history_flush = time.time()


def _maybe_flush_history() -> None:
    """脏数据超过间隔则刷盘。"""
    global _last_history_flush
    with _slot_history_lock:
        if not _slot_history_dirty:
            return
        if time.time() - _last_history_flush < _SLOT_HISTORY_FLUSH_INTERVAL:
            return
    flush_slot_history(force=True)


def save_slot_history(history: dict[str, list[str]]) -> None:
    """兼容旧接口：更新缓存并标记脏，再尝试按间隔刷盘。"""
    global _slot_history_cache, _slot_history_dirty
    with _slot_history_lock:
        _slot_history_cache = {str(k): list(v) if isinstance(v, list) else [str(v)] for k, v in history.items()}
        _slot_history_dirty = True
    _maybe_flush_history()


def get_used_nodes(history: dict[str, list[str]]) -> set[str]:
    used: set[str] = set()
    for ids in history.values():
        used.update(ids)
    return used


def record_node_used(slot: int, node_id: str) -> None:
    if not node_id:
        return
    global _slot_history_cache, _slot_history_dirty
    with _slot_history_lock:
        if _slot_history_cache is None:
            _slot_history_cache = _read_history_from_disk()
        key = str(slot)
        lst = _slot_history_cache.setdefault(key, [])
        if node_id not in lst:
            lst.append(node_id)
            _slot_history_dirty = True
    _maybe_flush_history()


def reset_slot_history(slot: int | None = None) -> None:
    global _slot_history_cache, _slot_history_dirty
    with _slot_history_lock:
        if _slot_history_cache is None:
            _slot_history_cache = _read_history_from_disk()
        if slot is None:
            _slot_history_cache = {}
            _slot_history_dirty = True
            # 立即落盘并尽量删除文件，保持语义一致
            try:
                if config.SLOT_HISTORY_FILE.exists():
                    config.SLOT_HISTORY_FILE.unlink()
                _slot_history_dirty = False
            except OSError:
                # 删除失败则保留脏标记，稍后重试写入空对象
                pass
        else:
            if str(slot) in _slot_history_cache:
                _slot_history_cache.pop(str(slot), None)
                _slot_history_dirty = True
    if slot is not None:
        _maybe_flush_history()
    else:
        flush_slot_history(force=True)

# ---------- 辅助函数 ----------
def _kill_pids(pids: list[int], label: str = "") -> list[int]:
    """先 SIGTERM 再 SIGKILL，返回实际发出信号的 pid 列表。"""
    killed: list[int] = []
    for pid in pids:
        if pid <= 0 or pid == os.getpid():
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            killed.append(pid)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    if killed:
        time.sleep(0.3)
        for pid in killed:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        if label:
            print(f"[多出口] {label}: {killed}", flush=True)
    return killed


def _find_slot_openvpn_pids() -> list[int]:
    """查找带 SLOT_PROCESS_MARKER 的 openvpn 进程。优先 pgrep，回退 /proc 扫描。"""
    if not sys.platform.startswith("linux"):
        return []
    # 1) pgrep 更快
    try:
        res = subprocess.run(
            ["pgrep", "-f", f"openvpn.*{config.SLOT_PROCESS_MARKER}"],
            capture_output=True, text=True, timeout=3,
        )
        if res.returncode == 0 and res.stdout.strip():
            pids: list[int] = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
            return pids
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 2) 回退扫描 /proc
    pids = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return []
    try:
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
            pids.append(pid)
    except OSError:
        pass
    return pids


def kill_slot_openvpn_processes() -> None:
    """启动时清理遗留槽位隧道进程与策略路由。优先用已记录的 process/pid，再扫残留。"""
    if not sys.platform.startswith("linux"):
        return
    try:
        # 先停内存中仍持有的 process 对象
        tracked: list[int] = []
        with exit_slots_lock:
            for s in list(exit_slots.values()):
                p = s.get("process")
                if p is not None and getattr(p, "poll", lambda: None)() is None:
                    try:
                        tracked.append(int(p.pid))
                    except (TypeError, ValueError, AttributeError):
                        pass
                pid = s.get("pid")
                if isinstance(pid, int) and pid > 0:
                    tracked.append(pid)
        if tracked:
            _kill_pids(sorted(set(tracked)), "清理已跟踪槽位进程")

        # 再扫系统中可能残留的 AIMILI_SLOT openvpn
        orphans = _find_slot_openvpn_pids()
        if orphans:
            _kill_pids(orphans, "启动清理遗留槽位隧道进程")

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
    trigger_supervise_exit_slots()
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
    trigger_supervise_exit_slots()
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
    def _rank(n: dict[str, Any]) -> tuple:
        # 住宅/移动优先，再按延迟、分数
        ip_t = n.get("ip_type") or ""
        res_rank = 0 if ip_t in ("residential", "mobile") else 1
        lat = utils.parse_int(n.get("latency_ms")) or 999999
        score = -utils.parse_int(n.get("score"))
        return (res_rank, lat, score)
    pool.sort(key=_rank)
    return pool[:need]

# ---------- 代理启动与拆除 ----------
def ensure_slot_proxy(i: int) -> None:
    with exit_slots_lock:
        if i in exit_slot_proxy_stops:
            stop_ev = exit_slot_proxy_stops[i]
            if not stop_ev.is_set():
                return
            else:
                del exit_slot_proxy_stops[i]
        stop_ev = threading.Event()
        exit_slot_proxy_stops[i] = stop_ev
    threading.Thread(
        target=proxy_server.start_proxy_server,
        args=(config.SLOT_PROXY_HOST, slot_port(i), slot_device(i), stop_ev),
        daemon=True,
    ).start()

# ========== 新增：强制释放 tun 设备 ==========
def release_tun_device(dev: str) -> None:
    """强制释放指定的 tun 设备：杀掉占用进程并删除设备。优先 pgrep，避免全量 ps。"""
    pids: list[int] = []
    try:
        res = subprocess.run(
            ["pgrep", "-f", f"openvpn.*--dev {dev}"],
            capture_output=True, text=True, timeout=3,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,cmd"], capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "openvpn" in line and f"--dev {dev}" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        pids.append(int(parts[0]))
        except Exception as e:
            print(f"[release_tun_device] 查找进程失败: {e}", flush=True)

    if pids:
        _kill_pids(pids, f"释放设备 {dev} 占用进程")

    try:
        subprocess.run(
            ["ip", "tuntap", "del", dev, "mode", "tun"],
            stderr=subprocess.DEVNULL, timeout=2,
        )
        print(f"[release_tun_device] 已删除设备 {dev}", flush=True)
    except Exception:
        pass

# ---------- 启动时出口验证（带重试，类似 manager.py 的 check_proxy_health） ----------
_EGRESS_ENDPOINTS = (
    "http://api.ipify.org",
    "http://ip.sb",
    "http://ifconfig.me/ip",
    "http://icanhazip.com",
)


def _parse_public_ip(body: str) -> str | None:
    body = (body or "").strip()
    if not body or len(body) > 64:
        return None
    # 取第一行，避免部分站点尾部带多余文本
    body = body.splitlines()[0].strip()
    try:
        ip = ipaddress.ip_address(body)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return None
    return str(ip)


def _curl_one_egress(port: int, url: str, timeout: float) -> str | None:
    try:
        res = subprocess.run(
            [
                "curl", "-s", "-L", "--max-redirs", "2",
                "-x", f"socks5h://127.0.0.1:{port}",
                url,
                "--max-time", str(timeout),
                "-w", "\n%{http_code}",
            ],
            capture_output=True, text=True, timeout=timeout + 1.5,
        )
        if res.returncode != 0:
            return None
        lines = res.stdout.strip().splitlines()
        if len(lines) < 2:
            return None
        http_code = lines[-1].strip()
        body = "\n".join(lines[:-1]).strip()
        if http_code != "200":
            return None
        return _parse_public_ip(body)
    except Exception:
        return None


def probe_slot_egress(port: int, timeout: float | None = None) -> tuple[bool, str]:
    """经槽位 SOCKS5 并行探测公网出口 IP；任一端点成功即返回。"""
    t = float(timeout if timeout is not None else config.SLOT_EGRESS_CURL_TIMEOUT)
    endpoints = _EGRESS_ENDPOINTS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints))
    try:
        futs = {pool.submit(_curl_one_egress, port, url, t): url for url in endpoints}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=t + 2):
                try:
                    ip = fut.result()
                except Exception:
                    continue
                if ip:
                    return True, ip
        except concurrent.futures.TimeoutError:
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return False, ""


def wait_for_proxy_ready(port: int, max_attempts: int = 2, timeout_per_attempt: float | None = None) -> tuple[bool, str]:
    """启动后出口验证：并行多端点，失败可短暂重试。"""
    t = float(timeout_per_attempt if timeout_per_attempt is not None else config.SLOT_EGRESS_CURL_TIMEOUT)
    for attempt in range(max(1, max_attempts)):
        ok, ip = probe_slot_egress(port, timeout=t)
        if ok:
            return True, ip
        if attempt + 1 < max_attempts:
            time.sleep(0.4)
    return False, ""

# ---------- 核心：bring_up_slot（含释放设备与重试） ----------
def bring_up_slot(i: int, node: dict[str, Any]) -> bool:
    dev = slot_device(i)
    # ----- 启动前强制释放设备 -----
    release_tun_device(dev)

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

    # ----- 若启动失败且因设备繁忙，则释放并重试一次 -----
    if not ok or process is None:
        if "Device or resource busy" in message or "errno=16" in message:
            print(f"[多出口] 槽位 {i} 启动因设备繁忙失败，尝试释放设备并重试...", flush=True)
            release_tun_device(dev)
            ok, message, process = openvpn.run_openvpn_until_ready(
                str(cfg_path), keep_alive=True, route_nopull=True,
                timeout=config.OPENVPN_TEST_TIMEOUT_SECONDS, dev=dev, extra_args=extra,
                report_status=False,
            )

    if not ok or process is None:
        print(f"[多出口] 槽位 {i} 节点 {node.get('id')} 连接失败: {message}", flush=True)
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

    # 等待代理端口 TCP 就绪（快速检查，最多约 3s）
    tcp_ready = False
    for _ in range(8):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            sock.connect(("127.0.0.1", slot_port(i)))
            sock.close()
            tcp_ready = True
            break
        except Exception:
            time.sleep(0.35)
    if not tcp_ready:
        print(f"[多出口] 槽位 {i} 代理端口 {slot_port(i)} 无法在约 3 秒内就绪，视为失败", flush=True)
        tear_down_slot(i, stop_proxy=True)
        return False

    # 并行多端点出口验证（失败再短重试一次）
    egress_ok, egress_ip = wait_for_proxy_ready(slot_port(i), max_attempts=2)
    if not egress_ok:
        print(f"[多出口] 槽位 {i} 出口验证失败（多次尝试后仍不可用），节点 {node.get('id')} 不可用，拆除槽位", flush=True)
        node_id = node.get('id')
        if node_id:
            slot_bad_nodes[node_id] = time.time() + config.SLOT_BAD_NODE_COOLDOWN
            print(f"[多出口] 节点 {node_id} 已加入冷却 {config.SLOT_BAD_NODE_COOLDOWN}s", flush=True)
        reset_slot_history(i)
        tear_down_slot(i, stop_proxy=True)
        return False
    else:
        print(f"[多出口] 槽位 {i} 出口验证通过，出口 IP: {egress_ip}", flush=True)

    # 所有检查通过，记录状态
    pid_val = None
    try:
        if process is not None:
            pid_val = int(process.pid)
    except (TypeError, ValueError, AttributeError):
        pid_val = None
    with exit_slots_lock:
        exit_slots[i] = {
            "slot": i, "device": dev, "table": slot_table(i), "port": slot_port(i),
            "node_id": node.get("id"), "country": node.get("country"),
            "country_short": node.get("country_short"),
            "ip": node.get("ip") or node.get("remote_host"),
            "ip_type": node.get("ip_type"), "location": node.get("location"),
            "owner": node.get("owner"), "latency_ms": node.get("latency_ms"),
            "process": process, "pid": pid_val,
            "status": "up", "since": time.time(), "message": "",
            "exit_ip": egress_ip,
            "egress_ok": True,
        }
    record_node_used(i, node.get("id"))
    print(f"[多出口] 槽位 {i} 已就绪: {node.get('country')} {node.get('ip')} -> 代理 127.0.0.1:{slot_port(i)} (设备 {dev}) 出口IP {egress_ip}", flush=True)
    utils.log_to_json("INFO", "MultiExit", f"槽位 {i} 就绪: {node.get('country')} {node.get('ip')} 端口 {slot_port(i)} 出口IP {egress_ip}")
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
    if slot:
        proc = slot.get("process")
        if proc is not None:
            openvpn.stop_process(proc)
        else:
            pid = slot.get("pid")
            if isinstance(pid, int) and pid > 0:
                _kill_pids([pid])
    openvpn.cleanup_policy_routing(slot_table(i))
    try:
        p = slot_config_path(i)
        if p.exists():
            p.unlink()
    except OSError:
        pass
    if stop_proxy and stop_ev is not None:
        stop_ev.set()
        time.sleep(0.2)
        print(f"[多出口] 槽位 {i} 已拆除（含代理端口 {slot_port(i)}）", flush=True)

    # 删除 tun 设备（若仍存在）
    dev = slot_device(i)
    try:
        subprocess.run(
            ["ip", "tuntap", "del", dev, "mode", "tun"],
            stderr=subprocess.DEVNULL, timeout=2,
        )
    except Exception:
        pass
    # 历史可能刚被 reset/record，顺手刷一次（廉价 no-op 若未脏）
    flush_slot_history()

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

# ---------- 核心：自动切换（含多级回退选择） ----------
def _select_with_fallback(used_ids: set[str], country: str, residential_only: bool, isp: str) -> dict[str, Any] | None:
    """尝试多级回退选择节点，返回第一个成功的节点，若全部失败返回 None"""
    # 第一轮：严格过滤 + 排除历史
    candidates = select_slot_nodes(used_ids, 1, country, residential_only, isp, exclude_history=True)
    if candidates:
        return candidates[0]

    # 第二轮：清除历史重试
    reset_slot_history()  # 清空所有历史，避免永久排除
    candidates = select_slot_nodes(used_ids, 1, country, residential_only, isp, exclude_history=False)
    if candidates:
        return candidates[0]

    # 第三轮：放宽过滤（忽略运营商和住宅类型，保留地区）
    candidates = select_slot_nodes(used_ids, 1, country, False, "", exclude_history=False)
    if candidates:
        print(f"[多出口] 未找到符合运营商/住宅要求的节点，已放宽过滤条件", flush=True)
        return candidates[0]

    # 第四轮：彻底忽略所有过滤（仅排除坏节点和当前已用节点）
    candidates = select_slot_nodes(used_ids, 1, "", False, "", exclude_history=False)
    if candidates:
        print(f"[多出口] 未找到符合地区要求的节点，已忽略所有过滤条件", flush=True)
        return candidates[0]

    return None


def trigger_supervise_exit_slots() -> None:
    """立即异步调度一次槽位供给，并唤醒主循环。"""
    exit_slots_wake.set()
    threading.Thread(target=supervise_exit_slots_once, daemon=True).start()

def supervise_exit_slots_once() -> None:
    if not exit_slots_supervise_lock.acquire(blocking=False):
        return
    try:
        active = set(get_active_slots())
        paused = get_paused_slots() & active

        # 拆除不在 active 中的槽位
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

        slot_residential_only = get_exit_slot_config().get('residential_only', True)
        global_country = get_exit_slot_config().get('country', '')
        global_isp = get_exit_slot_config().get('isp', '')

        need_bringup: list[int] = []
        for i in sorted(active):
            if i in paused:
                if (i in exit_slot_proxy_stops) or (i in exit_slots and exit_slots[i].get("process") is not None):
                    tear_down_slot(i, stop_proxy=True)
                mark_slot_paused(i)
                continue

            # 检查现有连接是否有效
            if slot_process_alive(i):
                with exit_slots_lock:
                    s = exit_slots.get(i)
                    current_node_id = s.get("node_id") if s else None
                if current_node_id:
                    if node_status_map.get(current_node_id) != "available":
                        print(f"[多出口] 槽位 {i} 的节点 {current_node_id} 已失效，强制拆除并重新分配", flush=True)
                        reset_slot_history(i)
                        tear_down_slot(i, stop_proxy=True)
                        need_bringup.append(i)
                    else:
                        continue
                else:
                    tear_down_slot(i, stop_proxy=True)
                    need_bringup.append(i)
            else:
                tear_down_slot(i, stop_proxy=False)
                need_bringup.append(i)

        # 先串行选节点（保证各槽位节点不重复），再并行 bring_up 加速多出口就绪
        bringup_jobs: list[tuple[int, dict[str, Any]]] = []
        for i in need_bringup:
            country = per_slot_country(i) or global_country
            isp = per_slot_isp(i) or global_isp
            used = set(current_slot_node_ids()) | {n.get("id") for _, n in bringup_jobs if n.get("id")}
            candidate = _select_with_fallback(used, country, slot_residential_only, isp)
            if candidate:
                bringup_jobs.append((i, candidate))
            else:
                mark_slot_pending(i, "无任何可用节点（过滤条件过于严格或节点池为空）")

        if bringup_jobs:
            workers = min(config.SLOT_BRINGUP_CONCURRENCY, len(bringup_jobs))
            print(f"[多出口] 并行启动 {len(bringup_jobs)} 个槽位（并发 {workers}）", flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(_bring_up_wrapper, i, node): i for i, node in bringup_jobs}
                for fut in concurrent.futures.as_completed(futs):
                    i = futs[fut]
                    node = next(n for idx, n in bringup_jobs if idx == i)
                    try:
                        ok = fut.result()
                    except Exception as e:
                        print(f"[多出口] 槽位 {i} 并行启动异常: {e}", flush=True)
                        ok = False
                    if not ok:
                        mark_slot_pending(i, f"启动节点 {node.get('id')} 失败")

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
    result = set_exit_slot_config(count=count, country=country, residential_only=residential_only, isp=isp)
    if result.get("count", 0) == 0:
        return {"ok": True, "message": "出口已关闭"}
    with exit_slots_supervise_lock:
        for i in list(exit_slots.keys()):
            tear_down_slot(i, stop_proxy=True)
        supervise_exit_slots_once()
    return {"ok": True, "message": f"已重新分配 {count} 个出口，每个使用不同IP"}

# ========== 出口持续健康检测 ==========
def check_slot_egress(port: int) -> tuple[bool, str]:
    """周期健康检查用：并行多端点探测槽位出口。"""
    return probe_slot_egress(port)

def _prune_slot_bad_nodes() -> None:
    now = time.time()
    expired = [nid for nid, until in slot_bad_nodes.items() if until <= now]
    for nid in expired:
        slot_bad_nodes.pop(nid, None)


def slot_egress_checker_loop() -> None:
    global last_slot_egress_heartbeat
    time.sleep(20)
    while True:
        last_slot_egress_heartbeat = time.time()
        try:
            _prune_slot_bad_nodes()
            active = set(get_active_slots())
            paused = get_paused_slots()
            targets: list[int] = []
            for i in sorted(active):
                if i in paused:
                    continue
                if not slot_process_alive(i):
                    continue
                targets.append(i)

            # 并行检测各槽位出口，缩短多出口场景下的一轮耗时
            results: dict[int, tuple[bool, str]] = {}
            if targets:
                workers = min(config.SLOT_EGRESS_PARALLEL, len(targets))
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    futs = {pool.submit(check_slot_egress, slot_port(i)): i for i in targets}
                    for fut in concurrent.futures.as_completed(futs):
                        i = futs[fut]
                        try:
                            results[i] = fut.result()
                        except Exception:
                            results[i] = (False, "")

            need_reschedule = False
            for i in targets:
                ok, ip = results.get(i, (False, ""))
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
                    reset_slot_history(i)
                print(f"[多出口] 槽位 {i} 节点 {nid} 出口不通，强制拆除并切换", flush=True)
                utils.log_to_json("WARNING", "MultiExit", f"槽位 {i} 节点 {nid} 出口不通，强制漂移")
                tear_down_slot(i, stop_proxy=True)
                need_reschedule = True
            if need_reschedule:
                trigger_supervise_exit_slots()
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
            # 等待期间也可被唤醒（例如节点池刚就绪）
            exit_slots_wake.wait(timeout=30)
            exit_slots_wake.clear()
            continue
        last_exit_slots_heartbeat = time.time()
        try:
            supervise_exit_slots_once()
        except Exception as e:
            print(f"[多出口] 供给器循环异常: {e}", flush=True)
            utils.log_to_json("ERROR", "MultiExit", f"供给器循环异常: {e}")
        # 可被 trigger_supervise_exit_slots 提前唤醒，不必干等满整个间隔
        exit_slots_wake.wait(timeout=config.EXIT_SLOTS_CHECK_INTERVAL)
        exit_slots_wake.clear()
