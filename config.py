#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import re
import random
import string
import hashlib
import threading
from pathlib import Path
from typing import Any

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

def generate_random_password() -> str:
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

# ---------- 环境变量与常量 ----------
API_URL = "https://www.vpngate.net/api/iphone/"
AUTO_OVPN_URL = os.environ.get("AUTO_OVPN_URL", "https://raw.githubusercontent.com/9xN/auto-ovpn/main/json/data.json")
IPSPEED_URL = os.environ.get("IPSPEED_URL", "https://ipspeed.info/free-openvpn.php")
VPNBOOK_URL = os.environ.get("VPNBOOK_URL", "https://www.vpnbook.com/zh/freevpn/openvpn")
NODE_SOURCES = [
    {"name": "vpngate_official", "url": API_URL, "format": "vpngate_csv", "weight": 10, "enabled": True},
    {"name": "auto_ovpn_mirror", "url": AUTO_OVPN_URL, "format": "auto_ovpn_json", "weight": 8, "enabled": False},
    {"name": "ipspeed", "url": IPSPEED_URL, "format": "ipspeed_html", "weight": 5, "enabled": True},
    {"name": "vpnbook", "url": VPNBOOK_URL, "format": "vpnbook_html", "weight": 3, "enabled": True},
]
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 7200, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 7200, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 30, 1)
OPENVPN_TEST_CONCURRENCY = env_int("OPENVPN_TEST_CONCURRENCY", 30, 1, 64)
PUBLICVPNLIST_TEST_CONCURRENCY = env_int("PUBLICVPNLIST_TEST_CONCURRENCY", 30, 1, 128)
TCP_PRESCREEN_CONCURRENCY = env_int("TCP_PRESCREEN_CONCURRENCY", 100, 1, 512)

PUBLICVPNLIST_SCRIPT = Path(__file__).parent / "download_and_import.py"
PUBLICVPNLIST_INTERVAL = env_int("PUBLICVPNLIST_INTERVAL", 7200, 1)

MAX_EXIT_SLOTS = env_int("MAX_EXIT_SLOTS", 100, 1)
DEFAULT_EXIT_SLOTS = env_int("MULTI_EXIT_SLOTS", 0, 0)
SLOT_DEV_BASE = env_int("SLOT_DEV_BASE", 100, 100, 900)
SLOT_TABLE_BASE = env_int("SLOT_TABLE_BASE", 100, 101, 60000)
SLOT_PORT_BASE = env_int("SLOT_PORT_BASE", 17928, 1024, 60000)
SLOT_PROXY_HOST = os.environ.get("SLOT_PROXY_HOST", "0.0.0.0")
SLOT_PROCESS_MARKER = "AIMILI_SLOT"
EXIT_SLOTS_CHECK_INTERVAL = env_int("EXIT_SLOTS_CHECK_INTERVAL", 15, 5)
SLOT_EGRESS_CHECK_INTERVAL = env_int("SLOT_EGRESS_CHECK_INTERVAL", 600, 10)
SLOT_EGRESS_FAIL_THRESHOLD = env_int("SLOT_EGRESS_FAIL_THRESHOLD", 2, 1)
SLOT_BAD_NODE_COOLDOWN = env_int("SLOT_BAD_NODE_COOLDOWN", 600, 60)

MAIN_EGRESS_FAIL_THRESHOLD = env_int("MAIN_EGRESS_FAIL_THRESHOLD", 2, 1)
MAIN_BAD_NODE_COOLDOWN = env_int("MAIN_BAD_NODE_COOLDOWN", 600, 60)

OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "0.0.0.0")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8787, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
SLOTS_FILE = DATA_DIR / "slots.json"
SLOT_HISTORY_FILE = DATA_DIR / "slot_history.json"   # 新增

# ---------- 配置加载（可修改全局配置） ----------
def load_ui_config() -> dict[str, Any]:
    """加载/初始化 ui_auth.json，并同步更新全局配置变量（如端口）"""
    global LOCAL_PROXY_PORT, UI_PORT, UI_HOST
    auth_file = DATA_DIR / "ui_auth.json"
    config = {
        "username": "520878",
        "secret_path": "Tp2p7wg1KVtf",
        "password": "520878",
        "host": UI_HOST,
        "port": UI_PORT,
        "proxy_port": LOCAL_PROXY_PORT,
        "routing_mode": "auto",
        "force_country": "",
        "routing_ip_type": "all",
        "connection_enabled": True,
        "fixed_node_id": "",
        "favorite_node_ids": [],
        "fav_fail_fallback": True
    }
    updated = False
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            for key, val in data.items():
                config[key] = val
            for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback"]:
                if key not in data:
                    updated = True
        except Exception:
            pass

    if not config.get("username"):
        config["username"] = generate_random_username()
        updated = True
    if not config.get("password"):
        config["password"] = generate_random_password()
        updated = True

    normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
    if normalized_port != config.get("port"):
        config["port"] = normalized_port
        updated = True

    normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
    if normalized_proxy_port == normalized_port:
        fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
        if fallback_proxy_port == normalized_port:
            fallback_proxy_port = 7929
        normalized_proxy_port = fallback_proxy_port
    if normalized_proxy_port != config.get("proxy_port"):
        config["proxy_port"] = normalized_proxy_port
        updated = True

    if not auth_file.exists() or updated:
        try:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    # 同步到全局配置变量
    LOCAL_PROXY_PORT = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
    UI_PORT = bounded_int(config.get("port"), UI_PORT, 1, 65535)
    UI_HOST = config.get("host", UI_HOST)
    return config

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def upstream_proxy_auth_file() -> str | None:
    import vpn_utils
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

# ---------- publicvpnlist 相关 ----------
PUBLICVPNLIST_LOCK = threading.Lock()
PUBLICVPNLIST_LAST_RUN = 0.0