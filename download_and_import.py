#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import random
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

BASE_URL = os.environ.get("BASE_URL", "https://publicvpnlist.com")
DATA_API = os.environ.get("DATA_API", f"{BASE_URL}/local/api/vpn-data.php")
OUT_DIR = Path(os.environ.get("OUT_DIR", "./publicvpnlist-ovpn")).resolve()
CONCURRENCY = max(1, int(os.environ.get("CONCURRENCY", "2")))
MAX_RETRIES = max(1, int(os.environ.get("MAX_RETRIES", "8")))
TOKEN_MIN_INTERVAL = max(0.25, float(os.environ.get("TOKEN_MIN_INTERVAL", "0.5")))
NODES_JSON = Path(os.environ.get("NODES_JSON", "./vpngate_data/nodes.json")).resolve()
NODE_ID_PREFIX = os.environ.get("NODE_ID_PREFIX", "publicvpnlist_")

_token_rate_lock = threading.Lock()
_next_token_time = 0.0

class RateLimitError(RuntimeError):
    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after

def sleep(ms: int) -> None:
    time.sleep(ms / 1000)

def retry_after_seconds(headers: dict[str, str]) -> float | None:
    value = headers.get("retry-after", "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None

def wait_for_token_slot() -> None:
    global _next_token_time
    with _token_rate_lock:
        now = time.monotonic()
        wait = max(0.0, _next_token_time - now)
        _next_token_time = max(now, _next_token_time) + TOKEN_MIN_INTERVAL
    if wait:
        time.sleep(wait)

def parse_content_disposition_filename(disposition: str) -> str:
    if not disposition:
        return ""
    match = re.search(r'filename\\*=(?:UTF-8\'\'|\")?([^\";]+)\"?|filename=\"?([^\";]+)\"?', disposition, flags=re.I)
    raw = match.group(1) if match and match.group(1) else match.group(2) if match else ""
    return raw.strip() if raw else ""

def sanitize_filename(name: str) -> str:
    return re.sub(r"[\\/:*?\"<>|]+", "_", re.sub(r"\s+", " ", str(name))).strip()

def dedupe_ids(rows: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        id_ = str(row.get("id", "")).strip()
        if id_ and id_ not in seen:
            seen.add(id_)
            ids.append(id_)
    return ids

def http_request(url: str, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None, timeout: int = 30) -> tuple[int, dict[str, str], bytes]:
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return getattr(resp, "status", 200), {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}, e.read() if e.fp else b""

def fetch_json(url: str, headers: dict[str, str], attempts: int = 3) -> Any:
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        status, _, body = http_request(url, headers=headers)
        if 200 <= status < 300:
            try:
                return json.loads(body)
            except json.JSONDecodeError as e:
                last = e
        else:
            last = RuntimeError(f"HTTP {status}")
        if attempt < attempts:
            time.sleep(attempt)
    raise last or RuntimeError("request failed")

def load_all_rows() -> list[dict[str, Any]]:
    url = f"{DATA_API}?{urlencode({'v': str(int(time.time() * 1000))})}"
    data = fetch_json(url, {"Accept": "application/json", "User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest", "Referer": f"{BASE_URL}/"})
    if not isinstance(data, list):
        raise RuntimeError("vpn data API did not return an array")
    return data

def get_token(id_: str) -> dict[str, Any]:
    wait_for_token_slot()
    status, headers, body = http_request(
        f"{BASE_URL}/get_token.php",
        method="POST",
        data=urlencode({"id": id_}).encode(),
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "User-Agent": "Mozilla/5.0", "Referer": f"{BASE_URL}/download/{id_}/", "X-Requested-With": "XMLHttpRequest"},
    )
    if status == 429:
        raise RateLimitError("token request rate limited: HTTP 429", retry_after_seconds(headers))
    if not 200 <= status < 300:
        raise RuntimeError(f"token request failed: HTTP {status}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"token response was not JSON: {body[:200]!r}") from e
    if not isinstance(data, dict):
        raise RuntimeError("token response was not an object")
    return data

def download_one(id_: str) -> str:
    existing = sorted(OUT_DIR.glob(f"{id_}-*.ovpn"))
    for path in existing:
        if path.is_file() and path.stat().st_size > 0:
            return str(path)
    last: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            token = get_token(id_)
            url = urljoin(BASE_URL, str(token.get("url") or f"/download.php?token={token.get('token', '')}"))
            status, headers, body = http_request(url, headers={"User-Agent": "Mozilla/5.0", "Referer": f"{BASE_URL}/download/{id_}/"})
            if not 200 <= status < 300:
                raise RuntimeError(f"download failed: HTTP {status}")
            name = sanitize_filename(str(token.get("filename") or parse_content_disposition_filename(headers.get("content-disposition", "")) or f"server-{id_}.ovpn"))
            path = OUT_DIR / (f"{id_}-{name}" if name.lower().endswith(".ovpn") else f"{id_}-{name}.ovpn")
            path.write_bytes(body)
            return str(path)
        except (RateLimitError, RuntimeError, URLError, OSError) as e:
            last = e
            if attempt < MAX_RETRIES:
                delay = e.retry_after if isinstance(e, RateLimitError) and e.retry_after is not None else min(60.0, 1.5 * (2 ** (attempt - 1)))
                time.sleep(max(0.5, delay) + random.uniform(0, 0.3))
    raise last or RuntimeError("download failed")

def import_ovpn_files(ovpn_dir: Path, nodes_json: Path, prefix: str) -> int:
    if not ovpn_dir.exists():
        print(f"警告: 目录 {ovpn_dir} 不存在，跳过导入")
        return 0
    nodes: list[dict[str, Any]] = []
    if nodes_json.exists():
        try:
            nodes = json.loads(nodes_json.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"读取 {nodes_json} 失败: {e}")
            return 0
    existing_ids = {n.get("id") for n in nodes if isinstance(n, dict)}
    new_count = 0
    for ovpn_file in ovpn_dir.glob("*.ovpn"):
        try:
            config = ovpn_file.read_text(encoding="utf-8", errors="ignore")
            remote_line = next((line.strip() for line in config.splitlines() if line.strip().startswith("remote ")), "")
            parts = remote_line.split()
            if len(parts) < 3:
                continue
            host = parts[1]
            try:
                port = int(parts[2])
            except ValueError:
                port = 443
            proto = parts[3].lower() if len(parts) > 3 else "tcp"
            node_id = prefix + ovpn_file.stem
            if node_id in existing_ids:
                continue
            nodes.append({"id": node_id, "country": "", "country_short": "", "ip": host, "remote_host": host, "remote_port": port, "proto": proto, "config_text": config, "config_file": f"vpngate_data/configs/{node_id}.ovpn", "score": 0, "ping": 0, "speed": 0, "sessions": 0, "uptime": 0, "total_users": 0, "total_traffic": 0, "log_type": "", "operator": "", "message": "", "source": "publicvpnlist_manual", "probed_at": 0, "owner": "", "asn": "", "as_name": "", "location": "", "ip_type": "", "quality": "", "fetched_at": time.time()})
            existing_ids.add(node_id)
            new_count += 1
        except OSError:
            continue
    if new_count:
        nodes_json.parent.mkdir(parents=True, exist_ok=True)
        nodes_json.write_text(json.dumps(nodes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return new_count

def main() -> None:
    global OUT_DIR, CONCURRENCY, MAX_RETRIES, NODES_JSON, NODE_ID_PREFIX
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    parser.add_argument("--nodes-json", default=str(NODES_JSON))
    parser.add_argument("--prefix", default=NODE_ID_PREFIX)
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--max-retries", type=int, default=MAX_RETRIES)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--skip-import", action="store_true")
    args = parser.parse_args()
    OUT_DIR = Path(args.out_dir).resolve(); CONCURRENCY = max(1, args.concurrency); MAX_RETRIES = max(1, args.max_retries); NODES_JSON = Path(args.nodes_json).resolve(); NODE_ID_PREFIX = args.prefix
    if not args.skip_download:
        print(f"开始下载 publicvpnlist 配置到 {OUT_DIR} ...", flush=True)
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        rows = load_all_rows(); ids = dedupe_ids(rows)
        (OUT_DIR / "rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (OUT_DIR / "ids.json").write_text(json.dumps(ids, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"found {len(rows)} rows, {len(ids)} unique ids", flush=True); print(f"saving to {OUT_DIR}", flush=True)
        results: list[dict[str, str]] = []; failures: list[dict[str, str]] = []; lock = threading.Lock(); workers = min(CONCURRENCY, len(ids))
        def task(index: int, id_: str) -> None:
            try:
                path = download_one(id_)
                with lock: results.append({"id": id_, "outPath": path})
                print(f"{index + 1}/{len(ids)} {id_} -> {Path(path).name}", flush=True)
            except Exception as e:
                with lock: failures.append({"id": id_, "error": str(e)})
                print(f"{index + 1}/{len(ids)} {id_} FAILED: {e}", flush=True)
        with cf.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(task, i, id_) for i, id_ in enumerate(ids)]
            for future in cf.as_completed(futures): future.result()
        (OUT_DIR / "manifest.json").write_text(json.dumps({"baseUrl": BASE_URL, "dataApi": DATA_API, "downloaded": results, "failed": failures}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"下载完成: {len(results)}/{len(ids)} 成功", flush=True)
    if not args.skip_import:
        print(f"开始导入到 {NODES_JSON} ...", flush=True); print(f"导入完成，新增 {import_ovpn_files(OUT_DIR, NODES_JSON, NODE_ID_PREFIX)} 个节点", flush=True)

if __name__ == "__main__":
    main()
