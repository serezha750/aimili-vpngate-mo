#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures as cf
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

# ===================== 配置（可通过环境变量或参数覆盖） =====================
BASE_URL = os.environ.get("BASE_URL", "https://publicvpnlist.com")
DATA_API = os.environ.get("DATA_API", f"{BASE_URL}/local/api/vpn-data.php")
OUT_DIR = Path(os.environ.get("OUT_DIR", "./publicvpnlist-ovpn")).resolve()
CONCURRENCY = max(1, int(os.environ.get("CONCURRENCY", "50")))
MAX_RETRIES = max(1, int(os.environ.get("MAX_RETRIES", "3")))
NODES_JSON = Path(os.environ.get("NODES_JSON", "./vpngate_data/nodes.json")).resolve()
NODE_ID_PREFIX = os.environ.get("NODE_ID_PREFIX", "publicvpnlist_")

_thread_local = threading.local()

# ===================== 工具函数（下载部分） =====================
def sleep(ms: int) -> None:
    time.sleep(ms / 1000)

def parse_content_disposition_filename(disposition: str) -> str:
    if not disposition:
        return ""
    match = re.search(
        r'filename\*=(?:UTF-8\'\'|\")?([^\";]+)\"?|filename=\"?([^\";]+)\"?',
        disposition,
        flags=re.I,
    )
    raw = (match.group(1) if match and match.group(1) else match.group(2) if match else "")
    return raw.strip() if raw else ""

def sanitize_filename(name: str) -> str:
    return re.sub(r"[\\/:*?\"<>|]+", "_", re.sub(r"\s+", " ", str(name))).strip()

def dedupe_ids(rows: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        id_ = str(row.get("id", "")).strip()
        if not id_ or id_ in seen:
            continue
        seen.add(id_)
        ids.append(id_)
    return ids

def http_get_text(url: str, headers: dict[str, str], timeout: int = 30) -> tuple[int, dict[str, str], str]:
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read().decode("utf-8", errors="replace")
            return status, resp_headers, body
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, resp_headers, body

def http_get_bytes(url: str, headers: dict[str, str], timeout: int = 30) -> tuple[int, dict[str, str], bytes]:
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read()
            return status, resp_headers, body
    except HTTPError as e:
        body = e.read() if e.fp else b""
        resp_headers = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, resp_headers, body

def fetch_json(url: str, headers: dict[str, str], attempts: int = 3) -> Any:
    last_error: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            status, _, text = http_get_text(url, headers=headers)
            if status < 200 or status >= 300:
                raise RuntimeError(f"HTTP {status}")
            try:
                return json.loads(text)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"response was not JSON: {text[:200]}") from e
        except (HTTPError, URLError, RuntimeError, OSError) as e:
            last_error = e if isinstance(e, Exception) else RuntimeError(str(e))
            if i < attempts:
                sleep(400 * i)
    assert last_error is not None
    raise last_error

def load_all_rows() -> list[dict[str, Any]]:
    api_url = f"{DATA_API}?{urlencode({'v': str(int(time.time() * 1000))})}"
    data = fetch_json(
        api_url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{BASE_URL}/",
        },
    )
    if not isinstance(data, list):
        raise RuntimeError("vpn data API did not return an array")
    return data

def get_token(id_: str) -> dict[str, Any]:
    token_url = f"{BASE_URL}/get_token.php?{urlencode({'id': id_, '_': str(int(time.time() * 1000))})}"
    data = fetch_json(
        token_url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "Mozilla/5.0",
            "Referer": f"{BASE_URL}/download/{id_}/",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    if not isinstance(data, dict):
        raise RuntimeError("token response was not an object")
    return data

def download_one(id_: str) -> str:
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            token_data = get_token(id_)
            token_url = token_data.get("url") or f"/download.php?token={urlencode({'token': token_data.get('token', '')})[6:]}"
            if not token_url or token_url.endswith("token="):
                raise RuntimeError("missing download url/token")

            full_url = urljoin(BASE_URL, token_url)
            status, resp_headers, body = http_get_bytes(
                full_url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Referer": f"{BASE_URL}/download/{id_}/",
                },
            )
            if status < 200 or status >= 300:
                raise RuntimeError(f"download failed: HTTP {status}")

            disposition = resp_headers.get("content-disposition", "")
            base_name = (
                token_data.get("filename")
                or parse_content_disposition_filename(disposition)
                or f"server-{id_}.ovpn"
            )
            clean_base_name = sanitize_filename(base_name)
            if clean_base_name.lower().endswith(".ovpn"):
                file_name = f"{id_}-{clean_base_name}"
            else:
                file_name = f"{id_}-{clean_base_name}.ovpn"

            out_path = OUT_DIR / file_name
            out_path.write_bytes(body)
            return str(out_path)
        except (HTTPError, URLError, RuntimeError, OSError) as e:
            last_error = e if isinstance(e, Exception) else RuntimeError(str(e))
            if attempt < MAX_RETRIES:
                sleep(600 * attempt)
    assert last_error is not None
    raise last_error

# ===================== 导入函数 =====================
def import_ovpn_files(ovpn_dir: Path, nodes_json: Path, prefix: str) -> int:
    """
    扫描 ovpn_dir 下的所有 .ovpn 文件，解析并导入到 nodes_json 中。
    返回新增节点数量。
    """
    if not ovpn_dir.exists():
        print(f"警告: 目录 {ovpn_dir} 不存在，跳过导入")
        return 0

    # 读取现有 nodes.json
    nodes = []
    if nodes_json.exists():
        try:
            with open(nodes_json, "r", encoding="utf-8") as f:
                nodes = json.load(f)
        except Exception as e:
            print(f"读取 {nodes_json} 失败: {e}")
            return 0
    else:
        print(f"{nodes_json} 不存在，将新建")

    existing_ids = {n["id"] for n in nodes if isinstance(n, dict)}
    new_count = 0

    for ovpn_file in ovpn_dir.glob("*.ovpn"):
        try:
            config = ovpn_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"读取 {ovpn_file.name} 失败: {e}")
            continue

        # 提取 remote 行
        remote_line = None
        for line in config.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("remote "):
                remote_line = line_strip
                break
        if not remote_line:
            print(f"跳过 {ovpn_file.name}: 未找到 remote 行")
            continue

        parts = remote_line.split()
        if len(parts) < 3:
            print(f"跳过 {ovpn_file.name}: remote 格式不完整")
            continue
        remote_host = parts[1]
        try:
            remote_port = int(parts[2])
        except ValueError:
            remote_port = 443
        proto = parts[3].lower() if len(parts) > 3 else "tcp"

        node_id = prefix + ovpn_file.stem  # 使用文件名（不含扩展名）

        if node_id in existing_ids:
            print(f"跳过已存在节点: {node_id}")
            continue

        node = {
            "id": node_id,
            "country": "",
            "country_short": "",
            "ip": remote_host,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "proto": proto,
            "config_text": config,
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
        new_count += 1
        print(f"添加节点: {node_id} -> {remote_host}:{remote_port} ({proto})")

    if new_count > 0:
        nodes_json.parent.mkdir(parents=True, exist_ok=True)
        with open(nodes_json, "w", encoding="utf-8") as f:
            json.dump(nodes, f, ensure_ascii=False, indent=2)
        print(f"成功导入 {new_count} 个新节点，当前节点总数: {len(nodes)}")
    else:
        print("没有新节点需要导入")

    return new_count

# ===================== 主程序 =====================
def main() -> None:
    global OUT_DIR, CONCURRENCY, MAX_RETRIES, NODES_JSON, NODE_ID_PREFIX
    import argparse

    parser = argparse.ArgumentParser(description="Download OpenVPN configs from publicvpnlist and import them into AimiliVPN.")
    parser.add_argument("--out-dir", default=str(OUT_DIR), help="Output directory for downloaded .ovpn files")
    parser.add_argument("--nodes-json", default=str(NODES_JSON), help="Path to AimiliVPN nodes.json")
    parser.add_argument("--prefix", default=NODE_ID_PREFIX, help="Prefix for node IDs")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help="Max concurrent downloads")
    parser.add_argument("--max-retries", type=int, default=MAX_RETRIES, help="Max retries per file")
    parser.add_argument("--skip-download", action="store_true", help="Skip download and only import existing files")
    parser.add_argument("--skip-import", action="store_true", help="Only download, do not import")
    args = parser.parse_args()

    # 更新全局配置
    OUT_DIR = Path(args.out_dir).resolve()
    CONCURRENCY = args.concurrency
    MAX_RETRIES = args.max_retries
    NODES_JSON = Path(args.nodes_json).resolve()
    NODE_ID_PREFIX = args.prefix

    if not args.skip_download:
        print(f"开始下载 publicvpnlist 配置到 {OUT_DIR} ...")
        OUT_DIR.mkdir(parents=True, exist_ok=True)

        rows = load_all_rows()
        ids = dedupe_ids(rows)
        if not ids:
            raise RuntimeError("no ids found in vpn data")

        (OUT_DIR / "rows.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (OUT_DIR / "ids.json").write_text(json.dumps(ids, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        print(f"found {len(rows)} rows, {len(ids)} unique ids")
        print(f"saving to {OUT_DIR}")

        results: list[dict[str, str]] = []
        failures: list[dict[str, str]] = []
        lock = threading.Lock()

        def task(index: int, id_: str, worker_no: int) -> None:
            try:
                out_path = download_one(id_)
                with lock:
                    results.append({"id": id_, "outPath": out_path})
                print(f"[{worker_no}] {index + 1}/{len(ids)} {id_} -> {Path(out_path).name}")
            except Exception as e:
                message = str(e)
                with lock:
                    failures.append({"id": id_, "error": message})
                print(f"[{worker_no}] {index + 1}/{len(ids)} {id_} FAILED: {message}")

        with cf.ThreadPoolExecutor(max_workers=min(CONCURRENCY, len(ids))) as executor:
            futures: list[cf.Future[None]] = []
            for i, id_ in enumerate(ids):
                worker_no = (i % min(CONCURRENCY, len(ids))) + 1
                futures.append(executor.submit(task, i, id_, worker_no))
            for fut in cf.as_completed(futures):
                fut.result()

        manifest = {
            "baseUrl": BASE_URL,
            "dataApi": DATA_API,
            "downloaded": results,
            "failed": failures,
        }
        (OUT_DIR / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        print(f"下载完成: {len(results)}/{len(ids)} 成功")
        if failures:
            print(f"失败: {len(failures)}")
            # 不退出，继续导入
    else:
        print("跳过下载，仅执行导入")

    if not args.skip_import:
        print(f"\n开始导入到 {NODES_JSON} ...")
        imported = import_ovpn_files(OUT_DIR, NODES_JSON, NODE_ID_PREFIX)
        print(f"导入完成，新增 {imported} 个节点")
    else:
        print("跳过导入")

if __name__ == "__main__":
    main()