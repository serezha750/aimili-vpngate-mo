#!/usr/bin/env bash
# ============================================================================
# AimiliVPN 多出口住宅 IP · 真机自检脚本
# 在已部署的 Linux VPS 上运行（建议 root），逐个核对每个出口槽位的：
#   ① tun 设备是否存在  ② 策略路由表/规则是否就绪  ③ 本地代理端口是否监听
#   ④ 经该槽位代理的真实出口 IP（验证流量确实走了对应隧道）
# 用法:  bash scripts/selfcheck_multiexit.sh [数据目录]
#   数据目录默认: $VPNGATE_DATA_DIR 或 /opt/aimilivpn/vpngate_data
# ============================================================================
set -u

DATA_DIR="${1:-${VPNGATE_DATA_DIR:-/opt/aimilivpn/vpngate_data}}"
SLOTS_FILE="${DATA_DIR}/slots.json"
PROXY_HOST="127.0.0.1"

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; PLAIN=$'\033[0m'
ok()   { echo "  ${GREEN}✓${PLAIN} $1"; }
bad()  { echo "  ${RED}✗${PLAIN} $1"; }
warn() { echo "  ${YELLOW}!${PLAIN} $1"; }

need() { command -v "$1" >/dev/null 2>&1; }

echo "${BLUE}==== AimiliVPN 多出口自检 ====${PLAIN}"
echo "数据目录: ${DATA_DIR}"

# 0. 依赖与服务
need python3 || { bad "缺少 python3"; exit 1; }
if need systemctl; then
  if systemctl is-active --quiet aimilivpn.service; then ok "服务 aimilivpn.service 运行中"; else warn "服务未运行 (systemctl start aimilivpn.service)"; fi
fi
need curl || warn "未安装 curl，将跳过真实出口 IP 检测"
need ip   || { bad "缺少 iproute2 (ip 命令)"; exit 1; }
if need ss; then LISTEN_CMD="ss -ltnH"; elif need netstat; then LISTEN_CMD="netstat -ltn"; else LISTEN_CMD=""; warn "无 ss/netstat，将跳过端口监听检测"; fi

if [ ! -f "$SLOTS_FILE" ]; then
  bad "未找到 ${SLOTS_FILE}（多出口可能未启用：后台 → 多出口住宅IP → 设数量>0）"
  exit 1
fi

# 1. 解析 slots.json -> 每行: slot|device|port|status|ip|country
mapfile -t ROWS < <(python3 - "$SLOTS_FILE" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    print("ERR|%s" % e); sys.exit(0)
print("META|%s|%s|%s" % (d.get("desired_count", 0), d.get("country", ""), d.get("residential_only", "")))
for s in d.get("slots", []):
    print("SLOT|%s|%s|%s|%s|%s|%s" % (
        s.get("slot",""), s.get("device",""), s.get("port",""),
        s.get("status",""), s.get("ip",""), s.get("country","")))
PY
)

PASS=0; FAIL=0
for row in "${ROWS[@]}"; do
  IFS='|' read -r kind a b c d e f <<< "$row"
  if [ "$kind" = "ERR" ]; then bad "解析 slots.json 失败: $a"; exit 1; fi
  if [ "$kind" = "META" ]; then
    echo "目标出口数: ${a}  国家过滤: ${b:-(不限)}  仅住宅: ${c}"
    echo "--------------------------------------------"
    continue
  fi
  [ "$kind" = "SLOT" ] || continue
  slot="$a"; dev="$b"; port="$c"; status="$d"; ip="$e"; country="$f"
  echo "${BLUE}● 槽位 #${slot}${PLAIN}  设备=${dev} 端口=${port} 节点=${country} ${ip} 状态=${status}"
  slot_ok=1

  # ① tun 设备
  if ip link show "$dev" >/dev/null 2>&1; then ok "tun 设备 ${dev} 存在"; else bad "tun 设备 ${dev} 不存在"; slot_ok=0; fi
  # ② 路由表 + 规则
  table=$((200 + slot))
  if ip route show table "$table" 2>/dev/null | grep -q .; then ok "路由表 ${table} 已配置"; else bad "路由表 ${table} 为空"; slot_ok=0; fi
  if ip rule 2>/dev/null | grep -q "$dev"; then ok "ip rule (oif ${dev}) 已就绪"; else warn "未发现 oif ${dev} 的 ip rule"; fi
  # ③ 端口监听
  if [ -n "$LISTEN_CMD" ]; then
    if $LISTEN_CMD 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then ok "代理端口 ${port} 正在监听"; else bad "代理端口 ${port} 未监听"; slot_ok=0; fi
  fi
  # ④ 真实出口 IP
  if need curl; then
    exit_ip=$(curl -s --socks5-hostname "${PROXY_HOST}:${port}" --max-time 10 http://api.ipify.org 2>/dev/null)
    if [ -n "$exit_ip" ]; then
      ok "出口 IP: ${exit_ip}"
      [ -n "$ip" ] && [ "$exit_ip" != "$ip" ] && warn "出口 IP 与节点登记 IP (${ip}) 不同（NAT/多出口节点常见，非必然异常）"
    else
      bad "经 ${PROXY_HOST}:${port} 出口测试失败（节点可能失效或隧道未通）"; slot_ok=0
    fi
  fi

  if [ "$slot_ok" = 1 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  echo
done

echo "--------------------------------------------"
echo "${BLUE}自检结果:${PLAIN} ${GREEN}通过 ${PASS}${PLAIN} / ${RED}异常 ${FAIL}${PLAIN}"
[ "$FAIL" = 0 ]

