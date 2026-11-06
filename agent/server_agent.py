#!/usr/bin/env python3
"""服务器管家 · 探针（Agent）

装在每台被管的 VPS 上，纯 Python 标准库，不装任何依赖。
职责：被插件问一句，就把这台机器的状态打包成 JSON 回过去；
      另外提供一个带白名单的「重启容器」动作口。

启动：
    AGENT_TOKEN=你的令牌 python3 server_agent.py
可选环境变量：
    AGENT_PORT              监听端口，默认 9876
    AGENT_TOKEN             访问令牌（强烈建议设置；不设则本机外也能问，不安全）
    AGENT_RESTART_WHITELIST 允许远程重启的容器名，逗号分隔，如 alist,emby
    AGENT_STATE             流量统计存档路径，默认脚本同目录 agent_state.json

接口：
    GET  /stats    机器状态（CPU/内存/磁盘/流量/容器/端口/进程）
    POST /restart  {"container": "alist"}  重启白名单内的容器
鉴权：请求头 X-Token，或 URL 参数 ?token=
"""
import json
import os
import re
from datetime import datetime, timedelta
import shutil
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

PORT = int(os.environ.get("AGENT_PORT", "9876"))
TOKEN = os.environ.get("AGENT_TOKEN", "")
WHITELIST = {s.strip() for s in os.environ.get("AGENT_RESTART_WHITELIST", "").split(",") if s.strip()}
STATE_PATH = Path(os.environ.get("AGENT_STATE", Path(__file__).with_name("agent_state.json")))


# ---------- 基础指标 ----------
def cpu_percent(sample: float = 0.15) -> float:
    def read_total_idle():
        with open("/proc/stat", encoding="utf-8") as f:
            parts = f.readline().split()[1:]
        nums = [int(x) for x in parts]
        return sum(nums), nums[3] + (nums[4] if len(nums) > 4 else 0)

    t1, i1 = read_total_idle()
    time.sleep(sample)
    t2, i2 = read_total_idle()
    dt, di = t2 - t1, i2 - i1
    if dt <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1 - di / dt) * 100)), 1)


def mem_info() -> dict:
    info = {}
    with open("/proc/meminfo", encoding="utf-8") as f:
        for line in f:
            k, _, rest = line.partition(":")
            if k in ("MemTotal", "MemAvailable"):
                info[k] = int(rest.split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", 0)
    used = total - avail
    return {
        "total": total,
        "used": used,
        "percent": round(used / total * 100, 1) if total else 0.0,
    }


def net_counters() -> tuple[int, int]:
    rx = tx = 0
    with open("/proc/net/dev", encoding="utf-8") as f:
        for line in f:
            if ":" not in line:
                continue
            name, _, rest = line.partition(":")
            if name.strip() == "lo":
                continue
            fields = rest.split()
            rx += int(fields[0])
            tx += int(fields[8])
    return rx, tx


def month_traffic() -> dict:
    """累计本月流量：把网卡计数差值攒进存档，重启/计数回绕都能扛。"""
    now = time.localtime()
    month_key = f"{now.tm_year:04d}-{now.tm_mon:02d}"
    rx, tx = net_counters()
    state = {}
    if STATE_PATH.exists():
        try:
            state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    if state.get("month") != month_key:
        state = {"month": month_key, "month_rx": 0, "month_tx": 0}
    last_rx, last_tx = state.get("last_rx"), state.get("last_tx")
    if last_rx is not None and rx >= last_rx:
        state["month_rx"] += rx - last_rx
    if last_tx is not None and tx >= last_tx:
        state["month_tx"] += tx - last_tx
    state["last_rx"], state["last_tx"] = rx, tx
    try:
        STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    except Exception:
        pass
    return {"month_rx": state["month_rx"], "month_tx": state["month_tx"], "total_rx": rx, "total_tx": tx}


def docker_containers() -> list[dict] | None:
    if not shutil.which("docker"):
        return None
    try:
        out = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except Exception:
        return None
    items = []
    for line in out.splitlines():
        if not line.strip():
            continue
        name, status, image = (line.split("\t") + ["", "", ""])[:3]
        items.append({"name": name, "status": status, "image": image, "running": status.startswith("Up")})
    return items


def listening_ports() -> list[int]:
    ports = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path, encoding="utf-8") as f:
                next(f)
                for line in f:
                    fields = line.split()
                    if len(fields) > 3 and fields[3] == "0A":  # LISTEN
                        ports.add(int(fields[1].split(":")[1], 16))
        except FileNotFoundError:
            continue
    return sorted(ports)


def top_processes(n: int = 5) -> list[dict]:
    try:
        out = subprocess.run(
            ["ps", "-eo", "comm,%cpu,%mem", "--sort=-%mem"],
            capture_output=True, text=True, timeout=5,
        ).stdout.splitlines()[1 : n + 1]
    except Exception:
        return []
    items = []
    for line in out:
        parts = line.split()
        if len(parts) >= 3:
            items.append({"name": parts[0], "cpu": parts[1], "mem": parts[2]})
    return items


AUTH_LOG_CANDIDATES = [os.environ.get("AGENT_AUTH_LOG", ""), "/var/log/auth.log", "/var/log/secure"]
FAIL_RE = re.compile(r"Failed (?:password|none) for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
OK_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def _parse_log_ts(line: str) -> datetime | None:
    """兼容 ISO 时间戳和传统 syslog（无年份）两种格式。"""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime(*[int(x) for x in m.groups()])
        except ValueError:
            return None
    m = re.match(r"(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})", line)
    if m:
        mon = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
               "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}.get(m.group(1))
        if mon:
            now = datetime.now()
            try:
                ts = datetime(now.year, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
                if ts - now > timedelta(days=1):  # 跨年残留日志
                    ts = ts.replace(year=now.year - 1)
                return ts
            except ValueError:
                return None
    return None


def ssh_info() -> dict | None:
    """统计近 1 小时 SSH 登录失败 + 最近成功登录。日志读不到就返回 None。"""
    lines: list[str] = []
    for path in AUTH_LOG_CANDIDATES:
        if path and os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()[-8000:]
                break
            except PermissionError:
                return None
            except OSError:
                continue
    if not lines:
        try:
            r = subprocess.run(
                ["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "short-iso", "-n", "3000"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                lines = r.stdout.splitlines()
        except Exception:
            pass
    if not lines:
        return None
    now = datetime.now()
    failed_10m = failed_1h = 0
    attackers: dict[str, int] = {}
    logins: list[dict] = []
    for line in lines:
        if "sshd" not in line:
            continue
        ts = _parse_log_ts(line)
        m = FAIL_RE.search(line)
        if m:
            ip = m.group(2)
            attackers[ip] = attackers.get(ip, 0) + 1
            if ts is not None:
                age = (now - ts).total_seconds()
                if age <= 600:
                    failed_10m += 1
                if age <= 3600:
                    failed_1h += 1
            continue
        m = OK_RE.search(line)
        if m:
            logins.append({"time": ts.strftime("%m-%d %H:%M") if ts else "?", "user": m.group(1), "ip": m.group(2)})
    top_ip = max(attackers, key=attackers.get) if attackers else ""
    return {
        "failed_10m": failed_10m,
        "failed_1h": failed_1h,
        "top_attacker": {"ip": top_ip, "count": attackers[top_ip]} if top_ip else None,
        "last_logins": logins[-5:][::-1],
    }


UPDATES_CACHE = Path(__file__).with_name("agent_updates.json")
BACKUP_DIRS = [s.strip() for s in os.environ.get("AGENT_BACKUP_DIRS", "").split(",") if s.strip()]
PING_TARGETS = [
    ("阿里DNS", "223.5.5.5", 53), ("腾讯DNS", "119.29.29.29", 53), ("百度", "www.baidu.com", 443),
    ("Cloudflare", "1.1.1.1", 443), ("Google", "8.8.8.8", 53), ("GitHub", "github.com", 443),
]


def pending_updates() -> dict | None:
    """待更新包数量（apt 模拟安装统计），结果缓存 6 小时，避免每次查都跑 apt。"""
    try:
        if UPDATES_CACHE.exists() and time.time() - UPDATES_CACHE.stat().st_mtime < 6 * 3600:
            return json.loads(UPDATES_CACHE.read_text(encoding="utf-8"))
    except Exception:
        pass
    result = None
    if shutil.which("apt-get"):
        try:
            r = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=60)
            inst = [l for l in r.stdout.splitlines() if l.startswith("Inst ")]
            result = {"total": len(inst), "security": sum(1 for l in inst if "security" in l.lower()), "checked_at": int(time.time())}
        except Exception:
            result = None
    elif shutil.which("dnf"):
        try:
            r = subprocess.run(["dnf", "-q", "check-update"], capture_output=True, text=True, timeout=60)
            pkgs = [l for l in r.stdout.splitlines() if l.strip() and not l.startswith("Last metadata")]
            result = {"total": len(pkgs), "security": None, "checked_at": int(time.time())}
        except Exception:
            result = None
    if result is not None:
        try:
            UPDATES_CACHE.write_text(json.dumps(result), encoding="utf-8")
        except Exception:
            pass
    return result


def backup_status() -> list[dict] | None:
    """每个备份目录里最新一份文件的年龄。没配目录就返回 None。"""
    if not BACKUP_DIRS:
        return None
    out = []
    for d in BACKUP_DIRS:
        p = Path(d)
        newest_ts, newest_name, count = 0.0, "", 0
        if p.is_dir():
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    count += 1
                    if count > 3000:
                        break
                    try:
                        fp = Path(root) / fn
                        mt = fp.stat().st_mtime
                        if mt > newest_ts:
                            newest_ts, newest_name = mt, fn
                    except OSError:
                        continue
        out.append({"dir": d, "newest_ts": int(newest_ts), "newest_name": newest_name, "files": count})
    return out


def ping_targets() -> list[dict]:
    """逐个目标测连通：先试 ICMP，不行退回 TCP 计时。"""
    import socket as _socket
    results = []
    for name, host, port in PING_TARGETS:
        ms, ok = None, False
        try:
            r = subprocess.run(["ping", "-c", "2", "-W", "2", host], capture_output=True, text=True, timeout=8)
            m = re.search(r"min/avg/max[^=]*= [\d.]+/([\d.]+)/", r.stdout)
            if r.returncode == 0 and m:
                ok, ms = True, round(float(m.group(1)), 1)
        except Exception:
            pass
        if not ok:
            try:
                t0 = time.time()
                with _socket.create_connection((host, port), timeout=3):
                    pass
                ok, ms = True, round((time.time() - t0) * 1000, 1)
            except Exception:
                ok, ms = False, None
        results.append({"name": name, "host": host, "ok": ok, "ms": ms})
    return results


def collect_stats() -> dict:
    disk = shutil.disk_usage("/")
    with open("/proc/uptime", encoding="utf-8") as f:
        uptime = int(float(f.read().split()[0]))
    return {
        "ok": True,
        "hostname": os.uname().nodename,
        "cpu_percent": cpu_percent(),
        "load": [round(x, 2) for x in os.getloadavg()],
        "mem": mem_info(),
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "percent": round(disk.used / disk.total * 100, 1) if disk.total else 0.0,
        },
        "traffic": month_traffic(),
        "uptime_seconds": uptime,
        "containers": docker_containers(),
        "ports": listening_ports(),
        "top_processes": top_processes(),
        "ssh": ssh_info(),
        "updates": pending_updates(),
        "backups": backup_status(),
        "time": int(time.time()),
    }


# ---------- HTTP 服务 ----------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # 安静
        pass

    def _authed(self) -> bool:
        if not TOKEN:
            return True
        if self.headers.get("X-Token") == TOKEN:
            return True
        qs = parse_qs(urlparse(self.path).query)
        return qs.get("token", [""])[0] == TOKEN

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/stats":
            if not self._authed():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            try:
                return self._send_json(200, collect_stats())
            except Exception as e:  # 探针自己别崩
                return self._send_json(500, {"ok": False, "error": str(e)})
        if path == "/pingtest":
            if not self._authed():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            return self._send_json(200, {"ok": True, "targets": ping_targets()})
        return self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/restart":
            if not self._authed():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                return self._send_json(400, {"ok": False, "error": "bad json"})
            name = str(payload.get("container", "")).strip()
            if name not in WHITELIST:
                return self._send_json(403, {"ok": False, "error": f"容器 {name} 不在重启白名单里"})
            try:
                r = subprocess.run(["docker", "restart", name], capture_output=True, text=True, timeout=60)
                if r.returncode == 0:
                    return self._send_json(200, {"ok": True, "container": name})
                return self._send_json(500, {"ok": False, "error": (r.stderr or "docker restart failed")[:200]})
            except Exception as e:
                return self._send_json(500, {"ok": False, "error": str(e)})
        return self._send_json(404, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    print(f"server_butler agent on :{PORT} (token {'set' if TOKEN else 'NOT set'})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
