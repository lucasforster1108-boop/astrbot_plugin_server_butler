"""服务器管家（AstrBot 插件）

在聊天里管你的 VPS：
- 一句话查状态 / 流量 / 容器 / 证书 / 进程
- 后台巡检：宕机、磁盘满、流量超额、证书快过期、服务器快到期、服务探活
  出问题主动推送到订阅了告警的会话，恢复了也报一声
- 每天定点一份全部服务器的日报
- 管理员可远程重启白名单内的 Docker 容器

数据来源是装在每台 VPS 上的小探针（见 agent/server_agent.py）。
"""
import asyncio
import calendar
import json
import socket
import ssl
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from astrbot.api import logger
from astrbot.api.event import MessageChain, filter, AstrMessageEvent
from astrbot.api.message_components import Plain
from astrbot.api.star import Context, Star

DATA_FILE = Path(__file__).with_name("data") / "butler_data.json"


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_uptime(sec: int) -> str:
    d, rem = divmod(int(sec), 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} 天 {h} 小时"
    if h:
        return f"{h} 小时 {m} 分"
    return f"{m} 分钟"


class ServerButler(Star):
    def __init__(self, context: Context, config: dict | None = None):
        super().__init__(context)
        self.config = config or {}
        self.servers = self._parse_json_list(self.config.get("servers", "[]"))
        self.services = self._parse_json_list(self.config.get("services", "[]"))
        self.agent_token = str(self.config.get("agent_token", "") or "")
        self.check_interval = max(60, self._int_cfg("check_interval", 300))
        self.disk_threshold = self._int_cfg("disk_threshold", 85)
        self.traffic_threshold = self._int_cfg("traffic_threshold", 90)
        self.cert_warn_days = self._int_cfg("cert_warn_days", 15)
        self.expiry_warn_days = self._int_cfg("expiry_warn_days", 15)
        self.ssh_fail_threshold = self._int_cfg("ssh_fail_threshold", 30)
        self.domains = self._parse_json_list(self.config.get("domains", "[]"))
        self.backup_warn_hours = self._int_cfg("backup_warn_hours", 48)
        self.daily_report_time = str(self.config.get("daily_report_time", "") or "").strip()
        self.admin_ids = {s.strip() for s in str(self.config.get("admin_ids", "") or "").split(",") if s.strip()}

        self.data = self._load_data()
        self._task: asyncio.Task | None = None
        try:
            self._task = asyncio.create_task(self._patrol_loop())
        except RuntimeError:
            logger.warning("[服务器管家] 当前无事件循环，巡检将在首次指令时启动")

    def _int_cfg(self, key: str, default: int) -> int:
        v = self.config.get(key, default)
        if v is None or v == "":
            return default
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _parse_json_list(raw) -> list:
        if isinstance(raw, list):
            return raw
        try:
            v = json.loads(raw or "[]")
            return v if isinstance(v, list) else []
        except Exception:
            logger.error(f"[服务器管家] 配置 JSON 解析失败: {raw!r}")
            return []

    def _load_data(self) -> dict:
        try:
            if DATA_FILE.exists():
                d = json.loads(DATA_FILE.read_text(encoding="utf-8"))
                d.setdefault("history", [])
                d.setdefault("notes", {})
                return d
        except Exception:
            pass
        return {"subscriptions": [], "state": {}, "last_report_date": "", "history": [], "notes": {}}

    def _save_data(self):
        try:
            DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            DATA_FILE.write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.error(f"[服务器管家] 保存数据失败: {e}")

    def _find_server(self, name: str | None) -> dict | None:
        if not self.servers:
            return None
        if not name:
            return self.servers[0]
        for s in self.servers:
            if s.get("name") == name:
                return s
        return None

    def _ensure_task(self):
        if self._task is None or self._task.done():
            try:
                self._task = asyncio.create_task(self._patrol_loop())
            except RuntimeError:
                pass

    async def _fetch_stats(self, server: dict) -> dict | None:
        url = str(server.get("agent", "")).rstrip("/") + "/stats"
        token = server.get("token") or self.agent_token
        headers = {"X-Token": token} if token else {}
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        logger.warning(f"[服务器管家] {server.get('name')} 探针返回 {resp.status}")
                        return None
                    data = await resp.json()
                    return data if data.get("ok") else None
        except Exception as e:
            logger.warning(f"[服务器管家] {server.get('name')} 探针连不上: {e}")
            return None

    async def _restart_container(self, server: dict, container: str) -> tuple[bool, str]:
        url = str(server.get("agent", "")).rstrip("/") + "/restart"
        token = server.get("token") or self.agent_token
        headers = {"X-Token": token} if token else {}
        try:
            timeout = aiohttp.ClientTimeout(total=70)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.post(url, headers=headers, json={"container": container}) as resp:
                    data = await resp.json()
                    if resp.status == 200 and data.get("ok"):
                        return True, ""
                    return False, str(data.get("error", f"HTTP {resp.status}"))
        except Exception as e:
            return False, str(e)

    def _server_block(self, server: dict, stats: dict | None, detail: bool = False) -> str:
        name = server.get("name", "?")
        if stats is None:
            return f"🔴 {name}：探针连不上（机器可能宕了，或探针没在跑）"
        mem, disk, traf = stats["mem"], stats["disk"], stats["traffic"]
        lines = [
            f"🟢 {name}（{stats.get('hostname', '')}）已运行 {fmt_uptime(stats.get('uptime_seconds', 0))}",
            f"   CPU {stats.get('cpu_percent', 0)}%｜负载 {'/'.join(str(x) for x in stats.get('load', []))}",
            f"   内存 {mem.get('percent', 0)}%（{fmt_bytes(mem.get('used', 0))}/{fmt_bytes(mem.get('total', 0))}）",
            f"   磁盘 {disk.get('percent', 0)}%（{fmt_bytes(disk.get('used', 0))}/{fmt_bytes(disk.get('total', 0))}）",
        ]
        month_used = traf.get("month_rx", 0) + traf.get("month_tx", 0)
        quota_gb = float(server.get("traffic_quota_gb") or 0)
        if quota_gb > 0:
            pct = month_used / (quota_gb * 1024**3) * 100
            lines.append(f"   本月流量 {fmt_bytes(month_used)} / {quota_gb:.0f} GB（{pct:.1f}%）")
        else:
            lines.append(f"   本月流量 {fmt_bytes(month_used)}（未设配额）")
        containers = stats.get("containers")
        if containers is not None:
            running = sum(1 for c in containers if c.get("running"))
            lines.append(f"   容器 {running}/{len(containers)} 在跑")
        if server.get("expires"):
            lines.append(f"   到期日 {server['expires']}")
        if detail and containers:
            for c in containers:
                mark = "🟢" if c.get("running") else "⚪"
                lines.append(f"   {mark} {c.get('name')} · {c.get('status')}")
        return "\n".join(lines)

    @filter.command("status", alias={"状态"})
    async def cmd_status(self, event: AstrMessageEvent, name: str = ""):
        """查服务器状态：/状态 查全部，/状态 美国 查单台"""
        self._ensure_task()
        if not self.servers:
            yield event.plain_result("还没配置服务器。先在插件配置里填 servers（格式见插件说明）。")
            return
        if name:
            server = self._find_server(name)
            if not server:
                yield event.plain_result(f"没有叫「{name}」的服务器，已配置：{'、'.join(s.get('name', '?') for s in self.servers)}")
                return
            stats = await self._fetch_stats(server)
            yield event.plain_result(self._server_block(server, stats, detail=True))
            return
        blocks = []
        for server in self.servers:
            stats = await self._fetch_stats(server)
            blocks.append(self._server_block(server, stats))
        yield event.plain_result("📊 服务器状态\n" + "\n\n".join(blocks))

    @filter.command("traffic", alias={"流量"})
    async def cmd_traffic(self, event: AstrMessageEvent, name: str = ""):
        """查本月流量：/流量 或 /流量 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        lines = ["🚦 本月流量"]
        for server in targets:
            stats = await self._fetch_stats(server)
            if stats is None:
                lines.append(f"🔴 {server.get('name')}：探针连不上")
                continue
            traf = stats["traffic"]
            used = traf.get("month_rx", 0) + traf.get("month_tx", 0)
            quota_gb = float(server.get("traffic_quota_gb") or 0)
            tail = f"，配额 {quota_gb:.0f} GB，已用 {used / (quota_gb * 1024**3) * 100:.1f}%" if quota_gb > 0 else "（未设配额）"
            lines.append(f"{server.get('name')}：↓{fmt_bytes(traf.get('month_rx', 0))} ↑{fmt_bytes(traf.get('month_tx', 0))}，合计 {fmt_bytes(used)}{tail}")
            if quota_gb > 0:
                proj = self._traffic_projection(server, stats)
                if proj is not None:
                    lines.append(f"   按目前速度，月底预计用 {fmt_bytes(proj)}（配额的 {proj / (quota_gb * 1024**3) * 100:.0f}%）")
        yield event.plain_result("\n".join(lines))

    @filter.command("docker", alias={"容器"})
    async def cmd_docker(self, event: AstrMessageEvent, name: str = ""):
        """查 Docker 容器：/容器 或 /容器 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        blocks = []
        for server in targets:
            stats = await self._fetch_stats(server)
            if stats is None:
                blocks.append(f"🔴 {server.get('name')}：探针连不上")
                continue
            containers = stats.get("containers")
            if containers is None:
                blocks.append(f"{server.get('name')}：这台没装 Docker（或探针没权限）")
                continue
            lines = [f"🐳 {server.get('name')} 的容器（{sum(1 for c in containers if c.get('running'))}/{len(containers)} 在跑）"]
            for c in containers:
                mark = "🟢" if c.get("running") else "⚪"
                lines.append(f"{mark} {c.get('name')} · {c.get('status')} · {c.get('image')}")
            blocks.append("\n".join(lines))
        yield event.plain_result("\n\n".join(blocks))

    @filter.command("top", alias={"进程"})
    async def cmd_top(self, event: AstrMessageEvent, name: str = ""):
        """查某台服务器的吃内存大户和监听端口：/进程 美国"""
        server = self._find_server(name or None)
        if not server:
            yield event.plain_result("先告诉我是哪台，比如 /进程 美国")
            return
        stats = await self._fetch_stats(server)
        if stats is None:
            yield event.plain_result(f"🔴 {server.get('name')}：探针连不上")
            return
        lines = [f"🔍 {server.get('name')} 进程 TOP（按内存）"]
        for p in stats.get("top_processes", []):
            lines.append(f"· {p.get('name')}：内存 {p.get('mem')}% / CPU {p.get('cpu')}%")
        ports = stats.get("ports", [])
        lines.append("监听端口：" + ("、".join(str(p) for p in ports) if ports else "无"))
        yield event.plain_result("\n".join(lines))

    @filter.command("cert", alias={"证书"})
    async def cmd_cert(self, event: AstrMessageEvent):
        """查已配置服务的 HTTPS 证书剩余天数：/证书"""
        if not self.services:
            yield event.plain_result("还没配置服务清单（services），没有可查的证书。")
            return
        lines = ["🔐 证书剩余天数"]
        for svc in self.services:
            days, host, err = await self._cert_days(svc.get("url", ""))
            if days is None:
                lines.append(f"❓ {svc.get('name', host)}：查不到（{err}）")
            else:
                mark = "⚠️" if days <= self.cert_warn_days else "✅"
                lines.append(f"{mark} {svc.get('name', host)}（{host}）：还剩 {days} 天")
        yield event.plain_result("\n".join(lines))

    @filter.command("subscribe", alias={"订阅告警"})
    async def cmd_subscribe(self, event: AstrMessageEvent):
        """把当前会话（群/私聊）加入告警推送名单：/订阅告警"""
        umo = event.unified_msg_origin
        subs = self.data.setdefault("subscriptions", [])
        if umo in subs:
            yield event.plain_result("这个会话已经在告警名单里了。")
            return
        subs.append(umo)
        self._save_data()
        yield event.plain_result("✅ 订好了。哪台服务器出问题（宕机、磁盘满、流量超额、证书快过期、服务挂了），我第一时间在这里喊你。")

    @filter.command("unsubscribe", alias={"取消订阅"})
    async def cmd_unsubscribe(self, event: AstrMessageEvent):
        """把当前会话移出告警推送名单：/取消订阅"""
        umo = event.unified_msg_origin
        subs = self.data.setdefault("subscriptions", [])
        if umo in subs:
            subs.remove(umo)
            self._save_data()
            yield event.plain_result("已取消，这个会话不会再收到服务器告警。")
        else:
            yield event.plain_result("这个会话本来就没订阅告警。")

    @filter.command("restart", alias={"重启容器"})
    async def cmd_restart(self, event: AstrMessageEvent, server_name: str = "", container: str = ""):
        """管理员重启容器：/重启容器 美国 alist（容器要在探针的白名单里）"""
        sender = str(event.get_sender_id())
        if not self.admin_ids:
            yield event.plain_result("还没配置管理员（admin_ids），为安全起见先不开这个口。在插件配置里填上你的账号 ID 再用。")
            return
        if sender not in self.admin_ids:
            yield event.plain_result("这个操作只有管理员能用。")
            return
        server = self._find_server(server_name or None)
        if not server or not container:
            yield event.plain_result("用法：/重启容器 服务器名 容器名，比如 /重启容器 美国 alist")
            return
        ok, err = await self._restart_container(server, container)
        if ok:
            self._record(f"🔧 {event.get_sender_name()} 重启了【{server.get('name')}】的容器 {container}")
            yield event.plain_result(f"✅ 已重启 {server.get('name')} 上的容器 {container}")
        else:
            yield event.plain_result(f"❌ 重启失败：{err}")

    @filter.command("butler", alias={"管家帮助"})
    async def cmd_help(self, event: AstrMessageEvent):
        """服务器管家全部指令：/管家帮助"""
        yield event.plain_result(
            "🧰 服务器管家指令\n"
            "/状态 [服务器名] —— 全部或单台的状态\n"
            "/流量 [服务器名] —— 本月流量和配额\n"
            "/容器 [服务器名] —— Docker 容器清单\n"
            "/进程 服务器名 —— 吃内存大户＋监听端口\n"
            "/证书 —— 服务的 HTTPS 证书还剩几天\n"
            "/订阅告警 / /取消订阅 —— 告警推送开关\n"
            "/重启容器 服务器名 容器名 —— 管理员专用\n"
            "/病历 [服务器名] —— 历史告警和恢复记录\n"
            "/记一笔 服务器名 内容 —— 给服务器记备忘\n"
            "/备忘 [服务器名] —— 看备忘清单\n"
            "/健康分 —— 每台服务器打个分排个名\n"
            "/登录 [服务器名] —— 最近 SSH 登录和爆破情况\n"
            "/更新 [服务器名] —— 待更新的包有几个\n"
            "/到期 —— 服务器/域名/证书到期清单\n"
            "/资产 —— 每台多少钱、一年烧多少\n"
            "/备份 [服务器名] —— 备份是不是新鲜的\n"
            "/测通 [服务器名] —— 国内外连通性（查 IP 被墙）\n"
            "后台还在自动巡检：宕机、磁盘满、流量超额、证书快过期、服务器快到期、服务挂了、监听端口变化、SSH 被爆破，都会推送到订阅的会话；配了看门狗的容器挂了还会自动重启。"
        )

    async def _cert_days(self, url: str) -> tuple[int | None, str, str]:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname or ""
        if not host:
            return None, "", "地址不对"
        port = parsed.port or 443

        def _check() -> int:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            return (not_after - datetime.utcnow()).days

        try:
            days = await asyncio.to_thread(_check)
            return days, host, ""
        except Exception as e:
            return None, host, str(e)[:60]

    async def _service_alive(self, url: str) -> tuple[bool, str]:
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(url) as resp:
                    return resp.status < 500, f"HTTP {resp.status}"
        except Exception as e:
            return False, str(e)[:60]

    def _record(self, text: str):
        """把事件写进病历本（全局时间线，最多留 200 条）。"""
        hist = self.data.setdefault("history", [])
        hist.append({"ts": datetime.now().strftime("%m-%d %H:%M"), "text": text})
        del hist[:-200]
        self._save_data()

    async def _broadcast(self, text: str):
        self._record(text)
        subs = list(self.data.get("subscriptions", []))
        for umo in subs:
            try:
                await self.context.send_message(umo, MessageChain([Plain(text)]))
            except Exception as e:
                logger.error(f"[服务器管家] 推送失败 {umo}: {e}")

    def _alert_transition(self, key: str, bad: bool, bad_msg: str, ok_msg: str | None):
        """状态翻转才发消息：变坏发告警，恢复发通知，不刷屏。"""
        state = self.data.setdefault("state", {})
        was_bad = bool(state.get(key, False))
        if bad and not was_bad:
            state[key] = True
            self._save_data()
            return bad_msg
        if not bad and was_bad:
            state[key] = False
            self._save_data()
            return ok_msg
        return None

    async def _check_ports(self, server: dict, stats: dict):
        """监听端口集合变了就报：新开端口是入侵/误装的早期信号。"""
        name = server.get("name", "?")
        cur = sorted(int(p) for p in stats.get("ports", []))
        state = self.data.setdefault("state", {})
        key = f"ports:{name}"
        prev = state.get(key)
        if prev is None:
            state[key] = cur
            self._save_data()
            return
        if list(prev) != cur:
            opened = [p for p in cur if p not in prev]
            closed = [p for p in prev if p not in cur]
            state[key] = cur
            self._save_data()
            parts = []
            if opened:
                parts.append(f"新开了 {opened}")
            if closed:
                parts.append(f"关掉了 {closed}")
            await self._broadcast(f"🔌【{name}】监听端口变了：{'，'.join(parts)}。不是你自己改的就赶紧查。")

    async def _check_ssh(self, server: dict, stats: dict):
        """SSH 爆破：10 分钟失败次数超阈值就报，停了报恢复。"""
        name = server.get("name", "?")
        ssh = stats.get("ssh")
        if not ssh:
            return
        failed = int(ssh.get("failed_10m", 0))
        top = ssh.get("top_attacker") or {}
        msg = self._alert_transition(
            f"sshbrute:{name}", failed >= self.ssh_fail_threshold,
            f"🚨【{name}】SSH 正在被爆破：近 10 分钟失败 {failed} 次，头号来源 {top.get('ip', '?')}。建议改端口/密钥登录/装 fail2ban。",
            f"✅【{name}】SSH 爆破停了（近 10 分钟失败降到 {failed} 次）。",
        )
        if msg:
            await self._broadcast(msg)

    async def _check_watchdog(self, server: dict, stats: dict):
        """看门狗：配置里点名的容器停了就自动重启，一小时最多 3 次。"""
        name = server.get("name", "?")
        guard = server.get("watchdog") or []
        if not guard:
            return
        containers = stats.get("containers")
        if containers is None:
            return
        by_name = {c.get("name"): c for c in containers}
        state = self.data.setdefault("state", {})
        for cname in guard:
            c = by_name.get(cname)
            if c is None:
                msg = self._alert_transition(
                    f"wdmissing:{name}:{cname}", True,
                    f"⚠️【{name}】看门狗盯的容器 {cname} 不见了（被删了？），没法守护。",
                    None,
                )
                if msg:
                    await self._broadcast(msg)
                continue
            self._alert_transition(f"wdmissing:{name}:{cname}", False, "", None)
            if c.get("running"):
                state.pop(f"wdgaveup:{name}:{cname}", None)
                continue
            key = f"wdrestarts:{name}:{cname}"
            now_ts = int(time.time())
            stamps = [t for t in state.get(key, []) if now_ts - t < 3600]
            if len(stamps) >= 3:
                if not state.get(f"wdgaveup:{name}:{cname}"):
                    state[f"wdgaveup:{name}:{cname}"] = True
                    self._save_data()
                    await self._broadcast(f"🆘【{name}】容器 {cname} 一小时内自动重启 3 次还是起不来，看门狗先停手，你人工看看吧。")
                continue
            ok, err = await self._restart_container(server, cname)
            stamps.append(now_ts)
            state[key] = stamps
            self._save_data()
            if ok:
                await self._broadcast(f"🐕【{name}】看门狗发现容器 {cname} 停了，已自动重启（本小时第 {len(stamps)} 次）。")
            else:
                await self._broadcast(f"🐕【{name}】看门狗想重启容器 {cname} 没成：{err}")

    def _traffic_projection(self, server: dict, stats: dict) -> float | None:
        """按本月已用速度推算月底总用量。太早（1 号）不算，避免吓人。"""
        quota_gb = float(server.get("traffic_quota_gb") or 0)
        if quota_gb <= 0:
            return None
        used = stats["traffic"].get("month_rx", 0) + stats["traffic"].get("month_tx", 0)
        now = datetime.now()
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        if now.day < 2:
            return None
        return used / now.day * days_in_month

    async def _check_forecast(self, server: dict, stats: dict):
        """流量预测：预计月底超配额就提前喊，每月每台只喊一次。"""
        name = server.get("name", "?")
        quota_gb = float(server.get("traffic_quota_gb") or 0)
        proj = self._traffic_projection(server, stats)
        if proj is None:
            return
        if proj <= quota_gb * 1024**3:
            return
        now = datetime.now()
        state = self.data.setdefault("state", {})
        key = f"forecast:{name}:{now.year}-{now.month:02d}"
        if state.get(key):
            return
        state[key] = True
        self._save_data()
        await self._broadcast(f"🔮【{name}】按目前的用法，本月流量预计用到 {fmt_bytes(proj)}，超配额 {quota_gb:.0f} GB。才 {now.day} 号，现在开始省还来得及。")

    async def _check_backup(self, server: dict, stats: dict):
        """备份新鲜度：最新一份备份太老就报，恢复新鲜了报解除。"""
        name = server.get("name", "?")
        backups = stats.get("backups")
        if not backups:
            return
        now_ts = int(time.time())
        for b in backups:
            newest = int(b.get("newest_ts", 0))
            age_h = (now_ts - newest) / 3600 if newest else 99999
            msg = self._alert_transition(
                f"backup:{name}:{b.get('dir')}", age_h > self.backup_warn_hours,
                f"💾【{name}】备份目录 {b.get('dir')} 最新一份是 {age_h / 24:.1f} 天前的了（{b.get('newest_name') or '空的'}）。备份任务可能已经死了，去看一眼。",
                f"✅【{name}】备份 {b.get('dir')} 又有新备份了，警报解除。",
            )
            if msg:
                await self._broadcast(msg)

    async def _check_updates(self, server: dict, stats: dict):
        """安全更新提醒：有安全更新就每周提一次。"""
        name = server.get("name", "?")
        upd = stats.get("updates")
        if not upd:
            return
        sec = upd.get("security")
        if not sec:
            return
        state = self.data.setdefault("state", {})
        key = f"updremind:{name}"
        last = float(state.get(key, 0))
        if time.time() - last < 7 * 86400:
            return
        state[key] = int(time.time())
        self._save_data()
        await self._broadcast(f"🔐【{name}】有 {sec} 个安全更新等着（待更新共 {upd.get('total')} 个）。抽空 apt upgrade 一下，别裸奔。")

    async def _patrol_once(self):
        now = datetime.now()
        for server in self.servers:
            name = server.get("name", "?")
            stats = await self._fetch_stats(server)
            msg = self._alert_transition(
                f"down:{name}", stats is None,
                f"🚨【{name}】探针连不上！机器可能宕了，快去看看。",
                f"✅【{name}】恢复了，探针又能连上了。",
            )
            if msg:
                await self._broadcast(msg)
            if stats is None:
                continue
            pct = stats["disk"].get("percent", 0)
            msg = self._alert_transition(
                f"disk:{name}", pct >= self.disk_threshold,
                f"⚠️【{name}】磁盘用到 {pct}% 了（阈值 {self.disk_threshold}%），再不清理要满了。",
                f"✅【{name}】磁盘降回 {pct}%，警报解除。",
            )
            if msg:
                await self._broadcast(msg)
            quota_gb = float(server.get("traffic_quota_gb") or 0)
            if quota_gb > 0:
                used = stats["traffic"].get("month_rx", 0) + stats["traffic"].get("month_tx", 0)
                used_pct = used / (quota_gb * 1024**3) * 100
                msg = self._alert_transition(
                    f"traffic:{name}", used_pct >= self.traffic_threshold,
                    f"⚠️【{name}】本月流量用到 {used_pct:.1f}%（配额 {quota_gb:.0f} GB），省着点用。",
                    None,
                )
                if msg:
                    await self._broadcast(msg)
            expires = str(server.get("expires") or "")
            if expires:
                try:
                    days_left = (datetime.strptime(expires, "%Y-%m-%d").date() - now.date()).days
                    state = self.data.setdefault("state", {})
                    key = f"expiry:{name}:{expires}"
                    if 0 <= days_left <= self.expiry_warn_days and state.get(key) != str(now.date()):
                        state[key] = str(now.date())
                        self._save_data()
                        await self._broadcast(f"⏰【{name}】还有 {days_left} 天到期（{expires}），记得续费，别等断了才想起来。")
                except ValueError:
                    pass
            await self._check_ports(server, stats)
            await self._check_ssh(server, stats)
            await self._check_watchdog(server, stats)
            await self._check_backup(server, stats)
            await self._check_forecast(server, stats)
            await self._check_updates(server, stats)
        for svc in self.services:
            sname = svc.get("name") or svc.get("url", "?")
            url = svc.get("url", "")
            alive, detail = await self._service_alive(url)
            msg = self._alert_transition(
                f"service:{sname}", not alive,
                f"🚨 服务【{sname}】挂了（{detail}）：{url}",
                f"✅ 服务【{sname}】恢复了。",
            )
            if msg:
                await self._broadcast(msg)
            if url.lower().startswith("https://"):
                days, host, _ = await self._cert_days(url)
                if days is not None:
                    msg = self._alert_transition(
                        f"cert:{host}", days <= self.cert_warn_days,
                        f"⚠️【{host}】HTTPS 证书只剩 {days} 天了，记得续。",
                        None,
                    )
                    if msg:
                        await self._broadcast(msg)

    async def _maybe_daily_report(self):
        if not self.daily_report_time:
            return
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        if now.strftime("%H:%M") != self.daily_report_time:
            return
        if self.data.get("last_report_date") == today:
            return
        self.data["last_report_date"] = today
        self._save_data()
        blocks = []
        for server in self.servers:
            stats = await self._fetch_stats(server)
            blocks.append(self._server_block(server, stats))
        await self._broadcast(f"🌅 服务器日报（{today}）\n" + "\n\n".join(blocks))

    async def _patrol_loop(self):
        logger.info(f"[服务器管家] 巡检启动：{len(self.servers)} 台服务器，间隔 {self.check_interval} 秒")
        while True:
            try:
                await self._patrol_once()
                await self._maybe_daily_report()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"[服务器管家] 巡检出错: {e}")
            await asyncio.sleep(self.check_interval)

    @filter.command("history", alias={"病历"})
    async def cmd_history(self, event: AstrMessageEvent, name: str = ""):
        """看病历本：/病历 看全部最近事件，/病历 美国 只看这台"""
        hist = self.data.get("history", [])
        if name:
            hist = [h for h in hist if f"【{name}】" in h.get("text", "") or name in h.get("text", "")]
        if not hist:
            yield event.plain_result("病历本还是空的——没 news 就是 good news，等真出过事这里就有了。")
            return
        lines = ["📖 病历本" + (f"（{name}）" if name else "（最近 15 条）")]
        for h in hist[-15:][::-1]:
            lines.append(f"{h.get('ts', '')} {h.get('text', '')}")
        yield event.plain_result("\n".join(lines))

    @filter.command("note", alias={"记一笔"})
    async def cmd_note(self, event: AstrMessageEvent):
        """给服务器记备忘：/记一笔 美国 10月3号续费过了，13.23刀"""
        raw = (event.message_str or "").strip()
        for prefix in ("/记一笔", "记一笔", "/note", "note"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):].strip()
                break
        parts = raw.split(None, 1)
        if len(parts) < 2:
            yield event.plain_result("用法：/记一笔 服务器名 内容，比如 /记一笔 美国 续费过了，13.23 刀")
            return
        name, text = parts[0], parts[1].strip()
        if not self._find_server(name):
            yield event.plain_result(f"没有叫「{name}」的服务器。")
            return
        notes = self.data.setdefault("notes", {}).setdefault(name, [])
        notes.append({"ts": datetime.now().strftime("%Y-%m-%d"), "text": text})
        del notes[:-50]
        self._save_data()
        yield event.plain_result(f"📝 记下了，【{name}】的备忘 +1。用 /备忘 {name} 随时翻。")

    @filter.command("notes", alias={"备忘"})
    async def cmd_notes(self, event: AstrMessageEvent, name: str = ""):
        """看备忘：/备忘 看全部，/备忘 美国 只看这台"""
        all_notes = self.data.get("notes", {})
        blocks = []
        for sname, notes in all_notes.items():
            if name and sname != name:
                continue
            if not notes:
                continue
            lines = [f"📝 {sname} 的备忘"]
            for n in notes[::-1]:
                lines.append(f"· {n.get('ts', '')} {n.get('text', '')}")
            blocks.append("\n".join(lines))
        if not blocks:
            yield event.plain_result("还没有备忘。用 /记一笔 服务器名 内容 记第一条。")
            return
        yield event.plain_result("\n\n".join(blocks))

    @filter.command("score", alias={"健康分"})
    async def cmd_score(self, event: AstrMessageEvent):
        """给每台服务器打健康分并排名：/健康分"""
        if not self.servers:
            yield event.plain_result("还没配置服务器。")
            return
        scored = []
        for server in self.servers:
            stats = await self._fetch_stats(server)
            name = server.get("name", "?")
            if stats is None:
                scored.append((0, name, "探针连不上，直接垫底"))
                continue
            score, reasons = 100, []
            disk_pct = stats["disk"].get("percent", 0)
            if disk_pct >= 85:
                score -= 25; reasons.append(f"磁盘 {disk_pct}%")
            elif disk_pct >= 70:
                score -= 10; reasons.append(f"磁盘 {disk_pct}%")
            mem_pct = stats["mem"].get("percent", 0)
            if mem_pct >= 90:
                score -= 15; reasons.append(f"内存 {mem_pct}%")
            elif mem_pct >= 80:
                score -= 7; reasons.append(f"内存 {mem_pct}%")
            containers = stats.get("containers")
            if containers:
                down = [c for c in containers if not c.get("running")]
                if down:
                    score -= 5 * len(down); reasons.append(f"{len(down)} 个容器停着")
            quota_gb = float(server.get("traffic_quota_gb") or 0)
            if quota_gb > 0:
                used_pct = (stats["traffic"].get("month_rx", 0) + stats["traffic"].get("month_tx", 0)) / (quota_gb * 1024**3) * 100
                if used_pct >= 90:
                    score -= 15; reasons.append(f"流量 {used_pct:.0f}%")
                elif used_pct >= 75:
                    score -= 7; reasons.append(f"流量 {used_pct:.0f}%")
            expires = str(server.get("expires") or "")
            if expires:
                try:
                    days_left = (datetime.strptime(expires, "%Y-%m-%d").date() - datetime.now().date()).days
                    if days_left <= 15:
                        score -= 10; reasons.append(f"还有 {days_left} 天到期")
                except ValueError:
                    pass
            scored.append((max(0, score), name, "、".join(reasons) if reasons else "一切正常"))
        scored.sort(key=lambda x: -x[0])
        medals = ["🥇", "🥈", "🥉"]
        lines = ["🏥 服务器健康分"]
        for i, (score, name, why) in enumerate(scored):
            medal = medals[i] if i < len(medals) else "·"
            face = "😎" if score >= 90 else ("🙂" if score >= 70 else ("😷" if score >= 40 else "🚑"))
            lines.append(f"{medal} {name}：{score} 分 {face}（{why}）")
        yield event.plain_result("\n".join(lines))

    @filter.command("sshlog", alias={"登录"})
    async def cmd_sshlog(self, event: AstrMessageEvent, name: str = ""):
        """看 SSH 登录情况：/登录 或 /登录 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        blocks = []
        for server in targets:
            stats = await self._fetch_stats(server)
            sname = server.get("name", "?")
            if stats is None:
                blocks.append(f"🔴 {sname}：探针连不上")
                continue
            ssh = stats.get("ssh")
            if not ssh:
                blocks.append(f"{sname}：读不到 SSH 日志（探针权限不足或没日志文件）")
                continue
            lines = [f"🔑 {sname} 的 SSH"]
            lines.append(f"近 10 分钟失败 {ssh.get('failed_10m', 0)} 次，近 1 小时 {ssh.get('failed_1h', 0)} 次")
            top = ssh.get("top_attacker")
            if top:
                lines.append(f"头号爆破来源：{top.get('ip')}（日志里累计 {top.get('count')} 次）")
            for lg in ssh.get("last_logins", []):
                lines.append(f"✅ {lg.get('time')} {lg.get('user')} 从 {lg.get('ip')} 登录")
            blocks.append("\n".join(lines))
        yield event.plain_result("\n\n".join(blocks))

    @filter.command("updates", alias={"更新"})
    async def cmd_updates(self, event: AstrMessageEvent, name: str = ""):
        """看待更新的包：/更新 或 /更新 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        lines = []
        for server in targets:
            stats = await self._fetch_stats(server)
            sname = server.get("name", "?")
            if stats is None:
                lines.append(f"🔴 {sname}：探针连不上")
                continue
            upd = stats.get("updates")
            if upd is None:
                lines.append(f"{sname}：数不出来（不支持的包管理器或探针没权限）")
            elif upd.get("total", 0) == 0:
                lines.append(f"✅ {sname}：系统是新的，没有待更新")
            else:
                sec = upd.get("security")
                sec_txt = f"，其中安全更新 {sec} 个" if sec is not None else ""
                lines.append(f"📦 {sname}：待更新 {upd.get('total')} 个{sec_txt}")
        yield event.plain_result("\n".join(lines))

    @filter.command("expiry", alias={"到期"})
    async def cmd_expiry(self, event: AstrMessageEvent):
        """到期清单：服务器、域名、证书，谁先到期排前面：/到期"""
        today = datetime.now().date()
        rows: list[tuple[int, str]] = []
        for server in self.servers:
            exp = str(server.get("expires") or "")
            if exp:
                try:
                    d = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
                    rows.append((d, f"🖥 服务器【{server.get('name')}】{exp}，还剩 {d} 天"))
                except ValueError:
                    pass
        for dom in self.domains:
            exp = str(dom.get("expires") or "")
            if exp:
                try:
                    d = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
                    rows.append((d, f"🌐 域名 {dom.get('domain') or dom.get('name')} {exp}，还剩 {d} 天"))
                except ValueError:
                    pass
        for svc in self.services:
            url = svc.get("url", "")
            if url.lower().startswith("https://"):
                days, host, _ = await self._cert_days(url)
                if days is not None:
                    rows.append((days, f"🔐 证书 {svc.get('name') or host}，还剩 {days} 天"))
        if not rows:
            yield event.plain_result("没有可排的到期项：服务器没填到期日、域名清单是空的、也没有 https 服务。")
            return
        rows.sort(key=lambda x: x[0])
        lines = ["⏰ 到期清单（近的在前）"]
        for d, text in rows:
            mark = "🚨" if d <= 7 else ("⚠️" if d <= 30 else "·")
            lines.append(f"{mark} {text}")
        yield event.plain_result("\n".join(lines))

    @filter.command("assets", alias={"资产"})
    async def cmd_assets(self, event: AstrMessageEvent):
        """资产总览：每台多少钱、一年总共烧多少：/资产"""
        if not self.servers:
            yield event.plain_result("还没配置服务器。")
            return
        totals: dict[str, float] = {}
        lines = ["💰 服务器资产"]
        for server in self.servers:
            fee = server.get("yearly_fee")
            cur = str(server.get("currency") or "USD")
            exp = str(server.get("expires") or "未填到期")
            if fee is None:
                lines.append(f"· {server.get('name')}：年费未填（{exp}）")
                continue
            fee = float(fee)
            totals[cur] = totals.get(cur, 0.0) + fee
            lines.append(f"· {server.get('name')}：{fee:.2f} {cur}/年（到期 {exp}）")
        if totals:
            for cur, total in totals.items():
                lines.append(f"合计：{total:.2f} {cur}/年，月均 {total / 12:.2f} {cur}")
        else:
            lines.append("还没给任何服务器填年费。在 servers 配置里给每台加 yearly_fee 和 currency 就能算总账。")
        yield event.plain_result("\n".join(lines))

    @filter.command("backups", alias={"备份"})
    async def cmd_backups(self, event: AstrMessageEvent, name: str = ""):
        """看备份新鲜度：/备份 或 /备份 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        now_ts = int(time.time())
        blocks = []
        for server in targets:
            stats = await self._fetch_stats(server)
            sname = server.get("name", "?")
            if stats is None:
                blocks.append(f"🔴 {sname}：探针连不上")
                continue
            backups = stats.get("backups")
            if not backups:
                blocks.append(f"{sname}：探针没配备份目录（AGENT_BACKUP_DIRS）")
                continue
            lines = [f"💾 {sname} 的备份"]
            for b in backups:
                newest = int(b.get("newest_ts", 0))
                if not newest:
                    lines.append(f"⚠️ {b.get('dir')}：一份备份都没有")
                else:
                    age_h = (now_ts - newest) / 3600
                    age_txt = f"{age_h:.0f} 小时前" if age_h < 48 else f"{age_h / 24:.1f} 天前"
                    mark = "⚠️" if age_h > self.backup_warn_hours else "✅"
                    lines.append(f"{mark} {b.get('dir')}：最新 {b.get('newest_name')}（{age_txt}），共 {b.get('files')} 个文件")
            blocks.append("\n".join(lines))
        yield event.plain_result("\n\n".join(blocks))

    @filter.command("pingtest", alias={"测通"})
    async def cmd_ping(self, event: AstrMessageEvent, name: str = ""):
        """从服务器测国内外连通（查 IP 是否被墙）：/测通 或 /测通 美国"""
        targets = [self._find_server(name)] if name else list(self.servers)
        if not targets or targets == [None]:
            yield event.plain_result("没找到这台服务器，或还没配置服务器。")
            return
        blocks = []
        for server in targets:
            sname = server.get("name", "?")
            url = str(server.get("agent", "")).rstrip("/") + "/pingtest"
            token = server.get("token") or self.agent_token
            headers = {"X-Token": token} if token else {}
            try:
                timeout = aiohttp.ClientTimeout(total=40)
                async with aiohttp.ClientSession(timeout=timeout) as sess:
                    async with sess.get(url, headers=headers) as resp:
                        data = await resp.json()
                results = data.get("targets", [])
            except Exception as e:
                blocks.append(f"🔴 {sname}：测通失败（{str(e)[:40]}）")
                continue
            lines = [f"📡 {sname} 连通性"]
            domestic_ok = foreign_ok = domestic_n = foreign_n = 0
            for i, t in enumerate(results):
                mark = f"{t.get('ms')} ms" if t.get("ok") else "不通"
                lines.append(f"· {t.get('name')}（{t.get('host')}）：{mark}")
                if i < 3:
                    domestic_n += 1
                    domestic_ok += 1 if t.get("ok") else 0
                else:
                    foreign_n += 1
                    foreign_ok += 1 if t.get("ok") else 0
            if domestic_ok > 0 and foreign_ok == 0:
                lines.append("结论：国内通、国外全断——这台的 IP 大概率被墙了，或者国际线路断了。")
            elif domestic_ok == 0 and foreign_ok == 0:
                lines.append("结论：全断——网络本身有问题。")
            elif foreign_ok == foreign_n:
                lines.append("结论：国内外都通，线路健康。")
            else:
                lines.append("结论：部分不通，线路有点毛病，个别目标的问题也可能。")
            blocks.append("\n".join(lines))
        yield event.plain_result("\n\n".join(blocks))

    async def terminate(self):
        if self._task and not self._task.done():
            self._task.cancel()
