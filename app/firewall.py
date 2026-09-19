"""有状态 IPv4 防火墙模拟核心逻辑（纯标准库实现，无 Web 依赖）。

输入一组**有序规则**（源/目的 CIDR、协议、目的端口范围、allow/deny）与一串
**按时间严格递增**的数据包事件（源/目的 IPv4 地址、协议、端口、方向），
逐事件模拟有状态防火墙：

1. **规则匹配（无状态）**：按规则数组顺序首条命中生效——协议相等、源地址命中
   源 CIDR、目的地址命中目的 CIDR，tcp/udp 还要求**目的端口**落在端口范围内；
   未命中任何规则时取 ``default_action``。
2. **会话建立**：首个动作最终为 allow 的**正向（forward）**包建立五元组会话
   ``(protocol, src_ip, src_port, dst_ip, dst_port)``，存活到
   ``建立时刻 + session_timeout``（固定时长，不因后续包刷新；边界时刻仍存活，
   严格大于过期时刻才清理）。
3. **状态放行**：会话存活期间，该五元组的后续正向包与**反向（reverse）**包
   （地址/端口对调后的五元组命中同一会话）一律 ``stateful`` 放行，不再走规则；
   每次命中（正向或反向）都会把会话的 ``last_seen`` 刷新为当前事件时间。
4. **超时重判**：会话过期后（惰性清理：每个事件处理前按其时间戳清理），
   后续包必须重新走规则匹配；反向包即使重新被规则放行也**不会**新建会话，
   正向包重新被规则放行则**重建**会话。
5. **固定容量与淘汰**：会话表容量固定为 ``max_sessions``（1～10000）。正向
   allow 通过重叠检查、确认可以建会话而容量已满时，先淘汰 ``last_seen`` 最早
   的**存活**会话（``last_seen`` 相同则取 ``established_by_event`` 最小者），
   再建立新会话。被淘汰会话即从会话表移除，该流的后续包必须重新走规则裁决，
   如同该流从未建过会话。

会话以正向五元组为键。新会话建立时，其正向键或反向键与任何**存活**会话冲突
（同键重复建立、或两个方向相反的会话同时存活）即判定为
:class:`OverlappingSessionError`，不产生部分结果。

时间戳必须为非负整数且在事件序列内**严格递增**，否则抛出
:class:`OutOfOrderTimestampsError`（一次性列出全部违规位置）。
"""
from __future__ import annotations

from ipaddress import IPv4Address
from typing import Sequence

from .analyzer import normalize_action, parse_cidr_v4
from .router import parse_address_v4

#: 单次请求允许的最大规则条数（允许为空）
FIREWALL_RULES_MAX = 500

#: 单次请求允许的事件数区间
FIREWALL_EVENTS_MIN = 1
FIREWALL_EVENTS_MAX = 2000

#: 会话存活时间（秒）取值范围
SESSION_TIMEOUT_MIN = 1
SESSION_TIMEOUT_MAX = 86400

#: 会话表容量（最大并发存活会话数）取值范围
MAX_SESSIONS_MIN = 1
MAX_SESSIONS_MAX = 10000

#: 端口取值范围
PORT_MIN = 0
PORT_MAX = 65535

TCP = "tcp"
UDP = "udp"
ICMP = "icmp"
PROTOCOLS = (TCP, UDP, ICMP)

#: IANA 协议号，仅用于五元组内部表示
_PROTOCOL_NUMBERS = {TCP: 6, UDP: 17, ICMP: 1}
_PROTOCOL_NAMES = {number: name for name, number in _PROTOCOL_NUMBERS.items()}

FORWARD = "forward"
REVERSE = "reverse"
DIRECTIONS = (FORWARD, REVERSE)

ALLOW = "allow"
DENY = "deny"

#: 匹配来源
MATCH_RULE = "rule"
MATCH_STATEFUL = "stateful"
MATCH_DEFAULT = "default"

#: 单事件会话状态
SESSION_NEW = "new"                          # 正向 allow，首次建立会话
SESSION_ACTIVE = "active"                   # 命中存活会话，stateful 放行
SESSION_EXPIRED = "expired"                 # 所属会话已过期，本包重新走规则
SESSION_REESTABLISHED = "expired_reestablished"  # 过期后正向 allow 重建会话
SESSION_NONE = "none"                       # 无任何关联会话（纯无状态裁决）

#: 会话键冲突类型
CONFLICT_DUPLICATE_FORWARD = "duplicate_forward_key"
CONFLICT_REVERSE = "reverse_key_collision"


class InvalidProtocolError(ValueError):
    """协议不是 tcp / udp / icmp。"""


class InvalidDirectionError(ValueError):
    """方向不是 forward / reverse。"""


class InvalidFirewallPortError(ValueError):
    """端口非法：非整数、布尔、越界或端口范围起点大于终点。"""


class InvalidTimestampError(ValueError):
    """时间戳非法：非非负整数。"""


class OutOfOrderTimestampsError(ValueError):
    """事件时间戳未严格递增。

    ``violations`` 列出全部违规位置，每条形如
    ``{"index", "timestamp", "previous_timestamp"}``。
    """

    def __init__(self, violations: list[dict]) -> None:
        self.violations = violations
        super().__init__(f"{len(violations)} 处时间戳乱序")


class OverlappingSessionError(ValueError):
    """新建会话的五元组键与存活会话重叠。

    - ``index``：触发冲突的事件下标；
    - ``conflict``：:data:`CONFLICT_DUPLICATE_FORWARD`（同键会话仍存活）或
      :data:`CONFLICT_REVERSE`（反向键与另一存活会话相同，即两个方向相反的
      会话同时存活）；
    - ``existing_index``：已存活会话的建立事件下标；
    - ``session_key``：冲突五元组键（正向规范化表示，可直接 JSON 序列化）。
    """

    def __init__(
        self,
        index: int,
        conflict: str,
        existing_index: int,
        session_key: dict,
    ) -> None:
        self.index = index
        self.conflict = conflict
        self.existing_index = existing_index
        self.session_key = session_key
        super().__init__(f"事件 {index} 的会话键与事件 {existing_index} 重叠（{conflict}）")


# ---------- 校验与解析 ----------


def normalize_protocol(protocol: object) -> str:
    """规范化协议：去空白、转小写；非 tcp/udp/icmp 抛出 ValueError。"""
    if not isinstance(protocol, str):
        raise InvalidProtocolError(f"protocol 必须是字符串: {protocol!r}")
    normalized = protocol.strip().lower()
    if normalized not in PROTOCOLS:
        raise InvalidProtocolError(f"非法 protocol（仅支持 tcp/udp/icmp）: {protocol!r}")
    return normalized


def normalize_direction(direction: object) -> str:
    """规范化方向：去空白、转小写；非 forward/reverse 抛出 ValueError。"""
    if not isinstance(direction, str):
        raise InvalidDirectionError(f"direction 必须是字符串: {direction!r}")
    normalized = direction.strip().lower()
    if normalized not in DIRECTIONS:
        raise InvalidDirectionError(
            f"非法 direction（仅支持 forward/reverse）: {direction!r}"
        )
    return normalized


def normalize_port(value: object, field: str = "port") -> int:
    """校验单个端口：非 bool 整数且在 0～65535 之间。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidFirewallPortError(f"{field} 必须是 0～{PORT_MAX} 的整数: {value!r}")
    if not PORT_MIN <= value <= PORT_MAX:
        raise InvalidFirewallPortError(
            f"{field} 必须在 {PORT_MIN}～{PORT_MAX} 之间，实际 {value}"
        )
    return value


def normalize_timestamp(value: object) -> int:
    """校验时间戳：非 bool、非负整数。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidTimestampError(f"时间戳必须是非负整数: {value!r}")
    if value < 0:
        raise InvalidTimestampError(f"时间戳不能为负，实际 {value}")
    return value


def normalize_session_timeout(value: object) -> int:
    """校验会话存活时间：非 bool 整数且在 1～86400 秒之间。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"session_timeout 必须是 {SESSION_TIMEOUT_MIN}～"
                         f"{SESSION_TIMEOUT_MAX} 的整数秒: {value!r}")
    if not SESSION_TIMEOUT_MIN <= value <= SESSION_TIMEOUT_MAX:
        raise ValueError(
            f"session_timeout 必须在 {SESSION_TIMEOUT_MIN}～{SESSION_TIMEOUT_MAX} "
            f"秒之间，实际 {value}"
        )
    return value


def normalize_max_sessions(value: object) -> int:
    """校验会话表容量：非 bool 整数且在 1～10000 之间。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"max_sessions 必须是 {MAX_SESSIONS_MIN}～"
                         f"{MAX_SESSIONS_MAX} 的整数: {value!r}")
    if not MAX_SESSIONS_MIN <= value <= MAX_SESSIONS_MAX:
        raise ValueError(
            f"max_sessions 必须在 {MAX_SESSIONS_MIN}～{MAX_SESSIONS_MAX} "
            f"之间，实际 {value}"
        )
    return value


def _parse_rule(rule: Sequence[object]) -> dict:
    """解析单条规则为整数区间表示。"""
    if len(rule) != 6:
        raise ValueError("每条规则必须是 (action, src_cidr, dst_cidr, protocol, port_start, port_end)")
    action, raw_src, raw_dst, raw_protocol, port_start, port_end = rule
    action = normalize_action(action)
    src_start, src_end, src_cidr = parse_cidr_v4(raw_src)
    dst_start, dst_end, dst_cidr = parse_cidr_v4(raw_dst)
    protocol = normalize_protocol(raw_protocol)

    if protocol == ICMP:
        if port_start is not None or port_end is not None:
            raise InvalidFirewallPortError("icmp 规则不能指定端口范围")
        port_start = port_end = None
    else:
        port_start = normalize_port(port_start, "port_start")
        port_end = normalize_port(port_end, "port_end")
        if port_start > port_end:
            raise InvalidFirewallPortError(
                f"端口范围起点不能大于终点: {port_start} > {port_end}"
            )

    return {
        "action": action,
        "src_start": src_start,
        "src_end": src_end,
        "src_cidr": src_cidr,
        "dst_start": dst_start,
        "dst_end": dst_end,
        "dst_cidr": dst_cidr,
        "protocol": protocol,
        "protocol_num": _PROTOCOL_NUMBERS[protocol],
        "port_start": port_start,
        "port_end": port_end,
    }


def _parse_events(events: Sequence[Sequence[object]]) -> list[dict]:
    """解析事件序列，并检查时间戳严格递增。"""
    parsed: list[dict] = []
    violations: list[dict] = []
    previous_timestamp: int | None = None

    for index, event in enumerate(events):
        if len(event) != 7:
            raise ValueError(
                "每个事件必须是 (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, direction)"
            )
        raw_ts, raw_src, raw_dst, raw_proto, raw_src_port, raw_dst_port, raw_direction = event
        timestamp = normalize_timestamp(raw_ts)
        if previous_timestamp is not None and timestamp <= previous_timestamp:
            violations.append(
                {
                    "index": index,
                    "timestamp": timestamp,
                    "previous_timestamp": previous_timestamp,
                }
            )
        previous_timestamp = timestamp

        src_int, src_ip = parse_address_v4(raw_src)
        dst_int, dst_ip = parse_address_v4(raw_dst)
        protocol = normalize_protocol(raw_proto)
        direction = normalize_direction(raw_direction)

        if protocol == ICMP:
            if raw_src_port is not None or raw_dst_port is not None:
                raise InvalidFirewallPortError("icmp 事件不能携带端口")
            src_port = dst_port = None
        else:
            src_port = normalize_port(raw_src_port, "src_port")
            dst_port = normalize_port(raw_dst_port, "dst_port")

        parsed.append(
            {
                "index": index,
                "timestamp": timestamp,
                "src_int": src_int,
                "src_ip": src_ip,
                "dst_int": dst_int,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "protocol_num": _PROTOCOL_NUMBERS[protocol],
                "src_port": src_port,
                "dst_port": dst_port,
                "direction": direction,
            }
        )

    if violations:
        raise OutOfOrderTimestampsError(violations)
    return parsed


# ---------- 五元组键 ----------


def _flow_key(event: dict) -> tuple[int, int, int, int, int]:
    """求事件所属流的**正向**五元组键（与事件方向无关的规范化表示）。

    正向包直接取自身五元组；反向包把地址/端口对调，得到其对应正向流的键。
    icmp 无端口，内部以 0 占位。
    """
    src_port = event["src_port"] if event["src_port"] is not None else 0
    dst_port = event["dst_port"] if event["dst_port"] is not None else 0
    if event["direction"] == FORWARD:
        return (
            event["protocol_num"],
            event["src_int"],
            src_port,
            event["dst_int"],
            dst_port,
        )
    return (
        event["protocol_num"],
        event["dst_int"],
        dst_port,
        event["src_int"],
        src_port,
    )


def _reverse_key(key: tuple[int, int, int, int, int]) -> tuple[int, int, int, int, int]:
    """正向五元组键对应的反向键。"""
    protocol, src_int, src_port, dst_int, dst_port = key
    return protocol, dst_int, dst_port, src_int, src_port


def _key_to_json(key: tuple[int, int, int, int, int]) -> dict:
    """五元组键转为可 JSON 序列化的正向表示。"""
    protocol_num, src_int, src_port, dst_int, dst_port = key
    protocol = _PROTOCOL_NAMES[protocol_num]
    result = {
        "protocol": protocol,
        "src_ip": str(IPv4Address(src_int)),
        "dst_ip": str(IPv4Address(dst_int)),
    }
    if protocol == ICMP:
        result["src_port"] = None
        result["dst_port"] = None
    else:
        result["src_port"] = src_port
        result["dst_port"] = dst_port
    return result


# ---------- 规则匹配与模拟 ----------


def _match_rule(parsed_rules: Sequence[dict], event: dict) -> int | None:
    """按顺序返回首条命中事件的规则下标；全部未命中返回 None。"""
    for index, rule in enumerate(parsed_rules):
        if rule["protocol_num"] != event["protocol_num"]:
            continue
        if not rule["src_start"] <= event["src_int"] <= rule["src_end"]:
            continue
        if not rule["dst_start"] <= event["dst_int"] <= rule["dst_end"]:
            continue
        if rule["protocol"] != ICMP:
            if not rule["port_start"] <= event["dst_port"] <= rule["port_end"]:
                continue
        return index
    return None


def _session_json(session: dict) -> dict:
    return {
        "key": _key_to_json(session["key"]),
        "created_at": session["created_at"],
        "last_seen": session["last_seen"],
        "expires_at": session["expires_at"],
        "rule_index": session["rule_index"],
        "established_by_event": session["event_index"],
    }


def simulate_firewall(
    rules: Sequence[Sequence[object]],
    events: Sequence[Sequence[object]],
    default_action: object,
    session_timeout: object,
    max_sessions: object,
) -> dict:
    """模拟有状态防火墙，逐事件返回裁决与会话状态。

    ``rules`` 每项为
    ``(action, src_cidr, dst_cidr, protocol, port_start, port_end)``，
    允许为空；``events`` 每项为
    ``(timestamp, src_ip, dst_ip, protocol, src_port, dst_port, direction)``，
    至少 1 个且时间戳严格递增；tcp/udp 事件必须带两个端口，icmp 事件必须
    不带端口；``session_timeout`` 为 1～86400 秒的固定会话存活时间；
    ``max_sessions`` 为 1～10000 的固定会话表容量，容量已满且新会话通过
    重叠检查时，先淘汰 ``last_seen`` 最早（相同则建立事件最早）的存活会话。

    返回可直接 JSON 序列化的字典（结构见 README）。时间戳乱序抛出
    :class:`OutOfOrderTimestampsError`，会话键重叠抛出
    :class:`OverlappingSessionError`，其余非法输入抛出对应 ValueError 子类。
    """
    default_action = normalize_action(default_action)
    session_timeout = normalize_session_timeout(session_timeout)
    max_sessions = normalize_max_sessions(max_sessions)

    if not 0 <= len(rules) <= FIREWALL_RULES_MAX:
        raise ValueError(f"规则数必须在 0～{FIREWALL_RULES_MAX} 之间，实际 {len(rules)}")
    if not FIREWALL_EVENTS_MIN <= len(events) <= FIREWALL_EVENTS_MAX:
        raise ValueError(
            f"事件数必须在 {FIREWALL_EVENTS_MIN}～{FIREWALL_EVENTS_MAX} 之间，"
            f"实际 {len(events)}"
        )

    parsed_rules = [_parse_rule(rule) for rule in rules]
    parsed_events = _parse_events(events)

    # 存活会话：正向五元组键 -> 会话；expired_flows 记录最近过期的会话，
    # 用于区分“从未有会话”与“会话刚过期、本包重新走规则”。
    sessions: dict[tuple, dict] = {}
    expired_flows: dict[tuple, dict] = {}

    results: list[dict] = []
    allowed = denied = new_sessions = expired_sessions = evicted_sessions = 0

    for event in parsed_events:
        timestamp = event["timestamp"]

        # 惰性清理：expires_at 严格小于当前时间戳才过期（边界时刻仍存活）
        for key, session in list(sessions.items()):
            if session["expires_at"] < timestamp:
                del sessions[key]
                expired_flows[key] = session
                expired_sessions += 1

        key = _flow_key(event)
        live_session = sessions.get(key)
        was_expired = key in expired_flows
        evicted_session = None

        if live_session is not None:
            # 存活会话：正向后续包与反向包一律 stateful 放行，并刷新 last_seen
            live_session["last_seen"] = timestamp
            match = {"type": MATCH_STATEFUL, "rule_index": None}
            action = ALLOW
            session_state = SESSION_ACTIVE
            session_obj = _session_json(live_session)
        else:
            rule_index = _match_rule(parsed_rules, event)
            if rule_index is None:
                match = {"type": MATCH_DEFAULT, "rule_index": None}
                action = default_action
            else:
                match = {"type": MATCH_RULE, "rule_index": rule_index}
                action = parsed_rules[rule_index]["action"]

            session_obj = None
            if event["direction"] == FORWARD and action == ALLOW:
                # 正向 allow 建立会话；先检查与存活会话的键重叠
                reverse = _reverse_key(key)
                if key in sessions:
                    # 同正向键会话仍存活（理论上已被上方存活分支处理，防御性兜底）
                    existing = sessions[key]
                    raise OverlappingSessionError(
                        event["index"],
                        CONFLICT_DUPLICATE_FORWARD,
                        existing["event_index"],
                        _key_to_json(key),
                    )
                if reverse in sessions:
                    # 新会话的反向键（=本流反向包的键）撞上另一存活会话的正向
                    # 键：两个方向相反的会话将同时存活，反向包无法唯一归属
                    existing = sessions[reverse]
                    raise OverlappingSessionError(
                        event["index"],
                        CONFLICT_REVERSE,
                        existing["event_index"],
                        _key_to_json(key),
                    )

                # 重叠检查通过、确认可建会话后，容量已满则淘汰一个存活会话：
                # last_seen 最早者优先；相同则 established_by_event 最小者优先。
                if len(sessions) >= max_sessions:
                    victim_key = min(
                        sessions,
                        key=lambda k: (
                            sessions[k]["last_seen"],
                            sessions[k]["event_index"],
                        ),
                    )
                    victim = sessions.pop(victim_key)
                    evicted_session = _session_json(victim)
                    evicted_sessions += 1

                new_session = {
                    "key": key,
                    "created_at": timestamp,
                    "last_seen": timestamp,
                    "expires_at": timestamp + session_timeout,
                    "rule_index": rule_index,
                    "event_index": event["index"],
                }
                sessions[key] = new_session
                expired_flows.pop(key, None)
                new_sessions += 1
                if was_expired:
                    session_state = SESSION_REESTABLISHED
                else:
                    session_state = SESSION_NEW
                session_obj = _session_json(new_session)
            elif was_expired:
                # 会话已过期：反向包或被拒正向包重新走规则，不建立会话
                session_state = SESSION_EXPIRED
                session_obj = _session_json(expired_flows[key])
            else:
                session_state = SESSION_NONE

        if action == ALLOW:
            allowed += 1
        else:
            denied += 1

        results.append(
            {
                "index": event["index"],
                "timestamp": timestamp,
                "src_ip": event["src_ip"],
                "dst_ip": event["dst_ip"],
                "protocol": event["protocol"],
                "src_port": event["src_port"],
                "dst_port": event["dst_port"],
                "direction": event["direction"],
                "match": match,
                "action": action,
                "session_state": session_state,
                "session": session_obj,
                "evicted_session": evicted_session,
            }
        )

    return {
        "rule_count": len(parsed_rules),
        "event_count": len(parsed_events),
        "default_action": default_action,
        "session_timeout": session_timeout,
        "max_sessions": max_sessions,
        "results": results,
        "summary": {
            "allowed": allowed,
            "denied": denied,
            "new_sessions": new_sessions,
            "expired_sessions": expired_sessions,
            "evicted_sessions": evicted_sessions,
            "active_sessions": len(sessions),
        },
    }
