"""有状态防火墙模拟核心逻辑的单元测试。"""
import pytest

from app.firewall import (
    FIREWALL_EVENTS_MAX,
    FIREWALL_RULES_MAX,
    MAX_SESSIONS_MAX,
    PORT_MAX,
    SESSION_TIMEOUT_MAX,
    CONFLICT_REVERSE,
    InvalidDirectionError,
    InvalidFirewallPortError,
    InvalidProtocolError,
    InvalidTimestampError,
    OutOfOrderTimestampsError,
    OverlappingSessionError,
    normalize_direction,
    normalize_max_sessions,
    normalize_port,
    normalize_protocol,
    normalize_session_timeout,
    normalize_timestamp,
    simulate_firewall,
)

ALLOW_ALL_TCP = (
    "allow",
    "0.0.0.0/0",
    "0.0.0.0/0",
    "tcp",
    0,
    65535,
)
DENY_ALL_TCP = ("deny", "0.0.0.0/0", "0.0.0.0/0", "tcp", 0, 65535)
ALLOW_ALL_ICMP = ("allow", "0.0.0.0/0", "0.0.0.0/0", "icmp", None, None)


def fwd(timestamp, src="1.1.1.1", sport=1000, dst="2.2.2.2", dport=80,
        proto="tcp", direction="forward"):
    return (timestamp, src, dst, proto, sport, dport, direction)


def rev(timestamp, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1000, proto="tcp"):
    return (timestamp, src, dst, proto, sport, dport, "reverse")


def simulate(events, rules=(ALLOW_ALL_TCP,), default="deny", timeout=30, max_sessions=10000):
    return simulate_firewall(list(rules), events, default, timeout, max_sessions)


# ---------- 校验函数 ----------


def test_normalize_protocol_direction_case_insensitive():
    assert normalize_protocol(" TCP ") == "tcp"
    assert normalize_protocol("UDP") == "udp"
    assert normalize_direction(" REVERSE ") == "reverse"
    with pytest.raises(InvalidProtocolError):
        normalize_protocol("gre")
    with pytest.raises(InvalidProtocolError):
        normalize_protocol(6)
    with pytest.raises(InvalidDirectionError):
        normalize_direction("inbound")


@pytest.mark.parametrize("value", [0, 1, 80, PORT_MAX])
def test_normalize_port_accepts_range(value):
    assert normalize_port(value) == value


@pytest.mark.parametrize("value", [-1, PORT_MAX + 1, 100_000, True, False, 1.0, "80", None])
def test_normalize_port_rejects_bad(value):
    with pytest.raises(InvalidFirewallPortError):
        normalize_port(value)


@pytest.mark.parametrize("value", [0, 1, 10_000])
def test_normalize_timestamp_accepts_non_negative(value):
    assert normalize_timestamp(value) == value


@pytest.mark.parametrize("value", [-1, 1.5, True, "0", None])
def test_normalize_timestamp_rejects_bad(value):
    with pytest.raises(InvalidTimestampError):
        normalize_timestamp(value)


@pytest.mark.parametrize("value", [1, 30, SESSION_TIMEOUT_MAX])
def test_normalize_session_timeout_accepts_range(value):
    assert normalize_session_timeout(value) == value


@pytest.mark.parametrize("value", [0, SESSION_TIMEOUT_MAX + 1, True, 1.0, "30"])
def test_normalize_session_timeout_rejects_bad(value):
    with pytest.raises(ValueError):
        normalize_session_timeout(value)


@pytest.mark.parametrize("value", [1, 2, 10000, MAX_SESSIONS_MAX])
def test_normalize_max_sessions_accepts_range(value):
    assert normalize_max_sessions(value) == value


@pytest.mark.parametrize("value", [0, MAX_SESSIONS_MAX + 1, -1, True, 1.0, "100", None])
def test_normalize_max_sessions_rejects_bad(value):
    with pytest.raises(ValueError):
        normalize_max_sessions(value)


# ---------- 基础语义 ----------


def test_first_forward_allow_creates_session():
    result = simulate([fwd(0)])
    event = result["results"][0]
    assert event["match"] == {"type": "rule", "rule_index": 0}
    assert event["action"] == "allow"
    assert event["session_state"] == "new"
    assert event["session"] == {
        "key": {
            "protocol": "tcp",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1000,
            "dst_port": 80,
        },
        "created_at": 0,
        "last_seen": 0,
        "expires_at": 30,
        "rule_index": 0,
        "established_by_event": 0,
    }
    assert event["evicted_session"] is None
    assert result["summary"] == {
        "allowed": 1,
        "denied": 0,
        "new_sessions": 1,
        "expired_sessions": 0,
        "evicted_sessions": 0,
        "active_sessions": 1,
    }


def test_reverse_packets_statefully_allowed_within_timeout():
    result = simulate([fwd(0), rev(5), rev(29)])
    states = [e["session_state"] for e in result["results"]]
    assert states == ["new", "active", "active"]
    matches = [e["match"] for e in result["results"]]
    assert matches[1] == {"type": "stateful", "rule_index": None}
    assert all(e["action"] == "allow" for e in result["results"])
    # stateful 放行携带原会话信息（含建立规则索引）
    assert result["results"][1]["session"]["rule_index"] == 0
    assert result["results"][1]["session"]["established_by_event"] == 0
    # 每次 stateful 命中（正向/反向）都把 last_seen 刷新为当前事件时间
    assert [e["session"]["last_seen"] for e in result["results"]] == [0, 5, 29]
    # 固定过期时刻不因 last_seen 刷新而延长
    assert all(e["session"]["expires_at"] == 30 for e in result["results"])


def test_expiry_boundary_inclusive():
    # expires_at == 30：时间戳 30 仍存活，31 才过期
    result = simulate([fwd(0), rev(30), rev(31)], default="deny")
    states = [e["session_state"] for e in result["results"]]
    assert states == ["new", "active", "expired"]
    actions = [e["action"] for e in result["results"]]
    # 过期后反向包重新走规则：allow-all 规则仍放行，但不再是 stateful
    assert actions == ["allow", "allow", "allow"]
    assert result["results"][1]["match"]["type"] == "stateful"
    assert result["results"][2]["match"] == {"type": "rule", "rule_index": 0}
    assert result["summary"] == {
        "allowed": 3,
        "denied": 0,
        "new_sessions": 1,
        "expired_sessions": 1,
        "evicted_sessions": 0,
        "active_sessions": 0,
    }


def test_expired_reverse_rematched_and_no_session_created_even_if_allowed():
    # 超时后反向包即使被规则 allow，也不建立会话
    result = simulate([fwd(0), rev(31)])
    assert result["results"][1]["session_state"] == "expired"
    assert result["results"][1]["action"] == "allow"
    assert result["results"][1]["match"]["type"] == "rule"
    assert result["summary"]["new_sessions"] == 1
    assert result["summary"]["active_sessions"] == 0


def test_forward_re_allow_after_expiry_reestablishes_session():
    result = simulate([fwd(0), fwd(40)])
    states = [e["session_state"] for e in result["results"]]
    assert states == ["new", "expired_reestablished"]
    second = result["results"][1]
    assert second["session"]["created_at"] == 40
    assert second["session"]["last_seen"] == 40
    assert second["session"]["expires_at"] == 70
    assert result["summary"] == {
        "allowed": 2,
        "denied": 0,
        "new_sessions": 2,
        "expired_sessions": 1,
        "evicted_sessions": 0,
        "active_sessions": 1,
    }


def test_denied_forward_creates_no_session():
    result = simulate([fwd(0), rev(1)], rules=(DENY_ALL_TCP,), default="deny")
    assert [e["action"] for e in result["results"]] == ["deny", "deny"]
    assert [e["session_state"] for e in result["results"]] == ["none", "none"]
    assert all(e["session"] is None for e in result["results"])
    assert result["summary"]["new_sessions"] == 0


def test_default_action_used_when_no_rule_matches():
    result = simulate([fwd(0)], rules=(), default="allow")
    event = result["results"][0]
    assert event["match"] == {"type": "default", "rule_index": None}
    assert event["action"] == "allow"
    assert event["session_state"] == "new"
    # 默认 allow 建立的会话，rule_index 为 None
    assert event["session"]["rule_index"] is None


def test_default_deny_no_session():
    result = simulate([fwd(0)], rules=(), default="deny")
    event = result["results"][0]
    assert event["match"]["type"] == "default"
    assert event["action"] == "deny"
    assert event["session_state"] == "none"
    assert event["session"] is None


def test_first_matching_rule_wins_in_order():
    rules = (
        ("deny", "0.0.0.0/0", "0.0.0.0/0", "tcp", 0, 65535),
        ALLOW_ALL_TCP,
    )
    result = simulate([fwd(0)], rules=rules, default="allow")
    assert result["results"][0]["match"] == {"type": "rule", "rule_index": 0}
    assert result["results"][0]["action"] == "deny"


def test_destination_port_range_matching():
    rules = (("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 80, 90),)
    # 不同源端口 => 不同五元组，逐个独立走规则，避免会话复用掩盖端口判定
    result = simulate(
        [fwd(0, sport=2001, dport=79), fwd(1, sport=2002, dport=80),
         fwd(2, sport=2003, dport=90), fwd(3, sport=2004, dport=91)],
        rules=rules,
    )
    assert [e["action"] for e in result["results"]] == ["deny", "allow", "allow", "deny"]
    assert [e["match"]["type"] for e in result["results"]] == [
        "default",
        "rule",
        "rule",
        "default",
    ]
    assert [e["session_state"] for e in result["results"]] == [
        "none",
        "new",
        "new",
        "none",
    ]


def test_source_port_not_considered_in_rule_match():
    rules = (("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 80, 80),)
    # 目的端口 80 命中；源端口是什么不影响
    result = simulate([fwd(0, sport=12345, dport=80)])
    assert result["results"][0]["action"] == "allow"


def test_src_dst_cidrs_and_protocol_must_all_match():
    rules = (
        ("allow", "10.0.0.0/8", "192.168.0.0/16", "tcp", 80, 80),
    )
    events = [
        fwd(0, src="10.1.2.3", dst="192.168.1.1", dport=80),   # 命中
        fwd(1, src="11.1.2.3", dst="192.168.1.1", dport=80),   # 源不命中
        fwd(2, src="10.1.2.3", dst="192.169.1.1", dport=80),   # 目的不命中
        fwd(3, src="10.1.2.3", dst="192.168.1.1", dport=80, proto="udp"),  # 协议不命中
    ]
    result = simulate(events, rules=rules, default="deny")
    assert [e["action"] for e in result["results"]] == ["allow", "deny", "deny", "deny"]


def test_icmp_sessions_without_ports():
    events = [
        fwd(0, proto="icmp", sport=None, dport=None),
        rev(1, proto="icmp", sport=None, dport=None),
    ]
    result = simulate(events, rules=(ALLOW_ALL_ICMP,))
    states = [e["session_state"] for e in result["results"]]
    assert states == ["new", "active"]
    key = result["results"][0]["session"]["key"]
    assert key["protocol"] == "icmp"
    assert key["src_port"] is None and key["dst_port"] is None


def test_repeated_forward_while_alive_is_stateful_not_overlap():
    result = simulate([fwd(0), fwd(10), fwd(20)])
    assert [e["session_state"] for e in result["results"]] == [
        "new",
        "active",
        "active",
    ]
    assert result["summary"]["new_sessions"] == 1


def test_lazy_expiry_sweeps_all_sessions_at_event_timestamp():
    # 两个不同会话分别在 t=0、t=5 建立（timeout=10）；t=20 的事件前二者
    # 都应被惰性清理，expired_sessions 按会话计为 2
    events = [
        fwd(0, sport=1000),
        fwd(5, sport=2000),
        fwd(20, sport=3000),
    ]
    result = simulate(events, timeout=10)
    assert result["results"][2]["session_state"] == "new"
    assert result["summary"]["expired_sessions"] == 2
    assert result["summary"]["new_sessions"] == 3


def test_fixed_lifetime_not_refreshed_by_traffic():
    # 存活期内大量流量不刷新过期时刻
    events = [fwd(0), rev(5), rev(10), rev(20), rev(31)]
    result = simulate(events, timeout=30, default="deny")
    assert result["results"][-1]["session_state"] == "expired"
    assert result["results"][0]["session"]["expires_at"] == 30


# ---------- 乱序时间戳 ----------


def test_out_of_order_timestamps_collected_at_once():
    events = [fwd(10), fwd(5), fwd(8), fwd(6), fwd(6)]
    with pytest.raises(OutOfOrderTimestampsError) as exc_info:
        simulate(events)
    violations = exc_info.value.violations
    assert violations == [
        {"index": 1, "timestamp": 5, "previous_timestamp": 10},
        {"index": 3, "timestamp": 6, "previous_timestamp": 8},
        {"index": 4, "timestamp": 6, "previous_timestamp": 6},
    ]


def test_equal_timestamps_are_out_of_order():
    with pytest.raises(OutOfOrderTimestampsError):
        simulate([fwd(0), fwd(0)])


def test_single_event_always_ordered():
    result = simulate([fwd(100)])
    assert result["results"][0]["timestamp"] == 100


# ---------- 重叠会话键 ----------


def test_reverse_key_collision_raises():
    # A 正向会话存活时，又来一个正向 allow，其正向键恰为 A 的反向键
    events = [
        fwd(0, src="1.1.1.1", sport=1000, dst="2.2.2.2", dport=80),
        fwd(1, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1000),
    ]
    with pytest.raises(OverlappingSessionError) as exc_info:
        simulate(events)
    err = exc_info.value
    assert err.index == 1
    assert err.conflict == CONFLICT_REVERSE
    assert err.existing_index == 0
    assert err.session_key["src_ip"] == "2.2.2.2"


def test_opposite_sessions_allowed_after_expiry():
    # A 过期后，反向再发起正向会话是合法的
    events = [
        fwd(0, src="1.1.1.1", sport=1000, dst="2.2.2.2", dport=80),
        fwd(40, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1000),
    ]
    result = simulate(events, timeout=30)
    assert [e["session_state"] for e in result["results"]] == ["new", "new"]
    assert result["summary"]["expired_sessions"] == 1
    assert result["summary"]["active_sessions"] == 1


# ---------- 输入校验（核心层防御） ----------


def test_port_range_reversed_rejected():
    rules = (("allow", "0.0.0.0/0", "0.0.0.0/0", "tcp", 100, 80),)
    with pytest.raises(InvalidFirewallPortError):
        simulate([fwd(0)], rules=rules)


def test_icmp_rule_with_ports_rejected():
    rules = (("allow", "0.0.0.0/0", "0.0.0.0/0", "icmp", 0, 0),)
    with pytest.raises(InvalidFirewallPortError):
        simulate([fwd(0, proto="icmp", sport=None, dport=None)], rules=rules)


def test_icmp_event_with_ports_rejected():
    with pytest.raises(InvalidFirewallPortError):
        simulate([fwd(0, proto="icmp", sport=None, dport=0)])


def test_bad_cidr_and_address_propagate():
    from app.analyzer import InvalidCIDRError
    from app.router import InvalidIPv4AddressError

    with pytest.raises(InvalidCIDRError):
        simulate([fwd(0)], rules=(("allow", "10.0.0.0/33", "0.0.0.0/0", "tcp", 0, 65535),))
    with pytest.raises(InvalidIPv4AddressError):
        simulate([fwd(0, src="8.8.8.8/32")])


def test_size_limits():
    with pytest.raises(ValueError):
        simulate_firewall(
            [ALLOW_ALL_TCP] * (FIREWALL_RULES_MAX + 1), [fwd(0)], "deny", 30, 10000
        )
    with pytest.raises(ValueError):
        simulate_firewall([], [], "deny", 30, 10000)
    with pytest.raises(ValueError):
        simulate_firewall(
            [], [fwd(i, sport=(1000 + i) % 65000) for i in range(FIREWALL_EVENTS_MAX + 1)],
            "deny",
            30,
            10000,
        )
    # max_sessions 边界：0 与 10001 均非法
    with pytest.raises(ValueError):
        simulate_firewall([ALLOW_ALL_TCP], [fwd(0)], "deny", 30, 0)
    with pytest.raises(ValueError):
        simulate_firewall([ALLOW_ALL_TCP], [fwd(0)], "deny", 30, MAX_SESSIONS_MAX + 1)


def test_limits_accepted():
    events = [fwd(i, src=f"1.0.{i // 256}.{i % 256}", sport=i % 60000 + 1)
              for i in range(100)]
    result = simulate(events, timeout=86400)
    assert len(result["results"]) == 100
    assert result["summary"]["active_sessions"] == 100


def test_result_order_matches_event_order():
    events = [fwd(0), rev(1), fwd(2, sport=2000), rev(3, sport=80, dport=2000)]
    result = simulate(events)
    assert [e["index"] for e in result["results"]] == [0, 1, 2, 3]
    assert [e["timestamp"] for e in result["results"]] == [0, 1, 2, 3]


def test_top_level_echo_fields():
    result = simulate([fwd(0)], default="deny", timeout=45, max_sessions=128)
    assert result["rule_count"] == 1
    assert result["event_count"] == 1
    assert result["default_action"] == "deny"
    assert result["session_timeout"] == 45
    assert result["max_sessions"] == 128


# ---------- 固定容量与淘汰 ----------


def test_capacity_full_evicts_oldest_last_seen():
    # 容量 2：流 A(t0，t2 反向刷新)、流 B(t1)，t3 建流 C 时淘汰 last_seen
    # 最早的 B（last_seen=1）而非 A（last_seen=2）
    events = [
        fwd(0, sport=1001),
        fwd(1, sport=1002),
        rev(2, sport=80, dport=1001),
        fwd(3, sport=1003),
    ]
    result = simulate(events, timeout=100, max_sessions=2)
    evicted = [e["evicted_session"] for e in result["results"]]
    assert evicted[:3] == [None, None, None]
    assert evicted[3] is not None
    assert evicted[3]["key"]["src_port"] == 1002
    assert evicted[3]["created_at"] == 1
    assert evicted[3]["last_seen"] == 1
    assert evicted[3]["established_by_event"] == 1

    assert [e["session_state"] for e in result["results"]] == [
        "new", "new", "active", "new",
    ]
    assert result["summary"] == {
        "allowed": 4,
        "denied": 0,
        "new_sessions": 3,
        "expired_sessions": 0,
        "evicted_sessions": 1,
        "active_sessions": 2,
    }


def test_evicted_flows_subsequent_packets_re_adjudicated_as_none():
    # A(t0) 在 t2 被反向包刷新（last_seen=2）；建 C(t3) 时淘汰 last_seen=1 的 B。
    # t4 B 的反向包无存活会话，按规则重新裁决：
    # allow-all 放行但反向不建会话，session_state 为 none（既未过期也无会话）
    events = [
        fwd(0, sport=1001),
        fwd(1, sport=1002),
        rev(2, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1001),  # A 刷新
        fwd(3, sport=1003),                        # 淘汰 B
        rev(4, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1002),  # B 的反向包
        fwd(5, sport=1002),                        # B 的正向包：重新建会话
    ]
    result = simulate(events, timeout=100, max_sessions=2)
    assert result["results"][3]["evicted_session"]["key"]["src_port"] == 1002
    fourth = result["results"][4]
    assert fourth["match"]["type"] == "rule"
    assert fourth["action"] == "allow"
    assert fourth["session_state"] == "none"
    assert fourth["session"] is None

    fifth = result["results"][5]
    assert fifth["session_state"] == "new"
    assert fifth["session"]["created_at"] == 5


def test_oldest_established_session_evicted_without_refresh():
    # 容量 2：A(t0)、B(t1) 均无后续流量（last_seen 分别为 0、1），
    # t2 建 C 时淘汰 last_seen 最早的 A（established_by_event 也最小）。
    # 注：时间戳严格递增，last_seen 跨存活会话不可能相等；
    # established_by_event 仅作相同 last_seen 时的防御性兜底次序。
    events = [
        fwd(0, sport=1001),
        fwd(1, sport=1002),
        fwd(2, sport=1003),
    ]
    result = simulate(events, timeout=100, max_sessions=2)
    assert result["results"][2]["evicted_session"]["key"]["src_port"] == 1001
    assert result["results"][2]["evicted_session"]["established_by_event"] == 0


def test_capacity_one_each_new_session_evicts_previous():
    events = [fwd(i, sport=1000 + i) for i in range(5)]
    result = simulate(events, timeout=1000, max_sessions=1)
    assert [e["evicted_session"] is None for e in result["results"]] == [
        True, False, False, False, False,
    ]
    for i, event in enumerate(result["results"][1:], start=1):
        assert event["evicted_session"]["established_by_event"] == i - 1
    assert result["summary"]["evicted_sessions"] == 4
    assert result["summary"]["active_sessions"] == 1


def test_expiry_frees_capacity_without_eviction():
    # timeout=10：A(t0,expires=10)、B(t1,expires=11) 在 t=12 的事件前均已
    # 严格过期并被惰性清理；建 C 不触发淘汰
    events = [
        fwd(0, sport=1001),
        fwd(1, sport=1002),
        fwd(12, sport=1003),
    ]
    result = simulate(events, timeout=10, max_sessions=2)
    assert result["results"][2]["evicted_session"] is None
    assert result["results"][2]["session_state"] == "new"
    assert result["summary"] == {
        "allowed": 3,
        "denied": 0,
        "new_sessions": 3,
        "expired_sessions": 2,
        "evicted_sessions": 0,
        "active_sessions": 1,
    }


def test_denied_packet_does_not_evict_when_full():
    # 仅 10.0.0.0/24 放行：先建满 2 个会话，第三个被拒的正向包不触发淘汰
    allow_lan = ("allow", "10.0.0.0/24", "0.0.0.0/0", "tcp", 0, 65535)
    events = [
        fwd(0, src="10.0.0.1", sport=1001),
        fwd(1, src="10.0.0.2", sport=1002),
        fwd(2, src="9.9.9.9", sport=1003),        # 未命中规则，默认 deny
    ]
    result = simulate(
        events,
        rules=(allow_lan,),
        default="deny",
        timeout=100,
        max_sessions=2,
    )
    assert [e["match"]["type"] for e in result["results"]] == [
        "rule", "rule", "default",
    ]
    assert result["results"][2]["action"] == "deny"
    assert result["results"][2]["evicted_session"] is None
    assert result["summary"]["evicted_sessions"] == 0
    assert result["summary"]["active_sessions"] == 2


def test_overlap_check_runs_before_eviction_no_partial_result():
    # 容量已满（A 存活），事件 1 的新会话反向键与 A 冲突：重叠错误优先，
    # 不淘汰任何会话
    events = [
        fwd(0, src="1.1.1.1", sport=1000, dst="2.2.2.2", dport=80),
        fwd(1, src="2.2.2.2", sport=80, dst="1.1.1.1", dport=1000),
    ]
    with pytest.raises(OverlappingSessionError):
        simulate(events, timeout=100, max_sessions=1)


def test_reestablish_after_expiry_at_full_capacity_does_not_evict():
    # 容量 1：A 在 t=40 已过期并被清理，同流重建不需要淘汰
    result = simulate([fwd(0), fwd(40)], timeout=30, max_sessions=1)
    assert result["results"][1]["session_state"] == "expired_reestablished"
    assert result["results"][1]["evicted_session"] is None
    assert result["summary"] == {
        "allowed": 2,
        "denied": 0,
        "new_sessions": 2,
        "expired_sessions": 1,
        "evicted_sessions": 0,
        "active_sessions": 1,
    }


def test_evicted_session_snapshot_carries_last_seen():
    events = [
        fwd(0, sport=1001),
        fwd(1, sport=1002),
        rev(5, sport=80, dport=1001),
        fwd(6, sport=1003),
    ]
    result = simulate(events, timeout=100, max_sessions=2)
    # A 的 last_seen 已刷新到 5；被淘汰的是 last_seen=1 的 B
    evicted = result["results"][3]["evicted_session"]
    assert evicted["last_seen"] == 1
    assert result["results"][2]["session"]["last_seen"] == 5
