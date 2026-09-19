"""FastAPI 接口测试。"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_analyze(rules):
    return client.post("/analyze", json={"rules": rules})


def post_compare(left, right):
    return client.post("/compare", json={"left": left, "right": right})


def test_root_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_full_partial_shadowed():
    resp = post_analyze(
        [
            {"action": "allow", "cidr": "10.0.0.0/8"},
            {"action": "deny", "cidr": "10.1.0.0/16"},
            {"action": "ALLOW", "cidr": "192.168.0.0/16"},
            {"action": "deny", "cidr": "10.0.0.0/7"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] == 4
    assert [r["status"] for r in body["rules"]] == [
        "full",
        "shadowed",
        "full",
        "partial",
    ]
    # action 大小写不敏感并规范化
    assert body["rules"][2]["action"] == "allow"
    assert body["rules"][0]["status_label"] == "全生效"
    assert body["rules"][3]["effective_cidrs"] == ["11.0.0.0/8"]
    assert body["summary"] == {
        "full": 2,
        "partial": 1,
        "shadowed": 1,
        "effective_allow_addresses": (1 << 24) + (1 << 16),
        "effective_deny_addresses": 1 << 24,
    }


def test_bare_ip_accepted_as_32():
    resp = post_analyze([{"action": "allow", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["cidr"] == "8.8.8.8/32"
    assert rule["total_addresses"] == 1
    assert rule["status"] == "full"


def test_empty_rules_422():
    assert client.post("/analyze", json={"rules": []}).status_code == 422
    assert client.post("/analyze", json={}).status_code == 422


def test_invalid_cidr_422():
    for bad in ["10.0.0.0/33", "10.0.0.1/8", "garbage", "9.9.9.9/99"]:
        resp = post_analyze([{"action": "allow", "cidr": bad}])
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]


def test_ipv6_422():
    for bad in ["2001:db8::/32", "::1", "fe80::1/64"]:
        assert post_analyze([{"action": "allow", "cidr": bad}]).status_code == 422, bad


def test_bad_action_422():
    assert post_analyze(
        [{"action": "permit", "cidr": "10.0.0.0/8"}]
    ).status_code == 422


def test_missing_field_422():
    assert client.post("/analyze", json={"rules": [{"cidr": "10.0.0.0/8"}]}).status_code == 422
    assert client.post("/analyze", json={"rules": [{"action": "allow"}]}).status_code == 422


def test_non_list_body_422():
    assert client.post("/analyze", json={"rules": "nope"}).status_code == 422


def test_malformed_json_422():
    resp = client.post(
        "/analyze",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ---------- /compare ----------

def test_compare_equivalent_empty_sets():
    resp = post_compare(
        {"rules": [], "default_action": "allow"},
        {"rules": [], "default_action": "ALLOW"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_default_only_full_space_diff():
    resp = post_compare(
        {"rules": [], "default_action": "deny"},
        {"rules": [], "default_action": "allow"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is False
    assert body["differences"] == [
        {
            "left_action": "deny",
            "right_action": "allow",
            "address_count": 1 << 32,
            "cidrs": ["0.0.0.0/0"],
        }
    ]


def test_compare_rules_only_one_side():
    resp = post_compare(
        {"rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        {"rules": [], "default_action": "deny"},
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_compare_order_sensitivity_and_bidirectional_groups():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.1.0.0/16"},
            ],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "deny", "cidr": "10.1.0.0/16"},
                {"action": "allow", "cidr": "10.0.0.0/8"},
            ],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_shadowed_rule_still_equivalent():
    resp = post_compare(
        {
            "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.0.0.1/32"},
            ],
            "default_action": "Deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_validation_422():
    base = {"rules": [], "default_action": "deny"}

    # 缺少 default_action
    resp = client.post("/compare", json={"left": {"rules": []}, "right": base})
    assert resp.status_code == 422

    # 非法 default_action / action
    assert post_compare(
        {"rules": [], "default_action": "permit"}, base
    ).status_code == 422
    assert post_compare(
        {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        base,
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用 /analyze 校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        resp = post_compare(
            {"rules": [{"action": "allow", "cidr": bad}],
             "default_action": "deny"},
            base,
        )
        assert resp.status_code == 422, bad

    # 缺少一侧 / 请求体为空
    assert client.post("/compare", json={"left": base}).status_code == 422
    assert client.post("/compare", json={}).status_code == 422


# ---------- /explain ----------

def post_explain(rules, default_action, query):
    return client.post(
        "/explain",
        json={"rules": rules, "default_action": default_action, "query": query},
    )


def test_explain_basic_attribution():
    resp = post_explain(
        [
            {"action": "allow", "cidr": "10.0.0.0/16"},
            {"action": "deny", "cidr": "10.0.1.0/24"},
            {"action": "deny", "cidr": "10.2.0.0/16"},
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "10.0.0.0/8"
    assert body["total_addresses"] == 1 << 24

    attribution = body["attribution"]
    # 规则 1 在 query 内被完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0]["action"] == "allow"
    assert attribution[0]["cidrs"] == ["10.0.0.0/16"]
    assert attribution[1]["action"] == "deny"
    assert attribution[1]["cidrs"] == ["10.2.0.0/16"]
    assert attribution[2]["action"] == "deny"
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_normalized():
    resp = post_explain(
        [{"action": "ALLOW", "cidr": "8.8.8.0/24"}],
        "Deny",
        "8.8.8.8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "8.8.8.8/32"
    assert body["total_addresses"] == 1
    # action / default_action 大小写不敏感并规范化
    assert body["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    resp = post_explain([], "allow", "192.168.0.0/16")
    assert resp.status_code == 200
    assert resp.json()["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_validation_422():
    # 缺少 default_action / query、空请求体
    assert client.post(
        "/explain", json={"rules": [], "query": "10.0.0.0/8"}
    ).status_code == 422
    assert client.post(
        "/explain", json={"rules": [], "default_action": "deny"}
    ).status_code == 422
    assert client.post("/explain", json={}).status_code == 422

    # 非法 query：格式错误、主机位非零、IPv6
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        assert post_explain([], "deny", bad).status_code == 422, bad

    # 非法 default_action / action / 规则 CIDR（沿用现有校验）
    assert post_explain([], "permit", "10.0.0.0/8").status_code == 422
    assert post_explain(
        [{"action": "permit", "cidr": "10.0.0.0/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422
    assert post_explain(
        [{"action": "allow", "cidr": "10.0.0.1/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422


# ---------- /cidrs/hierarchy ----------

def post_hierarchy(entries):
    return client.post("/cidrs/hierarchy", json={"entries": entries})


def test_hierarchy_basic_tree():
    resp = post_hierarchy(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub", "cidr": "10.1.0.0/16"},
            {"id": "host", "cidr": "10.1.1.1"},
            {"id": "other", "cidr": "8.8.8.0/24"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 4
    assert body["root_count"] == 2

    # 根按网络地址稳定排序：8.8.8.0/24 在 10.0.0.0/8 之前
    other, net = body["roots"]
    assert other["id"] == "other"
    assert other["cidr"] == "8.8.8.0/24"
    assert other["parent_id"] is None
    assert other["children"] == []
    assert other["total_addresses"] == 256
    assert other["exclusive_address_count"] == 256
    assert other["exclusive_cidrs"] == ["8.8.8.0/24"]

    assert net["id"] == "net"
    assert net["cidr"] == "10.0.0.0/8"
    assert net["parent_id"] is None
    assert net["total_addresses"] == 1 << 24
    # /8 的直接子节点仅 10.1.0.0/16（host 是孙节点，不重复扣除）
    assert net["exclusive_address_count"] == (1 << 24) - (1 << 16)

    sub = net["children"][0]
    assert sub["id"] == "sub"
    assert sub["parent_id"] == "net"
    assert sub["total_addresses"] == 1 << 16
    # /16 扣除直接子节点 10.1.1.1/32
    assert sub["exclusive_address_count"] == (1 << 16) - 1
    assert sub["exclusive_cidrs"][0] == "10.1.0.0/24"

    host = sub["children"][0]
    assert host["id"] == "host"
    assert host["cidr"] == "10.1.1.1/32"  # 纯 IP 规范化为 /32
    assert host["parent_id"] == "sub"
    assert host["total_addresses"] == 1
    assert host["exclusive_address_count"] == 1
    assert host["exclusive_cidrs"] == ["10.1.1.1/32"]
    assert host["children"] == []


def test_hierarchy_longest_prefix_supernet_is_parent():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.1.0.0/16"},
            {"id": "c", "cidr": "10.1.2.0/24"},
        ]
    )
    assert resp.status_code == 200
    roots = resp.json()["roots"]
    assert [n["id"] for n in roots] == ["a"]
    b = roots[0]["children"][0]
    assert b["id"] == "b"
    # /24 的唯一 parent 是前缀最长的严格超网 /16，而非 /8
    assert [c["id"] for c in b["children"]] == ["c"]
    assert b["children"][0]["parent_id"] == "b"


def test_hierarchy_integer_ids_and_root_order():
    resp = post_hierarchy(
        [
            {"id": 2, "cidr": "192.168.0.0/16"},
            {"id": 1, "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 200
    assert [n["id"] for n in resp.json()["roots"]] == [1, 2]


def test_hierarchy_duplicate_network_422_lists_ids():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.0.0.0/08"},  # 规范化后与 a 相同
            {"id": "c", "cidr": "8.8.8.8/32"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == []
    assert detail["duplicate_networks"] == [
        {
            "cidr": "10.0.0.0/8",
            "entries": [
                {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
                {"index": 1, "id": "b", "cidr": "10.0.0.0/8"},
            ],
        }
    ]


def test_hierarchy_duplicate_id_422_lists_indexes():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "11.0.0.0/8"},
            {"id": 5, "cidr": "12.0.0.0/8"},
            {"id": 5, "cidr": "13.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 1]},
        {"id": 5, "indexes": [2, 3]},
    ]
    assert detail["duplicate_networks"] == []


def test_hierarchy_both_duplicates_reported_together():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail["duplicate_ids"]) == 1
    assert len(detail["duplicate_networks"]) == 1


def test_hierarchy_validation_422():
    # 空列表 / 缺少 entries
    assert post_hierarchy([]).status_code == 422
    assert client.post("/cidrs/hierarchy", json={}).status_code == 422

    # 超过 500 条
    too_many = [{"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(501)]
    assert post_hierarchy(too_many).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_hierarchy([{"id": "a", "cidr": bad}]).status_code == 422, bad

    # 非法 id：bool / float / 对象 / 空字符串 / 缺字段
    for bad_id in [True, 1.5, ["x"], {"k": 1}, "   "]:
        assert post_hierarchy(
            [{"id": bad_id, "cidr": "10.0.0.0/8"}]
        ).status_code == 422, bad_id
    assert post_hierarchy([{"cidr": "10.0.0.0/8"}]).status_code == 422
    assert post_hierarchy([{"id": "a"}]).status_code == 422


def test_hierarchy_max_500_entries_accepted():
    entries = [
        {"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    resp = post_hierarchy(entries)
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 500
    # 500 个互不相交的 /32：全部为 root，独占 1 个地址
    assert body["root_count"] == 500
    assert all(n["exclusive_address_count"] == 1 for n in body["roots"])
    # 按网络地址稳定排序（与输入顺序一致）
    assert [n["id"] for n in body["roots"]] == list(range(500))


def test_hierarchy_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert resp.json()["rules"][0]["status"] == "full"


# ---------- /cidrs/diff ----------

def post_diff(before, after):
    return client.post("/cidrs/diff", json={"before": before, "after": after})


def test_diff_basic_changes_order_and_replacement():
    resp = post_diff(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub-a", "cidr": "10.1.0.0/16"},
            {"id": "sub-b", "cidr": "10.2.0.0/16"},
            {"id": "old-dns", "cidr": "8.8.8.8/32"},
        ],
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub-a", "cidr": "10.1.0.0/24"},
            {"id": "sub-c", "cidr": "10.2.0.0/16"},
            {"id": "new-dns", "cidr": "8.8.8.8/32"},
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["before_count"] == 4
    assert body["after_count"] == 4

    # 保持 before 顺序，新增项按 after 顺序追加
    assert [(c["id"], c["change"]) for c in body["changes"]] == [
        ("net", "unchanged"),
        ("sub-a", "cidr_changed"),
        ("sub-b", "removed"),
        ("old-dns", "removed"),
        ("sub-c", "added"),
        ("new-dns", "added"),
    ]

    by_id = {c["id"]: c for c in body["changes"]}
    assert by_id["sub-a"]["before_parent_id"] == "net"
    assert by_id["sub-a"]["after_parent_id"] == "net"
    assert by_id["sub-a"]["parent_changed"] is False
    assert by_id["sub-a"]["affected_address_count"] == 65536 - 256  # 对称差
    assert by_id["sub-b"]["parent_changed"] is None
    assert by_id["sub-b"]["affected_address_count"] == 65536
    assert by_id["sub-c"]["before_parent_id"] is None
    assert by_id["sub-c"]["after_parent_id"] == "net"
    assert by_id["sub-c"]["parent_changed"] is None
    assert by_id["sub-c"]["affected_address_count"] == 65536
    assert by_id["new-dns"]["affected_address_count"] == 1

    # 规范化后网段相同但 id 不同 -> 替换候选（按 before 位置排序）
    assert body["replacement_candidates"] == [
        {"before_id": "sub-b", "after_id": "sub-c", "cidr": "10.2.0.0/16", "address_count": 65536},
        {"before_id": "old-dns", "after_id": "new-dns", "cidr": "8.8.8.8/32", "address_count": 1},
    ]
    assert body["summary"] == {
        "added": 2,
        "removed": 2,
        "cidr_changed": 1,
        "unchanged": 1,
        "parent_changed": 0,
        "replacement_candidate_count": 2,
        "affected_address_count": 65280 + 2 * 65536 + 2,
    }


def test_diff_parent_only_change_flagged():
    # 删除中间层 /16，host 网段不变但直接父节点从 sub 变为 net
    resp = post_diff(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub", "cidr": "10.1.0.0/16"},
            {"id": "host", "cidr": "10.1.0.1/32"},
        ],
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "host", "cidr": "10.1.0.1/32"},
        ],
    )
    assert resp.status_code == 200
    by_id = {c["id"]: c for c in resp.json()["changes"]}
    host = by_id["host"]
    assert host["change"] == "unchanged"
    assert host["parent_changed"] is True
    assert host["before_parent_id"] == "sub"
    assert host["after_parent_id"] == "net"
    assert host["affected_address_count"] == 0
    summary = resp.json()["summary"]
    assert summary["parent_changed"] == 1
    assert summary["affected_address_count"] == 65536  # 仅 sub 删除


def test_diff_normalized_same_network_different_writing_is_unchanged():
    resp = post_diff(
        [{"id": "a", "cidr": "10.0.0.0/8"}],
        [{"id": "a", "cidr": "10.0.0.0/08"}],
    )
    assert resp.status_code == 200
    change = resp.json()["changes"][0]
    assert change["change"] == "unchanged"
    assert change["before_cidr"] == change["after_cidr"] == "10.0.0.0/8"
    assert change["affected_address_count"] == 0
    assert resp.json()["replacement_candidates"] == []


def test_diff_empty_sides_accepted():
    assert post_diff([], []).json() == {
        "before_count": 0,
        "after_count": 0,
        "changes": [],
        "replacement_candidates": [],
        "summary": {
            "added": 0,
            "removed": 0,
            "cidr_changed": 0,
            "unchanged": 0,
            "parent_changed": 0,
            "replacement_candidate_count": 0,
            "affected_address_count": 0,
        },
    }
    # 仅 after：全部 added，顺序即 after 顺序
    resp = post_diff([], [{"id": "a", "cidr": "10.0.0.0/8"}, {"id": "b", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    body = resp.json()
    assert [c["id"] for c in body["changes"]] == ["a", "b"]
    assert body["changes"][1]["after_cidr"] == "8.8.8.8/32"  # 纯 IP 规范化
    assert body["summary"]["added"] == 2


def test_diff_integer_ids_preserved():
    resp = post_diff(
        [{"id": 1, "cidr": "10.0.0.0/8"}, {"id": 2, "cidr": "11.0.0.0/8"}],
        [{"id": 1, "cidr": "11.0.0.0/8"}, {"id": 3, "cidr": "8.8.8.8"}],
    )
    assert resp.status_code == 200
    by_id = {c["id"]: c for c in resp.json()["changes"]}
    assert by_id[1]["change"] == "cidr_changed"
    assert by_id[1]["affected_address_count"] == 2 * (1 << 24)  # 不相交的两个 /8
    assert by_id[2]["change"] == "removed"
    assert by_id[3]["change"] == "added"


def test_diff_duplicate_id_after_side_422_no_partial_result():
    resp = post_diff(
        [{"id": "a", "cidr": "10.0.0.0/8"}],
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "y", "cidr": "8.8.8.8/32"},
            {"id": "x", "cidr": "11.0.0.0/8"},
        ],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["before"] == {"duplicate_ids": [], "duplicate_networks": []}
    assert detail["after"]["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 2]}
    ]
    assert detail["after"]["duplicate_networks"] == []


def test_diff_duplicate_network_before_side_422():
    resp = post_diff(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.0.0.0/08"},
        ],
        [{"id": "a", "cidr": "10.0.0.0/8"}],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["after"] == {"duplicate_ids": [], "duplicate_networks": []}
    assert detail["before"]["duplicate_ids"] == []
    assert len(detail["before"]["duplicate_networks"]) == 1
    assert detail["before"]["duplicate_networks"][0]["cidr"] == "10.0.0.0/8"


def test_diff_both_sides_duplicates_reported_together():
    resp = post_diff(
        [{"id": "x", "cidr": "10.0.0.0/8"}, {"id": "x", "cidr": "11.0.0.0/8"}],
        [{"id": "y", "cidr": "10.0.0.0/8"}, {"id": "z", "cidr": "10.0.0.0/08"}],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail["before"]["duplicate_ids"]) == 1
    assert len(detail["after"]["duplicate_networks"]) == 1


def test_diff_validation_422():
    # 缺少 before / after、空请求体
    assert client.post("/cidrs/diff", json={}).status_code == 422
    assert client.post(
        "/cidrs/diff", json={"before": []}
    ).status_code == 422
    assert client.post(
        "/cidrs/diff", json={"after": []}
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_diff(
            [{"id": "a", "cidr": bad}], []
        ).status_code == 422, bad
        assert post_diff(
            [], [{"id": "a", "cidr": bad}]
        ).status_code == 422, bad

    # 非法 id：bool / float / 对象 / 空字符串 / 缺字段
    for bad_id in [True, 1.5, ["x"], {"k": 1}, "   "]:
        assert post_diff(
            [{"id": bad_id, "cidr": "10.0.0.0/8"}], []
        ).status_code == 422, bad_id
    assert post_diff([{"cidr": "10.0.0.0/8"}], []).status_code == 422
    assert post_diff([{"id": "a"}], []).status_code == 422

    # 单侧超过 500 条
    too_many = [{"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(501)]
    assert post_diff(too_many, []).status_code == 422
    assert post_diff([], too_many).status_code == 422

    # 字段类型错误
    assert client.post(
        "/cidrs/diff", json={"before": "x", "after": []}
    ).status_code == 422


def test_diff_max_500_entries_each_side_accepted():
    before = [
        {"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    after = [
        {"id": 500 + i, "cidr": f"2.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    resp = post_diff(before, after)
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["removed"] == 500
    assert body["summary"]["added"] == 500
    assert body["summary"]["affected_address_count"] == 1000  # 全是 /32
    # before 顺序在前，after 顺序追加
    assert [c["id"] for c in body["changes"]] == list(range(1000))


def test_diff_openapi_examples_present():
    schema = client.get("/openapi.json").json()
    op = schema["paths"]["/cidrs/diff"]["post"]
    assert "CIDR 变更" in op["summary"] or "cidr" in op["summary"].lower()
    # 请求示例
    examples = op["requestBody"]["content"]["application/json"]["examples"]
    assert "before" in list(examples.values())[0]["value"]
    # 200 响应示例与 422 错误示例
    responses = op["responses"]
    assert "200" in responses and "422" in responses
    ok_example = responses["200"]["content"]["application/json"]["examples"]["diff"]
    assert ok_example["value"]["replacement_candidates"]
    err_example = responses["422"]["content"]["application/json"]["examples"]["duplicates"]
    assert err_example["value"]["detail"]["error"] == "duplicate_entries"


def test_diff_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert post_hierarchy(
        [{"id": "a", "cidr": "10.0.0.0/8"}]
    ).status_code == 200


# ---------- /routes/resolve ----------

def post_resolve(routes, targets):
    return client.post(
        "/routes/resolve", json={"routes": routes, "targets": targets}
    )


def test_resolve_lpm_lowest_metric_and_ecmp_dedup():
    resp = post_resolve(
        [
            {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.254", "metric": 50},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},  # 重复
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 60},
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.2", "metric": 60},
        ],
        ["10.1.0.5", "10.2.2.2", "8.8.8.8", "172.16.0.1"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 7
    assert body["target_count"] == 4

    results = body["results"]
    # targets 输入顺序保持不变
    assert [r["target"] for r in results] == [
        "10.1.0.5",
        "10.2.2.2",
        "8.8.8.8",
        "172.16.0.1",
    ]
    assert results[0] == {
        "target": "10.1.0.5",
        "status": "reachable",
        "matched_cidr": "10.1.0.0/16",
        "metric": 60,
        "next_hops": ["10.1.0.1", "10.1.0.2"],
    }
    assert results[1] == {
        "target": "10.2.2.2",
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 20,
        "next_hops": ["10.0.0.1", "10.0.0.2"],  # 去重且按 routes 顺序
    }
    for outside in results[2:]:
        assert outside["status"] == "reachable"
        assert outside["matched_cidr"] == "0.0.0.0/0"
        assert outside["metric"] == 100
        assert outside["next_hops"] == ["192.0.2.254"]

    # ECMP 各下一跳分别计数；顺序按 next_hop 在 routes 中首次出现位置
    assert body["summary"] == {
        "reachable_count": 4,
        "unreachable_count": 0,
        "next_hop_counts": [
            {"next_hop": "192.0.2.254", "target_count": 2},
            {"next_hop": "10.0.0.1", "target_count": 1},
            {"next_hop": "10.0.0.2", "target_count": 1},
            {"next_hop": "10.1.0.1", "target_count": 1},
            {"next_hop": "10.1.0.2", "target_count": 1},
        ],
    }


def test_resolve_unreachable_targets():
    resp = post_resolve(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 0},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 0},
        ],
        ["8.8.8.8", "10.0.0.1", "9.9.9.9"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert [r["status"] for r in body["results"]] == [
        "unreachable",
        "reachable",
        "unreachable",
    ]
    assert body["results"][0] == {
        "target": "8.8.8.8",
        "status": "unreachable",
        "matched_cidr": None,
        "metric": None,
        "next_hops": [],
    }
    # 仅 10.0.0.1 这一目标命中，ECMP 两个下一跳各计一次
    assert body["summary"] == {
        "reachable_count": 1,
        "unreachable_count": 2,
        "next_hop_counts": [
            {"next_hop": "10.0.0.1", "target_count": 1},
            {"next_hop": "10.0.0.2", "target_count": 1},
        ],
    }


def test_resolve_empty_routes_all_unreachable():
    resp = post_resolve([], ["8.8.8.8"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 0
    assert body["results"][0]["status"] == "unreachable"
    assert body["summary"] == {
        "reachable_count": 0,
        "unreachable_count": 1,
        "next_hop_counts": [],
    }


def test_resolve_bare_ip_accepted_for_target_and_route():
    resp = post_resolve(
        [{"cidr": "8.8.8.8", "next_hop": "1.1.1.1", "metric": 5}],
        ["8.8.8.8"],
    )
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["matched_cidr"] == "8.8.8.8/32"
    assert item["metric"] == 5
    assert item["next_hops"] == ["1.1.1.1"]


def test_resolve_metric_boundaries():
    for metric in (0, 65535):
        resp = post_resolve(
            [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": metric}],
            ["8.8.8.8"],
        )
        assert resp.status_code == 200, metric
        assert resp.json()["results"][0]["metric"] == metric


def test_resolve_duplicate_targets_422_lists_indexes():
    resp = post_resolve(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9", "8.8.8.8"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_targets",
        "duplicates": [{"target": "8.8.8.8", "indexes": [0, 2]}],
    }


def test_resolve_validation_422():
    valid_route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10}

    # 缺少字段 / 请求体为空
    assert client.post("/routes/resolve", json={}).status_code == 422
    assert client.post(
        "/routes/resolve", json={"routes": []}
    ).status_code == 422
    assert client.post(
        "/routes/resolve", json={"targets": ["8.8.8.8"]}
    ).status_code == 422

    # 空目标 / 超过 500 个目标
    assert post_resolve([valid_route], []).status_code == 422
    too_many_targets = [f"8.8.{i // 256}.{i % 256}" for i in range(501)]
    assert post_resolve([valid_route], too_many_targets).status_code == 422

    # 超过 1000 条路由
    too_many_routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1001)
    ]
    assert post_resolve(too_many_routes, ["8.8.8.8"]).status_code == 422

    # 非法 route cidr（主机位非零 / 前缀越界 / IPv6）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        route = {"cidr": bad, "next_hop": "10.0.0.1", "metric": 10}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad

    # 非法 next_hop（CIDR 写法 / IPv6 / 越界）
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1", ""]:
        route = {"cidr": "10.0.0.0/8", "next_hop": bad, "metric": 10}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad

    # 非法 target（CIDR 写法 / IPv6 / 前导零 / 非字符串）
    for bad in ["8.8.8.8/32", "2001:db8::1", "010.0.0.1", 8, True, None]:
        assert post_resolve([valid_route], [bad]).status_code == 422, bad

    # 非法 metric：越界 / bool / float / 字符串
    for bad_metric in [-1, 65536, True, 1.5, "10"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": bad_metric}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad_metric

    # routes / targets 类型错误
    assert client.post(
        "/routes/resolve", json={"routes": "x", "targets": ["8.8.8.8"]}
    ).status_code == 422
    assert post_resolve(valid_route, ["8.8.8.8"]).status_code == 422


def test_resolve_limits_accepted():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1000)
    ]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(500)]
    resp = post_resolve(routes, targets)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert body["target_count"] == 500
    assert len(body["results"]) == 500
    assert body["summary"]["reachable_count"] == 500
    assert body["summary"]["unreachable_count"] == 0
    # 重复下一跳去重为一项，命中全部目标
    assert body["summary"]["next_hop_counts"] == [
        {"next_hop": "1.1.1.1", "target_count": 500}
    ]


def test_resolve_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert post_hierarchy(
        [{"id": "a", "cidr": "10.0.0.0/8"}]
    ).status_code == 200


# ---------- /routes/failover ----------

def post_failover(routes, targets, failed_next_hops):
    return client.post(
        "/routes/failover",
        json={
            "routes": routes,
            "targets": targets,
            "failed_next_hops": failed_next_hops,
        },
    )


def test_failover_all_four_impacts():
    resp = post_failover(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 10},
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 5},
            {"cidr": "11.0.0.0/8", "next_hop": "11.0.0.1", "metric": 7},
            {"cidr": "12.0.0.0/8", "next_hop": "12.0.0.1", "metric": 3},
        ],
        ["10.0.9.9", "10.1.0.9", "11.0.0.9", "12.0.0.9"],
        ["10.0.0.2", "10.1.0.1", "11.0.0.1"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 5
    assert body["target_count"] == 4
    assert body["failed_next_hops"] == ["10.0.0.2", "10.1.0.1", "11.0.0.1"]

    results = body["results"]
    # 严格保持 targets 输入顺序
    assert [r["target"] for r in results] == [
        "10.0.9.9",
        "10.1.0.9",
        "11.0.0.9",
        "12.0.0.9",
    ]
    assert [r["impact"] for r in results] == [
        "ecmp_reduced",
        "rerouted",
        "unreachable",
        "unchanged",
    ]

    # ecmp_reduced：命中网段与 metric 不变，等价下一跳减少
    assert results[0]["before"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1", "10.0.0.2"],
    }
    assert results[0]["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"],
    }
    # rerouted：/16 失效后回退到更短前缀 /8
    assert results[1]["before"]["matched_cidr"] == "10.1.0.0/16"
    assert results[1]["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"],
    }
    # unreachable：唯一路由失效
    assert results[2]["after"] == {
        "status": "unreachable",
        "matched_cidr": None,
        "metric": None,
        "next_hops": [],
    }
    # unchanged：before/after 完全一致
    assert results[3]["before"] == results[3]["after"]

    assert body["summary"] == {
        "unchanged": 1,
        "ecmp_reduced": 1,
        "rerouted": 1,
        "unreachable": 1,
    }


def test_failover_fallback_to_higher_metric_not_ecmp_shrink():
    # 同网段最低 metric 路由全部失效：回退到更高 metric，而不是把 ECMP 删空
    resp = post_failover(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 50},
        ],
        ["10.0.0.9"],
        ["10.0.0.1"],
    )
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["impact"] == "rerouted"
    assert item["before"]["metric"] == 10
    assert item["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 50,
        "next_hops": ["10.0.0.2"],
    }


def test_failover_empty_failed_next_hops_all_unchanged():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9"],
        [],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["failed_next_hops"] == []
    assert [r["impact"] for r in body["results"]] == ["unchanged", "unchanged"]
    assert body["summary"] == {
        "unchanged": 2,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_failed_next_hops_normalized():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
        [" 1.1.1.1 "],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["failed_next_hops"] == ["1.1.1.1"]
    assert body["results"][0]["impact"] == "unreachable"


def test_failover_duplicate_failed_next_hops_422_lists_indexes():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
        ["1.1.1.1", "2.2.2.2", "1.1.1.1"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_next_hops",
        "duplicates": [{"next_hop": "1.1.1.1", "indexes": [0, 2]}],
    }


def test_failover_duplicate_targets_422():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9", "8.8.8.8"],
        ["1.1.1.1"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_targets",
        "duplicates": [{"target": "8.8.8.8", "indexes": [0, 2]}],
    }


def test_failover_validation_422():
    valid_route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10}

    # 缺少字段 / 请求体为空
    assert client.post("/routes/failover", json={}).status_code == 422
    assert client.post(
        "/routes/failover", json={"routes": [], "targets": ["8.8.8.8"]}
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"routes": [], "failed_next_hops": ["1.1.1.1"]},
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"targets": ["8.8.8.8"], "failed_next_hops": []},
    ).status_code == 422

    # 非法 failed_next_hops：CIDR 写法 / IPv6 / 越界 / 前导零 / 空串 / 非字符串
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1", "010.0.0.1", "", 8, True, None]:
        resp = post_failover([valid_route], ["10.0.0.9"], [bad])
        assert resp.status_code == 422, bad

    # 非法 route cidr / next_hop / metric / target：沿用 /routes/resolve 校验
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        route = {"cidr": bad, "next_hop": "10.0.0.1", "metric": 10}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": bad, "metric": 10}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad
    for bad_metric in [-1, 65536, True, 1.5, "10"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": bad_metric}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad_metric
    for bad in ["8.8.8.8/32", "2001:db8::1", "010.0.0.1", 8, True, None]:
        assert post_failover([valid_route], [bad], []).status_code == 422, bad

    # 数量限制：路由 > 1000、目标 > 500、目标为空、失败下一跳 > 1000
    too_many_routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1001)
    ]
    assert post_failover(too_many_routes, ["8.8.8.8"], []).status_code == 422
    too_many_targets = [f"8.8.{i // 256}.{i % 256}" for i in range(501)]
    assert post_failover([valid_route], too_many_targets, []).status_code == 422
    assert post_failover([valid_route], [], []).status_code == 422
    too_many_failed = [f"192.0.{i // 256}.{i % 256}" for i in range(1001)]
    assert post_failover([valid_route], ["10.0.0.9"], too_many_failed).status_code == 422

    # 字段类型错误
    assert client.post(
        "/routes/failover",
        json={"routes": "x", "targets": ["8.8.8.8"], "failed_next_hops": []},
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"routes": [], "targets": ["8.8.8.8"], "failed_next_hops": "x"},
    ).status_code == 422


def test_failover_limits_accepted():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1000)
    ]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(500)]
    failed = [f"192.0.{i // 256}.{i % 256}" for i in range(1000)]
    resp = post_failover(routes, targets, failed)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert body["target_count"] == 500
    assert len(body["failed_next_hops"]) == 1000
    # 失败下一跳均不在路由表中：全部 unchanged
    assert body["summary"] == {
        "unchanged": 500,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    resp = post_resolve(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["next_hops"] == ["1.1.1.1"]
    assert post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}]).status_code == 200


# ---------- /routes/audit ----------

def post_audit(routes):
    return client.post("/routes/audit", json={"routes": routes})


AUDIT_ROUTES = [
    {"cidr": "10.0.0.0/24", "next_hop": "10.0.0.1", "metric": 100},
    {"cidr": "10.0.0.0/24", "next_hop": "10.0.0.2", "metric": 10},
    {"cidr": "10.0.0.0/24", "next_hop": "10.0.0.3", "metric": 10},
    {"cidr": "10.0.0.128/25", "next_hop": "10.0.0.254", "metric": 50},
    {"cidr": "10.0.1.0/24", "next_hop": "10.0.1.1", "metric": 20},
    {"cidr": "10.0.1.0/24", "next_hop": "10.0.1.2", "metric": 20},
    {"cidr": "10.0.1.0/24", "next_hop": "10.0.1.9", "metric": 99},
    {"cidr": "10.0.2.0/25", "next_hop": "10.0.2.1", "metric": 5},
    {"cidr": "10.0.2.128/25", "next_hop": "10.0.2.2", "metric": 5},
]


def test_audit_statuses_ecmp_sharing_and_order():
    resp = post_audit(AUDIT_ROUTES)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 9

    results = body["results"]
    # 严格保持输入顺序
    assert [r["index"] for r in results] == list(range(9))
    assert [r["status"] for r in results] == [
        "shadowed",   # 同网段 metric 100 被最低 metric 10 淘汰
        "partial",    # /24 被 /25 遮蔽下半段
        "partial",    # ECMP 并行路由共享同一集合
        "active",     # /25 子网段
        "active",     # /24 全生效（ECMP 成员 1）
        "active",     # ECMP 成员 2，与成员 1 集合完全相同
        "shadowed",   # metric 99 被 metric 20 淘汰
        "active",
        "active",
    ]

    # 高 metric 遮蔽路由：生效集合为空，但 ecmp_next_hops 指向最低 metric 组
    assert results[0] == {
        "index": 0,
        "cidr": "10.0.0.0/24",
        "next_hop": "10.0.0.1",
        "metric": 100,
        "status": "shadowed",
        "status_label": "完全遮蔽",
        "total_addresses": 256,
        "effective_addresses": 0,
        "effective_cidrs": [],
        "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"],
    }

    # 同 metric 并行路由：共享集合 + 输入顺序
    assert results[1] == {
        "index": 1,
        "cidr": "10.0.0.0/24",
        "next_hop": "10.0.0.2",
        "metric": 10,
        "status": "partial",
        "status_label": "部分生效",
        "total_addresses": 256,
        "effective_addresses": 128,
        "effective_cidrs": ["10.0.0.0/25"],
        "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"],
    }
    assert results[2]["effective_addresses"] == 128
    assert results[2]["effective_cidrs"] == ["10.0.0.0/25"]
    assert results[2]["ecmp_next_hops"] == ["10.0.0.2", "10.0.0.3"]
    # 共享：两个并行路由的生效字段完全一致
    for key in (
        "effective_addresses",
        "effective_cidrs",
        "ecmp_next_hops",
    ):
        assert results[1][key] == results[2][key]

    # 子网段 active
    assert results[3] == {
        "index": 3,
        "cidr": "10.0.0.128/25",
        "next_hop": "10.0.0.254",
        "metric": 50,
        "status": "active",
        "status_label": "全部生效",
        "total_addresses": 128,
        "effective_addresses": 128,
        "effective_cidrs": ["10.0.0.128/25"],
        "ecmp_next_hops": ["10.0.0.254"],
    }

    # 10.0.1.0/24 的 ECMP 成员共享整段，高 metric 成员遮蔽
    assert results[4]["status"] == results[5]["status"] == "active"
    assert results[4]["effective_cidrs"] == results[5]["effective_cidrs"] == [
        "10.0.1.0/24"
    ]
    assert results[4]["ecmp_next_hops"] == results[5]["ecmp_next_hops"] == [
        "10.0.1.1",
        "10.0.1.2",
    ]
    assert results[6]["status"] == "shadowed"
    assert results[6]["effective_cidrs"] == []
    assert results[6]["ecmp_next_hops"] == ["10.0.1.1", "10.0.1.2"]

    assert results[7]["effective_cidrs"] == ["10.0.2.0/25"]
    assert results[8]["effective_cidrs"] == ["10.0.2.128/25"]


def test_audit_summary_counts_and_space_invariants():
    body = post_audit(AUDIT_ROUTES).json()
    # 三个不相交网段：/24(256) + /24(256) + /25+/25(256) = 768
    assert body["summary"] == {
        "active": 5,
        "partial": 2,
        "shadowed": 2,
        "routed_address_count": 768,
        "unreachable_address_count": (1 << 32) - 768,
        # partial 两条 ×128 + active：128 + 2×256 + 128 + 128 = 1152
        "effective_address_sum": 1152,
    }


def test_audit_empty_routes_all_space_unreachable():
    resp = post_audit([])
    assert resp.status_code == 200
    assert resp.json() == {
        "route_count": 0,
        "results": [],
        "summary": {
            "active": 0,
            "partial": 0,
            "shadowed": 0,
            "routed_address_count": 0,
            "unreachable_address_count": 1 << 32,
            "effective_address_sum": 0,
        },
    }


def test_audit_default_route_covers_full_space():
    resp = post_audit(
        [
            {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    default, ten = body["results"]
    assert default["status"] == "partial"
    assert default["effective_addresses"] == (1 << 32) - (1 << 24)
    assert ten["status"] == "active"
    summary = body["summary"]
    assert summary["routed_address_count"] == 1 << 32
    assert summary["unreachable_address_count"] == 0
    assert summary["effective_address_sum"] == (1 << 32)


def test_audit_bare_ip_normalized_to_slash32():
    resp = post_audit([{"cidr": "8.8.8.8", "next_hop": "1.1.1.1", "metric": 5}])
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["cidr"] == "8.8.8.8/32"
    assert item["status"] == "active"
    assert item["total_addresses"] == item["effective_addresses"] == 1
    assert item["effective_cidrs"] == ["8.8.8.8/32"]


def test_audit_lpm_beats_worse_metric():
    # /8 metric 1 vs /16 metric 65535：/16 仍 active，/8 partial
    resp = post_audit(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 1},
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 65535},
        ]
    )
    assert resp.status_code == 200
    parent, child = resp.json()["results"]
    assert parent["status"] == "partial"
    assert parent["effective_addresses"] == (1 << 24) - (1 << 16)
    assert child["status"] == "active"
    assert child["effective_addresses"] == 1 << 16


def test_audit_validation_422():
    # 缺少 routes / 请求体为空
    assert client.post("/routes/audit", json={}).status_code == 422

    # 超过 1000 条路由
    too_many = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1001)
    ]
    assert post_audit(too_many).status_code == 422

    # 非法 route cidr（主机位 / 前缀越界 / IPv6）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        route = {"cidr": bad, "next_hop": "10.0.0.1", "metric": 10}
        assert post_audit([route]).status_code == 422, bad

    # 非法 next_hop（CIDR 写法 / IPv6 / 前导零 / 越界 / 空）
    for bad in ["10.0.0.1/32", "::1", "010.0.0.1", "999.0.0.1", ""]:
        route = {"cidr": "10.0.0.0/8", "next_hop": bad, "metric": 10}
        assert post_audit([route]).status_code == 422, bad

    # 非法 metric：越界 / bool / float / 字符串
    for bad_metric in [-1, 65536, True, 1.5, "10"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": bad_metric}
        assert post_audit([route]).status_code == 422, bad_metric

    # routes 类型错误
    assert client.post(
        "/routes/audit", json={"routes": "x"}
    ).status_code == 422
    # 路由条目缺字段
    assert post_audit([{"cidr": "10.0.0.0/8", "metric": 1}]).status_code == 422
    assert post_audit([{"next_hop": "10.0.0.1", "metric": 1}]).status_code == 422


def test_audit_limits_accepted():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1000)
    ]
    resp = post_audit(routes)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert len(body["results"]) == 1000
    assert body["summary"]["active"] == 1000
    assert body["summary"]["routed_address_count"] == 1 << 32
    assert body["summary"]["unreachable_address_count"] == 0
    assert body["summary"]["effective_address_sum"] == 1000 * (1 << 32)


def test_audit_openapi_documented():
    spec = client.get("/openapi.json").json()
    assert "/routes/audit" in spec["paths"]
    operation = spec["paths"]["/routes/audit"]["post"]
    assert operation["summary"]
    # 请求 / 响应模型已注册
    assert "RouteAuditRequest" in spec["components"]["schemas"]
    assert "RouteAuditResponse" in spec["components"]["schemas"]
    assert "RouteAuditResult" in spec["components"]["schemas"]
    assert "RouteAuditSummary" in spec["components"]["schemas"]
    # 标签归入 routes
    assert operation["tags"] == ["routes"]
    # 内置 OpenAPI 示例
    assert "audit" in operation["requestBody"]["content"]["application/json"]["examples"]
    assert (
        "audit"
        in operation["responses"]["200"]["content"]["application/json"]["examples"]
    )


def test_audit_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    resp = post_resolve(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
    )
    assert resp.status_code == 200
    assert post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}]).status_code == 200


# ---------- /firewall/simulate ----------


def post_firewall(rules, events, default_action="deny", session_timeout=30,
                  max_sessions=10000):
    return client.post(
        "/firewall/simulate",
        json={
            "rules": rules,
            "events": events,
            "default_action": default_action,
            "session_timeout": session_timeout,
            "max_sessions": max_sessions,
        },
    )


FW_ALLOW_WEB = {
    "action": "allow",
    "src_cidr": "10.0.0.0/24",
    "dst_cidr": "10.0.1.0/24",
    "protocol": "tcp",
    "port_start": 80,
    "port_end": 80,
}
FW_DENY_OTHERS = {
    "action": "deny",
    "src_cidr": "0.0.0.0/0",
    "dst_cidr": "0.0.0.0/0",
    "protocol": "tcp",
    "port_start": 0,
    "port_end": 65535,
}


def fw_event(timestamp, src, sport, dst, dport, proto="tcp", direction="forward"):
    return {
        "timestamp": timestamp,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport,
        "direction": direction,
    }


def test_firewall_stateful_lifecycle_and_summary():
    events = [
        fw_event(0, "10.0.0.10", 40000, "10.0.1.20", 80),
        fw_event(5, "10.0.1.20", 80, "10.0.0.10", 40000, direction="reverse"),
        fw_event(30, "10.0.1.20", 80, "10.0.0.10", 40000, direction="reverse"),
        fw_event(31, "10.0.1.20", 80, "10.0.0.10", 40000, direction="reverse"),
        fw_event(50, "10.0.0.10", 40000, "10.0.1.20", 80),
    ]
    resp = post_firewall([FW_ALLOW_WEB, FW_DENY_OTHERS], events)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["rule_count"] == 2
    assert body["event_count"] == 5
    assert body["default_action"] == "deny"
    assert body["session_timeout"] == 30
    assert body["max_sessions"] == 10000

    results = body["results"]
    assert [r["index"] for r in results] == [0, 1, 2, 3, 4]
    assert [r["session_state"] for r in results] == [
        "new",                 # 正向 allow 建会话
        "active",              # 反向 stateful
        "active",              # 边界时刻 expires_at==30 仍存活
        "expired",             # 31 > 30，过期后重新走规则命中 deny
        "expired_reestablished",  # 过期后正向 allow 重建
    ]
    assert [r["action"] for r in results] == [
        "allow", "allow", "allow", "deny", "allow"
    ]
    assert [r["match"]["type"] for r in results] == [
        "rule", "stateful", "stateful", "rule", "rule"
    ]
    assert results[0]["match"]["rule_index"] == 0
    assert results[1]["match"]["rule_index"] is None
    assert results[3]["match"]["rule_index"] == 1  # deny 兜底规则

    # stateful 放行携带正向会话键（src/dst 与反向包相反）
    session = results[1]["session"]
    assert session["key"] == {
        "protocol": "tcp",
        "src_ip": "10.0.0.10",
        "dst_ip": "10.0.1.20",
        "src_port": 40000,
        "dst_port": 80,
    }
    assert session["created_at"] == 0
    assert session["last_seen"] == 5  # 反向 stateful 命中刷新 last_seen
    assert session["expires_at"] == 30
    assert session["rule_index"] == 0
    assert session["established_by_event"] == 0
    assert results[2]["session"]["last_seen"] == 30

    assert results[3]["session"]["expires_at"] == 30  # expired 带原会话
    assert results[4]["session"]["created_at"] == 50
    assert results[4]["session"]["last_seen"] == 50
    assert results[4]["session"]["expires_at"] == 80

    # 容量充足时所有事件均无淘汰
    assert all(r["evicted_session"] is None for r in results)

    assert body["summary"] == {
        "allowed": 4,
        "denied": 1,
        "new_sessions": 2,
        "expired_sessions": 1,
        "evicted_sessions": 0,
        "active_sessions": 1,
    }


def test_firewall_denied_forward_no_session_and_reverse_denied():
    events = [
        fw_event(0, "8.8.8.8", 1000, "10.0.1.20", 22),
        fw_event(1, "10.0.1.20", 22, "8.8.8.8", 1000, direction="reverse"),
    ]
    resp = post_firewall([FW_ALLOW_WEB, FW_DENY_OTHERS], events)
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert [r["action"] for r in results] == ["deny", "deny"]
    assert [r["match"]["type"] for r in results] == ["rule", "rule"]
    assert [r["session_state"] for r in results] == ["none", "none"]
    assert all(r["session"] is None for r in results)
    assert all(r["evicted_session"] is None for r in results)
    assert resp.json()["summary"] == {
        "allowed": 0,
        "denied": 2,
        "new_sessions": 0,
        "expired_sessions": 0,
        "evicted_sessions": 0,
        "active_sessions": 0,
    }


def test_firewall_default_action_used_and_case_insensitive():
    events = [fw_event(0, "8.8.8.8", 1000, "9.9.9.9", 443)]
    resp = post_firewall([], events, default_action="ALLOW")
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["match"] == {"type": "default", "rule_index": None}
    assert item["action"] == "allow"
    assert item["session_state"] == "new"


def test_firewall_first_matching_rule_wins_and_port_range():
    rules = [
        {"action": "deny", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 0, "port_end": 65535},
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 80, "port_end": 80},
    ]
    events = [
        fw_event(0, "1.1.1.1", 1000, "2.2.2.2", 80),
    ]
    resp = post_firewall(rules, events)
    item = resp.json()["results"][0]
    assert item["match"]["rule_index"] == 0  # 首条 deny 先生效
    assert item["action"] == "deny"


def test_firewall_icmp_no_ports():
    rules = [
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "icmp", "port_start": None, "port_end": None},
    ]
    events = [
        fw_event(0, "1.1.1.1", None, "2.2.2.2", None, proto="icmp"),
        fw_event(1, "2.2.2.2", None, "1.1.1.1", None, proto="icmp", direction="reverse"),
    ]
    resp = post_firewall(rules, events)
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [r["session_state"] for r in results] == ["new", "active"]
    key = results[0]["session"]["key"]
    assert key["protocol"] == "icmp"
    assert key["src_port"] is None and key["dst_port"] is None
    assert results[0]["src_port"] is None and results[0]["dst_port"] is None


def test_firewall_out_of_order_timestamps_422():
    events = [
        fw_event(10, "1.1.1.1", 1000, "2.2.2.2", 80),
        fw_event(5, "1.1.1.1", 1000, "2.2.2.2", 80),
        fw_event(8, "1.1.1.1", 1000, "2.2.2.2", 80),
    ]
    resp = post_firewall([FW_ALLOW_WEB], events)
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "out_of_order_timestamps",
        "violations": [
            {"index": 1, "timestamp": 5, "previous_timestamp": 10},
        ],
    }


def test_firewall_overlapping_reverse_session_422():
    events = [
        fw_event(0, "1.1.1.1", 1000, "2.2.2.2", 80),
        fw_event(2, "2.2.2.2", 80, "1.1.1.1", 1000),
    ]
    rules = [
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 0, "port_end": 65535},
    ]
    resp = post_firewall(rules, events)
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "overlapping_session",
        "index": 1,
        "conflict": "reverse_key_collision",
        "existing_index": 0,
        "session_key": {
            "protocol": "tcp",
            "src_ip": "2.2.2.2",
            "src_port": 80,
            "dst_ip": "1.1.1.1",
            "dst_port": 1000,
        },
    }


def test_firewall_reverse_after_expiry_may_start_new_forward_session():
    # 过期后不存在重叠：反向流作为新的 forward 发起方可建立新会话
    rules = [
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 0, "port_end": 65535},
    ]
    events = [
        fw_event(0, "1.1.1.1", 1000, "2.2.2.2", 80),
        fw_event(40, "2.2.2.2", 80, "1.1.1.1", 1000),
    ]
    resp = post_firewall(rules, events, session_timeout=30)
    assert resp.status_code == 200
    assert [r["session_state"] for r in resp.json()["results"]] == ["new", "new"]


def test_firewall_validation_422():
    valid_event = fw_event(0, "1.1.1.1", 1000, "2.2.2.2", 80)
    valid_rule = FW_ALLOW_WEB

    # 缺少字段 / 空请求体
    assert client.post("/firewall/simulate", json={}).status_code == 422
    assert client.post(
        "/firewall/simulate",
        json={"rules": [], "events": [valid_event], "default_action": "deny"},
    ).status_code == 422  # 缺 session_timeout / max_sessions
    assert client.post(
        "/firewall/simulate",
        json={"rules": [], "events": [valid_event], "session_timeout": 30},
    ).status_code == 422  # 缺 default_action / max_sessions
    assert client.post(
        "/firewall/simulate",
        json={"rules": [], "events": [valid_event], "default_action": "deny",
              "session_timeout": 30},
    ).status_code == 422  # 缺 max_sessions

    # 空事件 / 超过 2000 个事件
    assert post_firewall([valid_rule], []).status_code == 422
    too_many = [
        fw_event(i, f"1.0.{i // 256}", 1000 + i % 50000, "2.2.2.2", 80)
        for i in range(2001)
    ]
    assert post_firewall([valid_rule], too_many).status_code == 422

    # 超过 500 条规则
    too_many_rules = [
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 0, "port_end": 65535}
        for _ in range(501)
    ]
    assert post_firewall(too_many_rules, [valid_event]).status_code == 422

    # 非法端口：越界 / bool / float / 字符串
    for bad_port in [-1, 65536, True, 1.5, "80"]:
        bad = fw_event(0, "1.1.1.1", bad_port, "2.2.2.2", 80)
        assert post_firewall([valid_rule], [bad]).status_code == 422, bad_port
    bad_rule = {**valid_rule, "port_start": 100, "port_end": 80}
    assert post_firewall([bad_rule], [valid_event]).status_code == 422

    # icmp 带端口 / tcp 缺端口
    assert post_firewall(
        [{"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
          "protocol": "icmp", "port_start": 0, "port_end": 0}],
        [fw_event(0, "1.1.1.1", None, "2.2.2.2", None, proto="icmp")],
    ).status_code == 422
    assert post_firewall(
        [valid_rule],
        [fw_event(0, "1.1.1.1", None, "2.2.2.2", 80)],
    ).status_code == 422

    # 非法时间戳：负数 / bool / float
    for bad_ts in [-1, True, 1.5]:
        assert post_firewall(
            [valid_rule], [fw_event(bad_ts, "1.1.1.1", 1000, "2.2.2.2", 80)]
        ).status_code == 422, bad_ts

    # 非法 session_timeout：0 / 86401 / bool / float
    for bad_timeout in [0, 86401, True, 1.5, "30"]:
        resp = client.post(
            "/firewall/simulate",
            json={"rules": [], "events": [valid_event],
                  "default_action": "deny", "session_timeout": bad_timeout,
                  "max_sessions": 10000},
        )
        assert resp.status_code == 422, bad_timeout

    # 非法 max_sessions：0 / 10001 / 负数 / bool / float / 字符串
    for bad_capacity in [0, 10001, -1, True, 1.5, "100"]:
        resp = client.post(
            "/firewall/simulate",
            json={"rules": [], "events": [valid_event],
                  "default_action": "deny", "session_timeout": 30,
                  "max_sessions": bad_capacity},
        )
        assert resp.status_code == 422, bad_capacity

    # 非法协议 / 方向 / 动作 / CIDR / 地址
    assert post_firewall(
        [{"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
          "protocol": "gre", "port_start": 0, "port_end": 0}],
        [valid_event],
    ).status_code == 422
    assert post_firewall(
        [valid_rule],
        [fw_event(0, "1.1.1.1", 1000, "2.2.2.2", 80, direction="inbound")],
    ).status_code == 422
    assert post_firewall(
        [{**valid_rule, "action": "permit"}], [valid_event]
    ).status_code == 422
    assert post_firewall(
        [{**valid_rule, "src_cidr": "10.0.0.0/33"}], [valid_event]
    ).status_code == 422
    assert post_firewall(
        [valid_rule], [fw_event(0, "1.1.1.1/32", 1000, "2.2.2.2", 80)]
    ).status_code == 422
    assert post_firewall(
        [valid_rule],
        [fw_event(0, "2001:db8::1", 1000, "2.2.2.2", 80)],
    ).status_code == 422


def test_firewall_openapi_documented():
    spec = client.get("/openapi.json").json()
    assert "/firewall/simulate" in spec["paths"]
    operation = spec["paths"]["/firewall/simulate"]["post"]
    assert operation["tags"] == ["firewall"]
    assert operation["summary"]
    for name in (
        "FirewallSimulateRequest",
        "FirewallSimulateResponse",
        "FirewallRule",
        "FirewallEvent",
        "FirewallEventResult",
        "FirewallSummary",
        "FirewallSession",
        "FirewallSessionKey",
    ):
        assert name in spec["components"]["schemas"], name
    # max_sessions 必填且带 1～10000 边界
    request_props = spec["components"]["schemas"]["FirewallSimulateRequest"]["properties"]
    assert request_props["max_sessions"]["minimum"] == 1
    assert request_props["max_sessions"]["maximum"] == 10000
    required = spec["components"]["schemas"]["FirewallSimulateRequest"]["required"]
    assert "max_sessions" in required
    # 会话对象含 last_seen；逐事件结果含 evicted_session；summary 含 evicted_sessions
    session_props = spec["components"]["schemas"]["FirewallSession"]["properties"]
    assert "last_seen" in session_props
    result_props = spec["components"]["schemas"]["FirewallEventResult"]["properties"]
    assert "evicted_session" in result_props
    summary_props = spec["components"]["schemas"]["FirewallSummary"]["properties"]
    assert "evicted_sessions" in summary_props
    # 内置 422 错误示例
    examples = operation["responses"]["422"]["content"]["application/json"]["examples"]
    assert set(examples) == {"out_of_order", "overlapping"}
    # 请求示例
    req_examples = operation["requestBody"]["content"]["application/json"]["examples"]
    assert set(req_examples) == {"simulate", "eviction"}
    assert req_examples["eviction"]["value"]["max_sessions"] == 2


def test_firewall_capacity_eviction_and_rematch():
    rules = [
        {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
         "protocol": "tcp", "port_start": 0, "port_end": 65535},
    ]
    events = [
        fw_event(0, "10.0.0.1", 1001, "10.0.1.1", 80),
        fw_event(1, "10.0.0.2", 1002, "10.0.1.2", 80),
        fw_event(2, "10.0.1.1", 80, "10.0.0.1", 1001, direction="reverse"),
        fw_event(3, "10.0.0.3", 1003, "10.0.1.3", 80),
        fw_event(4, "10.0.1.2", 80, "10.0.0.2", 1002, direction="reverse"),
    ]
    resp = post_firewall(rules, events, session_timeout=100, max_sessions=2)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["max_sessions"] == 2
    results = body["results"]

    # t=2 流 A 反向命中，last_seen 刷新为 2
    assert results[2]["session_state"] == "active"
    assert results[2]["session"]["last_seen"] == 2

    # t=3 建流 C：容量已满，淘汰 last_seen 更早的流 B（1），而非 A（2）
    assert results[3]["session_state"] == "new"
    evicted = results[3]["evicted_session"]
    assert evicted["key"] == {
        "protocol": "tcp",
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.1.2",
        "src_port": 1002,
        "dst_port": 80,
    }
    assert evicted["created_at"] == 1
    assert evicted["last_seen"] == 1
    assert evicted["expires_at"] == 101
    assert evicted["established_by_event"] == 1
    assert results[3]["session"]["last_seen"] == 3

    # t=4 被淘汰流 B 的反向包不再 stateful：重新按规则裁决（allow 但不建会话）
    assert results[4]["match"]["type"] == "rule"
    assert results[4]["action"] == "allow"
    assert results[4]["session_state"] == "none"
    assert results[4]["session"] is None
    assert results[4]["evicted_session"] is None

    assert [r["evicted_session"] is not None for r in results] == [
        False, False, False, True, False,
    ]
    assert body["summary"] == {
        "allowed": 5,
        "denied": 0,
        "new_sessions": 3,
        "expired_sessions": 0,
        "evicted_sessions": 1,
        "active_sessions": 2,
    }


def test_firewall_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    assert post_audit([]).status_code == 200
    assert post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}]).status_code == 200


# ---------- /ipv4/reassemble ----------


def post_reassemble(header_bytes, fragments):
    return client.post(
        "/ipv4/reassemble",
        json={"header_bytes": header_bytes, "fragments": fragments},
    )


def fr(offset, more_fragments, raw):
    import base64

    payload = raw if isinstance(raw, str) else base64.b64encode(raw).decode()
    return {"offset": offset, "more_fragments": more_fragments, "payload": payload}


def test_reassemble_complete_basic():
    resp = post_reassemble(
        20,
        [
            fr(1, False, b"rld-ipv4"),
            fr(0, True, b"hello-wo"),
            fr(0, True, b"hello-wo"),
        ],
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "complete",
        "contributing_fragments": [1, 2, 0],
        "payload": "aGVsbG8td29ybGQtaXB2NA==",
        "missing_ranges": None,
        "first_conflict_offset": None,
    }


def test_reassemble_complete_single_last_fragment():
    resp = post_reassemble(20, [fr(0, False, b"abc")])
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "complete"
    assert body["contributing_fragments"] == [0]
    assert body["payload"] == "YWJj"
    assert body["missing_ranges"] is None
    assert body["first_conflict_offset"] is None


def test_reassemble_incomplete():
    resp = post_reassemble(
        20,
        [fr(0, True, b"\x00" * 8), fr(2, False, b"\x00" * 4)],
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "incomplete",
        "contributing_fragments": None,
        "payload": None,
        "missing_ranges": [[8, 16]],
        "first_conflict_offset": None,
    }


def test_reassemble_conflict_first_offset():
    resp = post_reassemble(
        20,
        [
            fr(0, True, b"\x00" * 16),
            fr(1, True, b"\x00\x40" + b"\x00" * 6),
            fr(2, False, b"\x00" * 4),
        ],
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "conflict",
        "contributing_fragments": None,
        "payload": None,
        "missing_ranges": None,
        "first_conflict_offset": 9,
    }


def test_reassemble_duplicate_identical_overlap_accepted():
    resp = post_reassemble(
        20,
        [
            fr(0, True, b"A" * 16),
            fr(1, True, b"A" * 8 + b"B" * 8),
            fr(3, False, b"B" * 8),
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "complete"
    import base64

    assert base64.b64decode(body["payload"]) == b"A" * 16 + b"B" * 16


def test_reassemble_non_aligned_non_last_422():
    resp = post_reassemble(
        20, [fr(0, True, b"abc"), fr(1, False, b"")]
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "non_aligned_fragment",
        "indexes": [0],
        "limit": None,
    }


def test_reassemble_missing_last_422():
    resp = post_reassemble(20, [fr(0, True, b"\x00" * 8)])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_last_fragment_count"
    assert detail["indexes"] == []


def test_reassemble_multiple_last_422():
    resp = post_reassemble(20, [fr(0, False, b""), fr(1, False, b"")])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "invalid_last_fragment_count"
    assert detail["indexes"] == [0, 1]


def test_reassemble_datagram_too_large_422():
    resp = post_reassemble(
        20,
        [fr(0, True, b"\x00" * 65512), fr(8189, False, b"\x00" * 4)],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "datagram_too_large",
        "indexes": [1],
        "limit": 65535,
    }


def test_reassemble_exact_limit_200():
    resp = post_reassemble(
        20,
        [fr(0, True, b"\x00" * 65512), fr(8189, False, b"\x00" * 3)],
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "complete"


def test_reassemble_header_boundaries_200():
    resp = post_reassemble(60, [fr(0, False, b"x" * 100)])
    assert resp.status_code == 200
    resp = post_reassemble(20, [fr(0, False, b"x" * 100)])
    assert resp.status_code == 200


def test_reassemble_header_out_of_range_422():
    for header in (19, 61, 0):
        assert post_reassemble(header, [fr(0, False, b"")]).status_code == 422


def test_reassemble_validation_422():
    # 缺少字段
    assert client.post("/ipv4/reassemble", json={}).status_code == 422
    assert client.post(
        "/ipv4/reassemble", json={"header_bytes": 20}
    ).status_code == 422
    # 空分片列表 / 超过 500
    assert post_reassemble(20, []).status_code == 422
    too_many = [fr(i, True, b"\x00" * 8) for i in range(500)] + [fr(500, False, b"")]
    assert post_reassemble(20, too_many).status_code == 422
    # 类型严格
    assert post_reassemble("20", [fr(0, False, b"")]).status_code == 422
    assert post_reassemble(20.0, [fr(0, False, b"")]).status_code == 422
    assert post_reassemble(True, [fr(0, False, b"")]).status_code == 422
    # offset 负数 / 非整数
    assert post_reassemble(20, [fr(-1, False, b"")]).status_code == 422
    assert post_reassemble(20, [{"offset": 1.5, "more_fragments": False,
                                 "payload": ""}]).status_code == 422
    # more_fragments 非布尔
    assert post_reassemble(
        20, [{"offset": 0, "more_fragments": "false", "payload": ""}]
    ).status_code == 422
    # 非法 Base64
    assert post_reassemble(
        20, [{"offset": 0, "more_fragments": False, "payload": "not base64!"}]
    ).status_code == 422
    assert post_reassemble(
        20, [{"offset": 0, "more_fragments": False, "payload": "A"}]
    ).status_code == 422


def test_reassemble_last_fragment_unaligned_payload_ok():
    # 末片长度不必为 8 的倍数
    resp = post_reassemble(
        20, [fr(0, True, b"\x00" * 8), fr(1, False, b"\x00" * 3)]
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "complete"


def test_reassemble_endpoints_listed_in_openapi():
    schema = client.get("/openapi.json").json()
    assert "/ipv4/reassemble" in schema["paths"]


# ---------- /ipv4/fragment ----------


def post_fragment(payload, header_bytes=20, mtu=1500, dont_fragment=False, **extra):
    import base64

    body = {
        "payload": (
            payload
            if isinstance(payload, str)
            else base64.b64encode(payload).decode()
        ),
        "header_bytes": header_bytes,
        "mtu": mtu,
        "dont_fragment": dont_fragment,
    }
    body.update(extra)
    return client.post("/ipv4/fragment", json=body)


def test_fragment_unfragmented_basic():
    resp = post_fragment(b"hello")
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "unfragmented",
        "fragment_count": 1,
        "fragments": [
            {
                "offset": 0,
                "more_fragments": False,
                "payload": "aGVsbG8=",
                "total_length": 25,
            }
        ],
    }


def test_fragment_unfragmented_exact_mtu():
    assert post_fragment(b"x" * 80, mtu=100).json()["status"] == "unfragmented"
    assert post_fragment(b"x" * 80, mtu=99).json()["status"] == "fragmented"


def test_fragment_unfragmented_preserves_original_offset_and_mf():
    # MF=true 的非末片载荷必须 8 字节对齐（这里取 8 字节）
    resp = post_fragment(
        b"A" * 8, original_offset=5, original_more_fragments=True
    )
    assert resp.status_code == 200
    fragment = resp.json()["fragments"][0]
    assert fragment["offset"] == 5
    assert fragment["more_fragments"] is True
    assert fragment["total_length"] == 28


def test_fragment_unfragmented_df_true_still_forwards():
    resp = post_fragment(b"hello", dont_fragment=True)
    assert resp.status_code == 200
    assert resp.json()["status"] == "unfragmented"


def test_fragment_fragmented_basic():
    resp = post_fragment(b"hello-world-ipv4!!!!", mtu=28)
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "fragmented",
        "fragment_count": 3,
        "fragments": [
            {"offset": 0, "more_fragments": True,
             "payload": "aGVsbG8td28=", "total_length": 28},
            {"offset": 1, "more_fragments": True,
             "payload": "cmxkLWlwdjQ=", "total_length": 28},
            {"offset": 2, "more_fragments": False,
             "payload": "ISEhIQ==", "total_length": 24},
        ],
    }


def test_fragment_fragmented_max_8_byte_multiple():
    # MTU 30、首部 20 → 预算 10 向下取 8；24 字节切成 8/8/8
    resp = post_fragment(b"A" * 24, mtu=30)
    assert resp.status_code == 200
    body = resp.json()
    import base64

    assert [len(base64.b64decode(f["payload"])) for f in body["fragments"]] == [
        8, 8, 8,
    ]
    assert [f["offset"] for f in body["fragments"]] == [0, 1, 2]
    assert [f["more_fragments"] for f in body["fragments"]] == [
        True, True, False,
    ]


def test_fragment_needs_fragmentation_no_payload():
    resp = post_fragment(b"x" * 100, mtu=28, dont_fragment=True)
    assert resp.status_code == 200
    assert resp.json() == {
        "status": "needs_fragmentation",
        "fragment_count": 0,
        "fragments": [],
    }


def test_fragment_refragment_offsets_and_mf():
    # 非末片（MF=true）载荷必须 8 字节对齐：24 字节切成三个 8 字节子片
    resp = post_fragment(
        b"A" * 24, mtu=28, original_offset=2, original_more_fragments=True
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "fragmented"
    assert [f["offset"] for f in body["fragments"]] == [2, 3, 4]
    # 最后子片继承原始 MF=true
    assert [f["more_fragments"] for f in body["fragments"]] == [
        True, True, True,
    ]
    # 末片（MF=false）不要求对齐：20 字节切成 8/8/4
    resp = post_fragment(
        b"A" * 20, mtu=28, original_offset=7, original_more_fragments=False
    )
    assert [f["more_fragments"] for f in resp.json()["fragments"]] == [
        True, True, False,
    ]


def test_fragment_mtu_too_small_422():
    resp = post_fragment(b"x" * 100, mtu=27)
    assert resp.status_code == 422
    assert resp.json()["detail"] == {"error": "mtu_too_small", "limit": 28}
    # 边界：MTU 28 = 首部 20 + 8，恰好可以切片
    assert post_fragment(b"x" * 100, mtu=28).status_code == 200


def test_fragment_datagram_too_large_422():
    resp = post_fragment(b"\x00" * 65516, header_bytes=20)
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "datagram_too_large",
        "limit": 65535,
    }
    # 恰好 65535 不越界
    resp = post_fragment(b"\x00" * 65475, header_bytes=60, mtu=65535)
    assert resp.status_code == 200
    assert resp.json()["status"] == "unfragmented"


def test_fragment_non_aligned_original_non_last_422():
    # original_more_fragments=true 但载荷 5 字节、不是 8 的倍数；
    # 即使数据报本身不超 MTU（unfragmented 分支）也必须 422
    resp = post_fragment(
        b"hello", mtu=1500, original_offset=5, original_more_fragments=True
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "non_aligned_fragment",
        "limit": None,
    }
    # 校验早于 DF 分支：DF=true 超 MTU 同样报 non_aligned_fragment
    resp = post_fragment(
        b"x" * 100, mtu=28, dont_fragment=True,
        original_offset=1, original_more_fragments=True,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "non_aligned_fragment"
    # 同时越界时对齐错误优先
    resp = post_fragment(
        b"x" * 65525, mtu=1500,
        original_offset=1, original_more_fragments=True,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "non_aligned_fragment"
    # 末片（MF=false）不要求对齐
    resp = post_fragment(
        b"hello", mtu=1500, original_offset=5, original_more_fragments=False
    )
    assert resp.status_code == 200
    assert resp.json()["fragments"][0]["offset"] == 5


def test_fragment_datagram_end_too_large_with_offset_422():
    # 单片仅 28 字节、不超 MTU，但原数据报绝对结束位置
    # 8191*8 + 8 + 20 = 65556 > 65535
    resp = post_fragment(
        b"A" * 8, mtu=1500,
        original_offset=8191, original_more_fragments=True,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "datagram_too_large",
        "limit": 65535,
    }
    # 结束位置校验早于 DF 分支
    resp = post_fragment(
        b"A" * 8, mtu=28, dont_fragment=True,
        original_offset=8191, original_more_fragments=True,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "datagram_too_large"
    # 结束位置校验早于 mtu_too_small 分支
    resp = post_fragment(
        b"A" * 8, mtu=20,
        original_offset=8191, original_more_fragments=True,
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "datagram_too_large"
    # 结束位置恰好 65535（offset=8188、11 字节末片）合法
    resp = post_fragment(
        b"A" * 11, mtu=1500,
        original_offset=8188, original_more_fragments=False,
    )
    assert resp.status_code == 200
    assert resp.json()["fragments"][0]["offset"] == 8188


def test_fragment_output_offsets_never_exceed_8191():
    # offset=8180、MF=true 的 72 字节对齐载荷（结束位置 65532 ≤ 65535），
    # MTU 28 切成 9 片，最大输出 offset 8188 ≤ 8191
    resp = post_fragment(
        b"A" * 72, mtu=28,
        original_offset=8180, original_more_fragments=True,
    )
    assert resp.status_code == 200
    offsets = [f["offset"] for f in resp.json()["fragments"]]
    assert offsets == list(range(8180, 8189))
    assert max(offsets) <= 8191


def test_fragment_validation_422():
    # 缺少必填字段
    assert client.post("/ipv4/fragment", json={}).status_code == 422
    assert client.post(
        "/ipv4/fragment",
        json={"payload": "", "header_bytes": 20, "mtu": 1500},
    ).status_code == 422
    # header_bytes 越界 / 类型
    for bad in (19, 61, 0, "20", 20.0, True):
        assert post_fragment(b"", header_bytes=bad).status_code == 422
    # mtu 非正整数 / 类型
    for bad in (0, -1, "1500", 1500.0, True):
        assert post_fragment(b"x" * 100, mtu=bad).status_code == 422
    # dont_fragment / original_more_fragments 非布尔
    assert post_fragment(b"", dont_fragment="true").status_code == 422
    assert post_fragment(b"", dont_fragment=1).status_code == 422
    assert post_fragment(b"", original_more_fragments="false").status_code == 422
    # original_offset 越界 / 类型
    for bad in (-1, 8192, 1.5, "0", True):
        assert post_fragment(b"", original_offset=bad).status_code == 422
    # 非法 Base64
    assert post_fragment("not base64!").status_code == 422
    assert post_fragment("A").status_code == 422


def test_fragment_endpoint_listed_in_openapi():
    schema = client.get("/openapi.json").json()
    assert "/ipv4/fragment" in schema["paths"]
