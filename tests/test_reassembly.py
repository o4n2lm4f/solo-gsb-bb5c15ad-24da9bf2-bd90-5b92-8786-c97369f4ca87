"""IPv4 分片重组核心逻辑的单元测试。"""
import base64

import pytest

from app.reassembly import (
    FRAGMENTS_MAX,
    HEADER_MAX,
    HEADER_MIN,
    IPV4_DATAGRAM_MAX,
    OFFSET_UNIT,
    ReassemblyInputError,
    decode_payload,
    reassemble_ipv4,
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def frag(offset, more, payload):
    return (offset, more, payload)


# ---------- 基本完成场景 ----------


def test_single_fragment_complete():
    result = reassemble_ipv4(20, [frag(0, False, b"hello")])
    assert result == {
        "status": "complete",
        "contributing_fragments": [0],
        "payload": b64(b"hello"),
    }


def test_complete_out_of_order_sorted_by_offset():
    result = reassemble_ipv4(
        20,
        [
            frag(2, False, b"C" * 8),
            frag(0, True, b"A" * 8),
            frag(1, True, b"B" * 8),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [1, 2, 0]
    assert base64.b64decode(result["payload"]) == b"A" * 8 + b"B" * 8 + b"C" * 8


def test_complete_same_offset_tie_break_by_input_index():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefgh"),
            frag(1, False, b"ijkl"),
            frag(1, True, b"ijklXXXX"),  # 与末片同偏移，输入序号更大
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 1, 2]
    assert base64.b64decode(result["payload"]) == b"abcdefghijkl"


def test_duplicate_identical_fragment_accepted():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"hello-wo"),
            frag(1, False, b"rld-ipv4"),
            frag(0, True, b"hello-wo"),  # 完全重发
        ],
    )
    assert result == {
        "status": "complete",
        "contributing_fragments": [0, 2, 1],
        "payload": b64(b"hello-world-ipv4"),
    }


def test_partial_overlap_identical_accepted():
    # 第二片覆盖 [8,24)，与 [0,16) 在 [8,16) 上重复且一致
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"A" * 16),
            frag(1, True, b"A" * 8 + b"B" * 8),
            frag(3, False, b"B" * 8),
        ],
    )
    assert result["status"] == "complete"
    assert base64.b64decode(result["payload"]) == b"A" * 16 + b"B" * 16


def test_last_fragment_payload_need_not_be_aligned():
    result = reassemble_ipv4(20, [frag(0, False, b"abc")])
    assert result["status"] == "complete"
    # 唯一末片即使长度为 3（非 8 倍数）也合法
    result = reassemble_ipv4(
        20, [frag(0, True, b"\x00" * 8), frag(1, False, b"\x00" * 3)]
    )
    assert result["status"] == "complete"


def test_zero_length_last_fragment_empty_datagram():
    result = reassemble_ipv4(20, [frag(0, False, b"")])
    assert result == {
        "status": "complete",
        "contributing_fragments": [],
        "payload": "",
    }


def test_empty_non_last_fragment_not_contributing():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefgh"),
            frag(1, True, b""),          # 空载荷非末片（对齐），不计贡献
            frag(1, False, b"ijkl"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 2]


# ---------- 缺口场景 ----------


def test_incomplete_middle_gap():
    result = reassemble_ipv4(
        20, [frag(0, True, b"\x00" * 8), frag(2, False, b"\x00" * 4)]
    )
    assert result == {"status": "incomplete", "missing_ranges": [[8, 16]]}


def test_incomplete_leading_gap():
    result = reassemble_ipv4(
        20, [frag(1, True, b"\x00" * 8), frag(2, False, b"\x00" * 8)]
    )
    assert result == {"status": "incomplete", "missing_ranges": [[0, 8]]}


def test_incomplete_multiple_gaps_merged():
    # 覆盖 [0,8) 与 [24,28)，缺口 [8,24) 合并为一个半开区间
    result = reassemble_ipv4(
        20, [frag(0, True, b"\x00" * 8), frag(3, False, b"\x00" * 4)]
    )
    assert result == {"status": "incomplete", "missing_ranges": [[8, 24]]}


def test_incomplete_separate_gaps_kept_separate():
    # 覆盖 [0,8) 与 [16,24)，末片锚定 24；缺口 [8,16)
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"\x00" * 8),
            frag(2, True, b"\x00" * 8),
            frag(3, False, b""),
        ],
    )
    assert result == {"status": "incomplete", "missing_ranges": [[8, 16]]}


def test_gaps_half_open_adjacent_intervals_merge():
    # 覆盖 [0,8) 与 [16,20)（末片 4 字节），缺口 [8,16)
    result = reassemble_ipv4(
        20, [frag(0, True, b"\x00" * 8), frag(2, False, b"\x00" * 4)]
    )
    assert result["missing_ranges"] == [[8, 16]]


# ---------- 冲突场景 ----------


def test_conflict_first_offset():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"\x00" * 8),
            frag(0, True, b"\x00" * 7 + b"\x01"),
            frag(1, False, b"\x00" * 8),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 7}


def test_conflict_offset_across_overlap():
    # 原片 16 字节覆盖 [0,16)，重发片在偏移 8 处，其本地第 1 字节冲突 => 绝对 9
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"\x00" * 16),
            frag(1, True, b"\x00\x40" + b"\x00" * 6),
            frag(2, False, b"\x00" * 4),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 9}


def test_conflict_min_offset_among_all_pairs():
    # 两对冲突：偏移 5（[0,8) 内）与偏移 13（[8,16) 内）；返回最小的 5，
    # 且与分片输入顺序无关（冲突片排在前）
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"\x00" * 5 + b"\xee" + b"\x00" * 2),
            frag(1, True, b"\x00" * 5 + b"\xff" + b"\x00" * 2),
            frag(0, True, b"\x00" * 8),
            frag(1, True, b"\x00" * 8),
            frag(2, False, b"\x00" * 8),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 5}


def test_conflict_takes_precedence_over_gap():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"\x00" * 8),
            frag(0, True, b"\x00" * 7 + b"\x01"),
            frag(10, False, b""),
        ],
    )
    assert result["status"] == "conflict"
    assert result["first_conflict_offset"] == 7


# ---------- 越过末片锚定末尾的字节 ----------


def test_fragment_entirely_beyond_anchor_excluded():
    # 末片锚定总长度 12；非末片 index 2 落在 [16,24)，完全越界
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefgh"),
            frag(1, False, b"ijkl"),
            frag(2, True, b"mooooooo"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 1]
    assert base64.b64decode(result["payload"]) == b"abcdefghijkl"


def test_fragment_partially_beyond_anchor_clamped():
    # index 2 覆盖 [8,16)，仅 [8,12) 计入；与末片一致即接受
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefgh"),
            frag(1, False, b"ijkl"),
            frag(1, True, b"ijklXXXX"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 1, 2]


def test_conflict_on_clamped_overlap_still_detected():
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefgh"),
            frag(1, False, b"ijkl"),
            frag(1, True, b"ijXmXXXX"),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 10}


# ---------- 首尾嵌套 ----------


def test_last_fragment_fully_nested_inside_earlier_one():
    # 末片 [16,20) 完全嵌套在非末片 [8,40) 的尾部；越出锚点的 [20,40)
    # 部分须裁剪，非末片长度 32 仍按 8 对齐
    result = reassemble_ipv4(
        20,
        [
            frag(2, False, b"qrst"),
            frag(1, True, b"ijklmnop" + b"qrst" + b"X" * 20),
            frag(0, True, b"abcdefgh"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [2, 1, 0]
    assert base64.b64decode(result["payload"]) == b"abcdefghijklmnopqrst"


def test_last_fragment_nested_identical_duplicate_accepted():
    # 末片 [8,16) 被完全相同的非末片 [8,16) 覆盖包裹，另有 8 对齐大片
    # [0,24) 越过锚点 [16,24)
    result = reassemble_ipv4(
        20,
        [
            frag(0, True, b"abcdefghijklmnop" + b"X" * 8),
            frag(1, True, b"ijklmnop"),
            frag(1, False, b"ijklmnop"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 1, 2]
    assert base64.b64decode(result["payload"]) == b"abcdefghijklmnop"


def test_first_fragment_nested_inside_later_one():
    # 首片 [0,8) 完全嵌套在后续 8 对齐片 [0,24) 的头部，末片锚定 28
    result = reassemble_ipv4(
        20,
        [
            frag(3, False, b"yzAB"),
            frag(0, True, b"abcdefgh"),
            frag(0, True, b"abcdefghijklmnopqrstuvwx"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [1, 2, 0]
    assert base64.b64decode(result["payload"]) == b"abcdefghijklmnopqrstuvwxyzAB"


def test_nested_conflict_reports_inner_offset_regardless_of_order():
    # 末片 [8,16) 与 8 对齐包裹片 [0,24) 在绝对偏移 9 处冲突；
    # 两种输入顺序结果一致
    payloads = [
        frag(0, True, b"abcdefgh" + b"iXklmnop" + b"X" * 8),
        frag(1, False, b"ijklmnop"),
    ]
    for order in (payloads, list(reversed(payloads))):
        result = reassemble_ipv4(20, order)
        assert result == {"status": "conflict", "first_conflict_offset": 9}


# ---------- 多片交叉重叠 ----------


def test_three_fragments_crossing_overlap_identical():
    # [0,24)、[8,32)、[16,40) 三片两两交叉；末片锚定 40
    result = reassemble_ipv4(
        20,
        [
            frag(2, True, bytes(range(16, 40))),
            frag(0, True, bytes(range(0, 24))),
            frag(4, False, bytes(range(32, 40))),
            frag(1, True, bytes(range(8, 32))),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [1, 3, 0, 2]
    assert base64.b64decode(result["payload"]) == bytes(range(40))


def test_three_fragments_crossing_overlap_first_conflict_offset():
    # [0,24) 与 [8,32) 共享 [8,24)；[16,40) 与两者共享 [16,24)，
    # 与 [8,32) 共享 [24,32)。冲突：[0,24) 在偏移 20 处为 \x14 而
    # [16,40) 为 \xff，故首个冲突为 20；另在偏移 28 放置冲突（30>20）
    result = reassemble_ipv4(
        20,
        [
            frag(2, True,
                 bytes(range(16, 20)) + b"\xff" + bytes(range(21, 28))
                 + b"\x00" + bytes(range(29, 40))),
            frag(0, True, bytes(range(0, 24))),
            frag(4, False, bytes(range(32, 40))),
            frag(1, True, bytes(range(8, 32))),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 20}


def test_many_fragments_same_span_conflict_min_offset():
    # 4 个分片覆盖同一区间 [0,16)，分别在不同字节冲突；返回最小偏移，
    # 与输入顺序无关
    def variant(bad_pos, bad_byte):
        data = bytearray(b"\x00" * 16)
        data[bad_pos] = bad_byte
        return bytes(data)

    shuffled = [
        frag(0, True, variant(13, 0x11)),
        frag(0, True, variant(3, 0x22)),
        frag(0, True, variant(7, 0x33)),
        frag(2, False, b"\x00" * 8),
        frag(0, True, b"\x00" * 16),
    ]
    for order in (shuffled, list(reversed(shuffled))):
        result = reassemble_ipv4(20, order)
        assert result == {"status": "conflict", "first_conflict_offset": 3}


# ---------- 末片锚点外数据 ----------


def test_multiple_fragments_beyond_anchor_clamped():
    # 末片锚定总长 8；index 1 部分越界 [0,16)→仅 [0,8)，index 2 完全越界
    result = reassemble_ipv4(
        20,
        [
            frag(2, True, b"zzzzzzzz"),          # 完全越界 [16,24)
            frag(0, True, b"abcdefghXXXXXXXX"),  # 部分越界 [0,16)
            frag(0, False, b"abcdefgh"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [1, 2]
    assert base64.b64decode(result["payload"]) == b"abcdefgh"


def test_data_beyond_anchor_never_compared_even_if_different():
    # 越出锚点 [8,16) 的两片字节即使不同也不报冲突；锚点内一致即完成
    result = reassemble_ipv4(
        20,
        [
            frag(0, False, b"abcdefgh"),
            frag(0, True, b"abcdefghXXXXXXXX"),
            frag(0, True, b"abcdefghYYYYYYYY"),
        ],
    )
    assert result["status"] == "complete"
    assert result["contributing_fragments"] == [0, 1, 2]


def test_conflict_inside_anchor_takes_precedence_over_garbage_outside():
    # 锚点内在偏移 5 冲突，锚点外 [8,16) 两片内容随意
    result = reassemble_ipv4(
        20,
        [
            frag(0, False, b"abcdeXgh"),
            frag(0, True, b"abcdefghZZZZZZZZ"),
            frag(0, True, b"abcdefghQQQQQQQQ"),
        ],
    )
    assert result == {"status": "conflict", "first_conflict_offset": 5}


def test_empty_anchor_with_all_data_beyond_is_complete_empty():
    # 零长度末片锚定空数据报；所有非末片数据全在锚点外，不贡献
    result = reassemble_ipv4(
        20,
        [
            frag(1, True, b"XXXXXXXX"),
            frag(0, True, b"YYYYYYYY"),
            frag(0, False, b""),
        ],
    )
    assert result == {
        "status": "complete",
        "contributing_fragments": [],
        "payload": "",
    }


# ---------- 422 类输入错误 ----------


def test_non_aligned_non_last_fragment():
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(20, [frag(0, True, b"abc"), frag(1, False, b"")])
    error = exc_info.value
    assert error.error == "non_aligned_fragment"
    assert error.indexes == [0]


def test_non_aligned_reports_first_violating_index():
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(
            20,
            [
                frag(0, True, b"\x00" * 8),
                frag(1, True, b"\x00" * 5),
                frag(2, False, b""),
            ],
        )
    assert exc_info.value.indexes == [1]


def test_missing_last_fragment():
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(20, [frag(0, True, b"\x00" * 8)])
    assert exc_info.value.error == "invalid_last_fragment_count"
    assert exc_info.value.indexes == []


def test_multiple_last_fragments_reports_all_indexes():
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(20, [frag(0, False, b""), frag(1, False, b"")])
    error = exc_info.value
    assert error.error == "invalid_last_fragment_count"
    assert error.indexes == [0, 1]


def test_datagram_too_large():
    # 首部 20 + 载荷 65516 = 65536 > 65535
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(
            20, [frag(0, True, b"\x00" * 65512), frag(8189, False, b"\x00" * 4)]
        )
    error = exc_info.value
    assert error.error == "datagram_too_large"
    assert error.limit == IPV4_DATAGRAM_MAX
    assert error.indexes == [1]


def test_datagram_exact_limit_ok():
    result = reassemble_ipv4(
        HEADER_MIN,
        [frag(0, True, b"\x00" * 65512), frag(8189, False, b"\x00" * 3)],
    )
    assert result["status"] == "complete"
    assert len(base64.b64decode(result["payload"])) == 65515


def test_datagram_limit_respects_header_bytes():
    # 首部 60 时最大载荷 65475
    result = reassemble_ipv4(
        60, [frag(0, True, b"\x00" * 65472), frag(8184, False, b"\x00" * 3)]
    )
    assert result["status"] == "complete"
    with pytest.raises(ReassemblyInputError) as exc_info:
        reassemble_ipv4(
            60, [frag(0, True, b"\x00" * 65472), frag(8184, False, b"\x00" * 4)]
        )
    assert exc_info.value.error == "datagram_too_large"


def test_invalid_header_length():
    for header in (HEADER_MIN - 1, HEADER_MAX + 1, 0, -1):
        with pytest.raises(ReassemblyInputError) as exc_info:
            reassemble_ipv4(header, [frag(0, False, b"")])
        assert exc_info.value.error == "invalid_header_length"


def test_invalid_header_length_type():
    for header in (20.0, "20", True, None):
        with pytest.raises(ReassemblyInputError) as exc_info:
            reassemble_ipv4(header, [frag(0, False, b"")])
        assert exc_info.value.error == "invalid_header_length"


def test_empty_fragment_list():
    with pytest.raises(ValueError):
        reassemble_ipv4(20, [])


def test_too_many_fragments():
    fragments = [frag(i, True, b"\x00" * OFFSET_UNIT) for i in range(FRAGMENTS_MAX)]
    fragments.append(frag(FRAGMENTS_MAX, False, b""))
    with pytest.raises(ValueError):
        reassemble_ipv4(20, fragments)


def test_invalid_offset_and_more_fragments_types():
    with pytest.raises(ValueError):
        reassemble_ipv4(20, [frag(-1, False, b"")])
    with pytest.raises(ValueError):
        reassemble_ipv4(20, [frag(1.0, False, b"")])
    with pytest.raises(ValueError):
        reassemble_ipv4(20, [frag(True, False, b"")])
    with pytest.raises(ValueError):
        reassemble_ipv4(20, [(0, 1, b"")])


# ---------- Base64 解码 ----------


def test_decode_base64():
    assert decode_payload("") == b""
    assert decode_payload("AAAA") == b"\x00\x00\x00"
    assert decode_payload("aGVsbG8=") == b"hello"


@pytest.mark.parametrize(
    "bad",
    ["A", "!!!", "AAA", "AAA=A", "AB CD", "aGVsb G8=", "\n", "@@@@"],
)
def test_decode_invalid_base64(bad):
    with pytest.raises(ValueError):
        decode_payload(bad)


def test_core_accepts_base64_string_payload():
    result = reassemble_ipv4(20, [(0, False, "aGVsbG8=")])
    assert result["payload"] == b64(b"hello")


# ---------- 随机属性：完整重组与缺口集合 ----------


def test_random_complete_property():
    import random

    rng = random.Random(42)
    for _ in range(200):
        n = rng.randint(1, 600)
        data = bytes(rng.randrange(256) for _ in range(n))
        cuts = [0]
        pos = 0
        while pos < n:
            step = rng.choice([8, 16, 24]) if n - pos > 8 else (n - pos)
            pos = min(pos + step, n)
            cuts.append(pos)
        pieces = [(cuts[i], cuts[i + 1] - cuts[i]) for i in range(len(cuts) - 1)]
        fragments = [
            (st // 8, i < len(pieces) - 1, data[st:st + ln])
            for i, (st, ln) in enumerate(pieces)
        ]
        if len(fragments) > 1:
            dup = rng.randrange(0, len(fragments) - 1)
            fragments.append((fragments[dup][0], True, fragments[dup][2]))
        rng.shuffle(fragments)
        result = reassemble_ipv4(20, fragments)
        assert result["status"] == "complete"
        assert base64.b64decode(result["payload"]) == data


def test_random_gap_property():
    import random

    rng = random.Random(7)
    for _ in range(200):
        n = rng.choice(range(8, 400, 8))
        data = bytes(rng.randrange(256) for _ in range(n))
        cuts = list(range(0, n, rng.choice([8, 16]))) + [n]
        pieces = [(cuts[i], cuts[i + 1] - cuts[i]) for i in range(len(cuts) - 1)]
        fragments = [
            (st // 8, i < len(pieces) - 1, data[st:st + ln])
            for i, (st, ln) in enumerate(pieces)
        ]
        if len(fragments) < 3:
            continue
        drop = rng.randrange(0, len(fragments) - 1)
        kept = [fragment for i, fragment in enumerate(fragments) if i != drop]
        rng.shuffle(kept)
        result = reassemble_ipv4(20, kept)
        assert result["status"] == "incomplete"
        missing = result["missing_ranges"]
        missing_set = {
            pos
            for start, end in missing
            for pos in range(start, end)
        }
        expected = set(range(pieces[drop][0], pieces[drop][0] + pieces[drop][1]))
        assert missing_set == expected


# ---------- 差分模糊：区间内核 vs 独立逐字节参考实现 ----------


def _reference_reassemble(header_length, fragments):
    """与产品代码独立的逐字节参考实现（旧 owner 列表语义）。"""
    parsed = []
    for index, (raw_offset, more_fragments, payload) in enumerate(fragments):
        parsed.append(
            (raw_offset * OFFSET_UNIT, bool(more_fragments), payload, index)
        )
    last_indexes = [index for _s, more, _p, index in parsed if not more]
    assert len(last_indexes) == 1
    for start, more, payload, index in parsed:
        if more and len(payload) % OFFSET_UNIT != 0:
            raise ReassemblyInputError("non_aligned_fragment")
    last_start, _more, last_payload, _idx = parsed[last_indexes[0]]
    total_length = last_start + len(last_payload)
    assert header_length + total_length <= IPV4_DATAGRAM_MAX

    buffer = bytearray(total_length)
    owner = [None] * total_length
    first_conflict = None
    for start, _more, payload, index in parsed:
        if start >= total_length:
            continue
        for rel, byte in enumerate(payload):
            pos = start + rel
            if pos >= total_length:
                break
            if owner[pos] is None:
                owner[pos] = index
                buffer[pos] = byte
            elif buffer[pos] != byte and (
                first_conflict is None or pos < first_conflict
            ):
                first_conflict = pos
    if first_conflict is not None:
        return {"status": "conflict", "first_conflict_offset": first_conflict}

    covered = [False] * total_length
    for start, _more, payload, _index in parsed:
        for pos in range(start, min(start + len(payload), total_length)):
            covered[pos] = True
    missing = []
    gap_start = None
    for pos in range(total_length):
        if not covered[pos] and gap_start is None:
            gap_start = pos
        if covered[pos] and gap_start is not None:
            missing.append([gap_start, pos])
            gap_start = None
    if gap_start is not None:
        missing.append([gap_start, total_length])
    if missing:
        return {"status": "incomplete", "missing_ranges": missing}

    contributing = sorted(
        {
            index
            for start, _more, payload, index in parsed
            if start < total_length
            and min(start + len(payload), total_length) > start
        },
        key=lambda idx: (next(s for s, _m, _p, i in parsed if i == idx), idx),
    )
    return {
        "status": "complete",
        "contributing_fragments": contributing,
        "payload": b64(bytes(buffer)),
    }


def test_differential_fuzz_against_bytewise_reference():
    import random

    rng = random.Random(20240919)
    for trial in range(400):
        n = rng.randint(0, 96)
        data = bytes(rng.randrange(256) for _ in range(n))

        # 末片起点必须 8 对齐（片偏移字段语义）；末片载荷可不对齐
        anchor = 8 * rng.randint(0, n // 8)
        fragments = []

        # [0, anchor) 内的标准 8 字节非末片：随机丢弃制造缺口，
        # 随机改字节制造冲突
        for start in range(0, anchor, 8):
            if rng.random() < 0.2:
                continue
            payload = bytearray(data[start:start + 8])
            for _ in range(rng.randint(0, 2)):
                payload[rng.randrange(8)] = rng.randrange(256)
            fragments.append([start // 8, True, bytes(payload)])

        # 随机追加：重发片、跨越锚点片、完全越界片（均为 8 对齐非末片）
        for _ in range(rng.randint(0, 3)):
            kind = rng.randrange(3)
            if kind == 0 and anchor > 0:
                src_start = 8 * rng.randrange(anchor // 8)
                dup = bytearray(data[src_start:src_start + 8])
                if dup and rng.random() < 0.5:
                    dup[rng.randrange(8)] = rng.randrange(256)
                fragments.append([src_start // 8, True, bytes(dup)])
            elif kind == 1 and anchor > 0:
                src_start = 8 * rng.randrange(anchor // 8)
                length = 8 * rng.randint(1, 4)
                crossing = bytearray(
                    rng.randrange(256) for _ in range(length)
                )
                # 前半段通常与真值一致，随机污染
                shared = min(length, n - src_start)
                if shared > 0:
                    crossing[:shared] = data[src_start:src_start + shared]
                for _ in range(rng.randint(0, 2)):
                    crossing[rng.randrange(length)] = rng.randrange(256)
                fragments.append([src_start // 8, True, bytes(crossing)])
            else:
                fragments.append([
                    (n + 8) // 8 + rng.randint(0, 3),
                    True,
                    bytes(rng.randrange(256) for _ in range(8)),
                ])

        # 唯一末片锚定 [anchor, n)；可能被污染制造尾部冲突
        last_payload = bytearray(data[anchor:n])
        if last_payload and rng.random() < 0.3:
            last_payload[rng.randrange(len(last_payload))] = rng.randrange(256)
        fragments.append([anchor // 8, False, bytes(last_payload)])

        rng.shuffle(fragments)
        tuples = [(off, more, payload) for off, more, payload in fragments]
        expected = _reference_reassemble(20, tuples)
        actual = reassemble_ipv4(20, tuples)
        assert actual == expected, (
            f"trial {trial} mismatch\nfragments={tuples!r}\n"
            f"expected={expected!r}\nactual={actual!r}"
        )


def test_differential_fuzz_order_independence():
    import random

    rng = random.Random(987654321)
    for _ in range(100):
        n = rng.randint(8, 80)
        data = bytes(rng.randrange(256) for _ in range(n))
        fragments = []
        starts = list(range(0, n, 8))
        for piece_index, start in enumerate(starts):
            payload = bytearray(data[start:min(start + 8, n)])
            if rng.random() < 0.3 and payload:
                payload[rng.randrange(len(payload))] ^= 0xFF
            fragments.append(
                (start // 8, piece_index != len(starts) - 1, bytes(payload))
            )
        rng.shuffle(fragments)
        assert reassemble_ipv4(20, fragments) == _reference_reassemble(
            20, fragments
        )


