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
