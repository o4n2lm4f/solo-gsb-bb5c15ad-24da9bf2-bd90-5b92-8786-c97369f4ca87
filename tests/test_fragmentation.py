"""IPv4 数据报分片规划核心逻辑的单元测试。"""
import base64

import pytest

from app.fragmentation import (
    FRAGMENT_OFFSET_MAX,
    HEADER_MAX,
    HEADER_MIN,
    IPV4_DATAGRAM_MAX,
    MTU_MIN,
    OFFSET_UNIT,
    FragmentationInputError,
    plan_ipv4_fragmentation,
)
from app.reassembly import reassemble_ipv4


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


def plan(header, mtu, df, payload, offset=0, mf=False):
    return plan_ipv4_fragmentation(header, mtu, df, payload, offset, mf)


# ---------- 不超 MTU：原样返回 ----------


def test_unfragmented_basic():
    result = plan(20, 1500, False, b"hello")
    assert result == {
        "status": "unfragmented",
        "fragment_count": 1,
        "fragments": [
            {
                "offset": 0,
                "more_fragments": False,
                "payload": b64(b"hello"),
                "total_length": 25,
            }
        ],
    }


def test_unfragmented_exact_mtu_boundary():
    # 数据报长度恰好等于 MTU：不超，原样返回
    result = plan(20, 100, False, b"x" * 80)
    assert result["status"] == "unfragmented"
    assert result["fragments"][0]["total_length"] == 100
    # 超 1 字节即需切片
    result = plan(20, 99, False, b"x" * 80)
    assert result["status"] == "fragmented"


def test_unfragmented_empty_payload():
    result = plan(20, 20, False, b"")
    assert result == {
        "status": "unfragmented",
        "fragment_count": 1,
        "fragments": [
            {
                "offset": 0,
                "more_fragments": False,
                "payload": "",
                "total_length": 20,
            }
        ],
    }


def test_unfragmented_preserves_original_offset_and_mf():
    # 已有分片不超新 MTU：原样转发，保留原始片偏移与原始 MF；
    # MF=true 的非末片载荷必须 8 字节对齐（这里取 8 字节）
    result = plan(20, 1500, False, b"A" * 8, offset=5, mf=True)
    assert result["status"] == "unfragmented"
    fragment = result["fragments"][0]
    assert fragment["offset"] == 5
    assert fragment["more_fragments"] is True


def test_unfragmented_df_irrelevant():
    # DF=true 但不超 MTU：仍原样返回
    result = plan(20, 1500, True, b"hello")
    assert result["status"] == "unfragmented"


# ---------- 超限且 DF=true：needs_fragmentation ----------


def test_needs_fragmentation_no_payload():
    result = plan(20, 28, True, b"x" * 100)
    assert result == {
        "status": "needs_fragmentation",
        "fragment_count": 0,
        "fragments": [],
    }


def test_needs_fragmentation_boundary():
    # 恰好等于 MTU 时 DF 不触发
    assert plan(20, 120, True, b"x" * 100)["status"] == "unfragmented"
    assert plan(20, 119, True, b"x" * 100)["status"] == "needs_fragmentation"


# ---------- 切片 ----------


def test_fragmented_basic_chunks_and_offsets():
    # MTU 28、首部 20 → 非末片载荷最大 8 字节；20 字节载荷切成 8/8/4
    result = plan(20, 28, False, b"hello-world-ipv4!!!!")
    assert result["status"] == "fragmented"
    assert result["fragment_count"] == 3
    assert result["fragments"] == [
        {"offset": 0, "more_fragments": True,
         "payload": b64(b"hello-wo"), "total_length": 28},
        {"offset": 1, "more_fragments": True,
         "payload": b64(b"rld-ipv4"), "total_length": 28},
        {"offset": 2, "more_fragments": False,
         "payload": b64(b"!!!!"), "total_length": 24},
    ]


def test_fragmented_max_nonfinal_rounds_down_to_8():
    # MTU 30、首部 20 → 预算 10，向下取 8 的倍数得 8
    result = plan(20, 30, False, b"A" * 24)
    sizes = [len(unb64(f["payload"])) for f in result["fragments"]]
    assert sizes == [8, 8, 8]
    # MTU 37、首部 20 → 预算 17，向下取 16
    result = plan(20, 37, False, b"A" * 40)
    sizes = [len(unb64(f["payload"])) for f in result["fragments"]]
    assert sizes == [16, 16, 8]


def test_fragmented_last_chunk_exact_multiple():
    # 载荷恰好是非末片尺寸的整数倍：最后一片仍是满片，但 MF=false
    result = plan(20, 28, False, b"A" * 16)
    assert result["fragment_count"] == 2
    assert [len(unb64(f["payload"])) for f in result["fragments"]] == [8, 8]
    assert [f["more_fragments"] for f in result["fragments"]] == [True, False]


def test_fragmented_offsets_in_8_byte_units():
    result = plan(20, 68, False, b"A" * 200)
    # 预算 48 → 48/48/48/48/8，偏移 0/6/12/18/24
    assert [f["offset"] for f in result["fragments"]] == [0, 6, 12, 18, 24]
    assert [len(unb64(f["payload"])) for f in result["fragments"]] == [
        48, 48, 48, 48, 8,
    ]


def test_fragmented_total_length_never_exceeds_mtu():
    result = plan(60, 100, False, b"A" * 500)
    assert result["status"] == "fragmented"
    for fragment in result["fragments"]:
        assert fragment["total_length"] <= 100
        assert fragment["total_length"] == 60 + len(unb64(fragment["payload"]))


def test_fragmented_non_last_payloads_aligned():
    result = plan(20, 148, False, b"A" * 1000)
    fragments = result["fragments"]
    for fragment in fragments[:-1]:
        assert len(unb64(fragment["payload"])) % OFFSET_UNIT == 0
        assert fragment["more_fragments"] is True
    assert fragments[-1]["more_fragments"] is False


def test_fragmented_concatenation_restores_payload():
    payload = bytes(range(256)) * 3
    result = plan(40, 132, False, payload)
    assert result["status"] == "fragmented"
    assert b"".join(unb64(f["payload"]) for f in result["fragments"]) == payload


# ---------- 对已有分片再次切分 ----------


def test_refragment_offsets_accumulate_original_offset():
    # 已有分片：原始偏移 2（字节 16）、原始 MF=true；非末片载荷必须 8 字节
    # 对齐，取 24 字节切成三个 8 字节子片，偏移叠加为 2/3/4
    result = plan(20, 28, False, b"A" * 24, offset=2, mf=True)
    assert result["status"] == "fragmented"
    assert [f["offset"] for f in result["fragments"]] == [2, 3, 4]
    # 最后子片继承原始 MF=true，其余子片 MF=true
    assert [f["more_fragments"] for f in result["fragments"]] == [
        True, True, True,
    ]


def test_refragment_last_subfragment_inherits_original_mf_false():
    result = plan(20, 28, False, b"A" * 20, offset=7, mf=False)
    assert [f["offset"] for f in result["fragments"]] == [7, 8, 9]
    assert [f["more_fragments"] for f in result["fragments"]] == [
        True, True, False,
    ]


def test_refragment_max_original_offset():
    # 不切片时输出 offset 即原始偏移；原数据报不越 65535 时高位 offset 能
    # 容纳的载荷极小：8189*8 + 0 + 20 = 65532，故 8189 + 空载荷（末片，
    # MF=false）合法；而 offset=8191 即使空载荷（8191*8+20=65548）也越界。
    result = plan(20, 65535, False, b"",
                  offset=8189, mf=False)
    assert result["status"] == "unfragmented"
    assert result["fragments"][0]["offset"] == 8189
    assert result["fragments"][0]["more_fragments"] is False
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 65535, False, b"", offset=FRAGMENT_OFFSET_MAX, mf=False)
    assert exc_info.value.error == "datagram_too_large"


def test_refragment_offsets_never_exceed_8191_when_slicing():
    # 原始偏移 8180、MF=true 的 72 字节对齐载荷、首部 20：结束位置
    # 8180*8 + 72 + 20 = 65532 ≤ 65535；MTU 28 切成 9 个 8 字节子片，
    # 末子片起始偏移 8180+8 = 8188 ≤ 8191。
    result = plan(20, 28, False, b"A" * 72, offset=8180, mf=True)
    assert result["status"] == "fragmented"
    offsets = [f["offset"] for f in result["fragments"]]
    assert offsets == list(range(8180, 8189))
    assert max(offsets) <= FRAGMENT_OFFSET_MAX


# ---------- 非末片 8 字节对齐校验（早于 unfragmented / DF / MTU 分支） ----------


def test_non_aligned_with_original_mf_true_unfragmented():
    # 不超 MTU 也必须拒绝：5 字节载荷不是 8 的倍数
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"hello", offset=5, mf=True)
    assert exc_info.value.error == "non_aligned_fragment"
    assert exc_info.value.limit is None


def test_non_aligned_with_original_mf_true_even_df_true():
    # 校验早于 DF 分支：100 字节载荷（100%8=4）超 MTU 且 DF=true，
    # 仍报 non_aligned_fragment 而非 needs_fragmentation
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 28, True, b"x" * 100, offset=1, mf=True)
    assert exc_info.value.error == "non_aligned_fragment"


def test_non_aligned_takes_precedence_over_datagram_too_large():
    # 同时违反两项时先报 non_aligned_fragment
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"x" * 65525, offset=1, mf=True)
    assert exc_info.value.error == "non_aligned_fragment"


def test_aligned_payload_with_original_mf_true_ok():
    # 8 字节倍数的载荷即使不切片也合法
    result = plan(20, 1500, False, b"A" * 8, offset=5, mf=True)
    assert result["status"] == "unfragmented"
    assert result["fragments"][0]["offset"] == 5
    assert result["fragments"][0]["more_fragments"] is True


def test_non_aligned_allowed_when_original_mf_false():
    # 末片（MF=false）载荷不要求对齐，5 字节载荷原样返回
    result = plan(20, 1500, False, b"hello", offset=5, mf=False)
    assert result["status"] == "unfragmented"
    assert result["fragments"][0]["offset"] == 5
    assert result["fragments"][0]["more_fragments"] is False


# ---------- 原数据报绝对结束位置校验（早于 unfragmented / DF / MTU 分支） ----------


def test_datagram_end_too_large_with_original_offset_unfragmented():
    # 单片本身仅 28 字节、不超 MTU，但原数据报绝对结束位置
    # 8191*8 + 8 + 20 = 65556 > 65535，必须拒绝
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"A" * 8,
             offset=FRAGMENT_OFFSET_MAX, mf=True)
    error = exc_info.value
    assert error.error == "datagram_too_large"
    assert error.limit == IPV4_DATAGRAM_MAX


def test_datagram_end_too_large_checked_before_df():
    # 结束位置越界优先于 DF 判定（DF=true 也报 datagram_too_large）
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 28, True, b"A" * 8, offset=8191, mf=True)
    assert exc_info.value.error == "datagram_too_large"


def test_datagram_end_too_large_checked_before_mtu_too_small():
    # 结束位置越界优先于 mtu_too_small（MTU 同样容不下非末片载荷）
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 20, False, b"A" * 8, offset=8191, mf=True)
    assert exc_info.value.error == "datagram_too_large"


def test_datagram_end_exact_limit_ok():
    # 结束位置恰好 65535：offset=8188、11 字节末片（MF=false），
    # 8188*8 + 11 + 20 = 65535
    result = plan(20, 1500, False, b"A" * 11, offset=8188, mf=False)
    assert result["status"] == "unfragmented"
    assert result["fragments"][0]["offset"] == 8188
    # 再多 1 字节即越界
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"A" * 12, offset=8188, mf=False)
    assert exc_info.value.error == "datagram_too_large"


def test_datagram_end_boundary_with_mf_true():
    # MF=true 的对齐载荷：offset=8188、16 字节 → 8188*8+16+20=65540 越界；
    # offset=8181、64 字节 → 8181*8+64+20=65532 ≤ 65535 合法
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"A" * 16, offset=8188, mf=True)
    assert exc_info.value.error == "datagram_too_large"
    result = plan(20, 28, False, b"A" * 64, offset=8181, mf=True)
    assert result["status"] == "fragmented"
    assert [f["offset"] for f in result["fragments"]] == list(
        range(8181, 8189)
    )
    assert max(f["offset"] for f in result["fragments"]) <= FRAGMENT_OFFSET_MAX


# ---------- 422 类输入错误 ----------


def test_datagram_too_large():
    # 首部 20 + 载荷 65516 = 65536 > 65535
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, False, b"\x00" * 65516)
    error = exc_info.value
    assert error.error == "datagram_too_large"
    assert error.limit == IPV4_DATAGRAM_MAX


def test_datagram_exact_limit_ok():
    # 首部 60 + 载荷 65475 = 65535，恰好不越界
    result = plan(60, 65535, False, b"\x00" * 65475)
    assert result["status"] == "unfragmented"
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(60, 65535, False, b"\x00" * 65476)
    assert exc_info.value.error == "datagram_too_large"


def test_datagram_too_large_checked_before_df():
    # 越界优先于 DF 判定（DF=true 也报 datagram_too_large）
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 1500, True, b"\x00" * 65516)
    assert exc_info.value.error == "datagram_too_large"


def test_mtu_too_small():
    # 首部 20、MTU 27 → 预算 7，容不下一个 8 字节非末片载荷
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 27, False, b"x" * 100)
    error = exc_info.value
    assert error.error == "mtu_too_small"
    assert error.limit == 28  # 所需最小 MTU = 首部 20 + 8


def test_mtu_too_small_boundary():
    # MTU 28 = 首部 20 + 8：恰好容下最小非末片载荷
    result = plan(20, 28, False, b"x" * 100)
    assert result["status"] == "fragmented"
    # MTU 等于首部长度：无任何载荷空间
    with pytest.raises(FragmentationInputError) as exc_info:
        plan(20, 20, False, b"x" * 1)
    assert exc_info.value.error == "mtu_too_small"


def test_mtu_too_small_only_when_fragmenting():
    # MTU 容不下非末片载荷，但数据报本身不超 MTU：原样返回，不报错
    result = plan(60, 65, False, b"x" * 5)
    assert result["status"] == "unfragmented"


def test_mtu_too_small_not_reported_when_df():
    # DF=true 且超限：返回 needs_fragmentation 而非 mtu_too_small
    result = plan(20, 25, True, b"x" * 100)
    assert result["status"] == "needs_fragmentation"


def test_invalid_header_length():
    for header in (HEADER_MIN - 1, HEADER_MAX + 1, 0, -20):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(header, 1500, False, b"")
        assert exc_info.value.error == "invalid_header_length"


def test_invalid_header_length_type():
    for header in (20.0, "20", True, None):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(header, 1500, False, b"")
        assert exc_info.value.error == "invalid_header_length"


def test_invalid_mtu():
    for mtu in (0, -1, MTU_MIN - 1):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(20, mtu, False, b"")
        assert exc_info.value.error == "invalid_mtu"


def test_invalid_mtu_type():
    for mtu in (1500.0, "1500", True, None):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(20, mtu, False, b"")
        assert exc_info.value.error == "invalid_mtu"


def test_invalid_original_offset():
    for offset in (-1, FRAGMENT_OFFSET_MAX + 1):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(20, 1500, False, b"", offset=offset)
        assert exc_info.value.error == "invalid_fragment_offset"


def test_invalid_original_offset_type():
    for offset in (1.5, "0", True, None):
        with pytest.raises(FragmentationInputError) as exc_info:
            plan(20, 1500, False, b"", offset=offset)
        assert exc_info.value.error == "invalid_fragment_offset"


def test_invalid_flag_types():
    for bad in ("true", 1, 0, None):
        with pytest.raises(ValueError):
            plan(20, 1500, bad, b"")
        with pytest.raises(ValueError):
            plan(20, 1500, False, b"", mf=bad)


def test_invalid_payload_type_and_base64():
    with pytest.raises(ValueError):
        plan(20, 1500, False, "not base64!")
    with pytest.raises(ValueError):
        plan(20, 1500, False, 123)
    with pytest.raises(ValueError):
        plan(20, 1500, False, None)


def test_core_accepts_base64_string_payload():
    result = plan(20, 1500, False, "aGVsbG8=")
    assert result["fragments"][0]["payload"] == b64(b"hello")


# ---------- 随机属性：与重组模块往返 ----------


def test_random_fragmentation_roundtrip_property():
    import random

    rng = random.Random(20260919)
    for _ in range(300):
        header = rng.choice([HEADER_MIN, 24, 40, HEADER_MAX])
        max_nonfinal = rng.choice([8, 16, 24, 64, 256, 1400])
        mtu = header + max_nonfinal + rng.randint(0, 7)
        n = rng.randint(0, 3000)
        data = bytes(rng.randrange(256) for _ in range(n))
        result = plan(header, mtu, False, data)
        if header + n <= mtu:
            assert result["status"] == "unfragmented"
            assert unb64(result["fragments"][0]["payload"]) == data
            continue
        assert result["status"] == "fragmented"
        fragments = result["fragments"]
        # 结构不变量：偏移连续、非末片对齐、仅末片 MF=false、总长不超 MTU
        expected_offset = 0
        for i, fragment in enumerate(fragments):
            chunk = unb64(fragment["payload"])
            assert fragment["offset"] == expected_offset
            expected_offset += len(chunk) // OFFSET_UNIT
            assert fragment["total_length"] == header + len(chunk) <= mtu
            if i < len(fragments) - 1:
                assert len(chunk) % OFFSET_UNIT == 0
                assert len(chunk) == max_nonfinal
                assert fragment["more_fragments"] is True
            else:
                assert fragment["more_fragments"] is False
        # 与 /ipv4/reassemble 往返：输出分片可无损重组为原载荷
        reassembled = reassemble_ipv4(
            header,
            [
                (f["offset"], f["more_fragments"], unb64(f["payload"]))
                for f in fragments
            ],
        )
        assert reassembled["status"] == "complete"
        assert unb64(reassembled["payload"]) == data


def test_random_refragmentation_property():
    import random

    rng = random.Random(7)
    for _ in range(200):
        header = rng.choice([HEADER_MIN, 40, HEADER_MAX])
        first_mtu = header + rng.choice([64, 256, 1024])
        n = rng.randint(1, 2000)
        data = bytes(rng.randrange(256) for _ in range(n))
        first = plan(header, first_mtu, False, data)
        # 对每个输出分片以更小的 MTU 再次切分
        second_mtu = header + 8 * rng.randint(1, 4)
        sub_fragments = []
        for fragment in first["fragments"]:
            sub = plan(
                header,
                second_mtu,
                False,
                unb64(fragment["payload"]),
                offset=fragment["offset"],
                mf=fragment["more_fragments"],
            )
            sub_fragments.extend(sub["fragments"])
        # 全部子片拼接还原原载荷，偏移连续，仅最终子片 MF=false
        assert b"".join(unb64(f["payload"]) for f in sub_fragments) == data
        expected_offset = 0
        for i, fragment in enumerate(sub_fragments):
            chunk = unb64(fragment["payload"])
            assert fragment["offset"] == expected_offset
            expected_offset += len(chunk) // OFFSET_UNIT
            assert fragment["more_fragments"] is (i < len(sub_fragments) - 1)
        reassembled = reassemble_ipv4(
            header,
            [
                (f["offset"], f["more_fragments"], unb64(f["payload"]))
                for f in sub_fragments
            ],
        )
        assert reassembled["status"] == "complete"
        assert unb64(reassembled["payload"]) == data
