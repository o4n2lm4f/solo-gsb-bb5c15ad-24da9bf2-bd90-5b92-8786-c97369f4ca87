"""IPv4 数据报分片重组核心逻辑（纯标准库实现，无 Web 依赖）。

输入 IPv4 首部长度（20～60 字节，不含在重组结果内）与同一数据报的
1～500 个分片，每个分片给出：

- ``offset``：片偏移字段值，以 **8 字节** 为单位；
- ``more_fragments``：MF 标志，是否还有后续分片；
- ``payload``：本分片承载的载荷字节。

重组规则：

1. **非末片对齐**：除唯一一个 ``more_fragments=false`` 的末片外，其余
   分片的载荷长度必须是 8 的倍数（IPv4 片偏移以 8 字节计）。
2. **末片定长**：必须**恰好一个**末片；末片按
   ``offset*8 + len(payload)`` 确定总载荷长度。
3. **数据报上限**：总载荷长度加首部长度不能越过 IPv4 数据报 65535 字节
   上限。
4. **按字节区间重组**：每个分片占据半开字节区间
   ``[offset*8, offset*8 + len(payload))``。重叠覆盖处字节必须一致，
   重复且字节一致的覆盖可接受；任一重叠字节冲突即报 ``conflict`` 与
   **首个冲突偏移**（全部分片中最小的不一致字节偏移），优先于缺口结论。
5. 无冲突但相对 ``[0, 总载荷长度)`` 存在缺口时返回 ``incomplete`` 与
   合并后的缺失半开区间；覆盖完整时返回 ``complete``、按偏移排序的
   **贡献分片索引**（至少贡献一个总载荷字节的输入分片序号）与重组后的
   Base64 载荷。
"""
from __future__ import annotations

import base64
import binascii
from typing import Sequence

from .analyzer import merge_intervals, subtract_covered

#: IPv4 首部长度（IHL，单位字节）取值范围
HEADER_MIN = 20
HEADER_MAX = 60

#: 单次请求允许的分片数区间
FRAGMENTS_MIN = 1
FRAGMENTS_MAX = 500

#: IPv4 数据报（首部 + 载荷）总长度上限
IPV4_DATAGRAM_MAX = 65535

#: 片偏移字段以 8 字节为单位
OFFSET_UNIT = 8

#: 重组结论
COMPLETE = "complete"
INCOMPLETE = "incomplete"
CONFLICT = "conflict"

#: 输入错误类型（Web 层映射为 422 detail.error）
ERR_INVALID_HEADER_LENGTH = "invalid_header_length"
ERR_NON_ALIGNED_FRAGMENT = "non_aligned_fragment"
ERR_LAST_FRAGMENT_COUNT = "invalid_last_fragment_count"
ERR_DATAGRAM_TOO_LARGE = "datagram_too_large"


class ReassemblyInputError(ValueError):
    """分片重组输入不合法（Web 层映射为 422）。

    - ``error``：错误类型标识（``non_aligned_fragment`` /
      ``invalid_last_fragment_count`` / ``datagram_too_large`` /
      ``invalid_header_length``）；
    - ``indexes``：相关分片的输入序号（末片数量类问题给出全部末片序号，
      对齐 / 超长类问题给出相关分片；与首部相关时为 ``[]``）；
    - ``limit``：越界错误附带的上限值（总长度类问题为 65535，其余为
      ``None``）。
    """

    def __init__(
        self,
        error: str,
        message: str,
        indexes: list[int] | None = None,
        limit: int | None = None,
    ) -> None:
        self.error = error
        self.indexes = indexes or []
        self.limit = limit
        super().__init__(message)


def decode_payload(value: object) -> bytes:
    """解码标准 Base64 载荷；空串视为空字节串。

    使用 ``validate=True`` 拒绝任何填充错误或非字母表字符（含内嵌空白），
    非法 Base64 抛出 :class:`ValueError`。
    """
    if not isinstance(value, str):
        raise ValueError("payload 必须是 Base64 字符串")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"非法 Base64 payload: {exc}") from exc


def _validate_common(
    header_length: object,
    fragments: Sequence[tuple[object, object, object]],
) -> tuple[int, list[dict]]:
    """校验首部长度与分片列表规模，并逐片解析为字节区间表示。

    返回 ``(header_length, parsed_fragments)``；后者每项为
    ``{"index", "offset_bytes", "more_fragments", "payload"}``。
    """
    if isinstance(header_length, bool) or not isinstance(header_length, int):
        raise ReassemblyInputError(
            ERR_INVALID_HEADER_LENGTH,
            f"header_length 必须是 {HEADER_MIN}～{HEADER_MAX} 的整数: {header_length!r}",
        )
    if not HEADER_MIN <= header_length <= HEADER_MAX:
        raise ReassemblyInputError(
            ERR_INVALID_HEADER_LENGTH,
            f"header_length 必须在 {HEADER_MIN}～{HEADER_MAX} 之间，"
            f"实际 {header_length}",
        )

    if not isinstance(fragments, Sequence) or isinstance(fragments, (str, bytes)):
        raise ValueError("fragments 必须是分片元组列表")
    if not FRAGMENTS_MIN <= len(fragments) <= FRAGMENTS_MAX:
        raise ValueError(
            f"分片数必须在 {FRAGMENTS_MIN}～{FRAGMENTS_MAX} 之间，"
            f"实际 {len(fragments)}"
        )

    parsed: list[dict] = []
    for index, fragment in enumerate(fragments):
        if len(fragment) != 3:
            raise ValueError("每个分片必须是 (offset, more_fragments, payload)")
        raw_offset, more_fragments, payload = fragment
        if isinstance(raw_offset, bool) or not isinstance(raw_offset, int):
            raise ValueError(f"分片 {index} 的 offset 必须是非负整数: {raw_offset!r}")
        if raw_offset < 0:
            raise ValueError(f"分片 {index} 的 offset 不能为负: {raw_offset}")
        if not isinstance(more_fragments, bool):
            raise ValueError(
                f"分片 {index} 的 more_fragments 必须是布尔值: {more_fragments!r}"
            )
        if isinstance(payload, str):
            payload = decode_payload(payload)
        if not isinstance(payload, bytes):
            raise ValueError(f"分片 {index} 的 payload 必须是 Base64 字符串或字节串")
        parsed.append(
            {
                "index": index,
                "offset_bytes": raw_offset * OFFSET_UNIT,
                "more_fragments": more_fragments,
                "payload": payload,
            }
        )
    return header_length, parsed


def reassemble_ipv4(
    header_length: object,
    fragments: Sequence[tuple[object, object, object]],
) -> dict:
    """重组同一 IPv4 数据报的分片，返回可直接 JSON 序列化的结果字典。

    ``fragments`` 每项为 ``(offset, more_fragments, payload)``，其中
    ``offset`` 为 8 字节单位的非负整数、``more_fragments`` 为布尔值、
    ``payload`` 为字节串（独立使用时也接受标准 Base64 字符串）。

    返回结构（按结论三选一，无多余键）：

    - ``{"status": "conflict", "first_conflict_offset": int}``：
      重叠覆盖处存在不一致字节，给出全部分片中最小的冲突字节偏移；
    - ``{"status": "incomplete", "missing_ranges": [[start, end], ...]}``：
      无冲突但 ``[0, 总载荷长度)`` 未被完全覆盖，区间为合并后的**半开**
      ``[start, end)``、按起点升序；
    - ``{"status": "complete", "contributing_fragments": [int, ...],
      "payload": "<Base64>"}``：覆盖完整，贡献分片按
      ``(字节偏移, 输入序号)`` 升序排列，载荷为重组后字节的标准 Base64。

    语义类输入错误抛出 :class:`ReassemblyInputError`（非末片未按 8 字节
    对齐、末片数量不为一、总长度越过 65535、首部长度非法）；非法 Base64、
    offset 类型/负数等抛出 :class:`ValueError`（Web 层通常已在入口拦截）。
    """
    header_length, parsed = _validate_common(header_length, fragments)

    # 末片数量校验必须先于总长度判定（没有末片即无从确定总载荷长度）
    last_indexes = [f["index"] for f in parsed if not f["more_fragments"]]
    if len(last_indexes) != 1:
        raise ReassemblyInputError(
            ERR_LAST_FRAGMENT_COUNT,
            f"必须恰好有一个 more_fragments=false 的末片，实际 {len(last_indexes)} 个",
            indexes=last_indexes,
        )
    last_index = last_indexes[0]

    # 非末片载荷必须按 8 字节对齐；末片（总长度由其锚定）不要求对齐
    for fragment in parsed:
        if fragment["more_fragments"] and len(fragment["payload"]) % OFFSET_UNIT != 0:
            raise ReassemblyInputError(
                ERR_NON_ALIGNED_FRAGMENT,
                f"非末片 {fragment['index']} 的载荷长度 {len(fragment['payload'])} "
                f"不是 {OFFSET_UNIT} 的倍数",
                indexes=[fragment["index"]],
            )

    last_fragment = parsed[last_index]
    total_length = last_fragment["offset_bytes"] + len(last_fragment["payload"])
    if header_length + total_length > IPV4_DATAGRAM_MAX:
        raise ReassemblyInputError(
            ERR_DATAGRAM_TOO_LARGE,
            f"重组数据报长度 {header_length + total_length} 越过 IPv4 "
            f"{IPV4_DATAGRAM_MAX} 字节上限",
            indexes=[last_index],
            limit=IPV4_DATAGRAM_MAX,
        )

    # 按字节重组：owner[pos] 为首个写入该字节的分片序号；重复且字节一致的
    # 覆盖允许，字节冲突时记录全部分片中最小的不一致偏移（越出末片锚定总
    # 长度的字节不参与数据报重组）。
    buffer = bytearray(total_length)
    owner: list[int | None] = [None] * total_length
    first_conflict: int | None = None
    for fragment in parsed:
        start = fragment["offset_bytes"]
        if start >= total_length:
            continue
        for rel, byte in enumerate(fragment["payload"]):
            pos = start + rel
            if pos >= total_length:
                break
            existing = owner[pos]
            if existing is None:
                owner[pos] = fragment["index"]
                buffer[pos] = byte
            elif buffer[pos] != byte and (
                first_conflict is None or pos < first_conflict
            ):
                first_conflict = pos

    if first_conflict is not None:
        return {"status": CONFLICT, "first_conflict_offset": first_conflict}

    # 已覆盖区间（半开）归并后求其在 [0, total_length) 内的补集
    def clamped_end(fragment: dict) -> int:
        return min(
            fragment["offset_bytes"] + len(fragment["payload"]), total_length
        )

    filled = [
        (fragment["offset_bytes"], clamped_end(fragment) - 1)
        for fragment in parsed
        if fragment["offset_bytes"] < total_length
        and clamped_end(fragment) > fragment["offset_bytes"]
    ]
    missing_closed = (
        subtract_covered((0, total_length - 1), merge_intervals(filled))
        if total_length
        else []
    )
    missing_ranges = [[start, end + 1] for start, end in missing_closed]
    if missing_ranges:
        return {"status": INCOMPLETE, "missing_ranges": missing_ranges}

    contributing = sorted(
        {
            fragment["index"]
            for fragment in parsed
            if fragment["offset_bytes"] < total_length
            and clamped_end(fragment) > fragment["offset_bytes"]
        },
        key=lambda index: (parsed[index]["offset_bytes"], index),
    )
    return {
        "status": COMPLETE,
        "contributing_fragments": contributing,
        "payload": base64.b64encode(bytes(buffer)).decode("ascii"),
    }
