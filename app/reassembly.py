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
   ``[offset*8, offset*8 + len(payload))``。将各片裁剪到末片锚定的
   ``[0, 总载荷长度)`` 后按区间排序，用事件扫描 + 区间/切片运算检测
   重叠，既不为每个分片逐字节遍历，也不建立与总载荷等长的 owner 表。
   重叠覆盖处字节必须一致，重复且字节一致的覆盖可接受；任一重叠字节
   冲突即报 ``conflict`` 与**首个冲突偏移**（全部分片中最小的不一致字节
   偏移，与输入顺序无关），优先于缺口结论。
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


def _clamped_fragments(parsed: list[dict], total_length: int) -> list[dict]:
    """把各分片裁剪到末片锚定的 ``[0, total_length)`` 半开区间。

    返回按 ``(起点, 输入序号)`` 升序、仅含至少一个锚定字节的分片列表；
    每项为 ``{"index", "start", "end", "slice"}``，``slice`` 是该片落在
    锚定区间内的载荷视图（零拷贝 memoryview），空载荷与完全越界片丢弃。
    """
    items: list[dict] = []
    for fragment in parsed:
        start = fragment["offset_bytes"]
        if start >= total_length:
            continue  # 整片落在锚点之外
        end = min(start + len(fragment["payload"]), total_length)
        if end <= start:
            continue  # 空载荷片不贡献任何字节
        items.append(
            {
                "index": fragment["index"],
                "start": start,
                "end": end,
                "slice": memoryview(fragment["payload"])[: end - start],
            }
        )
    items.sort(key=lambda item: (item["start"], item["index"]))
    return items


def _first_mismatch(left: memoryview, right: memoryview) -> int | None:
    """两段等长字节的首个不一致相对偏移；完全一致时返回 ``None``。

    用整体切片比较 + 二分定位，避免逐字节 Python 循环：一致时只有一次
    原生 memcmp；不一致时二分，复制量不超过 ``2 × len``。
    """
    length = len(left)
    if length == 0 or left == right:
        return None
    lo, hi = 0, length
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if left[lo:mid] == right[lo:mid]:
            lo = mid
        else:
            hi = mid
    return lo


def _first_conflict_offset(items: list[dict]) -> int | None:
    """以区间事件扫描求全部分片间最小的不一致字节偏移。

    按起点排序后，用 ``(position, kind, index)`` 事件维护当前活跃分片集合
    （同位置先出后入——半开区间端点相接不算重叠），逐段扫描活跃集不变的
    原子段。任一段内：与该段**输入序号最小**分片（即原逐字节 owner 语义
    下的写入方）逐对比较载荷切片；若第三方与写入方一致则二者一致，若冲突
    则必与写入方冲突，故只对写入方比较即可覆盖所有分片对。原子段按位置
    升序处理，当前段得到的最小不一致就是全局最小值（与输入顺序无关）。
    """
    by_index = {item["index"]: item for item in items}
    events: list[tuple[int, int, int]] = []
    for item in items:
        events.append((item["end"], 0, item["index"]))    # 出事件
        events.append((item["start"], 1, item["index"]))  # 入事件
    events.sort()

    active: dict[int, dict] = {}
    cursor: int | None = None
    ei = 0
    n_events = len(events)
    while ei < n_events:
        position = events[ei][0]
        # 处理 [cursor, position) 这一活跃集不变的原子段
        if cursor is not None and position > cursor and active:
            ref_index = min(active)
            reference = active[ref_index]
            rel = cursor - reference["start"]
            span = position - cursor
            segment_min: int | None = None
            for item in active.values():
                if item["index"] == ref_index:
                    continue
                other_rel = cursor - item["start"]
                mismatch = _first_mismatch(
                    item["slice"][other_rel:other_rel + span],
                    reference["slice"][rel:rel + span],
                )
                if mismatch is not None:
                    offset = cursor + mismatch
                    if segment_min is None or offset < segment_min:
                        segment_min = offset
            if segment_min is not None:
                return segment_min  # 更早的段已确认无冲突，此即全局最小
        # 应用该位置的全部事件（半开区间：先出后入，端点相接不算重叠）
        cursor = position
        while ei < n_events and events[ei][0] == position:
            _, kind, index = events[ei]
            if kind == 0:
                del active[index]
            else:
                active[index] = by_index[index]
            ei += 1
    return None


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

    # 将各片裁剪到末片锚定的 [0, total_length)（越界部分不参与数据报
    # 重组），并按 (起点, 输入序号) 排序；后续全部基于区间/切片运算。
    items = _clamped_fragments(parsed, total_length)

    # 冲突优先于缺口：事件扫描所有重叠原子段，按切片比较求全局最小冲突偏移
    first_conflict = _first_conflict_offset(items)
    if first_conflict is not None:
        return {"status": CONFLICT, "first_conflict_offset": first_conflict}

    # 已覆盖区间（闭区间表示）归并后求其在 [0, total_length) 内的补集
    filled = [(item["start"], item["end"] - 1) for item in items]
    missing_closed = (
        subtract_covered((0, total_length - 1), merge_intervals(filled))
        if total_length
        else []
    )
    missing_ranges = [[start, end + 1] for start, end in missing_closed]
    if missing_ranges:
        return {"status": INCOMPLETE, "missing_ranges": missing_ranges}

    # 覆盖完整：无冲突时重叠字节处处一致，按 (起点, 输入序号) 顺序逐片用
    # 切片赋值拼装即可（与原“首个写入分片”逐字节 owner 语义等价）。
    buffer = bytearray(total_length)
    for item in items:
        buffer[item["start"]:item["end"]] = item["slice"]
    contributing = [item["index"] for item in items]
    return {
        "status": COMPLETE,
        "contributing_fragments": contributing,
        "payload": base64.b64encode(buffer).decode("ascii"),
    }
