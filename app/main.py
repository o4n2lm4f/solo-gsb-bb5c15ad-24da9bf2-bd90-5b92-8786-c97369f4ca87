"""FastAPI 应用：IPv4 CIDR 遮蔽分析、规则集等价性比较、包含层级分析、路由解析、有状态防火墙模拟、分片重组与分片规划 API。"""
from __future__ import annotations

from typing import Literal

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field, StrictInt, StrictStr, field_validator, model_validator

from .analyzer import (
    CIDR_DIFF_MAX_ENTRIES,
    HIERARCHY_MAX_ENTRIES,
    CidrDiffInputError,
    HierarchyInputError,
    InvalidCIDRError,
    analyze_rules,
    build_cidr_hierarchy,
    compare_rule_sets,
    diff_cidr_lists,
    explain_query,
    parse_cidr_v4,
)
from .firewall import (
    FIREWALL_EVENTS_MAX,
    FIREWALL_RULES_MAX,
    MAX_SESSIONS_MAX,
    SESSION_TIMEOUT_MAX,
    OutOfOrderTimestampsError,
    OverlappingSessionError,
    simulate_firewall,
)
from .fragmentation import (
    FRAGMENT_OFFSET_MAX,
    MTU_MIN,
    FragmentationInputError,
    plan_ipv4_fragmentation,
)
from .reassembly import (
    FRAGMENTS_MAX,
    HEADER_MAX,
    HEADER_MIN,
    ReassemblyInputError,
    decode_payload,
    reassemble_ipv4,
)
from .router import (
    FAILED_NEXT_HOPS_MAX,
    METRIC_MAX,
    ROUTES_MAX,
    TARGETS_MAX,
    DuplicateNextHopsError,
    DuplicateTargetsError,
    InvalidIPv4AddressError,
    audit_routes,
    failover_routes,
    parse_address_v4,
    resolve_routes,
)

app = FastAPI(
    title="IPv4 遮蔽分析 API",
    description=(
        "接收有序的 allow/deny CIDR 规则，计算每条规则未被此前规则覆盖的"
        "地址集合，按 **全生效 (full)** / **部分遮蔽 (partial)** / "
        "**完全遮蔽 (shadowed)** 分类，并将剩余集合无损压缩为数量最少的 CIDR；"
        "也可通过 /compare 比较两组规则在整个 IPv4 空间上的最终判定是否等价，"
        "通过 /explain 解释一段地址空间由哪条规则或默认动作最终裁决，"
        "通过 /cidrs/hierarchy 分析一组 CIDR 的包含层级（森林）与独占地址，"
        "通过 /cidrs/diff 比对两份带唯一 id 的网段清单的新增、删除、CIDR "
        "变更与直接父节点变化（并标记规范化后网段相同但 id 不同的替换候选），"
        "通过 /routes/resolve 对目标地址做最长前缀匹配、最低 metric 的"
        "等价多路径（ECMP）路由解析，通过 /routes/failover 模拟一组下一跳"
        "失效后的路由切换影响（before/after/impact），或通过 /routes/audit "
        "把最长前缀优先、同前缀最低 metric 与 ECMP 语义应用到整个 IPv4 空间，"
        "计算每条路由实际负责的地址集合（active/partial/shadowed、生效地址数"
        "与无损最少 CIDR）。"
        "通过 /firewall/simulate 模拟有状态防火墙：有序五元组规则按首条匹配"
        "裁决，首个正向 allow 建立五元组会话，存活期内反向包 stateful 放行，"
        "超时后重新走规则匹配；会话表容量固定，建会话遇容量满时按 "
        "last_seen 淘汰最早的存活会话。"
        "通过 /ipv4/reassemble 对同一 IPv4 数据报的 1～500 个分片按字节"
        "区间重组：非末片载荷按 8 字节对齐，唯一末片锚定总载荷长度，"
        "越过 65535 字节数据报上限报错；重复一致覆盖可接受，重叠字节冲突"
        "返回首个冲突偏移，无冲突但有缺口返回合并后的缺失半开区间，覆盖"
        "完整时返回贡献分片索引与重组后的 Base64 载荷。"
        "通过 /ipv4/fragment 做反向的分片规划：给定 Base64 载荷、20～60 "
        "字节首部长度、MTU 与 DF 标志（可选原始片偏移与原始 MF），"
        "original_more_fragments=true 时载荷必须 8 字节对齐，并按"
        " original_offset*8 + 载荷长度 + 首部长度校验原数据报不越 65535；"
        "数据报不超 MTU 时原样返回一个分片，超限且 DF=true 时返回 "
        "needs_fragmentation（不输出载荷），其余情况按不超过 MTU 的最大 "
        "8 字节倍数切片，子片偏移叠加原始片偏移、末子片继承原始 MF。"
    ),
    version="1.11.0",
)


class Rule(BaseModel):
    """单条规则：动作 + IPv4 CIDR。"""

    action: Literal["allow", "deny"] = Field(
        ..., description="动作，仅允许 allow 或 deny（大小写不敏感）"
    )
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AnalyzeRequest(BaseModel):
    """分析请求：有序规则列表，至少 1 条。"""

    rules: list[Rule] = Field(..., min_length=1, description="有序规则列表（按序处理）")


class RuleResult(BaseModel):
    index: int = Field(..., description="规则在输入中的序号（从 0 开始）")
    action: Literal["allow", "deny"]
    cidr: str = Field(..., description="规范化后的规则 CIDR")
    status: Literal["full", "partial", "shadowed"]
    status_label: str = Field(..., description="状态中文说明")
    total_addresses: int
    covered_addresses: int = Field(..., description="被此前规则遮蔽的地址数")
    effective_addresses: int = Field(..., description="本规则实际生效的地址数")
    effective_cidrs: list[str] = Field(
        ..., description="生效地址集合无损压缩后的最少 CIDR 列表（空表示完全遮蔽）"
    )


class Summary(BaseModel):
    full: int
    partial: int
    shadowed: int
    effective_allow_addresses: int = Field(..., description="汇总生效的 allow 地址数")
    effective_deny_addresses: int = Field(..., description="汇总生效的 deny 地址数")


class AnalyzeResponse(BaseModel):
    rule_count: int
    rules: list[RuleResult]
    summary: Summary


class RuleSet(BaseModel):
    """一侧规则集：有序规则列表 + 未命中时的默认动作。"""

    rules: list[Rule] = Field(
        default_factory=list, description="有序规则列表（按序处理），可为空"
    )
    default_action: Literal["allow", "deny"] = Field(
        ...,
        description="未命中任何规则时的默认动作（大小写不敏感）",
    )

    @field_validator("default_action", mode="before")
    @classmethod
    def normalize_default_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class CompareRequest(BaseModel):
    """比较请求：左右两侧规则集及其默认动作。"""

    left: RuleSet
    right: RuleSet


class DifferenceGroup(BaseModel):
    left_action: Literal["allow", "deny"]
    right_action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该判定组合覆盖的地址数")
    cidrs: list[str] = Field(
        ...,
        description="该组地址集合无损压缩后的最少 CIDR 列表",
    )


class CompareResponse(BaseModel):
    equivalent: bool = Field(
        ..., description="两侧在整个 IPv4 空间上的最终判定是否完全一致"
    )
    differences: list[DifferenceGroup] = Field(
        ...,
        description="判定不同的地址分组（按 left_action/right_action）；等价时为空",
    )


class ExplainRequest(RuleSet):
    """解释请求：有序规则列表 + 默认动作 + 单个待解释的 query CIDR。"""

    query: str = Field(
        ...,
        description="待解释的 IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AttributionItem(BaseModel):
    source: Literal["rule", "default"] = Field(
        ..., description="裁决来源：rule 表示命中规则，default 表示走默认动作"
    )
    rule_index: int | None = Field(
        ..., description="命中规则在输入中的序号（从 0 开始）；默认项为 null"
    )
    action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该项覆盖的地址数")
    cidrs: list[str] = Field(
        ..., description="该项地址集合无损压缩后的最少 CIDR 列表"
    )


class ExplainResponse(BaseModel):
    query: str = Field(..., description="规范化后的 query CIDR")
    total_addresses: int = Field(..., description="query 覆盖的地址总数")
    attribution: list[AttributionItem] = Field(
        ...,
        description=(
            "归因列表：按规则索引升序、默认项最后；所有项不重不漏覆盖 query"
        ),
    )


# ---------- /cidrs/hierarchy ----------

#: 层级条目 id：非空字符串或整数（bool 明确拒绝，不做隐式类型转换）
EntryId = StrictStr | StrictInt


class CidrEntry(BaseModel):
    """单个层级条目：唯一 id + 严格 IPv4 CIDR。"""

    id: EntryId = Field(..., description="条目标识，字符串或整数，全请求内唯一")
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: object) -> object:
        # 防御性校验：pydantic StrictStr|StrictInt 已拦截 bool/float 等，
        # 这里兜底拒绝空白字符串（独立使用 analyzer 时同样由核心层校验）
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("id 仅支持字符串或整数")
        if isinstance(value, str) and not value.strip():
            raise ValueError("id 不能为空字符串")
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class HierarchyRequest(BaseModel):
    """层级分析请求：1～500 个含 id 与 cidr 的条目。"""

    entries: list[CidrEntry] = Field(
        ...,
        min_length=1,
        max_length=HIERARCHY_MAX_ENTRIES,
        description="含 id 与 cidr 的条目列表（1～500 个）",
    )


class HierarchyNode(BaseModel):
    id: EntryId = Field(..., description="条目 id")
    cidr: str = Field(..., description="规范化后的条目 CIDR")
    parent_id: EntryId | None = Field(
        ..., description="唯一父节点 id（前缀最长的严格超网）；根节点为 null"
    )
    total_addresses: int = Field(..., description="本网段覆盖的地址总数")
    exclusive_address_count: int = Field(
        ...,
        description="自身范围扣除全部直接子节点并集后的独占地址数",
    )
    exclusive_cidrs: list[str] = Field(
        ...,
        description="独占地址集合无损压缩后的最少 CIDR 列表（无子节点时为本网段自身）",
    )
    children: list["HierarchyNode"] = Field(
        ...,
        description="直接子节点列表，按网络地址、前缀长度、输入顺序稳定排序",
    )


class HierarchyResponse(BaseModel):
    node_count: int = Field(..., description="节点（条目）总数")
    root_count: int = Field(..., description="根节点数量")
    roots: list[HierarchyNode] = Field(
        ...,
        description="根节点组成的森林，按网络地址、前缀长度、输入顺序稳定排序",
    )


HierarchyNode.model_rebuild()


# ---------- /cidrs/diff ----------


class CidrDiffRequest(BaseModel):
    """网段清单差异请求：before / after 各为 0～500 个含唯一 id 与 cidr 的条目。"""

    before: list[CidrEntry] = Field(
        ...,
        max_length=CIDR_DIFF_MAX_ENTRIES,
        description="变更前的条目列表（允许为空 []）；id 与规范化网段在本侧内必须唯一",
    )
    after: list[CidrEntry] = Field(
        ...,
        max_length=CIDR_DIFF_MAX_ENTRIES,
        description="变更后的条目列表（允许为空 []）；id 与规范化网段在本侧内必须唯一",
    )


class CidrReplacementCandidate(BaseModel):
    before_id: EntryId = Field(..., description="before 侧条目 id")
    after_id: EntryId = Field(..., description="after 侧条目 id")
    cidr: str = Field(..., description="两侧规范化后相同的网段")
    address_count: int = Field(..., description="该网段的地址数")


class CidrChangeItem(BaseModel):
    id: EntryId = Field(..., description="条目 id（before/after 两侧或其中一侧）")
    change: Literal["added", "removed", "cidr_changed", "unchanged"] = Field(
        ...,
        description=(
            "变化分类：added 仅 after 存在；removed 仅 before 存在；"
            "cidr_changed 同 id 但规范化网段不同；unchanged 同 id 且网段相同"
            "（parent_changed 可能同时为 true）"
        ),
    )
    before_cidr: str | None = Field(
        ..., description="before 侧规范化网段；新增项为 null"
    )
    after_cidr: str | None = Field(
        ..., description="after 侧规范化网段；删除项为 null"
    )
    before_parent_id: EntryId | None = Field(
        ...,
        description="before 侧的直接父节点 id（前缀最长的严格超网，root 为 null）；新增项为 null",
    )
    after_parent_id: EntryId | None = Field(
        ...,
        description="after 侧的直接父节点 id（前缀最长的严格超网，root 为 null）；删除项为 null",
    )
    parent_changed: bool | None = Field(
        ...,
        description=(
            "同 id 匹配项的直接父节点是否发生变化（仅在本侧清单内独立择父）；"
            "新增 / 删除项为 null"
        ),
    )
    affected_address_count: int = Field(
        ...,
        description=(
            "受影响地址数：CIDR 变更取旧、新网段的对称差地址数；"
            "新增 / 删除取该网段地址数；其余为 0"
        ),
    )


class CidrDiffSummary(BaseModel):
    added: int = Field(..., description="新增条目数")
    removed: int = Field(..., description="删除条目数")
    cidr_changed: int = Field(..., description="同 id 但 CIDR 变更的条目数")
    unchanged: int = Field(
        ...,
        description="同 id 且网段相同的条目数（其中部分可能 parent_changed=true）",
    )
    parent_changed: int = Field(
        ...,
        description="同 id 匹配且直接父节点发生变化的条目数（可与 cidr_changed 重叠）"
    )
    replacement_candidate_count: int = Field(
        ..., description="替换候选（网段相同但 id 不同）的配对数"
    )
    affected_address_count: int = Field(
        ..., description="全部新增、删除与 CIDR 变更条目的受影响地址数之和"
    )


class CidrDiffResponse(BaseModel):
    before_count: int = Field(..., description="before 侧条目数")
    after_count: int = Field(..., description="after 侧条目数")
    changes: list[CidrChangeItem] = Field(
        ...,
        description="逐条变化结果：保持 before 顺序（删除 / 匹配项），新增项按 after 顺序追加",
    )
    replacement_candidates: list[CidrReplacementCandidate] = Field(
        ...,
        description="规范化后网段相同但 id 不同的配对（替换候选），按 before 侧位置排序",
    )
    summary: CidrDiffSummary


# ---------- /routes/resolve ----------


class RouteEntry(BaseModel):
    """单条静态路由：严格 IPv4 CIDR + 严格 IPv4 下一跳 + metric。"""

    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )
    next_hop: str = Field(
        ..., description="下一跳 IPv4 地址（纯地址，禁止 CIDR 写法与 IPv6）"
    )
    metric: int = Field(
        ..., ge=0, le=METRIC_MAX, strict=True, description="路由度量，0～65535 的整数"
    )

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]

    @field_validator("next_hop")
    @classmethod
    def validate_next_hop(cls, value: str) -> str:
        # 校验并规范化；非法地址 / CIDR 写法 / IPv6 抛出 ValueError -> 422
        return parse_address_v4(value)[1]


class RouteResolveRequest(BaseModel):
    """路由解析请求：0～1000 条路由 + 1～500 个唯一目标地址。"""

    routes: list[RouteEntry] = Field(
        ..., max_length=ROUTES_MAX, description="静态路由列表，按数组顺序作为去重/ECMP 次序"
    )
    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=TARGETS_MAX,
        description="目标 IPv4 地址列表（纯地址），全请求内唯一；响应保持该顺序",
    )

    @field_validator("targets", mode="before")
    @classmethod
    def validate_targets(cls, value: object) -> object:
        # 逐地址严格校验并规范化；非法地址 / CIDR 写法 / IPv6 -> 422
        if isinstance(value, list):
            return [parse_address_v4(item)[1] for item in value]
        return value


class ResolvedTarget(BaseModel):
    target: str = Field(..., description="规范化后的目标 IPv4 地址")
    status: Literal["reachable", "unreachable"]
    matched_cidr: str | None = Field(
        ..., description="命中的最长前缀 CIDR（ECMP 路由共同网段）；不可达为 null"
    )
    metric: int | None = Field(
        ..., description="命中路由的最低 metric；不可达为 null"
    )
    next_hops: list[str] = Field(
        ...,
        description="等价下一跳列表，按 routes 输入顺序去重；不可达为空",
    )


class NextHopCount(BaseModel):
    next_hop: str = Field(..., description="规范化后的下一跳 IPv4 地址")
    target_count: int = Field(
        ..., description="该下一跳命中的目标数（同一 ECMP 结果的各下一跳分别计一次）"
    )


class RouteResolveSummary(BaseModel):
    reachable_count: int = Field(..., description="可达目标数")
    unreachable_count: int = Field(..., description="不可达目标数")
    next_hop_counts: list[NextHopCount] = Field(
        ...,
        description=(
            "每个 next_hop 命中的目标数，按 next_hop 在 routes 中的首次出现"
            "位置排序；仅列实际命中过的下一跳"
        ),
    )


class RouteResolveResponse(BaseModel):
    route_count: int = Field(..., description="请求中的路由条数")
    target_count: int = Field(..., description="请求中的目标数")
    results: list[ResolvedTarget] = Field(
        ..., description="逐目标解析结果，严格保持 targets 输入顺序"
    )
    summary: RouteResolveSummary


# ---------- /routes/failover ----------


class RouteFailoverRequest(RouteResolveRequest):
    """故障切换请求：在 /routes/resolve 请求基础上增加唯一失败下一跳列表。"""

    failed_next_hops: list[str] = Field(
        ...,
        max_length=FAILED_NEXT_HOPS_MAX,
        description=(
            "失效的下一跳 IPv4 地址列表（纯地址），全请求内唯一，允许为空；"
            "这些下一跳对应的全部路由将被移除后重新解析"
        ),
    )

    @field_validator("failed_next_hops", mode="before")
    @classmethod
    def validate_failed_next_hops(cls, value: object) -> object:
        # 逐地址严格校验并规范化；非法地址 / CIDR 写法 / IPv6 -> 422
        if isinstance(value, list):
            return [parse_address_v4(item)[1] for item in value]
        return value


class RouteResolution(BaseModel):
    """单次路由解析结果（before / after 共用，不含 target）。"""

    status: Literal["reachable", "unreachable"]
    matched_cidr: str | None = Field(
        ..., description="命中的最长前缀 CIDR（ECMP 路由共同网段）；不可达为 null"
    )
    metric: int | None = Field(
        ..., description="命中路由的最低 metric；不可达为 null"
    )
    next_hops: list[str] = Field(
        ...,
        description="等价下一跳列表，按 routes 输入顺序去重；不可达为空",
    )


class RouteFailoverResult(BaseModel):
    target: str = Field(..., description="规范化后的目标 IPv4 地址")
    before: RouteResolution = Field(..., description="故障前（完整路由表）的解析结果")
    after: RouteResolution = Field(
        ..., description="移除失败下一跳对应全部路由后的重新解析结果"
    )
    impact: Literal["unchanged", "ecmp_reduced", "rerouted", "unreachable"] = Field(
        ...,
        description=(
            "影响分类：unchanged 结果不变；ecmp_reduced 网段与 metric 不变、"
            "等价下一跳减少；rerouted 仍可达但网段或 metric 改变；"
            "unreachable 故障后不可达"
        ),
    )


class RouteFailoverSummary(BaseModel):
    unchanged: int = Field(..., description="解析结果完全不变的目标数（含两侧均不可达）")
    ecmp_reduced: int = Field(
        ..., description="命中网段与 metric 不变、等价下一跳减少的目标数"
    )
    rerouted: int = Field(
        ..., description="仍可达但命中网段或 metric 改变的目标数"
    )
    unreachable: int = Field(..., description="原本可达、故障后不可达的目标数")


class RouteFailoverResponse(BaseModel):
    route_count: int = Field(..., description="请求中的路由条数")
    target_count: int = Field(..., description="请求中的目标数")
    failed_next_hops: list[str] = Field(
        ..., description="规范化后的失败下一跳列表，保持输入顺序"
    )
    results: list[RouteFailoverResult] = Field(
        ..., description="逐目标故障切换结果，严格保持 targets 输入顺序"
    )
    summary: RouteFailoverSummary


# ---------- /routes/audit ----------


class RouteAuditRequest(BaseModel):
    """路由表空间审计请求：0～1000 条有序路由。"""

    routes: list[RouteEntry] = Field(
        ...,
        max_length=ROUTES_MAX,
        description=(
            "有序静态路由列表，按数组顺序作为去重/ECMP 次序；允许为空 []"
            "（此时整个 IPv4 空间均无路由覆盖）"
        ),
    )


class RouteAuditResult(BaseModel):
    index: int = Field(..., description="路由在输入中的序号（从 0 开始）")
    cidr: str = Field(..., description="规范化后的路由 CIDR")
    next_hop: str = Field(..., description="规范化后的下一跳 IPv4 地址")
    metric: int = Field(..., description="路由度量，0～65535 的整数")
    status: Literal["active", "partial", "shadowed"] = Field(
        ...,
        description=(
            "active：本路由是其网段的最低 metric 组且网段未被任何更长前缀"
            "覆盖；partial：属最低 metric 组但网段部分被更长前缀覆盖；"
            "shadowed：生效集合为空（metric 被同网段更低 metric 路由淘汰，"
            "或网段被更长前缀完全覆盖）"
        ),
    )
    status_label: str = Field(..., description="状态中文说明")
    total_addresses: int = Field(..., description="本路由网段覆盖的地址总数")
    effective_addresses: int = Field(
        ...,
        description=(
            "本路由实际负责的地址数；同网段同最低 metric 的并行路由"
            "（ECMP 组）该值相同"
        ),
    )
    effective_cidrs: list[str] = Field(
        ...,
        description=(
            "实际负责地址集合无损压缩后的最少 CIDR 列表（shadowed 为空）；"
            "同一 ECMP 组的并行路由内容完全相同"
        ),
    )
    ecmp_next_hops: list[str] = Field(
        ...,
        description=(
            "所属网段最低 metric 组的等价下一跳，按 routes 输入顺序去重；"
            "高 metric 路由同样返回该组下一跳，便于定位遮蔽来源"
        ),
    )


class RouteAuditSummary(BaseModel):
    active: int = Field(..., description="全部生效的路由条数")
    partial: int = Field(..., description="部分生效的路由条数")
    shadowed: int = Field(..., description="完全遮蔽的路由条数")
    routed_address_count: int = Field(
        ..., description="整张路由表实际承载（被至少一条最低 metric 最长前缀路由覆盖）的地址数"
    )
    unreachable_address_count: int = Field(
        ..., description="未被任何路由覆盖的地址数；与 routed_address_count 之和恒为 2^32"
    )
    effective_address_sum: int = Field(
        ...,
        description=(
            "逐条路由 effective_addresses 之和；同一 ECMP 组的并行路由"
            "各计一次，故可大于 routed_address_count"
        ),
    )


class RouteAuditResponse(BaseModel):
    route_count: int = Field(..., description="请求中的路由条数")
    results: list[RouteAuditResult] = Field(
        ..., description="逐条路由审计结果，严格保持 routes 输入顺序"
    )
    summary: RouteAuditSummary


# ---------- /firewall/simulate ----------


class FirewallRule(BaseModel):
    """单条有序防火墙规则：动作 + 源/目的 CIDR + 协议 + 目的端口范围。"""

    action: Literal["allow", "deny"] = Field(
        ..., description="动作，仅允许 allow 或 deny（大小写不敏感）"
    )
    src_cidr: str = Field(
        ...,
        description="源 IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )
    dst_cidr: str = Field(
        ...,
        description="目的 IPv4 CIDR，如 192.168.1.0/24；纯 IP 按 /32 处理；禁止 IPv6",
    )
    protocol: Literal["tcp", "udp", "icmp"] = Field(
        ..., description="传输层协议（大小写不敏感）；icmp 不允许端口"
    )
    port_start: int | None = Field(
        ..., ge=0, le=65535, strict=True,
        description="目的端口范围起点（含），0～65535；tcp/udp 必填，icmp 必须为 null",
    )
    port_end: int | None = Field(
        ..., ge=0, le=65535, strict=True,
        description="目的端口范围终点（含），0～65535，且不小于 port_start；icmp 必须为 null",
    )

    @field_validator("action", "protocol", mode="before")
    @classmethod
    def normalize_lower(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("src_cidr")
    @classmethod
    def validate_src_cidr(cls, value: str) -> str:
        return parse_cidr_v4(value)[2]

    @field_validator("dst_cidr")
    @classmethod
    def validate_dst_cidr(cls, value: str) -> str:
        return parse_cidr_v4(value)[2]

    @model_validator(mode="after")
    def validate_ports(self) -> "FirewallRule":
        if self.protocol == "icmp":
            if self.port_start is not None or self.port_end is not None:
                raise ValueError("icmp 规则不能指定端口范围，port_start/port_end 必须为 null")
        elif self.port_start is None or self.port_end is None:
            raise ValueError("tcp/udp 规则必须同时提供 port_start 与 port_end")
        elif self.port_start > self.port_end:
            raise ValueError(
                f"端口范围起点不能大于终点: {self.port_start} > {self.port_end}"
            )
        return self


class FirewallEvent(BaseModel):
    """单个数据包事件（时间戳必须在事件序列内严格递增）。"""

    timestamp: int = Field(
        ..., ge=0, strict=True,
        description="非负整数事件时间（秒）；整个 events 序列必须严格递增",
    )
    src_ip: str = Field(..., description="源 IPv4 地址（纯地址，禁止 CIDR 写法与 IPv6）")
    dst_ip: str = Field(..., description="目的 IPv4 地址（纯地址，禁止 CIDR 写法与 IPv6）")
    protocol: Literal["tcp", "udp", "icmp"] = Field(
        ..., description="传输层协议（大小写不敏感）；icmp 不允许端口"
    )
    src_port: int | None = Field(
        ..., ge=0, le=65535, strict=True,
        description="源端口，0～65535；tcp/udp 必填，icmp 必须为 null",
    )
    dst_port: int | None = Field(
        ..., ge=0, le=65535, strict=True,
        description="目的端口，0～65535；tcp/udp 必填，icmp 必须为 null",
    )
    direction: Literal["forward", "reverse"] = Field(
        ..., description="包方向（大小写不敏感）：forward 正向、reverse 反向"
    )

    @field_validator("protocol", "direction", mode="before")
    @classmethod
    def normalize_lower(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, value: str) -> str:
        return parse_address_v4(value)[1]

    @field_validator("dst_ip")
    @classmethod
    def validate_dst_ip(cls, value: str) -> str:
        return parse_address_v4(value)[1]

    @model_validator(mode="after")
    def validate_ports(self) -> "FirewallEvent":
        if self.protocol == "icmp":
            if self.src_port is not None or self.dst_port is not None:
                raise ValueError("icmp 事件不能携带端口，src_port/dst_port 必须为 null")
        elif self.src_port is None or self.dst_port is None:
            raise ValueError("tcp/udp 事件必须同时提供 src_port 与 dst_port")
        return self


class FirewallSimulateRequest(BaseModel):
    """有状态防火墙模拟请求。"""

    rules: list[FirewallRule] = Field(
        ...,
        max_length=FIREWALL_RULES_MAX,
        description="有序规则列表（按数组顺序首条命中生效），允许为空 []",
    )
    events: list[FirewallEvent] = Field(
        ...,
        min_length=1,
        max_length=FIREWALL_EVENTS_MAX,
        description="按时间严格递增的数据包事件列表（1～2000 个）",
    )
    default_action: Literal["allow", "deny"] = Field(
        ..., description="未命中任何规则时的默认动作（大小写不敏感）"
    )
    session_timeout: int = Field(
        ..., ge=1, le=SESSION_TIMEOUT_MAX, strict=True,
        description="会话固定存活时间（秒），1～86400；边界时刻仍存活，严格超时才清理",
    )
    max_sessions: int = Field(
        ..., ge=1, le=MAX_SESSIONS_MAX, strict=True,
        description=(
            "固定会话表容量（最大并发存活会话数），1～10000；正向 allow 建会话"
            "通过重叠检查后若容量已满，先淘汰 last_seen 最早（相同则 "
            "established_by_event 最小）的存活会话"
        ),
    )

    @field_validator("default_action", mode="before")
    @classmethod
    def normalize_default_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class FirewallMatch(BaseModel):
    type: Literal["rule", "stateful", "default"] = Field(
        ...,
        description=(
            "裁决来源：rule 命中规则；stateful 命中存活会话（自动放行）；"
            "default 未命中规则走默认动作"
        ),
    )
    rule_index: int | None = Field(
        ...,
        description=(
            "命中规则在输入中的序号（从 0 开始）；default/stateful 为 null；"
            "stateful 放行的原始规则见 session.rule_index"
        ),
    )


class FirewallSessionKey(BaseModel):
    protocol: Literal["tcp", "udp", "icmp"]
    src_ip: str = Field(..., description="正向会话源 IPv4 地址（规范化）")
    dst_ip: str = Field(..., description="正向会话目的 IPv4 地址（规范化）")
    src_port: int | None = Field(..., description="正向源端口；icmp 为 null")
    dst_port: int | None = Field(..., description="正向目的端口；icmp 为 null")


class FirewallSession(BaseModel):
    key: FirewallSessionKey = Field(..., description="正向五元组会话键")
    created_at: int = Field(..., description="会话建立时间（首个正向 allow 的时间戳）")
    last_seen: int = Field(
        ...,
        description=(
            "最近一次命中该会话的事件时间（stateful 放行的正向/反向包均刷新为"
            "当前事件时间）；新会话等于 created_at，固定过期时刻不因此延长"
        ),
    )
    expires_at: int = Field(..., description="会话过期边界时间（created_at + session_timeout）")
    rule_index: int | None = Field(..., description="建立会话的 allow 规则序号（从 0 开始）")
    established_by_event: int = Field(..., description="建立该会话的事件序号（从 0 开始）")


class FirewallEventResult(BaseModel):
    index: int = Field(..., description="事件在输入中的序号（从 0 开始）")
    timestamp: int = Field(..., description="事件时间戳（秒）")
    src_ip: str = Field(..., description="规范化后的源 IPv4 地址")
    dst_ip: str = Field(..., description="规范化后的目的 IPv4 地址")
    protocol: Literal["tcp", "udp", "icmp"]
    src_port: int | None = Field(..., description="源端口；icmp 为 null")
    dst_port: int | None = Field(..., description="目的端口；icmp 为 null")
    direction: Literal["forward", "reverse"]
    match: FirewallMatch = Field(..., description="命中来源（规则 / stateful / 默认）")
    action: Literal["allow", "deny"] = Field(..., description="最终动作")
    session_state: Literal[
        "new", "active", "expired", "expired_reestablished", "none"
    ] = Field(
        ...,
        description=(
            "会话状态：new 正向 allow 首次建立；active 命中存活会话 stateful 放行；"
            "expired 所属会话已过期、本包重新走规则；"
            "expired_reestablished 过期后正向 allow 重建会话；none 无关联会话"
        ),
    )
    session: FirewallSession | None = Field(
        ...,
        description=(
            "关联的正向会话信息：new/active/expired_reestablished 为（新）会话，"
            "expired 为已过期会话；none 为 null"
        ),
    )
    evicted_session: FirewallSession | None = Field(
        ...,
        description=(
            "本事件为建会话而淘汰的存活会话（容量满时按 last_seen 最早、"
            "established_by_event 最小选出）；未发生淘汰时为 null"
        ),
    )


class FirewallSummary(BaseModel):
    allowed: int = Field(..., description="最终动作为 allow 的事件数（含 stateful 放行）")
    denied: int = Field(..., description="最终动作为 deny 的事件数")
    new_sessions: int = Field(..., description="新建会话数（含过期重建）")
    expired_sessions: int = Field(..., description="惰性清理掉的过期会话总数（按会话计）")
    evicted_sessions: int = Field(
        ..., description="因会话表容量满而被淘汰的存活会话总数（按会话计）"
    )
    active_sessions: int = Field(..., description="全部事件处理完后仍存活的会话数")


class FirewallSimulateResponse(BaseModel):
    rule_count: int = Field(..., description="请求中的规则条数")
    event_count: int = Field(..., description="请求中的事件数")
    default_action: Literal["allow", "deny"]
    session_timeout: int = Field(..., description="会话固定存活时间（秒）")
    max_sessions: int = Field(..., description="固定会话表容量（最大并发存活会话数）")
    results: list[FirewallEventResult] = Field(
        ..., description="逐事件裁决结果，严格保持 events 输入顺序"
    )
    summary: FirewallSummary


# ---------- /ipv4/reassemble ----------


class IPv4Fragment(BaseModel):
    """同一 IPv4 数据报的单个分片：8 字节单位偏移 + MF 标志 + Base64 载荷。"""

    offset: int = Field(
        ..., ge=0, strict=True,
        description="片偏移（fragment offset），以 8 字节为单位的非负整数",
    )
    more_fragments: bool = Field(
        ...,
        description="MF 标志：true 表示还有后续分片（非末片），false 表示末片；全请求必须恰好一个 false",
    )
    payload: StrictStr = Field(
        ...,
        description="本分片载荷的标准 Base64 编码；非末片解码后长度必须是 8 的倍数",
    )

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        # 仅做标准 Base64 解码校验，核心层复用 decode_payload 取得字节
        decode_payload(value)
        return value

    @field_validator("more_fragments", mode="before")
    @classmethod
    def reject_non_bool(cls, value: object) -> object:
        # pydantic 严格模式仍会把 "true"/"false"/"0"/"1" 等字符串转为布尔，
        # 这里与项目其他布尔/整数入参保持一致，明确拒绝非 bool 输入 -> 422
        if not isinstance(value, bool):
            raise ValueError("more_fragments 必须是布尔值 true 或 false")
        return value


class IPv4ReassembleRequest(BaseModel):
    """IPv4 分片重组请求：20～60 字节首部 + 1～500 个同一数据报分片。"""

    header_bytes: int = Field(
        ..., ge=HEADER_MIN, le=HEADER_MAX, strict=True,
        description="IPv4 首部长度（IHL × 4），20～60 字节的整数；不含在重组载荷内",
    )
    fragments: list[IPv4Fragment] = Field(
        ...,
        min_length=1,
        max_length=FRAGMENTS_MAX,
        description="同一数据报的分片列表（1～500 个，顺序任意）",
    )


class IPv4ReassembleResponse(BaseModel):
    status: Literal["complete", "incomplete", "conflict"]
    contributing_fragments: list[int] | None = Field(
        default=None,
        description=(
            "complete：至少贡献一个总载荷字节的分片输入序号（从 0 开始），"
            "按 (字节偏移, 输入序号) 升序；其余状态为 null"
        ),
    )
    payload: str | None = Field(
        default=None,
        description="complete：重组后完整载荷的标准 Base64；其余状态为 null",
    )
    missing_ranges: list[list[int]] | None = Field(
        default=None,
        description=(
            "incomplete：相对 [0, 总载荷长度) 合并后的缺失半开区间 "
            "[start, end)，按起点升序；其余状态为 null"
        ),
    )
    first_conflict_offset: int | None = Field(
        default=None,
        description="conflict：全部分片中最小的不一致重叠字节偏移；其余状态为 null",
    )


# ---------- /ipv4/fragment ----------


class IPv4FragmentRequest(BaseModel):
    """IPv4 分片规划请求：Base64 载荷 + 首部长度 + MTU + DF 标志（+ 可选原始片信息）。"""

    payload: StrictStr = Field(
        ...,
        description=(
            "数据报载荷的标准 Base64 编码（空串为空载荷）；"
            "original_offset*8 + 解码后载荷长度 + header_bytes 不得超过 65535"
        ),
    )
    header_bytes: int = Field(
        ..., ge=HEADER_MIN, le=HEADER_MAX, strict=True,
        description="IPv4 首部长度（IHL × 4），20～60 字节的整数",
    )
    mtu: int = Field(
        ..., ge=MTU_MIN, strict=True,
        description=(
            "链路 MTU（字节），正整数；需要切片时必须能容下一个合法非末片"
            "载荷（首部长度 + 至少 8 字节），否则 422"
        ),
    )
    dont_fragment: bool = Field(
        ...,
        description="DF 标志：true 时禁止分片，数据报超 MTU 返回 needs_fragmentation",
    )
    original_offset: int = Field(
        default=0, ge=0, le=FRAGMENT_OFFSET_MAX, strict=True,
        description=(
            "原始片偏移（8 字节单位，0～8191），对已有分片再次切分时使用；"
            "各子片偏移在此基础上叠加；默认 0；"
            "original_offset*8 + 载荷长度 + header_bytes 不得越过 65535"
        ),
    )
    original_more_fragments: bool = Field(
        default=False,
        description=(
            "原始 MF 标志：输入本身是某数据报的非末片时为 true，此时载荷"
            "长度必须是 8 的倍数（否则 422 non_aligned_fragment）；"
            "切片后最后子片继承该标志，其余子片 MF=true"
        ),
    )

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        # 仅做标准 Base64 解码校验，核心层复用 decode_payload 取得字节
        decode_payload(value)
        return value

    @field_validator("dont_fragment", "original_more_fragments", mode="before")
    @classmethod
    def reject_non_bool(cls, value: object) -> object:
        # 与项目其他布尔入参保持一致，明确拒绝非 bool 输入 -> 422
        if not isinstance(value, bool):
            raise ValueError("必须是布尔值 true 或 false")
        return value


class IPv4PlannedFragment(BaseModel):
    """规划输出的单个分片：8 字节单位偏移 + MF 标志 + Base64 载荷 + 总长度。"""

    offset: int = Field(
        ...,
        ge=0,
        le=FRAGMENT_OFFSET_MAX,
        description=(
            "片偏移（fragment offset），以 8 字节为单位（已叠加原始片偏移），"
            "不超过 8191"
        ),
    )
    more_fragments: bool = Field(
        ...,
        description="MF 标志：除最后子片外恒为 true，最后子片继承原始 MF",
    )
    payload: str = Field(..., description="本片载荷的标准 Base64 编码")
    total_length: int = Field(
        ..., description="本片 IPv4 总长度（首部长度 + 本片载荷字节数），不超过 MTU"
    )


class IPv4FragmentResponse(BaseModel):
    status: Literal["unfragmented", "fragmented", "needs_fragmentation"]
    fragment_count: int = Field(
        ..., description="输出分片数；needs_fragmentation 为 0"
    )
    fragments: list[IPv4PlannedFragment] = Field(
        ...,
        description=(
            "分片序列，按输入顺序切片（偏移递增）；"
            "needs_fragmentation 为空（不输出载荷）"
        ),
    )


@app.get("/", tags=["meta"])
def root() -> dict:
    """服务信息。"""
    return {
        "service": "ipv4-shadow-analyzer",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    """健康检查。"""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["analyze"],
    summary="分析有序 allow/deny 规则的遮蔽情况",
)
def analyze(request: AnalyzeRequest) -> dict:
    """按顺序计算每条规则未被此前规则覆盖的地址集合并分类。

    非法 CIDR、IPv6、空规则集均返回 **422 Unprocessable Entity**。
    """
    # analyzer 再做一次防御性校验（该模块也可独立使用）
    try:
        return analyze_rules([(r.action, r.cidr) for r in request.rules])
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["compare"],
    summary="比较两组有序规则在整个 IPv4 空间上的最终判定是否等价",
)
def compare(request: CompareRequest) -> dict:
    """两侧均沿用 /analyze 的 CIDR 校验与“首条匹配规则生效”顺序。

    未命中任何规则的地址取各自 ``default_action``；判定不同的地址按
    left_action/right_action 分组，返回地址数与无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return compare_rule_sets(
            [(r.action, r.cidr) for r in request.left.rules],
            request.left.default_action,
            [(r.action, r.cidr) for r in request.right.rules],
            request.right.default_action,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/explain",
    response_model=ExplainResponse,
    tags=["explain"],
    summary="解释一段 IPv4 地址空间由哪条规则或默认动作最终裁决",
)
def explain(request: ExplainRequest) -> dict:
    """在 ``query`` 范围内按“首条匹配规则生效”语义归因。

    query 中的每个地址归属于首条命中它的规则；未命中任何规则的部分
    归于 ``default_action``。归因项按规则索引升序、默认项最后返回，
    所有项不重不漏地覆盖整个 query；每项给出无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return explain_query(
            [(r.action, r.cidr) for r in request.rules],
            request.default_action,
            request.query,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/cidrs/hierarchy",
    response_model=HierarchyResponse,
    tags=["hierarchy"],
    summary="分析一组 IPv4 CIDR 的包含层级（森林）与各节点独占地址",
)
def cidr_hierarchy(request: HierarchyRequest) -> dict:
    """对每个网段选择输入中前缀最长的严格超网作为唯一 parent，没有则为 root。

    - 每个节点给出 ``total_addresses``；
    - ``exclusive_address_count`` / ``exclusive_cidrs`` 为自身范围扣除
      **全部直接子节点**并集后的独占地址集合，无损、数量最少；
    - 返回按网络地址、前缀长度、输入顺序稳定排列的树（兄弟有序的森林）。

    id 必须唯一；规范化后网段相同的条目（如 ``10.0.0.0/8`` 与
    ``10.0.0.0/08``）返回 **422** 并列出冲突 id；非法 CIDR / IPv6 同样 422。
    """
    try:
        return build_cidr_hierarchy(
            [(entry.id, entry.cidr) for entry in request.entries]
        )
    except HierarchyInputError as exc:
        # 重复 id / 规范化后重复网段：422 并列出冲突 id
        raise HTTPException(
            status_code=422,
            detail={
                "error": "duplicate_entries",
                "duplicate_ids": exc.duplicate_ids,
                "duplicate_networks": exc.duplicate_networks,
            },
        ) from exc
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/cidrs/diff",
    response_model=CidrDiffResponse,
    tags=["hierarchy"],
    summary="比对两份带唯一 id 的 IPv4 网段清单的新增、删除、CIDR 变更与父节点变化",
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": {
                        "diff": {
                            "summary": "新增 / 删除 / CIDR 变更 / 父节点变化 / 替换候选",
                            "value": {
                                "before_count": 4,
                                "after_count": 4,
                                "changes": [
                                    {
                                        "id": "net",
                                        "change": "unchanged",
                                        "before_cidr": "10.0.0.0/8",
                                        "after_cidr": "10.0.0.0/8",
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": False,
                                        "affected_address_count": 0,
                                    },
                                    {
                                        "id": "sub-a",
                                        "change": "cidr_changed",
                                        "before_cidr": "10.1.0.0/16",
                                        "after_cidr": "10.1.0.0/24",
                                        "before_parent_id": "net",
                                        "after_parent_id": "net",
                                        "parent_changed": False,
                                        "affected_address_count": 65280,
                                    },
                                    {
                                        "id": "sub-b",
                                        "change": "removed",
                                        "before_cidr": "10.2.0.0/16",
                                        "after_cidr": None,
                                        "before_parent_id": "net",
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 65536,
                                    },
                                    {
                                        "id": "old-dns",
                                        "change": "removed",
                                        "before_cidr": "8.8.8.8/32",
                                        "after_cidr": None,
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 1,
                                    },
                                    {
                                        "id": "sub-c",
                                        "change": "added",
                                        "before_cidr": None,
                                        "after_cidr": "10.2.0.0/16",
                                        "before_parent_id": None,
                                        "after_parent_id": "net",
                                        "parent_changed": None,
                                        "affected_address_count": 65536,
                                    },
                                    {
                                        "id": "new-dns",
                                        "change": "added",
                                        "before_cidr": None,
                                        "after_cidr": "8.8.8.8/32",
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 1,
                                    },
                                ],
                                "replacement_candidates": [
                                    {
                                        "before_id": "sub-b",
                                        "after_id": "sub-c",
                                        "cidr": "10.2.0.0/16",
                                        "address_count": 65536,
                                    },
                                    {
                                        "before_id": "old-dns",
                                        "after_id": "new-dns",
                                        "cidr": "8.8.8.8/32",
                                        "address_count": 1,
                                    },
                                ],
                                "summary": {
                                    "added": 2,
                                    "removed": 2,
                                    "cidr_changed": 1,
                                    "unchanged": 1,
                                    "parent_changed": 0,
                                    "replacement_candidate_count": 2,
                                    "affected_address_count": 196354,
                                },
                            },
                        }
                    }
                }
            }
        },
        422: {
            "content": {
                "application/json": {
                    "examples": {
                        "duplicates": {
                            "summary": "after 侧存在重复 id",
                            "value": {
                                "detail": {
                                    "error": "duplicate_entries",
                                    "before": {
                                        "duplicate_ids": [],
                                        "duplicate_networks": [],
                                    },
                                    "after": {
                                        "duplicate_ids": [
                                            {"id": "x", "indexes": [0, 2]}
                                        ],
                                        "duplicate_networks": [],
                                    },
                                }
                            },
                        }
                    }
                }
            }
        },
    },
)
def cidr_diff(
    request: CidrDiffRequest = Body(
        ...,
        openapi_examples={
            "diff": {
                "summary": "新增 / 删除 / CIDR 变更 / 父节点变化 / 替换候选",
                "value": {
                    "before": [
                        {"id": "net", "cidr": "10.0.0.0/8"},
                        {"id": "sub-a", "cidr": "10.1.0.0/16"},
                        {"id": "sub-b", "cidr": "10.2.0.0/16"},
                        {"id": "old-dns", "cidr": "8.8.8.8/32"},
                    ],
                    "after": [
                        {"id": "net", "cidr": "10.0.0.0/8"},
                        {"id": "sub-a", "cidr": "10.1.0.0/24"},
                        {"id": "sub-c", "cidr": "10.2.0.0/16"},
                        {"id": "new-dns", "cidr": "8.8.8.8/32"},
                    ],
                },
            }
        },
    ),
) -> dict:
    """按 **id** 匹配 before / after 两份清单并逐条报告差异。

    - ``change`` 分类：``added``（仅 after）、``removed``（仅 before）、
      ``cidr_changed``（同 id 但规范化网段不同）、``unchanged``（同 id 且
      网段相同）；
    - 每个条目的直接父节点（前缀最长的严格超网）在**各自清单内独立**
      计算，``parent_changed`` 标记同 id 条目的父节点变化（可与
      ``cidr_changed`` 同时出现；新增 / 删除项为 ``null``）；
    - 规范化后**网段相同但 id 不同**的前后条目两两配对，列入
      ``replacement_candidates``（替换候选）；
    - ``affected_address_count``：CIDR 变更取旧、新网段的**对称差**地址数，
      新增 / 删除取该网段地址数，其余为 0；
    - ``changes`` 保持 **before 顺序**（删除 / 匹配项），新增项按
      **after 顺序**追加。

    任一侧 id 或规范化网段重复时返回 **422**，两侧重复问题一次性报告、
    **不产生部分结果**；两侧均允许为空（``[]``），单侧最多 500 个条目。
    """
    try:
        return diff_cidr_lists(
            [(entry.id, entry.cidr) for entry in request.before],
            [(entry.id, entry.cidr) for entry in request.after],
        )
    except CidrDiffInputError as exc:
        # 任一侧重复 id / 规范化后重复网段：422 并一次性列出两侧冲突
        raise HTTPException(
            status_code=422,
            detail={
                "error": "duplicate_entries",
                "before": exc.sides["before"],
                "after": exc.sides["after"],
            },
        ) from exc
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/routes/resolve",
    response_model=RouteResolveResponse,
    tags=["routes"],
    summary="按最长前缀匹配、最低 metric 解析目标地址的等价下一跳",
)
def routes_resolve(request: RouteResolveRequest) -> dict:
    """对每个目标先做**最长前缀匹配（LPM）**，再在命中路由中保留
    **最低 metric** 的全部路由，其 `next_hop` 构成等价多路径（ECMP）结果，
    按 `routes` 输入顺序**去重**后返回；未命中任何路由的目标标记为
    `unreachable`。

    - `results` 严格保持 `targets` 输入顺序；
    - `summary.next_hop_counts` 汇总每个 next_hop 命中的**目标数**
      （同一 ECMP 结果的各下一跳分别计一次），按 next_hop 在 routes 中
      的首次出现位置排序；
    - `targets` 必须唯一，重复时返回 **422** 并列出冲突位置；
    - CIDR / 目标 / 下一跳均沿用严格 IPv4 校验，`metric` 为 0～65535；
      路由最多 1000 条、目标 1～500 个。

    全程只做 32 位整数比较，**不逐地址展开网段**。
    """
    try:
        return resolve_routes(
            [(route.cidr, route.next_hop, route.metric) for route in request.routes],
            list(request.targets),
        )
    except DuplicateTargetsError as exc:
        # 重复目标：422 并列出规范化目标与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_targets", "duplicates": exc.duplicates},
        ) from exc
    except (InvalidCIDRError, InvalidIPv4AddressError):
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/routes/failover",
    response_model=RouteFailoverResponse,
    tags=["routes"],
    summary="模拟一组下一跳失效后的路由切换影响（before/after/impact）",
)
def routes_failover(request: RouteFailoverRequest) -> dict:
    """先在完整路由表上按 /routes/resolve 语义解析一次（``before``），再移除
    ``failed_next_hops`` 对应的**全部路由**，重新执行最长前缀、最低 metric
    与 ECMP 选择（``after``）——**不是**从原 ECMP 列表中删值，因此允许
    回退到**更高 metric** 或**更短前缀**。

    - `results` 严格保持 `targets` 输入顺序，每项含 `before` / `after` /
      `impact`；
    - `impact` 分类：`unchanged`（结果不变，含两侧均不可达）、
      `ecmp_reduced`（网段与 metric 不变、等价下一跳减少）、
      `rerouted`（仍可达但网段或 metric 改变）、
      `unreachable`（原本可达、故障后不可达）；
    - `summary` 汇总四类影响的目标数；
    - `routes` / `targets` 校验与 /routes/resolve 完全一致；
      `failed_next_hops` 必须唯一，重复时返回 **422** 并在
      `detail.duplicates` 中列出冲突位置。
    """
    try:
        return failover_routes(
            [(route.cidr, route.next_hop, route.metric) for route in request.routes],
            list(request.targets),
            list(request.failed_next_hops),
        )
    except DuplicateTargetsError as exc:
        # 重复目标：422 并列出规范化目标与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_targets", "duplicates": exc.duplicates},
        ) from exc
    except DuplicateNextHopsError as exc:
        # 重复失败下一跳：422 并列出规范化下一跳与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_next_hops", "duplicates": exc.duplicates},
        ) from exc
    except (InvalidCIDRError, InvalidIPv4AddressError):
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/routes/audit",
    response_model=RouteAuditResponse,
    tags=["routes"],
    summary="审计有序路由表：每条路由在整个 IPv4 空间实际负责的地址集合",
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": {
                        "audit": {
                            "summary": (
                                "同网段高 metric 遮蔽、更长前缀部分遮蔽、"
                                "ECMP 共享与默认路由之外的不可达空间"
                            ),
                            "value": {
                                "route_count": 9,
                                "results": [
                                    {
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
                                    },
                                    {
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
                                    },
                                    {
                                        "index": 2,
                                        "cidr": "10.0.0.0/24",
                                        "next_hop": "10.0.0.3",
                                        "metric": 10,
                                        "status": "partial",
                                        "status_label": "部分生效",
                                        "total_addresses": 256,
                                        "effective_addresses": 128,
                                        "effective_cidrs": ["10.0.0.0/25"],
                                        "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"],
                                    },
                                    {
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
                                    },
                                    {
                                        "index": 4,
                                        "cidr": "10.0.1.0/24",
                                        "next_hop": "10.0.1.1",
                                        "metric": 20,
                                        "status": "active",
                                        "status_label": "全部生效",
                                        "total_addresses": 256,
                                        "effective_addresses": 256,
                                        "effective_cidrs": ["10.0.1.0/24"],
                                        "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"],
                                    },
                                    {
                                        "index": 5,
                                        "cidr": "10.0.1.0/24",
                                        "next_hop": "10.0.1.2",
                                        "metric": 20,
                                        "status": "active",
                                        "status_label": "全部生效",
                                        "total_addresses": 256,
                                        "effective_addresses": 256,
                                        "effective_cidrs": ["10.0.1.0/24"],
                                        "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"],
                                    },
                                    {
                                        "index": 6,
                                        "cidr": "10.0.1.0/24",
                                        "next_hop": "10.0.1.9",
                                        "metric": 99,
                                        "status": "shadowed",
                                        "status_label": "完全遮蔽",
                                        "total_addresses": 256,
                                        "effective_addresses": 0,
                                        "effective_cidrs": [],
                                        "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"],
                                    },
                                    {
                                        "index": 7,
                                        "cidr": "10.0.2.0/25",
                                        "next_hop": "10.0.2.1",
                                        "metric": 5,
                                        "status": "active",
                                        "status_label": "全部生效",
                                        "total_addresses": 128,
                                        "effective_addresses": 128,
                                        "effective_cidrs": ["10.0.2.0/25"],
                                        "ecmp_next_hops": ["10.0.2.1"],
                                    },
                                    {
                                        "index": 8,
                                        "cidr": "10.0.2.128/25",
                                        "next_hop": "10.0.2.2",
                                        "metric": 5,
                                        "status": "active",
                                        "status_label": "全部生效",
                                        "total_addresses": 128,
                                        "effective_addresses": 128,
                                        "effective_cidrs": ["10.0.2.128/25"],
                                        "ecmp_next_hops": ["10.0.2.2"],
                                    },
                                ],
                                "summary": {
                                    "active": 5,
                                    "partial": 2,
                                    "shadowed": 2,
                                    "routed_address_count": 768,
                                    "unreachable_address_count": 4294966528,
                                    "effective_address_sum": 1152,
                                },
                            },
                        }
                    }
                }
            }
        }
    },
)
def routes_audit(
    request: RouteAuditRequest = Body(
        ...,
        openapi_examples={
            "audit": {
                "summary": (
                    "同网段高 metric 遮蔽、更长前缀部分遮蔽、ECMP 共享"
                ),
                "value": {
                    "routes": [
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
                },
            }
        },
    ),
) -> dict:
    """把 /routes/resolve 的选择规则应用到**整个 IPv4 空间**，而不是逐个目标：

    - **最长前缀优先**：一个地址命中多个不同网段时，只有前缀最长的网段
      负责它——更短网段在该地址上被更长网段遮蔽（metric 再优也不例外）；
    - **同前缀最低 metric**：同一网段内只有 metric 最小的**全部**路由生效，
      metric 更高的同网段路由完全遮蔽；
    - **ECMP 共享**：同网段同最低 metric 的并行路由**共享同一生效地址集合**
      （``effective_addresses`` 与 ``effective_cidrs`` 完全相同），其
      ``ecmp_next_hops`` 按 routes 输入顺序去重。

    每条路由给出：

    - ``status``：``active``（最低 metric 组且网段未被任何更长前缀覆盖）、
      ``partial``（属最低 metric 组但网段部分被更长前缀覆盖）、``shadowed``
      （生效集合为空）；
    - ``effective_addresses`` / ``effective_cidrs``：实际负责地址集合的
      地址数与**无损、数量最少**的 CIDR；
    - ``ecmp_next_hops``：所属网段最低 metric 组的等价下一跳（高 metric
      路由也返回该组，便于定位遮蔽来源）。

    ``results`` **严格保持 routes 输入顺序**；``summary`` 给出三类状态
    计数、整表承载地址数 ``routed_address_count`` 与其补集
    ``unreachable_address_count``（二者之和恒为 2^32），以及逐条
    ``effective_addresses`` 之和 ``effective_address_sum``（ECMP 并行路由
    各计一次）。路由允许为空（整表均不可达），最多 1000 条；
    CIDR / next_hop / metric 沿用严格 IPv4 校验。

    全程基于整数区间运算，**不逐地址展开网段**，可安全处理 ``0.0.0.0/0``。
    """
    return audit_routes(
        [(route.cidr, route.next_hop, route.metric) for route in request.routes]
    )


@app.post(
    "/firewall/simulate",
    response_model=FirewallSimulateResponse,
    tags=["firewall"],
    summary="有状态防火墙模拟：有序规则首条匹配 + 五元组会话状态放行与超时重判",
    responses={
        422: {
            "content": {
                "application/json": {
                    "examples": {
                        "out_of_order": {
                            "summary": "事件时间戳未严格递增",
                            "value": {
                                "detail": {
                                    "error": "out_of_order_timestamps",
                                    "violations": [
                                        {"index": 2, "timestamp": 5, "previous_timestamp": 10}
                                    ],
                                }
                            },
                        },
                        "overlapping": {
                            "summary": "新建会话键与存活会话重叠",
                            "value": {
                                "detail": {
                                    "error": "overlapping_session",
                                    "index": 3,
                                    "conflict": "reverse_key_collision",
                                    "existing_index": 0,
                                    "session_key": {
                                        "protocol": "tcp",
                                        "src_ip": "10.0.0.10",
                                        "src_port": 40000,
                                        "dst_ip": "10.0.1.20",
                                        "dst_port": 80,
                                    },
                                }
                            },
                        },
                    }
                }
            }
        }
    },
)
def firewall_simulate(
    request: FirewallSimulateRequest = Body(
        ...,
        openapi_examples={
            "simulate": {
                "summary": "正向建立会话、反向 stateful 放行、超时后重新走规则",
                "value": {
                    "rules": [
                        {
                            "action": "allow",
                            "src_cidr": "10.0.0.0/24",
                            "dst_cidr": "10.0.1.0/24",
                            "protocol": "tcp",
                            "port_start": 80,
                            "port_end": 80,
                        },
                        {
                            "action": "deny",
                            "src_cidr": "0.0.0.0/0",
                            "dst_cidr": "0.0.0.0/0",
                            "protocol": "tcp",
                            "port_start": 0,
                            "port_end": 65535,
                        },
                    ],
                    "default_action": "deny",
                    "session_timeout": 30,
                    "max_sessions": 10000,
                    "events": [
                        {
                            "timestamp": 0,
                            "src_ip": "10.0.0.10",
                            "dst_ip": "10.0.1.20",
                            "protocol": "tcp",
                            "src_port": 40000,
                            "dst_port": 80,
                            "direction": "forward",
                        },
                        {
                            "timestamp": 5,
                            "src_ip": "10.0.1.20",
                            "dst_ip": "10.0.0.10",
                            "protocol": "tcp",
                            "src_port": 80,
                            "dst_port": 40000,
                            "direction": "reverse",
                        },
                        {
                            "timestamp": 40,
                            "src_ip": "10.0.1.20",
                            "dst_ip": "10.0.0.10",
                            "protocol": "tcp",
                            "src_port": 80,
                            "dst_port": 40000,
                            "direction": "reverse",
                        },
                        {
                            "timestamp": 50,
                            "src_ip": "10.0.0.10",
                            "dst_ip": "10.0.1.20",
                            "protocol": "tcp",
                            "src_port": 40001,
                            "dst_port": 80,
                            "direction": "forward",
                        },
                    ],
                },
            },
            "eviction": {
                "summary": "容量为 2：建第三个会话时淘汰 last_seen 最早的存活会话",
                "value": {
                    "rules": [
                        {
                            "action": "allow",
                            "src_cidr": "0.0.0.0/0",
                            "dst_cidr": "0.0.0.0/0",
                            "protocol": "tcp",
                            "port_start": 0,
                            "port_end": 65535,
                        }
                    ],
                    "default_action": "deny",
                    "session_timeout": 100,
                    "max_sessions": 2,
                    "events": [
                        {
                            "timestamp": 0,
                            "src_ip": "10.0.0.1",
                            "dst_ip": "10.0.1.1",
                            "protocol": "tcp",
                            "src_port": 1001,
                            "dst_port": 80,
                            "direction": "forward",
                        },
                        {
                            "timestamp": 1,
                            "src_ip": "10.0.0.2",
                            "dst_ip": "10.0.1.2",
                            "protocol": "tcp",
                            "src_port": 1002,
                            "dst_port": 80,
                            "direction": "forward",
                        },
                        {
                            "timestamp": 2,
                            "src_ip": "10.0.1.1",
                            "dst_ip": "10.0.0.1",
                            "protocol": "tcp",
                            "src_port": 80,
                            "dst_port": 1001,
                            "direction": "reverse",
                        },
                        {
                            "timestamp": 3,
                            "src_ip": "10.0.0.3",
                            "dst_ip": "10.0.1.3",
                            "protocol": "tcp",
                            "src_port": 1003,
                            "dst_port": 80,
                            "direction": "forward",
                        },
                        {
                            "timestamp": 4,
                            "src_ip": "10.0.1.2",
                            "dst_ip": "10.0.0.2",
                            "protocol": "tcp",
                            "src_port": 80,
                            "dst_port": 1002,
                            "direction": "reverse",
                        },
                    ],
                },
            },
        },
    ),
) -> dict:
    """按以下语义逐事件模拟有状态防火墙：

    - **规则匹配**：规则按数组顺序**首条命中生效**——协议相等、源地址命中
      ``src_cidr``、目的地址命中 ``dst_cidr``；tcp/udp 还要求包的**目的端口**
      落在 ``port_start``～``port_end`` 闭区间内；未命中任何规则时取
      ``default_action``。
    - **会话建立**：首个最终动作 allow 的 **forward** 包建立正向五元组会话
      ``(protocol, src_ip, src_port, dst_ip, dst_port)``，固定存活
      ``session_timeout`` 秒（不因后续包刷新；``created_at + session_timeout``
      边界时刻仍存活，严格超过才过期）。
    - **状态放行**：存活期内该会话的后续正向包与 **reverse** 包（地址/端口
      对调后命中同一会话）一律 ``stateful`` 放行，不再查规则；每次命中都把
      会话 ``last_seen`` 刷新为当前事件时间（新会话的 ``last_seen`` 等于
      建立时间）。
    - **超时重判**：每个事件处理前按其时间戳**惰性清理**过期会话；过期后
      的包（含反向包）必须重新走规则匹配——反向包即使重新被 allow 也不建会话，
      正向包重新 allow 则**重建**会话（``expired_reestablished``）。
    - **固定容量淘汰**：会话表容量固定为 ``max_sessions``（1～10000）。正向
      allow **先做现有重叠检查**，确认可建会话且容量已满时，淘汰
      ``last_seen`` 最早的存活会话（相同则 ``established_by_event`` 最小者
      优先）后再建新会话；逐事件返回 ``evicted_session``（未淘汰为 null），
      被淘汰流的后续包必须**重新按规则裁决**。
    - **重叠会话键**：新会话的正向键或反向键与任何存活会话冲突（同键重复
      建立、或两个方向相反的会话同时存活）时返回 **422**
      （``error="overlapping_session"``），不产生部分结果。

    每个事件返回命中来源（``rule`` / ``stateful`` / ``default`` +
    规则序号）、最终动作、会话状态（``new`` / ``active`` / ``expired`` /
    ``expired_reestablished`` / ``none``）、会话信息（含 ``last_seen``）与
    淘汰会话；``summary`` 汇总放行 / 拒绝事件数、新建会话数、惰性清理的
    过期会话数、容量淘汰会话数与处理结束后仍存活的会话数。

    事件时间戳必须为非负整数且**严格递增**，违规时返回 **422**
    （``error="out_of_order_timestamps"``）并一次性列出全部违规位置；
    非法 CIDR / IPv4 地址、端口（越界、bool/float、范围倒置、icmp 带端口）、
    协议、方向、存活时间与容量参数同样返回 **422**。
    """
    try:
        return simulate_firewall(
            [
                (
                    rule.action,
                    rule.src_cidr,
                    rule.dst_cidr,
                    rule.protocol,
                    rule.port_start,
                    rule.port_end,
                )
                for rule in request.rules
            ],
            [
                (
                    event.timestamp,
                    event.src_ip,
                    event.dst_ip,
                    event.protocol,
                    event.src_port,
                    event.dst_port,
                    event.direction,
                )
                for event in request.events
            ],
            request.default_action,
            request.session_timeout,
            request.max_sessions,
        )
    except OutOfOrderTimestampsError as exc:
        # 时间戳乱序：422 并一次性列出全部违规位置
        raise HTTPException(
            status_code=422,
            detail={"error": "out_of_order_timestamps", "violations": exc.violations},
        ) from exc
    except OverlappingSessionError as exc:
        # 会话键重叠：422 并指出冲突事件、既有会话建立事件与冲突五元组键
        raise HTTPException(
            status_code=422,
            detail={
                "error": "overlapping_session",
                "index": exc.index,
                "conflict": exc.conflict,
                "existing_index": exc.existing_index,
                "session_key": exc.session_key,
            },
        ) from exc
    except (InvalidCIDRError, InvalidIPv4AddressError):
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/ipv4/reassemble",
    response_model=IPv4ReassembleResponse,
    tags=["reassembly"],
    summary="按字节区间重组同一 IPv4 数据报的分片（冲突 / 缺口 / 完成）",
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": {
                        "complete": {
                            "summary": "乱序到达、存在重复一致覆盖：完整重组",
                            "value": {
                                "status": "complete",
                                "contributing_fragments": [0, 2, 1],
                                "payload": "aGVsbG8td29ybGQtaXB2NA==",
                                "missing_ranges": None,
                                "first_conflict_offset": None,
                            },
                        },
                        "incomplete": {
                            "summary": "无冲突但存在缺口：返回合并后的缺失半开区间",
                            "value": {
                                "status": "incomplete",
                                "contributing_fragments": None,
                                "payload": None,
                                "missing_ranges": [[8, 16]],
                                "first_conflict_offset": None,
                            },
                        },
                        "conflict": {
                            "summary": "重叠覆盖处字节不一致：返回首个冲突偏移",
                            "value": {
                                "status": "conflict",
                                "contributing_fragments": None,
                                "payload": None,
                                "missing_ranges": None,
                                "first_conflict_offset": 8,
                            },
                        },
                    }
                }
            }
        },
        422: {
            "content": {
                "application/json": {
                    "examples": {
                        "datagram_too_large": {
                            "summary": "末片锚定的总长度越过 IPv4 65535 字节上限",
                            "value": {
                                "detail": {
                                    "error": "datagram_too_large",
                                    "indexes": [1],
                                    "limit": 65535,
                                }
                            },
                        }
                    }
                }
            }
        },
    },
)
def ipv4_reassemble(
    request: IPv4ReassembleRequest = Body(
        ...,
        openapi_examples={
            "complete": {
                "summary": "乱序到达 + 重复一致覆盖（16 字节载荷，另含一片完全重发）",
                "value": {
                    "header_bytes": 20,
                    "fragments": [
                        {"offset": 0, "more_fragments": True, "payload": "aGVsbG8td28="},
                        {"offset": 1, "more_fragments": False, "payload": "cmxkLWlwdjQ="},
                        {"offset": 0, "more_fragments": True, "payload": "aGVsbG8td28="},
                    ],
                },
            },
            "incomplete": {
                "summary": "中间缺口：offset 0 与 offset 2 已到，offset 1 缺失，末片只含 4 字节",
                "value": {
                    "header_bytes": 20,
                    "fragments": [
                        {"offset": 0, "more_fragments": True, "payload": "AAAAAAAAAAA="},
                        {"offset": 2, "more_fragments": False, "payload": "AAAAAA=="},
                    ],
                },
            },
            "conflict": {
                "summary": "重发分片在偏移 8 处的字节与原片不一致",
                "value": {
                    "header_bytes": 20,
                    "fragments": [
                        {"offset": 0, "more_fragments": True, "payload": "AAAAAAAAAAAAAAAAAAAAAA=="},
                        {"offset": 1, "more_fragments": True, "payload": "QAAAAAAAAAA="},
                        {"offset": 2, "more_fragments": False, "payload": "AAAAAA=="},
                    ],
                },
            },
        },
    ),
) -> dict:
    """把同一 IPv4 数据报的分片按**字节区间**重组（``offset`` 以 8 字节为单位，
    每片覆盖半开区间 ``[offset*8, offset*8 + len(payload))``）：

    - **非末片对齐**：除唯一一个 ``more_fragments=false`` 的末片外，其余分片
      载荷长度必须是 **8 的倍数**，否则返回 **422**
      （``error="non_aligned_fragment"``）；
    - **末片定长**：必须**恰好一个** ``more_fragments=false`` 的末片，零个或
      多个均返回 **422**（``error="invalid_last_fragment_count"``）；末片按
      ``offset*8 + len(payload)`` 锚定总载荷长度；
    - **长度上限**：首部长度 + 总载荷长度越过 IPv4 数据报 **65535** 字节上限
      时返回 **422**（``error="datagram_too_large"``）；``header_bytes``
      必须为 20～60 的整数，分片数 1～500；
    - **重叠处理**：重复覆盖且重叠字节完全一致可接受；任一重叠字节不一致即
      返回 ``status="conflict"`` 与 **首个冲突偏移**
      ``first_conflict_offset``（全部分片中最小的不一致字节偏移，冲突结论
      优先于缺口）；
    - **缺口**：无冲突但 ``[0, 总载荷长度)`` 未被完全覆盖时返回
      ``status="incomplete"`` 与合并后的缺失**半开区间**
      ``missing_ranges``（形如 ``[start, end)``，按起点升序）；
    - **完成**：覆盖完整时返回 ``status="complete"``、按
      ``(字节偏移, 输入序号)`` 升序的**贡献分片索引**
      ``contributing_fragments``（至少贡献一个总载荷字节的分片；空载荷或
      完全越界的分片不计入）与重组后完整载荷的标准 Base64 ``payload``。

    非法 Base64、负/非整数 ``offset``、非布尔 ``more_fragments``、字段缺失等
    同样返回 **422**。
    """
    try:
        return reassemble_ipv4(
            request.header_bytes,
            [
                (
                    fragment.offset,
                    fragment.more_fragments,
                    decode_payload(fragment.payload),
                )
                for fragment in request.fragments
            ],
        )
    except ReassemblyInputError as exc:
        # 语义类输入错误：422 并给出错误类型与相关分片位置
        raise HTTPException(
            status_code=422,
            detail={"error": exc.error, "indexes": exc.indexes, "limit": exc.limit},
        ) from exc


@app.post(
    "/ipv4/fragment",
    response_model=IPv4FragmentResponse,
    tags=["fragmentation"],
    summary="规划 IPv4 数据报在指定 MTU 链路上的分片序列",
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": {
                        "unfragmented": {
                            "summary": "数据报不超 MTU：原样返回一个分片",
                            "value": {
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
                            },
                        },
                        "fragmented": {
                            "summary": "超 MTU 且 DF=false：按最大 8 字节倍数切片",
                            "value": {
                                "status": "fragmented",
                                "fragment_count": 3,
                                "fragments": [
                                    {
                                        "offset": 0,
                                        "more_fragments": True,
                                        "payload": "aGVsbG8td28=",
                                        "total_length": 28,
                                    },
                                    {
                                        "offset": 1,
                                        "more_fragments": True,
                                        "payload": "cmxkLWlwdjQ=",
                                        "total_length": 28,
                                    },
                                    {
                                        "offset": 2,
                                        "more_fragments": False,
                                        "payload": "ISEhIQ==",
                                        "total_length": 24,
                                    },
                                ],
                            },
                        },
                        "needs_fragmentation": {
                            "summary": "超 MTU 且 DF=true：不输出载荷",
                            "value": {
                                "status": "needs_fragmentation",
                                "fragment_count": 0,
                                "fragments": [],
                            },
                        },
                    }
                }
            }
        },
        422: {
            "content": {
                "application/json": {
                    "examples": {
                        "non_aligned_fragment": {
                            "summary": "original_more_fragments=true 但载荷不是 8 字节倍数",
                            "value": {
                                "detail": {
                                    "error": "non_aligned_fragment",
                                    "limit": None,
                                }
                            },
                        },
                        "datagram_too_large": {
                            "summary": (
                                "原数据报绝对结束位置 original_offset*8 + "
                                "载荷长度 + 首部长度越过 IPv4 65535 字节上限"
                            ),
                            "value": {
                                "detail": {
                                    "error": "datagram_too_large",
                                    "limit": 65535,
                                }
                            },
                        },
                        "mtu_too_small": {
                            "summary": "MTU 容不下一个合法非末片载荷",
                            "value": {
                                "detail": {
                                    "error": "mtu_too_small",
                                    "limit": 28,
                                }
                            },
                        },
                    }
                }
            }
        },
    },
)
def ipv4_fragment(
    request: IPv4FragmentRequest = Body(
        ...,
        openapi_examples={
            "fragmented": {
                "summary": "20 字节首部 + 20 字节载荷，MTU 28：切成 8/8/4 三片",
                "value": {
                    "payload": "aGVsbG8td29ybGQtaXB2NCEhISE=",
                    "header_bytes": 20,
                    "mtu": 28,
                    "dont_fragment": False,
                },
            },
            "needs_fragmentation": {
                "summary": "同样的数据报，DF=true：返回 needs_fragmentation",
                "value": {
                    "payload": "aGVsbG8td29ybGQtaXB2NCEhISE=",
                    "header_bytes": 20,
                    "mtu": 28,
                    "dont_fragment": True,
                },
            },
            "refragment": {
                "summary": "对已有分片（原始偏移 2、原始 MF=true，24 字节对齐载荷）再次切分",
                "value": {
                    "payload": "aGVsbG8td29ybGQtaXB2NHJlZnJhLW9r",
                    "header_bytes": 20,
                    "mtu": 28,
                    "dont_fragment": False,
                    "original_offset": 2,
                    "original_more_fragments": True,
                },
            },
        },
    ),
) -> dict:
    """规划 IPv4 数据报（或其中一个已有分片）在指定 MTU 链路上的分片序列。

    以下两项校验**早于**不超 MTU、DF 与切片分支：

    - **非末片对齐**：``original_more_fragments=true`` 表示输入本身是某个
      数据报的非末片，其载荷长度**必须为 8 的倍数**，否则返回 **422**
      （``error="non_aligned_fragment"``）；
    - **原数据报上限**：无论是否实际切片，都按
      ``original_offset*8 + 载荷长度 + header_bytes`` 校验原数据报的绝对
      结束位置，越过 IPv4 **65535** 字节上限时返回 **422**
      （``error="datagram_too_large"``，``limit=65535``）；该约束同时保证
      所有输出 ``offset`` 不超过片偏移字段上限 **8191**。

    通过上述校验后按以下顺序判定：

    - **不超 MTU**：``header_bytes + 载荷`` 不超过 ``mtu`` 时原样返回一个
      分片（``unfragmented``），保留 ``original_offset`` 与
      ``original_more_fragments``；
    - **超限且 DF=true**：返回 ``needs_fragmentation``，
      ``fragments`` 为空（**不输出载荷**）；
    - **其余情况切片**（``fragmented``）：除最终片外，每片载荷取
      ``MTU − header_bytes`` 向下取整的**最大 8 字节倍数**（非末片载荷
      必须 8 字节对齐），最终片取剩余载荷（不要求对齐）；各片输出偏移 =
      ``original_offset`` + 片内字节偏移 / 8（8 字节单位）；**最后子片
      继承原始 MF**，其余子片 MF=true。

    每片返回 ``offset``（8 字节单位，不超过 8191）、``more_fragments``、
    Base64 ``payload`` 与 ``total_length``（首部长度 + 本片载荷字节数，不超
    MTU）；输出与 /ipv4/reassemble 的输入同构，可直接往返重组。

    需要切片而 MTU 连一个合法非末片载荷（首部长度 + 至少 8 字节）都容不下
    时返回 **422**（``error="mtu_too_small"``，``limit`` 为所需最小 MTU）。
    非法 Base64、非布尔 ``dont_fragment`` / ``original_more_fragments``、
    ``original_offset`` 不在 0～8191、``mtu`` 非正整数等同样返回 **422**。
    """
    try:
        return plan_ipv4_fragmentation(
            request.header_bytes,
            request.mtu,
            request.dont_fragment,
            decode_payload(request.payload),
            request.original_offset,
            request.original_more_fragments,
        )
    except FragmentationInputError as exc:
        # 语义类输入错误：422 并给出错误类型与相关阈值
        raise HTTPException(
            status_code=422,
            detail={"error": exc.error, "limit": exc.limit},
        ) from exc
