# IPv4 遮蔽分析 API

基于 **Python + FastAPI** 的 IPv4 CIDR 规则遮蔽（shadowing）分析、等价性比较、
包含层级分析、静态路由解析与有状态防火墙模拟服务。

按输入顺序处理一组有序的 `allow` / `deny` CIDR 规则，计算每条规则
**未被此前任何规则覆盖**的地址集合，并分为：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| 全生效 | `full` | 规则地址均未被此前规则覆盖 |
| 部分遮蔽 | `partial` | 部分地址此前已被覆盖 |
| 完全遮蔽 | `shadowed` | 全部地址此前已被覆盖，规则不产生任何生效地址 |

每条规则的生效（剩余）地址集合会**无损压缩成数量最少的 CIDR 列表**，
并在 `summary` 中汇总生效的 `allow`、`deny` 地址数。

`POST /compare` 还可比较两组规则（各带未命中时的 `default_action`）在
**整个 IPv4 空间**上的最终判定是否等价，并按 left/right 动作分组给出
判定不同的地址集合及其最少 CIDR 表示。

`POST /explain` 则回答反向问题：给定一段 IPv4 地址空间（`query`），
其中每个地址最终由**哪条规则**（首条匹配）或**默认动作**裁决，
并按规则索引升序给出各归属方的地址集合及其最少 CIDR 表示。

`POST /cidrs/hierarchy` 分析 **1～500 个带唯一 id 的 IPv4 CIDR 条目**的
包含层级：为每个网段选择输入中**前缀最长的严格超网**作为唯一 parent
（没有则作为 root），返回按网络地址、前缀长度与输入顺序稳定排列的树；
每个节点给出 `total_addresses`，以及自身范围扣除全部直接子节点并集后的
`exclusive_address_count` 与无损、数量最少的 `exclusive_cidrs`。

`POST /cidrs/diff` 比对 **before / after 两份各 0～500 个带唯一 id 的
IPv4 网段清单**：按 id 匹配后逐条报告新增（`added`）、删除（`removed`）、
CIDR 变更（`cidr_changed`）与未变（`unchanged`），并在各自清单内独立
计算每个网段的**直接父节点**（前缀最长的严格超网），标记父节点变化
（`parent_changed`）；规范化后**网段相同但 id 不同**的前后条目标记为
**替换候选**（`replacement_candidates`）。CIDR 变更条目的受影响地址数
取旧、新网段的**对称差**，新增 / 删除取该网段地址数；结果保持
**before 顺序**，新增项按 **after 顺序**追加。

`POST /routes/resolve` 则是静态路由解析：给定最多 1000 条路由
（`cidr` / `next_hop` / `metric`）与最多 500 个唯一目标 IPv4 地址，对每个
目标先做**最长前缀匹配（LPM）**，再在命中路由中保留**最低 metric** 的全部
等价下一跳（ECMP），按 `routes` 输入顺序去重返回；未命中任何路由的目标标记为
`unreachable`，并汇总每个 `next_hop` 命中的目标数。

`POST /routes/failover` 在 `/routes/resolve` 的基础上模拟**下一跳故障**：
先在完整路由表上解析一次（`before`），再移除 `failed_next_hops` 对应的
**全部路由**并重新执行最长前缀、最低 metric 与 ECMP 选择（`after`）——
不是从原 ECMP 列表中删值，因此允许回退到**更高 metric** 或**更短前缀**。
逐目标返回 `before` / `after` / `impact`（`unchanged` / `ecmp_reduced` /
`rerouted` / `unreachable`），并汇总四类影响的目标数。

`POST /routes/audit` 把同一套选择规则从“逐个目标”提升到**整个 IPv4 空间**：
给定最多 1000 条有序路由（允许为空），按**最长前缀优先、同前缀最低 metric、
同 metric ECMP 并行**的语义，计算每条路由实际负责的地址集合，分类为
`active`（全部生效）/ `partial`（部分生效）/ `shadowed`（完全遮蔽），返回
每条路由的生效地址数与**无损最少 CIDR**；同网段同 metric 的并行路由
**共享同一集合**并保持输入顺序；`summary` 给出整表承载地址数、不可达地址数
（二者之和恒为 2³²）与逐条生效地址之和（ECMP 并行路由各计一次）。

`POST /firewall/simulate` 模拟**有状态防火墙**：给定最多 500 条有序规则
（源/目的 CIDR、协议、目的端口范围、`allow`/`deny`）与最多 2000 个**按时间
严格递增**的数据包事件，按**首条匹配规则生效**逐事件裁决。首个最终放行的
**正向（forward）**包建立五元组会话 `(protocol, src_ip, src_port, dst_ip,
dst_port)`，在固定的 `session_timeout` 存活时间内，会话的后续正向包与
**反向（reverse）**包一律 `stateful` 自动放行、不再查规则，且每次命中都把
会话的 `last_seen` 刷新为当前时间；超时（惰性清理：
`created_at + session_timeout` 边界时刻仍存活，严格超过才过期）后的包必须
**重新走规则匹配**——反向包即使重新放行也不建会话，正向包重新放行则重建会话。
会话表容量固定为 `max_sessions`（1～10000）：正向 allow 通过重叠检查、确认
可建会话而容量已满时，先淘汰 `last_seen` 最早的存活会话（相同则
`established_by_event` 最小者优先），被淘汰流的后续包必须重新按规则裁决。
逐事件返回命中规则或 `stateful` / 默认动作、最终动作、会话状态与本事件淘汰
的会话，并汇总放行 / 拒绝 / 新建 / 过期 / 淘汰数量；乱序时间戳、非法端口与
重叠会话键均返回 **422**。

`POST /ipv4/reassemble` 实现 **IPv4 数据报分片重组**：给定 20～60 字节的
`header_bytes` 与同一数据报的 1～500 个分片（每片给出以 8 字节为单位的
`offset`、`more_fragments` 标志与 Base64 编码的 `payload`），按字节区间
`[offset*8, offset*8 + len(payload))` 重组。非末片载荷长度必须是 **8 的倍数**，
且必须**恰好一个** `more_fragments=false` 的末片——末片锚定总载荷长度，
首部加载荷越过 IPv4 **65535** 字节上限即返回 422。重复覆盖且字节一致可接受；
任一重叠字节冲突返回 `conflict` 与**首个冲突偏移**；无冲突但有缺口返回
`incomplete` 与合并后的缺失**半开区间**；覆盖完整返回 `complete`、按偏移
排序的贡献分片索引与重组后的 Base64 载荷。

`POST /ipv4/fragment` 是反向的 **IPv4 数据报分片规划**：给定 Base64
`payload`、20～60 字节 `header_bytes`、链路 `mtu` 与 DF 标志
（`dont_fragment`），以及可选的 `original_offset` /
`original_more_fragments`（对**已有分片**再次切分时使用），规划该数据报
在此链路上的分片序列。当 `original_more_fragments=true`（输入是非末片）时，
载荷长度**必须为 8 字节倍数**，否则返回 422
（`error=non_aligned_fragment`）；无论是否实际切片，都按
`original_offset*8 + 载荷长度 + header_bytes` 校验原数据报的绝对结束位置，
越过 65535 返回 422（`error=datagram_too_large`、`limit=65535`），该约束
也保证所有输出 `offset` 不超过 8191。两项校验均早于不超 MTU、DF 与切片
分支。数据报（首部 + 载荷，不得越过 65535）不超 MTU 时
**原样返回一个分片**（`unfragmented`，保留原始片偏移与 MF）；超限且
DF=true 时返回 `needs_fragmentation`、**不输出载荷**；其余情况按输入顺序
切片（`fragmented`）：除最终片外每片载荷取不超过 MTU 的**最大 8 字节
倍数**，输出偏移以 8 字节计并**叠加原始片偏移**，最后子片**继承原始
MF**、其余子片 MF=true。MTU 连一个合法非末片载荷（首部 + 至少 8 字节）
都容不下时返回 422。每片返回 Base64 载荷、`offset`、MF 与 `total_length`，
输出与 `/ipv4/reassemble` 的输入同构，可直接往返重组。

> 遮蔽来源不区分动作：先前的 **allow 与 deny 规则取并集**，共同遮蔽后续规则。

---

## 快速开始（Docker Compose 一条命令）

```bash
docker compose up --build -d
```

服务地址与端口：

- **API 基础地址：** http://localhost:8000
- **分析接口：** `POST http://localhost:8000/analyze`
- **比较接口：** `POST http://localhost:8000/compare`
- **解释接口：** `POST http://localhost:8000/explain`
- **层级接口：** `POST http://localhost:8000/cidrs/hierarchy`
- **网段清单差异接口：** `POST http://localhost:8000/cidrs/diff`
- **路由解析接口：** `POST http://localhost:8000/routes/resolve`
- **故障切换接口：** `POST http://localhost:8000/routes/failover`
- **路由表审计接口：** `POST http://localhost:8000/routes/audit`
- **有状态防火墙模拟接口：** `POST http://localhost:8000/firewall/simulate`
- **IPv4 分片重组接口：** `POST http://localhost:8000/ipv4/reassemble`
- **IPv4 分片规划接口：** `POST http://localhost:8000/ipv4/fragment`
- **交互式文档（Swagger UI）：** http://localhost:8000/docs
- **OpenAPI Schema：** http://localhost:8000/openapi.json
- **健康检查：** http://localhost:8000/health

如需更换宿主机端口（例如改用 18000）：

```bash
HTTP_PORT=18000 docker compose up --build -d
# 随后访问 http://localhost:18000
```

停止服务：

```bash
docker compose down
```

容器内服务监听 `8000` 端口，通过 `http://localhost:${HTTP_PORT:-8000}`
访问全部接口与 `/docs`；新接口无需额外配置，例如：

```bash
curl -s http://localhost:8000/ipv4/reassemble \
  -H 'Content-Type: application/json' \
  -d '{
    "header_bytes": 20,
    "fragments": [
      {"offset": 1, "more_fragments": false, "payload": "cmxkLWlwdjQ="},
      {"offset": 0, "more_fragments": true,  "payload": "aGVsbG8td28="}
    ]
  }'
```

也可不使用 Compose，直接用 Docker 构建并运行（同样通过 `HOST` / `PORT`
环境变量覆盖容器内监听地址，默认 `0.0.0.0:8000`）：

```bash
docker build -t ipv4-shadow-analyzer .
docker run --rm -p 8000:8000 ipv4-shadow-analyzer
```

---

## 接口说明

### `POST /analyze`

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},
    {"action": "deny",  "cidr": "10.1.0.0/16"},
    {"action": "allow", "cidr": "192.168.0.0/16"},
    {"action": "deny",  "cidr": "10.0.0.0/7"}
  ]
}
```

- `rules`：**有序**规则列表，按数组顺序逐条处理；至少 1 条。
- `action`：仅允许 `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `cidr`：严格 IPv4 CIDR（如 `10.0.0.0/8`、`0.0.0.0/0`）；
  纯 IP 地址按 `/32` 处理；**主机位必须为零**（如 `10.0.0.1/8` 非法）；
  **禁止 IPv6**。

#### 响应示例（200）

```json
{
  "rule_count": 4,
  "rules": [
    {
      "index": 0,
      "action": "allow",
      "cidr": "10.0.0.0/8",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 16777216,
      "covered_addresses": 0,
      "effective_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/8"]
    },
    {
      "index": 1,
      "action": "deny",
      "cidr": "10.1.0.0/16",
      "status": "shadowed",
      "status_label": "完全遮蔽",
      "total_addresses": 65536,
      "covered_addresses": 65536,
      "effective_addresses": 0,
      "effective_cidrs": []
    },
    {
      "index": 2,
      "action": "allow",
      "cidr": "192.168.0.0/16",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 65536,
      "covered_addresses": 0,
      "effective_addresses": 65536,
      "effective_cidrs": ["192.168.0.0/16"]
    },
    {
      "index": 3,
      "action": "deny",
      "cidr": "10.0.0.0/7",
      "status": "partial",
      "status_label": "部分遮蔽",
      "total_addresses": 33554432,
      "covered_addresses": 16777216,
      "effective_addresses": 16777216,
      "effective_cidrs": ["11.0.0.0/8"]
    }
  ],
  "summary": {
    "full": 2,
    "partial": 1,
    "shadowed": 1,
    "effective_allow_addresses": 16842752,
    "effective_deny_addresses": 16777216
  }
}
```

`effective_cidrs` 为生效地址集合的最少 CIDR 表示：碎片会先合并
（首尾相邻也合并），再用贪心取最大对齐 2 的幂分块，保证**块数最少且无损**。

#### curl 示例

```bash
curl -s http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"action":"allow","cidr":"0.0.0.0/0"},{"action":"deny","cidr":"8.8.8.8/32"}]}'
```

---

### `POST /compare`

比较两组有序 allow/deny 规则在**整个 IPv4 空间**（`0.0.0.0/0`）上的最终
判定是否等价。两侧各自独立，均沿用 `/analyze` 的 CIDR 校验与
**首条匹配规则生效**的顺序语义；未命中任何规则的地址取该侧的
`default_action`。

#### 请求体

```json
{
  "left": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "deny",  "cidr": "10.1.0.0/16"},
      {"action": "allow", "cidr": "10.0.0.0/8"}
    ],
    "default_action": "deny"
  }
}
```

- `left` / `right`：两侧规则集，结构相同。
  - `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
    为空时该侧所有地址都走默认动作。
  - `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
    `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `rules` 内每条规则的 `action` / `cidr` 校验规则与 `/analyze` 完全一致
  （严格 IPv4 CIDR、纯 IP 按 `/32`、主机位必须为零、禁止 IPv6）。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `equivalent` | 两侧在整个 IPv4 空间上的最终判定是否完全一致；为 `true` 时 `differences` 为空 |
| `differences[]` | 判定不同的地址分组，按 `left_action`、`right_action` 组合聚合，最多 2 组 |
| `differences[].left_action` / `.right_action` | 该组地址在左侧 / 右侧的最终动作 |
| `differences[].address_count` | 该组覆盖的地址数（各组之和 ≤ 2³²） |
| `differences[].cidrs` | 该组地址集合**无损压缩后的最少 CIDR 列表** |

分组按 `(left_action, right_action)` 字典序返回：
`(allow, deny)` 在前，`(deny, allow)` 在后。整个比较基于整数区间归并
计算，**不会逐地址枚举 IPv4 空间**。

#### 响应示例（200，不等价）

上例中 `10.1.0.0/16` 左侧先命中 `allow 10.0.0.0/8`，右侧先命中
`deny 10.1.0.0/16`，因此仅这一个 `/16` 的判定不同：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "allow",
      "right_action": "deny",
      "address_count": 65536,
      "cidrs": ["10.1.0.0/16"]
    }
  ]
}
```

#### 响应示例（200，完全等价）

被此前规则**完全遮蔽**的规则不影响最终判定；`default_action` 大小写不敏感：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "DENY"
  }
}
```

响应：

```json
{
  "equivalent": true,
  "differences": []
}
```

#### 默认动作导致的全空间差异

左侧仅放行 `10.0.0.0/8`、其余默认 `deny`；右侧无规则、默认 `allow`。
除 `10.0.0.0/8` 外的全部地址构成一个 `deny → allow` 组，被压缩为
8 个 CIDR（地址计数 4294967296 − 16777216 = 4278190080）：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [],
    "default_action": "allow"
  }
}
```

响应：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "deny",
      "right_action": "allow",
      "address_count": 4278190080,
      "cidrs": [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
    "left":  {"rules":[{"action":"allow","cidr":"10.0.0.0/8"}], "default_action":"deny"},
    "right": {"rules": [],                                        "default_action":"allow"}
  }'
```

---

### `POST /explain`

解释一段 IPv4 地址空间（`query`）最终由**哪条规则或默认动作**裁决。
沿用 `/analyze` 的 CIDR 校验与**首条匹配规则生效**的顺序语义，
但只在 `query` 范围内归因：query 中的每个地址归属于首条命中它的规则；
未命中任何规则的部分归于 `default_action`。

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/16"},
    {"action": "deny",  "cidr": "10.0.1.0/24"},
    {"action": "deny",  "cidr": "10.2.0.0/16"}
  ],
  "default_action": "deny",
  "query": "10.0.0.0/8"
}
```

- `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
  为空时整个 query 都走默认动作。每条规则的 `action` / `cidr` 校验规则
  与 `/analyze` 完全一致。
- `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
  `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `query`：**必填**，单个严格 IPv4 CIDR；纯 IP 按 `/32` 处理；
  主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `query` | 规范化后的 query CIDR（纯 IP 规范化为 `/32`） |
| `total_addresses` | query 覆盖的地址总数 |
| `attribution[]` | 归因列表，**按规则索引升序、默认项最后**；所有项**不重不漏**覆盖整个 query |
| `attribution[].source` | `rule`（命中规则）或 `default`（走默认动作） |
| `attribution[].rule_index` | 命中规则在输入中的序号（从 0 开始）；默认项为 `null` |
| `attribution[].action` | 该项地址的最终动作 |
| `attribution[].address_count` | 该项覆盖的地址数（各项之和 = `total_addresses`） |
| `attribution[].cidrs` | 该项地址集合**无损压缩后的最少 CIDR 列表** |

在 query 范围内被此前规则完全遮蔽、或与 query 不相交的规则不会产生
归因项；若规则已完整覆盖 query，则不出现默认项。

#### 响应示例（200）

上例中 `deny 10.0.1.0/24` 被规则 0 完全遮蔽（不出现）；`10.0.0.0/16`
归规则 0、`10.2.0.0/16` 归规则 2，其余地址走默认动作 `deny`：

```json
{
  "query": "10.0.0.0/8",
  "total_addresses": 16777216,
  "attribution": [
    {
      "source": "rule",
      "rule_index": 0,
      "action": "allow",
      "address_count": 65536,
      "cidrs": ["10.0.0.0/16"]
    },
    {
      "source": "rule",
      "rule_index": 2,
      "action": "deny",
      "address_count": 65536,
      "cidrs": ["10.2.0.0/16"]
    },
    {
      "source": "default",
      "rule_index": null,
      "action": "deny",
      "address_count": 16646144,
      "cidrs": [
        "10.1.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/explain \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [{"action":"allow","cidr":"10.0.0.0/16"}],
    "default_action": "deny",
    "query": "10.0.0.0/8"
  }'
```

---

### `POST /cidrs/hierarchy`

分析 **1～500 个带唯一 `id` 的 IPv4 CIDR 条目**的包含层级。

- 对每个网段，选择输入中**前缀最长的严格超网**（strict supernet）作为它的
  **唯一 parent**；不存在严格超网的网段作为 **root**。
- 每个节点给出：
  - `total_addresses`：本网段覆盖的地址总数；
  - `exclusive_address_count`：自身范围扣除**全部直接子节点**并集后的
    独占地址数（孙节点不重复扣除）；
  - `exclusive_cidrs`：该独占地址集合**无损压缩、数量最少**的 CIDR 列表
    （无子节点时就是网段自身）。
- 树（森林）按 **网络地址升序 → 前缀长度升序 → 输入顺序** 稳定排列
  （先根遍历的兄弟顺序）。
- `id` 必须在全请求内唯一（字符串或整数）；**规范化后网络相同**的条目
  （如 `10.0.0.0/8` 与 `10.0.0.0/08`）返回 **422** 并列出冲突 id。
- CIDR 校验与其他接口完全一致：严格 IPv4、纯 IP 按 `/32`、主机位必须为零、
  禁止 IPv6。基于整数区间运算，**不逐地址枚举**。

#### 请求体

```json
{
  "entries": [
    {"id": "net",   "cidr": "10.0.0.0/8"},
    {"id": "sub",   "cidr": "10.1.0.0/16"},
    {"id": "host1", "cidr": "10.1.0.1/32"},
    {"id": "host2", "cidr": "10.1.0.2/32"},
    {"id": "dns",   "cidr": "8.8.8.8"}
  ]
}
```

- `entries`：**必填**，1～500 个条目。
- `id`：非空字符串或整数，全请求内唯一；不接受 `true` / `1.5` 等其他类型，
  不做隐式类型转换。
- `cidr`：严格 IPv4 CIDR；纯 IP 按 `/32` 处理；主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `node_count` | 节点（条目）总数 |
| `root_count` | 根节点数量 |
| `roots[]` | 根节点组成的森林，按网络地址、前缀长度、输入顺序稳定排序 |
| `roots[].id` / `.cidr` | 节点 id 与规范化后的 CIDR |
| `roots[].parent_id` | 唯一父节点 id（前缀最长的严格超网）；根节点为 `null` |
| `roots[].total_addresses` | 本网段覆盖的地址总数（2^(32−前缀长度)） |
| `roots[].exclusive_address_count` | 自身范围扣除全部直接子节点并集后的地址数 |
| `roots[].exclusive_cidrs` | 独占地址集合**无损压缩后的最少 CIDR 列表** |
| `roots[].children[]` | 直接子节点（递归同构），排序规则与 `roots` 相同 |

#### 响应示例（200）

上例中 `host1` / `host2` 的 parent 是前缀最长的严格超网 `sub`（`/16`），
而非 `net`（`/8`）；`sub` 的独占范围要扣除这两个直接子节点，`net` 只扣除
它的直接子节点 `sub`（孙节点不重复扣除）。`dns`（`8.8.8.8/32`）与
`10.0.0.0/8` 不相交，是另一个 root；根按网络地址升序排列：

```json
{
  "node_count": 5,
  "root_count": 2,
  "roots": [
    {
      "id": "dns",
      "cidr": "8.8.8.8/32",
      "parent_id": null,
      "total_addresses": 1,
      "exclusive_address_count": 1,
      "exclusive_cidrs": ["8.8.8.8/32"],
      "children": []
    },
    {
      "id": "net",
      "cidr": "10.0.0.0/8",
      "parent_id": null,
      "total_addresses": 16777216,
      "exclusive_address_count": 16711680,
      "exclusive_cidrs": [
        "10.0.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ],
      "children": [
        {
          "id": "sub",
          "cidr": "10.1.0.0/16",
          "parent_id": "net",
          "total_addresses": 65536,
          "exclusive_address_count": 65534,
          "exclusive_cidrs": [
            "10.1.0.0/32",
            "10.1.0.3/32",
            "10.1.0.4/30",
            "10.1.0.8/29",
            "10.1.0.16/28",
            "10.1.0.32/27",
            "10.1.0.64/26",
            "10.1.0.128/25",
            "10.1.1.0/24",
            "10.1.2.0/23",
            "10.1.4.0/22",
            "10.1.8.0/21",
            "10.1.16.0/20",
            "10.1.32.0/19",
            "10.1.64.0/18",
            "10.1.128.0/17"
          ],
          "children": [
            {
              "id": "host1",
              "cidr": "10.1.0.1/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.1/32"],
              "children": []
            },
            {
              "id": "host2",
              "cidr": "10.1.0.2/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.2/32"],
              "children": []
            }
          ]
        }
      ]
    }
  ]
}
```

#### 错误示例（422，规范化后网络重复）

请求中 `b` 与 `a` 规范化后指向同一网络，返回 422 并在
`duplicate_networks[].entries` 中列出冲突条目（含冲突 id）：

```json
{
  "detail": {
    "error": "duplicate_entries",
    "duplicate_ids": [],
    "duplicate_networks": [
      {
        "cidr": "10.0.0.0/8",
        "entries": [
          {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
          {"index": 1, "id": "b", "cidr": "10.0.0.0/8"}
        ]
      }
    ]
  }
}
```

`id` 重复时，冲突位置列在 `duplicate_ids`（每项含 `id` 与全部出现位置
`indexes`）；两类问题可能同时出现。

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/hierarchy \
  -H 'Content-Type: application/json' \
  -d '{"entries":[{"id":"net","cidr":"10.0.0.0/8"},{"id":"sub","cidr":"10.1.0.0/16"},{"id":"host","cidr":"10.1.1.1"}]}'
```

---

### `POST /cidrs/diff`

比对 **before / after 两份带唯一 id 的 IPv4 网段清单**，回答“这批网段从
旧清单到新清单发生了什么变化”。

1. 两侧条目先做严格 IPv4 校验与规范化（纯 IP 按 `/32`），并分别检查
   **id 唯一**与**规范化后网段唯一**；
2. 按 **id** 匹配两侧条目，分为 `added` / `removed` / `cidr_changed` /
   `unchanged` 四类；
3. 每个条目的**直接父节点**（清单内前缀最长的严格超网，规则与
   `/cidrs/hierarchy` 相同）在**各自清单内独立**计算；同 id 匹配上的
   条目比较前后父节点，变化时 `parent_changed = true`（可与
   `cidr_changed` 同时成立）；新增 / 删除项两侧只有一侧有父节点，
   `parent_changed` 为 `null`；
4. 规范化后**网段相同但 id 不同**的前后条目两两配对（两侧网段各自唯一，
   每个网段至多一对），列入 `replacement_candidates`，提示“同网段换 id”
   的替换关系；
5. 受影响地址数 `affected_address_count`：
   - `cidr_changed`：旧、新网段的**对称差**（`|旧 △ 新| = |旧| + |新| − 2×|交集|`），
     网段缩小取差值、扩张取增量、互不相交取两者之和；
   - `added` / `removed`：该网段自身地址数；
   - `unchanged`：`0`（父节点变化不改变地址集合）。

- `before` / `after`：**各 0～500 个**条目，**允许两侧或任一侧为空** `[]`；
  条目的 `id` / `cidr` 校验与 `/cidrs/hierarchy` 完全一致
  （id 为非空字符串或整数；严格 IPv4 CIDR、纯 IP 按 `/32`、主机位必须为
  零、禁止 IPv6）。
- 排序：`changes` **保持 before 顺序**（删除项与同 id 匹配项按 before
  出现位置排列），**新增项按 after 顺序追加**；`replacement_candidates`
  按 before 侧位置排序。
- 任一侧 id 或规范化网段重复时返回 **422**，两侧重复问题在同一次响应中
  分别列出、**不产生任何部分结果**。基于整数区间运算，**不逐地址枚举**。

#### 请求体

```json
{
  "before": [
    {"id": "net",     "cidr": "10.0.0.0/8"},
    {"id": "sub-a",   "cidr": "10.1.0.0/16"},
    {"id": "sub-b",   "cidr": "10.2.0.0/16"},
    {"id": "old-dns", "cidr": "8.8.8.8/32"}
  ],
  "after": [
    {"id": "net",     "cidr": "10.0.0.0/8"},
    {"id": "sub-a",   "cidr": "10.1.0.0/24"},
    {"id": "sub-c",   "cidr": "10.2.0.0/16"},
    {"id": "new-dns", "cidr": "8.8.8.8/32"}
  ]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `before_count` / `after_count` | before / after 侧条目数 |
| `changes[]` | 逐条变化结果：保持 before 顺序（删除 / 匹配项），新增项按 after 顺序追加 |
| `changes[].id` | 条目 id（两侧共有或仅一侧存在） |
| `changes[].change` | `added` / `removed` / `cidr_changed` / `unchanged` |
| `changes[].before_cidr` / `.after_cidr` | before / after 侧规范化网段；缺失侧为 `null` |
| `changes[].before_parent_id` / `.after_parent_id` | 各自清单内的直接父节点 id（root 为 `null`）；缺失侧为 `null` |
| `changes[].parent_changed` | 同 id 匹配项的直接父节点是否变化；新增 / 删除项为 `null` |
| `changes[].affected_address_count` | 受影响地址数：CIDR 变更取旧新对称差，新增 / 删除取该网段地址数，其余为 0 |
| `replacement_candidates[]` | 规范化后网段相同但 id 不同的配对：`before_id` / `after_id` / `cidr` / `address_count`，按 before 侧位置排序 |
| `summary.added` / `.removed` / `.cidr_changed` / `.unchanged` | 四类变化各自的条目数（四类之和 = `before_count + added`） |
| `summary.parent_changed` | 同 id 匹配且父节点变化的条目数（可与 `cidr_changed` 重叠） |
| `summary.replacement_candidate_count` | 替换候选配对数 |
| `summary.affected_address_count` | 全部新增、删除与 CIDR 变更条目的受影响地址数之和 |

#### 响应示例（200）

上例中：`net` 未变；`sub-a` 由 `/16` 缩成 `/24`（对称差
65536 − 256 = 65280）；`sub-b` 被删除、`sub-c` 为新增，二者网段同为
`10.2.0.0/16` 但 id 不同，构成替换候选；`old-dns` / `new-dns` 同理
（同一个 `/32` 换了 id）：

```json
{
  "before_count": 4,
  "after_count": 4,
  "changes": [
    {
      "id": "net",
      "change": "unchanged",
      "before_cidr": "10.0.0.0/8",
      "after_cidr": "10.0.0.0/8",
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": false,
      "affected_address_count": 0
    },
    {
      "id": "sub-a",
      "change": "cidr_changed",
      "before_cidr": "10.1.0.0/16",
      "after_cidr": "10.1.0.0/24",
      "before_parent_id": "net",
      "after_parent_id": "net",
      "parent_changed": false,
      "affected_address_count": 65280
    },
    {
      "id": "sub-b",
      "change": "removed",
      "before_cidr": "10.2.0.0/16",
      "after_cidr": null,
      "before_parent_id": "net",
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 65536
    },
    {
      "id": "old-dns",
      "change": "removed",
      "before_cidr": "8.8.8.8/32",
      "after_cidr": null,
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 1
    },
    {
      "id": "sub-c",
      "change": "added",
      "before_cidr": null,
      "after_cidr": "10.2.0.0/16",
      "before_parent_id": null,
      "after_parent_id": "net",
      "parent_changed": null,
      "affected_address_count": 65536
    },
    {
      "id": "new-dns",
      "change": "added",
      "before_cidr": null,
      "after_cidr": "8.8.8.8/32",
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 1
    }
  ],
  "replacement_candidates": [
    {"before_id": "sub-b", "after_id": "sub-c", "cidr": "10.2.0.0/16", "address_count": 65536},
    {"before_id": "old-dns", "after_id": "new-dns", "cidr": "8.8.8.8/32", "address_count": 1}
  ],
  "summary": {
    "added": 2,
    "removed": 2,
    "cidr_changed": 1,
    "unchanged": 1,
    "parent_changed": 0,
    "replacement_candidate_count": 2,
    "affected_address_count": 196354
  }
}
```

父节点变化与 CIDR 变更可同时发生：例如删掉中间层 `10.1.0.0/16` 后，
`host`（`10.1.0.1/32`）网段未变（`change = "unchanged"`），但直接父节点
由 `sub` 变为 `net`，其 `parent_changed` 为 `true` 且
`affected_address_count` 为 `0`；若同时修改 `host` 的网段，则该条目
`change = "cidr_changed"`、`parent_changed = true`，受影响地址数仍按
旧新网段对称差计算（两个不相交 `/32` 时为 2）。

#### 错误示例（422，两侧重复一次性报告）

任一侧 id 或规范化网段重复均返回 422，`detail.before` / `detail.after`
分别给出该侧的 `duplicate_ids` / `duplicate_networks`（结构同
`/cidrs/hierarchy`，无问题一侧为空结构），**不产生部分结果**。下例中
before 侧 id `x` 重复，after 侧 `y` 与 `z` 规范化后网段相同：

```json
{
  "detail": {
    "error": "duplicate_entries",
    "before": {
      "duplicate_ids": [
        {"id": "x", "indexes": [0, 1]}
      ],
      "duplicate_networks": []
    },
    "after": {
      "duplicate_ids": [],
      "duplicate_networks": [
        {
          "cidr": "10.0.0.0/8",
          "entries": [
            {"index": 0, "id": "y", "cidr": "10.0.0.0/8"},
            {"index": 1, "id": "z", "cidr": "10.0.0.0/8"}
          ]
        }
      ]
    }
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/diff \
  -H 'Content-Type: application/json' \
  -d '{
    "before": [{"id":"a","cidr":"10.0.0.0/8"},{"id":"b","cidr":"8.8.8.8"}],
    "after":  [{"id":"a","cidr":"10.0.0.0/8"},{"id":"c","cidr":"9.9.9.9"}]
  }'
```

---

### `POST /routes/resolve`

对一组唯一目标 IPv4 地址做静态路由解析。解析规则：

1. **最长前缀匹配（LPM）**：在所有覆盖目标的路由中只保留前缀长度最大者；
2. **最低 metric**：在 LPM 集合中再保留 metric 最小的**全部**路由，它们构成
   等价多路径（ECMP）结果；
3. ECMP 的 `next_hop` 按 **routes 输入顺序去重**后返回；
4. 未命中任何路由的目标标记为 `unreachable`。

- `routes`：**0～1000 条**路由（允许为空 `[]`，此时所有目标均不可达）。
  - `cidr`：严格 IPv4 CIDR，校验与其他接口完全一致（纯 IP 按 `/32`、
    主机位必须为零、禁止 IPv6）；
  - `next_hop`：严格 **IPv4 地址**（纯地址，不允许 `10.0.0.1/32` 这类
    CIDR 写法，禁止前导零与 IPv6）；
  - `metric`：**0～65535** 的整数（不接受 `true`、`1.5` 等）。
- `targets`：**1～500 个**唯一目标 IPv4 地址（纯地址，校验同 `next_hop`）；
  重复时返回 **422** 并在 `detail.duplicates` 中列出冲突位置。
- `results` **严格保持 targets 输入顺序**；`summary.next_hop_counts` 汇总每个
  next_hop 命中的**目标数**——同一 ECMP 结果中的各下一跳**分别计数一次**，
  仅列出实际命中过的下一跳，按其在 `routes` 中的首次出现位置排序。

全程只做 32 位整数比较，**不逐地址展开网段**，可安全处理 `0.0.0.0/0`。

#### 请求体

```json
{
  "routes": [
    {"cidr": "0.0.0.0/0",   "next_hop": "192.0.2.254", "metric": 100},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.254",  "metric": 50},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 20},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.2",    "metric": 20},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 20},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1",    "metric": 60},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.2",    "metric": 60}
  ],
  "targets": ["10.1.0.5", "10.2.2.2", "8.8.8.8", "172.16.0.1"]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `route_count` / `target_count` | 请求中的路由条数 / 目标数 |
| `results[]` | 逐目标解析结果，**严格保持 targets 输入顺序** |
| `results[].target` | 规范化后的目标 IPv4 地址 |
| `results[].status` | `reachable` 或 `unreachable` |
| `results[].matched_cidr` | 命中的最长前缀 CIDR（ECMP 路由的共同网段）；不可达为 `null` |
| `results[].metric` | 命中路由的最低 metric；不可达为 `null` |
| `results[].next_hops` | 等价下一跳，按 routes 输入顺序去重；不可达为 `[]` |
| `summary.reachable_count` / `.unreachable_count` | 可达 / 不可达目标数 |
| `summary.next_hop_counts[]` | 每个 next_hop 命中的目标数（ECMP 各下一跳分别计数），按 routes 首次出现位置排序 |

#### 响应示例（200）

上例中：`10.1.0.5` 走最长前缀 `/16`（两个 metric 60 的等价下一跳）；
`10.2.2.2` 命中 `/8`，metric 50 的下一跳被最低 metric 20 的两个等价下一跳
淘汰，重复的 `10.0.0.1` 只保留一次；`8.8.8.8` 与 `172.16.0.1` 走默认路由：

```json
{
  "route_count": 7,
  "target_count": 4,
  "results": [
    {
      "target": "10.1.0.5",
      "status": "reachable",
      "matched_cidr": "10.1.0.0/16",
      "metric": 60,
      "next_hops": ["10.1.0.1", "10.1.0.2"]
    },
    {
      "target": "10.2.2.2",
      "status": "reachable",
      "matched_cidr": "10.0.0.0/8",
      "metric": 20,
      "next_hops": ["10.0.0.1", "10.0.0.2"]
    },
    {
      "target": "8.8.8.8",
      "status": "reachable",
      "matched_cidr": "0.0.0.0/0",
      "metric": 100,
      "next_hops": ["192.0.2.254"]
    },
    {
      "target": "172.16.0.1",
      "status": "reachable",
      "matched_cidr": "0.0.0.0/0",
      "metric": 100,
      "next_hops": ["192.0.2.254"]
    }
  ],
  "summary": {
    "reachable_count": 4,
    "unreachable_count": 0,
    "next_hop_counts": [
      {"next_hop": "192.0.2.254", "target_count": 2},
      {"next_hop": "10.0.0.1", "target_count": 1},
      {"next_hop": "10.0.0.2", "target_count": 1},
      {"next_hop": "10.1.0.1", "target_count": 1},
      {"next_hop": "10.1.0.2", "target_count": 1}
    ]
  }
}
```

未命中任何路由的目标对应：

```json
{
  "target": "8.8.8.8",
  "status": "unreachable",
  "matched_cidr": null,
  "metric": null,
  "next_hops": []
}
```

#### 错误示例（422，目标重复）

```json
{
  "detail": {
    "error": "duplicate_targets",
    "duplicates": [
      {"target": "8.8.8.8", "indexes": [0, 2]}
    ]
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/routes/resolve \
  -H 'Content-Type: application/json' \
  -d '{
    "routes": [
      {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20}
    ],
    "targets": ["10.0.0.9", "8.8.8.8"]
  }'
```

---

### `POST /routes/failover`

模拟一组下一跳失效后的路由切换影响。处理流程：

1. 先在完整路由表上按 `/routes/resolve` 语义解析一次（`before`）；
2. 移除 `failed_next_hops` 对应的**全部路由**（同一失败下一跳出现在多条
   路由中时全部移除），**重新执行**最长前缀、最低 metric 与 ECMP 选择
   （`after`）——**不是**从原 ECMP 列表中删值，因此允许回退到
   **更高 metric** 或**更短前缀**；
3. 逐目标比较前后结果并归类 `impact`，`summary` 汇总四类数量。

- `routes` / `targets`：与 `/routes/resolve` 完全一致（路由 0～1000 条、
  目标 1～500 个且唯一，校验规则相同）。
- `failed_next_hops`：**0～1000 个**唯一失败下一跳 IPv4 地址（纯地址，
  校验同 `next_hop`），允许为空 `[]`（此时所有目标均为 `unchanged`）；
  重复时返回 **422** 并在 `detail.duplicates` 中列出冲突位置。
- `results` **严格保持 targets 输入顺序**。

`impact` 分类：

| 值 | 含义 |
| --- | --- |
| `unchanged` | 解析结果完全不变（含两侧均不可达） |
| `ecmp_reduced` | 命中网段与 metric 不变，等价下一跳减少（after 是 before 的严格子集） |
| `rerouted` | 仍可达但命中网段或 metric 改变（回退到更短前缀或更高 metric） |
| `unreachable` | 原本可达、故障后不可达 |

#### 请求体

```json
{
  "routes": [
    {"cidr": "0.0.0.0/0",   "next_hop": "192.0.2.254", "metric": 100},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 10},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.2",    "metric": 10},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1",    "metric": 5},
    {"cidr": "11.0.0.0/8",  "next_hop": "11.0.0.1",    "metric": 7}
  ],
  "targets": ["10.0.9.9", "10.1.0.9", "11.0.0.9", "8.8.8.8"],
  "failed_next_hops": ["10.0.0.2", "10.1.0.1", "11.0.0.1"]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `route_count` / `target_count` | 请求中的路由条数 / 目标数 |
| `failed_next_hops` | 规范化后的失败下一跳列表，保持输入顺序 |
| `results[]` | 逐目标故障切换结果，**严格保持 targets 输入顺序** |
| `results[].target` | 规范化后的目标 IPv4 地址 |
| `results[].before` / `.after` | 故障前 / 后的解析结果，结构同 `/routes/resolve` 的单目标结果（`status` / `matched_cidr` / `metric` / `next_hops`） |
| `results[].impact` | 影响分类：`unchanged` / `ecmp_reduced` / `rerouted` / `unreachable` |
| `summary.unchanged` / `.ecmp_reduced` / `.rerouted` / `.unreachable` | 四类影响各自的目标数（总和 = `target_count`） |

#### 响应示例（200）

上例中：`10.0.9.9` 的 ECMP 少了一个下一跳（`ecmp_reduced`）；`10.1.0.9`
的 `/16` 路由失效，回退到更短前缀 `/8`（`rerouted`）；`11.0.0.9` 的唯一
路由失效，回退到默认路由 `0.0.0.0/0`（`rerouted`）；`8.8.8.8` 不受影响
（`unchanged`）：

```json
{
  "route_count": 5,
  "target_count": 4,
  "failed_next_hops": ["10.0.0.2", "10.1.0.1", "11.0.0.1"],
  "results": [
    {
      "target": "10.0.9.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1", "10.0.0.2"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"]
      },
      "impact": "ecmp_reduced"
    },
    {
      "target": "10.1.0.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "10.1.0.0/16",
        "metric": 5,
        "next_hops": ["10.1.0.1"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"]
      },
      "impact": "rerouted"
    },
    {
      "target": "11.0.0.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "11.0.0.0/8",
        "metric": 7,
        "next_hops": ["11.0.0.1"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "impact": "rerouted"
    },
    {
      "target": "8.8.8.8",
      "before": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "impact": "unchanged"
    }
  ],
  "summary": {
    "unchanged": 1,
    "ecmp_reduced": 1,
    "rerouted": 2,
    "unreachable": 0
  }
}
```

若失败下一跳是某目标的唯一可达路径，`after` 为不可达：

```json
{
  "target": "11.0.0.9",
  "before": {
    "status": "reachable",
    "matched_cidr": "11.0.0.0/8",
    "metric": 7,
    "next_hops": ["11.0.0.1"]
  },
  "after": {
    "status": "unreachable",
    "matched_cidr": null,
    "metric": null,
    "next_hops": []
  },
  "impact": "unreachable"
}
```

#### 错误示例（422，失败下一跳重复）

```json
{
  "detail": {
    "error": "duplicate_next_hops",
    "duplicates": [
      {"next_hop": "1.1.1.1", "indexes": [0, 2]}
    ]
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/routes/failover \
  -H 'Content-Type: application/json' \
  -d '{
    "routes": [
      {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20}
    ],
    "targets": ["10.0.0.9", "8.8.8.8"],
    "failed_next_hops": ["10.0.0.1"]
  }'
```

---

### `POST /routes/audit`

把 `/routes/resolve` 的选择规则应用到**整个 IPv4 空间**（而不是逐个目标），
审计每条路由实际负责哪些地址。选择规则：

1. **最长前缀优先（LPM）**：一个地址命中多个不同网段时，只有前缀最长的网段
   负责它——更短网段在该地址上被更长网段遮蔽（**metric 再优也不例外**）；
2. **同前缀最低 metric**：同一网段内只有 metric 最小的**全部**路由生效，
   metric 更高的同网段路由**完全遮蔽**（生效集合为空）；
3. **ECMP 共享**：同网段同最低 metric 的并行路由**共享同一生效地址集合**
   （`effective_addresses` 与 `effective_cidrs` 完全相同），其等价下一跳
   按 `routes` 输入顺序去重。

- `routes`：**0～1000 条**有序路由（允许为空 `[]`，此时整个 IPv4 空间均无
  路由覆盖），字段校验与 `/routes/resolve` 完全一致：
  - `cidr`：严格 IPv4 CIDR（纯 IP 按 `/32`、主机位必须为零、禁止 IPv6）；
  - `next_hop`：严格 IPv4 地址（禁止 CIDR 写法、前导零与 IPv6）；
  - `metric`：**0～65535** 的整数。
- 不要求路由唯一：同网段多条路由按 metric 与输入顺序组成 ECMP；完全重复的
  路由（同 CIDR / next_hop / metric）各自保留一条结果。

每条路由的状态：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| 全部生效 | `active` | 属其网段最低 metric 组，且网段未被任何更长前缀覆盖 |
| 部分生效 | `partial` | 属最低 metric 组，但网段部分被更长前缀覆盖 |
| 完全遮蔽 | `shadowed` | 生效集合为空：metric 被同网段更低 metric 路由淘汰，或网段被更长前缀完全覆盖 |

`results` **严格保持 routes 输入顺序**；同网段同 metric 的并行路由结果中
`effective_addresses` / `effective_cidrs` 完全相同。全程只做 32 位整数区间
运算，**不逐地址展开网段**，可安全处理 `0.0.0.0/0`。

#### 请求体

```json
{
  "routes": [
    {"cidr": "10.0.0.0/24",    "next_hop": "10.0.0.1",   "metric": 100},
    {"cidr": "10.0.0.0/24",    "next_hop": "10.0.0.2",   "metric": 10},
    {"cidr": "10.0.0.0/24",    "next_hop": "10.0.0.3",   "metric": 10},
    {"cidr": "10.0.0.128/25",  "next_hop": "10.0.0.254", "metric": 50},
    {"cidr": "10.0.1.0/24",    "next_hop": "10.0.1.1",   "metric": 20},
    {"cidr": "10.0.1.0/24",    "next_hop": "10.0.1.2",   "metric": 20},
    {"cidr": "10.0.1.0/24",    "next_hop": "10.0.1.9",   "metric": 99},
    {"cidr": "10.0.2.0/25",    "next_hop": "10.0.2.1",   "metric": 5},
    {"cidr": "10.0.2.128/25",  "next_hop": "10.0.2.2",   "metric": 5}
  ]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `route_count` | 请求中的路由条数 |
| `results[]` | 逐条路由审计结果，**严格保持 routes 输入顺序** |
| `results[].index` | 路由在输入中的序号（从 0 开始） |
| `results[].cidr` / `.next_hop` / `.metric` | 规范化后的路由 CIDR、下一跳与原 metric |
| `results[].status` | `active` / `partial` / `shadowed` |
| `results[].status_label` | 状态中文说明（全部生效 / 部分生效 / 完全遮蔽） |
| `results[].total_addresses` | 路由网段覆盖的地址总数 |
| `results[].effective_addresses` | 实际负责的地址数；同 metric 并行路由相同，`shadowed` 为 0 |
| `results[].effective_cidrs` | 实际负责集合的**无损、数量最少** CIDR 列表；`shadowed` 为 `[]` |
| `results[].ecmp_next_hops` | 所属网段最低 metric 组的等价下一跳（按输入顺序去重）；高 metric 路由同样返回该组，便于定位遮蔽来源 |
| `summary.active` / `.partial` / `.shadowed` | 三类状态各自的路由条数（总和 = `route_count`） |
| `summary.routed_address_count` | 整表实际承载的地址数（被至少一条最低 metric 最长前缀路由覆盖，ECMP 只计一次） |
| `summary.unreachable_address_count` | 未被任何路由覆盖的地址数；与上一字段之和恒为 2³² |
| `summary.effective_address_sum` | 逐条 `effective_addresses` 之和；同一 ECMP 组的并行路由**各计一次**，故可大于承载地址数 |

#### 响应示例（200）

上例中：`10.0.0.0/24` 的 metric 100 路由被同网段最低 metric 10 的两条并行
路由淘汰（`shadowed`）；两条 metric 10 路由共享网段扣除 `10.0.0.128/25`
后的上半段 `10.0.0.0/25`（128 个，`partial`）；`10.0.0.128/25` 作为更长
前缀全部生效（`active`）；`10.0.1.0/24` 的 metric 20 双下一跳共享整段
（`active`），metric 99 路由 `shadowed`；`10.0.2.0/25` 与
`10.0.2.128/25` 各自 `active`。整表承载 768 个地址，其余 IPv4 空间不可达：

```json
{
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
      "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"]
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
      "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"]
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
      "ecmp_next_hops": ["10.0.0.2", "10.0.0.3"]
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
      "ecmp_next_hops": ["10.0.0.254"]
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
      "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"]
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
      "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"]
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
      "ecmp_next_hops": ["10.0.1.1", "10.0.1.2"]
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
      "ecmp_next_hops": ["10.0.2.1"]
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
      "ecmp_next_hops": ["10.0.2.2"]
    }
  ],
  "summary": {
    "active": 5,
    "partial": 2,
    "shadowed": 2,
    "routed_address_count": 768,
    "unreachable_address_count": 4294966528,
    "effective_address_sum": 1152
  }
}
```

含默认路由时，`0.0.0.0/0` 承载除更具体网段外的全部空间，
`routed_address_count` 为 2³²、`unreachable_address_count` 为 0：

```json
{
  "routes": [
    {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
    {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10}
  ]
}
```

空路由表也是合法请求，整个 IPv4 空间均不可达：

```json
{
  "route_count": 0,
  "results": [],
  "summary": {
    "active": 0,
    "partial": 0,
    "shadowed": 0,
    "routed_address_count": 0,
    "unreachable_address_count": 4294967296,
    "effective_address_sum": 0
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/routes/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "routes": [
      {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 10},
      {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 5}
    ]
  }'
```

---

### `POST /firewall/simulate`

模拟**有状态（stateful）防火墙**对一串数据包的逐包裁决。

1. **规则匹配（无状态）**：规则按数组顺序**首条命中生效**——协议相等、源地址
   命中 `src_cidr`、目的地址命中 `dst_cidr`；`tcp` / `udp` 还要求包的**目的
   端口**落在 `port_start`～`port_end` **闭区间**内（源端口不参与规则匹配，
   只用于五元组区分会话）；未命中任何规则时取 `default_action`。
2. **会话建立**：首个最终动作为 `allow` 的 **`forward`（正向）**包建立正向
   五元组会话 `(protocol, src_ip, src_port, dst_ip, dst_port)`。会话**固定**
   存活 `session_timeout` 秒（不因后续流量刷新），过期边界为
   `created_at + session_timeout`——**边界时刻仍存活，严格超过才过期**。
   新会话的 `last_seen` 等于建立时间。
3. **状态放行**：存活期内，该会话的后续正向包与 **`reverse`（反向）**包
   （地址/端口对调后的五元组命中同一会话）一律 `stateful` 放行，**不再查规则**；
   无论正向还是反向命中，会话的 `last_seen` 都更新为当前事件时间（**不延长**
   固定过期时刻）。
4. **超时重判**：每个事件处理前按其时间戳**惰性清理**全部过期会话；过期后的
   包（含反向包）必须**重新走规则匹配**：反向包即使重新被 `allow` 也**不建立
   会话**；正向包重新被 `allow` 则**重建**会话（状态 `expired_reestablished`）。
5. **固定容量淘汰**：会话表容量固定为 `max_sessions`（1～10000）。正向 allow
   建会话时**先执行既有重叠检查**，确认可以建立且容量已满时，淘汰
   **`last_seen` 最早的存活会话**（`last_seen` 相同则 `established_by_event`
   最小者优先），再建立新会话。被淘汰会话即从会话表移除，该流的后续包必须
   **重新按规则裁决**（与从未建立过会话一致）；先于淘汰的重叠冲突直接返回
   422，不淘汰、不产生部分结果。
6. **重叠会话键**：新会话的正向键或反向键与任何**存活**会话冲突（同键重复
   建立、或两个方向相反的会话同时存活）时返回 **422**
   （`error="overlapping_session"`），不产生部分结果；一方过期后再建立则合法。

#### 请求体

- `rules`：**0～500 条**有序规则（允许为空 `[]`，此时全部走默认动作）：
  - `action`：`allow` / `deny`（大小写不敏感）；
  - `src_cidr` / `dst_cidr`：严格 IPv4 CIDR（纯 IP 按 `/32`、主机位必须为零、
    禁止 IPv6）；
  - `protocol`：`tcp` / `udp` / `icmp`（大小写不敏感）；
  - `port_start` / `port_end`：目的端口闭区间，**0～65535 的整数**（拒绝
    `true` / `1.5` / `"80"`），且 `port_start <= port_end`；`tcp` / `udp`
    必填，`icmp` 必须为 `null`。
- `events`：**1～2000 个**数据包事件，**严格保持输入顺序返回**：
  - `timestamp`：**非负整数**秒，整个序列必须**严格递增**（相等也视为乱序）；
  - `src_ip` / `dst_ip`：严格 **IPv4 地址**（纯地址，禁止 CIDR 写法、前导零
    与 IPv6）；
  - `src_port` / `dst_port`：`tcp` / `udp` 必填的 0～65535 整数；`icmp`
    必须为 `null`；
  - `direction`：`forward` / `reverse`（大小写不敏感）。
- `default_action`：未命中任何规则时的动作，`allow` / `deny`。
- `session_timeout`：会话固定存活时间，**1～86400 秒**的整数。
- `max_sessions`：**必填**，固定会话表容量（最大并发存活会话数），
  **1～10000 的整数**；容量已满且正向 allow 通过重叠检查时淘汰
  `last_seen` 最早（相同则建立事件最早）的存活会话。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `results[]` | 逐事件裁决结果，**严格保持 events 输入顺序** |
| `results[].match.type` | `rule`（命中规则）/ `stateful`（命中存活会话）/ `default`（走默认动作） |
| `results[].match.rule_index` | 命中规则序号（从 0 开始）；`stateful` / `default` 为 `null`；stateful 放行的原始规则见 `session.rule_index` |
| `results[].action` | 最终动作 `allow` / `deny`（stateful 命中恒为 `allow`） |
| `results[].session_state` | 会话状态，见下表 |
| `results[].session` | 关联的正向会话（五元组键 / `created_at` / `last_seen` / `expires_at` / 建立规则与事件序号）；`none` 为 `null` |
| `results[].evicted_session` | 本事件为建会话而淘汰的存活会话（结构同 `session`，携带淘汰前的最终 `last_seen`）；未发生淘汰为 `null` |
| `summary.allowed` / `.denied` | 最终动作为放行 / 拒绝的**事件数**（stateful 放行计入 allowed） |
| `summary.new_sessions` | 新建会话数（含过期重建） |
| `summary.expired_sessions` | 惰性清理掉的过期会话总数（**按会话计**，由触发清理的事件统一记账） |
| `summary.evicted_sessions` | 容量满时淘汰的存活会话总数（**按会话计**） |
| `summary.active_sessions` | 全部事件处理完后仍存活的会话数 |

顶层还回显 `max_sessions`（请求的会话表容量）。会话对象的 `last_seen`
为最近一次命中该会话的事件时间：新会话等于 `created_at`，之后每次正向 /
反向 stateful 命中都刷新为当前事件时间；`expires_at` 始终为
`created_at + session_timeout`，**不因 `last_seen` 刷新而延长**。

会话状态 `session_state`：

| 值 | 含义 |
| --- | --- |
| `new` | 正向 allow，首次建立会话 |
| `active` | 命中存活会话，stateful 放行（正向后续包或反向包） |
| `expired` | 所属会话已过期，本包重新走规则匹配（反向包或被拒正向包，不建会话） |
| `expired_reestablished` | 会话过期后，正向包重新被 allow 并重建会话 |
| `none` | 从未有过关联会话（纯无状态裁决） |

#### 请求与响应示例（200）

`t=0` 内网正向访问 80 端口命中 allow 建立会话（存活到 `t=30`）；`t=5` 与
`t=30`（边界时刻）的反向包均 stateful 放行；`t=31` 会话已过期，反向包重新
走规则命中 deny 兜底；`t=50` 正向访问重新 allow 并重建会话：

请求：

```json
{
  "rules": [
    {"action": "allow", "src_cidr": "10.0.0.0/24", "dst_cidr": "10.0.1.0/24",
     "protocol": "tcp", "port_start": 80, "port_end": 80},
    {"action": "deny",  "src_cidr": "0.0.0.0/0",  "dst_cidr": "0.0.0.0/0",
     "protocol": "tcp", "port_start": 0,  "port_end": 65535}
  ],
  "default_action": "deny",
  "session_timeout": 30,
  "max_sessions": 10000,
  "events": [
    {"timestamp": 0,  "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
     "protocol": "tcp", "src_port": 40000, "dst_port": 80, "direction": "forward"},
    {"timestamp": 5,  "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
     "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse"},
    {"timestamp": 30, "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
     "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse"},
    {"timestamp": 31, "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
     "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse"},
    {"timestamp": 50, "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
     "protocol": "tcp", "src_port": 40000, "dst_port": 80, "direction": "forward"}
  ]
}
```

响应（会话对象新增 `last_seen`，逐事件新增 `evicted_session`，`summary`
新增 `evicted_sessions`；本例容量充足，无淘汰）：

```json
{
  "rule_count": 2,
  "event_count": 5,
  "default_action": "deny",
  "session_timeout": 30,
  "max_sessions": 10000,
  "results": [
    {
      "index": 0, "timestamp": 0,
      "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
      "protocol": "tcp", "src_port": 40000, "dst_port": 80, "direction": "forward",
      "match": {"type": "rule", "rule_index": 0},
      "action": "allow", "session_state": "new",
      "session": {
        "key": {"protocol": "tcp", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
                "src_port": 40000, "dst_port": 80},
        "created_at": 0, "last_seen": 0, "expires_at": 30,
        "rule_index": 0, "established_by_event": 0
      },
      "evicted_session": null
    },
    {
      "index": 1, "timestamp": 5,
      "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
      "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse",
      "match": {"type": "stateful", "rule_index": null},
      "action": "allow", "session_state": "active",
      "session": {
        "key": {"protocol": "tcp", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
                "src_port": 40000, "dst_port": 80},
        "created_at": 0, "last_seen": 5, "expires_at": 30,
        "rule_index": 0, "established_by_event": 0
      },
      "evicted_session": null
    },
    {
      "index": 2, "timestamp": 30,
      "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
      "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse",
      "match": {"type": "stateful", "rule_index": null},
      "action": "allow", "session_state": "active",
      "session": {
        "key": {"protocol": "tcp", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
                "src_port": 40000, "dst_port": 80},
        "created_at": 0, "last_seen": 30, "expires_at": 30,
        "rule_index": 0, "established_by_event": 0
      },
      "evicted_session": null
    },
    {
      "index": 3, "timestamp": 31,
      "src_ip": "10.0.1.20", "dst_ip": "10.0.0.10",
      "protocol": "tcp", "src_port": 80, "dst_port": 40000, "direction": "reverse",
      "match": {"type": "rule", "rule_index": 1},
      "action": "deny", "session_state": "expired",
      "session": {
        "key": {"protocol": "tcp", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
                "src_port": 40000, "dst_port": 80},
        "created_at": 0, "last_seen": 30, "expires_at": 30,
        "rule_index": 0, "established_by_event": 0
      },
      "evicted_session": null
    },
    {
      "index": 4, "timestamp": 50,
      "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
      "protocol": "tcp", "src_port": 40000, "dst_port": 80, "direction": "forward",
      "match": {"type": "rule", "rule_index": 0},
      "action": "allow", "session_state": "expired_reestablished",
      "session": {
        "key": {"protocol": "tcp", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.20",
                "src_port": 40000, "dst_port": 80},
        "created_at": 50, "last_seen": 50, "expires_at": 80,
        "rule_index": 0, "established_by_event": 4
      },
      "evicted_session": null
    }
  ],
  "summary": {
    "allowed": 4,
    "denied": 1,
    "new_sessions": 2,
    "expired_sessions": 1,
    "evicted_sessions": 0,
    "active_sessions": 1
  }
}
```

#### 容量淘汰示例（200）

`max_sessions=2`、`session_timeout=100`（全部会话均未超时）：流 A 在 `t=0`
建立、`t=2` 的反向包把其 `last_seen` 刷新为 2；流 B 在 `t=1` 建立后无流量，
`last_seen` 仍为 1。`t=3` 流 C 的正向 allow 通过重叠检查后容量已满，淘汰
**`last_seen` 更早的 B（=1）而非 A（=2）**；`t=4` B 的反向包已无存活会话，
重新走规则被 allow，但反向包不建会话（`none`）：

请求：

```json
{
  "rules": [
    {"action": "allow", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0",
     "protocol": "tcp", "port_start": 0, "port_end": 65535}
  ],
  "default_action": "deny",
  "session_timeout": 100,
  "max_sessions": 2,
  "events": [
    {"timestamp": 0, "src_ip": "10.0.0.1", "dst_ip": "10.0.1.1",
     "protocol": "tcp", "src_port": 1001, "dst_port": 80, "direction": "forward"},
    {"timestamp": 1, "src_ip": "10.0.0.2", "dst_ip": "10.0.1.2",
     "protocol": "tcp", "src_port": 1002, "dst_port": 80, "direction": "forward"},
    {"timestamp": 2, "src_ip": "10.0.1.1", "dst_ip": "10.0.0.1",
     "protocol": "tcp", "src_port": 80, "dst_port": 1001, "direction": "reverse"},
    {"timestamp": 3, "src_ip": "10.0.0.3", "dst_ip": "10.0.1.3",
     "protocol": "tcp", "src_port": 1003, "dst_port": 80, "direction": "forward"},
    {"timestamp": 4, "src_ip": "10.0.1.2", "dst_ip": "10.0.0.2",
     "protocol": "tcp", "src_port": 80, "dst_port": 1002, "direction": "reverse"}
  ]
}
```

响应（仅列逐事件关键字段）：

```json
{
  "rule_count": 1,
  "event_count": 5,
  "default_action": "deny",
  "session_timeout": 100,
  "max_sessions": 2,
  "results": [
    {"index": 0, "match": {"type": "rule", "rule_index": 0}, "action": "allow",
     "session_state": "new",
     "session": {"key": {"protocol": "tcp", "src_ip": "10.0.0.1",
                         "dst_ip": "10.0.1.1", "src_port": 1001, "dst_port": 80},
                 "created_at": 0, "last_seen": 0, "expires_at": 100,
                 "rule_index": 0, "established_by_event": 0},
     "evicted_session": null},
    {"index": 1, "match": {"type": "rule", "rule_index": 0}, "action": "allow",
     "session_state": "new",
     "session": {"key": {"protocol": "tcp", "src_ip": "10.0.0.2",
                         "dst_ip": "10.0.1.2", "src_port": 1002, "dst_port": 80},
                 "created_at": 1, "last_seen": 1, "expires_at": 101,
                 "rule_index": 0, "established_by_event": 1},
     "evicted_session": null},
    {"index": 2, "match": {"type": "stateful", "rule_index": null},
     "action": "allow", "session_state": "active",
     "session": {"key": {"protocol": "tcp", "src_ip": "10.0.0.1",
                         "dst_ip": "10.0.1.1", "src_port": 1001, "dst_port": 80},
                 "created_at": 0, "last_seen": 2, "expires_at": 100,
                 "rule_index": 0, "established_by_event": 0},
     "evicted_session": null},
    {"index": 3, "match": {"type": "rule", "rule_index": 0}, "action": "allow",
     "session_state": "new",
     "session": {"key": {"protocol": "tcp", "src_ip": "10.0.0.3",
                         "dst_ip": "10.0.1.3", "src_port": 1003, "dst_port": 80},
                 "created_at": 3, "last_seen": 3, "expires_at": 103,
                 "rule_index": 0, "established_by_event": 3},
     "evicted_session": {
       "key": {"protocol": "tcp", "src_ip": "10.0.0.2", "dst_ip": "10.0.1.2",
               "src_port": 1002, "dst_port": 80},
       "created_at": 1, "last_seen": 1, "expires_at": 101,
       "rule_index": 0, "established_by_event": 1
     }},
    {"index": 4, "match": {"type": "rule", "rule_index": 0}, "action": "allow",
     "session_state": "none", "session": null, "evicted_session": null}
  ],
  "summary": {
    "allowed": 5,
    "denied": 0,
    "new_sessions": 3,
    "expired_sessions": 0,
    "evicted_sessions": 1,
    "active_sessions": 2
  }
}
```

#### 错误示例（422，乱序时间戳）

时间戳必须严格递增；全部违规位置一次性列出（`previous_timestamp` 为紧邻
前一个事件的时间戳），不产生部分结果：

```json
{
  "detail": {
    "error": "out_of_order_timestamps",
    "violations": [
      {"index": 2, "timestamp": 5, "previous_timestamp": 10}
    ]
  }
}
```

#### 错误示例（422，重叠会话键）

会话 A（`1.1.1.1:1000 → 2.2.2.2:80`）仍存活时，事件 1 作为正向 allow
又试图建立一个正向键恰为 A **反向键**的会话（两个方向相反的会话将同时存活，
反向包无法确定归属），返回 422：

```json
{
  "detail": {
    "error": "overlapping_session",
    "index": 1,
    "conflict": "reverse_key_collision",
    "existing_index": 0,
    "session_key": {
      "protocol": "tcp",
      "src_ip": "2.2.2.2",
      "src_port": 80,
      "dst_ip": "1.1.1.1",
      "dst_port": 1000
    }
  }
}
```

`conflict` 另可能为 `duplicate_forward_key`（同五元组的正向会话仍存活时
重复建立；正常情况下重复正向包会先走 stateful 放行，此值为防御性兜底）。

#### curl 示例

```bash
curl -s http://localhost:8000/firewall/simulate \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [
      {"action":"allow","src_cidr":"10.0.0.0/24","dst_cidr":"10.0.1.0/24",
       "protocol":"tcp","port_start":80,"port_end":80}
    ],
    "default_action": "deny",
    "session_timeout": 30,
    "max_sessions": 10000,
    "events": [
      {"timestamp":0,"src_ip":"10.0.0.10","dst_ip":"10.0.1.20",
       "protocol":"tcp","src_port":40000,"dst_port":80,"direction":"forward"},
      {"timestamp":5,"src_ip":"10.0.1.20","dst_ip":"10.0.0.10",
       "protocol":"tcp","src_port":80,"dst_port":40000,"direction":"reverse"}
    ]
  }'
```

### `POST /ipv4/reassemble`

对同一 IPv4 数据报的若干**IP 分片**按**字节区间**重组。每个分片给出
`offset`（IPv4 片偏移字段，以 **8 字节** 为单位）、`more_fragments`（MF
标志）与标准 Base64 的 `payload`；分片承载的字节区间为半开区间
`[offset*8, offset*8 + len(payload))`。

1. **非末片对齐**：除唯一一个 `more_fragments=false` 的末片外，其余分片
   （非末片）的载荷长度必须是 **8 的倍数**，否则 **422**
   （`error="non_aligned_fragment"`，`indexes` 给出首个违规分片序号）；
   末片本身（长度由其锚定）**不要求** 8 字节对齐。
2. **末片定长**：必须**恰好一个** `more_fragments=false` 的末片；零个或
   多个均为 **422**（`error="invalid_last_fragment_count"`，多个时
   `indexes` 列出全部末片序号）。末片按
   `offset*8 + len(payload)` 确定总载荷长度。
3. **长度上限**：`header_bytes + 总载荷长度` 越过 IPv4 数据报 **65535**
   字节上限时 **422**（`error="datagram_too_large"`，`limit=65535`，
   `indexes` 给出末片序号）。
4. **重叠与冲突**：重复覆盖处字节必须**完全一致**（重传分片可接受）；
   任一重叠字节不一致即返回 `status="conflict"` 与
   `first_conflict_offset`——全部分片中**最小**的不一致字节偏移。冲突
   结论优先于缺口（即使同时存在缺口）。
5. **缺口**：无冲突但 `[0, 总载荷长度)` 未被完全覆盖时返回
   `status="incomplete"`，`missing_ranges` 为合并后的缺失**半开区间**
   `[start, end)`（按起点升序、互不相交）。
6. **完成**：覆盖完整时返回 `status="complete"`、
   `contributing_fragments`（至少贡献一个总载荷字节的分片输入序号，按
   **(字节偏移, 输入序号)** 升序；空载荷或完全落在总长度之外的分片不计
   入）与重组后完整载荷的标准 Base64 `payload`。

分片**输入顺序任意**（乱序到达照样重组）。落在末片锚定总长度之外的字节
不参与数据报重组（仅在总长度范围内做重叠校验与补全）。

#### 请求体

- `header_bytes`：IPv4 首部长度（IHL × 4），**20～60 的整数**（拒绝
  `19` / `61` / `20.0` / `"20"` / `true`），不含在重组载荷内；
- `fragments`：**1～500 个**同一数据报分片：
  - `offset`：片偏移，**8 字节单位**的非负整数（拒绝负数、`1.5`、`true`）；
  - `more_fragments`：**布尔值** `true` / `false`（拒绝 `"false"` 等字符串），
    全请求必须**恰好一个** `false`；
  - `payload`：载荷的**标准 Base64** 编码（`validate` 严格解码，空串为
    空载荷；拒绝内嵌空白、错误填充与非字母表字符）；非末片解码后长度必须
    是 8 的倍数。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `status` | `complete` / `incomplete` / `conflict` 三选一 |
| `contributing_fragments` | `complete`：贡献分片的输入序号（从 0 开始），按 (字节偏移, 输入序号) 升序；其余状态为 `null` |
| `payload` | `complete`：重组后完整载荷的标准 Base64（空数据报为 `""`）；其余状态为 `null` |
| `missing_ranges` | `incomplete`：合并后的缺失**半开区间** `[start, end)` 列表，按起点升序；其余状态为 `null` |
| `first_conflict_offset` | `conflict`：首个（最小）不一致重叠字节偏移；其余状态为 `null` |

#### 响应示例（200，complete）

乱序到达且含一片完全重发（16 字节载荷 `hello-world-ipv4`）：

请求：

```json
{
  "header_bytes": 20,
  "fragments": [
    {"offset": 1, "more_fragments": false, "payload": "cmxkLWlwdjQ="},
    {"offset": 0, "more_fragments": true,  "payload": "aGVsbG8td28="},
    {"offset": 0, "more_fragments": true,  "payload": "aGVsbG8td28="}
  ]
}
```

响应（贡献索引按字节偏移排序：offset 0 的两片 [1, 2]，末片 [0]）：

```json
{
  "status": "complete",
  "contributing_fragments": [1, 2, 0],
  "payload": "aGVsbG8td29ybGQtaXB2NA==",
  "missing_ranges": null,
  "first_conflict_offset": null
}
```

#### 响应示例（200，incomplete）

offset 0（8 字节）与 offset 2（末片 4 字节）已到，offset 1 缺失，缺口
`[8,16)`：

请求：

```json
{
  "header_bytes": 20,
  "fragments": [
    {"offset": 0, "more_fragments": true,  "payload": "AAAAAAAAAAA="},
    {"offset": 2, "more_fragments": false, "payload": "AAAAAA=="}
  ]
}
```

响应：

```json
{
  "status": "incomplete",
  "contributing_fragments": null,
  "payload": null,
  "missing_ranges": [[8, 16]],
  "first_conflict_offset": null
}
```

#### 响应示例（200，conflict）

原片覆盖 `[0,16)`，重传片位于 offset 1，其本地第 0 字节（绝对偏移 **8**）
与原片不一致；`[16,20)` 由末片补齐：

请求：

```json
{
  "header_bytes": 20,
  "fragments": [
    {"offset": 0, "more_fragments": true,  "payload": "AAAAAAAAAAAAAAAAAAAAAA=="},
    {"offset": 1, "more_fragments": true,  "payload": "QAAAAAAAAAA="},
    {"offset": 2, "more_fragments": false, "payload": "AAAAAA=="}
  ]
}
```

响应（冲突优先，即使无缺口以外的其它问题也直接返回）：

```json
{
  "status": "conflict",
  "contributing_fragments": null,
  "payload": null,
  "missing_ranges": null,
  "first_conflict_offset": 8
}
```

#### 错误示例（422，越过 65535 上限）

`header_bytes=20`，末片位于 offset 8189（字节偏移 65512）且载荷 4 字节，
总数据报长度 65536 > 65535：

```json
{
  "detail": {
    "error": "datagram_too_large",
    "indexes": [1],
    "limit": 65535
  }
}
```

其余语义错误同构：非末片未按 8 字节对齐
（`{"error": "non_aligned_fragment", "indexes": [0], "limit": null}`）、
末片数量不为一（`{"error": "invalid_last_fragment_count",
"indexes": [...], "limit": null}`，`indexes` 列出全部末片）。

#### curl 示例

```bash
curl -s http://localhost:8000/ipv4/reassemble \
  -H 'Content-Type: application/json' \
  -d '{
    "header_bytes": 20,
    "fragments": [
      {"offset": 1, "more_fragments": false, "payload": "cmxkLWlwdjQ="},
      {"offset": 0, "more_fragments": true,  "payload": "aGVsbG8td28="}
    ]
  }'
```

---

### `POST /ipv4/fragment`

**IPv4 数据报分片规划**（`/ipv4/reassemble` 的反向操作）：给定数据报载荷、
首部长度、链路 MTU 与 DF 标志，规划该数据报在此链路上发送时所需的分片
序列；也支持对**已有分片**再次切分（经可选的原始片偏移与原始 MF 描述）。

判定顺序（前两项为前置校验，均早于不超 MTU、DF 与切片分支）：

1. **非末片对齐**：`original_more_fragments=true` 表示输入本身是某个数据报
   的非末片，其载荷长度**必须为 8 字节倍数**，否则返回 **422**
   （`error=non_aligned_fragment`）；
2. **原数据报上限**：无论是否实际切片，都按
   `original_offset*8 + 载荷长度 + header_bytes` 校验原数据报的绝对结束
   位置，越过 IPv4 **65535** 字节上限时返回 **422**
   （`error=datagram_too_large`，`limit=65535`）；该约束同时保证所有输出
   `offset` 不超过片偏移字段上限 **8191**；
3. **不超 MTU**：`header_bytes + 载荷` 不超过 `mtu` 时**原样返回一个
   分片**（`unfragmented`），保留 `original_offset` 与
   `original_more_fragments`；
4. **超限且 DF=true**：返回 `needs_fragmentation`，`fragments` 为空
   （**不输出载荷**）；
5. **其余情况切片**（`fragmented`）：除最终片外，每片载荷取
   `MTU − header_bytes` 向下取整的**最大 8 字节倍数**（片偏移以 8 字节
   计，非末片载荷必须 8 字节对齐），最终片取剩余载荷（长度不要求对齐）；
   各片输出偏移 = `original_offset` + 片内字节偏移 / 8；**最后子片继承
   原始 MF**，其余子片 MF=true。

#### 请求体

```json
{
  "payload": "aGVsbG8td29ybGQtaXB2NCEhISE=",
  "header_bytes": 20,
  "mtu": 28,
  "dont_fragment": false,
  "original_offset": 0,
  "original_more_fragments": false
}
```

> `original_more_fragments=true` 的再切分请求，载荷必须为 8 字节对齐长度，
> 例如 24 字节载荷 `aGVsbG8td29ybGQtaXB2NHJlZnJhLW9r`。

- `payload`：**必填**，数据报载荷的标准 Base64（空串为空载荷）；
  `original_offset*8 + 解码后载荷长度 + header_bytes` 不得越过 IPv4
  **65535** 字节上限。
- `header_bytes`：**必填**，IPv4 首部长度，**20～60 的整数**。
- `mtu`：**必填**，链路 MTU（字节），**正整数**；需要切片时必须能容下
  一个合法非末片载荷（首部长度 + 至少 8 字节），否则 422。
- `dont_fragment`：**必填**，DF 标志（布尔值，拒绝 `"true"` / `1` 等
  非布尔输入）。
- `original_offset`：可选，原始片偏移（**8 字节单位**，0～8191 的整数），
  默认 `0`；各子片偏移在此基础上叠加；与载荷、首部合计的原数据报绝对
  结束位置不得越过 65535。
- `original_more_fragments`：可选，原始 MF 标志（布尔值），默认 `false`；
  输入本身是某数据报的非末片时为 `true`，此时载荷长度**必须是 8 的倍数**
  （否则 422 `non_aligned_fragment`），切片后最后子片继承该标志。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `status` | `unfragmented`（原样返回）/ `fragmented`（已切片）/ `needs_fragmentation`（超限且 DF=true） |
| `fragment_count` | 输出分片数；`needs_fragmentation` 为 0 |
| `fragments[]` | 分片序列，按输入顺序切片（偏移递增）；`needs_fragmentation` 为空 `[]` |
| `fragments[].offset` | 片偏移（8 字节单位），已叠加 `original_offset`，不超过 8191 |
| `fragments[].more_fragments` | MF 标志；除最后子片外恒为 `true`，最后子片继承 `original_more_fragments` |
| `fragments[].payload` | 本片载荷的标准 Base64 |
| `fragments[].total_length` | 本片 IPv4 总长度（`header_bytes` + 本片载荷字节数），不超 MTU |

输出与 `/ipv4/reassemble` 的输入同构：把 `fragments` 连同 `header_bytes`
直接提交重组即可还原原载荷。

#### 响应示例（200，fragmented）

上例中 20 字节首部 + 20 字节载荷、MTU 28：非末片载荷预算
`28 − 20 = 8` 字节，载荷切成 8/8/4 三片，偏移 0/1/2（8 字节单位）：

```json
{
  "status": "fragmented",
  "fragment_count": 3,
  "fragments": [
    {"offset": 0, "more_fragments": true,  "payload": "aGVsbG8td28=", "total_length": 28},
    {"offset": 1, "more_fragments": true,  "payload": "cmxkLWlwdjQ=", "total_length": 28},
    {"offset": 2, "more_fragments": false, "payload": "ISEhIQ==",     "total_length": 24}
  ]
}
```

#### 响应示例（200，unfragmented）

`header_bytes=20`、`mtu=1500`、`payload="aGVsbG8="`（5 字节）：数据报
25 字节不超 MTU，原样返回：

```json
{
  "status": "unfragmented",
  "fragment_count": 1,
  "fragments": [
    {"offset": 0, "more_fragments": false, "payload": "aGVsbG8=", "total_length": 25}
  ]
}
```

#### 响应示例（200，needs_fragmentation）

同样的 40 字节数据报、MTU 28 但 `dont_fragment=true`：需要分片却被
DF 禁止，不输出载荷：

```json
{
  "status": "needs_fragmentation",
  "fragment_count": 0,
  "fragments": []
}
```

#### 响应示例（200，对已有分片再次切分）

`original_offset=2`、`original_more_fragments=true`、24 字节对齐载荷、
MTU 28：非末片载荷预算为 8 字节，载荷切成 8/8/8 三片，子片偏移叠加原始
偏移（2/3/4），最后子片继承原始 MF=true：

```json
{
  "status": "fragmented",
  "fragment_count": 3,
  "fragments": [
    {"offset": 2, "more_fragments": true, "payload": "aGVsbG8td28=", "total_length": 28},
    {"offset": 3, "more_fragments": true, "payload": "cmxkLWlwdjQ=", "total_length": 28},
    {"offset": 4, "more_fragments": true, "payload": "cmVmcmEtb2s=", "total_length": 28}
  ]
}
```

#### 错误示例（422）

`original_more_fragments=true` 但载荷长度不是 8 的倍数（即使数据报不超
MTU、不实际切片也返回 422；该校验早于 DF 与 MTU 分支）：

```json
{"detail": {"error": "non_aligned_fragment", "limit": null}}
```

原数据报绝对结束位置 `original_offset*8 + 载荷长度 + header_bytes` 越过
65535（无论是否实际切片，该校验早于 DF 与 MTU 分支）：

```json
{"detail": {"error": "datagram_too_large", "limit": 65535}}
```

`header_bytes=20`、`mtu=27`：MTU 容不下一个合法非末片载荷（所需最小
MTU = 20 + 8 = 28）：

```json
{"detail": {"error": "mtu_too_small", "limit": 28}}
```

#### curl 示例

```bash
curl -s http://localhost:8000/ipv4/fragment \
  -H 'Content-Type: application/json' \
  -d '{
    "payload": "aGVsbG8td29ybGQtaXB2NCEhISE=",
    "header_bytes": 20,
    "mtu": 28,
    "dont_fragment": false
  }'
```

### 错误响应（422 Unprocessable Entity）

以下输入均返回 HTTP `422`，错误明细位于 `detail`：

- 空规则集（仅 `/analyze`）：`{"rules": []}` 或缺少 `rules`
- `/compare` 缺少 `left` / `right`，或任一侧缺少 `default_action`
- `/explain` 缺少 `query` 或 `default_action`
- `/cidrs/hierarchy` 缺少 `entries`、条目数不在 1～500、`id` 缺失/为空/
  类型非法（如 `true`、`1.5`）、**`id` 重复**或**规范化后网段重复**
  （后两者在 `detail.duplicate_ids` / `detail.duplicate_networks` 中列出
  冲突 id 与位置）
- `/cidrs/diff` 缺少 `before` / `after`、任一侧条目数超过 500、任一侧
  **`id` 重复**或**规范化后网段重复**：422 明细在
  `detail.before.duplicate_ids` / `detail.before.duplicate_networks` 与
  `detail.after.duplicate_ids` / `detail.after.duplicate_networks` 中**两侧
  分别列出**（无问题一侧为空结构），不产生部分结果；条目字段校验同
  `/cidrs/hierarchy`（两侧均允许为空 `[]`）
- `/routes/resolve` 缺少 `routes` / `targets`、路由数超过 1000、目标数不在
  1～500、**目标地址重复**（在 `detail.duplicates` 中列出规范化目标及全部
  出现位置 `indexes`）、`next_hop` / `targets` 不是严格 IPv4 地址
  （CIDR 写法、前导零、IPv6 等）、`metric` 不在 0～65535 或不是整数
- `/routes/failover` 除沿用 `/routes/resolve` 的全部校验外，还要求
  `failed_next_hops` 为 0～1000 个**唯一**的严格 IPv4 地址，重复时在
  `detail.duplicates` 中列出规范化下一跳及全部出现位置 `indexes`
- `/routes/audit` 缺少 `routes`、路由数超过 1000、`routes` 不是数组，或
  路由条目的 `cidr` / `next_hop` / `metric` 未通过与 `/routes/resolve`
  相同的严格 IPv4 / 整数校验（允许为空数组 `[]`，此时整表不可达）
- `/firewall/simulate` 缺少 `rules` / `events` / `default_action` /
  `session_timeout` / `max_sessions`、规则数超过 500、事件数不在 1～2000、
  `session_timeout` 不在 1～86400、`max_sessions` 不在 1～10000 或不是整数、
  **时间戳乱序**（非负整数且必须严格递增，全部违规位置在
  `detail.violations` 中一次性列出）、**重叠会话键**（新会话正向/反向键与
  存活会话冲突，`detail` 给出 `index` / `conflict` / `existing_index` /
  `session_key`）；**非法端口**（越界、`true` / `1.5` / `"80"` 等非整数、
  范围 `port_start > port_end`、tcp/udp 缺端口、icmp 带端口）、非法
  `protocol` / `direction` 同样 422
- `/ipv4/reassemble` 缺少 `header_bytes` / `fragments`、`header_bytes`
  不在 20～60 或不是整数、分片数不在 1～500、`offset` 为负/非整数、
  `more_fragments` 非布尔、`payload` 不是合法标准 Base64；**非末片载荷
  长度不是 8 的倍数**（`detail.error="non_aligned_fragment"`，
  `detail.indexes` 给出违规分片序号）、**末片数量不为一**
  （`detail.error="invalid_last_fragment_count"`，`detail.indexes`
  列出全部末片序号）、**首部加载荷越过 65535 字节上限**
  （`detail.error="datagram_too_large"`，`detail.limit=65535`）
- `/ipv4/fragment` 缺少 `payload` / `header_bytes` / `mtu` /
  `dont_fragment`、`header_bytes` 不在 20～60 或不是整数、`mtu` 不是
  正整数、`dont_fragment` / `original_more_fragments` 非布尔、
  `original_offset` 不在 0～8191、`payload` 不是合法标准 Base64；
  **`original_more_fragments=true` 时载荷长度不是 8 的倍数**
  （`detail.error="non_aligned_fragment"`，`detail.limit=null`）、
  **原数据报绝对结束位置 `original_offset*8 + 载荷长度 + header_bytes`
  越过 65535 字节上限**（早于不超 MTU、DF 与 MTU 分支；
  `detail.error="datagram_too_large"`，`detail.limit=65535`；该约束同时
  保证所有输出 `offset` ≤ 8191）、**MTU 容不下一个合法非末片载荷**
  （`detail.error="mtu_too_small"`，`detail.limit` 为所需最小 MTU =
  首部长度 + 8）
- 非法 CIDR：格式错误、前缀越界（`/33`）、主机位非零（`10.0.0.1/8`）等
- IPv6 地址或网段：`2001:db8::/32`、`::1` 等
- 非法 / 缺失 `action` 或 `default_action`、字段类型错误、JSON 格式错误

---

## 本地开发（不使用 Docker）

需要 Python 3.11+。

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pytest -q
```

测试覆盖：解析校验（含 IPv6 拒绝）、区间差集与合并、最少 CIDR 压缩、
三种遮蔽分类、跨动作遮蔽、顺序敏感性，`/compare` 的等价判定、顺序/默认
动作差异、双向分组与全空间压缩，`/explain` 的归因归属、默认项位置、
不重不漏覆盖，`/cidrs/hierarchy` 的最长前缀超网择父、森林稳定排序、
独占集合（仅扣直接子节点）、重复 id / 重复网段 422 与 1～500 数量边界，
`/cidrs/diff` 的新增/删除/CIDR 变更/未变分类与 before 顺序、新增项 after
顺序追加、父节点在各侧独立择父与 `parent_changed`（含与 CIDR 变更同时
发生）、对称差受影响地址数（扩张/收缩/不相交）、网段相同但 id 不同的
替换候选、任一侧重复 id / 网段 422 且两侧一次性报告不产生部分结果、
两侧为空与各 500 条边界，
`/routes/resolve` 的最长前缀优先于 metric、同前缀最低 metric 选择、ECMP
下一跳按输入顺序去重、未命中标记、逐下一跳命中汇总、重复目标 422 与
数量/metric 边界，`/routes/failover` 的四类影响归类（unchanged /
ecmp_reduced / rerouted / unreachable）、回退到更高 metric 与更短前缀、
失败下一跳整体移除其全部路由、重复失败下一跳 422 与数量边界，
`/routes/audit` 的 active/partial/shadowed 三分类、最长前缀遮蔽优先于
metric、同网段高 metric 遮蔽、同 metric 并行路由共享集合且保持输入顺序、
被更长前缀无缝完全覆盖、多层嵌套不重不漏、默认路由全空间补集、空表整表
不可达、承载/不可达/逐条生效之和等汇总不变量、422 与数量边界，
`/firewall/simulate` 的首条规则匹配（源/目的 CIDR、协议、目的端口范围、
顺序优先）、默认动作、首个正向 allow 建会话、存活期内正向后续包与反向包
stateful 放行（正/反向命中均刷新 `last_seen` 但不延长固定过期时刻）、
过期边界（含边界时刻仍存活）与惰性清理、超时后重新走规则、
反向包重放行不建会话、正向包过期重建（expired_reestablished）、拒绝不建会话、
icmp 无端口五元组、固定存活时间不被流量刷新、乱序时间戳一次性报告、反向键
重叠会话 422 且过期后建立合法、重叠检查先于容量淘汰、容量满时按
`last_seen`（最早、`established_by_event` 次序兜底）淘汰存活会话、逐事件
`evicted_session` 与 `summary.evicted_sessions`、被淘汰流后续包重新按规则
裁决、过期清出容量不淘汰、非法端口/协议/方向/存活时间/容量 422 与数量边界，
以及用标准库 `ipaddress.collapse_addresses` 作为 oracle
的随机属性测试（无损 + 最少块，并与逐地址暴力判定/逐路由暴力 LPM 对比；
failover 与“过滤失败下一跳后重新 resolve”的 oracle 交叉验证；
audit 与逐地址暴力“最长前缀 + 最低 metric + ECMP”oracle 交叉验证），
`/ipv4/reassemble` 的完整/缺口/冲突三态结论、乱序到达与贡献分片按
(偏移, 序号) 排序、重复一致覆盖接受（含部分重叠）、同偏移序号兜底次序、
首个冲突偏移取全部重叠对最小值且冲突优先于缺口、缺失半开区间合并
（首部/中间/尾部缺口与相邻区间）、非末片 8 字节对齐、末片恰好一个与
多末片下标报告、空末片零长度数据报、末片未对齐合法、65535 上限边界
（含 60 字节首部）与越界分片裁剪、非法 Base64/类型/数量 422，以及随机
分片重组与“删片后缺失区间集合”的 oracle 属性测试，
`/ipv4/fragment` 的不超 MTU 原样返回（含保留原始片偏移/MF、DF 不触发）、
恰好等于 MTU 的边界、超限且 DF=true 返回 needs_fragmentation 不输出载荷、
最大 8 字节倍数向下取整切片与 8 字节单位偏移、末片满片/余数片、
再次切分时子片偏移叠加原始偏移与末子片继承原始 MF、非末片（原始 MF=true）
载荷未按 8 字节对齐返回 non_aligned_fragment（含早于 unfragmented / DF /
越界 / mtu_too_small 各分支）、原数据报绝对结束位置越界返回
datagram_too_large（含早于 unfragmented / DF / mtu_too_small 各分支）与
65535 边界、输出 offset 不超过 8191、mtu_too_small 边界
（含 DF 优先与数据报不超 MTU 时不触发）、65535 上限边界、非法
Base64/类型/标志/偏移 422，以及与 `/ipv4/reassemble` 的随机往返重组
oracle 属性测试（含二次切分后偏移连续、仅最终子片 MF=false）。

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py    # 核心：CIDR 解析、区间差集、最少 CIDR 压缩、规则分析、等价比较、裁决归因、包含层级与网段清单差异
│   ├── router.py      # 核心：严格 IPv4 地址校验、最长前缀匹配 + 最低 metric 的 ECMP 路由解析、下一跳故障切换与整表空间审计
│   ├── firewall.py    # 核心：有序五元组规则首条匹配、正向建会话、反向 stateful 放行（last_seen 刷新）、超时惰性清理与重判、固定容量 LRU 淘汰、乱序/重叠校验
│   ├── reassembly.py  # 核心：IPv4 分片按字节区间重组、8 字节对齐/唯一末片/65535 上限校验、重叠冲突首个偏移、缺失半开区间合并、贡献分片排序
│   ├── fragmentation.py # 核心：IPv4 分片规划——非末片 8 字节对齐与原数据报绝对结束位置 65535 前置校验（输出 offset ≤ 8191）、不超 MTU 原样返回、DF 超限报 needs_fragmentation、最大 8 字节倍数切片、子片偏移叠加原始偏移、末子片继承原始 MF
│   └── main.py        # FastAPI 应用、请求/响应模型与 /analyze、/compare、/explain、/cidrs/hierarchy、/cidrs/diff、/routes/resolve、/routes/failover、/routes/audit、/firewall/simulate、/ipv4/reassemble、/ipv4/fragment 接口
├── tests/
│   ├── test_analyzer.py
│   ├── test_router.py
│   ├── test_firewall.py
│   ├── test_reassembly.py
│   ├── test_fragmentation.py
│   └── test_api.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 设计要点

- **遮蔽语义**：处理第 *i* 条规则时，遮蔽集合 = 前 *i-1* 条规则
  （allow ∪ deny）覆盖地址的并集；规则区间减去遮蔽集合即生效集合。
- **无损压缩**：剩余碎片先合并相邻区间，再以“当前地址能对齐的最大
  2 的幂块、且不越过区间末端”贪心切块，得到最少数量的 CIDR。
- **等价比较**：先为每侧构造覆盖整个 IPv4 空间的有序判定分区
  （规则生效碎片 + 未命中地址的 default_action），再以双指针归并两个
  分区，交叠处动作不同即记入对应 `(left_action, right_action)` 分组；
  分组碎片同样走“合并 + 贪心切块”。时间复杂度仅取决于区间数量，
  **不逐地址枚举**，可安全处理 `0.0.0.0/0` 全空间。
- **裁决归因**：`/explain` 复用同一套区间运算，把每条规则的生效碎片
  裁剪到 query 范围并记到该规则名下，query 内未被任何规则覆盖的剩余
  部分记为默认项；各归属集合分别做“合并 + 贪心切块”，最终按规则索引
  升序、默认项最后输出，不重不漏覆盖整个 query。
- **包含层级**：`/cidrs/hierarchy` 先按严格 IPv4 校验解析全部条目并
  检查 id 与规范化网段的唯一性；为每个网段在全部条目中选择前缀最长的
  严格超网作为唯一 parent（无同网段重复时该选择唯一），形成森林。
  节点独占集合 = 自身区间减去其**直接子节点**区间并集（孙节点已包含在
  子节点内，不重复扣除），再走“合并 + 贪心切块”得到数量最少的
  `exclusive_cidrs`；兄弟节点按 `(网络地址, 前缀长度, 输入序号)` 稳定
  排序。全程为区间运算，不逐地址枚举。
- **清单差异**：`/cidrs/diff` 复用层级接口的条目解析与“最长前缀严格超网
  择父”逻辑，在 before / after 两侧**分别独立**解析、查重并计算父节点；
  任一侧存在重复 id 或规范化网段重复时收集两侧问题后一次性抛出
  （不产生部分结果）。以 id 匹配分类新增 / 删除 / CIDR 变更 / 未变，
  父节点变化只比较同 id 匹配项（新增 / 删除为 `null`）；CIDR 变更的受
  影响地址数以闭区间长度计算对称差 `|旧| + |新| − 2×|交集|`，无需展开
  地址。网段相同但 id 不同的配对通过“after 网段 → 条目”索引在一次 before
  扫描中得到（两侧网段各自唯一，故每个网段至多一对）。输出先按 before
  顺序、再追加 after 顺序的新增项，排序不依赖任何哈希遍历次序。
- **路由解析**：`/routes/resolve` 先把路由 CIDR 解析为 32 位整数区间，
  对每个目标线性扫描，仅以区间包含判断命中，先取前缀长度最大者（LPM），
  再在其中取 metric 最小值并保留全部并列路由；其 next_hop 按 routes 输入
  顺序去重得到 ECMP 列表。命中计数只随目标遍历累加（同一 ECMP 结果的
  每个下一跳各计一次），汇总按 next_hop 首次出现的路由序号排序。
  复杂度为 O(路由数 × 目标数) 的整数比较，**不逐地址展开网段**。
- **故障切换**：`/routes/failover` 复用同一套解析流程跑两遍——完整路由表
  得到 `before`，剔除失败下一跳对应的全部路由后重新解析得到 `after`
  （因此可回退到更高 metric 或更短前缀，而非收缩原 ECMP 列表）；逐目标
  比较归类 `impact`：两侧均不可达或结果一致为 `unchanged`，同网段同
  metric 但下一跳减少为 `ecmp_reduced`，仍可达但网段或 metric 改变为
  `rerouted`，原本可达而后不可达为 `unreachable`。
- **整表审计**：`/routes/audit` 先按规范化网段把路由分组（保持首次出现
  顺序）并求每组最低 metric；每个网段的生效集合 = 自身闭区间减去**全部
  更具体网段**（严格包含它的更长前缀）并集——同前缀长度的不同 IPv4 CIDR
  必然不相交，故只需区间包含判断。集合经“合并 + 贪心切块”得到无损最少
  CIDR；同网段同最低 metric 的并行路由直接复用同一份区间与 CIDR 结果
  （ECMP 共享），其下一跳按输入顺序去重；高 metric 同网段路由状态为
  `shadowed`、生效集合置空，但仍返回该组下一跳以便定位遮蔽来源。整表
  承载地址数由所有网段生效碎片再做一次并集合并得到（ECMP 与嵌套都不重复
  计数），其补集即不可达地址数。复杂度为 O(网段数²) 的区间运算，
  不逐地址枚举。
- **有状态防火墙**：`/firewall/simulate` 复用现有严格 IPv4 解析
  （`parse_cidr_v4` / `parse_address_v4`），把规则预处理为协议号 + 整数
  地址区间 + 端口范围，事件预处理为整数五元组。会话以**正向**五元组为键，
  反向包经地址/端口对调后用同一个键查表，因此无需独立反向索引；每个事件
  处理前以 `expires_at < 当前时间戳` **惰性清理**过期会话（边界时刻仍存活，
  固定时长不随流量刷新），清理按会话记账到 `expired_sessions`，并保留最近
  过期会话以区分 `expired` 与 `none`。存活会话命中（正向或反向）即
  `stateful` 放行，并把会话 `last_seen` 刷新为当前事件时间（新会话
  `last_seen` 等于建立时间；不改变 `expires_at`）；否则按顺序线性扫描规则
  做整数包含 + 端口比较，未命中取默认动作；仅正向 allow 建立会话，建立前
  先检查正向键（重复建立）与反向键（两个反向会话同时存活的歧义）是否撞上
  存活会话，重叠即报错、不产生部分结果。会话表容量固定为 `max_sessions`：
  通过重叠检查、确认可建会话后若容量已满，按
  `(last_seen, established_by_event)` 升序选出唯一存活会话淘汰——事件时间
  严格递增使 `last_seen` 跨会话不可能相等，后者为防御性兜底次序；被淘汰
  会话逐事件记入 `evicted_session` 并按会话累计到 `summary.evicted_sessions`，
  随即从会话表移除，该流后续包像从未建过会话一样重新走规则。时间戳严格
  递增的违规在解析阶段一次性收集后抛出，不产生部分结果。
- **分片重组**：`/ipv4/reassemble` 复用 `merge_intervals` /
  `subtract_covered` 区间工具：逐片把 8 字节单位偏移换算为字节半开区间，
  先做**唯一末片 → 非末片 8 字节对齐 → 65535 上限**的语义校验（顺序固定，
  无末片即无从锚定长度）。重组时以一个字节缓冲加每字节“首个写入分片”
  归属数组单次扫描完成：重复覆盖逐字节比较，一致即接受、不一致则更新
  最小冲突偏移；扫描结束后冲突优先返回，否则把各片区间归并求其在
  `[0, 总载荷长度)` 的补集（闭区间差集再转半开），有缺口返回
  `incomplete`，无缺口才输出 `complete` 与 Base64 载荷。贡献分片按
  `(字节偏移, 输入序号)` 排序，空载荷与完全越界（落在末片锚定末尾之后）
  的分片不计入；部分越界分片按总长度裁剪其贡献与重叠校验范围。
- **分片规划**：`/ipv4/fragment` 复用 reassembly 的 `decode_payload` 与
  首部/数据报上限常量。先校验首部长度、MTU、标志与原始片偏移，随后做
  **非末片 8 字节对齐（原始 MF=true）→ 原数据报绝对结束位置
  `original_offset*8 + 载荷长度 + 首部长度 ≤ 65535`** 的语义校验（二者均
  早于不超 MTU、DF 与切片分支；后者同时保证所有输出 offset ≤ 8191），
  再按“不超 MTU 原样返回 → DF 超限返回
  `needs_fragmentation`（不输出载荷）→ 切片”的固定顺序判定。切片预算为
  `MTU − 首部长度` 向下取 8 的倍数（非末片载荷的对齐要求），不足 8 字节
  即 `mtu_too_small`（`limit` 为所需最小 MTU = 首部长度 + 8）；随后顺序
  切块，块内字节偏移换算为 8 字节单位后**叠加原始片偏移**，最后一块
  **继承原始 MF**、其余 MF=true。输出与 `/ipv4/reassemble` 输入同构，
  可直接往返重组。
- **整数运算**：全部基于 32 位无符号整数区间处理，避免字符串/对象开销，
  可正确支持 `0.0.0.0/0` 全空间等边界场景。
