# Agent Authz（中文）

> **公开 Beta — GitHub Release · Python 3.11+ · Apache-2.0**

## 同一个业务操作，在真正执行的位置做一次授权检查

在 FastAPI 路由、Python Agent Tool、MCP v2 Tool、检索边界或后台任务执行前，
为同一个 SaaS 业务操作做最终允许/拒绝判断。

Agent Authz 是嵌入式 Python 授权 PEP。你的服务提供已经验证的身份，以及来自
可信数据源的租户和资源事实；Authz 将已登记的入口映射为一个业务操作，并在执行
边界进行授权判断。可以使用内置决策器，也可以保留已有策略后端。

它**不是** PDP、关系数据库、身份系统、向量数据库、Agent 框架或托管控制平面。
只有显式登记并实际路由经过 Authz 的路径才会受到保护；它不会自动发现漏接的路径。

**适合使用它的场景：**同一个业务操作跨 API、Agent Tool、MCP、RAG 或任务边界，
且需要对同一条可信资源做一致的最终决策。**应与专用 PDP 或关系数据库搭配使用的场景：**
需要策略分发、tuple 写入、全局一致性或托管控制平面。

~~~
已验证身份  →  业务操作  →  可信资源  →  决策
~~~

## 安装并验证

在明确启用 PyPI 发布前，请使用经过校验的 GitHub Release wheel，不要依赖
未验证的包名。下载 wheel 时一并下载校验和：

~~~bash
gh release download v0.7.0b1 --repo FrankPlusPlus/agent-authz \
  --pattern 'agent_authz_sdk-0.7.0b1-py3-none-any.whl' --pattern WHEEL-SHA256SUMS
shasum -a 256 -c WHEEL-SHA256SUMS
gh attestation verify agent_authz_sdk-0.7.0b1-py3-none-any.whl \
  -R FrankPlusPlus/agent-authz
python -m pip install --no-deps agent_authz_sdk-0.7.0b1-py3-none-any.whl
~~~

若希望透明地审查源码并运行完整证明，可使用该 release tag 做开发和源码审查。Git tag
不是按内容寻址的发布证明；部署发布物时仍应先验证上面的 release wheel：

~~~bash
git clone --branch v0.7.0b1 https://github.com/FrankPlusPlus/agent-authz.git
cd agent-authz
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python examples/secure_document_agent.py
~~~

这个无依赖示例会断言：

- API 与 Tool 对同一条已授权业务操作允许访问；
- 直接调用未授权 Tool 会被拒绝；
- 跨租户请求会被拒绝；
- 未授权检索候选不会进入 prompt；
- 最终执行 Permit 只能被消费一次。

若在开发或源码审查中以审查过的 tag 作为源码依赖安装（不作为发布完整性证明）：

~~~bash
python -m pip install "agent-authz-sdk @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b1"
~~~

**从这里开始：** [保护 MCP Tool](../mcp.md) ·
[接入 FastAPI 路由](../frameworks.md#fastapi) ·
[支持范围](#支持范围) · [Beta 边界](#beta-边界) ·
[English](../../README.md)

## 它解决什么问题

同一个 "document.publish" 可能同时从 HTTP 接口、Agent Tool、MCP 服务、后台任务
和检索工作流进入系统。框架 hook 能方便地为某一个入口加检查，但无法天然保证所有
入口都对同一条可信资源问同一个业务问题。
这里的 **entrypoint（执行入口）** 就是这些实际执行面：路由、callable Tool、MCP Tool、
检索边界或后台任务。

~~~
POST /documents/{id}/publish ─┐
tool: publish_document         ├─ document.publish ─ 可信文档 ─ 决策
mcp: publish_document          │
task: publish_scheduled        ┘
~~~

Agent Authz 用下面的契约解决这种权限漂移：

- Catalog 将一个业务操作映射到已登记的入口。
- ResourceRegistry 从业务数据源加载租户、成员关系、owner/viewer 等事实，不信任
  请求 JSON、模型输出或 Tool 参数里的关系字段。
- API、Python callable Tool、MCP、RAG、任务共用同一份
  AgentRequest → Decision 合同。
- CoverageManifest 可在 CI 中检查**已声明**的最终 guard 和数据边界；它是治理清单，
  不是自动扫描所有旁路的安全证明。
- Permit、审计事件、候选过滤为高风险边界提供明确原语，但不假装是分布式控制平面。

## 推荐的五分钟安全接入

请求只提供资源坐标；你的 loader 负责资源的租户和关系事实。这是生产服务应该先走的
路径。

~~~python
from authz_sdk import Authz, Catalog, PolicySet, ResourceRegistry, Subject

catalog = Catalog()
catalog.resource(
    "document",
    actions=("read",),
    relations=("viewer",),
    tenant_required=True,
)
policies = PolicySet()
policies.bind(
    id="document_viewers_read",
    operation="document.read",
    template="relation",
    relations=("viewer",),
)

rows = {
    "doc-1": {
        "tenant_id": "acme",
        "viewers": {"alice"},
        "body": "季度计划",
    }
}
resources = ResourceRegistry()
resources.register(
    "document",
    lambda document_id, subject, _context: (
        {
            "id": document_id,
            "attributes": {"tenant_id": rows[document_id]["tenant_id"]},
            "relations": {"viewer": subject.id in rows[document_id]["viewers"]},
        }
        if document_id in rows
        else None
    ),
)

authz = Authz.production(catalog, policies, resources)
assert authz.can(
    Subject(id="alice", tenant_id="acme"),
    operation="document.read",
    resource_type="document",
    resource_id="doc-1",
).allowed
~~~

然后把同一个业务操作挂到最终执行 guard：

~~~python
from authz_sdk import AgentRuntime, protect_tool

runtime = AgentRuntime(authz)

@protect_tool(
    runtime=runtime,
    operation="document.read",
    subject=lambda call: call.kwargs["subject"],
    resource_type="document",
    resource_id=lambda call: call.kwargs["document_id"],
)
def read_document(*, subject, document_id):
    return rows[document_id]["body"]
~~~

## 支持范围

| 能力面 | 状态 | 你可以依赖什么 | 明确边界 |
| --- | --- | --- | --- |
| Native core + Authz.production | 可用 | 进程内决策、严格 Catalog、可信资源和租户检查 | 宿主负责认证和数据查询正确性 |
| FastAPI | 可用，可选依赖 | 路由处理器执行前的 dependency guard | 宿主提供验证后的请求身份 |
| MCP Python SDK v2 | Beta，可选依赖 | 已登记 Tool callable 执行前的最终 guard | 不包含 MCP OAuth、同意、限流或动态 tools/list 过滤 |
| Agno / LangGraph | 基础 callable wrapper | Tool/node 执行前的 guard | 不是原生框架插件；未覆盖 checkpoint、handoff、streaming |
| Casbin | 可用，可选依赖 | 在统一 contract 后复用已有 enforcer | Casbin 继续拥有模型和策略存储 |
| OPA / Cerbos | 实验性 starter transport | 远程决策的 PoC | 不是官方/完整 client；没有异步连接池、重试或控制平面 |
| OpenFGA / SpiceDB | 实验性；生产环境必须静态显式映射 | 远程 relation/permission 检查的 PoC | 宿主把业务操作映射为合法 relation/permission，并负责模型/版本语义 |
| RAG CandidateFilter | 可用原语 | 候选进入 prompt 前过滤 | 不会自动做 SQL/向量 pushdown，也无法证明每个检索路径都已接入 |
| Pack 与后台任务 | 手动 contract | 宿主可映射并检查相同业务操作 | SDK 不负责执行、发现或自动覆盖 |
| 托管 PDP / 关系图 / 控制平面 | 未提供 | — | 使用外部系统 |

~~~mermaid
flowchart LR
    I["已验证身份<br/>(宿主认证)"] --> G["Agent Authz guard<br/>入口 → 业务操作"]
    E["FastAPI 路由 · Agent Tool · MCP Tool"] --> G
    G --> R["ResourceRegistry<br/>(宿主数据：租户 + 关系)"]
    R --> P["Native policy<br/>或已有 PDP"]
    P -->|允许| S["业务 API 或 Tool 副作用"]
    P -->|拒绝| D["403 或 Tool 错误"]
~~~

## Beta 边界

Authz 在自己作出决策时采用 fail-closed；但宿主应用仍必须：

- 验证调用者身份，并传入请求级 Subject；绝不能从 Tool 参数或不可信 header 推导身份。
- 通过 ResourceRegistry 从可信存储加载 owner、成员关系和租户事实。
- 将最终 guard 放在副作用前，并在业务需要时在事务内复查资源版本/状态。
- 让所有相关 API、Tool、MCP、检索和任务路径经过 guard；未登记路径不在 SDK 的视野内。
- 根据实际风险配置持久审计、共享原子 PermitStore、查询 pushdown、密钥管理和故障策略。

安全敏感场景请先阅读[威胁模型](../threat-model.md)、
[生产指南](../production.md)和[安全策略](../../SECURITY.md)。

## 更多文档

- [Quickstart](../quickstart.md) — Catalog、策略绑定与可信 loader
- [架构](../architecture.md) — 执行合同与信任边界
- [Agent Runtime](../agent-runtime.md) — discover、mount、execute 与 Permit
- [框架集成](../frameworks.md) — FastAPI、LangGraph、Agno 风格 guard
- [MCP v2](../mcp.md) — 已验证身份和 Tool 集成
- [后端适配](../backends.md) — Remote PDP 边界与 operation mapping
- [Coverage Manifest](../coverage.md) — 已声明入口的 CI 证据
- [迁移指南](../migration.md) — 不重写全系统的渐进接入
- [对比与定位](../comparison.md)
- [English README](../../README.md)

## 路线图与贡献

下一阶段不是再发明一种策略语言，而是让安全路径更省心：框架 inventory、可观测的
remote PDP contract、持久 reference store、query-pushdown interface，以及真实后端
conformance suite。见 [ROADMAP.md](../../ROADMAP.md)。

提交 PR 或使用发布物前，请阅读 [CONTRIBUTING.md](../../CONTRIBUTING.md)、
[SECURITY.md](../../SECURITY.md) 和 [SUPPLY_CHAIN.md](../../SUPPLY_CHAIN.md)。

## 协议

Apache-2.0，见 [LICENSE](../../LICENSE)。
