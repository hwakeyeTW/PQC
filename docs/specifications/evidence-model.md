# PQC Evidence Model V1.0.0

**Contract:** PQC-M1-01 / Issue #10 / R1. Product release V2.0, schema
`1.0.0`, collector version and rule version are independent. This is the
controller-side contract, not a collector, taxonomy, rule engine or release QA.

## 1. Boundaries and data flow

`Collector -> normalized evidence -> assessment -> Report/Portal`.
保存 evidence 後可離線重新評估，不需重新連線主機。#6 提供原始
`target_id`；#7 提供 policy 狀態；#8 提供固定 target manifest 和 host 終態；
#9 負責 run ID、可信 namespace 的本機配置、安全儲存及發布。
#11 負責 taxonomy/rules；#12 負責 legacy importer；#13 CFF、#26 CBOM
projection 與 schema conformity；#14–18 等 collector 另行實作。
本包不觸發任何掃描、Active、安裝、設定修改、報告發布或資料外傳。

本地 `schemas/evidence.schema.json` 為 JSON Schema draft 2020-12，logical
`$id = urn:pqc:evidence:1.0.0`，所有 `$ref` 只指向同文件 `$defs`。
`tools/evidence.py` 為純 Python stdlib library；不從資料指定 schema、檔案、
URL、命令、template 或動態 import。V1 只接受 exact `1.0.0`，未知版本、
欄位及 evidence kind 拒絕；未來需明示新版本及 migration，不默默降級。

## 2. Envelope / registry

所有 registry arrays 必須存在。`[]` 只表示這個 registry 沒有記錄，
不代表無資產、成功掃描或安全。每個 object 都是 closed shape。
下列欄位必填（`?` 代表可省略；nullable 必須填 null 或有效值）。

| Registry | Fields and purpose |
| --- | --- |
| run | `run_id`, `run_state`, `recorded_at`, nullable `started_at`/`finished_at`, `source`, unique `expected_host_ids`, optional `scope_reason`/`coverage_reason`. `recorded_at` 是記錄/匯入時間，不是取得時刻。 |
| hosts | `host_id`, nullable literal `target_id`, `identity_scope`, `host_state`, `reason_code`, nullable `inventory_authority_id`/`identity_key`。Stable host 必有 namespace 及 exact target；run-local host 必有 local key，namespace=null。 |
| collections | `collection_id`, `host_id`, `collector_id`, nullable `collector_version`, `scope_key`, `collection_state`, `reason_code`, `source`, nullable `observed_at`, unique `evidence_ids`。每 run/host/collector/scope 唯一。Native/synthetic collector 與 source producer ID/version 一致；成功或部分取得及 N/A 需已知版本。未執行的 collector 可尚無版本。 |
| assets | `asset_id`, `host_id`, `asset_kind`, `identity_scope`, `identity_key`, unique `evidence_ids`。initial kinds: `platform`, `package`, `library`, `certificate`, `public_key`, `application`, `service`, `unknown`；kind 為可擴展 lowercase slug，未知類別本身不代表分類成立。 |
| evidence | `evidence_id`, `host_id`, `collection_id`, nullable `asset_id`, `observation_key`, `evidence_kind`, `source`, nullable `observed_at`, typed `data`, nullable `algorithm`; optional nullable `evidence_ref`/`raw_sha256`。 |
| claims | `claim_id`, `subject`, `claim_key`, `level`, `assessment_state`, `rule_id`/`rule_version`, `reason_code`, unique `evidence_ids`, nullable `conditions` (L4/L5 mandatory). |
| findings | `finding_id`, `subject`, `condition_key`, `rule_id`/`rule_version`, `assessment_state`, `reason_code`, unique `claim_ids`/`evidence_ids`。 |

`subject` = `host_id` + optional nullable `asset_id`/`algorithm_id`。缺省或
null 表示不指定該維度，不是可隨意跨 asset 匯集的 wildcard。
未指定 asset 的主張須使用 host-scope evidence。指定 algorithm 時 evidence
必須具相同 `algorithm_id`。引用 claim 的 finding 必須同 subject、rule ID
及 rule version。Asset/collection 的 evidence 列表與 evidence 的 parent
指標均一致；除了這些明示雙向索引，引用方向為 finding -> claim/evidence
-> asset/collection -> host，無任意 graph 遞迴。不能跨 host、捏造關聯、
引用不存在記錄、以其他資產或 rule 的 evidence 支持本主張。

`source` 固定欄位：`source_kind` (`NATIVE_COLLECTOR`, `LEGACY_IMPORT`,
`SYNTHETIC`), `producer_id`, nullable `producer_version`, `origin_ref`, nullable
`input_sha256`。Evidence source 與 collection 的 kind/producer/version 一致；
origin/hash 可因個別原始資料而異。Native 及 synthetic evidence 有實際取得
時刻（synthetic 是 fixture 時刻）；legacy unknown 保持 null。Run 與子記錄
不可混用 synthetic 和非 synthetic source。`SYNTHETIC` 僅工程測試；
標記不是現場證明或信任簽章。雜湊只在已核原 bytes 時填寫；不由 validator
讀取/解析 ref 或聲稱已查核原件。

## 3. Typed observations and algorithms

所有 data fields 在下表必填；`?` 不代表省略，而表示 value 可以 null。
非空 bounded text 只用允許的單一 normalized scalar，不是 raw dump。

| evidence_kind | data fields |
| --- | --- |
| PLATFORM_INFO | `os_family?`, `os_version?` (text) |
| PACKAGE_INVENTORY | `name`, `version?` (text), `present?` (bool); library installation inventory 同樣可用本 kind |
| RUNTIME_CAPABILITY | `capability` (slug), `supported?` (bool); 實際 runtime 能力 |
| EFFECTIVE_CONFIGURATION | `setting` (slug), `effective_value?` (text), `allowed?` (bool); effective permission 不從版本/policy 字串推導 |
| AUTHORIZED_NEGOTIATION | `conditions` (下節 L4 context), `outcome` = NEGOTIATED / REJECTED / UNKNOWN / ERROR / TIMEOUT |
| OBSERVED_USAGE | `conditions` (下節 L5 context), `outcome` = OBSERVED / CONTRADICTED / UNKNOWN |
| ASSET_METADATA | `name?`, `version?` (text), 不是 readiness assertion |
| COLLECTION_SUMMARY | `scope` (logical key), `attempted?` (bool), `coverage` = COMPLETE / PARTIAL / UNKNOWN, `observation_count?` (nonnegative integer), `applicable?` (bool) |
| LEGACY_OBSERVATION | `field` (slug), `value` (bounded text, exact integer, bool, null); 不視為直接 readiness assertion |

`algorithm` = null 或 `{algorithm_id, family, primitive, observed_name,
taxonomy_version}`。`algorithm_id`, `observed_name`, `taxonomy_version` 未知
時可 null。Family: CLASSICAL / PQC / HYBRID / UNKNOWN；primitive: KEM / KEX /
SIGNATURE / PUBLIC_KEY / SYMMETRIC / UNKNOWN。#11 才提供演算法 ID、alias、
分類和 readiness rules；本包不從任何字串自動推論。TLS cipher suite != KEX；
cert public key != signature；SSH client capability != server effective config
!= negotiation；FIPS 狀態獨立，不等於 PQC。無法關聯用 null/UNKNOWN，
不把 unknown 證據補成 false 或 merge by name。

## 4. ID-V1 and canonical representation

`derive_id(kind, components)` = `prefix + sha256(UTF8(canonical JSON array
["pqc-id-v1", kind, ...components]))`，完整 64 lowercase hex。JSON compact
separators `,`/`:`，UTF-8 Unicode 不轉義、不 trim、不 casefold、不正規化
Unicode。不以分隔符串接、timestamp、array index、隨機數、輸出路徑或
ansible_host 代替識別。Components 是非空有界 literal strings；nullable
subject part 用 JSON null tag（不能單獨當 identity），不得用 bool/int
冒充字串。Typed helpers 精確驗證相應欄位。

| Kind / prefix | Ordered components after kind |
| --- | --- |
| host / h- | stable: STABLE, inventory_authority_id, exact target_id; run-scoped: RUN_SCOPED, run_id, identity_key |
| asset / a- | stable: STABLE, host_id, asset_kind, identity_key; run-scoped: RUN_SCOPED, run_id, host_id, asset_kind, identity_key |
| collection / c- | run_id, host_id, collector_id, scope_key |
| evidence / e- | run_id, host_id, collection_id, observation_key |
| claim / cl- | run_id, host_id, nullable asset_id, nullable algorithm_id, level, rule_id, claim_key, context parts below |
| finding / f- | host_id, nullable asset_id, nullable algorithm_id, rule_id, condition_key |

Run ID 由 #9 提供（`[A-Za-z0-9][A-Za-z0-9_-]{0,63}`），不由本包生成。
`target_id` 為 #6 literal `inventory_hostname`，保留大小寫及原空白，不以
IP/address 代替；stable namespace 是可信、非秘密的 opaque token。
Legacy 缺可信 namespace/identity 採本 run 明確唯一 local key，不能猜同
一 host；不同 run 之 host/asset/finding 不等同。Stable asset 必須 stable host
且已有實證、具證實的 logical identity；unknown kind 必須 RUN_SCOPED。
同 host 的不明資產亦不得用演算法/共享名稱當作穩定 identity。Collector/
importer 負責供應可信、非位置/array index 的 key；validator 重算 ID 並拒
絕重複/衝突，不能替代來源真實性。版本不藏在 collector/rule ID；rule
語義變更須新 rule ID 或明示 migration。

`canonical_bytes(document)` 驗證後將 registry arrays 依 ID 排序，reference
sets / expected host IDs sorted unique（duplicate 先拒絕而不是去重），
object keys sorted，UTF-8 compact JSON，無尾端換行；保持原 document 不變。
保留有語義的 values、原時間字面、legacy scalar types。穩定 ID/hash
不是匿名化；真實主機名/ID、namespace、原報告不能上傳公開 Repo。

## 5. Independent acquisition / assessment / claim states

| Dimension | States / meaning |
| --- | --- |
| run | PLANNED / COMPLETE / PARTIAL / ERROR。COMPLETE 有非空且全 COMPLETE expected hosts；PLANNED hosts 必須 NOT_ATTEMPTED。不是安全評分或完整 asset coverage。 |
| host | COMPLETE / PARTIAL / ERROR / UNREACHABLE / NOT_ATTEMPTED。Expected host manifest 與 registry 完全相等，不因無報告刪除 host。NOT_ATTEMPTED 不視為 UNREACHABLE。 |
| collection | COLLECTED / PARTIAL / UNKNOWN / NOT_SCANNED / NOT_APPLICABLE / PERMISSION_DENIED / ERROR / UNREACHABLE。 |
| assessment | PASS / FAIL / PARTIAL / UNKNOWN / NOT_SCANNED / NOT_APPLICABLE。 |

Collection COLLECTED 必須有實證；成功空集合須具 `COLLECTION_SUMMARY`：
`attempted=true`, `coverage=COMPLETE`, `observation_count=0`, `applicable=true`。
每個 COLLECTION_SUMMARY 的 `data.scope` 必須與其 parent collection 的
`scope_key` 完全相等（含大小寫）；V1 不推論父子、substring 或 aggregate
關係。不同 scope 分段各自記錄；錯配文件以 SCOPE_MISMATCH 拒絕，不能
借用其他 scope 支持 COLLECTED、PARTIAL、N/A 或相關 claim/finding。
Count 是具名 scope 的 producer observation count，不等同 evidence registry
大小。未知 coverage/count 或無資料不得當作成功空集合。PARTIAL 需已知
部分實證及具名 gap reason；N/A 必有 `applicable=false` applicability summary
及理由，不能由 empty 推導。N/A summary coverage=UNKNOWN、count=null。
NOT_SCANNED 僅明確原因（DISABLED_BY_USER / DISABLED_BY_PROFILE / PLAN_ONLY /
AWAITING_COLLECTOR / ADAPTER_NOT_AVAILABLE / ACTIVE_NOT_AVAILABLE_V2_0 /
NOT_ATTEMPTED）且無取得 evidence。#7 policy VALIDATED/DENIED/DEFERRED
不是 assessment。NOT_ATTEMPTED host 只能有 NOT_SCANNED collections；
UNREACHABLE host 不標 COLLECTED。Tool missing/permission denial/command
error/timeout/unreachable 與算法 FAIL 分開。Legacy 缺欄不是 disabled。

PASS/FAIL 需具名 rule/version 及同 subject 的 actual supporting/direct
counterexample evidence，來源 acquisition 必 COLLECTED/PARTIAL；不得
以 collector failure、metadata、版本、empty、absence of evidence 推論。
PARTIAL 需已知實證與缺口；UNKNOWN 可保留不完整資料；NOT_APPLICABLE
需同 subject applicability evidence；NOT_SCANNED 無取得 evidence。
Finding 可連接同 rule/version/subject 的同 verdict claim，或連接規則所用
的 explicit boolean/actual outcome observation（非單純 metadata）；
validator 只檢查結構與可追溯性，**不執行 #11 的規則或決定 finding polarity**。
同一 decisive claim 不能同時引用同 level/context 的相反實證；有矛盾需
分條件或保留 PARTIAL/UNKNOWN，不自動選擇一個結果。

| Level | Required direct observation for PASS/FAIL |
| --- | --- |
| L1 Installed | PACKAGE_INVENTORY `present=true/false`，不是 name/version 存在 |
| L2 Supported | RUNTIME_CAPABILITY `supported=true/false`，不是 package 推論 |
| L3 Configured | EFFECTIVE_CONFIGURATION `allowed=true/false`，不是宣告或 policy 字串 |
| L4 Negotiable | AUTHORIZED_NEGOTIATION、同具名 service asset/context、實際 NEGOTIATED/REJECTED 結果及已知 algorithm_id/primitive。ERROR/TIMEOUT/UNKNOWN 不能支持 PASS/FAIL |
| L5 Observed in Use | OBSERVED_USAGE、實際業務觀察來源/方法、有效時間區間、service/algorithm 關聯，OBSERVED/CONTRADICTED 是實際正例/直接反例（不是未觀察到） |

L1–L5 各自獨立；沒有固定遞進、反推或百分比。L1–L3 conditions=null。
L4 conditions 有固定順序 `host_id, service_asset_id, endpoint_ref, protocol,
context_ref, authorization_ref`，protocol TLS/SSH；logical authorization ref
只作來源追溯，不簽發授權。L5 conditions 固定順序 `host_id, service_asset_id,
business_source_ref, method, started_at, finished_at`，method 為
APPLICATION_TELEMETRY / PASSIVE_SESSION_OBSERVATION / SERVICE_AUDIT_RECORD。
方法 enum 是 V1 初始可接受的業務觀察種類；新增方法需明示 schema version
contract。Probe/協商本身不算業務使用。Claim context 必須與 evidence 的
context 完全相同，實際結果在 `data.outcome`，algorithm/primitive 在
`evidence.algorithm`。Service asset、host、algorithm 與 subject 一致。
L4/L5 反例同樣須具實際條件與結果；timeout/error 或 probe-only 非反例。
實際 OBSERVED_USAGE（OBSERVED 或 CONTRADICTED）須符合 `started_at <=
finished_at`、`started_at <= evidence.observed_at <= run.recorded_at` 及
`finished_at <= run.recorded_at`（精確 UTC 比較，保留九位小數秒）。允許
區間內觀察或事後取得／匯入，不要求 observation 與記錄時刻相等，也不
從單次觀察推定整段連續使用。時間矛盾以 USAGE_TIME_ORDER 拒絕（逆序
區間仍為 TIME_ORDER），不支持任何 claim/finding。UNKNOWN 不提供
實際使用正反證；不增加 L4 或其他 evidence kind 的一般時間限制。
V2.0 僅 synthetic L4/L5 語義測試，真實 Active 由 #36–38 另行授權。

## 6. API / validation / safety

```python
from tools.evidence import parse_evidence_bytes, validate_document, canonical_bytes
# raw: trusted caller already acquired bytes; do not give this API a path/URL.
document = parse_evidence_bytes(raw)
validate_document(document)   # returns None; raises EvidenceError on invalid
canonical = canonical_bytes(document)
```

`EvidenceError.code` + `.location` 是固定 model field/index；未知 key、raw
values、credentials、paths 不寫入錯誤訊息。拒絕 duplicate JSON keys、
invalid UTF-8/BOM、NaN/Infinity、非有限值、wrong types（含 bool-as-int、
float-as-int）、unknown enum/field/version、bad timestamp、control chars、
invalid refs、duplicate identities/members、dangling/cross-host refs。
Raw UTF-8 及 canonical representation 上限 32 MiB，最大深度 64；超限拒絕、
無截斷。ID component / normalized text 上限 512 chars、ASCII slugs/refs
128 chars、reason codes 96 chars；ref token 無 slash、colon、percent escape，
不是 URI/path。Logical keys 禁止 path-like separators/prefixes，保持其餘
字面。UTC timestamps 接受 Z 或 +00:00，fraction 1–9 digits；calendar
invalid/leap-second/unknown offset 拒絕。Counts 及 legacy integer 使用
JSON interoperable safe-integer 範圍，count nonnegative。這些為 R1 的有界
model-specific 初始表示；需求擴充經核准版本化，不靜默截斷。

Schema 與專用 Python validator 共用 model-specific field declarations；
`model_schema()` 只回傳本地 schema 物件以供開發交叉核對，不是通用
JSON Schema interpreter。JSON Schema 約束 shape/type/enum/pattern、
required/closed objects/conditional variants；Python 另做 strict JSON lexical
檢查、Unicode control/format/surrogate、calendar/size/ID、references 及
cross-record semantics。標準 JSON Schema 對 1.0 和 1 的 integer 語義不同；
本 runtime 不接受 float-as-int。標準工具須啟用 date-time format checker；
純 schema 合規不等於完整 model validation。

禁止 raw hostvars、command dump、private key、credential、blob、file URL、
任意未型別化 object。Validator 非 DLP；允許的 scalar 仍可能敏感，producer
須依 #2 最小允許欄位、正規化、脫敏、私有儲存和來源核驗。不要用真實
報告或環境資料做 public fixtures。#9 私有存放及 atomic publish 尚未實作。

## 7. Legacy migration and QA handoff

V1 固定 exact version；未來明示 adapter/migration，不自動 coercion。#12
依 #3 已確認來源 per-host / upstream (`generated_at`, `total_hosts`, `hosts`)
/ local fleet (`selected_hosts`, `successful_hosts`, `hosts_without_report`,
`selected_count`, `completed_count`, `reports`) 逐欄映射、核對 counts/sets。
Decimal string 和 integer 保留來源型別並由 importer 明確判定語義；不從
HTML 補 JSON，不繼承舊 risk/score 為新 verdict。缺來源/版本/hash/時刻
保持 null/UNKNOWN；未取得 legacy 欄位不得推定 disabled 或成功空集合。
本包不實作 migration/legacy parsing、rule evaluation、CFF/CBOM conversion。

R4 工程檢查 E01–E05 僅此 module 合成資料：

```sh
python3 -m py_compile tools/evidence.py tests/unit/test_evidence.py
python3 -m json.tool schemas/evidence.schema.json >/dev/null
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q -rs -p no:cacheprovider tests/unit/test_evidence.py
```

現有可用 `jsonschema` 僅為 optional development cross-check：
Draft202012Validator.check_schema + 同 shape fixtures + format checker，
缺套件記 NOT_TESTED，不從網路安裝。Runtime 不依賴 jsonschema/pytest。
實際 Controller、OL 9.7/9.8/9.9、跨 collector/importer/Portal 整合及正式
release QA 交 #28；synthetic L4/L5 不代表任何 live negotiation/usage。

## 8. Complete synthetic examples (not actual environment evidence)

### Planned / no attempt

```json
{
  "schema_version": "1.0.0",
  "run": {
    "run_id": "synthetic-1",
    "run_state": "PLANNED",
    "recorded_at": "2026-01-01T00:01:00Z",
    "started_at": null,
    "finished_at": null,
    "source": {
      "source_kind": "SYNTHETIC",
      "producer_id": "fixture",
      "producer_version": "1.0",
      "origin_ref": "fixture-origin",
      "input_sha256": null
    },
    "expected_host_ids": [
      "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c"
    ]
  },
  "hosts": [
    {
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "target_id": "Host-A.example.invalid",
      "identity_scope": "STABLE",
      "inventory_authority_id": "fixture-authority",
      "identity_key": null,
      "host_state": "NOT_ATTEMPTED",
      "reason_code": "PLAN_ONLY"
    }
  ],
  "collections": [
    {
      "collection_id": "c-57260a5ecdaf1e578e787fff5ef154ac195cf572d04a8da0ec7ab87c3fed4a5a",
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "collector_id": "fixture",
      "collector_version": null,
      "scope_key": "all",
      "collection_state": "NOT_SCANNED",
      "reason_code": "PLAN_ONLY",
      "source": {
        "source_kind": "SYNTHETIC",
        "producer_id": "fixture",
        "producer_version": null,
        "origin_ref": "fixture-origin",
        "input_sha256": null
      },
      "observed_at": null,
      "evidence_ids": []
    }
  ],
  "assets": [],
  "evidence": [],
  "claims": [],
  "findings": []
}
```

### Collected / L1 claim (not L2–L5 readiness)

```json
{
  "schema_version": "1.0.0",
  "run": {
    "run_id": "synthetic-1",
    "run_state": "COMPLETE",
    "recorded_at": "2026-01-01T00:01:00Z",
    "started_at": null,
    "finished_at": null,
    "source": {
      "source_kind": "SYNTHETIC",
      "producer_id": "fixture",
      "producer_version": "1.0",
      "origin_ref": "fixture-origin",
      "input_sha256": null
    },
    "expected_host_ids": [
      "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c"
    ]
  },
  "hosts": [
    {
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "target_id": "Host-A.example.invalid",
      "identity_scope": "STABLE",
      "inventory_authority_id": "fixture-authority",
      "identity_key": null,
      "host_state": "COMPLETE",
      "reason_code": "FIXTURE"
    }
  ],
  "collections": [
    {
      "collection_id": "c-57260a5ecdaf1e578e787fff5ef154ac195cf572d04a8da0ec7ab87c3fed4a5a",
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "collector_id": "fixture",
      "collector_version": "1.0",
      "scope_key": "all",
      "collection_state": "COLLECTED",
      "reason_code": "FIXTURE",
      "source": {
        "source_kind": "SYNTHETIC",
        "producer_id": "fixture",
        "producer_version": "1.0",
        "origin_ref": "fixture-origin",
        "input_sha256": null
      },
      "observed_at": "2026-01-01T00:00:00Z",
      "evidence_ids": [
        "e-eac5d97f2ae74e364752880978edc2b4ade83bb96ab40f082a0867fb4d57cdeb"
      ]
    }
  ],
  "assets": [
    {
      "asset_id": "a-5f192d48c85398536ffa6840526124d5411defe8fedf08c6f7871a4db89a3334",
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "asset_kind": "package",
      "identity_scope": "STABLE",
      "identity_key": "fixture-package",
      "evidence_ids": [
        "e-eac5d97f2ae74e364752880978edc2b4ade83bb96ab40f082a0867fb4d57cdeb"
      ]
    }
  ],
  "evidence": [
    {
      "evidence_id": "e-eac5d97f2ae74e364752880978edc2b4ade83bb96ab40f082a0867fb4d57cdeb",
      "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
      "collection_id": "c-57260a5ecdaf1e578e787fff5ef154ac195cf572d04a8da0ec7ab87c3fed4a5a",
      "asset_id": "a-5f192d48c85398536ffa6840526124d5411defe8fedf08c6f7871a4db89a3334",
      "observation_key": "observation",
      "evidence_kind": "PACKAGE_INVENTORY",
      "source": {
        "source_kind": "SYNTHETIC",
        "producer_id": "fixture",
        "producer_version": "1.0",
        "origin_ref": "fixture-origin",
        "input_sha256": null
      },
      "observed_at": "2026-01-01T00:00:00Z",
      "data": {
        "name": "fixture-package",
        "version": "1.0",
        "present": true
      },
      "algorithm": null
    }
  ],
  "claims": [
    {
      "claim_id": "cl-b6798e728cea732f2745a57a301dd0c43dacd9f7db02e3753535b49fec985463",
      "subject": {
        "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
        "asset_id": "a-5f192d48c85398536ffa6840526124d5411defe8fedf08c6f7871a4db89a3334",
        "algorithm_id": null
      },
      "claim_key": "claim",
      "level": "L1",
      "assessment_state": "PASS",
      "rule_id": "fixture-rule",
      "rule_version": "1.0",
      "reason_code": "FIXTURE",
      "evidence_ids": [
        "e-eac5d97f2ae74e364752880978edc2b4ade83bb96ab40f082a0867fb4d57cdeb"
      ],
      "conditions": null
    }
  ],
  "findings": [
    {
      "finding_id": "f-e2cedab18ffdab0e04653b1045bd8ee8e6442ac6cd46596cb9d3459a05bb7e55",
      "subject": {
        "host_id": "h-700c965c5bde3cb13835c3001cb222fbe38a65e4d3718cdb7b52ef5448cf621c",
        "asset_id": "a-5f192d48c85398536ffa6840526124d5411defe8fedf08c6f7871a4db89a3334",
        "algorithm_id": null
      },
      "condition_key": "fixture-condition",
      "rule_id": "fixture-rule",
      "rule_version": "1.0",
      "assessment_state": "PASS",
      "reason_code": "FIXTURE",
      "evidence_ids": [],
      "claim_ids": [
        "cl-b6798e728cea732f2745a57a301dd0c43dacd9f7db02e3753535b49fec985463"
      ]
    }
  ]
}
```

