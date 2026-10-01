# Cipher Ledger

Python 3.11+ 的本地 HTTP/SQLite 服务。提供命令行配置、keyring 校验、数据库连接、服务元数据和健康检查，以及下文公开协议定义的多租户信封加密记录功能。单进程、多 HTTP 请求并发；不涉及前端、账号体系、网络鉴权、外部 KMS、删除和更新记录。

## 安装和启动

在项目目录执行，Windows 与 Linux 命令一致：

```text
python -m pip install -r requirements.txt
python tools/create_keyring.py --output keyring.json
python -m cipher_ledger --host 127.0.0.1 --port 8087 --db data/ledger.sqlite3 --keyring keyring.json
```

创建 keyring 的命令生成三个本地开发用随机密钥，已有文件不会覆盖。服务仅绑定环回地址；`X-Tenant-ID` 是上游已确定的租户上下文，并非认证凭据。记录接口依靠该字段选择租户，管理密钥接口用于本地受信任的管理调用，不需租户头。日志不得包含请求正文、原文或密钥材料。

公开基础检查：`python -m unittest discover -s tests -v`。`GET /health` 始终返回 `200 {"status":"ok","service":"cipher-ledger"}`。

## 配置和持久状态

`--db` 指定 SQLite 文件，`--keyring` 指定 UTF-8 JSON 文件，形状为 `{"active_version":1,"keys":{"1":"<base64>","2":"<base64>","3":"<base64>"}}`。版本是正整数，密钥是各自独立的 32 字节随机值，编码采用标准 Base64。keyring 只在启动时加载；文件属于外部配置，禁止把其中的密钥写入数据库或日志。已有配置校验行为需保留。

数据库首次启用记录功能时，以配置中的 `active_version` 初始化持久活动版本。之后重启以数据库状态为准，即使配置中的初始值仍为 1。活动版本存于现有 `service_metadata` 表，`name='active_version'`，`value` 为十进制字符串；保留其他元数据。加载的 keyring 必须包含数据库活动版本及读取/轮换所需的版本；维护者会保留这些密钥。完成轮换后，不再有记录引用的旧密钥可以从文件移除，重启时把配置初始值调整为仍存在的版本。

## HTTP 契约

请求与响应均为 UTF-8 JSON。错误响应为 `{"error":"错误码"}`，不返回原文、密钥、栈信息或密码库的详细错误。未列明的 JSON 扩展字段可忽略。响应必须包含下表列出的字段；可以添加不含秘密的扩展字段。

记录接口要求 `X-Tenant-ID`，租户值与记录 `id` 均匹配 `[A-Za-z0-9_-]{1,64}`，区分大小写。缺少或无效的租户值、id、非对象 JSON、语法错误、缺失字段、错误字段类型，返回 `400 invalid_request`。版本必须是 JSON 正整数，布尔值不视作整数。无需支持 URL 编码的标识符、分块上传或重复 JSON 属性。

| 方法与路径 | 输入 | 成功返回 |
|---|---|---|
| `GET /v1/keys` | 无 | `200 {"active_version":1}` |
| `POST /v1/records` | 租户头；`{"id":"invoice_1","plaintext":"待保存文字"}` | `201 {"id":"invoice_1","key_version":1}` |
| `POST /v1/records/batch` | 租户头；`{"records":[{"id":"invoice_1","plaintext":"..."}, ...]}` | `201 {"key_version":1,"created":["invoice_1", ...]}` |
| `GET /v1/records` | 租户头；查询参数 `limit`、`cursor`（均可省略） | `200 {"items":[{"id":"invoice_1"}, ...],"next_cursor":"..."}` |
| `GET /v1/records/invoice_1` | 租户头 | `200 {"id":"invoice_1","plaintext":"待保存文字","key_version":1}` |
| `POST /v1/records/batch/read` | 租户头；`{"ids":["invoice_1", ...]}` | `200 {"items":[{"id":"invoice_1","plaintext":"...","key_version":1}, ...]}` |
| `POST /v1/encrypted-records/batches` | 租户头；`{"idempotency_key":"可选","records":[{"id":"invoice_1","algorithm":{...},"envelope":"...","nonce":"...","ciphertext":"...","metadata":{...}}, ...]}` | `201 {"batch_id":"bat_...","tenant":"...","count":2,"records":[{"id":"invoice_1","status":"created"}, ...]}` |
| `POST /v1/keys/rotate` | `{"version":2}` | `200 {"active_version":2,"rewrapped":记录总数}` |

`plaintext` 必须是字符串，UTF-8 编码长度允许 0 到 65536 字节（含两端）。超限返回 `400 invalid_request`；空串、中文、emoji 和换行往返保持原样。租户内 id 唯一，重复创建返回 `409 conflict`，原记录保持不变；不同租户允许同名 id。不存在的记录及另一个租户的记录均返回 `404 not_found`。读取信封的任一认证失败返回 `422 integrity_error`，不能返回部分明文，服务之后仍可处理正常请求。

批量接口的 `records` 必须是 1 到 100 项的数组；缺失、空数组、超过 100 项、任一项不是对象、缺失或类型错误的 `id`/`plaintext`、`id` 不合标识符规则或 `plaintext` 超字节上限，均为 `400 invalid_request`，未列明字段照旧忽略。批内重复 id 或任一 id 已存在于该租户返回 `409 {"error":"conflict"}`，此时整批不写入任何记录，已有记录保持不变；不同租户同名 id 仍相互独立。`key_version` 是整批共同使用的当前活动版本，`created` 按输入顺序给出本次创建的 id。SQLite 写入失败返回 `503 storage_error`，整批无部分提交。批内每条记录沿用单条记录的信封格式与 AAD 绑定，使用各自独立的随机数据密钥和 nonce。

记录清单 `GET /v1/records` 同样以 `X-Tenant-ID` 选择租户，只返回 id、不返回 `plaintext` 或 `key_version`，因此密钥轮换不改变分页内容，信封损坏的记录也照常列出其 id（真正读取该记录时仍返回 `422 integrity_error`）。`items` 按 id 的稳定顺序（SQLite BINARY 升序）逐项给出 `{"id":"..."}`，64 字符 id 照常列出，不同租户同名 id 彼此独立。`limit` 省略时每页 50 项；显式给出时必须由纯 ASCII 数字组成且在 1 到 100 之间，否则 `400 invalid_request`。`limit` 或 `cursor` 同名参数重复出现为 `400 invalid_request`，其他查询参数忽略。缺少或无效租户、游标格式损坏或属于其他租户，均为 `400 invalid_request`，错误响应不包含任何部分页面。

游标是不透明值，调用方只把它原样带回同一租户的后续请求。第一次不带 `cursor` 的请求在某个完整串行时刻确定一次清单快照：后续沿返回的 `next_cursor` 翻页时，即使期间发生创建或密钥轮换，也只返回这次快照里的记录，不重复、不漏项；快照之后新建的记录必须重新发起一次不带游标的清单请求才能看到。仍有后续页时响应包含 `next_cursor`，最后一页不带该字段；空租户返回 `200 {"items":[]}` 且不带 `next_cursor`。快照查询发生 SQLite 读取失败返回 `503 storage_error`；快照一旦建立，后续页直接从内存快照给出，因此存储失败不影响已经返回的页。

批量读取的 `ids` 必须是 1 到 100 项的字符串数组，每个 id 符合标识符规则且批内不得重复；字段缺失、非数组、空数组、超过 100 项、任一元素不是字符串或不合规则、批内重复 id，均为 `400 invalid_request`，未列明字段照旧忽略。通过校验后先做整批存在性查询：该查询发生数据库读取失败返回 `503 storage_error`；查询成功后任一 id 不存在或属于另一租户即返回 `404 not_found`，整次不返回任何明文、不做部分结果，因此同时包含不存在 id 与损坏信封时仍确定返回 404。所有 id 都存在后才逐项解密，任一信封认证失败返回 `422 integrity_error`，响应不包含其他条目的明文，服务随后仍可处理正常请求。成功时 `items` 严格按请求顺序逐项给出 `id`、`plaintext`、`key_version`，空串、中文、emoji 和换行原样返回，每项沿用单条读取的信封认证与 AAD 绑定。并发下批量读取等价于一个完整串行时刻：与创建并发时要么完整看到创建前状态（404）要么完整看到创建后记录；与轮换并发时 `items` 中所有 `key_version` 要么全部为轮换前版本、要么全部为轮换后版本，不观察半轮换或部分解密状态。

### 客户端加密记录的批量写入

`POST /v1/encrypted-records/batches` 用于由调用方自行加密后，一次为同一租户原子提交多条记录。与 `POST /v1/records` 系列不同，服务端不接触明文、不生成数据密钥，也不拆开、解密或复用任何信封：每条记录携带各自独立的加密信封、密文、nonce 与算法元数据，服务只做结构校验并原样保存，再在读取侧由调用方掌握的密钥体系负责解密。本入口是独立接口，不改变 `POST /v1/records`、`POST /v1/records/batch` 等既有入口的请求、校验、冲突与响应语义；两类记录分表存储，同名 id 互不影响。

请求体为对象，`records` 是 1 到 100 项的有序数组，顺序即结果返回顺序。每条记录字段如下：

| 字段 | 要求 |
|---|---|
| `id` | 必填，稳定记录标识，匹配 `[A-Za-z0-9_-]{1,64}`，区分大小写 |
| `algorithm` | 必填对象。`name` 必填且为受支持算法（当前仅 `AES-256-GCM`）；可选 `key_id` 为 1 到 256 字符的字符串，用于调用方标识信封所用密钥 |
| `envelope` | 必填，标准 Base64（带填充的规范编码）非空字符串，最长 8192 字节解码长度。该记录独立的加密信封，服务原样保存、绝不拆封或复用 |
| `nonce` | 必填，标准 Base64 字符串。`AES-256-GCM` 必须恰为 12 字节 |
| `ciphertext` | 必填，标准 Base64 字符串；长度不得短于算法的 16 字节认证标签，解码后最长 65552 字节（65536 字节正文 + 16 字节标签） |
| `metadata` | 可选，关联元数据对象（省略或为 `null` 均可），规范化（紧凑、按键名排序）后 UTF-8 最长 8192 字节，内容随记录保存 |
| `tenant` | 可选，记录内租户声明。省略时以请求租户为准；填写时必须与鉴权租户一致 |

`nonce`、`ciphertext` 的长度必须与 `algorithm.name` 一致，相互矛盾（如 GCM nonce 非 12 字节、密文短于标签）即整批校验失败。未列明的扩展字段照旧忽略。可选顶层 `idempotency_key` 匹配 `[A-Za-z0-9_-]{1,128}`，用于异步重试去重，作用域为单个租户。

服务先完成整批校验，再一次性写入。确定错误结果如下（错误响应体在 `error` 之外带 `message`，指向具体输入位置，如 `records[2].nonce: ...`）：

| 情况 | 状态与错误码 |
|---|---|
| 请求体不是对象/JSON 语法错误；`records` 缺失、非数组、空、超过 100 项；任一项为空或非对象；`id` 缺失或不合法；`envelope`/`nonce`/`ciphertext` 缺失、非规范 Base64 或为空；算法元数据缺失或 `name` 不受支持；字段长度与算法矛盾；`metadata`/`algorithm.key_id` 类型或长度不合法；同一批次内重复 `id`；该租户已存在相同 `id` 的记录 | `400 {"error":"INVALID_BATCH","message":"..."}` |
| 某条记录的 `tenant` 声明为另一个租户（跨租户写入/覆盖企图）；或请求身份无法确定租户（缺少或非法 `X-Tenant-ID`） | `403 {"error":"TENANT_RECORD_FORBIDDEN","message":"..."}` |
| 数据库约束失败、账本追加失败或提交期校验失败 | `500 {"error":"BATCH_WRITE_FAILED","message":"..."}` |

批内重复 id 与“同租户既有记录冲突”统一为 `400 INVALID_BATCH`，不区分成不同错误；仅当记录在结构合法的前提下声明了*别的*租户时才是 `403 TENANT_RECORD_FORBIDDEN`。不同租户使用相同 id 相互独立、互不可见、互不可覆盖；记录标识、所属租户与各自加密内容在服务端按 `(tenant, id)` 绑定。

整批校验通过后，所有记录行与一条批次台账行在同一个 SQLite 事务中提交：要么全部可见，要么全部回滚。`500 BATCH_WRITE_FAILED` 时已有记录保持原值、新记录全部不可见，也不会留下批次台账或部分数据（可用 `BEFORE INSERT ON encrypted_records` 触发器的 `RAISE(ABORT,...)` 复现）。成功返回 `201`：

```json
{
  "batch_id": "bat_9fQ...",
  "tenant": "acme",
  "count": 2,
  "records": [
    {"id": "invoice_1", "status": "created"},
    {"id": "invoice_2", "status": "created"}
  ]
}
```

`batch_id` 是服务端生成的不透明全局唯一批次标识；`count` 为成功记录总数；`records` 严格按输入顺序给出每条的 `id` 与写入结果 `status`（当前固定为 `"created"`）。请求带 `idempotency_key` 时成功体原样回显该键。

幂等与重试口径：同一租户用相同 `idempotency_key` 且提交完全相同的一批记录（相同的有序 id 与各字段密封字节）重试，返回同一个 `batch_id` 与相同结果，数据库只落一批，不会因异步重试产生重复记录；同一 key 搭配不同记录集合重试，返回 `400 INVALID_BATCH`，已提交批次不变。不带 `idempotency_key` 的重复提交按普通冲突处理：命中既有 id 返回 `400 INVALID_BATCH`。并发下同一批记录（无论是否带幂等键）在 `(tenant, id)` 约束与进程级串行锁下只有一次提交成功，失败方整批不落库。

加密批记录使用独立的公开表 `encrypted_records`（列：`tenant`、`id`、`algorithm`、`envelope`、`nonce`、`ciphertext`、`metadata`、`batch_id`、`created_at`，主键 `(tenant, id)`），批次台账为 `batch_commits`（`batch_id`、`tenant`、`idempotency_key`、`record_count`、`record_ids`、`fingerprint`、`created_at`，并对 `(tenant, idempotency_key)` 建唯一索引）。两表与既有 `records` 表彼此独立；服务端不保存、也无法从这些列还原明文或信封数据密钥。


轮换版本必须在 keyring 中，否则 `400 invalid_version`。格式非法仍为 `400 invalid_request`。版本低于当前值返回 `409 version_conflict`；版本等于当前值为幂等空操作，返回当前版本及 `rewrapped:0`，不改任何信封。更高版本允许跳号，成功时更新全部租户的每条记录及活动版本，`rewrapped` 等于记录数，包括空库返回 0。成功后新建记录只能使用新的活动版本。

## 信封存储与兼容格式

使用 `cryptography.hazmat.primitives.ciphers.aead.AESGCM`，正文及数据密钥封装都采用 AES-256-GCM。每条记录使用独立随机 32 字节数据密钥；正文和封装各使用独立随机 12 字节 nonce，不得复用同一密钥下的 nonce。数据库仅保存信封，不存正文、数据密钥或 keyring 密钥的明文/可逆编码。不得自制密码原语。

为便于离线备份和兼容工具读取，SQLite 公开 `records` 表，以下列名与类型保持稳定，允许增加不含秘密的列；不要求具体 SQL 建表语句：

| 列 | 类型与含义 |
|---|---|
| `tenant` | TEXT，租户标识 |
| `id` | TEXT，租户内记录标识；与 tenant 联合唯一 |
| `key_version` | INTEGER，封装所用 keyring 版本 |
| `nonce` | BLOB，正文 nonce，12 字节 |
| `ciphertext` | BLOB，AESGCM 正文密文，末尾含 16 字节认证标签 |
| `wrap_nonce` | BLOB，数据密钥封装 nonce，12 字节 |
| `wrapped_key` | BLOB，AESGCM 封装结果，32 字节数据密钥加 16 字节标签 |

AAD 是 UTF-8 编码的无多余空白 JSON 数组。正文 AAD 为 `[1,"租户","记录id"]`，封装 AAD 为 `[1,"租户","记录id",密钥版本]`。数字 1 表示信封格式版本。标识符均为上述 ASCII 字符，因此不涉及字符串转义差异。这样导出的信封可用相同公开格式恢复。数据库中移植整组密文字段到其他租户或 id，或改变版本、nonce、密文和封装，应在读取时被拒绝；不能仅依靠查询过滤代替密码学绑定。

## 轮换和并发边界

轮换只重封装数据密钥，不重新加密正文，所有记录的 `nonce` 和 `ciphertext` 字节必须保持不变。轮换需确认每条旧信封的封装和正文都可认证；任一损坏返回 `422 integrity_error`，该次请求开始前的所有记录字段及活动版本都保持不变。SQLite 写入失败返回 `503 storage_error`，同样不得出现部分提交。旧版本记录在轮换前可读，完成轮换后仍可读；重启不得重置活动版本或丢失记录。

同一进程中，并发创建同租户同 id 只能一个成功，其余返回 `409 conflict`；批量批次之间、批次与单条创建之间争用同租户同 id 时同样只有一个请求成功，失败批次一条都不落库。创建、读取、轮换的成功结果必须与某个完整串行顺序一致，不能观察半轮换状态。写入与成功轮换并发结束后，所有记录均应为最终活动版本且可读；两个相同目标版本的轮换并发执行时，一个完成实际轮换，另一个返回幂等空操作。数据量范围为本地小型账本，无需分页、跨进程协调、批次后台迁移或性能基准。

可用离线 SQLite 维护复现损坏：先停止服务，改动一条记录的任一密文字段后重启。存储失败可用 SQLite `BEFORE UPDATE ON records` 触发器的 `RAISE(ABORT,...)` 模拟；此时观察到的 HTTP 失败不得留下其他行更新或活动版本变化。移除触发器或恢复原字段后服务应继续正常运行。这些错误路径属于本模块公开兼容要求。

密码库参考：[cryptography 49 AESGCM 文档](https://cryptography.io/en/49.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)。
