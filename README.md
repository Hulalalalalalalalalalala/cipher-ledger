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
| `POST /v1/encrypted-records/batch` | 租户头；可选 `Idempotency-Key` 头；调用方已密封的记录集合（见下） | 新键 `201 {"batch_id":"batch_…","count":2,"results":[{"id":"invoice_1","status":"created"}, ...]}`；同键同内容重放 `200`，正文与首次成功一致 |
| `GET /v1/encrypted-records/batches/{batch_id}` | 租户头；批号为 `batch_` 加 32 个小写十六进制字符；查询参数忽略 | `200 {"batch_id":"…","count":2,"created_at":"…","records":[...]}`（见下） |
| `GET /v1/encrypted-records/batches` | 租户头；查询参数 `limit`、`cursor`（均可省略） | `200 {"items":[{"batch_id":"…","count":2,"created_at":"…"}, ...],"next_cursor":"..."}`（见下） |
| `GET /v1/encrypted-records/events` | 租户头；首次查询参数 `after_seq`（省略为 0）、`limit`；续页参数 `cursor`、可选 `limit` | `200 {"items":[{"seq":…,"batch_id":"…","id":"…","position":…,"created_at":"…"}, ...],"high_water":…,"next_cursor":"..."}`（见下） |
| `POST /v1/encrypted-records/batch/read` | 租户头；`{"ids":["invoice_1", ...]}`（1 到 100 个不重复 id）；查询参数与未列明字段忽略 | `200 {"count":2,"items":[...]}`（见下，按输入顺序跨批次返回） |
| `GET /v1/encrypted-records/receipts/{key}` | 租户头；`key` 沿用 `Idempotency-Key` 的格式与大小写规则；查询参数忽略 | `200 {"batch_id":"…","count":2,"results":[{"id":"…","status":"created"}, ...],"created_at":"…"}`（见下） |
| `POST /v1/keys/rotate` | `{"version":2}` | `200 {"active_version":2,"rewrapped":记录总数}` |

`plaintext` 必须是字符串，UTF-8 编码长度允许 0 到 65536 字节（含两端）。超限返回 `400 invalid_request`；空串、中文、emoji 和换行往返保持原样。租户内 id 唯一，重复创建返回 `409 conflict`，原记录保持不变；不同租户允许同名 id。不存在的记录及另一个租户的记录均返回 `404 not_found`。读取信封的任一认证失败返回 `422 integrity_error`，不能返回部分明文，服务之后仍可处理正常请求。

批量接口的 `records` 必须是 1 到 100 项的数组；缺失、空数组、超过 100 项、任一项不是对象、缺失或类型错误的 `id`/`plaintext`、`id` 不合标识符规则或 `plaintext` 超字节上限，均为 `400 invalid_request`，未列明字段照旧忽略。批内重复 id 或任一 id 已存在于该租户返回 `409 {"error":"conflict"}`，此时整批不写入任何记录，已有记录保持不变；不同租户同名 id 仍相互独立。`key_version` 是整批共同使用的当前活动版本，`created` 按输入顺序给出本次创建的 id。SQLite 写入失败返回 `503 storage_error`，整批无部分提交。批内每条记录沿用单条记录的信封格式与 AAD 绑定，使用各自独立的随机数据密钥和 nonce。

记录清单 `GET /v1/records` 同样以 `X-Tenant-ID` 选择租户，只返回 id、不返回 `plaintext` 或 `key_version`，因此密钥轮换不改变分页内容，信封损坏的记录也照常列出其 id（真正读取该记录时仍返回 `422 integrity_error`）。`items` 按 id 的稳定顺序（SQLite BINARY 升序）逐项给出 `{"id":"..."}`，64 字符 id 照常列出，不同租户同名 id 彼此独立。`limit` 省略时每页 50 项；显式给出时必须由纯 ASCII 数字组成且在 1 到 100 之间，否则 `400 invalid_request`。`limit` 或 `cursor` 同名参数重复出现为 `400 invalid_request`，其他查询参数忽略。缺少或无效租户、游标格式损坏或属于其他租户，均为 `400 invalid_request`，错误响应不包含任何部分页面。

游标是不透明值，调用方只把它原样带回同一租户的后续请求。第一次不带 `cursor` 的请求在某个完整串行时刻确定一次清单快照：后续沿返回的 `next_cursor` 翻页时，即使期间发生创建或密钥轮换，也只返回这次快照里的记录，不重复、不漏项；快照之后新建的记录必须重新发起一次不带游标的清单请求才能看到。仍有后续页时响应包含 `next_cursor`，最后一页不带该字段；空租户返回 `200 {"items":[]}` 且不带 `next_cursor`。快照查询发生 SQLite 读取失败返回 `503 storage_error`；快照一旦建立，后续页直接从内存快照给出，因此存储失败不影响已经返回的页。

批量读取的 `ids` 必须是 1 到 100 项的字符串数组，每个 id 符合标识符规则且批内不得重复；字段缺失、非数组、空数组、超过 100 项、任一元素不是字符串或不合规则、批内重复 id，均为 `400 invalid_request`，未列明字段照旧忽略。通过校验后先做整批存在性查询：该查询发生数据库读取失败返回 `503 storage_error`；查询成功后任一 id 不存在或属于另一租户即返回 `404 not_found`，整次不返回任何明文、不做部分结果，因此同时包含不存在 id 与损坏信封时仍确定返回 404。所有 id 都存在后才逐项解密，任一信封认证失败返回 `422 integrity_error`，响应不包含其他条目的明文，服务随后仍可处理正常请求。成功时 `items` 严格按请求顺序逐项给出 `id`、`plaintext`、`key_version`，空串、中文、emoji 和换行原样返回，每项沿用单条读取的信封认证与 AAD 绑定。并发下批量读取等价于一个完整串行时刻：与创建并发时要么完整看到创建前状态（404）要么完整看到创建后记录；与轮换并发时 `items` 中所有 `key_version` 要么全部为轮换前版本、要么全部为轮换后版本，不观察半轮换或部分解密状态。

### 客户端密封的批量写入 `POST /v1/encrypted-records/batch`

该入口用于**调用方在本地完成加密**、服务端只存储信封与密文的场景。服务端不接触正文明文、不生成或拆开数据密钥、也不在记录之间复用密钥；每条记录必须携带各自独立的 `envelope` 与 `ciphertext`。它与上文“服务端加密”的 `POST /v1/records`、`POST /v1/records/batch` 完全独立，单记录入口的输入校验、`409 conflict` 冲突响应与持久化结果保持不变，也不统一到本入口的响应结构。

请求头必须带合法的 `X-Tenant-ID`。请求体是一个对象，`records` 为 1 到 100 项的有序数组，每项形状如下（字节字段均为标准 Base64、含填充）：

```json
{
  "records": [
    {
      "id": "invoice_1",
      "algorithm": "AES-256-GCM",
      "key_id": "client-key-1",
      "envelope": {"nonce": "<base64 12 字节>", "wrapped_key": "<base64 48 字节>"},
      "ciphertext": {
        "data": "<base64 密文正文，0 到 1048576 字节>",
        "nonce": "<base64 12 字节>",
        "tag": "<base64 16 字节>"
      },
      "metadata": {"order": "A-100"}
    }
  ]
}
```

字段语义：

- `id`：稳定记录标识，匹配 `[A-Za-z0-9_-]{1,64}`，区分大小写，在所属租户内唯一。
- `algorithm`：算法元数据，目前仅支持精确字符串 `"AES-256-GCM"` 与 `"AES-128-GCM"`；其他值（含大小写变体）不受支持。
- `key_id`：可选，1 到 128 字符的字符串，标识调用方用于封装数据密钥的密钥；省略时按 null 存储。
- `envelope`：该记录独立的密钥信封。`nonce` 必须 12 字节；`wrapped_key` 为“被封装的数据密钥 + 16 字节 GCM 标签”，长度必须与 `algorithm` 一致——`AES-256-GCM` 为 48 字节（32+16），`AES-128-GCM` 为 32 字节（16+16）。
- `ciphertext`：该记录独立的正文密文。`data` 解码后 0 到 1048576 字节（空正文允许，此时只有标签）；`nonce` 必须 12 字节；`tag` 必须 16 字节。
- `metadata`：可选关联元数据，必须是 JSON 对象，紧凑 UTF-8 序列化后不超过 16384 字节，原样存储；省略时按 null 存储。
- 每项可带 `tenant` 字段，但取值必须与请求头租户一致；属于其他租户见 403 口径。未列明的其他字段忽略。

请求头可选带 `Idempotency-Key`，用于在响应丢失后安全重试：

- 取值精确匹配 `[A-Za-z0-9_-]{1,64}`，区分大小写，按租户隔离。不带该头时完全保持既有写入行为。
- 关联只在请求通过既有形状校验与批内重复 id 校验后才判定，且先于“该租户下 id 已存在”的检查。空值、非法值或该头重复出现，均返回 `400 INVALID_BATCH`，`message` 指向 `Idempotency-Key` 请求头；租户身份缺失/非法与跨租户声明仍沿用既有 `403` 优先规则。
- 绑定一旦成功建立不自动过期，服务重启后仍有效。旧数据库可直接启动，既有批次无需补键。

成功返回 `201`：

```json
{
  "batch_id": "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "count": 2,
  "results": [
    {"id": "invoice_1", "status": "created"},
    {"id": "invoice_2", "status": "created"}
  ]
}
```

`batch_id` 是本次提交的批次标识（`batch_` 加 32 个十六进制字符）；`count` 为成功记录总数；`results` 严格按输入顺序逐条给出记录标识与写入结果 `created`，调用方可据此逐条确认。

携带新 `Idempotency-Key` 的首次成功返回上述 `201` 正文。同租户同键、且内容与首次成功提交一致的重试返回 `200`，响应正文与首次成功完全相同——`batch_id`、`count` 与有序 `results` 均不变，且不新增批次、记录或追加事件。内容一致性按**实际保存字段**比较：逐条记录及数组顺序都参与比较；对象键顺序、JSON 排版空白以及未保存（忽略）字段不影响结果；字节字段比较 Base64 解码后的字节值（标准含填充编码）；`key_id` 与 `metadata` 的省略与显式 `null` 等价；`metadata` 数字按数值比较（`1` 与 `1.0` 相等），但布尔值与数字不同（`true` 不等于 `1`）。

#### 确定的错误结果

错误响应形状为 `{"error":"错误码","message":"具体说明"}`，`message` 用点路径指向具体输入位置（如 `records[2].envelope.nonce`）。结果是确定且互斥的：

- `400 {"error":"INVALID_BATCH", ...}`：整批先校验、后写入，只要出现下列任一情况，整批都不提交，且不区分成多个模糊错误码——批内重复 id 与既有记录冲突同样返回本结果：
  - 请求体不是 JSON 对象；`records` 缺失、不是数组、为空或超过 100 项；
  - 任一记录为空/不是对象；`id` 缺失、类型错误或不合标识符规则；
  - `envelope` 或 `ciphertext` 缺失、不是对象，或其中必需的 `nonce`/`wrapped_key`/`data`/`tag` 缺失、不是合法 Base64；
  - `algorithm` 缺失或不受支持；字段与算法互相矛盾（如 `AES-128-GCM` 却给 48 字节 `wrapped_key`），或 nonce/tag/wrapped_key 长度不符、`data` 超限；
  - `metadata` 非对象或超限；`key_id` 类型或长度非法；
  - 同一批次内重复使用同一记录标识；该租户下已存在相同 `id` 的记录（携带**新**幂等键时亦然，且该键不会被绑定）；
  - `Idempotency-Key` 头为空、取值不合法，或该头重复出现——`message` 指向该请求头。
  - 校验在触碰数据库之前完成，返回第一个非法位置，此时新记录不可见。
- `403 {"error":"TENANT_RECORD_FORBIDDEN", ...}`：请求身份无法确定租户（缺少或非法的 `X-Tenant-ID`），或任一记录属于/声称为其他租户、试图跨租户覆盖。跨租户绑定判定先于形状与幂等头校验，因此即使该记录其他字段也不合法，只要声明了其他租户即返回 403。不同租户使用相同 `id`（及相同幂等键）彼此独立、互不可读、互不可覆盖。
- 携带幂等键且该键已绑定时，在既有 id 冲突检查**之前**判定：内容一致 → `200` 重放（见上）；内容不一致 → `409 {"error":"IDEMPOTENCY_CONFLICT"}`，即使重试中的 `id` 也已存在，仍以 409 为准；绑定指向的批次缺失、被错绑到其他租户，或不满足下文“整批一致性复核”，返回 `422 {"error":"integrity_error"}`。
- `500 {"error":"BATCH_WRITE_FAILED"}`：整批通过校验后，在幂等查询/提交、数据库约束、账本追加或提交阶段发生任何 SQLite 失败。整批回滚：已有记录与已有关联保持原值，批次行、记录、追加事件与新键绑定都不可见，不留部分数据；新键未被占用，故障恢复后同键可直接重试。该响应不含其他细节。

#### 原子性与幂等/重试口径

整批记录在同一次原子提交中落库（批次行、每条记录、每条追加事件，以及携带幂等键时的幂等关联，同一事务）。失败请求绝不留下部分数据，也不会占用一个新键；恢复后同键可重试。记录标识与所属租户在服务端与加密内容绑定存储；主键为 `(tenant, id)`，因此同一租户同一 `id` 已存在时整批 `INVALID_BATCH`，不会覆盖。重试口径分两种：

- 不带 `Idempotency-Key`：第一次已成功提交后，重试会因这些 `id` 已存在而确定得到 `400 INVALID_BATCH`，不会产生重复行；调用方应以记录标识为准去重，或在重试前改用新的标识。
- 携带 `Idempotency-Key`：同租户同键同内容的重试确定返回 `200` 与首次成功正文，不新增批次、记录或事件；同键不同内容确定返回 `409 IDEMPOTENCY_CONFLICT`。绑定按租户隔离、区分大小写、不自动过期，重启后仍有效。

并发提交同一组 `(tenant, id)`（均不带幂等键）时只有一个请求 `201`，其余确定失败且一条都不落库。并发携带同一幂等键时：同内容只有一次 `201`，其余返回 `200` 且指向同一批次；不同内容只有成功提交者占用该键，其余返回 `409`。

服务端不校验也不解密客户端信封的密码学正确性，只校验算法名与字节形状并原样存储；调用方需自行保证数据密钥封装、正文 AEAD 与所需的上下文绑定，以便日后用相同格式离线恢复。

### 按批号取回整批密封记录 `GET /v1/encrypted-records/batches/{batch_id}`

该入口只读地返回一次成功提交的客户端密封批次。请求头必须带合法的 `X-Tenant-ID`；路径中的批号必须精确匹配 `batch_` 加 32 个**小写**十六进制字符，查询参数一律忽略。成功返回 `200`：

```json
{
  "batch_id": "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "count": 2,
  "created_at": "2026-10-02T08:30:00+00:00",
  "records": [
    {
      "id": "invoice_1",
      "algorithm": "AES-256-GCM",
      "key_id": "client-key-1",
      "envelope": {"nonce": "<base64 12 字节>", "wrapped_key": "<base64 48 字节>"},
      "ciphertext": {"data": "<base64 密文正文>", "nonce": "<base64 12 字节>", "tag": "<base64 16 字节>"},
      "metadata": {"order": "A-100"}
    }
  ]
}
```

- `count` 等于该批次的记录数（1 到 100）；`created_at` 按提交时存库的字符串原样返回；`records` 严格按提交顺序（即写入时的位置 0..count-1）排列。
- 每条记录返回 `id`、`algorithm`、`key_id`、`envelope`、`ciphertext`、`metadata`，嵌套结构沿用密封写入入口。所有字节字段以含填充的标准 Base64 返回；空正文的 `ciphertext.data` 仍为空字符串。写入时省略的 `key_id` 与 `metadata` 返回 `null`；`metadata` 恢复为 JSON 对象，值与提交时一致。
- 既有成功批次无需重新写入即可读取；服务重启后仍可按批号查询。读取不修改任何存储内容。

#### 读取时的一致性确认

返回整批之前，服务按批次租户核对批次行、记录与追加事件三者的一致性：该批号下的全部记录与全部事件都必须属于批次租户，数量分别恰好等于 `record_count`，记录位置与事件位置都恰好覆盖 `0..count-1` 且不重复，并按“租户 + 记录 id + 位置”逐一对应。任何缺失、多余、重复、错位或跨租户关联，统一返回 `422 integrity_error`。同时逐条复核存储形状：批次计数在 1 到 100 之间；记录 `algorithm` 受支持，字节字段类型与长度沿用写入限制（含 `data` 不超过 1048576 字节），`id` 合标识符规则，`key_id` 为 null 或 1 到 128 字符字符串；`metadata` 为 null 或可解析为 JSON 对象且紧凑序列化不超过 16384 字节——元数据 JSON 损坏、存储类型或长度不合法同样返回 `422 integrity_error`。

服务在读取时**不解密**客户端信封，也不判断密码学认证结果：符合形状的等长密文字节变化仍原样返回，不因此报错。

#### 确定的错误结果与顺序

错误响应只含 `{"error":"错误码"}`，不含部分记录或任何内部细节，判定顺序固定：

1. 缺少或非法的 `X-Tenant-ID`：`403 TENANT_RECORD_FORBIDDEN`，优先于批号格式判定。
2. 租户有效但批号形状错误：`400 invalid_request`。
3. 批号不存在，或批次归属其他租户：统一 `404 not_found`，且不检查该批次的任何详情（即使其内部已损坏，外租户仍只得到 404）。
4. 批次存在且属于本租户，但上述一致性或形状复核未通过：`422 integrity_error`。
5. 读取过程中 SQLite 失败：`503 storage_error`。

该读取与本进程的并发密封写入、密钥轮换处于同一串行状态：要么看到写入前（404）要么看到完整提交后的整批，不能看到未提交批次的部分内容。密封记录不参与服务端密钥轮换，原有记录写入、读取、快照分页、健康检查与密钥管理的语义保持不变；日志不记录信封内容或密钥。

### 查询租户批次清单 `GET /v1/encrypted-records/batches`

该入口只读地列出当前租户成功提交的客户端密封批次摘要。请求头必须带合法的 `X-Tenant-ID`；成功返回 `200`，`items` 按 `batch_id` 的 ASCII 升序（SQLite BINARY）排列，每项只含 `batch_id`、`count`、`created_at`，取值与按批号整批读取一致。其他租户的批次以及服务端加密的普通记录均不可见；没有任何密封批次的租户返回 `200 {"items":[]}`。既有批次无需重写即可列出；该查询不新增任何记录、批次、追加事件或幂等绑定。清单只检查摘要形状，批次内部记录与事件的一致性仍由既有整批读取复核。

分页沿用记录清单的口径：`limit` 省略时每页 50 项；显式给出时必须由纯 ASCII 数字组成且在 1 到 100 之间（`01`、`007` 等前导零可接受），否则 `400 invalid_request`。`limit` 或 `cursor` 同名参数重复出现均为 `400 invalid_request`，其他查询参数忽略。有后续页时响应才含 `next_cursor`，最后一页省略该字段。

第一次不带 `cursor` 的请求在某个完整串行时刻冻结一次该租户的批次清单；后续沿 `next_cursor` 翻页时只遍历这次冻结集合，不重复、不漏项，期间新提交的批次必须重新发起一次不带游标的查询才能看到；失败写入与幂等重放都不会增加清单项。游标不透明，绑定租户与首次查询状态，不自动过期；允许在续传时换用不同的 `limit`，同一游标连同相同 `limit` 重复使用返回同一页。冻结状态持久化在数据库中，因此同一数据库正常重启后游标仍有效；游标签名密钥独立于 keyring 存于 `service_metadata`，密钥轮换既不改变摘要也不使游标失效。

错误响应只含 `{"error":"错误码"}` 且不含部分页面，判定顺序固定：

1. 缺少或非法的 `X-Tenant-ID`：`403 TENANT_RECORD_FORBIDDEN`，优先于一切查询参数判定。
2. 租户合法后：非法 `limit`、空或无效 `cursor`、属于其他租户的游标，以及 `limit`/`cursor` 同名重复，均为 `400 invalid_request`；其他查询参数忽略。
3. 参数合法后发生 SQLite 读取失败：`503 storage_error`。
4. 待返回页中批号格式非法、`count` 非整数或超出 1 到 100、`created_at` 非字符串：`422 integrity_error`。后续页中的损坏摘要只在该页被请求时才报错，不影响其前各页。

该查询与本进程的并发密封提交等价于一个完整串行时刻，只能看到提交前或完整提交后的清单，不观察部分提交。

### 增量查询租户追加事件 `GET /v1/encrypted-records/events`

该入口只读地按追加账本序号（`encrypted_record_events.seq`，全局单调递增）增量返回当前租户在密封批量写入中产生的追加事件。请求头必须带合法的 `X-Tenant-ID`。成功返回 `200`：

```json
{
  "items": [
    {
      "seq": 7,
      "batch_id": "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      "id": "invoice_1",
      "position": 0,
      "created_at": "2026-10-02T08:30:00+00:00"
    }
  ],
  "high_water": 12,
  "next_cursor": "..."
}
```

- 每个事件一项，严格按 `seq` 升序，每页最多 `limit` 项。每项只含 `seq`、`batch_id`、`id`、`position`、`created_at`：前四项取自追加事件，`created_at` 取自所属批次行（同批各项相同）。不返回任何密文或信封字段。
- 其他租户的事件以及服务端加密的普通记录（`records` 表）不可见。序号是全局序列，因此本租户看到的序号允许有间隔。
- 第一次查询（不带 `cursor`）接受 `after_seq` 与 `limit`：`after_seq` 省略时默认 `0`，必须由纯 ASCII 数字组成，取值 0 到 9223372036854775807，允许前导零（如 `007`）；只遍历**严格大于** `after_seq` 的事件。
- 第一次查询在某个完整串行时刻固定一次范围：`high_water` 取 `max(after_seq, 当时本租户最大事件序号)`；没有任何事件的空租户最大序号视为 0。本次查询的整条翻页链只遍历 `after_seq < seq <= high_water` 的事件；范围确定后新提交的事件一律留到下次查询。调用方读完后以返回的 `high_water` 作为新的 `after_seq` 发起下一次不带游标的查询获取后续事件。
- 仍有范围内未返回事件时响应才含 `next_cursor`，末页省略；空结果为 `200 {"items":[],"high_water":…}`（当 `after_seq` 不小于当前最大序号时，`high_water` 等于 `after_seq`）。
- 续页接受 `cursor` 及可选的 `limit`，允许换用不同页大小；`cursor` 与 `after_seq` 不得同时出现。续页的 `high_water` 与首页一致，同一游标连同相同页大小重复查询结果一致。游标不透明，绑定租户与本入口（不能在其他清单入口或其他租户处使用），只携带 HMAC 签名的整数而不依赖服务端快照状态，因此数据库正常重启后仍有效；游标签名密钥与其他清单共用且独立于 keyring，密钥轮换不影响结果。失败写入与幂等重放不增加事件，自然也不出现在任何页中。
- 该查询不新增或修改任何批次、记录、追加事件或幂等绑定。

`limit` 沿用批次清单的分页大小规则：省略时每页 50 项；显式给出时必须由纯 ASCII 数字组成且在 1 到 100 之间（允许前导零）；`limit`、`cursor`、`after_seq` 同名参数重复出现均为 `400 invalid_request`，未知查询参数忽略。

判定顺序固定，错误正文只含 `{"error":"错误码"}`，不返回部分页面：

1. 缺少或非法的 `X-Tenant-ID`：`403 TENANT_RECORD_FORBIDDEN`，优先于一切查询参数判定。
2. 租户合法后：已知参数空值、格式非法或越界（含 `after_seq` 超过 9223372036854775807、`limit` 超出 1 到 100）、同名参数重复、`cursor` 与 `after_seq` 并存，以及损坏、属于其他租户或属于其他入口的游标：均为 `400 invalid_request`；未知参数忽略。
3. 参数合法后，先读取当前页事件以及所涉及批次的批次行、那些批次的全部记录与全部追加事件；期间任何 SQLite 失败返回 `503 storage_error`。
4. 取得全部数据后，沿用跨批次密封记录读取的完整一致性与形状复核：关联批次缺失、事件存储的批号非法（非 `batch_` 加 32 个小写十六进制字符）或批次归属其他租户，以及涉及批次的任一记录、事件不合规（含同批中未出现在本页的记录），整次返回 `422 integrity_error`；本页未涉及的批次即使损坏也不影响本页。

该查询与本进程的并发密封提交等价于一个完整串行时刻：水位与页数据在同一串行点读取，只能看到完整提交的批次，不观察未提交批次的部分事件；密封记录不参与服务端密钥轮换。

### 按记录 id 跨批次取回密封记录 `POST /v1/encrypted-records/batch/read`

该入口只读地按记录 id 一次取回当前租户的多条客户端密封记录，这些记录可来自一个或多个批次。请求头必须带合法的 `X-Tenant-ID`；请求体是一个对象，`ids` 为 1 到 100 项的字符串数组，每个 id 匹配 `[A-Za-z0-9_-]{1,64}` 且批内不得重复；未列明的正文字段与任何查询参数一律忽略。成功返回 `200`：

```json
{
  "count": 2,
  "items": [
    {
      "id": "invoice_1",
      "algorithm": "AES-256-GCM",
      "key_id": "client-key-1",
      "envelope": {"nonce": "<base64 12 字节>", "wrapped_key": "<base64 48 字节>"},
      "ciphertext": {"data": "<base64 密文正文>", "nonce": "<base64 12 字节>", "tag": "<base64 16 字节>"},
      "metadata": {"order": "A-100"},
      "batch_id": "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      "created_at": "2026-10-02T08:30:00+00:00"
    }
  ]
}
```

- `count` 恒等于请求的 id 数（即返回条数，1 到 100）；`items` 严格按请求 id 的顺序排列，只包含被请求的记录。
- 每条记录在按批号整批读取的记录结构上额外携带 `batch_id`（该记录所属批次）与 `created_at`（其批次提交时原样存库的字符串，同一批次的多条记录取值相同）。`id`、`algorithm`、`key_id`、`envelope`、`ciphertext`、`metadata` 各字段的 Base64、空密文、元数据与可选字段 `null` 口径与整批读取完全一致；服务同样不解密、不认证客户端密文，等长字节改动仍原样返回。
- 既有记录无需重新写入即可读取，服务重启后仍可按 id 取回。该查询不新增或修改任何批次、记录、追加事件或幂等绑定。

判定分三个阶段，错误响应只含 `{"error":"错误码"}`，不返回部分记录或内部细节，顺序固定：

1. 缺少或非法的 `X-Tenant-ID`：`403 TENANT_RECORD_FORBIDDEN`，优先于一切正文判定（即使正文不是合法 JSON）。
2. 租户有效后，正文不是合法 UTF-8 JSON 对象；或 `ids` 缺失、不是数组、项数不在 1 到 100、任一元素不是字符串或不合标识符规则、批内重复：均为 `400 invalid_request`。
3. 参数合法后先做一次**本租户**全部 id 的存在性查询：该查询发生 SQLite 失败返回 `503 storage_error`；查询成功但任一 id 不存在即返回 `404 not_found`。其他租户密封记录中的同名 id、以及服务端加密普通记录（`records` 表）中的同名 id 都**不算**存在；因此一个不存在的 id 与一个损坏批次同时出现时，仍在检查批次详情之前确定返回 `404`。
4. 全部 id 确认存在后，才读取所涉及批次的批次行、**该批次的全部记录与全部追加事件**；任何 SQLite 读取失败返回 `503 storage_error`。
5. 取得全部数据后才逐批复核，口径与按批号整批读取一致：计数在 1 到 100 之间、记录与事件位置恰好覆盖 `0..count-1`、租户与"租户 + 记录 id + 位置"逐一对应，并复核全部存储字段形状。记录关联批次缺失或归属不符、记录存储的批号非法（非 `batch_` 加 32 个小写十六进制字符），或涉及批次的**任一**记录、事件不合规——包括同批中未被请求的记录损坏——整次返回 `422 integrity_error`；未涉及的其他批次即使损坏也不影响本次结果。

该读取与本进程的并发密封写入、密钥轮换处于同一串行状态：要么看到写入前（该批新 id 全部 `404`）要么看到完整提交后的记录，不观察未提交批次的部分内容；密封记录不参与服务端密钥轮换。

### 按幂等键查询写入凭据 `GET /v1/encrypted-records/receipts/{key}`

该入口只读地返回某租户此前携带 `Idempotency-Key` 成功提交的密封批次写入凭据，使调用方在响应丢失后**无需重传密文**即可确认写入结果。路径中的 `key` 精确匹配 `[A-Za-z0-9_-]{1,64}`、区分大小写，规则与写入时的 `Idempotency-Key` 头完全一致；键按租户隔离。任何查询参数一律忽略。成功返回 `200`：

```json
{
  "batch_id": "batch_0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "count": 2,
  "results": [
    {"id": "invoice_1", "status": "created"},
    {"id": "invoice_2", "status": "created"}
  ],
  "created_at": "2026-10-02T08:30:00+00:00"
}
```

- `batch_id`、`count`、`results` 与该键**首次写入成功**的响应完全一致；`results` 严格按原提交顺序（批次存储位置 0..count-1）逐项给出 `{"id","status":"created"}`。幂等重放不改变任何取值。
- `created_at` 原样取自关联批次行提交时存库的字符串（同键绑定行写入时取值相同）。
- 响应只含上述四个字段，不含任何密文、信封或密钥内容（无 `algorithm`、`key_id`、`envelope`、`ciphertext`、`metadata`）；访问日志同样只记录请求行与状态。
- 既有成功绑定无需重写即可查询；绑定持久化在数据库中，服务正常重启后凭据保持一致；密封批次不参与密钥轮换，轮换后凭据不变。
- 未携带 `Idempotency-Key` 写入的旧批次不产生绑定行，因此任何键名都查不到其凭据。该查询不新增、不修改也不修复任何批次、记录、追加事件或绑定，不解密信封；未被该键关联的其他批次即使损坏也不影响本次结果。

判定顺序固定，错误正文只含 `{"error":"错误码"}`，绝不返回部分凭据：

1. 缺少或非法的 `X-Tenant-ID`：`403 TENANT_RECORD_FORBIDDEN`，优先于键的格式判定（即使键为空或同样非法）。
2. 租户合法但路径键为空或不合 `[A-Za-z0-9_-]{1,64}`：`400 invalid_request`。
3. 键合法后先按 `(租户, 键)` 读取绑定；查无本租户绑定（键未绑定，或仅其他租户绑定了同名键）统一返回 `404 not_found`。
4. 绑定存在后，关联批次缺失、归属其他租户、绑定的批号非法（非 `batch_` 加 32 个小写十六进制字符），或绑定 `created_at` 不是字符串、与批次行取值不同：`422 integrity_error`。
5. 返回前再按既有整批读取口径复核关联批次的批次行、全部记录与全部追加事件：计数、位置（恰好覆盖 `0..count-1`）、租户、"租户 + 记录 id + 位置"对应关系，或任一字段存储形状不合规，同样返回 `422 integrity_error`。
6. 上述任一步骤所需的数据库读取发生 SQLite 失败：`503 storage_error`。仅当所需读取全部成功后才判定损坏（422），不会把读取失败误报为完整性错误。

该查询与本进程内并发密封写入处于同一完整串行状态：同一键正在提交期间，查询只会得到未绑定的 `404` 或提交完成后的完整成功凭据，不观察部分提交；携带新键的提交失败回滚后该键仍为 `404`。单记录接口、两类批量写入、全部读取与分页、增量事件、健康检查及密钥管理的既有公开行为保持不变。

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

客户端密封批量入口使用四张独立的表，均在同一次事务中写入：`encrypted_batches(batch_id, tenant, record_count, created_at)` 记录每个成功批次；`encrypted_records(tenant, id, batch_id, position, algorithm, encryption_key_id, envelope_nonce, wrapped_key, ciphertext, ciphertext_nonce, tag, metadata)` 以 `(tenant, id)` 为主键原样保存调用方提交的字节，与服务端加密的 `records` 表互不影响；`encrypted_record_events(seq, batch_id, tenant, record_id, position)` 是仅追加的账本，`seq` 单调递增，每条新可见记录对应一行；`encrypted_batch_idempotency_keys(tenant, idempotency_key, batch_id, created_at)` 以 `(tenant, idempotency_key)` 为主键记录幂等关联，仅在携带 `Idempotency-Key` 成功提交时与该批次同事务写入，旧批次没有对应行。批次任一步骤失败时这些表一起回滚，因此不会出现有记录无事件、有批次无记录，或有幂等关联却无完整批次的中间状态。该入口的信封不参与服务端密钥轮换（服务端不持有其封装密钥）。

批次清单分页另用两张仅服务于冻结快照的表：`encrypted_batch_list_snapshots(snapshot_id, tenant, total, created_at)` 记录每次多页首次查询的冻结状态与当时的批次总数，`encrypted_batch_list_snapshot_items(snapshot_id, position, summary)` 以紧凑且保留原始存储类型的 JSON 保存当时的 `[batch_id, record_count, created_at]` 摘要；二者在同一事务中写入，查询本身不改动上述四张协议表，离线删改快照行导致总数不符或位置不连续时按 `422 integrity_error` 处理。游标签名密钥存于 `service_metadata`（`name='cursor_secret'`），与记录清单游标共用，因此游标可在正常重启后继续使用。

## 轮换和并发边界

轮换只重封装数据密钥，不重新加密正文，所有记录的 `nonce` 和 `ciphertext` 字节必须保持不变。轮换需确认每条旧信封的封装和正文都可认证；任一损坏返回 `422 integrity_error`，该次请求开始前的所有记录字段及活动版本都保持不变。SQLite 写入失败返回 `503 storage_error`，同样不得出现部分提交。旧版本记录在轮换前可读，完成轮换后仍可读；重启不得重置活动版本或丢失记录。

同一进程中，并发创建同租户同 id 只能一个成功，其余返回 `409 conflict`；批量批次之间、批次与单条创建之间争用同租户同 id 时同样只有一个请求成功，失败批次一条都不落库。创建、读取、轮换的成功结果必须与某个完整串行顺序一致，不能观察半轮换状态。写入与成功轮换并发结束后，所有记录均应为最终活动版本且可读；两个相同目标版本的轮换并发执行时，一个完成实际轮换，另一个返回幂等空操作。数据量范围为本地小型账本，无需分页、跨进程协调、批次后台迁移或性能基准。

可用离线 SQLite 维护复现损坏：先停止服务，改动一条记录的任一密文字段后重启。存储失败可用 SQLite `BEFORE UPDATE ON records` 触发器的 `RAISE(ABORT,...)` 模拟；此时观察到的 HTTP 失败不得留下其他行更新或活动版本变化。移除触发器或恢复原字段后服务应继续正常运行。这些错误路径属于本模块公开兼容要求。

密码库参考：[cryptography 49 AESGCM 文档](https://cryptography.io/en/49.0.0/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)。
