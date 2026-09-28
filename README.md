# 登录态与访问控制（本地内存实现）

一个零外部中间件依赖的服务端登录态 / 访问控制演示：登录下发**访问凭证**与**续期凭证**，
续期凭证支持**轮换 + 重放检测**；接口按**角色**授权，角色调整**实时生效**；
登录失败与续期操作按**账号 + 来源**两个维度做固定窗口限流，可自动恢复。

- 技术栈：Spring Boot 3.4 / Java 21，凭证为自实现 HMAC-SHA256 签名令牌（不引入 JWT 库）
- 存储：全部本地内存（`ConcurrentHashMap`），不需要数据库 / Redis
- 凭据：演示账号硬编码在 `UserDirectory`，密码明文仅用于本地验证

---

## 1. 登录态模型

### 1.1 两种凭证

| 凭证 | 用途 | 默认有效期 | 是否无状态 |
|---|---|---|---|
| 访问凭证 `accessToken` | 每次访问受保护接口时携带（`Authorization: Bearer ...`） | 15 分钟 | 是，服务端只验签 + 查会话状态 |
| 续期凭证 `refreshToken` | 仅用于换新凭证对 | 24 小时 | 否，服务端保存其轮换状态 |

凭证结构：`base64url(payloadJSON).base64url(HMAC-SHA256(payload))`，
负载字段：`typ`(ACCESS/REFRESH)、`sub`(用户名)、`sid`(会话 id)、`jti`(凭证唯一 id)、`iat`、`exp`。

### 1.2 会话（Session）

- 一次设备登录 = 一个会话，**多设备登录**即同一账号拥有多个互不影响的 ACTIVE 会话。
- 会话保存：当前续期凭证的 `jti`、已使用的历史 `jti` 集合、状态（`ACTIVE` / `LOGGED_OUT` / `REVOKED`）。
- **角色不写入访问凭证**，每次请求实时从用户目录读取（见第 2 节）。
- 会话内的“续期 / 退出”判定在会话对象锁内完成，保证并发时结论确定。

### 1.3 续期：轮换与重放检测

每次成功续期都签发一对新凭证，并把旧续期凭证的 `jti` 记入会话历史：

```
旧 refreshToken ──成功──> 新 accessToken + 新 refreshToken（旧的立即作废）
```

各种异常的**可区分结论**（HTTP 状态码 + 错误码）：

| 情形 | 结论 RefreshResult | HTTP | 错误码 |
|---|---|---|---|
| 结构损坏/缺段/非法编码 | `MALFORMED` | 401 | `REFRESH_MALFORMED` |
| 签名或负载被篡改 | `BAD_SIGNATURE` | 401 | `REFRESH_BAD_SIGNATURE` |
| 已过有效期 | `EXPIRED` | 401 | `REFRESH_EXPIRED` |
| 拿访问凭证来续期（或反之） | `WRONG_TYPE` | 401 | `REFRESH_WRONG_TYPE` |
| 凭证合法但会话不存在 | `SESSION_NOT_FOUND` | 404 | `REFRESH_SESSION_NOT_FOUND` |
| **旧凭证被再次使用（重放）** | `REUSED` | 401 | `REFRESH_REUSED` |
| 会话因重放被安全撤销 | `REVOKED` | 401 | `REFRESH_SESSION_REVOKED` |
| 会话已退出 | `LOGGED_OUT` | 401 | `REFRESH_SESSION_LOGGED_OUT` |
| 账号被停用 | `ACCOUNT_DISABLED` | 403 | `REFRESH_ACCOUNT_DISABLED` |
| 触发频率限制 | `RATE_LIMITED` | 429 | `REFRESH_RATE_LIMITED` |

关键安全语义：

1. **签名验证先于过期判定**——对一张已过期凭证做任何篡改，结论稳定为 `BAD_SIGNATURE`。
2. **已退出的会话不能靠续期恢复**：退出后会话为 `LOGGED_OUT`，任何续期凭证都只得到 `LOGGED_OUT`。
3. **重放检测**：提交的 `jti` 不是会话当前 `jti` 时：
   - 若该 `jti` 在历史集合中 → `REUSED`；否则 → `REVOKED`；
   - 两种情况都会把整个会话置为 `REVOKED`，攻击者若盗用了轮换后的新凭证也会一并失效。
4. **并发续期恰好一次成功**：同一张续期凭证被多线程同时使用时，1 个成功，其余得到 `REUSED`/`REVOKED`。

### 1.4 退出

`POST /api/auth/logout` 把会话置为 `LOGGED_OUT`（幂等）。此后：

- 该会话的**访问凭证立即失效**（不必等 15 分钟过期）；
- 该会话的续期凭证只能得到 `LOGGED_OUT`；
- 同一账号其它设备的会话不受影响。

---

## 2. 权限判定规则

### 2.1 接口分三档

| 接口 | 要求 |
|---|---|
| `GET /api/public/ping`、`/api/auth/**` | 匿名可访问（无 `@RequireRole`） |
| `GET /api/profile` | 登录即可（`USER` 或 `ADMIN`） |
| `GET /api/admin/panel`、`POST /api/admin/users/roles` | 仅 `ADMIN` |

### 2.2 判定顺序（`AuthInterceptor`）

1. 方法/类没有 `@RequireRole` → 直接放行（公开）。
2. 缺少 `Authorization: Bearer` → **401 `ACCESS_UNAUTHENTICATED`**（未登录）。
3. 访问凭证校验（验签 / 过期 / 类型）、会话状态、账号状态：
   - 凭证篡改 → 401 `ACCESS_TOKEN_INVALID`；过期 → 401 `ACCESS_TOKEN_EXPIRED`；
   - 会话已退出 → 401 `ACCESS_SESSION_LOGGED_OUT`；被撤销 → 401 `ACCESS_SESSION_REVOKED`；
   - 账号停用 → 401 `ACCESS_ACCOUNT_DISABLED`。
4. 已认证但角色不匹配 → **403 `FORBIDDEN_ROLE`**（越权）。
   未登录(401) 与 越权(403) 通过状态码与错误码明确区分。

### 2.3 角色调整实时生效

角色集合**不固化在凭证中**。每次受保护请求都用凭证中的用户名实时读取 `UserDirectory`；
管理员通过 `POST /api/admin/users/roles` **整体替换**某用户的角色（volatile 发布不可变快照）：

- 提权：下一次请求即放行，无需重新登录、无需等凭证过期；
- 降权：下一次请求即拒绝，不会出现旧权限继续放行；
- 对该用户**所有设备的会话**同时生效。

---

## 3. 频率限制行为

`FixedWindowRateLimiter` 固定窗口计数器，登录与续期各自独立、账号与来源两个维度独立：

| 计数器 | 默认阈值 | 窗口 | 键 |
|---|---|---|---|
| 登录·账号 | 5 次 | 60s | `u:<username>` |
| 登录·来源 | 20 次（账号阈值 ×4） | 60s | `s:<来源标识>` |
| 续期·账号 | 20 次 | 60s | `u:<username>` |
| 续期·来源 | 80 次 | 60s | `s:<来源标识>` |

行为约定：

1. **只计失败，不计成功**：登录先做不计数的前置检查，账密校验失败才计数；
   登录成功立即 `reset` 账号维度。正常用户偶发输错密码不会被误伤。
2. **前置检查不计数**：被 429 拦截的探测请求不污染窗口。
3. **边界确定**：窗口内第 1..N 次放行，第 N+1 次起拒绝；越过窗口起点后下一次操作自动开启新窗口，
   **无需任何调度即可自动恢复**。
4. **来源维度**：来源标识取 `X-Client-Id` 请求头（本地测试可模拟不同来源），
   其次 `X-Forwarded-For`，再其次对端 IP。畸形续期凭证解不出账号时，来源维度仍能拦住刷接口行为。
5. **并发正确性**：每个 key 内置一把锁，“读窗口→判定→自增”在锁内一次完成，
   并发请求计数**既不丢失也不翻倍**（`hot-key` 上 100 并发精确放行阈值次数）。
6. **内存治理**：过期窗口键在周期性扫描中惰性淘汰。
7. 所有阈值 / 窗口均可通过 `application.properties` 调整（见第 6 节）。

---

## 4. HTTP 接口

### 4.1 登录

```
POST /api/auth/login
{ "username": "alice", "password": "user123", "deviceLabel": "phone" }
```

成功 200：`{ "accessToken": "...", "refreshToken": "...", "tokenType": "Bearer" }`
失败：401 `LOGIN_INVALID_CREDENTIALS` / 403 `LOGIN_ACCOUNT_DISABLED` / 429 `LOGIN_RATE_LIMITED`

### 4.2 续期

```
POST /api/auth/refresh
{ "refreshToken": "..." }
```

成功 200 返回新凭证对；失败结论见 1.3 节表格。

### 4.3 退出

```
POST /api/auth/logout
Authorization: Bearer <accessToken>
```

### 4.4 角色调整（仅 ADMIN）

```
POST /api/admin/users/roles
Authorization: Bearer <admin accessToken>
{ "username": "bob", "roles": ["ADMIN", "USER"] }
```

`roles` 为**整体替换**；传空数组即移除所有角色。

### 4.5 演示接口

- `GET /api/public/ping`：公开
- `GET /api/profile`：登录可访问，返回用户名 / 会话 id / 当前角色
- `GET /api/admin/panel`：仅 ADMIN

### 4.6 内置账号

| 用户名 | 密码 | 角色 | 状态 |
|---|---|---|---|
| admin | admin123 | ADMIN, USER | 启用 |
| alice | user123 | USER | 启用 |
| bob | user123 | USER | 启用 |
| carol | user123 | USER | 停用 |

---

## 5. 测试

```bash
mvn test
```

测试清单（35 个用例）：

| 测试类 | 覆盖内容 |
|---|---|
| `TokenServiceTest` | 凭证签发、篡改(BAD_SIGNATURE)、畸形(MALFORMED)、过期(EXPIRED)、类型混用(WRONG_TYPE)、换密钥 |
| `FixedWindowRateLimiterTest` | 边界放行、窗口自动恢复、100 并发计数精确、reset 清零、key 隔离、过期键淘汰 |
| `RefreshFlowTest` | 续期轮换、旧凭证重放→REUSED 并撤销会话、篡改、过期、类型错误、已退出不可恢复、会话不存在、账号停用、20 并发恰好一次成功 |
| `AccessControlMvcTest` | 未登录 401、越权 403、管理员 200、会话中提权/降权立即生效、篡改凭证 401、退出立即失效、多设备会话隔离 |
| `RateLimitMvcTest` | 登录失败阈值边界、窗口恢复、成功清零、来源维度防撞库、续期限流、续期恢复、40 并发计数精确 |

测试使用可控时钟 `MutableClock`（`TestClockConfig`，以 `@Primary` 覆盖生产时钟）构造
“凭证过期 / 窗口恢复”场景。

**审计日志**：所有判定通过 logger `AUTH-AUDIT`（测试中为 `AUTH-AUDIT-TEST`）打印，
格式为 `identity=<身份> rule=<命中规则> decision=<结论> detail=<细节>`，
例如：

```
AUDIT requestId=- identity=alice rule=REFRESH_ROTATION decision=REUSED detail=sessionId=... presentedJti=...
identity=bob rule=ROLE_CHANGE decision=PROMOTED detail=same token now 200
identity=hot-key rule=RATE_LIMIT_CONCURRENCY decision=EXACT detail=threads=100 allowed=25 rejected=75
```

运行 `mvn test` 时这些日志直接输出到控制台，可观察每个请求走到了哪条规则、得到什么结论。

### 手工快速验证

```bash
mvn spring-boot:run
# 登录
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"user123","deviceLabel":"curl"}'
# 访问受保护接口
curl -s localhost:8080/api/profile -H "Authorization: Bearer <accessToken>"
# 越权
curl -i localhost:8080/api/admin/panel -H "Authorization: Bearer <accessToken>"
```

---

## 6. 配置项（`src/main/resources/application.properties`）

```properties
app.security.token.secret=local-demo-secret-key-change-me
app.security.token.access-ttl-seconds=900
app.security.token.refresh-ttl-seconds=86400

app.security.rate-limit.login-max-attempts=5
app.security.rate-limit.login-window-seconds=60
app.security.rate-limit.refresh-max-attempts=20
app.security.rate-limit.refresh-window-seconds=60
```

> 本实现为本地演示：密钥与密码均不适合生产；内存状态在重启后丢失。
