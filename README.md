# 服务端登录态与访问控制

本地即可运行的一套会话认证、基于角色的访问控制（RBAC）与频率限制实现。
不依赖 Redis、数据库等任何外部中间件：用户、会话、限流计数全部保存在应用内存中，
令牌使用本地配置的 HMAC 密钥签名，密码为内置演示账号，不使用真实凭据。

## 快速开始

```bash
mvn spring-boot:run        # 启动（随机端口，见 server.port=0，可自行改为固定端口）
mvn test                   # 运行全部测试（22+ 用例）
```

内置演示账号：

| 账号  | 密码       | 角色           |
|-------|------------|----------------|
| alice | alice-pwd  | USER           |
| bob   | bob-pwd    | USER（角色可在运行期调整） |
| admin | admin-pwd  | USER, ADMIN    |

## 接口一览

| 方法 | 路径                  | 说明                                   |
|------|-----------------------|----------------------------------------|
| POST | `/auth/login`         | 登录，返回 accessToken / refreshToken  |
| POST | `/auth/refresh`       | 刷新令牌轮换，换取新令牌对             |
| POST | `/auth/logout`        | 撤销当前会话                           |
| GET  | `/api/public/hello`   | 公开接口，无需登录                     |
| GET  | `/api/user/profile`   | 需 USER 角色                           |
| GET  | `/api/admin/stats`    | 需 ADMIN 角色                          |

## 1. 登录态模型

### 双令牌

登录成功后下发两个 HMAC-SHA256 签名的令牌，格式为
`v1.<base64url(payload)>.<base64url(hmac)>`：

- **访问令牌（access token）**：无状态、自包含 `会话ID / 用户名 / 过期时间`，
  默认有效期 60 秒（`auth.access-token-ttl-seconds`）。用于接口鉴权。
- **续期令牌（refresh token）**：含 `会话ID / 随机令牌ID`，默认有效期 600 秒
  （`auth.refresh-token-ttl-seconds`）。服务端只保存令牌 ID 的 SHA-256 哈希。

### 多设备登录

每次登录都会新建一个独立会话（`SessionStore` 中的一条记录），
同一账号可同时持有多个会话；设备 A 退出只撤销 A 的会话，不影响设备 B。

### 续期令牌轮换（rotation）

每次调用 `/auth/refresh` 都会**原子地**把服务端认可的令牌哈希替换为新值：

- 新令牌对返回客户端，旧刷新令牌立即失效；
- 轮换通过 `ConcurrentHashMap.compute` 中的比较-替换完成，
  并发续期时只有一个请求成功，其余判定为“重复使用”，计数不丢不重。

### 续期结果可区分

| 结果 (`reason`) | 触发条件                                       |
|-----------------|------------------------------------------------|
| `TAMPERED`      | 签名校验失败 / 格式非法（凭证被篡改）          |
| `EXPIRED`       | 会话的刷新令牌有效期已过                       |
| `REVOKED`       | 会话不存在或已撤销（已退出的会话不能靠续期恢复）|
| `REUSED`        | 令牌签名合法，但不是当前认可的令牌（旧令牌重放）|
| `RATE_LIMITED`  | 命中续期频率限制（HTTP 429，不计入上述 401）   |

### 退出登录

`/auth/logout` 撤销会话后：访问令牌立即判定为 `SESSION_REVOKED`（401），
刷新令牌判定为 `REVOKED`，无法再恢复登录态。

## 2. 权限判定规则

由 `AuthInterceptor` + `@RequireRole` 实现，拦截 `/api/**`：

1. 读取 `Authorization: Bearer <accessToken>`，先做令牌校验；
2. 未认证一律返回 **401** `UNAUTHENTICATED`，并以 `reason` 区分：
   `MISSING`（未带凭证）、`MALFORMED`、`TAMPERED`、`EXPIRED`、`SESSION_REVOKED`；
3. 令牌合法后，**每次请求都实时读取 `UserStore` 中的最新角色集合**，
   与接口要求的任一角色匹配：
   - 匹配 → 放行，并把用户名、会话 ID 写入请求属性；
   - 不匹配 → **403** `FORBIDDEN`（已登录但越权）。

因此角色在会话有效期内被调整后：

- 被降级的用户，下一个请求立即失去访问权（旧权限不会继续放行）；
- 被升级的用户，下一个请求立即获得访问权（新权限不会延迟生效）；
- 不需要重新登录或换发令牌。

## 3. 频率限制

`RateLimiter` 为固定窗口计数器，本地内存实现：

- **登录失败限制**：同一账号（`login-fail:acct:<用户名>`）与同一来源
  （`login-fail:src:<IP>`，取 `X-Forwarded-For` 首段或 remoteAddr）分别计数，
  默认每个窗口 5 次（`auth.login-fail-limit` / `auth.login-fail-window-seconds=60`）。
  任一维度超限返回 429 `RATE_LIMITED`；登录成功后两个维度计数均清零，正常用户不被误伤。
- **续期限制**：按来源 IP 计数，默认每窗口 10 次
  （`auth.refresh-limit` / `auth.refresh-window-seconds=60`），超限返回 429。
- **自动恢复**：窗口过期后计数清零，无需人工干预。
- **并发安全**：窗口滚动与计数自增在 `ConcurrentHashMap.compute` 的原子区间内完成，
  32 线程并发压测下放行数恰好等于限额，计数不丢失也不翻倍。

## 主要类

| 类/接口             | 职责                                           |
|---------------------|------------------------------------------------|
| `TokenService`      | 签发/校验令牌、续期轮换、撤销会话               |
| `SessionStore`      | 内存会话存储，原子比较-轮换刷新令牌             |
| `UserStore`         | 内存用户与实时角色（支持在线调整角色）          |
| `RateLimiter`       | 并发安全的固定窗口限流                          |
| `AuthInterceptor`   | 令牌校验 + 实时角色判定，401/403 可区分         |
| `@RequireRole`      | 接口/类级角色要求注解                           |
| `AuthController`    | 登录、续期、退出接口                            |
| `ResourceController`| 公开 / USER / ADMIN 示例接口                    |

## 测试

- `TokenServiceTest`：续期成功、篡改、过期、撤销、重复使用、16 并发续期、
  多设备独立、访问令牌过期；
- `AccessControlTest`：401 各原因、403 越权、角色提升/降级立即生效；
- `RateLimiterTest`：限制生效与自动恢复、key 间隔离、32 线程并发计数精确；
- `LoginRateLimitTest`：HTTP 层登录失败限流、来源维度联动、成功重置、续期限流；
- `RefreshFlowIntegrationTest`：登录→续期→旧令牌重放→退出→再续期的完整链路。

每个测试用例均通过日志打印 **请求身份、命中规则、判定结论**
（格式：`身份=... 规则=... 结论=...`）。
