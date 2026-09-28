package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * 令牌服务：签发/校验访问令牌与刷新令牌。
 *
 * <p>令牌格式：{@code v1.<base64url(payload)>.<base64url(hmac-sha256)>}。
 * 密钥是本地配置的固定值（仅用于本地运行，不依赖真实凭据）。
 *
 * <p>刷新令牌采用轮换机制：每次续期都会原子地替换服务端认可的令牌哈希，
 * 旧令牌再次使用会被判定为 {@link RefreshResult.Failure#REUSED}。
 */
@Service
public class TokenService {

    private final SessionStore sessionStore;
    private final byte[] secret;
    private final Duration accessTokenTtl;
    private final Duration refreshTokenTtl;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    @Autowired
    public TokenService(SessionStore sessionStore,
                        @Value("${auth.token-secret:local-dev-secret-not-for-production}") String secret,
                        @Value("${auth.access-token-ttl-seconds:60}") long accessTokenTtlSeconds,
                        @Value("${auth.refresh-token-ttl-seconds:600}") long refreshTokenTtlSeconds) {
        this(sessionStore, secret, Duration.ofSeconds(accessTokenTtlSeconds),
                Duration.ofSeconds(refreshTokenTtlSeconds), Clock.systemUTC());
    }

    /** 便于测试注入固定时钟与自定义有效期。 */
    public TokenService(SessionStore sessionStore, String secret,
                        Duration accessTokenTtl, Duration refreshTokenTtl, Clock clock) {
        this.sessionStore = sessionStore;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenTtl = refreshTokenTtl;
        this.clock = clock;
    }

    /** 登录成功后调用：创建一个新会话（一个设备）并签发令牌对。 */
    public TokenPair login(String username) {
        String sessionId = UUID.randomUUID().toString();
        String refreshTokenId = newTokenId();
        Session session = new Session(
                sessionId,
                username,
                Instant.now(clock),
                Instant.now(clock).plus(refreshTokenTtl),
                sha256Hex(refreshTokenId),
                false);
        sessionStore.save(session);
        return new TokenPair(buildAccessToken(session), buildRefreshToken(sessionId, refreshTokenId));
    }

    /** 校验访问令牌，结果可区分：缺失/格式错误/被篡改/过期/会话已撤销。 */
    public AccessCheckResult checkAccessToken(String token) {
        if (token == null || token.isBlank()) {
            return AccessCheckResult.Invalid.MISSING;
        }
        String[] parts = parseAndVerify(token);
        if (parts == null) {
            return AccessCheckResult.Invalid.TAMPERED;
        }
        String[] fields = parts[1].split("\\|", -1);
        if (fields.length != 4 || !fields[0].equals("access")) {
            return AccessCheckResult.Invalid.MALFORMED;
        }
        String sessionId = fields[1];
        String username = fields[2];
        long expiryMillis;
        try {
            expiryMillis = Long.parseLong(fields[3]);
        } catch (NumberFormatException e) {
            return AccessCheckResult.Invalid.MALFORMED;
        }
        if (clock.millis() >= expiryMillis) {
            return AccessCheckResult.Invalid.EXPIRED;
        }
        Session session = sessionStore.find(sessionId);
        if (session == null || session.revoked()) {
            return AccessCheckResult.Invalid.SESSION_REVOKED;
        }
        return new AccessCheckResult.Valid(sessionId, username);
    }

    /**
     * 续期：用刷新令牌换新的令牌对。
     * 可区分：被篡改 / 已过期 / 已撤销（含已退出）/ 重复使用。
     */
    public RefreshResult refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return RefreshResult.Failure.TAMPERED;
        }
        String[] parts = parseAndVerify(refreshToken);
        if (parts == null) {
            return RefreshResult.Failure.TAMPERED;
        }
        String[] fields = parts[1].split("\\|", -1);
        if (fields.length != 3 || !fields[0].equals("refresh")) {
            return RefreshResult.Failure.TAMPERED;
        }
        String sessionId = fields[1];
        String tokenId = fields[2];

        Session session = sessionStore.find(sessionId);
        if (session == null || session.revoked()) {
            // 已退出（撤销）的会话不能靠续期恢复
            return RefreshResult.Failure.REVOKED;
        }
        if (!Instant.now(clock).isBefore(session.refreshExpiresAt())) {
            return RefreshResult.Failure.EXPIRED;
        }
        // 原子比较并轮换：并发下只有一个请求能换成功
        String newTokenId = newTokenId();
        boolean rotated = sessionStore.compareAndRotateRefresh(
                sessionId, sha256Hex(tokenId), sha256Hex(newTokenId));
        if (!rotated) {
            return RefreshResult.Failure.REUSED;
        }
        Session updated = sessionStore.find(sessionId);
        return new RefreshResult.Success(new TokenPair(
                buildAccessToken(updated), buildRefreshToken(sessionId, newTokenId)));
    }

    /** 退出登录：撤销会话，之后访问令牌与刷新令牌都失效。 */
    public void revokeSession(String sessionId) {
        sessionStore.revoke(sessionId);
    }

    // ---------- 内部实现 ----------

    private String buildAccessToken(Session session) {
        String payload = "access|" + session.sessionId() + "|" + session.username()
                + "|" + (clock.millis() + accessTokenTtl.toMillis());
        return "v1." + b64(payload) + "." + b64(hmac(payload));
    }

    private String buildRefreshToken(String sessionId, String tokenId) {
        String payload = "refresh|" + sessionId + "|" + tokenId;
        return "v1." + b64(payload) + "." + b64(hmac(payload));
    }

    /** 校验版本与签名，返回 [payloadBase64, payload]；失败返回 null。 */
    private String[] parseAndVerify(String token) {
        String[] segs = token.split("\\.", -1);
        if (segs.length != 3 || !segs[0].equals("v1")) {
            return null;
        }
        String payload;
        byte[] signature;
        try {
            payload = new String(Base64.getUrlDecoder().decode(segs[1]), StandardCharsets.UTF_8);
            signature = Base64.getUrlDecoder().decode(segs[2]);
        } catch (IllegalArgumentException e) {
            return null;
        }
        byte[] expected = hmac(payload);
        if (!MessageDigest.isEqual(expected, signature)) {
            return null;
        }
        return new String[]{segs[1], payload};
    }

    private byte[] hmac(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String newTokenId() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return HexFormat.of().formatHex(buf);
    }

    static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
