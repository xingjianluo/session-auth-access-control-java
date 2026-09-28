package com.github.xingjianluo.sessionauthaccesscontroljava.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.xingjianluo.sessionauthaccesscontroljava.config.TokenProperties;

import java.io.IOException;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * 本地 HMAC 凭证服务：负责签发与校验访问凭证 / 续期凭证，不依赖任何外部组件。
 *
 * <p>凭证结构为两段式：{@code base64url(payloadJSON).base64url(HMAC-SHA256(payload))}，
 * payload 中包含类型、主体、会话 id、唯一 id（jti）、签发与过期时间。
 *
 * <p>校验结论严格区分：结构/编码/字段损坏 → {@link VerificationStatus#MALFORMED}；
 * 签名与负载不匹配 → {@link VerificationStatus#BAD_SIGNATURE}；
 * 已过有效期 → {@link VerificationStatus#EXPIRED}；
 * 凭证类型与使用场景不符 → {@link VerificationStatus#WRONG_TYPE}。
 */
@Component
public class TokenService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final TokenProperties properties;
    private final Clock clock;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public TokenService(TokenProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    /** 签发结果：凭证原文 + 解析后的声明（轮换续期时需要其中的 jti）。 */
    public record IssuedToken(String compact, TokenClaims claims) {
    }

    /** 签发访问凭证。 */
    public IssuedToken issueAccess(String subject, String sessionId) {
        return issue(TokenType.ACCESS, subject, sessionId, properties.getAccessTtlSeconds());
    }

    /** 签发续期凭证。 */
    public IssuedToken issueRefresh(String subject, String sessionId) {
        return issue(TokenType.REFRESH, subject, sessionId, properties.getRefreshTtlSeconds());
    }

    private IssuedToken issue(TokenType type, String subject, String sessionId, long ttlSeconds) {
        Instant now = clock.instant();
        String jti = UUID.randomUUID().toString();
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        Payload payload = new Payload(
                type.name(), subject, sessionId, jti, now.getEpochSecond(), expiresAt.getEpochSecond());
        byte[] payloadBytes = writePayload(payload);
        byte[] signature = hmac(payloadBytes);
        String compact = encoder.encodeToString(payloadBytes) + "." + encoder.encodeToString(signature);
        TokenClaims claims = new TokenClaims(type, subject, sessionId, jti, now, expiresAt);
        return new IssuedToken(compact, claims);
    }

    /**
     * 校验凭证。
     *
     * @param compact  凭证原文
     * @param expected 期望的凭证类型
     */
    public Verification verify(String compact, TokenType expected) {
        if (compact == null || compact.isBlank()) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }
        int dot = compact.indexOf('.');
        // 必须恰好两段
        if (dot <= 0 || dot >= compact.length() - 1 || compact.indexOf('.', dot + 1) >= 0) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }
        byte[] payloadBytes;
        byte[] providedSignature;
        try {
            payloadBytes = decoder.decode(compact.substring(0, dot));
            providedSignature = decoder.decode(compact.substring(dot + 1));
        } catch (IllegalArgumentException ex) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }

        Payload payload;
        try {
            payload = PayloadJson.MAPPER.readValue(payloadBytes, Payload.class);
        } catch (IOException ex) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }
        if (payload == null || !payload.isComplete()) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }

        // 签名验证先于时效判定：任何对负载或签名的篡改都稳定归类为 BAD_SIGNATURE
        byte[] expectedSignature = hmac(payloadBytes);
        if (!MessageDigest.isEqual(expectedSignature, providedSignature)) {
            return Verification.invalid(VerificationStatus.BAD_SIGNATURE);
        }

        Instant expiresAt = Instant.ofEpochSecond(payload.exp());
        if (!clock.instant().isBefore(expiresAt)) {
            return Verification.invalid(VerificationStatus.EXPIRED);
        }

        TokenType type;
        try {
            type = TokenType.valueOf(payload.typ());
        } catch (IllegalArgumentException ex) {
            return Verification.invalid(VerificationStatus.MALFORMED);
        }
        if (type != expected) {
            return Verification.invalid(VerificationStatus.WRONG_TYPE);
        }

        TokenClaims claims = new TokenClaims(
                type,
                payload.sub(),
                payload.sid(),
                payload.jti(),
                Instant.ofEpochSecond(payload.iat()),
                expiresAt);
        return Verification.ok(claims);
    }

    private byte[] writePayload(Payload payload) {
        try {
            return PayloadJson.MAPPER.writeValueAsBytes(payload);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("failed to serialize token payload", ex);
        }
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(properties.getSecret().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new IllegalStateException("failed to compute HMAC", ex);
        }
    }

    /** 凭证负载。字段简写保持凭证紧凑。 */
    public record Payload(
            @JsonProperty("typ") String typ,
            @JsonProperty("sub") String sub,
            @JsonProperty("sid") String sid,
            @JsonProperty("jti") String jti,
            @JsonProperty("iat") long iat,
            @JsonProperty("exp") long exp) {

        boolean isComplete() {
            return typ != null && sub != null && sid != null && jti != null && iat > 0 && exp > 0;
        }
    }

    /** 惰性持有 ObjectMapper，避免实例字段顺序带来的初始化问题。 */
    private static final class PayloadJson {
        private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
                new com.fasterxml.jackson.databind.ObjectMapper();
    }
}
