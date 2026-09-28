package com.github.xingjianluo.sessionauthaccesscontroljava.tests;

import com.github.xingjianluo.sessionauthaccesscontroljava.config.TokenProperties;
import com.github.xingjianluo.sessionauthaccesscontroljava.support.MutableClock;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenService;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.TokenType;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.Verification;
import com.github.xingjianluo.sessionauthaccesscontroljava.token.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/** 凭证签发与校验：正常、篡改、畸形、过期、类型混用必须得到可区分结论。 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT-TEST");

    private MutableClock clock;
    private TokenService tokenService;
    private long accessTtl;
    private long refreshTtl;

    @BeforeEach
    void setUp() {
        Instant start = Instant.parse("2026-01-01T00:00:00Z");
        clock = new MutableClock(start);
        TokenProperties properties = new TokenProperties();
        accessTtl = properties.getAccessTtlSeconds();
        refreshTtl = properties.getRefreshTtlSeconds();
        tokenService = new TokenService(properties, clock);
    }

    @Test
    @DisplayName("签发的访问/续期凭证可按期望类型校验通过并携带正确声明")
    void validTokensVerify() {
        TokenService.IssuedToken access = tokenService.issueAccess("alice", "s-1");
        TokenService.IssuedToken refresh = tokenService.issueRefresh("alice", "s-1");

        Verification va = tokenService.verify(access.compact(), TokenType.ACCESS);
        Verification vr = tokenService.verify(refresh.compact(), TokenType.REFRESH);

        log.info("identity=alice rule=TOKEN_ISSUE decision=OK detail=accessJti={}, refreshJti={}",
                access.claims().jti(), refresh.claims().jti());

        assertEquals(VerificationStatus.OK, va.status());
        assertEquals(VerificationStatus.OK, vr.status());
        assertEquals("alice", va.claims().subject());
        assertEquals("s-1", va.claims().sessionId());
        assertNotEquals(access.claims().jti(), refresh.claims().jti());
    }

    @Test
    @DisplayName("篡改负载或签名一律判定 BAD_SIGNATURE，且与过期相互独立")
    void tamperedTokenIsBadSignature() {
        TokenService.IssuedToken access = tokenService.issueAccess("alice", "s-1");

        // 1) 篡改签名段
        String tamperedSignature = access.compact().substring(0, access.compact().length() - 2) + "AA";
        Verification tampered = tokenService.verify(tamperedSignature, TokenType.ACCESS);

        // 2) 篡改负载段（把主体改成 admin），签名不重算
        String tamperedPayload = replacePayloadSubject(access.compact(), "admin");
        Verification tamperedPayloadResult = tokenService.verify(tamperedPayload, TokenType.ACCESS);

        log.info("identity=alice rule=TOKEN_SIGNATURE decision=BAD_SIGNATURE detail=signature-and-payload-tampered");

        assertEquals(VerificationStatus.BAD_SIGNATURE, tampered.status());
        assertEquals(VerificationStatus.BAD_SIGNATURE, tamperedPayloadResult.status());
    }

    @Test
    @DisplayName("结构损坏（缺段/乱码/空）判定 MALFORMED，不会被当成签名错误")
    void malformedTokensAreMalformed() {
        assertEquals(VerificationStatus.MALFORMED, tokenService.verify(null, TokenType.ACCESS).status());
        assertEquals(VerificationStatus.MALFORMED, tokenService.verify("", TokenType.ACCESS).status());
        assertEquals(VerificationStatus.MALFORMED, tokenService.verify("only-one-part", TokenType.ACCESS).status());
        assertEquals(VerificationStatus.MALFORMED,
                tokenService.verify("a.b.c", TokenType.ACCESS).status());
        assertEquals(VerificationStatus.MALFORMED,
                tokenService.verify("!!!.@@@", TokenType.ACCESS).status());
        log.info("identity=anonymous rule=TOKEN_FORMAT decision=MALFORMED detail=5 malformed inputs");
    }

    @Test
    @DisplayName("超过有效期判定 EXPIRED；恰好到期也算过期")
    void expiredTokenIsExpired() {
        TokenService.IssuedToken access = tokenService.issueAccess("alice", "s-1");

        clock.advance(Duration.ofSeconds(accessTtl - 1));
        assertEquals(VerificationStatus.OK,
                tokenService.verify(access.compact(), TokenType.ACCESS).status(), "到期前一秒仍有效");

        clock.advance(Duration.ofSeconds(1));
        Verification atExpiry = tokenService.verify(access.compact(), TokenType.ACCESS);

        clock.advance(Duration.ofHours(1));
        Verification longAfter = tokenService.verify(access.compact(), TokenType.ACCESS);

        log.info("identity=alice rule=TOKEN_EXPIRY decision=EXPIRED detail=ttlSeconds={}", accessTtl);

        assertEquals(VerificationStatus.EXPIRED, atExpiry.status());
        assertEquals(VerificationStatus.EXPIRED, longAfter.status());
    }

    @Test
    @DisplayName("凭证类型不能混用：访问凭证当续期用得到 WRONG_TYPE，反之亦然")
    void wrongTypeIsDistinguishable() {
        TokenService.IssuedToken access = tokenService.issueAccess("alice", "s-1");
        TokenService.IssuedToken refresh = tokenService.issueRefresh("alice", "s-1");

        Verification accessAsRefresh = tokenService.verify(access.compact(), TokenType.REFRESH);
        Verification refreshAsAccess = tokenService.verify(refresh.compact(), TokenType.ACCESS);

        log.info("identity=alice rule=TOKEN_TYPE decision=WRONG_TYPE detail=both directions rejected");

        assertEquals(VerificationStatus.WRONG_TYPE, accessAsRefresh.status());
        assertEquals(VerificationStatus.WRONG_TYPE, refreshAsAccess.status());
    }

    @Test
    @DisplayName("不同密钥签发的凭证判定 BAD_SIGNATURE")
    void differentSecretIsRejected() {
        TokenService other = new TokenService(new TokenProperties() {{
            setSecret("a-totally-different-secret");
        }}, clock);
        TokenService.IssuedToken foreign = other.issueAccess("alice", "s-1");

        Verification result = tokenService.verify(foreign.compact(), TokenType.ACCESS);
        log.info("identity=alice rule=TOKEN_SIGNATURE decision=BAD_SIGNATURE detail=foreign-secret");
        assertEquals(VerificationStatus.BAD_SIGNATURE, result.status());
        assertEquals(refreshTtl, 86400);
    }

    /** 把 payload 中的 sub 字段替换掉但保留原签名（base64url，无填充）。 */
    private static String replacePayloadSubject(String compact, String newSubject) {
        int dot = compact.indexOf('.');
        String payloadB64 = compact.substring(0, dot);
        String signatureB64 = compact.substring(dot + 1);
        byte[] payloadBytes = Base64.getUrlDecoder().decode(payloadB64);
        String json = new String(payloadBytes, StandardCharsets.UTF_8);
        String replaced = json.replace("\"sub\":\"alice\"", "\"sub\":\"" + newSubject + "\"");
        String newPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(replaced.getBytes(StandardCharsets.UTF_8));
        return newPayload + "." + signatureB64;
    }
}
